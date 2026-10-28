//! The connection loop and the dispatcher: one thread per connection, newline-delimited JSON,
//! strictly one response per request (plus `progress` lines a long request asked for).
//! Threads rather than an async runtime: a connection does blocking file system work for as long
//! as a walk takes, there are a handful of connections, and `std` is the smaller dependency.

use crate::matcher::{self, Policy};
use crate::proto::*;
use crate::run::Runner;
use crate::scope::Scope;
use crate::walk::Sums;
use crate::{prims, walk};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const PROTOCOL: u32 = 1;
pub const MAX_LINE: usize = 8 * 1024 * 1024;
pub const MAX_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(900);
const WRITE_TIMEOUT: Duration = Duration::from_secs(300);
const BAD_TOKEN_DELAY: Duration = Duration::from_secs(1);

pub struct Shared {
    pub token: Vec<u8>,
    pub scope: Scope,
    pub tls: Arc<ServerConfig>,
    pub sums: Sums,
    pub runner: Runner,
    pub hostname: String,
    pub connections: AtomicUsize,
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) } == 0;
    if !ok {
        return "unknown".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Equal in time that does not depend on where the tokens differ: compare fixed-size digests.
pub fn token_matches(expected: &[u8], given: &[u8]) -> bool {
    let (a, b) = (Sha256::digest(expected), Sha256::digest(given));
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0 && expected.len() == given.len()
}

pub fn serve(listener: TcpListener, shared: Arc<Shared>) {
    for conn in listener.incoming() {
        let Ok(tcp) = conn else { continue };
        if shared.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            shared.connections.fetch_sub(1, Ordering::SeqCst);
            continue; // dropped: too many connections
        }
        let sh = shared.clone();
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| handle(&sh, tcp)));
            sh.connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

type Stream = StreamOwned<ServerConnection, TcpStream>;

fn write_line(stream: &mut Stream, v: &Value) -> std::io::Result<()> {
    let mut data = serde_json::to_vec(v).unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"unserialisable\",\"code\":\"io\"}".to_vec());
    data.push(b'\n');
    stream.write_all(&data)?;
    stream.flush()
}

enum Line {
    Data(Vec<u8>),
    Eof,
    TooLong,
}

fn read_line(stream: &mut Stream, pending: &mut Vec<u8>) -> std::io::Result<Line> {
    let mut scanned = 0;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        if let Some(pos) = pending[scanned..].iter().position(|&b| b == b'\n') {
            let end = scanned + pos;
            if end > MAX_LINE {
                return Ok(Line::TooLong);
            }
            let line: Vec<u8> = pending.drain(..=end).take(end).collect();
            return Ok(Line::Data(line));
        }
        scanned = pending.len();
        if pending.len() > MAX_LINE {
            return Ok(Line::TooLong);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(Line::Eof),
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

struct State {
    authed: bool,
    policy: Policy,
}

fn handle(shared: &Shared, tcp: TcpStream) {
    let _ = tcp.set_nodelay(true);
    let _ = tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(WRITE_TIMEOUT));
    let Ok(conn) = ServerConnection::new(shared.tls.clone()) else { return };
    let mut stream = StreamOwned::new(conn, tcp);
    let mut pending = Vec::new();
    let mut st = State { authed: false, policy: Policy::default() };
    let mut first = true;
    loop {
        let line = match read_line(&mut stream, &mut pending) {
            Ok(Line::Data(l)) => l,
            Ok(Line::TooLong) => {
                let _ = write_line(&mut stream, &Fail::bad("request line is over 8 MiB").to_json());
                return;
            }
            Ok(Line::Eof) | Err(_) => return,
        };
        if first {
            first = false;
            let _ = stream.sock.set_read_timeout(Some(IDLE_TIMEOUT));
        }
        let mut close = false;
        let resp = match std::panic::catch_unwind(AssertUnwindSafe(|| dispatch(shared, &mut st, &mut stream, &line, &mut close))) {
            Ok(v) => v,
            Err(_) => Fail::io("internal error").to_json(),
        };
        if write_line(&mut stream, &resp).is_err() || close {
            return;
        }
    }
}

fn ok_with(mut v: Value) -> Value {
    v["ok"] = json!(true);
    v
}

fn dispatch(shared: &Shared, st: &mut State, stream: &mut Stream, line: &[u8], close: &mut bool) -> Value {
    match dispatch_inner(shared, st, stream, line, close) {
        Ok(v) => v,
        Err(f) => f.to_json(),
    }
}

fn dispatch_inner(shared: &Shared, st: &mut State, stream: &mut Stream, line: &[u8], close: &mut bool) -> R<Value> {
    let parsed: Value = serde_json::from_slice(line).map_err(|_| Fail::bad("bad json"))?;
    let req = parsed.as_object().ok_or_else(|| Fail::bad("not an object"))?;
    let cmd = req.get("cmd").and_then(Value::as_str).unwrap_or("");
    match cmd {
        "hello" => {
            return Ok(json!({"ok": true, "protocol": PROTOCOL, "agent_version": env!("CARGO_PKG_VERSION"), "hostname": shared.hostname,
                             "os": std::env::consts::OS, "arch": std::env::consts::ARCH}));
        }
        "auth" => {
            let given = req.get("token").and_then(Value::as_str).unwrap_or("");
            if !token_matches(&shared.token, given.as_bytes()) {
                std::thread::sleep(BAD_TOKEN_DELAY);
                *close = true;
                return Err(Fail::new("unauthorized", "invalid token"));
            }
            st.authed = true;
            return Ok(json!({"ok": true}));
        }
        _ if !st.authed => return Err(Fail::new("unauthorized", "authenticate first")),
        _ => {}
    }
    match cmd {
        "configure_policy" => {
            let raw = match req.get("policy") {
                None | Some(Value::Null) => Obj::new(),
                Some(Value::Object(o)) => o.clone(),
                _ => return Err(Fail::bad("policy must be an object")),
            };
            let policy = matcher::configure(&raw)?;
            let mut resp = json!({"ok": true});
            if policy.has_rules() {
                resp["policy_id"] = json!(policy.id);
                resp["rules"] = json!(policy.rules.len());
                resp["markers"] = json!(policy.markers.len());
            }
            st.policy = policy;
            Ok(resp)
        }
        "cancel" => {
            let id = req.get("id").and_then(Value::as_str).unwrap_or("");
            Ok(json!({"ok": true, "found": shared.sums.cancel(id)}))
        }
        "list_dir" => {
            let mut emit = |v: &Value| write_line(stream, v);
            walk::list_dir(&shared.scope, &st.policy, &shared.sums, req, &mut emit)
        }
        "sum_subtree" => {
            let mut emit = |v: &Value| write_line(stream, v);
            walk::sum_subtree(&shared.scope, &st.policy, &shared.sums, req, &mut emit)
        }
        "measure" => prims::measure(&shared.scope, req),
        "read_range" => prims::read_range(&shared.scope, req),
        "read_file" => prims::read_file(&shared.scope, req),
        "statfs" => prims::statfs(&shared.scope, req),
        "run" => shared.runner.run(req),
        "capabilities" => Ok(ok_with(shared.runner.capabilities(&shared.scope))),
        "wmi" => Err(Fail::bad("wmi is only available on Windows agents")),
        other => Err(Fail::bad(format!("unknown cmd {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison() {
        assert!(token_matches(b"s3cret", b"s3cret"));
        assert!(!token_matches(b"s3cret", b"s3creT"));
        assert!(!token_matches(b"s3cret", b"s3cret "));
        assert!(!token_matches(b"s3cret", b""));
    }

    #[test]
    fn hostname_is_something() {
        assert!(!hostname().is_empty());
    }
}
