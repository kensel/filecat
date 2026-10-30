//! The registry of open connections behind the `activity` command and the periodic status log.
//! A session is one connection; it exists from accept to close. Hot counters are atomics (a file
//! is one relaxed add, no lock); the rest sits behind a mutex that is taken once per request.
//! Nothing here holds a path or a request argument: command names, the client's label and
//! numbers only, because a path could lie inside a `[REDACTED]` rollup.

use crate::clock::Instant;
use crate::proto::Fail;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_LABEL_CHARS: usize = 200;
const MIB: u64 = 1024 * 1024;
const GIB: f64 = (1u64 << 30) as f64;

/// A client-supplied label, safe to log: control characters dropped, at most 200 characters.
pub fn sanitize_label(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).take(MAX_LABEL_CHARS).collect::<String>().trim().to_string()
}

#[derive(Default)]
pub struct Counters {
    pub requests: AtomicU64,
    pub dirs_listed: AtomicU64,
    pub entries_listed: AtomicU64,
    pub files_measured: AtomicU64,
    pub bytes_read: AtomicU64,
    pub files_summed: AtomicU64,
    pub bytes_summed: AtomicU64,
    pub errors: AtomicU64,
}

#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Totals {
    pub requests: u64,
    pub dirs_listed: u64,
    pub entries_listed: u64,
    pub files_measured: u64,
    pub bytes_read: u64,
    pub files_summed: u64,
    pub bytes_summed: u64,
    pub errors: u64,
}

impl Totals {
    /// Files the session has looked at: measured plus summed.
    pub fn files(&self) -> u64 {
        self.files_measured + self.files_summed
    }
}

impl Counters {
    pub fn snapshot(&self) -> Totals {
        Totals {
            requests: self.requests.load(Relaxed),
            dirs_listed: self.dirs_listed.load(Relaxed),
            entries_listed: self.entries_listed.load(Relaxed),
            files_measured: self.files_measured.load(Relaxed),
            bytes_read: self.bytes_read.load(Relaxed),
            files_summed: self.files_summed.load(Relaxed),
            bytes_summed: self.bytes_summed.load(Relaxed),
            errors: self.errors.load(Relaxed),
        }
    }
    pub fn add_summed_file(&self, bytes: u64) {
        self.files_summed.fetch_add(1, Relaxed);
        self.bytes_summed.fetch_add(bytes, Relaxed);
    }
    pub fn add_dir(&self) {
        self.dirs_listed.fetch_add(1, Relaxed);
    }
    pub fn add_entry(&self) {
        self.entries_listed.fetch_add(1, Relaxed);
    }
}

#[derive(Default)]
struct Meta {
    authenticated: bool,
    label: String,
    current: Option<(&'static str, Instant)>,
    last_request: Option<Instant>,
}

pub struct Session {
    pub id: u64,
    pub peer: String,
    connected: Instant,
    connected_unix: u64,
    meta: Mutex<Meta>,
    pub counters: Counters,
}

impl Session {
    fn meta(&self) -> MutexGuard<'_, Meta> {
        self.meta.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn set_authenticated(&self) {
        self.meta().authenticated = true;
    }
    pub fn set_label(&self, raw: &str) {
        self.meta().label = sanitize_label(raw);
    }
    /// A request starts; the returned guard clears the current command when it is dropped.
    pub fn begin(&self, cmd: &'static str) -> Running<'_> {
        let now = Instant::now();
        {
            let mut m = self.meta();
            m.current = Some((cmd, now));
            m.last_request = Some(now);
        }
        self.counters.requests.fetch_add(1, Relaxed);
        Running(self)
    }
    pub fn totals(&self) -> Totals {
        self.counters.snapshot()
    }
    /// Count what a finished request produced, from its reply (never from its arguments).
    pub fn account(&self, cmd: &str, reply: &Result<Value, Fail>) {
        let c = &self.counters;
        let Ok(v) = reply else {
            c.errors.fetch_add(1, Relaxed);
            return;
        };
        match cmd {
            "list_dir" => {
                c.add_dir();
                c.entries_listed.fetch_add(v["entries"].as_array().map_or(0, |e| e.len() as u64), Relaxed);
            }
            "measure" => {
                c.files_measured.fetch_add(1, Relaxed);
                let size = v["size"].as_u64().unwrap_or(0);
                let n = if v.get("sha256").is_some() {
                    size
                } else if v.get("sha256_partial").is_some() {
                    2 * MIB
                } else {
                    b64_decoded_len(v["head_b64"].as_str().unwrap_or(""))
                };
                c.bytes_read.fetch_add(n, Relaxed);
            }
            "read_range" | "read_file" => {
                c.bytes_read.fetch_add(b64_decoded_len(v["data_b64"].as_str().unwrap_or("")), Relaxed);
            }
            _ => {}
        }
    }
    pub fn to_json(&self) -> Value {
        let now = Instant::now();
        let m = self.meta();
        let t = self.counters.snapshot();
        json!({
            "id": self.id, "peer": self.peer, "connected_at": self.connected_unix,
            "connected_secs": now.duration_since(self.connected).as_secs(),
            "authenticated": m.authenticated, "label": m.label,
            "command": m.current.map(|c| c.0), "command_secs": m.current.map(|c| now.duration_since(c.1).as_secs()),
            "last_request_secs": m.last_request.map(|t| now.duration_since(t).as_secs()),
            "requests": t.requests, "dirs_listed": t.dirs_listed, "entries_listed": t.entries_listed,
            "files_measured": t.files_measured, "bytes_read": t.bytes_read,
            "files_summed": t.files_summed, "bytes_summed": t.bytes_summed, "errors": t.errors,
        })
    }
}

fn b64_decoded_len(s: &str) -> u64 {
    let pad = s.bytes().rev().take_while(|&b| b == b'=').count();
    (s.len() / 4 * 3).saturating_sub(pad) as u64
}

pub struct Running<'a>(&'a Session);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.meta().current = None;
    }
}

#[derive(Default)]
pub struct Registry {
    next: AtomicU64,
    sessions: Mutex<HashMap<u64, Arc<Session>>>,
}

/// Keeps a session registered; dropping it (the connection closed, or its thread panicked) removes it.
pub struct Registered {
    pub session: Arc<Session>,
    registry: Arc<Registry>,
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.registry.map().remove(&self.session.id);
    }
}

impl Registry {
    fn map(&self) -> MutexGuard<'_, HashMap<u64, Arc<Session>>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn open(self: &Arc<Self>, peer: String) -> Registered {
        let session = Arc::new(Session {
            id: self.next.fetch_add(1, Relaxed) + 1,
            peer,
            connected: Instant::now(),
            connected_unix: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
            meta: Mutex::new(Meta::default()),
            counters: Counters::default(),
        });
        self.map().insert(session.id, session.clone());
        Registered { session, registry: self.clone() }
    }
    pub fn all(&self) -> Vec<Arc<Session>> {
        let mut v: Vec<Arc<Session>> = self.map().values().cloned().collect();
        v.sort_by_key(|s| s.id);
        v
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.map().len()
    }
    /// The reply of `activity`.
    pub fn activity(&self, self_id: u64) -> Value {
        json!({"ok": true, "self_id": self_id, "sessions": self.all().iter().map(|s| s.to_json()).collect::<Vec<_>>()})
    }
}

// --- the periodic status log ------------------------------------------------------------------------
/// `FILECAT_AGENT_STATUS_INTERVAL`: seconds, `0` turns the log off, unset is ten minutes.
pub fn parse_interval(text: Option<&str>) -> Result<u64, String> {
    match text.map(str::trim) {
        None | Some("") => Ok(600),
        Some(t) => t.parse::<u64>().map_err(|_| format!("FILECAT_AGENT_STATUS_INTERVAL must be a number of seconds (0 turns the status log off), not {t:?}")),
    }
}

fn human_duration(s: u64) -> String {
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        _ => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
    }
}

/// One status line for a session that was busy during the last `interval`; `None` when it was idle.
pub fn status_line(s: &Session, prev: &Totals, interval: Duration) -> Option<String> {
    let now = s.totals();
    let m = s.meta();
    if now.requests == prev.requests && m.current.is_none() {
        return None;
    }
    let secs = interval.as_secs_f64().max(1.0);
    let (df, db, de) = (now.files() - prev.files(), now.bytes_read - prev.bytes_read, now.entries_listed - prev.entries_listed);
    let label = if m.label.is_empty() { "(no label)" } else { m.label.as_str() };
    let cmd = match m.current {
        Some((c, since)) => format!("running {c} for {}", human_duration(since.elapsed().as_secs())),
        None => "idle now".to_string(),
    };
    Some(format!(
        "filecat-agent: session {} \"{label}\" from {}, connected {}, {cmd}: files +{df} ({} total), read +{:.2} GB ({:.2} GB total), entries +{de} ({} total), {:.1} files/s, requests +{} ({} total), {} errors",
        s.id,
        s.peer,
        human_duration(s.connected.elapsed().as_secs()),
        now.files(),
        db as f64 / GIB,
        now.bytes_read as f64 / GIB,
        now.entries_listed,
        df as f64 / secs,
        now.requests - prev.requests,
        now.requests,
        now.errors,
    ))
}

/// The one background thread: every `interval_secs`, one line per session that did something.
pub fn spawn_status_log(registry: Arc<Registry>, interval_secs: u64) {
    if interval_secs == 0 {
        return;
    }
    let interval = Duration::from_secs(interval_secs);
    std::thread::spawn(move || {
        let mut prev: HashMap<u64, Totals> = HashMap::new();
        loop {
            std::thread::sleep(interval);
            let sessions = registry.all();
            for s in &sessions {
                let before = prev.get(&s.id).copied().unwrap_or_default();
                if let Some(line) = status_line(s, &before, interval) {
                    println!("{line}");
                }
                prev.insert(s.id, s.totals());
            }
            prev.retain(|id, _| sessions.iter().any(|s| s.id == *id));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_lose_control_characters_and_are_capped() {
        assert_eq!(sanitize_label("scan \\\\nas3\\Apps by k@D"), "scan \\\\nas3\\Apps by k@D");
        assert_eq!(sanitize_label("a\nb\x1b[31mc\u{7f}\td"), "ab[31mcd");
        assert_eq!(sanitize_label("  padded  "), "padded");
        assert_eq!(sanitize_label(&"x".repeat(500)).chars().count(), 200);
        assert_eq!(sanitize_label(&"é".repeat(300)).chars().count(), 200);
    }

    #[test]
    fn sessions_register_and_leave_with_their_connection() {
        let reg = Arc::new(Registry::default());
        let a = reg.open("10.0.0.1:1".into());
        let b = reg.open("10.0.0.2:2".into());
        assert_eq!(reg.len(), 2);
        assert_ne!(a.session.id, b.session.id);
        let b_id = b.session.id;
        drop(a);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.all()[0].id, b_id);
        drop(b);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn counters_commands_and_replies_are_counted() {
        let reg = Arc::new(Registry::default());
        let r = reg.open("p".into());
        let s = &r.session;
        {
            let _run = s.begin("list_dir");
            assert_eq!(s.to_json()["command"], "list_dir");
            s.account("list_dir", &Ok(json!({"entries": [1, 2, 3]})));
        }
        assert!(s.to_json()["command"].is_null());
        s.account("measure", &Ok(json!({"size": 1000, "sha256": "x"})));
        s.account("measure", &Ok(json!({"size": 1000, "sha256_partial": "x"})));
        s.account("read_range", &Ok(json!({"data_b64": "AAAA"})));
        s.account("measure", &Err(Fail::bad("x")));
        s.counters.add_summed_file(7);
        let t = s.totals();
        assert_eq!((t.requests, t.dirs_listed, t.entries_listed, t.files_measured), (1, 1, 3, 2));
        assert_eq!((t.bytes_read, t.files_summed, t.bytes_summed, t.errors), (1000 + 2 * MIB + 3, 1, 7, 1));
    }

    #[test]
    fn activity_reply_has_the_documented_shape_and_no_paths() {
        let reg = Arc::new(Registry::default());
        let a = reg.open("10.0.0.1:4000".into());
        a.session.set_label("job nightly: scan\n");
        a.session.set_authenticated();
        let _b = reg.open("10.0.0.2:5".into());
        let _run = a.session.begin("sum_subtree");
        let v = reg.activity(a.session.id);
        assert_eq!(v["ok"], true);
        assert_eq!(v["self_id"], a.session.id);
        let list = v["sessions"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        let s = &list[0];
        assert_eq!((s["label"].as_str(), s["command"].as_str(), s["authenticated"].as_bool()), (Some("job nightly: scan"), Some("sum_subtree"), Some(true)));
        for k in ["id", "peer", "connected_at", "connected_secs", "command_secs", "last_request_secs", "requests", "dirs_listed", "entries_listed", "files_measured", "bytes_read", "files_summed", "bytes_summed", "errors"] {
            assert!(s.get(k).is_some(), "missing {k}");
        }
        assert!(s.as_object().unwrap().keys().all(|k| !k.contains("path") && !k.contains("arg")));
        assert_eq!(list[1]["authenticated"], false);
        assert!(list[1]["command"].is_null() && list[1]["last_request_secs"].is_null());
    }

    #[test]
    fn interval_parsing() {
        assert_eq!(parse_interval(None), Ok(600));
        assert_eq!(parse_interval(Some("")), Ok(600));
        assert_eq!(parse_interval(Some(" 30 ")), Ok(30));
        assert_eq!(parse_interval(Some("0")), Ok(0));
        assert!(parse_interval(Some("ten")).is_err());
        assert!(parse_interval(Some("-5")).is_err());
    }

    #[test]
    fn status_lines_only_for_sessions_that_did_something() {
        let reg = Arc::new(Registry::default());
        let r = reg.open("10.0.0.9:7".into());
        let s = &r.session;
        s.set_label("agents status");
        let before = s.totals();
        assert!(status_line(s, &before, Duration::from_secs(600)).is_none());
        let run = s.begin("measure");
        s.account("measure", &Ok(json!({"size": 1u64 << 30, "sha256": "x"})));
        let line = status_line(s, &before, Duration::from_secs(600)).unwrap();
        assert!(line.starts_with("filecat-agent: session 1 \"agents status\" from 10.0.0.9:7"), "{line}");
        assert!(line.contains("running measure for") && line.contains("files +1 (1 total)") && line.contains("read +1.00 GB"), "{line}");
        drop(run);
        let now = s.totals();
        assert!(status_line(s, &now, Duration::from_secs(600)).is_none());
    }
}
