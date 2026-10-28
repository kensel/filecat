//! Protocol plumbing shared by every command: the error type and its codes, request field
//! access, timestamps and the byte-string rule of docs/agent-protocol.md.

use base64::Engine;
use serde_json::{Map, Value};
use std::io;

pub type Obj = Map<String, Value>;
pub type R<T> = Result<T, Fail>;

/// A failed request: `code` is the protocol's, `msg` is for people.
#[derive(Debug)]
pub struct Fail {
    pub code: &'static str,
    pub msg: String,
}

impl Fail {
    pub fn new(code: &'static str, msg: impl Into<String>) -> Fail {
        Fail { code, msg: msg.into() }
    }
    pub fn bad(msg: impl Into<String>) -> Fail {
        Fail::new("bad_request", msg)
    }
    pub fn refused(msg: impl Into<String>) -> Fail {
        Fail::new("refused", msg)
    }
    pub fn io(msg: impl Into<String>) -> Fail {
        Fail::new("io", msg)
    }
    pub fn to_json(&self) -> Value {
        serde_json::json!({"ok": false, "error": self.msg, "code": self.code})
    }
}

/// The one mapping from an OS error to a protocol code.
pub fn code_of(e: &io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => "not_found",
        Some(libc::EACCES) | Some(libc::EPERM) => "permission_denied",
        Some(libc::ELOOP) => "bad_request",
        Some(_) => "io",
        None => match e.kind() {
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::PermissionDenied => "permission_denied",
            _ => "io",
        },
    }
}

impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Fail {
        Fail { code: code_of(&e), msg: e.to_string() }
    }
}

/// Timestamps are floored to 100 ns (`div_euclid`, so also before 1970).
pub fn floor100(ns: i64) -> i64 {
    ns.div_euclid(100) * 100
}

/// `X` with invalid sequences replaced, plus `X_b64` only when the bytes are not UTF-8.
pub fn put_text(obj: &mut Obj, key: &str, bytes: &[u8]) {
    obj.insert(key.to_string(), Value::String(String::from_utf8_lossy(bytes).into_owned()));
    if std::str::from_utf8(bytes).is_err() {
        obj.insert(format!("{key}_b64"), Value::String(b64(bytes)));
    }
}

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn unb64(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// The catalog's spelling of a name: each byte of an invalid UTF-8 sequence becomes U+F700 + b.
pub fn storage_name(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).unwrap_or(""));
                let n = e.error_len().unwrap_or(bad.len());
                for &b in &bad[..n] {
                    out.push(char::from_u32(0xF700 + b as u32).unwrap_or('\u{FFFD}'));
                }
                rest = &bad[n..];
            }
        }
    }
}

/// The path of a request: `path_b64` (exact bytes) wins over `path`.
pub fn req_path(req: &Obj) -> R<Vec<u8>> {
    if let Some(v) = req.get("path_b64") {
        let text = v.as_str().ok_or_else(|| Fail::bad("path_b64 must be a string"))?;
        return unb64(text).ok_or_else(|| Fail::bad("path_b64 is not Base64"));
    }
    match req.get("path") {
        Some(Value::String(s)) => Ok(s.as_bytes().to_vec()),
        _ => Err(Fail::bad("path must be absolute")),
    }
}

/// An optional integer field in `lo..=hi`; anything else is `bad_request`.
pub fn opt_int(req: &Obj, key: &str, lo: i64, hi: i64) -> R<Option<i64>> {
    match req.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_i64() {
            Some(n) if n >= lo && n <= hi => Ok(Some(n)),
            _ => Err(Fail::bad(format!("{key} must be an integer from {lo} to {hi}"))),
        },
    }
}

pub fn opt_bool(req: &Obj, key: &str, default: bool) -> R<bool> {
    match req.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(Fail::bad(format!("{key} must be true or false"))),
    }
}

pub fn opt_str<'a>(req: &'a Obj, key: &str) -> R<Option<&'a str>> {
    match req.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(Fail::bad(format!("{key} must be a string"))),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_toward_minus_infinity() {
        assert_eq!(floor100(1_234_567_899), 1_234_567_800);
        assert_eq!(floor100(-1), -100);
        assert_eq!(floor100(-100), -100);
        assert_eq!(floor100(0), 0);
    }

    #[test]
    fn storage_names_map_invalid_bytes_to_private_use() {
        assert_eq!(storage_name(b"abc"), "abc");
        assert_eq!(storage_name(b"a\xffb"), "a\u{F7FF}b");
        assert_eq!(storage_name("é".as_bytes()), "é");
        assert_eq!(storage_name(b"x\xe2\x82"), "x\u{F7E2}\u{F782}");
    }

    #[test]
    fn put_text_adds_b64_only_for_invalid_utf8() {
        let mut o = Obj::new();
        put_text(&mut o, "name", b"ok");
        assert!(!o.contains_key("name_b64"));
        put_text(&mut o, "name", b"a\xffb");
        assert_eq!(o["name_b64"], "Yf9i");
    }

    #[test]
    fn os_errors_map_to_codes() {
        assert_eq!(code_of(&io::Error::from_raw_os_error(libc::ENOENT)), "not_found");
        assert_eq!(code_of(&io::Error::from_raw_os_error(libc::EACCES)), "permission_denied");
        assert_eq!(code_of(&io::Error::from_raw_os_error(libc::EIO)), "io");
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
        assert_eq!(unhex("00ff10").unwrap(), vec![0, 255, 16]);
        assert!(unhex("0").is_none());
    }
}
