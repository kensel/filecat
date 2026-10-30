//! The byte-level commands: `measure`, `read_range`, `read_file`, `statfs`, and the digests of
//! `src/filecat/hashing.py` (sha256 up to 64 MiB, `sha256_partial` above).

use crate::proto::*;
use crate::scope::{self, Scope};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

pub const MIB: u64 = 1024 * 1024;
pub const PARTIAL_CUTOFF: u64 = 64 * MIB;
pub const PARTIAL_EDGE: u64 = MIB;
pub const MAX_READ: i64 = 4 * 1024 * 1024;
pub const READ_FILE_DEFAULT: i64 = 256 * 1024;
const READ_FILE_DEADLINE: Duration = Duration::from_secs(10);

/// Open a regular file for reading without following a link in the last component and without
/// blocking on a FIFO. A directory, device, FIFO or link is `bad_request`.
pub fn open_regular(host: &Path) -> R<(File, std::fs::Metadata)> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(host)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(Fail::bad("not a regular file"));
    }
    Ok((f, m))
}

/// Read into `buf` from `offset` until it is full or the file ends; returns the bytes read.
pub fn pread_full(f: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match f.read_at(&mut buf[got..], offset + got as u64) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

fn changed() -> Fail {
    Fail::io("file changed while it was read (shorter than its size)")
}

fn sha256_full(f: &File, size: u64) -> R<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; MIB as usize];
    let mut off = 0u64;
    while off < size {
        let want = ((size - off).min(MIB)) as usize;
        let n = pread_full(f, &mut buf[..want], off)?;
        if n < want {
            return Err(changed());
        }
        h.update(&buf[..n]);
        off += n as u64;
    }
    Ok(hex(&h.finalize()))
}

/// First 1 MiB, last 1 MiB, size (u64 BE), mtime_ns (i64 BE, already floored).
pub fn sha256_partial(f: &File, size: u64, mtime_ns: i64) -> R<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; PARTIAL_EDGE as usize];
    if pread_full(f, &mut buf, 0)? < buf.len() {
        return Err(changed());
    }
    h.update(&buf);
    if pread_full(f, &mut buf, size.saturating_sub(PARTIAL_EDGE))? < buf.len() {
        return Err(changed());
    }
    h.update(&buf);
    h.update(size.to_be_bytes());
    h.update(mtime_ns.to_be_bytes());
    Ok(hex(&h.finalize()))
}

/// `{}`, `{"sha256"}` or `{"sha256_partial"}` per the policy table of hashing.py.
pub fn hash_policy(f: &File, size: u64, mtime_ns: i64, policy: &str) -> R<Option<(&'static str, String)>> {
    Ok(match policy {
        "none" => None,
        "full" => Some(("sha256", sha256_full(f, size)?)),
        _ if size == 0 => None,
        _ if size <= PARTIAL_CUTOFF => Some(("sha256", sha256_full(f, size)?)),
        _ => Some(("sha256_partial", sha256_partial(f, size, mtime_ns)?)),
    })
}

fn mtime_of(m: &std::fs::Metadata) -> i64 {
    floor100(m.mtime() * 1_000_000_000 + m.mtime_nsec())
}

fn denied(res: &scope::Resolved) -> Fail {
    Fail::refused(format!("{}: denied by agent policy", res.display))
}

/// The common front of the three content commands: scope, deny list, no link, regular file.
fn open_content(scope: &Scope, req: &Obj) -> R<(scope::Resolved, File, std::fs::Metadata)> {
    // The scope check resolved every link (`/proc/mounts` is one); the file is opened by its
    // resolved path, so a link in the last component can only be one swapped in since: O_NOFOLLOW.
    let res = scope.resolve_content(&req_path(req)?)?;
    let (f, m) = open_regular(&res.host)?;
    Ok((res, f, m))
}

pub fn measure(scope: &Scope, req: &Obj) -> R<Value> {
    let policy = opt_str(req, "hash")?.unwrap_or("auto");
    let head_bytes = opt_int(req, "head_bytes", 0, MIB as i64)?.unwrap_or(8192) as usize;
    if !matches!(policy, "auto" | "full" | "none") {
        return Err(Fail::bad("hash must be auto, full or none"));
    }
    let (res, f, m) = open_content(scope, req)?;
    if scope::redact_keys(&res.canon).is_some() {
        return Err(denied(&res)); // read_file only
    }
    let (size, mtime_ns) = (m.len(), mtime_of(&m));
    let mut head = vec![0u8; (size as usize).min(head_bytes.max(scope::SIGNATURE_WINDOW))];
    let n = pread_full(&f, &mut head, 0)?;
    if n < head.len() {
        return Err(changed());
    }
    if scope::private_key_head(&head) {
        return Ok(json!({"ok": true, "size": size, "mtime_ns": mtime_ns, "unread": "private_key"}));
    }
    head.truncate(head_bytes);
    let mut resp = json!({"ok": true, "size": size, "mtime_ns": mtime_ns, "head_b64": b64(&head)});
    if let Some((k, v)) = hash_policy(&f, size, mtime_ns, policy)? {
        resp[k] = Value::String(v);
    }
    Ok(resp)
}

pub fn read_range(scope: &Scope, req: &Obj) -> R<Value> {
    let offset = req.get("offset").and_then(Value::as_i64).filter(|o| *o >= 0);
    let len = req.get("len").and_then(Value::as_i64).filter(|l| *l >= 0);
    let (Some(offset), Some(len)) = (offset, len) else {
        return Err(Fail::bad("bad offset or len"));
    };
    if len > MAX_READ {
        return Err(Fail::bad(format!("len {len} is over the maximum {MAX_READ}")));
    }
    let (res, f, m) = open_content(scope, req)?;
    let mut head = [0u8; scope::SIGNATURE_WINDOW];
    let hn = pread_full(&f, &mut head, 0)?;
    if scope::redact_keys(&res.canon).is_some() || scope::private_key_head(&head[..hn]) {
        return Err(denied(&res));
    }
    let mut buf = vec![0u8; len as usize];
    let n = pread_full(&f, &mut buf, offset as u64)?;
    buf.truncate(n);
    let size = f.metadata().map(|m2| m2.len()).unwrap_or(m.len());
    let eof = offset as u64 + n as u64 >= size;
    Ok(json!({"ok": true, "data_b64": b64(&buf), "eof": eof}))
}

pub fn read_file(scope: &Scope, req: &Obj) -> R<Value> {
    let max = match req.get("max") {
        None | Some(Value::Null) => READ_FILE_DEFAULT,
        Some(v) => v.as_i64().filter(|m| (1..=MAX_READ).contains(m)).ok_or_else(|| Fail::bad(format!("max must be 1 to {MAX_READ}")))?,
    } as usize;
    let (res, f, m) = open_content(scope, req)?;
    let keys = scope::redact_keys(&res.canon);
    if keys.is_some() && m.len() > MAX_READ as u64 {
        return Err(Fail::io("file too large"));
    }
    // sysfs attributes of a dying disk can block: the read gets its own thread and a deadline
    let limit = if keys.is_some() { MAX_READ as usize + 1 } else { max + 1 };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut f = f;
        let mut data = vec![0u8; limit];
        let mut got = 0;
        let out = loop {
            if got == limit {
                break Ok(());
            }
            match f.read(&mut data[got..]) {
                Ok(0) => break Ok(()),
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        };
        data.truncate(got);
        let _ = tx.send(out.map(|_| data));
    });
    let mut data = match crate::clock::recv_timeout(&rx, READ_FILE_DEADLINE) {
        Ok(r) => r?,
        Err(_) => return Err(Fail::io("read timed out")),
    };
    match keys {
        Some(k) => data = scope::redact_credentials(&data, k),
        None => {
            if scope::private_key_head(&data[..data.len().min(scope::SIGNATURE_WINDOW)]) {
                return Err(denied(&res));
            }
        }
    }
    let truncated = data.len() > max;
    data.truncate(max);
    Ok(json!({"ok": true, "data_b64": b64(&data), "truncated": truncated}))
}

pub fn statfs(scope: &Scope, req: &Obj) -> R<Value> {
    let res = scope.resolve(&req_path(req)?)?;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(res.host.as_os_str().as_bytes()).map_err(|_| Fail::bad("path has a NUL"))?;
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut sv) } != 0 || unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let frsize = sv.f_frsize as u64;
    Ok(json!({
        "ok": true,
        "total_bytes": sv.f_blocks as u64 * frsize,
        "free_bytes": sv.f_bfree as u64 * frsize,
        "avail_bytes": sv.f_bavail as u64 * frsize,
        "block_size": frsize,
        "fs_type_id": (sf.f_type as u64) & 0xFFFF_FFFF,
        "flags": sv.f_flag as u64,
        "files": sv.f_files as u64,
        "files_free": sv.f_ffree as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::RootsSource;
    use std::io::Write;

    fn fixture(name: &str) -> (std::path::PathBuf, Scope) {
        let d = std::env::temp_dir().join(format!("fc-prims-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let root = std::fs::canonicalize(&d).unwrap();
        let scope = Scope::new(vec![root.to_string_lossy().into_owned()], RootsSource::Env, None).unwrap();
        (root, scope)
    }

    fn req(v: Value) -> Obj {
        v.as_object().unwrap().clone()
    }

    /// The byte at offset `i` of the generated vectors (tests/fixtures/hash_vectors.json).
    fn pattern_block(k: u64) -> Vec<u8> {
        (0..MIB).map(|i| ((i + (i >> 12) * 7 + k * 13) & 0xff) as u8).collect()
    }

    fn write_pattern(path: &Path, size: u64) {
        let mut f = File::create(path).unwrap();
        let mut left = size;
        let mut k = 0;
        while left > 0 {
            let block = pattern_block(k);
            let n = left.min(MIB) as usize;
            f.write_all(&block[..n]).unwrap();
            left -= n as u64;
            k += 1;
        }
    }

    #[test]
    fn hash_vectors_match_python() {
        let v: Value = serde_json::from_str(include_str!("../tests/fixtures/hash_vectors.json")).unwrap();
        let (root, _) = fixture("hash");
        let mut seen_partial = 0;
        for case in v["cases"].as_array().unwrap() {
            let size = case["size"].as_u64().unwrap();
            let mtime = case["mtime_ns"].as_i64().unwrap();
            let p = root.join(format!("f{size}"));
            write_pattern(&p, size);
            let f = File::open(&p).unwrap();
            for (policy, want) in case["expect"].as_object().unwrap() {
                let got = hash_policy(&f, size, floor100(mtime), policy).unwrap();
                match (want.as_object().unwrap().iter().next(), got) {
                    (None, None) => {}
                    (Some((k, w)), Some((gk, gv))) => {
                        assert_eq!((k.as_str(), w.as_str().unwrap()), (gk, gv.as_str()), "size {size} policy {policy}");
                        if gk == "sha256_partial" {
                            seen_partial += 1;
                        }
                    }
                    (w, g) => panic!("size {size} policy {policy}: want {w:?} got {g:?}"),
                }
            }
        }
        assert!(seen_partial >= 3);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn measure_returns_fstat_numbers_head_and_digest() {
        let (root, scope) = fixture("measure");
        std::fs::write(root.join("a.txt"), b"hello world").unwrap();
        let p = format!("{}/a.txt", root.display());
        let r = measure(&scope, &req(json!({"path": p, "head_bytes": 5}))).unwrap();
        assert_eq!(r["size"], 11);
        assert_eq!(r["head_b64"], b64(b"hello"));
        assert_eq!(r["sha256"], hex(&Sha256::digest(b"hello world")));
        assert_eq!(r["mtime_ns"].as_i64().unwrap() % 100, 0);
        let none = measure(&scope, &req(json!({"path": p, "hash": "none"}))).unwrap();
        assert!(none.get("sha256").is_none());
        std::fs::write(root.join("empty"), b"").unwrap();
        let ep = format!("{}/empty", root.display());
        assert!(measure(&scope, &req(json!({"path": ep}))).unwrap().get("sha256").is_none());
        assert_eq!(measure(&scope, &req(json!({"path": ep, "hash": "full"}))).unwrap()["sha256"], hex(&Sha256::digest(b"")));
        assert_eq!(measure(&scope, &req(json!({"path": p, "hash": "bogus"}))).err().unwrap().code, "bad_request");
        assert_eq!(measure(&scope, &req(json!({"path": p, "head_bytes": 2_000_000}))).err().unwrap().code, "bad_request");
        assert_eq!(measure(&scope, &req(json!({"path": root.to_string_lossy()}))).err().unwrap().code, "bad_request");
        assert_eq!(measure(&scope, &req(json!({"path": format!("{}/nope", root.display())}))).err().unwrap().code, "not_found");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn private_keys_and_denied_files_are_not_read() {
        let (root, scope) = fixture("keys");
        std::fs::write(root.join("id"), b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n").unwrap();
        std::fs::write(root.join(".env"), b"TOKEN=1\n").unwrap();
        std::fs::write(root.join(".env.example"), b"TOKEN=\n").unwrap();
        std::fs::write(root.join("pub"), b"ssh-ed25519 AAAA\n").unwrap();
        let p = |n: &str| format!("{}/{n}", root.display());
        let m = measure(&scope, &req(json!({"path": p("id")}))).unwrap();
        assert_eq!(m["unread"], "private_key");
        assert!(m.get("head_b64").is_none() && m.get("sha256").is_none());
        for cmd in [read_range(&scope, &req(json!({"path": p("id"), "offset": 0, "len": 10}))), read_file(&scope, &req(json!({"path": p("id")})))] {
            let e = cmd.err().unwrap();
            assert_eq!(e.code, "refused");
            assert!(e.msg.ends_with("denied by agent policy"));
        }
        assert_eq!(measure(&scope, &req(json!({"path": p(".env")}))).err().unwrap().code, "refused");
        assert_eq!(read_file(&scope, &req(json!({"path": p(".env")}))).err().unwrap().code, "refused");
        assert!(measure(&scope, &req(json!({"path": p(".env.example")}))).is_ok());
        assert!(read_file(&scope, &req(json!({"path": p("pub")}))).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_range_and_read_file_limits() {
        let (root, scope) = fixture("range");
        std::fs::write(root.join("f"), b"0123456789").unwrap();
        let p = format!("{}/f", root.display());
        let r = read_range(&scope, &req(json!({"path": p, "offset": 2, "len": 3}))).unwrap();
        assert_eq!((r["data_b64"].as_str().unwrap(), r["eof"].as_bool().unwrap()), (b64(b"234").as_str(), false));
        let r = read_range(&scope, &req(json!({"path": p, "offset": 7, "len": 100}))).unwrap();
        assert_eq!((r["data_b64"].as_str().unwrap(), r["eof"].as_bool().unwrap()), (b64(b"789").as_str(), true));
        let r = read_range(&scope, &req(json!({"path": p, "offset": 50, "len": 4}))).unwrap();
        assert_eq!((r["data_b64"].as_str().unwrap(), r["eof"].as_bool().unwrap()), ("", true));
        assert_eq!(read_range(&scope, &req(json!({"path": p, "offset": 0, "len": MAX_READ + 1}))).err().unwrap().code, "bad_request");
        assert_eq!(read_range(&scope, &req(json!({"path": p, "offset": -1, "len": 1}))).err().unwrap().code, "bad_request");
        let r = read_file(&scope, &req(json!({"path": p, "max": 4}))).unwrap();
        assert_eq!((r["data_b64"].as_str().unwrap(), r["truncated"].as_bool().unwrap()), (b64(b"0123").as_str(), true));
        let r = read_file(&scope, &req(json!({"path": p, "max": 10}))).unwrap();
        assert_eq!(r["truncated"], false);
        for bad in [0, MAX_READ + 1] {
            assert_eq!(read_file(&scope, &req(json!({"path": p, "max": bad}))).err().unwrap().code, "bad_request");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn links_inside_the_roots_resolve_and_links_out_are_refused() {
        let (root, scope) = fixture("links");
        let outside = std::env::temp_dir().join(format!("fc-prims-outside-{}", std::process::id()));
        std::fs::write(&outside, b"secret").unwrap();
        std::fs::write(root.join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("ln")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("out")).unwrap();
        std::os::unix::fs::symlink("nowhere", root.join("dangling")).unwrap();
        let p = |n: &str| format!("{}/{n}", root.display());
        // /proc/mounts is a link to self/mounts: the resolved file is read
        assert_eq!(read_file(&scope, &req(json!({"path": p("ln")}))).unwrap()["data_b64"], b64(b"x"));
        assert_eq!(measure(&scope, &req(json!({"path": p("ln")}))).unwrap()["size"], 1);
        assert_eq!(read_file(&scope, &req(json!({"path": p("out")}))).err().unwrap().code, "refused");
        assert_eq!(measure(&scope, &req(json!({"path": p("dangling")}))).err().unwrap().code, "bad_request");
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn statfs_reports_the_mount() {
        let (root, scope) = fixture("statfs");
        let r = statfs(&scope, &req(json!({"path": root.to_string_lossy()}))).unwrap();
        assert!(r["total_bytes"].as_u64().unwrap() > 0);
        assert!(r["block_size"].as_u64().unwrap() > 0);
        assert!(r["free_bytes"].as_u64() >= r["avail_bytes"].as_u64());
        let _ = std::fs::remove_dir_all(&root);
    }
}
