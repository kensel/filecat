//! `run` and `capabilities`: start a command of the allowlist, never anything else.
//! No shell; an absolute binary from the entry's candidates; an empty environment but
//! `LC_ALL=C`, `LANG=C` and a fixed `PATH`; stdin `/dev/null`; working directory `/`; output
//! caps; a timeout that kills the child's process group; at most two at once.

use crate::allowlist::{self, ArgKind, Entry};
use crate::proto::*;
use crate::scope::{Scope, RootsSource};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_RUNS: usize = 2;
pub const MAX_STDOUT: usize = 4 * 1024 * 1024;
pub const MAX_STDERR: usize = 64 * 1024;
const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const VERSION_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Default)]
pub struct Runner {
    running: AtomicUsize,
    versions: Mutex<HashMap<&'static str, Option<String>>>,
}

struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Output {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub ms: u128,
}

type Buf = Arc<Mutex<(Vec<u8>, bool)>>;

fn drain(mut r: impl Read + Send + 'static, cap: usize) -> (Buf, std::thread::JoinHandle<()>) {
    let buf: Buf = Arc::new(Mutex::new((Vec::new(), false)));
    let b = buf.clone();
    let h = std::thread::spawn(move || {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut g = b.lock().unwrap_or_else(|e| e.into_inner());
                    let room = cap.saturating_sub(g.0.len());
                    let take = room.min(n);
                    g.0.extend_from_slice(&chunk[..take]);
                    if take < n {
                        g.1 = true; // the rest is read and thrown away so the child never blocks
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    (buf, h)
}

/// Run `binary` with `args` under the fixed environment. Not an API for requests: callers pass
/// only allowlist entries and validated arguments.
pub fn exec(binary: &str, args: &[&str], timeout: Duration, out_cap: usize, err_cap: usize) -> std::io::Result<Output> {
    let started = Instant::now();
    let mut child = Command::new(binary)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", FIXED_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir("/")
        .process_group(0)
        .spawn()?;
    let pid = child.id() as i32;
    let (out, oh) = drain(child.stdout.take().expect("piped"), out_cap);
    let (err, eh) = drain(child.stderr.take().expect("piped"), err_cap);
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // a grandchild that kept the pipe open must not hold the reply for long
    let grace = Instant::now();
    while !(oh.is_finished() && eh.is_finished()) && grace.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(2));
    }
    let take = |b: &Buf| {
        let g = b.lock().unwrap_or_else(|e| e.into_inner());
        (g.0.clone(), g.1)
    };
    let ((stdout, stdout_truncated), (stderr, stderr_truncated)) = (take(&out), take(&err));
    Ok(Output {
        code: if timed_out { None } else { status.code() },
        signal: if timed_out { None } else { status.signal() },
        timed_out,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        ms: started.elapsed().as_millis(),
    })
}

/// The first existing, executable candidate of an entry.
pub fn resolve_binary(e: &Entry) -> Option<&'static str> {
    e.candidates.iter().copied().find(|c| {
        let p = std::path::Path::new(c);
        let Ok(cp) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return false };
        std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false) && unsafe { libc::access(cp.as_ptr(), libc::X_OK) } == 0
    })
}

// --- argument kinds ------------------------------------------------------------------------------------
fn bad_arg(kind: ArgKind, arg: &str, why: &str) -> Fail {
    Fail::refused(format!("{}: {arg:?} {why}", kind.name()))
}

/// A path argument is absolute and canonical: no leading `-`, newline, NUL, empty, `.` or `..`
/// component, or trailing slash.
fn plain_path(kind: ArgKind, arg: &str) -> R<()> {
    let ok = arg.starts_with('/')
        && !arg.contains(['\n', '\0'])
        && (arg == "/" || arg[1..].split('/').all(|c| !c.is_empty() && c != "." && c != ".."));
    if ok {
        Ok(())
    } else {
        Err(bad_arg(kind, arg, "is not an acceptable argument"))
    }
}

/// `\040`-style octal escapes of /proc/mounts and mountinfo.
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push(((b[i + 1] - b'0') << 6) | ((b[i + 2] - b'0') << 3) | (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The btrfs mount points of a `mountinfo` or `mounts` text.
pub fn btrfs_mounts(mountinfo: Option<&str>, mounts: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(t) = mountinfo {
        for line in t.lines() {
            if let Some((left, right)) = line.split_once(" - ") {
                let l: Vec<&str> = left.split(' ').collect();
                if l.len() > 4 && right.split(' ').next() == Some("btrfs") {
                    out.push(unescape_mount(l[4]));
                }
            }
        }
    }
    if out.is_empty() {
        if let Some(t) = mounts {
            for line in t.lines() {
                let p: Vec<&str> = line.split(' ').collect();
                if p.len() >= 3 && p[2] == "btrfs" {
                    out.push(unescape_mount(p[1]));
                }
            }
        }
    }
    out
}

fn whole_disk_name(arg: &str) -> Option<&str> {
    let name = arg.strip_prefix("/dev/")?;
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && !name.starts_with("loop")
        && !name.starts_with("ram")
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    ok.then_some(name)
}

fn mdstat_has(text: &str, name: &str) -> bool {
    text.lines().any(|l| l.strip_prefix(name).map_or(false, |r| r.starts_with(" :")))
}

fn zfs_pool_name(arg: &str) -> bool {
    let b = arg.as_bytes();
    !b.is_empty() && b.len() <= 255 && b[0].is_ascii_alphabetic() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-'))
}

/// Validate `arg` of `kind` against the host's state at this moment.
pub fn validate_arg(kind: ArgKind, arg: &str) -> R<()> {
    match kind {
        ArgKind::BtrfsMount => {
            plain_path(kind, arg)?;
            let mi = std::fs::read_to_string("/proc/self/mountinfo").ok();
            let m = std::fs::read_to_string("/proc/mounts").ok();
            if btrfs_mounts(mi.as_deref(), m.as_deref()).iter().any(|p| p == arg) {
                Ok(())
            } else {
                Err(bad_arg(kind, arg, "is not a btrfs mount point"))
            }
        }
        ArgKind::BlockDevice => {
            plain_path(kind, arg)?;
            let name = whole_disk_name(arg).ok_or_else(|| bad_arg(kind, arg, "is not a whole disk"))?;
            if std::fs::metadata(format!("/sys/block/{name}")).map(|m| m.is_dir()).unwrap_or(false) {
                Ok(())
            } else {
                Err(bad_arg(kind, arg, "is not a whole disk of /sys/block"))
            }
        }
        ArgKind::MdDevice => {
            plain_path(kind, arg)?;
            let name = arg.strip_prefix("/dev/").filter(|n| n.len() > 2 && n.starts_with("md") && n[2..].bytes().all(|c| c.is_ascii_digit()));
            let text = std::fs::read_to_string("/proc/mdstat").unwrap_or_default();
            match name {
                Some(n) if mdstat_has(&text, n) => Ok(()),
                _ => Err(bad_arg(kind, arg, "is not an array of /proc/mdstat")),
            }
        }
        ArgKind::ZfsPool => {
            if !zfs_pool_name(arg) {
                return Err(bad_arg(kind, arg, "is not a pool name"));
            }
            let list = allowlist::find("zpool_list").and_then(resolve_binary);
            let Some(bin) = list else { return Err(bad_arg(kind, arg, "cannot be checked: no zpool")) };
            let out = exec(bin, &["list", "-H", "-o", "name"], Duration::from_secs(10), MAX_STDOUT, MAX_STDERR).map_err(|_| bad_arg(kind, arg, "cannot be checked"))?;
            if String::from_utf8_lossy(&out.stdout).lines().any(|l| l.trim() == arg) {
                Ok(())
            } else {
                Err(bad_arg(kind, arg, "is not a pool of this host"))
            }
        }
    }
}

// --- the commands --------------------------------------------------------------------------------------
fn put_out(o: &mut Obj, key: &str, bytes: &[u8]) {
    put_text(o, key, bytes);
}

impl Runner {
    pub fn run(&self, req: &Obj) -> R<Value> {
        let id = match req.get("id") {
            Some(Value::String(s)) => s.as_str(),
            _ => return Err(Fail::bad("unknown allowlist id")),
        };
        let entry = allowlist::find(id).ok_or_else(|| Fail::bad(format!("unknown allowlist id {id:?}")))?;
        let arg = match req.get("arg") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(Fail::bad("arg must be a string")),
        };
        match (entry.kind, arg) {
            (None, Some(_)) => return Err(Fail::bad(format!("{id} takes no argument"))),
            (Some(k), None) => return Err(Fail::bad(format!("{id} needs an argument ({})", k.name()))),
            (Some(k), Some(a)) => validate_arg(k, a)?,
            (None, None) => {}
        }
        let binary = resolve_binary(entry).ok_or_else(|| Fail::new("not_found", format!("no binary for {id}")))?;
        if self.running.fetch_add(1, Ordering::SeqCst) >= MAX_RUNS {
            self.running.fetch_sub(1, Ordering::SeqCst);
            return Err(Fail::new("busy", "too many commands are running; retry later"));
        }
        let _slot = Slot(&self.running);
        let mut args: Vec<&str> = entry.args.to_vec();
        if let Some(a) = arg {
            args.push(a);
        }
        let out = exec(binary, &args, Duration::from_secs(entry.timeout_s), MAX_STDOUT, MAX_STDERR).map_err(|e| Fail::io(format!("{id}: {e}")))?;
        let mut o = Obj::new();
        o.insert("ok".into(), json!(true));
        o.insert("id".into(), json!(id));
        o.insert("binary".into(), json!(binary));
        o.insert("exit_code".into(), json!(out.code));
        if let Some(s) = out.signal {
            o.insert("signal".into(), json!(s));
        }
        o.insert("timed_out".into(), json!(out.timed_out));
        put_out(&mut o, "stdout", &out.stdout);
        put_out(&mut o, "stderr", &out.stderr);
        o.insert("stdout_truncated".into(), json!(out.stdout_truncated));
        o.insert("stderr_truncated".into(), json!(out.stderr_truncated));
        o.insert("duration_ms".into(), json!(out.ms as u64));
        Ok(Value::Object(o))
    }

    /// The first number a version probe prints, cached for the life of the process.
    fn version_of(&self, e: &'static Entry, binary: &str) -> Option<String> {
        let probe = e.version?;
        {
            let g = self.versions.lock().unwrap_or_else(|x| x.into_inner());
            if let Some(v) = g.get(e.id) {
                return v.clone();
            }
        }
        let v = exec(binary, probe, VERSION_TIMEOUT, 16 * 1024, 16 * 1024).ok().filter(|o| !o.timed_out).and_then(|o| {
            first_number(&String::from_utf8_lossy(&o.stdout)).or_else(|| first_number(&String::from_utf8_lossy(&o.stderr)))
        });
        self.versions.lock().unwrap_or_else(|x| x.into_inner()).insert(e.id, v.clone());
        v
    }

    pub fn capabilities(&self, scope: &Scope) -> Value {
        let mut sorted: Vec<&'static Entry> = allowlist::ENTRIES.iter().collect();
        sorted.sort_by_key(|e| e.id);
        let entries: Vec<Value> = sorted
            .into_iter()
            .map(|e| {
                let bin = resolve_binary(e);
                json!({"id": e.id, "available": bin.is_some(), "binary": bin,
                       "version": bin.and_then(|b| self.version_of(e, b)), "arg_kind": e.kind.map(ArgKind::name)})
            })
            .collect();
        json!({"ok": true, "allowlist_version": allowlist::ALLOWLIST_VERSION, "allowlist_sha256": allowlist::allowlist_sha256(),
               "deny_sha256": crate::scope::deny_sha256(), "allow_roots": scope.roots, "allow_roots_source": source_name(scope.source),
               "platform": "linux", "entries": entries})
    }
}

fn source_name(s: RootsSource) -> &'static str {
    s.as_str()
}

/// The first run of digits and dots in `text` ("smartctl 6.5 2016-05-07" gives "6.5").
pub fn first_number(text: &str) -> Option<String> {
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let rest = &text[start..];
    let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
    let n = rest[..end].trim_end_matches('.');
    (!n.is_empty()).then(|| n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_numbers() {
        assert_eq!(first_number("smartctl 6.5 2016-05-07 r4318"), Some("6.5".into()));
        assert_eq!(first_number("lsblk from util-linux 2.38.1"), Some("2.38.1".into()));
        assert_eq!(first_number("mdadm - v4.2 - 2021-12-30"), Some("4.2".into()));
        assert_eq!(first_number("btrfs-progs v6.6.3"), Some("6.6.3".into()));
        assert_eq!(first_number("none"), None);
    }

    #[test]
    fn mount_tables() {
        let mi = "36 35 0:30 / /volume1 rw,noatime shared:1 - btrfs /dev/mapper/vg1-volume_1 rw\n37 35 8:1 / /boot\\040efi rw - vfat /dev/sda1 rw\n38 35 0:31 / /mnt/x rw - ext4 /dev/sdb1 rw\n";
        assert_eq!(btrfs_mounts(Some(mi), None), vec!["/volume1"]);
        let m = "/dev/mapper/vg1-volume_1 /volume1 btrfs rw 0 0\n/dev/sdb1 /mnt/x ext4 rw 0 0\n/dev/x /with\\040space btrfs rw 0 0\n";
        assert_eq!(btrfs_mounts(None, Some(m)), vec!["/volume1", "/with space"]);
        assert!(btrfs_mounts(None, None).is_empty());
    }

    #[test]
    fn argument_kinds_reject_what_is_not_theirs() {
        for bad in ["-rf", "/volume1\n", "/volume1/../etc", "relative", "/a//b", "/a/", "/proc/self/../x"] {
            assert_eq!(validate_arg(ArgKind::BtrfsMount, bad).err().unwrap().code, "refused", "{bad}");
        }
        assert_eq!(validate_arg(ArgKind::BtrfsMount, "/definitely/not/btrfs").err().unwrap().code, "refused");
        for bad in ["/dev/..", "/dev/.", "/dev/loop0", "/dev/ram0", "/dev/sda1; id", "/etc/passwd", "sda", "/dev/", "/dev/sd a", "/dev/nonexistent-disk"] {
            assert_eq!(validate_arg(ArgKind::BlockDevice, bad).err().unwrap().code, "refused", "{bad}");
        }
        for bad in ["/dev/md", "/dev/mdx", "/dev/md0/../sda", "/dev/sda", "/dev/md99999"] {
            assert_eq!(validate_arg(ArgKind::MdDevice, bad).err().unwrap().code, "refused", "{bad}");
        }
        for bad in ["", "-x", "a b", "a;b", "a\nb", "1pool", "/abs"] {
            assert!(!zfs_pool_name(bad), "{bad}");
        }
        assert!(zfs_pool_name("tank-1.backup"));
        assert!(mdstat_has("Personalities : [raid1]\nmd0 : active raid1 sda1[0]\n", "md0"));
        assert!(!mdstat_has("md10 : active\n", "md1"));
        assert!(whole_disk_name("/dev/sata1").is_some() && whole_disk_name("/dev/nvme0n1").is_some());
    }

    #[test]
    fn exec_runs_with_a_fixed_environment_and_caps_output() {
        let o = exec("/usr/bin/env", &[], Duration::from_secs(5), 4096, 4096).or_else(|_| exec("/bin/env", &[], Duration::from_secs(5), 4096, 4096)).unwrap();
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        let mut vars: Vec<&str> = text.lines().collect();
        vars.sort();
        let path = format!("PATH={FIXED_PATH}");
        assert_eq!(vars, ["LANG=C", "LC_ALL=C", path.as_str()]);
        assert_eq!(o.code, Some(0));
        // output cap: the child is not blocked and the rest is dropped
        let o = exec("/bin/sh", &["-c", "head -c 100000 /dev/zero"], Duration::from_secs(5), 1000, 10).unwrap();
        assert_eq!((o.stdout.len(), o.stdout_truncated, o.code), (1000, true, Some(0)));
        // timeout kills the process group
        let t = Instant::now();
        let o = exec("/bin/sh", &["-c", "sleep 30 & sleep 30"], Duration::from_millis(200), 10, 10).unwrap();
        assert!(o.timed_out && o.code.is_none() && t.elapsed() < Duration::from_secs(5));
        // exit code and signal
        assert_eq!(exec("/bin/sh", &["-c", "exit 3"], Duration::from_secs(5), 10, 10).unwrap().code, Some(3));
        let o = exec("/bin/sh", &["-c", "kill -9 $$"], Duration::from_secs(5), 10, 10).unwrap();
        assert_eq!((o.code, o.signal), (None, Some(9)));
    }

    #[test]
    fn run_request_validation_and_limits() {
        let r = Runner::default();
        let q = |v: Value| r.run(v.as_object().unwrap());
        assert_eq!(q(json!({"id": "rm_rf"})).err().unwrap().code, "bad_request");
        assert_eq!(q(json!({})).err().unwrap().code, "bad_request");
        assert_eq!(q(json!({"id": "lsblk_json", "arg": "/dev/sda"})).err().unwrap().code, "bad_request");
        assert_eq!(q(json!({"id": "btrfs_usage"})).err().unwrap().code, "bad_request");
        assert_eq!(q(json!({"id": "btrfs_usage", "arg": "/etc"})).err().unwrap().code, "refused");
        assert_eq!(q(json!({"id": "smartctl_info", "arg": "/dev/../etc/passwd"})).err().unwrap().code, "refused");
        // a third concurrent command is busy
        r.running.store(MAX_RUNS, Ordering::SeqCst);
        if let Some(e) = allowlist::ENTRIES.iter().find(|e| e.kind.is_none() && resolve_binary(e).is_some()) {
            assert_eq!(q(json!({"id": e.id})).err().unwrap().code, "busy");
        }
    }

    #[test]
    fn capabilities_lists_every_entry_sorted() {
        let scope = Scope::new(vec!["/proc".into()], RootsSource::Env, None).unwrap();
        let c = Runner::default().capabilities(&scope);
        let ids: Vec<&str> = c["entries"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), allowlist::ENTRIES.len());
        let mut s = ids.clone();
        s.sort();
        assert_eq!(ids, s);
        assert_eq!(c["allow_roots"], json!(["/proc"]));
        assert_eq!(c["allow_roots_source"], "env");
        assert_eq!(c["deny_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(c["platform"], "linux");
    }
}
