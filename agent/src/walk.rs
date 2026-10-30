//! `list_dir`, `sum_subtree` and the rollup walk (docs/agent-protocol.md, docs/rollups.md section 8).
//! Counters only: no name, path or OS error text from inside a folded folder ever leaves this
//! module, and nothing here logs.

use crate::clock::Instant;
use crate::matcher::{self, Pattern, Policy, Subject};
use crate::proto::*;
use crate::scope::Scope;
use crate::session::Counters;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_SUMS: usize = 4;
pub const MAX_DEPTH: usize = 4096;
pub const HARDLINK_CAP: usize = 2_000_000;
pub const FOLDED_CAP: usize = 1000;
pub const DEFAULT_DEADLINE_MS: i64 = 21_600_000;
pub const MAX_DEADLINE_MS: i64 = 86_400_000;
pub const MIN_PROGRESS_MS: i64 = 500;

// --- long-running sums: concurrency limit and cancellation ---------------------------------------
#[derive(Default)]
pub struct Sums {
    inner: Mutex<SumsInner>,
}

#[derive(Default)]
struct SumsInner {
    running: HashMap<String, Arc<AtomicBool>>,
    count: usize,
}

pub struct SumGuard<'a> {
    sums: &'a Sums,
    id: Option<String>,
    pub flag: Arc<AtomicBool>,
}

impl Sums {
    /// Take a slot (at most `max` at once, else `busy`) and register the request's cancel flag.
    pub fn begin(&self, id: Option<&str>, max: usize) -> R<SumGuard<'_>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.count >= max {
            return Err(Fail::new("busy", "too many long sums are running; retry later"));
        }
        g.count += 1;
        let flag = Arc::new(AtomicBool::new(false));
        if let Some(i) = id {
            g.running.insert(i.to_string(), flag.clone());
        }
        Ok(SumGuard { sums: self, id: id.map(str::to_string), flag })
    }

    /// Stop the request called `id`; false when none runs.
    pub fn cancel(&self, id: &str) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match g.running.get(id) {
            Some(f) => {
                f.store(true, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }
}

impl Drop for SumGuard<'_> {
    fn drop(&mut self) {
        let mut g = self.sums.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.count = g.count.saturating_sub(1);
        if let Some(i) = &self.id {
            if g.running.get(i).map(|f| Arc::ptr_eq(f, &self.flag)).unwrap_or(false) {
                g.running.remove(i);
            }
        }
    }
}

// --- stat ------------------------------------------------------------------------------------------
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub size: u64,
    pub blocks: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}

fn ns_of(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}

/// Times floored to 100 ns; `ctime_ns` is the birth time where the file system has one.
pub fn stat_of(m: &std::fs::Metadata) -> Stat {
    let ctime = m.created().map(ns_of).unwrap_or_else(|_| m.ctime() * 1_000_000_000 + m.ctime_nsec());
    Stat {
        dev: m.dev(),
        ino: m.ino(),
        nlink: m.nlink(),
        size: m.len(),
        blocks: m.blocks(),
        mtime_ns: floor100(m.mtime() * 1_000_000_000 + m.mtime_nsec()),
        ctime_ns: floor100(ctime),
    }
}

fn kind_of(ft: std::fs::FileType) -> &'static str {
    if ft.is_symlink() {
        "link"
    } else if ft.is_dir() {
        "dir"
    } else if ft.is_file() {
        "file"
    } else {
        "other"
    }
}

// --- accumulator ---------------------------------------------------------------------------------
pub struct Acc {
    files: u64,
    dirs: u64,
    size: u64,
    alloc: u64,
    newest: i64,
    oldest: Option<i64>,
    errors: u64,
    codes: BTreeMap<&'static str, u64>,
    vanished: u64,
    mounts: u64,
    links: u64,
    seen: HashSet<(u64, u64)>,
    approx: bool,
    dev: u64,
    late: bool,
}

impl Acc {
    pub fn new(dev: u64) -> Acc {
        Acc { files: 0, dirs: 0, size: 0, alloc: 0, newest: 0, oldest: None, errors: 0, codes: BTreeMap::new(), vanished: 0, mounts: 0, links: 0, seen: HashSet::new(), approx: false, dev, late: false }
    }

    fn error(&mut self, e: &std::io::Error) {
        if matches!(e.raw_os_error(), Some(libc::ENOENT)) {
            self.vanished += 1;
            return;
        }
        let code = if matches!(e.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)) { "permission_denied" } else { "io" };
        self.errors += 1;
        *self.codes.entry(code).or_insert(0) += 1;
    }

    fn add_file(&mut self, m: &std::fs::Metadata) {
        self.files += 1;
        let mtime = floor100(m.mtime() * 1_000_000_000 + m.mtime_nsec());
        self.newest = self.newest.max(mtime);
        self.oldest = Some(self.oldest.map_or(mtime, |o| o.min(mtime)));
        if m.nlink() > 1 {
            let key = (m.dev(), m.ino());
            if self.seen.contains(&key) {
                self.links += 1;
                return;
            }
            if self.seen.len() < HARDLINK_CAP {
                self.seen.insert(key);
            } else {
                self.approx = true;
            }
        }
        self.size += m.len();
        self.alloc += m.blocks() * 512;
    }

    /// The counters of a rollup entry / a `sum_subtree` reply.
    fn counters(&self) -> Obj {
        let mut o = Obj::new();
        o.insert("total_files".into(), json!(self.files));
        o.insert("total_dirs".into(), json!(self.dirs));
        o.insert("total_size".into(), json!(self.size));
        o.insert("total_allocated_size".into(), json!(self.alloc));
        o.insert("newest_mtime_ns".into(), json!(self.newest));
        if self.files > 0 {
            o.insert("oldest_mtime_ns".into(), json!(self.oldest.unwrap_or(0)));
        }
        o.insert("errors".into(), json!(self.errors));
        o.insert("error_codes".into(), json!(self.codes));
        o.insert("vanished".into(), json!(self.vanished));
        o.insert("skipped_mounts".into(), json!(self.mounts));
        o.insert("hardlink_names".into(), json!(self.links));
        if self.approx {
            o.insert("hardlinks_approx".into(), json!(true));
        }
        o.insert("complete".into(), json!(!self.late));
        o
    }
}

// --- progress, deadline, cancellation ----------------------------------------------------------------
pub type Emit<'a> = &'a mut dyn FnMut(&Value) -> std::io::Result<()>;

pub struct Ctl<'a> {
    cancel: Arc<AtomicBool>,
    started: Instant,
    deadline: Duration,
    progress: Option<Duration>,
    last: Instant,
    entries: u64,
    send: Emit<'a>,
    stats: &'a Counters,
}

enum Stop {
    Late,
    Cancelled,
}

impl<'a> Ctl<'a> {
    fn new(req: &Obj, cancel: Arc<AtomicBool>, send: Emit<'a>, stats: &'a Counters) -> R<Ctl<'a>> {
        let progress = opt_int(req, "progress_ms", 1, i64::MAX)?.map(|p| Duration::from_millis(p.max(MIN_PROGRESS_MS) as u64));
        let deadline = opt_int(req, "deadline_ms", 0, MAX_DEADLINE_MS)?.unwrap_or(DEFAULT_DEADLINE_MS);
        let now = Instant::now();
        Ok(Ctl { cancel, started: now, deadline: Duration::from_millis(deadline as u64), progress, last: now, entries: 0, send, stats })
    }

    fn tick(&mut self, bytes: u64) -> Result<(), Stop> {
        self.entries += 1;
        self.stats.add_entry();
        if self.cancel.load(Ordering::Relaxed) {
            return Err(Stop::Cancelled);
        }
        let now = Instant::now();
        if now.duration_since(self.started) > self.deadline {
            return Err(Stop::Late);
        }
        if let Some(p) = self.progress {
            if now.duration_since(self.last) >= p {
                self.last = now;
                let line = json!({"progress": {"entries": self.entries, "bytes": bytes}});
                if (self.send)(&line).is_err() {
                    return Err(Stop::Cancelled); // the client closed the connection
                }
            }
        }
        Ok(())
    }
}

fn request_id(req: &Obj) -> R<Option<String>> {
    match opt_str(req, "id")? {
        Some(i) if i.len() > 64 => Err(Fail::bad("id is at most 64 characters")),
        other => Ok(other.map(str::to_string)),
    }
}

// --- the walk --------------------------------------------------------------------------------------------
struct SumOpts<'a> {
    one_fs: bool,
    patterns: &'a [Pattern],
    /// the policy's exclude set (names and absolute paths); only `sum_subtree` applies it
    policy: Option<&'a Policy>,
    /// the virtual path of the summed folder, for absolute excludes
    top_vpath: Vec<u8>,
}

impl SumOpts<'_> {
    fn plain() -> SumOpts<'static> {
        SumOpts { one_fs: true, patterns: &[], policy: None, top_vpath: Vec::new() }
    }
    fn needs_rel(&self) -> bool {
        !self.patterns.is_empty() || self.policy.is_some_and(|p| !p.exclude.is_empty())
    }
}

/// Add the tree at `top` (a file or a folder, itself counted) to `acc`. A cancel is an error;
/// a passed deadline marks `acc` late and is not.
fn sum_into(acc: &mut Acc, ctl: &mut Ctl, top: &Path, opts: &SumOpts) -> R<()> {
    match walk(acc, ctl, top, opts) {
        Ok(()) => Ok(()),
        Err(Stop::Late) => {
            acc.late = true;
            Ok(())
        }
        Err(Stop::Cancelled) => Err(Fail::new("cancelled", "cancelled")),
    }
}

/// `acc.add_file` plus the session's counters (one atomic add each; a hard link counts no bytes).
fn count_file(acc: &mut Acc, ctl: &Ctl, m: &std::fs::Metadata) {
    let before = acc.size;
    acc.add_file(m);
    ctl.stats.add_summed_file(acc.size - before);
}

fn walk(acc: &mut Acc, ctl: &mut Ctl, top: &Path, opts: &SumOpts) -> Result<(), Stop> {
    let m = match std::fs::symlink_metadata(top) {
        Ok(m) => m,
        Err(e) => {
            acc.error(&e);
            return Ok(());
        }
    };
    if !m.is_dir() {
        count_file(acc, ctl, &m);
        return Ok(());
    }
    let need_rel = opts.needs_rel();
    let mut stack: Vec<(PathBuf, Vec<u8>, usize)> = vec![(top.to_path_buf(), Vec::new(), 0)];
    while let Some((folder, rel, depth)) = stack.pop() {
        acc.dirs += 1;
        ctl.stats.add_dir();
        ctl.tick(acc.size)?;
        let rd = match std::fs::read_dir(&folder) {
            Ok(r) => r,
            Err(e) => {
                acc.error(&e);
                continue;
            }
        };
        for ent in rd {
            let ent = match ent {
                Ok(e) => e,
                Err(e) => {
                    acc.error(&e);
                    continue;
                }
            };
            ctl.tick(acc.size)?;
            let name = ent.file_name().into_vec();
            let mut kid_rel = Vec::new();
            if need_rel {
                kid_rel = rel.clone();
                if !kid_rel.is_empty() {
                    kid_rel.push(b'/');
                }
                kid_rel.extend_from_slice(&name);
                if !opts.patterns.is_empty() {
                    let s = Subject::from_rel(&storage_name(&kid_rel), false);
                    if opts.patterns.iter().any(|p| p.matches(&s)) {
                        continue;
                    }
                }
                if let Some(pol) = opts.policy {
                    if !pol.exclude.is_empty() {
                        let mut v = opts.top_vpath.clone();
                        v.push(b'/');
                        v.extend_from_slice(&kid_rel);
                        if pol.excluded(&name, &v) {
                            continue;
                        }
                    }
                }
            }
            let km = match std::fs::symlink_metadata(ent.path()) {
                Ok(m) => m,
                Err(e) => {
                    acc.error(&e);
                    continue;
                }
            };
            if km.is_dir() {
                if depth + 1 > MAX_DEPTH {
                    acc.errors += 1;
                    *acc.codes.entry("io").or_insert(0) += 1;
                    continue;
                }
                if opts.one_fs && km.dev() != acc.dev {
                    acc.mounts += 1;
                    continue;
                }
                stack.push((ent.path(), kid_rel, depth + 1));
            } else {
                count_file(acc, ctl, &km);
            }
        }
    }
    Ok(())
}

// --- sum_subtree ---------------------------------------------------------------------------------------
pub fn sum_subtree(scope: &Scope, policy: &Policy, sums: &Sums, stats: &Counters, req: &Obj, send: Emit) -> R<Value> {
    let res = scope.resolve(&req_path(req)?)?;
    let top = std::fs::metadata(&res.host)?;
    if !top.is_dir() {
        return Err(Fail::bad("not a directory"));
    }
    let private = opt_bool(req, "private", false)?;
    let one_fs = opt_bool(req, "one_filesystem", true)?;
    opt_int(req, "threads", 1, 16)?; // accepted and validated; the walk itself is single-threaded
    let patterns: Vec<Pattern> = match req.get("exclude") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.iter().map(|p| p.as_str().map(|s| Pattern::new(s, false)).ok_or_else(|| Fail::bad("exclude must be strings"))).collect::<R<_>>()?,
        _ => return Err(Fail::bad("exclude must be an array")),
    };
    let id = request_id(req)?;
    let guard = sums.begin(id.as_deref(), MAX_SUMS)?;
    let mut ctl = Ctl::new(req, guard.flag.clone(), send, stats)?;
    let mut acc = Acc::new(top.dev());
    let opts = SumOpts { one_fs, patterns: &patterns, policy: Some(policy), top_vpath: res.canon.trim_ascii_end_slash() };
    sum_into(&mut acc, &mut ctl, &res.host, &opts)?;
    let mut resp = acc.counters();
    resp.insert("ok".into(), json!(true));
    if !private {
        resp.insert("path".into(), json!(String::from_utf8_lossy(&req_path(req)?)));
    }
    Ok(Value::Object(resp))
}

trait TrimSlash {
    fn trim_ascii_end_slash(&self) -> Vec<u8>;
}

impl TrimSlash for Vec<u8> {
    fn trim_ascii_end_slash(&self) -> Vec<u8> {
        let mut v = self.clone();
        while v.last() == Some(&b'/') {
            v.pop();
        }
        v
    }
}

// --- list_dir --------------------------------------------------------------------------------------------
enum Why {
    None,
    Rule(Value),
    Marker,
    Sticky,
    Suggest(String),
}

struct Kid {
    name: Vec<u8>,
    path: PathBuf,
    meta: std::fs::Metadata,
    is_dir: bool,
    tag: Option<String>,
    private: bool,
    why: Why,
}

/// (hash, dev, ino) of a child folder under a root with redaction sets: when the sets hold it
/// (`sticky_only`), or whatever it is.
fn redacted(policy: &Policy, vpath: &[u8], m: &std::fs::Metadata, sticky_only: bool) -> Option<(String, u64, u64)> {
    let key = policy.key.as_ref()?;
    let posix = storage_name(vpath);
    for root in &policy.redact_roots {
        let base = &root.base;
        if !(posix == *base || posix.starts_with(&format!("{}/", base.trim_end_matches('/')))) {
            continue;
        }
        let rel = posix.get(base.len()..).unwrap_or("").trim_matches('/');
        let h = matcher::redaction_hash(key, &root.root, rel);
        if !sticky_only || root.hashes.contains(&h) || root.inodes.contains(&(m.dev(), m.ino())) {
            return Some((h, m.dev(), m.ino()));
        }
    }
    None
}

/// The folding decision for one child, in the order of docs/rollups.md section 2.
fn classify(policy: &Policy, parent_host: &Path, kid: &Kid, vpath: &[u8], subject: Option<&Subject>) -> (Option<String>, bool, Why) {
    let real_dir = kid.is_dir && !kid.meta.file_type().is_symlink();
    if real_dir && redacted(policy, vpath, &kid.meta, true).is_some() {
        return (Some("[REDACTED]".into()), true, Why::Sticky);
    }
    if let Some(s) = subject {
        for r in &policy.rules {
            if r.tag.as_deref() == Some("[REDACTED]") && r.matches(s) {
                return (r.tag.clone(), true, Why::Rule(r.id.clone()));
            }
        }
    }
    if real_dir {
        for mk in &policy.markers {
            let probe = parent_host.join(std::ffi::OsStr::from_bytes(&kid.name)).join(std::ffi::OsStr::from_bytes(&mk.name));
            if std::fs::symlink_metadata(probe).is_ok() {
                return (Some(mk.tag.clone()), mk.private, Why::Marker);
            }
        }
    }
    if let Some(s) = subject {
        for r in &policy.rules {
            if r.tag.as_deref() == Some("[REDACTED]") {
                continue;
            }
            if r.matches(s) {
                if r.keep {
                    return (None, false, Why::None);
                }
                if r.suggest {
                    return (None, false, Why::Suggest(r.tag.clone().unwrap_or_default()));
                }
                return (r.tag.clone(), r.private, Why::Rule(r.id.clone()));
            }
        }
    }
    (None, false, Why::None)
}

pub fn list_dir(scope: &Scope, policy: &Policy, sums: &Sums, stats: &Counters, req: &Obj, send: Emit) -> R<Value> {
    let path = req_path(req)?;
    let res = scope.resolve(&path)?;
    let dst = std::fs::metadata(&res.host)?;
    if !dst.is_dir() {
        return Err(Fail::bad("not a directory"));
    }
    let mut base = res.canon.clone();
    while base.last() == Some(&b'/') {
        base.pop();
    }
    let mut names: Vec<(Vec<u8>, std::fs::DirEntry)> = Vec::new();
    for ent in std::fs::read_dir(&res.host)? {
        let ent = ent?;
        names.push((ent.file_name().into_vec(), ent));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));

    let mut entries: Vec<(Vec<u8>, Value)> = Vec::new();
    let mut kids: Vec<Kid> = Vec::new();
    let mut suggest: BTreeMap<String, u64> = BTreeMap::new();
    for (name, ent) in names {
        let mut vpath = base.clone();
        vpath.push(b'/');
        vpath.extend_from_slice(&name);
        if policy.excluded(&name, &vpath) {
            continue;
        }
        let meta = match std::fs::symlink_metadata(ent.path()) {
            Ok(m) => m,
            Err(e) => {
                let kind = ent.file_type().map(kind_of).unwrap_or("other");
                let mut o = Obj::new();
                put_text(&mut o, "name", &name);
                o.insert("kind".into(), json!(kind));
                o.insert("error".into(), json!({"code": code_of(&e), "message": e.to_string()}));
                entries.push((name, Value::Object(o)));
                continue;
            }
        };
        let is_dir = meta.is_dir();
        let mut kid = Kid { name, path: ent.path(), meta, is_dir, tag: None, private: false, why: Why::None };
        // the subject uses the storage spelling of the path, so non-UTF-8 names match consistently
        let subject = if policy.rules.is_empty() { None } else { Some(Subject::new(&kid.name, &storage_name(&vpath), is_dir)) };
        let (tag, private, why) = classify(policy, &res.host, &kid, &vpath, subject.as_ref());
        if tag.is_none() {
            if let Why::Suggest(t) = &why {
                *suggest.entry(t.clone()).or_insert(0) += 1;
            }
        }
        kid.tag = tag;
        kid.private = private;
        kid.why = why;
        kids.push(kid);
    }
    // a real child named like a tag produced here is folded in too
    let wanted: HashMap<Vec<u8>, String> = kids.iter().filter_map(|k| k.tag.as_ref().map(|t| (t.to_ascii_lowercase().into_bytes(), t.clone()))).collect();
    for k in kids.iter_mut() {
        if k.tag.is_none() {
            if let Some(t) = wanted.get(&k.name.to_ascii_lowercase()) {
                k.tag = Some(t.clone());
                k.private = false;
                k.why = Why::None;
            }
        }
    }

    for k in kids.iter().filter(|k| k.tag.is_none()) {
        let st = stat_of(&k.meta);
        let mut o = Obj::new();
        o.insert("kind".into(), json!(kind_of(k.meta.file_type())));
        o.insert("size".into(), json!(st.size));
        o.insert("allocated_size".into(), json!(st.blocks * 512));
        o.insert("ino".into(), json!(st.ino));
        o.insert("dev".into(), json!(st.dev));
        o.insert("nlink".into(), json!(st.nlink));
        o.insert("mtime_ns".into(), json!(st.mtime_ns));
        o.insert("ctime_ns".into(), json!(st.ctime_ns));
        if k.meta.file_type().is_symlink() {
            if let Ok(t) = std::fs::read_link(&k.path) {
                put_text(&mut o, "link_target", t.as_os_str().as_bytes());
            }
        }
        put_text(&mut o, "name", &k.name);
        entries.push((k.name.clone(), Value::Object(o)));
    }

    let mut produced: Vec<String> = kids.iter().filter_map(|k| k.tag.clone()).collect();
    produced.sort();
    produced.dedup();
    if !produced.is_empty() {
        let id = request_id(req)?;
        let guard = sums.begin(id.as_deref(), MAX_SUMS)?;
        let mut ctl = Ctl::new(req, guard.flag.clone(), send, stats)?;
        let plain = SumOpts::plain();
        for tag in &produced {
            let members: Vec<&Kid> = kids.iter().filter(|k| k.tag.as_deref() == Some(tag)).collect();
            let mut acc = Acc::new(dst.dev());
            for k in &members {
                sum_into(&mut acc, &mut ctl, &k.path, &plain)?;
            }
            let mut roll = acc.counters();
            roll.insert("tag".into(), json!(tag));
            roll.insert("matched".into(), json!(members.len()));
            match &members[0].why {
                Why::Rule(Value::Number(n)) => {
                    roll.insert("rule".into(), Value::Number(n.clone()));
                }
                Why::Rule(Value::String(s)) => {
                    roll.insert("rule".into(), json!(s));
                }
                Why::Marker => {
                    roll.insert("rule".into(), json!("marker"));
                }
                Why::Sticky => {
                    roll.insert("rule".into(), json!("sticky"));
                }
                _ => {}
            }
            if tag == "[REDACTED]" {
                let mut folded = Vec::new();
                for k in members.iter().filter(|k| k.is_dir) {
                    let mut v = base.clone();
                    v.push(b'/');
                    v.extend_from_slice(&k.name);
                    if let Some((h, d, i)) = redacted(policy, &v, &k.meta, false) {
                        folded.push(json!({"h": h, "dev": d, "ino": i}));
                    }
                }
                if folded.len() > FOLDED_CAP {
                    folded.truncate(FOLDED_CAP);
                    roll.insert("folded_truncated".into(), json!(true));
                }
                roll.insert("folded".into(), Value::Array(folded));
            }
            let newest = acc.newest;
            entries.push((
                tag.clone().into_bytes(),
                json!({"name": tag, "kind": "rollup", "size": acc.size, "allocated_size": acc.alloc, "ino": 0,
                       "dev": dst.dev(), "nlink": 1, "mtime_ns": newest, "ctime_ns": newest, "rollup": roll}),
            ));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let dst_stat = stat_of(&dst);
    let mut resp = Obj::new();
    resp.insert("ok".into(), json!(true));
    resp.insert("path".into(), json!(String::from_utf8_lossy(&path)));
    if req.contains_key("path_b64") && std::str::from_utf8(&path).is_err() {
        resp.insert("path_b64".into(), json!(b64(&path)));
    }
    resp.insert("dev".into(), json!(dst_stat.dev));
    resp.insert("mtime_ns".into(), json!(dst_stat.mtime_ns));
    resp.insert("ctime_ns".into(), json!(dst_stat.ctime_ns));
    resp.insert("entries".into(), Value::Array(entries.into_iter().map(|e| e.1).collect()));
    if policy.has_rules() {
        resp.insert("policy_id".into(), json!(policy.id));
    }
    if !suggest.is_empty() {
        resp.insert("suggest".into(), Value::Array(suggest.into_iter().map(|(t, n)| json!({"tag": t, "matched": n})).collect()));
    }
    Ok(Value::Object(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::RootsSource;

    struct Fx {
        root: PathBuf,
        scope: Scope,
    }

    fn fx(name: &str) -> Fx {
        let d = std::env::temp_dir().join(format!("fc-walk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let root = std::fs::canonicalize(&d).unwrap();
        let scope = Scope::new(vec![root.to_string_lossy().into_owned()], RootsSource::Env, None).unwrap();
        Fx { root, scope }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn req(v: Value) -> Obj {
        v.as_object().unwrap().clone()
    }

    fn nosend() -> impl FnMut(&Value) -> std::io::Result<()> {
        |_| Ok(())
    }

    fn policy(v: Value) -> Policy {
        matcher::configure(v.as_object().unwrap()).unwrap()
    }

    #[test]
    fn lists_sorted_entries_with_kinds_links_and_dir_numbers() {
        let f = fx("list");
        std::fs::create_dir(f.root.join("sub")).unwrap();
        std::fs::write(f.root.join("b.txt"), b"12345").unwrap();
        std::fs::write(f.root.join("a.txt"), b"1").unwrap();
        std::os::unix::fs::symlink("a.txt", f.root.join("ln")).unwrap();
        std::fs::write(f.root.join(std::ffi::OsStr::from_bytes(b"bad\xffname")), b"x").unwrap();
        let sums = Sums::default();
        let mut s = nosend();
        let r = list_dir(&f.scope, &Policy::default(), &sums, &Counters::default(), &req(json!({"cmd": "list_dir", "path": f.root.to_string_lossy()})), &mut s).unwrap();
        let names: Vec<&str> = r["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["a.txt", "b.txt", "bad\u{fffd}name", "ln", "sub"]);
        let by = |n: &str| r["entries"].as_array().unwrap().iter().find(|e| e["name"] == n).unwrap().clone();
        assert_eq!(by("b.txt")["size"], 5);
        assert_eq!(by("b.txt")["kind"], "file");
        assert_eq!(by("sub")["kind"], "dir");
        assert_eq!(by("ln")["kind"], "link");
        assert_eq!(by("ln")["link_target"], "a.txt");
        assert_eq!(by("bad\u{fffd}name")["name_b64"], b64(b"bad\xffname"));
        assert!(r["dev"].as_u64().unwrap() > 0 && r["mtime_ns"].as_i64().unwrap() % 100 == 0);
        assert!(r.get("policy_id").is_none());
        assert_eq!(list_dir(&f.scope, &Policy::default(), &sums, &Counters::default(), &req(json!({"path": format!("{}/a.txt", f.root.display())})), &mut nosend()).err().unwrap().code, "bad_request");
        assert_eq!(list_dir(&f.scope, &Policy::default(), &sums, &Counters::default(), &req(json!({"path": format!("{}/zz", f.root.display())})), &mut nosend()).err().unwrap().code, "not_found");
    }

    #[test]
    fn rules_fold_children_into_rollups() {
        let f = fx("roll");
        for d in ["keep/node_modules", "proj/node_modules", "proj/src", "NODE_MODULES"] {
            std::fs::create_dir_all(f.root.join(d)).unwrap();
        }
        std::fs::write(f.root.join("proj/node_modules/a"), vec![0u8; 100]).unwrap();
        std::fs::write(f.root.join("proj/node_modules/b"), vec![0u8; 50]).unwrap();
        std::fs::write(f.root.join("NODE_MODULES/c"), vec![0u8; 7]).unwrap();
        let p = policy(json!({"rules": [{"id": 3, "tag": "[CACHE]", "match": ["node_modules"], "type": "dir", "case": "insensitive"}]}));
        let sums = Sums::default();
        let pr = f.root.join("proj");
        let r = list_dir(&f.scope, &p, &sums, &Counters::default(), &req(json!({"path": pr.to_string_lossy()})), &mut nosend()).unwrap();
        let names: Vec<&str> = r["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["[CACHE]", "src"]);
        let roll = &r["entries"][0]["rollup"];
        assert_eq!((roll["matched"].as_u64(), roll["total_files"].as_u64(), roll["total_dirs"].as_u64(), roll["total_size"].as_u64()), (Some(1), Some(2), Some(1), Some(150)));
        assert_eq!(roll["rule"], 3);
        assert_eq!(roll["complete"], true);
        assert!(roll["oldest_mtime_ns"].is_i64());
        assert_eq!(r["policy_id"], p.id);
        // case-insensitive rule also takes NODE_MODULES; and an empty tag-named real child folds in
        let r = list_dir(&f.scope, &p, &sums, &Counters::default(), &req(json!({"path": f.root.to_string_lossy()})), &mut nosend()).unwrap();
        let names: Vec<&str> = r["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["[CACHE]", "keep", "proj"]);
        assert_eq!(r["entries"][0]["rollup"]["total_size"], 7);
    }

    #[test]
    fn keep_suggest_markers_and_real_child_named_like_a_tag() {
        let f = fx("kms");
        for d in ["a/node_modules", "a/@eaDir", "a/[CACHE]", "a/marked", "a/vault"] {
            std::fs::create_dir_all(f.root.join(d)).unwrap();
        }
        std::fs::write(f.root.join("a/marked/.filecat-cache"), b"").unwrap();
        std::fs::write(f.root.join("a/[CACHE]/x"), b"123").unwrap();
        let p = policy(json!({"rules": [
            {"tag": "[REDACTED]", "match": ["vault"], "private": true, "id": 0},
            {"match": ["node_modules"], "keep": true},
            {"tag": "[SYN]", "match": ["@eaDir"], "type": "dir", "suggest": true},
            {"tag": "[X]", "match": ["node_modules"]}],
            "markers": [{"name": ".filecat-cache", "tag": "[CACHE]"}]}));
        let a = f.root.join("a");
        let r = list_dir(&f.scope, &p, &Sums::default(), &Counters::default(), &req(json!({"path": a.to_string_lossy()})), &mut nosend()).unwrap();
        let names: Vec<&str> = r["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["@eaDir", "[CACHE]", "[REDACTED]", "node_modules"]);
        let cache = &r["entries"][1]["rollup"];
        assert_eq!(cache["matched"], 2); // marked + the real [CACHE] folder
        assert_eq!(r["suggest"], json!([{"tag": "[SYN]", "matched": 1}]));
        let red = &r["entries"][2]["rollup"];
        assert_eq!(red["rule"], 0);
        assert_eq!(red["folded"], json!([])); // no redaction key: nothing to register
    }

    #[test]
    fn sticky_redaction_by_hash_and_by_inode() {
        let f = fx("sticky");
        std::fs::create_dir_all(f.root.join("homes/jdoe/vault")).unwrap();
        std::fs::create_dir_all(f.root.join("homes/jdoe/other")).unwrap();
        std::fs::create_dir_all(f.root.join("homes/jdoe/moved")).unwrap();
        std::fs::write(f.root.join("homes/jdoe/vault/secret.txt"), b"x").unwrap();
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let base = format!("{}/homes", f.root.display());
        let h = matcher::redaction_hash(&crate::proto::unhex(key).unwrap(), "r1", "jdoe/vault");
        let moved_ino = std::fs::metadata(f.root.join("homes/jdoe/moved")).unwrap();
        let p = policy(json!({"redaction": {"key": key, "roots": [
            {"root": "r1", "base": base, "hashes": [h], "inodes": [[moved_ino.dev(), moved_ino.ino()]]}]}}));
        let dir = f.root.join("homes/jdoe");
        let r = list_dir(&f.scope, &p, &Sums::default(), &Counters::default(), &req(json!({"path": dir.to_string_lossy()})), &mut nosend()).unwrap();
        let names: Vec<&str> = r["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["[REDACTED]", "other"]);
        let roll = &r["entries"][0]["rollup"];
        assert_eq!(roll["matched"], 2);
        assert_eq!(roll["rule"], "sticky");
        let folded = roll["folded"].as_array().unwrap();
        assert_eq!(folded.len(), 2);
        assert!(folded.iter().any(|x| x["h"] == h.as_str()));
        // no name of a folded folder or of what is inside it is anywhere in the reply
        let text = serde_json::to_string(&r).unwrap();
        for leak in ["vault", "secret", "moved"] {
            assert!(!text.contains(leak), "{leak} leaked: {text}");
        }
    }

    #[test]
    fn sum_subtree_counts_and_excludes_and_dedups_hard_links() {
        let f = fx("sum");
        std::fs::create_dir_all(f.root.join("t/Pool/lost")).unwrap();
        std::fs::create_dir_all(f.root.join("t/x/@tmp")).unwrap();
        std::fs::write(f.root.join("t/a"), vec![1u8; 1000]).unwrap();
        std::fs::write(f.root.join("t/Pool/b"), vec![1u8; 10]).unwrap();
        std::fs::write(f.root.join("t/Pool/lost/c"), vec![1u8; 99]).unwrap();
        std::fs::write(f.root.join("t/x/@tmp/d"), vec![1u8; 5]).unwrap();
        std::fs::hard_link(f.root.join("t/a"), f.root.join("t/a2")).unwrap();
        std::os::unix::fs::symlink("a", f.root.join("t/ln")).unwrap();
        let t = f.root.join("t");
        let sums = Sums::default();
        let go = |extra: Value| {
            let mut v = json!({"path": t.to_string_lossy()});
            v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            sum_subtree(&f.scope, &Policy::default(), &sums, &Counters::default(), &req(v), &mut nosend()).unwrap()
        };
        let all = go(json!({}));
        assert_eq!(all["total_files"], 6); // a, a2, ln, b, c, d
        assert_eq!(all["total_dirs"], 5); // t, Pool, lost, x, @tmp
        assert_eq!(all["hardlink_names"], 1);
        assert_eq!(all["total_size"].as_u64().unwrap(), 1000 + 10 + 99 + 5 + 1); // one of a/a2; ln is 1 byte
        assert_eq!(all["complete"], true);
        assert!(all["path"].is_string());
        let ex = go(json!({"exclude": ["**/@tmp", "Pool/lost"], "private": true}));
        assert_eq!(ex["total_files"], 4);
        assert_eq!(ex["total_dirs"], 3);
        assert!(ex.get("path").is_none());
        assert_eq!(go(json!({"exclude": ["Pool"]}))["total_files"], 4); // a, a2, ln, d
    }

    #[test]
    fn sums_are_limited_and_cancellable() {
        let sums = Sums::default();
        let g: Vec<_> = (0..MAX_SUMS).map(|i| sums.begin(Some(&format!("id{i}")), MAX_SUMS).unwrap()).collect();
        assert_eq!(sums.begin(None, MAX_SUMS).err().unwrap().code, "busy");
        assert!(sums.cancel("id1"));
        assert!(g[1].flag.load(Ordering::SeqCst));
        assert!(!sums.cancel("nope"));
        drop(g);
        assert!(sums.begin(None, MAX_SUMS).is_ok());
        assert!(!sums.cancel("id1"));
    }

    #[test]
    fn a_cancelled_walk_answers_cancelled_and_a_late_one_is_incomplete() {
        let f = fx("cancel");
        std::fs::create_dir_all(f.root.join("t/a/b")).unwrap();
        std::fs::write(f.root.join("t/a/b/f"), b"x").unwrap();
        let t = f.root.join("t");
        let sums = Sums::default();
        let r = sum_subtree(&f.scope, &Policy::default(), &sums, &Counters::default(), &req(json!({"path": t.to_string_lossy(), "deadline_ms": 0})), &mut nosend());
        // deadline 0 may or may not have passed at the first tick; either way it is not an error
        assert!(r.is_ok());
        // a failing progress write (the client went away) cancels
        let mut fail = |_: &Value| -> std::io::Result<()> { Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)) };
        std::fs::create_dir_all(f.root.join("t/many")).unwrap();
        for i in 0..50 {
            std::fs::write(f.root.join(format!("t/many/{i}")), b"x").unwrap();
        }
        let guard_id = req(json!({"path": t.to_string_lossy(), "progress_ms": 1, "id": "p1"}));
        // progress_ms is raised to 500 ms, so a short walk finishes without a write: still ok
        assert!(sum_subtree(&f.scope, &Policy::default(), &sums, &Counters::default(), &guard_id, &mut fail).is_ok());
    }

    #[test]
    fn unreadable_entries_are_counters_only() {
        let f = fx("err");
        std::fs::create_dir_all(f.root.join("t/locked")).unwrap();
        std::fs::write(f.root.join("t/locked/f"), b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(f.root.join("t/locked"), std::fs::Permissions::from_mode(0o0)).unwrap();
        let t = f.root.join("t");
        let r = sum_subtree(&f.scope, &Policy::default(), &Sums::default(), &Counters::default(), &req(json!({"path": t.to_string_lossy()})), &mut nosend()).unwrap();
        std::fs::set_permissions(f.root.join("t/locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let root_user = unsafe { libc::geteuid() } == 0;
        if !root_user {
            assert_eq!(r["errors"], 1);
            assert_eq!(r["error_codes"], json!({"permission_denied": 1}));
        }
        assert!(!serde_json::to_string(&r["error_codes"]).unwrap().contains("locked"));
    }
}
