//! The agent's read scope (docs/agent-protocol.md, "Allowed roots and the deny list"): allowed
//! roots (environment > `.env` > built-in default), path canonicalisation, the compiled-in deny
//! list, private keys by content and the files served with credentials blanked.
//! `tests/_fake_agent.py` is the executable specification.

use crate::proto::{Fail, R};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

// --- the deny list, compiled in ----------------------------------------------------------------
/// Path rules for the content commands. `*` matches inside one component; a rule covers itself
/// and everything below it.
pub const DENY_POSIX: &[&str] = &[
    "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ssh/ssh_host_*_key", "/etc/ssl/private", "/var/log", "/var/logs",
];
/// `.env` and `.env.*` are denied anywhere except these.
pub const ENV_ALLOWED: &[&str] = &[".env.example", ".env.sample", ".env.template"];
/// The Windows rules (phase 2); part of `deny_sha256` so one build reports one value everywhere.
pub const DENY_WINDOWS: &[&str] = &[r"%SystemRoot%\system32\config", r"%SystemRoot%\ntds"];
/// Private key signatures, as `filecat.secretfiles.SIGNATURES` spells them (hash input only; the
/// matching is `private_key_head`).
pub const SIGNATURES: &[&str] = &[
    "-----BEGIN *PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "PuTTY-User-Key-File-",
];
pub const SIGNATURE_WINDOW: usize = 256;

/// SHA-256 of the deny list: `DENY_POSIX`, `ENV_ALLOWED`, `DENY_WINDOWS` and `SIGNATURES`, in that
/// order, joined with `\n` (no trailing newline).
pub fn deny_sha256() -> String {
    let all: Vec<&str> = DENY_POSIX.iter().chain(ENV_ALLOWED).chain(DENY_WINDOWS).chain(SIGNATURES).copied().collect();
    crate::proto::hex(&Sha256::digest(all.join("\n").as_bytes()))
}

fn comps(p: &[u8]) -> Vec<&[u8]> {
    p.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect()
}

/// `*` is the only wildcard: any run of bytes inside one component.
fn star_match(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// `path` is `pattern` or below it, component by component.
pub fn under(pattern: &str, path: &[u8]) -> bool {
    let pp = comps(pattern.as_bytes());
    let xs = comps(path);
    xs.len() >= pp.len() && pp.iter().zip(xs.iter()).all(|(a, b)| star_match(a, b))
}

pub fn is_env_file(name: &[u8]) -> bool {
    let n = String::from_utf8_lossy(name);
    (n == ".env" || n.starts_with(".env.")) && !ENV_ALLOWED.contains(&n.as_ref())
}

/// The deny list on a canonical path.
pub fn denied(canon: &[u8]) -> bool {
    DENY_POSIX.iter().any(|p| under(p, canon)) || canon.rsplit(|&b| b == b'/').next().map(is_env_file).unwrap_or(false)
}

/// Whether the first bytes of a file are a private key's header (`secretfiles.private_key_in`).
pub fn private_key_head(head: &[u8]) -> bool {
    let mut h = &head[..head.len().min(SIGNATURE_WINDOW)];
    if h.starts_with(b"\xef\xbb\xbf") {
        h = &h[3..];
    }
    while let Some(&c) = h.first() {
        if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            h = &h[1..];
        } else {
            break;
        }
    }
    if h.starts_with(b"PuTTY-User-Key-File-") || h.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----") || h.starts_with(b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----") {
        return true;
    }
    if !h.starts_with(b"-----BEGIN ") {
        return false;
    }
    let first = h.split(|&b| b == b'\n').next().unwrap_or(b"");
    let mut end = first.len();
    while end > 0 && matches!(first[end - 1], b'\r' | b' ' | b'\t') {
        end -= 1;
    }
    first[..end].ends_with(b"PRIVATE KEY-----")
}

// --- credential blanking -------------------------------------------------------------------------
pub const REDACTED: &[u8] = b"<filecat-redacted>";
/// Files served by `read_file` with these keys' values blanked (and refused to the others).
pub const REDACT_FILES: &[(&str, &[&str])] =
    &[("/usr/syno/etc/iscsi_target.conf", &["username", "password", "mutual_username", "mutual_password"])];

pub fn redact_keys(canon: &[u8]) -> Option<&'static [&'static str]> {
    REDACT_FILES.iter().find(|(p, _)| p.as_bytes() == canon).map(|(_, k)| *k)
}

fn strip_ws(b: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = b.iter().position(|c| !ws(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !ws(c)).map(|i| i + 1).unwrap_or(start);
    &b[start..end]
}

/// Every `key=value` line whose key (trimmed) is in `keys` gets the marker as its value; the key,
/// the `=`, the line ending and every other line are the file's own.
pub fn redact_credentials(data: &[u8], keys: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        // a line ends at \n, \r\n or a lone \r (bytes.splitlines)
        let mut j = i;
        while j < data.len() && data[j] != b'\n' && data[j] != b'\r' {
            j += 1;
        }
        if j < data.len() {
            j += if data[j] == b'\r' && data.get(j + 1) == Some(&b'\n') { 2 } else { 1 };
        }
        let line = &data[i..j];
        match line.iter().position(|&c| c == b'=') {
            Some(eq) if keys.iter().any(|k| k.as_bytes() == strip_ws(&line[..eq])) => {
                let rest = &line[eq + 1..];
                let mut body = rest.len();
                while body > 0 && matches!(rest[body - 1], b'\r' | b'\n') {
                    body -= 1;
                }
                out.extend_from_slice(&line[..=eq]);
                out.extend_from_slice(REDACTED);
                out.extend_from_slice(&rest[body..]);
            }
            _ => out.extend_from_slice(line),
        }
        i = j;
    }
    out
}

// --- allowed roots -------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RootsSource {
    Env,
    EnvFile,
    Default,
}

impl RootsSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RootsSource::Env => "env",
            RootsSource::EnvFile => "env_file",
            RootsSource::Default => "default",
        }
    }
}

pub fn default_roots(dsm: bool) -> Vec<String> {
    let list: &[&str] = if dsm {
        &["/volume*", "/proc", "/sys", "/dev/disk", "/etc/samba", "/etc/space", "/etc/VERSION", "/etc/exports", "/etc/lvm/backup", "/usr/syno/etc/iscsi_*.conf"]
    } else {
        &["/proc", "/sys", "/dev/disk", "/etc/hostname", "/etc/os-release", "/etc/exports", "/mnt", "/srv", "/media"]
    };
    list.iter().map(|s| s.to_string()).collect()
}

/// DSM: `/etc/VERSION` has a `productversion`.
pub fn is_dsm() -> bool {
    std::fs::read_to_string("/etc/VERSION").map(|t| t.lines().any(|l| l.trim_start().starts_with("productversion"))).unwrap_or(false)
}

/// The effective roots and their source: `FILECAT_AGENT_ALLOW_ROOTS` in the environment wins over
/// the same key in the `.env` text; neither: `default`. Set but empty: no roots.
pub fn resolve_allow_roots(env: Option<&str>, dotenv: Option<&str>, default: Vec<String>) -> (Vec<String>, RootsSource) {
    let (mut raw, mut source) = (env.map(str::to_string), RootsSource::Env);
    if raw.is_none() {
        if let Some(text) = dotenv {
            for line in text.lines() {
                if let Some((k, v)) = line.trim().split_once('=') {
                    if k.trim() == "FILECAT_AGENT_ALLOW_ROOTS" {
                        raw = Some(v.trim().trim_matches(|c| c == '"' || c == '\'').to_string());
                        source = RootsSource::EnvFile;
                    }
                }
            }
        }
    }
    match raw {
        None => (default, RootsSource::Default),
        Some(r) => (r.split(':').filter(|s| !s.is_empty()).map(str::to_string).collect(), source),
    }
}

/// A root must be absolute with no empty, `.` or `..` component; anything else stops the agent.
pub fn validate_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/') || root.contains('\0') {
        return Err(format!("allowed root {root:?} is not an absolute path"));
    }
    let body = root.trim_end_matches('/');
    if body.is_empty() {
        return Ok(());
    }
    if body[1..].split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(format!("allowed root {root:?} has an empty, . or .. component"));
    }
    Ok(())
}

/// What the dispatcher needs to decide where a request may go.
pub struct Scope {
    pub roots: Vec<String>,
    pub source: RootsSource,
    /// Conformance builds: requests are taken below this directory (see `test-root` in Cargo.toml).
    test_root: Option<PathBuf>,
}

/// A request path after the scope check.
pub struct Resolved {
    /// The canonical path as the agent sees the host (symlinks resolved), the one the roots and the
    /// deny list are checked on.
    pub canon: Vec<u8>,
    /// Where to operate: the canonical path on the real file system.
    pub host: PathBuf,
    /// The path as the request wrote it, for messages.
    pub display: String,
}

impl Scope {
    pub fn new(roots: Vec<String>, source: RootsSource, test_root: Option<PathBuf>) -> Result<Scope, String> {
        let mut scope = Scope { roots: Vec::new(), source, test_root };
        let mut out = Vec::new();
        for r in roots {
            validate_root(&r)?;
            let r = if r.len() > 1 { r.trim_end_matches('/').to_string() } else { r };
            if r.contains('*') {
                out.push(r);
            } else {
                let canon = scope.canonical_virtual(r.as_bytes());
                match canon {
                    Some(c) if scope.exists(c.as_slice()) => out.push(String::from_utf8_lossy(&c).into_owned()),
                    _ => {
                        eprintln!("filecat-agent: allowed root {r} does not exist yet; kept as written");
                        out.push(r);
                    }
                }
            }
        }
        scope.roots = out;
        Ok(scope)
    }

    fn host_of(&self, virt: &[u8]) -> PathBuf {
        match &self.test_root {
            None => PathBuf::from(OsStr::from_bytes(virt)),
            Some(root) => {
                let mut p = root.clone().into_os_string().into_vec();
                p.extend_from_slice(virt);
                PathBuf::from(std::ffi::OsString::from_vec(p))
            }
        }
    }

    fn exists(&self, virt: &[u8]) -> bool {
        std::fs::symlink_metadata(self.host_of(virt)).is_ok()
    }

    /// The real path of a virtual path: symlinks resolved on the longest existing ancestor, the
    /// remaining components appended. `None` when it leaves the test root.
    pub fn canonical_virtual(&self, virt: &[u8]) -> Option<Vec<u8>> {
        let mut rest: Vec<&[u8]> = Vec::new();
        let all = comps(virt);
        let mut n = all.len();
        let resolved = loop {
            let mut v = Vec::new();
            for c in &all[..n] {
                v.push(b'/');
                v.extend_from_slice(c);
            }
            if v.is_empty() {
                v.push(b'/');
            }
            match std::fs::canonicalize(self.host_of(&v)) {
                Ok(p) => break Some(p),
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENOTDIR)) && n > 0 => {
                    n -= 1;
                    rest.push(all[n]);
                }
                // EACCES, ELOOP, ...: the lexical path stands; the operation will fail on its own
                Err(_) => break None,
            }
        };
        let mut out: Vec<u8> = match resolved {
            Some(p) => match &self.test_root {
                None => p.into_os_string().into_vec(),
                Some(root) => {
                    let base = std::fs::canonicalize(root).ok()?;
                    let rel = p.strip_prefix(&base).ok()?;
                    let mut v = vec![b'/'];
                    v.extend_from_slice(rel.as_os_str().as_bytes());
                    v
                }
            },
            None => {
                let mut v = Vec::new();
                for c in &all[..n] {
                    v.push(b'/');
                    v.extend_from_slice(c);
                }
                v
            }
        };
        for c in rest.iter().rev() {
            if out.last() != Some(&b'/') {
                out.push(b'/');
            }
            out.extend_from_slice(c);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        Some(out)
    }

    /// Validate a request path and check it against the allowed roots.
    pub fn resolve(&self, path: &[u8]) -> R<Resolved> {
        let display = String::from_utf8_lossy(path).into_owned();
        let bad = || Fail::bad(format!("{display}: path must be absolute, without empty, . or .. components, and not end in /"));
        if path.first() != Some(&b'/') || path.contains(&0) {
            return Err(bad());
        }
        if path != b"/" && path[1..].split(|&b| b == b'/').any(|c| c.is_empty() || c == b"." || c == b"..") {
            return Err(bad());
        }
        let canon = self.canonical_virtual(path).unwrap_or_else(|| b"/\0outside".to_vec());
        if !self.roots.iter().any(|r| under(r, &canon)) {
            return Err(Fail::refused(format!("{display}: outside the agent's allowed roots (FILECAT_AGENT_ALLOW_ROOTS on the agent host)")));
        }
        let host = self.host_of(&canon);
        Ok(Resolved { canon, host, display })
    }

    /// `resolve` plus the deny list, for the commands that return file content.
    pub fn resolve_content(&self, path: &[u8]) -> R<Resolved> {
        let r = self.resolve(path)?;
        if denied(&r.canon) {
            return Err(Fail::refused(format!("{}: denied by agent policy", r.display)));
        }
        Ok(r)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_list_paths() {
        for p in ["/etc/shadow", "/etc/shadow-", "/etc/sudoers.d/x", "/etc/ssh/ssh_host_rsa_key", "/etc/ssl/private/a/b", "/var/log/messages", "/var/logs", "/volume1/a/.env", "/volume1/.env.local", "/x/.env.production"] {
            assert!(denied(p.as_bytes()), "{p}");
        }
        for p in ["/etc/spacey", "/etc/shadowy", "/etc/ssh/ssh_host_rsa_key.pub", "/volume1/.environment", "/volume1/a.env", "/x/.env.example", "/x/.env.sample", "/x/.env.template", "/var/lib/x", "/var/logger"] {
            assert!(!denied(p.as_bytes()), "{p}");
        }
    }

    #[test]
    fn roots_match_by_component() {
        assert!(under("/etc/space", b"/etc/space/a.xml"));
        assert!(!under("/etc/space", b"/etc/spacey"));
        assert!(under("/volume*", b"/volume12/x/y"));
        assert!(!under("/volume*", b"/vol/x"));
        assert!(under("/usr/syno/etc/iscsi_*.conf", b"/usr/syno/etc/iscsi_target.conf"));
        assert!(!under("/usr/syno/etc/iscsi_*.conf", b"/usr/syno/etc/iscsi_target.bak"));
        assert!(under("/", b"/anything"));
    }

    #[test]
    fn root_resolution_precedence() {
        let d = || vec!["/default".to_string()];
        assert_eq!(resolve_allow_roots(Some("/a:/b"), Some("FILECAT_AGENT_ALLOW_ROOTS=/c"), d()), (vec!["/a".into(), "/b".into()], RootsSource::Env));
        assert_eq!(resolve_allow_roots(None, Some("# x\nFILECAT_AGENT_ALLOW_ROOTS=\"/c:/d\"\n"), d()), (vec!["/c".into(), "/d".into()], RootsSource::EnvFile));
        assert_eq!(resolve_allow_roots(None, Some("OTHER=1"), d()), (d(), RootsSource::Default));
        assert_eq!(resolve_allow_roots(None, None, d()).1, RootsSource::Default);
        assert_eq!(resolve_allow_roots(Some(""), None, d()), (vec![], RootsSource::Env));
        assert_eq!(resolve_allow_roots(None, Some("FILECAT_AGENT_ALLOW_ROOTS='/q'"), d()).0, vec!["/q".to_string()]);
    }

    #[test]
    fn malformed_roots_are_rejected() {
        assert!(validate_root("relative").is_err());
        assert!(validate_root("/a/../b").is_err());
        assert!(validate_root("/a//b").is_err());
        assert!(validate_root("/a/./b").is_err());
        assert!(validate_root("/volume*").is_ok());
        assert!(validate_root("/").is_ok());
    }

    #[test]
    fn default_roots_per_platform() {
        assert!(default_roots(true).contains(&"/volume*".to_string()));
        assert!(!default_roots(false).contains(&"/volume*".to_string()));
        assert!(default_roots(false).contains(&"/mnt".to_string()));
    }

    #[test]
    fn private_key_heads() {
        let yes: &[&[u8]] = &[
            b"-----BEGIN PRIVATE KEY-----\nMIIE",
            b"-----BEGIN RSA PRIVATE KEY-----\r\nabc",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            b"\xef\xbb\xbf  \n\t-----BEGIN EC PRIVATE KEY-----\n",
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n",
            b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n",
            b"PuTTY-User-Key-File-3: ssh-ed25519\n",
        ];
        for h in yes {
            assert!(private_key_head(h), "{:?}", String::from_utf8_lossy(h));
        }
        let no: &[&[u8]] = &[
            b"ssh-ed25519 AAAA\n",
            b"-----BEGIN PUBLIC KEY-----\n",
            b"-----BEGIN CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE REQUEST-----\n",
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
            b"text first\n-----BEGIN PRIVATE KEY-----\n",
            b"-----BEGIN CERTIFICATE-----\nx\n-----BEGIN PRIVATE KEY-----\n",
            b"-----BEGIN PRIVATE KEY----- trailing\n",
            b"",
        ];
        for h in no {
            assert!(!private_key_head(h), "{:?}", String::from_utf8_lossy(h));
        }
    }

    #[test]
    fn credentials_are_blanked() {
        let keys = &["username", "password", "mutual_username", "mutual_password"];
        let src = b"[t]\npassword=hunter2\r\n  username = bob \nname=keep\npasswordx=1\nmutual_password=z";
        let out = redact_credentials(src, keys);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "[t]\npassword=<filecat-redacted>\r\n  username =<filecat-redacted>\nname=keep\npasswordx=1\nmutual_password=<filecat-redacted>"
        );
        assert_eq!(redact_credentials(b"a=1\rpassword=x\r", keys), b"a=1\rpassword=<filecat-redacted>\r");
        assert_eq!(redact_credentials(b"", keys), b"");
        assert_eq!(redact_credentials(b"no equals", keys), b"no equals");
    }

    #[test]
    fn deny_hash_is_stable() {
        assert_eq!(deny_sha256().len(), 64);
        assert_eq!(deny_sha256(), deny_sha256());
    }

    #[test]
    fn scope_resolves_symlinks_before_checking() {
        let base = std::env::temp_dir().join(format!("fc-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("allowed/sub")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        std::fs::write(base.join("outside/secret"), b"x").unwrap();
        std::fs::write(base.join("allowed/sub/file"), b"x").unwrap();
        std::os::unix::fs::symlink(base.join("outside"), base.join("allowed/escape")).unwrap();
        std::os::unix::fs::symlink(base.join("allowed/sub"), base.join("allowed/inner")).unwrap();
        let root = std::fs::canonicalize(base.join("allowed")).unwrap().to_string_lossy().into_owned();
        let scope = Scope::new(vec![root.clone()], RootsSource::Env, None).unwrap();
        let p = |rel: &str| format!("{root}/{rel}");
        assert!(scope.resolve(p("sub/file").as_bytes()).is_ok());
        assert!(scope.resolve(p("inner/file").as_bytes()).is_ok());
        assert_eq!(scope.resolve(p("escape/secret").as_bytes()).err().unwrap().code, "refused");
        // outside whether or not it exists: no not_found oracle
        assert_eq!(scope.resolve(p("escape/nope").as_bytes()).err().unwrap().code, "refused");
        assert_eq!(scope.resolve(b"/etc/hostname").err().unwrap().code, "refused");
        // a missing file inside is resolved by its longest existing ancestor
        let ok = scope.resolve(p("sub/missing").as_bytes()).unwrap();
        assert!(ok.canon.ends_with(b"/sub/missing"));
        // syntax
        for bad in ["relative", "/a/../b", "/a//b", "/a/"] {
            assert_eq!(scope.resolve(bad.as_bytes()).err().unwrap().code, "bad_request", "{bad}");
        }
        // no roots: everything refused
        let none = Scope::new(vec![], RootsSource::Env, None).unwrap();
        assert_eq!(none.resolve(p("sub/file").as_bytes()).err().unwrap().code, "refused");
        let _ = std::fs::remove_dir_all(&base);
    }
}
