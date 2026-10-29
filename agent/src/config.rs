//! Configuration: command line, environment and the `.env` file next to the binary.
//!
//! Precedence for every key: command line, environment, `.env`, built-in default. The token is
//! never a command-line argument (it would show in `ps`): `FILECAT_AGENT_TOKEN` in the environment
//! or `.env`, or the first line of the file named by `FILECAT_AGENT_TOKEN_FILE` / `--token-file`.

use crate::scope::{self, RootsSource};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:9876";

pub struct Config {
    pub listen: String,
    pub token: String,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub roots: Vec<String>,
    pub roots_source: RootsSource,
    pub test_root: Option<PathBuf>,
    pub print_fingerprint: bool,
    /// seconds between status log lines; 0 is off
    pub status_interval: u64,
}

pub enum Parsed {
    Run(Box<Config>),
    Exit(String),
}

pub const USAGE: &str = "\
filecat-agent: read-only file system and storage agent for filecat (protocol 1)

usage: filecat-agent [--listen ADDR] [--cert FILE] [--key FILE] [--token-file FILE]
                     [--env-file FILE] [--print-fingerprint] [--version]

settings (command line, else environment, else the .env file next to the binary):
  FILECAT_AGENT_TOKEN         the bearer token (required; or FILECAT_AGENT_TOKEN_FILE)
  FILECAT_AGENT_TOKEN_FILE    a file whose first line is the token
  FILECAT_AGENT_LISTEN        address:port to listen on (default 0.0.0.0:9876)
  FILECAT_AGENT_CERT / _KEY   certificate and key (PEM), generated on first start
                              (default: filecat-agent.crt / .key next to the binary)
  FILECAT_AGENT_ALLOW_ROOTS   paths the agent may serve, ':' separated, '*' inside one component
                              (default: DSM or Linux metadata paths, see docs/agent-protocol.md)
  FILECAT_AGENT_STATUS_INTERVAL  seconds between status log lines for busy connections
                              (default 600, 0 turns them off)

The first start prints the certificate's SHA-256 fingerprint: paste it into filecat.toml as
`cert_sha256` of the [[agents]] entry.";

/// `KEY=value` lines; `#` comments, an optional `export `, optional single or double quotes.
pub fn parse_dotenv(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let v = if v.len() >= 2 && (v.starts_with('"') && v.ends_with('"') || v.starts_with('\'') && v.ends_with('\'')) { &v[1..v.len() - 1] } else { v };
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    out
}

fn warn_if_readable(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(m) = std::fs::metadata(path) {
        if m.mode() & 0o077 != 0 {
            eprintln!("filecat-agent: warning: {} is readable by other users; chmod 600 it", path.display());
        }
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."))
}

pub fn load(args: &[String], env: &dyn Fn(&str) -> Option<String>) -> Result<Parsed, String> {
    let (mut listen, mut cert, mut key, mut token_file, mut env_file) = (None, None, None, None, None);
    let mut print_fingerprint = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "--listen" => listen = Some(value("--listen")?),
            "--cert" => cert = Some(value("--cert")?),
            "--key" => key = Some(value("--key")?),
            "--token-file" => token_file = Some(value("--token-file")?),
            "--env-file" => env_file = Some(value("--env-file")?),
            "--print-fingerprint" => print_fingerprint = true,
            "--version" | "-V" => return Ok(Parsed::Exit(format!("filecat-agent {}", env!("CARGO_PKG_VERSION")))),
            "--help" | "-h" => return Ok(Parsed::Exit(USAGE.to_string())),
            other => return Err(format!("unknown argument {other:?} (--help lists them; the token is never an argument)")),
        }
    }
    let env_path = env_file.map(PathBuf::from).unwrap_or_else(|| exe_dir().join(".env"));
    let dotenv_text = std::fs::read_to_string(&env_path).ok();
    if dotenv_text.is_some() {
        warn_if_readable(&env_path);
    }
    let dotenv = dotenv_text.as_deref().map(parse_dotenv).unwrap_or_default();
    let get = |k: &str| env(k).or_else(|| dotenv.get(k).cloned());

    let token = match get("FILECAT_AGENT_TOKEN") {
        Some(t) => t,
        None => match token_file.or_else(|| get("FILECAT_AGENT_TOKEN_FILE")) {
            Some(f) => {
                warn_if_readable(Path::new(&f));
                let text = std::fs::read_to_string(&f).map_err(|e| format!("cannot read the token file {f}: {e}"))?;
                text.lines().next().unwrap_or("").trim().to_string()
            }
            None => String::new(),
        },
    };
    let token = token.trim().to_string();
    if token.is_empty() && !print_fingerprint {
        return Err("no token: set FILECAT_AGENT_TOKEN (environment or .env) or FILECAT_AGENT_TOKEN_FILE".into());
    }

    let (roots, roots_source) = scope::resolve_allow_roots(env("FILECAT_AGENT_ALLOW_ROOTS").as_deref(), dotenv_text.as_deref(), scope::default_roots(scope::is_dsm()));
    for r in &roots {
        scope::validate_root(r)?;
    }
    let status_interval = crate::session::parse_interval(get("FILECAT_AGENT_STATUS_INTERVAL").as_deref())?;
    let dir = exe_dir();
    #[cfg(feature = "test-root")]
    let test_root = env("FILECAT_AGENT_TEST_ROOT").map(PathBuf::from);
    #[cfg(not(feature = "test-root"))]
    let test_root = None;
    Ok(Parsed::Run(Box::new(Config {
        listen: listen.or_else(|| get("FILECAT_AGENT_LISTEN")).unwrap_or_else(|| DEFAULT_LISTEN.to_string()),
        token,
        cert: cert.or_else(|| get("FILECAT_AGENT_CERT")).map(PathBuf::from).unwrap_or_else(|| dir.join("filecat-agent.crt")),
        key: key.or_else(|| get("FILECAT_AGENT_KEY")).map(PathBuf::from).unwrap_or_else(|| dir.join("filecat-agent.key")),
        roots,
        roots_source,
        test_root,
        print_fingerprint,
        status_interval,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_syntax() {
        let m = parse_dotenv("# c\n\nA=1\nexport B = \"two words\"\nC='x'\nD=\nE==f\nnoequals\n");
        assert_eq!(m["A"], "1");
        assert_eq!(m["B"], "two words");
        assert_eq!(m["C"], "x");
        assert_eq!(m["D"], "");
        assert_eq!(m["E"], "=f");
        assert!(!m.contains_key("noequals"));
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_token_no_start_and_no_token_argument() {
        let none = |_: &str| None;
        let env_file = std::env::temp_dir().join(format!("fc-cfg-none-{}", std::process::id()));
        let a = args(&["--env-file", env_file.to_str().unwrap()]);
        assert!(load(&a, &none).is_err());
        let mut a2 = a.clone();
        a2.push("--token".into());
        a2.push("secret".into());
        assert!(load(&a2, &|k: &str| (k == "FILECAT_AGENT_TOKEN").then(|| "t".to_string())).is_err());
    }

    #[test]
    fn environment_beats_dotenv_beats_default() {
        let f = std::env::temp_dir().join(format!("fc-cfg-{}", std::process::id()));
        std::fs::write(&f, "FILECAT_AGENT_TOKEN=fromfile\nFILECAT_AGENT_LISTEN=1.2.3.4:5\nFILECAT_AGENT_ALLOW_ROOTS=/srv\n").unwrap();
        let a = args(&["--env-file", f.to_str().unwrap()]);
        let Parsed::Run(c) = load(&a, &|_| None).unwrap() else { panic!() };
        assert_eq!((c.token.as_str(), c.listen.as_str(), c.roots.clone(), c.roots_source), ("fromfile", "1.2.3.4:5", vec!["/srv".to_string()], RootsSource::EnvFile));
        let env = |k: &str| match k {
            "FILECAT_AGENT_TOKEN" => Some("fromenv".to_string()),
            "FILECAT_AGENT_ALLOW_ROOTS" => Some("/a:/b".to_string()),
            _ => None,
        };
        let Parsed::Run(c) = load(&args(&["--env-file", f.to_str().unwrap(), "--listen", "127.0.0.1:0"]), &env).unwrap() else { panic!() };
        assert_eq!((c.token.as_str(), c.listen.as_str(), c.roots_source), ("fromenv", "127.0.0.1:0", RootsSource::Env));
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn status_interval_resolves_like_the_other_settings() {
        let f = std::env::temp_dir().join(format!("fc-cfg-iv-{}", std::process::id()));
        std::fs::write(&f, "FILECAT_AGENT_TOKEN=t\nFILECAT_AGENT_STATUS_INTERVAL=120\n").unwrap();
        let a = args(&["--env-file", f.to_str().unwrap()]);
        let Parsed::Run(c) = load(&a, &|_| None).unwrap() else { panic!() };
        assert_eq!(c.status_interval, 120);
        let env = |k: &str| (k == "FILECAT_AGENT_STATUS_INTERVAL").then(|| "0".to_string());
        let Parsed::Run(c) = load(&a, &env).unwrap() else { panic!() };
        assert_eq!(c.status_interval, 0);
        let bad = |k: &str| (k == "FILECAT_AGENT_STATUS_INTERVAL").then(|| "soon".to_string());
        assert!(load(&a, &bad).is_err());
        std::fs::write(&f, "FILECAT_AGENT_TOKEN=t\n").unwrap();
        let Parsed::Run(c) = load(&a, &|_| None).unwrap() else { panic!() };
        assert_eq!(c.status_interval, 600);
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn token_file_and_malformed_roots() {
        let t = std::env::temp_dir().join(format!("fc-tok-{}", std::process::id()));
        std::fs::write(&t, "filetoken\nsecond line\n").unwrap();
        let none_env = std::env::temp_dir().join(format!("fc-tok-none-{}", std::process::id()));
        let a = args(&["--env-file", none_env.to_str().unwrap(), "--token-file", t.to_str().unwrap()]);
        let Parsed::Run(c) = load(&a, &|_| None).unwrap() else { panic!() };
        assert_eq!(c.token, "filetoken");
        let bad = |k: &str| match k {
            "FILECAT_AGENT_TOKEN" => Some("x".to_string()),
            "FILECAT_AGENT_ALLOW_ROOTS" => Some("/ok:relative".to_string()),
            _ => None,
        };
        assert!(load(&args(&["--env-file", none_env.to_str().unwrap()]), &bad).is_err());
        let _ = std::fs::remove_file(&t);
    }
}
