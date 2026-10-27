mod tls;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Default)]
pub struct WalkPolicy {
    #[serde(default)]
    pub exclude: HashSet<String>,
    /// Maps a synthetic rollup tag (e.g. "[REDACTED]", "[CACHE]", "[SYNOLOGY]")
    /// to a list of glob or path patterns.
    #[serde(default)]
    pub rollup_groups: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Auth { token: String },
    ConfigurePolicy { policy: WalkPolicy },
    ListDir { path: String },
    Measure {
        path: String,
        full_hash_max: u64,
        head_bytes: usize,
        smb_tick_quantize: bool,
    },
    ReadRange {
        path: String,
        offset: u64,
        len: usize,
    },
}

#[derive(Serialize)]
pub struct DirEntryRecord {
    pub name: String,
    pub path: String,
    pub kind: &'static str, // "file" | "dir" | "link" | "rollup"
    pub size: u64,
    pub allocated_size: u64,
    pub ino: u64,
    pub dev: u64,
    pub nlink: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollup_meta: Option<RollupGroupSummary>,
}

#[derive(Serialize, Default, Clone)]
pub struct RollupGroupSummary {
    pub tag: String,
    pub matched_Folders: u64,
    pub total_files: u64,
    pub total_dirs: u64,
    pub total_size: u64,
    pub total_allocated_size: u64,
    pub newest_mtime_ns: i64,
}

fn stat_to_record(name: String, path: &Path, meta: &fs::Metadata) -> DirEntryRecord {
    let ft = meta.file_type();
    let kind = if ft.is_symlink() {
        "link"
    } else if ft.is_dir() {
        "dir"
    } else {
        "file"
    };
    let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
    let ctime_ns = meta.ctime() * 1_000_000_000 + meta.ctime_nsec();

    DirEntryRecord {
        name,
        path: path.to_string_lossy().into_owned(),
        kind,
        size: meta.len(),
        allocated_size: meta.blocks() * 512,
        ino: meta.ino(),
        dev: meta.dev(),
        nlink: meta.nlink(),
        mtime_ns,
        ctime_ns,
        rollup_meta: None,
    }
}

/// Checks if a child path or name matches any configured rollup_groups tag
fn match_rollup_tag(child_path: &str, child_name: &str, policy: &WalkPolicy) -> Option<String> {
    for (tag, patterns) in &policy.rollup_groups {
        for pat in patterns {
            if pat == child_path || pat == child_name {
                return Some(tag.clone());
            }
            if let Ok(g) = Pattern::new(pat) {
                if g.matches(child_path) || g.matches(child_name) {
                    return Some(tag.clone());
                }
            }
        }
    }
    None
}

/// Fast lstat-only recursive summer for rollup subtrees ([REDACTED], [CACHE], [SYNOLOGY], etc.).
/// Stays on the same filesystem (`expected_dev`), tracks seen hardlink inodes, and never follows symlinks.
fn sum_rollup_subtree(root: &Path, expected_dev: u64, acc: &mut RollupGroupSummary) {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut seen_inodes: HashSet<u64> = HashSet::new();

    while let Some(curr) = stack.pop() {
        let entries = match fs::read_dir(&curr) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = fs::symlink_metadata(&p) {
                if meta.dev() != expected_dev {
                    continue;
                }
                let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
                if mtime_ns > acc.newest_mtime_ns {
                    acc.newest_mtime_ns = mtime_ns;
                }
                let ft = meta.file_type();
                if ft.is_dir() && !ft.is_symlink() {
                    acc.total_dirs += 1;
                    stack.push(p);
                } else {
                    acc.total_files += 1;
                    if meta.nlink() <= 1 || seen_inodes.insert(meta.ino()) {
                        acc.total_size += meta.len();
                        acc.total_allocated_size += meta.blocks() * 512;
                    }
                }
            }
        }
    }
}

fn handle_list_dir(dir_path: &str, policy: &WalkPolicy) -> serde_json::Value {
    let p = Path::new(dir_path);
    let parent_meta = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) => return serde_json::json!({"ok": false, "error": e.to_string()}),
    };
    let expected_dev = parent_meta.dev();

    let read_dir = match fs::read_dir(p) {
        Ok(r) => r,
        Err(e) => return serde_json::json!({"ok": false, "error": e.to_string()}),
    };

    let mut entries = Vec::new();
    let mut rollups: HashMap<String, RollupGroupSummary> = HashMap::new();

    for entry in read_dir.flatten() {
        let child_path = entry.path();
        let child_str = child_path.to_string_lossy().into_owned();
        let child_name = entry.file_name().to_string_lossy().into_owned();

        if policy.exclude.contains(&child_str) || policy.exclude.contains(&child_name) {
            continue;
        }

        let meta = match fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if let Some(tag) = match_rollup_tag(&child_str, &child_name, policy) {
            let acc = rollups.entry(tag.clone()).or_insert_with(|| RollupGroupSummary {
                tag: tag.clone(),
                ..Default::default()
            });
            acc.matched_Folders += 1;
            let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
            if mtime_ns > acc.newest_mtime_ns {
                acc.newest_mtime_ns = mtime_ns;
            }
            if meta.is_dir() && !meta.file_type().is_symlink() {
                acc.total_dirs += 1;
                sum_rollup_subtree(&child_path, expected_dev, acc);
            } else {
                acc.total_files += 1;
                acc.total_size += meta.len();
                acc.total_allocated_size += meta.blocks() * 512;
            }
            continue;
        }

        entries.push(stat_to_record(child_name, &child_path, &meta));
    }

    // Emit one synthetic child record per triggered rollup group (e.g., `/project/[REDACTED]`)
    for (tag, summary) in rollups {
        let synthetic_path = format!("{}/{}", dir_path.trim_end_matches('/'), tag);
        entries.push(DirEntryRecord {
            name: tag,
            path: synthetic_path,
            kind: "rollup",
            size: summary.total_size,
            allocated_size: summary.total_allocated_size,
            ino: 0,
            dev: expected_dev,
            nlink: 1,
            mtime_ns: summary.newest_mtime_ns,
            ctime_ns: summary.newest_mtime_ns,
            rollup_meta: Some(summary),
        });
    }

    serde_json::json!({
        "ok": true,
        "path": dir_path,
        "entries": entries
    })
}

/// Byte-exact implementation of filecat's hashing.py policy
fn handle_measure(
    path: &str,
    full_hash_max: u64,
    head_bytes: usize,
    smb_tick_quantize: bool,
) -> serde_json::Value {
    let p = Path::new(path);
    let meta = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) => return serde_json::json!({"ok": false, "error": e.to_string()}),
    };
    let size = meta.len();
    let mut mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
    if smb_tick_quantize {
        mtime_ns = (mtime_ns / 100) * 100;
    }

    let mut file = match File::open(p) {
        Ok(f) => f,
        Err(e) => return serde_json::json!({"ok": false, "error": e.to_string()}),
    };

    let head_len = std::cmp::min(size as usize, head_bytes);
    let mut head_buf = vec![0u8; head_len];
    if head_len > 0 {
        let _ = file.read_exact(&mut head_buf);
    }

    if size == 0 {
        serde_json::json!({
            "ok": true,
            "head_b64": "",
            "sha256": null,
            "sha256_partial": null
        })
    } else if size <= full_hash_max {
        let _ = file.seek(SeekFrom::Start(0));
        let mut hasher = Sha256::new();
        if std::io::copy(&mut file, &mut hasher).is_err() {
            return serde_json::json!({"ok": false, "error": "read failed during full hash"});
        }
        serde_json::json!({
            "ok": true,
            "head_b64": B64.encode(&head_buf),
            "sha256": format!("{:x}", hasher.finalize()),
            "sha256_partial": null
        })
    } else {
        const WIN: usize = 1024 * 1024; // 1 MiB
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; WIN];

        if file.seek(SeekFrom::Start(0)).is_err() || file.read_exact(&mut buf).is_err() {
            return serde_json::json!({"ok": false, "error": "head 1MiB read failed"});
        }
        hasher.update(&buf);

        if file.seek(SeekFrom::Start(size - WIN as u64)).is_err() || file.read_exact(&mut buf).is_err() {
            return serde_json::json!({"ok": false, "error": "tail 1MiB read failed"});
        }
        hasher.update(&buf);
        hasher.update(size.to_be_bytes());
        hasher.update(mtime_ns.to_be_bytes());

        serde_json::json!({
            "ok": true,
            "head_b64": B64.encode(&head_buf),
            "sha256": null,
            "sha256_partial": format!("{:x}", hasher.finalize())
        })
    }
}

fn handle_read_range(path: &str, offset: u64, len: usize) -> serde_json::Value {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return serde_json::json!({"ok": false, "error": e.to_string()}),
    };
    if let Err(e) = file.seek(SeekFrom::Start(offset)) {
        return serde_json::json!({"ok": false, "error": e.to_string()});
    }
    let mut buf = vec![0u8; len];
    let mut total_read = 0;
    while total_read < len {
        match file.read(&mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(e) => return serde_json::json!({"ok": false, "error": e.to_string()}),
        }
    }
    buf.truncate(total_read);
    serde_json::json!({
        "ok": true,
        "data_b64": B64.encode(&buf)
    })
}

fn handle_client(stream: TcpStream, tls_cfg: std::sync::Arc<rustls::ServerConfig>, expected_token: String) {
    let conn = match rustls::ServerConnection::new(tls_cfg) {
        Ok(c) => c,
        Err(_) => return,
    };
    let tls_stream = rustls::StreamOwned::new(conn, stream);
    let mut reader = BufReader::new(tls_stream);
    let mut authed = false;
    let mut policy = WalkPolicy::default();
    let mut line = String::new();

    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(Request::Auth { token }) => {
                if token == expected_token {
                    authed = true;
                    serde_json::json!({"ok": true})
                } else {
                    serde_json::json!({"ok": false, "error": "invalid token"})
                }
            }
            Ok(_) if !authed => serde_json::json!({"ok": false, "error": "unauthorized"}),
            Ok(Request::ConfigurePolicy { policy: new_policy }) => {
                policy = new_policy;
                serde_json::json!({"ok": true})
            }
            Ok(Request::ListDir { path }) => handle_list_dir(&path, &policy),
            Ok(Request::Measure {
                path,
                full_hash_max,
                head_bytes,
                smb_tick_quantize,
            }) => handle_measure(&path, full_hash_max, head_bytes, smb_tick_quantize),
            Ok(Request::ReadRange { path, offset, len }) => handle_read_range(&path, offset, len),
            Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
        };

        let out = format!("{}\n", resp);
        if reader.get_mut().write_all(out.as_bytes()).is_err() {
            break;
        }
        line.clear();
    }
}

fn main() {
    let listen_addr = std::env::var("FILECAT_AGENT_BIND").unwrap_or_else(|_| "0.0.0.0:9876".to_string());
    let expected_token = std::env::var("FILECAT_AGENT_TOKEN").unwrap_or_else(|_| "change-me-token".to_string());
    let cert_path = Path::new("agent.crt");
    let key_path = Path::new("agent.key");

    let tls = tls::load_or_generate_tls(cert_path, key_path).expect("Failed to initialize TLS");
    println!("filecat-agent listening on {}", listen_addr);
    println!("cert_sha256 = \"{}\"", tls.cert_sha256);

    let listener = TcpListener::bind(&listen_addr).expect("Failed to bind TCP listener");
    for stream in listener.incoming().flatten() {
        let cfg = tls.server_config.clone();
        let tok = expected_token.clone();
        std::thread::spawn(move || handle_client(stream, cfg, tok));
    }
}
