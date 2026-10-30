//! filecat-agent: the read-only file system and storage agent of filecat.
//! Protocol 1, docs/agent-protocol.md; commands allowlist, docs/agent-allowlist.md.
//! Phase 1 is the Linux/DSM agent. The Windows agent (WMI, cloud placeholders, `ProductType`
//! roots, Windows deny paths) is phase 2: see `windows_phase2.rs`.

#[cfg(not(unix))]
compile_error!("filecat-agent phase 1 is Linux only; the Windows agent is phase 2 (src/windows_phase2.rs)");

mod allowlist;
mod clock;
mod config;
mod matcher;
mod prims;
mod proto;
mod run;
mod scope;
mod session;
mod server;
mod tls;
mod walk;
#[cfg(windows)]
mod windows_phase2;

use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

fn fail(msg: &str) -> ! {
    eprintln!("filecat-agent: {msg}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match config::load(&args, &|k| std::env::var(k).ok()) {
        Ok(config::Parsed::Run(c)) => c,
        Ok(config::Parsed::Exit(text)) => {
            println!("{text}");
            return;
        }
        Err(e) => fail(&e),
    };
    let tls = tls::load_or_generate(&cfg.cert, &cfg.key).unwrap_or_else(|e| fail(&e));
    if cfg.print_fingerprint {
        println!("cert_sha256 {}", tls.fingerprint);
        return;
    }
    let scope = scope::Scope::new(cfg.roots.clone(), cfg.roots_source, cfg.test_root.clone()).unwrap_or_else(|e| fail(&e));
    let listener = TcpListener::bind(&cfg.listen).unwrap_or_else(|e| fail(&format!("cannot listen on {}: {e}", cfg.listen)));
    let addr = listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| cfg.listen.clone());
    println!("filecat-agent {} listening on {addr}", env!("CARGO_PKG_VERSION"));
    println!("cert_sha256 {}", tls.fingerprint);
    if tls.generated {
        println!("generated a new certificate: {}; paste cert_sha256 into filecat.toml", cfg.cert.display());
    }
    println!("allowed_roots ({}) {}", cfg.roots_source.as_str(), scope.roots.join(":"));
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let registry = Arc::new(session::Registry::default());
    session::spawn_status_log(registry.clone(), cfg.status_interval);
    let shared = Arc::new(server::Shared {
        token: cfg.token.clone().into_bytes(),
        scope,
        tls: tls.config,
        sums: walk::Sums::default(),
        runner: run::Runner::default(),
        hostname: server::hostname(),
        connections: AtomicUsize::new(0),
        registry: registry.clone(),
    });
    server::serve(listener, shared);
}
