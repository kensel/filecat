# filecat-agent

The Rust agent of filecat, phase 1: Linux and Synology DSM. Wire protocol 1,
[docs/agent-protocol.md](../docs/agent-protocol.md); the commands it may start,
[docs/agent-allowlist.md](../docs/agent-allowlist.md); deploying it on a NAS,
[docs/agent-deploy.md](../docs/agent-deploy.md).

It answers `hello`, `auth`, `configure_policy`, `list_dir`, `measure`, `read_range`, `read_file`,
`sum_subtree`, `statfs`, `run`, `capabilities` and `cancel`; `wmi` is the Windows agent's (phase 2,
`src/windows_phase2.rs`). Read-only, confined to the allowed roots, with a compiled-in deny list.

## Layout

| file | what |
|---|---|
| `src/main.rs`, `config.rs`, `tls.rs` | start-up, CLI / env / `.env`, self-signed certificate (rustls + ring, rcgen) |
| `src/server.rs` | one thread per connection, line reader (8 MiB cap), auth, dispatcher |
| `src/proto.rs` | error codes, field access, 100 ns timestamps, the byte-string rule |
| `src/scope.rs` | allowed roots, canonicalisation, deny list, private keys by content, credential blanking |
| `src/prims.rs` | `measure` (digests of `hashing.py`), `read_range`, `read_file`, `statfs` |
| `src/matcher.rs` | rollup matcher, policy id, redaction HMAC (the shared vectors) |
| `src/walk.rs` | `list_dir`, `sum_subtree`, rollups, progress, deadline, cancellation |
| `src/allowlist.rs`, `run.rs` | the 39-entry command table, argument kinds, `run`, `capabilities` |
| `build.sh` | static musl build, unit tests, the conformance build |

Dependencies: `serde_json`, `sha2`, `hmac`, `base64`, `libc`, `rustls` (ring provider, TLS 1.2/1.3),
`rcgen`. No async runtime (a connection does blocking file system work, a handful of connections,
`std` threads), no OpenSSL, no regex or glob crate (the matchers are hand-written to the shared
vectors).

## Build and test

```sh
rustup target add x86_64-unknown-linux-musl     # once
./build.sh              # static release binary
./build.sh test         # cargo test
./build.sh conformance  # the binary below
```

Run the agent by hand: `FILECAT_AGENT_TOKEN=secret ./filecat-agent --listen 127.0.0.1:9876`.
Output goes to `$CARGO_TARGET_DIR` (default `~/.cache/filecat-agent-target`); a build inside a
Windows-mounted checkout is slow otherwise. Cargo does not build on Windows hosts with Application
Control; use WSL.

### Unit tests

`cargo test` covers the matcher against `tests/data/rollup_match_vectors.json` (match, policy id,
redaction HMAC), the digests against `tests/fixtures/hash_vectors.json` (generated from
`src/filecat/hashing.py` by `tests/gen_hash_vectors.py`, including the 64 MiB boundary and partial
digests with a negative mtime), the deny list, allowed roots and their precedence, private key
heads, credential blanking, argument kinds, the allowlist table (pinned hash), `run` limits,
walks, rollups, sticky redaction, cancel and busy.

### Conformance: the Python agent tests against this binary

`tests/_fake_agent.py` is the executable specification. With `FILECAT_TEST_AGENT_BIN` set, every
test that builds a `FakeAgent` gets this agent instead (`tests/_real_agent.py`; no test changes):

```powershell
# Windows, the binary built by ./build.sh conformance inside WSL (distro ubuntu2)
$env:FILECAT_TEST_AGENT_BIN = "/root/.cache/filecat-agent-target-conformance/x86_64-unknown-linux-musl/release/filecat-agent"
$env:PYTHONPATH = "$PWD\src;$PWD"
C:\code\filecat\.venv\Scripts\python.exe -m pytest tests/test_agent_client.py tests/test_agent_scan.py `
  tests/test_rollup_privacy.py tests/test_rollup_stores.py tests/test_rollup_walk.py `
  tests/test_secret_files.py tests/test_store_fs.py tests/test_synology_space.py `
  tests/test_topology_collect.py -q -p no:cacheprovider -rs
```

The conformance binary is built with the `test-root` feature: every request path is taken below
`FILECAT_AGENT_TEST_ROOT`, so the temp directory a test serves as `/` works as it does for the
fake. A release build has no such code path. The fixture directory lives on Windows and the agent
in WSL sees it as `/mnt/c/...`; WSL2 forwards `127.0.0.1`. A small relay in the test process
records `requests` and `wire` and presents the test certificate. Tests that need a fake-only hook
(simulated Windows attributes, planted unreadable files, canned `run` output, forced progress
lines, recordings) are skipped with the hook's name; a few that assert the fake's own constants are
listed in `NOT_AGAINST_THE_REAL_AGENT` in `_real_agent.py` with the reason. On a Linux machine the
same variable with a local path runs the binary directly. Without the variable the tests use the
fake, as always.

## Deciding things for the next phase

Phase 2 (Windows) needs: `wmi`, cloud-placeholder attributes, `ProductType` roots, Windows deny
paths: see `src/windows_phase2.rs`. The armv7 build is `cargo build --target
armv7-unknown-linux-musleabihf` (untried).
