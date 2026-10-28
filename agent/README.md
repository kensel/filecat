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

### Targets

| `uname -m` on the NAS | `build.sh` | Rust target | notes |
|---|---|---|---|
| `x86_64` | `./build.sh` or `./build.sh x86_64` | `x86_64-unknown-linux-musl` | static-pie, about 2.2 MB |
| `armv7l` | `./build.sh armv7` | `armv7-unknown-linux-musleabihf` | 32-bit hard-float ARM, EABI5, about 1.6 MB |
| `aarch64` | `./build.sh aarch64` | `aarch64-unknown-linux-musl` | 64-bit ARM, about 1.8 MB |

`./build.sh all` builds the three and prints each artefact's path, size, sha256 and `file` line.
The binaries are fully static (no interpreter, no shared library), which matters on the old DSM
ARM kernels and libc.

Toolchain for the ARM targets (Debian/Ubuntu, root): `apt-get install gcc-arm-linux-gnueabihf
gcc-aarch64-linux-gnu qemu-user-static`, `rustup target add armv7-unknown-linux-musleabihf
aarch64-unknown-linux-musl`. Why the GNU cross gcc: `ring` compiles a little C (it only needs
`<string.h>`/`<stdint.h>`-level headers, so the glibc cross headers are fine) and gcc is also the
link driver; rustc's self-contained musl `crt1.o` and `libc.a` make the result static and
musl-linked. This was the smallest set-up that worked first time; `rust-lld` alone would still need
a C compiler for `ring`, so it saves nothing. `build.sh` exports `CC_<target>`,
`CARGO_TARGET_<TARGET>_LINKER` and `CARGO_TARGET_<TARGET>_RUNNER` (qemu) itself.

Output stays in `$CARGO_TARGET_DIR`, outside the repository (`/agent/target/` and `/agent/dist/`
are also ignored, in case of a plain `cargo build`). `./build.sh test armv7` (or `aarch64`, `all`)
runs the 53 unit tests under qemu-user; they are slow there (the 64 MiB hash vector takes minutes).
qemu-user is not a real DSM kernel: run `./filecat-agent --print-fingerprint` on the NAS once.

`./build.sh hashes` prints the Rust `allowlist_sha256` and `deny_sha256`, which
`src/filecat/data/agent_expected.json` must hold ([docs/agent-server.md](../docs/agent-server.md)).

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
paths: see `src/windows_phase2.rs`. The armv7 and aarch64 builds are done (see Targets).
