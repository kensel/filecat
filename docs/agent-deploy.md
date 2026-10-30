# Deploying filecat-agent on a Synology NAS (or any x86_64 Linux)

`filecat-agent` is one static executable (about 2.2 MB, no shared libraries, no OpenSSL) plus a
small `.env` file. It listens on TCP 9876 with TLS, authenticates the central filecat server with
a bearer token, and serves only the paths its allowed roots name. The protocol is
[agent-protocol.md](agent-protocol.md); what the agent may run is
[agent-allowlist.md](agent-allowlist.md).

Nothing here runs as part of this repository's tests or deploys itself anywhere: these are the
steps for you, on the NAS.

## 1. Build the binary

On any Linux with Rust (WSL works; the checkout may be on a Windows drive):

```sh
rustup target add x86_64-unknown-linux-musl
cd agent
./build.sh              # release; prints the path, normally agent/target/x86_64-unknown-linux-musl/release/filecat-agent
file target/x86_64-unknown-linux-musl/release/filecat-agent   # static-pie, statically linked
```

`build.sh` sets `CC_x86_64_unknown_linux_musl=gcc` (the `ring` crate compiles a little C; the host
`gcc` is enough, `musl-gcc` is not needed). Use `./build.sh test` for the unit tests.

### Which binary for which NAS

Run `uname -m` on the NAS (SSH) and build the matching target:

| `uname -m` | typical Synology | build |
|---|---|---|
| `x86_64` | Plus / XS series (Intel, AMD) | `./build.sh` |
| `armv7l` | older value / J series (Marvell, Alpine 32-bit) | `./build.sh armv7` |
| `aarch64` | newer ARM models (Realtek RTD1296/1619, Alpine v2) | `./build.sh aarch64` |

`./build.sh all` builds all three and prints path, size and sha256 for each; copy the file whose
name you need to the NAS (every build is called `filecat-agent`; keep them apart by directory).
The ARM toolchain (`gcc-arm-linux-gnueabihf`, `gcc-aarch64-linux-gnu`) is described in
[agent/README.md](../agent/README.md). All three are fully static.

## 2. Copy it to the NAS

Put it outside every shared folder (a file under `/volume1/<share>` would show up in the very
catalog the agent serves). `/usr/local` is on the system partition and survives DSM updates.

```sh
# from the machine that built it (SSH must be on: Control Panel > Terminal & SNMP)
scp filecat-agent admin@nas3:/tmp/
ssh admin@nas3
sudo -i                                   # DSM has no root login; admin may sudo
mkdir -p /usr/local/filecat-agent
mv /tmp/filecat-agent /usr/local/filecat-agent/
chmod 750 /usr/local/filecat-agent/filecat-agent
```

## 3. The `.env`

The quick way: on the filecat host, `filecat agents enroll nas3 --host nas3.lan` makes a token and
prints the `.env` lines for the NAS, the `[[agents]]` stanza (`token = "${FILECAT_NAS3_TOKEN}"`,
never the token itself) and how to set `FILECAT_NAS3_TOKEN`; it also reads the certificate
fingerprint once if the agent is already running. The token is printed once. To reuse a token you
already made (say the agent's `.env` exists), pass `--token HEX` (64 hex digits, as `openssl rand
-hex 32` prints) or `--token -` to read it from stdin; a supplied token is validated and is **not
printed back** (the `.env` and environment lines show `<the token you supplied>`), and never
written to filecat.toml. A command-line value stays in shell history and `ps`, so prefer `-`. The whole workflow:

1. `filecat agents enroll nas3 --host nas3.lan` while the agent is not running yet: the stanza has a
   placeholder fingerprint and nothing is written. Put `FILECAT_AGENT_TOKEN=...` in the NAS's `.env`
   and set `FILECAT_NAS3_TOKEN` on the filecat host with the same value.
2. Start the agent (section 4); it prints its `cert_sha256`.
3. `filecat agents fingerprint nas3.lan` shows what the agent presents; compare it with the agent's
   own output, then paste the stanza into `filecat.toml` with that value as `cert_sha256`. (Enrolling
   after the agent is up shows the fingerprint at once, and `--write` appends the stanza; it also
   makes a new token, so that order needs the `.env` changed and the agent restarted.)
4. `filecat agents status`: reachable, pin ok, allowlist and deny list match this filecat.
   A mismatch means the binary on the NAS is from another build ([agent-server.md](agent-server.md)).

By hand, the same thing, in the same directory as the binary (it is read once at start):

```sh
cd /usr/local/filecat-agent
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
cat > .env <<EOF
FILECAT_AGENT_TOKEN=$TOKEN
# what the agent may serve; ':' separated, '*' inside one path component.
# Unset: the DSM default (/volume*, /proc, /sys, /dev/disk, /etc/samba, /etc/space, /etc/VERSION,
# /etc/exports, /etc/lvm/backup, /usr/syno/etc/iscsi_*.conf). Narrow it to what you catalog:
# FILECAT_AGENT_ALLOW_ROOTS=/volume1/Backup:/volume1/Photos:/proc:/sys:/dev/disk:/etc/samba:/etc/space:/etc/VERSION:/etc/lvm/backup:/usr/syno/etc/iscsi_*.conf
# FILECAT_AGENT_LISTEN=0.0.0.0:9876
# seconds between status log lines for connections that are busy (default 600; 0 = off):
# FILECAT_AGENT_STATUS_INTERVAL=600
EOF
chmod 600 .env
echo "token (put it in the server's environment, not in filecat.toml): $TOKEN"
```

The token is never a command-line argument (it would show in `ps`). The agent refuses to start
without one. `.env` itself is on the agent's deny list: it cannot be read through the agent.

Settings are taken from the command line, then the environment, then the `.env`:
`FILECAT_AGENT_TOKEN`, `FILECAT_AGENT_TOKEN_FILE`, `FILECAT_AGENT_LISTEN` (default
`0.0.0.0:9876`), `FILECAT_AGENT_CERT` / `FILECAT_AGENT_KEY`, `FILECAT_AGENT_ALLOW_ROOTS`,
`FILECAT_AGENT_STATUS_INTERVAL` (below).

**Status log.** Every `FILECAT_AGENT_STATUS_INTERVAL` seconds (default 600, `0` turns it off) the
agent prints one line to its output for each connection that made requests, or is running one, in
that time. Nothing is printed for an idle agent. Each line names the connection's label (what the
client says it is doing), its address, how long it has been connected and the command it is
running, then the change since the last line and the total of files, GB read and entries listed,
and the rate:

```
filecat-agent: session 5 "scan \\nas3\Apps by kense@DESKTOP" from 192.0.2.20:51234, connected 12m, running sum_subtree for 3m: files +41234 (90211 total), read +12.40 GB (31.20 GB total), entries +88120 (190004 total), 68.7 files/s, requests +9 (1204 total), 3 errors
```

It sits in the output you already collect (the Task Scheduler's task log, or the file you redirect
to). The same numbers are available live from `filecat agents status`, which lists the other
connections on each agent. Labels and counters only: no path is ever in the log or in `activity`.

## 4. First start and the certificate fingerprint

```sh
/usr/local/filecat-agent/filecat-agent
# filecat-agent 0.2.2 listening on 0.0.0.0:9876
# cert_sha256 a436cafae7aa...
# generated a new certificate: /usr/local/filecat-agent/filecat-agent.crt; paste cert_sha256 into filecat.toml
# allowed_roots (default) /volume*:/proc:...
```

The first start generates `filecat-agent.crt` and `filecat-agent.key` (mode 0600) next to the
binary. Keep them: a new pair has a new fingerprint and every server must be told. To read the
fingerprint again without starting the agent: `./filecat-agent --print-fingerprint`.

On the filecat server, `filecat.toml`:

```toml
[[agents]]
name = "nas3"
host = "nas3"                      # or the IP
alias = '\\nas3'                   # the server name SMB scans record the same shares under
cert_sha256 = "a436cafae7aa..."    # trust on first use: the value printed above
token = "${NAS3_AGENT_TOKEN}"      # read from the environment of the server
```

Then `filecat agents test` shows the protocol, the host and the round trip, and refuses a
fingerprint or token mismatch before anything else is sent.

## 5. Start it at boot (DSM Task Scheduler)

Control Panel > Task Scheduler > Create > Triggered Task > User-defined script:

- General: task `filecat-agent`, user `root`, event **Boot-up**, enabled.
- Task Settings > Run command:

```sh
cd /usr/local/filecat-agent && exec ./filecat-agent >> agent.log 2>&1
```

`agent.log` only gets the start-up lines and warnings; the agent logs no file name, ever. To run
it now without rebooting, select the task and press Run. To stop it: `pkill filecat-agent`.

Other Linux (systemd), `/etc/systemd/system/filecat-agent.service`:

```ini
[Unit]
Description=filecat-agent
After=network-online.target

[Service]
ExecStart=/usr/local/filecat-agent/filecat-agent
WorkingDirectory=/usr/local/filecat-agent
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`systemctl enable --now filecat-agent`.

## 6. Firewall

Open TCP 9876 to the filecat server only. DSM: Control Panel > Security > Firewall > Edit rules:
allow, port 9876 (custom), source IP the server's address; the rules after it deny the rest. The
token and TLS protect the port, but a port nobody else needs to reach should not be open to them.

## 7. Running as root, and what that means

The agent runs as root because it must read every share and the system files the topology
collectors read. What bounds it: the allowed roots (decided on the host, never by a request), the
deny list compiled into the binary (shadow, sudoers, host keys, `/var/log`, `.env*`, private keys by
content), `run` limited to the 39 read-only commands of the compiled allowlist with validated
arguments, and no write anywhere. It is not a boundary against someone who is already root on the
NAS (they can edit the `.env`); it is one against a stolen token or a compromised server.

## 8. Updating

Replace the binary (stop the agent first: `pkill filecat-agent`) and start it again. `hello` and
`capabilities` report `agent_version`, `allowlist_version` and `allowlist_sha256`, so the server
can tell which build it talks to. Keep the `.crt` and `.key` and the fingerprint does not change.

**To 0.2.1** (connection labels, `activity`, the status log): nothing to configure, and the
allowlist and deny list hashes are the same as in 0.2.0 (`filecat agents status` shows `match`).
Update the agents before relying on busy detection: against a 0.2.0 agent `filecat agents status`
prints `activity not supported (agent 0.2.0)` and `filecat server` goes by its own running jobs
only. The newer `filecat` works with either agent.

**To 0.2.2**: the agent behaves exactly as 0.2.1 (same protocol, allowlist and deny list hashes);
0.2.2 is the first release built and published by the release workflow. Updating is optional.

## 9. Scheduled work: `filecat server`

Once `filecat agents status` is green, `filecat server` keeps the agents checked and runs
`[[server.jobs]]` (storage collects, scans, store re-sums) on a schedule, with its history in the
catalog and `--serve` for the viewer. Example for one NAS in `filecat.toml`:

```toml
[[server.jobs]]
name = "nas3-topology"
kind = "storage-collect"
agent = "nas3"
every = "24h"

[[server.jobs]]
name = "nas3-nightly"
kind = "scan"
agent = "nas3"          # no roots = every root nas3 covers
at = "02:30"
```

A job that has never run waits for its first slot (the next 02:30; 24 h after the server first saw
an `every = "24h"` job); add `run_on_start = true` to run it as soon as the server starts.

`filecat server --dry-run` shows the plan; Task Scheduler or cron can run `filecat server --once`
every 15 minutes instead of a resident process. Everything is in [agent-server.md](agent-server.md).

## Conformance and builds in CI

`.github/workflows/ci.yml` has three agent jobs (Rust 1.98.0): `agent` (every push and pull
request: clippy with `-D warnings`, `cargo test` natively, which includes
`expected_json_matches_this_build`, so allowlist or deny-list drift against
`src/filecat/data/agent_expected.json` fails the build, then `./build.sh all` for the three static
musl targets, a `file` check that each is statically linked, and the three binaries plus
`SHA256SUMS` as the workflow artifact `filecat-agent-linux-static`); `agent-arm-tests` (the ARM
unit tests under qemu-user, 3-4 minutes each, only on pushes to main and manual runs); and
`agent-conformance` (the Python agent tests against the real x86_64 binary built with
`test-root`; `tests/_real_agent.py` starts it directly on Linux, so the symlink tests that skip on
Windows run). The conformance job gates the build: the six Linux-only failures its first run found (UNC
spelling of an `x3_cat` sibling, the SMB fallback tests patching `os.stat` for every path, the two
`rollups redacted release` tests with a POSIX path, and local-versus-agent mtimes at nanosecond
versus 100 ns) were fixed in the code or the tests, and the job passes as a normal user against the
real binary. `cargo fmt
--check` is not in CI: the sources are not rustfmt-formatted yet.

**Releases.** `.github/workflows/release.yml` runs on a tag `vX.Y.Z`: it fails unless the tag
matches the version everywhere (`scripts/version.py --check`), runs `cargo test`, builds the three static agents with
`./build.sh all`, checks each is statically linked, and publishes a GitHub release with
`filecat-agent-X.Y.Z-linux-{x86_64,armv7,aarch64}` and `SHA256SUMS` (the tag message is the
release notes). The steps, and every file that carries the version, are in
[releasing.md](releasing.md).

## Notes for DSM

- DSM 7.1 and 7.2 run a 4.x kernel with an old glibc; a musl static binary does not care. `statx`
  is missing there, so `ctime_ns` is the inode change time rather than the birth time; the
  protocol allows both.
- DSM has no `lsblk` or `findmnt`: those `run` entries report `available: false` in
  `capabilities` and the collectors use `/proc`, `/sys` and `/etc/space` instead. `smartctl`,
  `mdadm`, `btrfs` and `blkid` are there.
- Large trees: a walk is bound by `lstat`; allow minutes for millions of files and use the
  client's `progress_ms` rather than a long timeout.
- Large pages: Synology's `alpine` kernel (DS2015xs and the other Annapurna Alpine models on
  Linux 3.10.108; the `alpine4k` ones use 4 KiB) uses **32 KiB** memory pages (`KernelPageSize:
  32 kB`, measured on a DS2015xs). A binary whose LOAD segments are laid out for 4 KiB pages is
  killed at exec, as `Killed` (exit 137) with nothing in `dmesg`, when a segment's address and file
  offset differ by other than a multiple of 32 KiB; when two segments share a 32 KiB page, the
  later one's permissions replace the earlier one's (code that is no longer executable). The 0.2.2
  armv7 build loaded by luck. `build.sh` links armv7 with `-z max-page-size=0x10000` (GNU ld already
  does so for aarch64, not for armv7), which loads with 4, 16, 32 and 64 KiB pages, and
  `check_pages` fails the build of either ARM binary that would not load with 64 KiB pages.
- The clock on Synology's 32-bit ARM kernels: musl reads the time with `clock_gettime64`
  (syscall 403, Linux 5.1+) and falls back to the old `clock_gettime` only when the kernel says
  `ENOSYS`. Synology's 3.10 kernel has its own syscall at 403 ("archive bit") that answers `EINVAL`
  (`dmesg`: `Archive bit cmd:<address> not implement.`), so every clock reading of a musl binary
  fails, and std panics on it (`time.rs ... Os { code: 22, kind: InvalidInput }`): the agent
  starts, then each connection's thread dies and the client sees `ConnectionResetError`. Before
  0.2.3 the armv7 agent could not serve a connection on such a NAS. The agent now reads every
  clock through `src/clock.rs`, which makes the old syscall on 32-bit ARM, including rustls's
  clock; a test fails if any other source reads std's clocks.
- Synology's syscall block on ARM: upstream Linux 3.10 ends at 379 (`finit_module`); Synology's
  own syscalls reportedly occupy 402-427 (`SYNOUtime`, `SYNOArchiveBit`, `recvfile`, the
  `SYNO*Stat64` calls, `SYNONotifyInit` ...), which collides with the 64-bit time syscalls newer
  kernels put at 403-423 and with `io_uring` at 425-427. Only 403 is confirmed here (the `dmesg`
  line above); the rest is from a summary of Synology's 3.10 `calls.S`, not checked against the
  source. What the agent uses on 32-bit ARM, and why it stays out of that block:

  | need | syscall | note |
  |---|---|---|
  | the clock | `clock_gettime` (263) | `src/clock.rs` calls it directly; musl would try 403 first |
  | sleeping | `nanosleep` (162) | musl uses `clock_nanosleep_time64` (407) only for a time that does not fit 32 bits |
  | locks, untimed waits | `futex` (240) | std calls it directly on musl; timed waits go through `src/clock.rs` instead |
  | file metadata | `statx` (397), then `fstatat64` (327) | 397 is not implemented on 3.10 (`ENOSYS`), and std falls back to 327 for good |
  | directory listing | `getdents64` (217) | |
  | random (TLS) | `getrandom` (384), then `/dev/urandom` | 384 is Linux 3.17+: `ENOSYS` on 3.10, and the fallback reads the device |

  No timers, `ppoll`/`pselect`, `utimensat` (the agent never writes), message queues or
  `io_uring`. A new dependency or std feature that reads the clock or uses those calls would
  reach Synology's block: test armv7 builds on the NAS itself, since qemu-user and CI kernels
  have the upstream syscalls.
- Which build a Synology model needs: look up its CPU and package arch (platform) in Synology's
  table, [What kind of CPU does my NAS have?](https://kb.synology.com/en-global/DSM/tutorial/What_kind_of_CPU_does_my_NAS_have#x15-series)
  (the DS2015xs: Annapurna Labs Alpine AL-514, 4 cores, `armv7`, package arch `alpine`, DDR3 4 GB).
  `uname -a` on the NAS ends in the platform too (`synology_alpine_ds2015xs`). The platform picks
  the binary by `uname -m` (`armv7l` -> armv7, `aarch64` -> aarch64, `x86_64` -> x86_64) and tells
  the page size: Synology's toolchains come per platform, and a platform with a `4k` twin
  (`alpine` and `alpine4k`) is the one that does not use 4 KiB pages (`alpine`: 32 KiB). The
  toolchains and their kernel versions
  are listed per DSM release in the [toolchain archive](https://archive.synology.com/download/ToolChain/toolchain/7.1-42661)
  (DSM 7.1: `alpine` and `alpine4k`, both Linux 3.10.108), and how to use them is in the developer
  guide, [Download DSM Tool Chain](https://help.synology.com/developer-guide/compile_applications/download_dsm_tool_chain.html).
  filecat does not use them (the agent is a static musl binary built with Rust's own toolchain);
  they are the reference for a platform's kernel, page size and architecture flags.
- To check the page size on the NAS itself: `grep -m1 KernelPageSize /proc/self/smaps` (`32 kB`
  on `alpine`, `4 kB` on most others).
