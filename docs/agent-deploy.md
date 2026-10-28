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
./build.sh              # release; prints the path, normally ~/.cache/filecat-agent-target/x86_64-unknown-linux-musl/release/filecat-agent
file "$HOME/.cache/filecat-agent-target/x86_64-unknown-linux-musl/release/filecat-agent"   # static-pie, statically linked
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
fingerprint once if the agent is already running. The token is printed once. The whole workflow:

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
EOF
chmod 600 .env
echo "token (put it in the server's environment, not in filecat.toml): $TOKEN"
```

The token is never a command-line argument (it would show in `ps`). The agent refuses to start
without one. `.env` itself is on the agent's deny list: it cannot be read through the agent.

Settings are taken from the command line, then the environment, then the `.env`:
`FILECAT_AGENT_TOKEN`, `FILECAT_AGENT_TOKEN_FILE`, `FILECAT_AGENT_LISTEN` (default
`0.0.0.0:9876`), `FILECAT_AGENT_CERT` / `FILECAT_AGENT_KEY`, `FILECAT_AGENT_ALLOW_ROOTS`.

## 4. First start and the certificate fingerprint

```sh
/usr/local/filecat-agent/filecat-agent
# filecat-agent 0.2.0 listening on 0.0.0.0:9876
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

`filecat server --dry-run` shows the plan; Task Scheduler or cron can run `filecat server --once`
every 15 minutes instead of a resident process. Everything is in [agent-server.md](agent-server.md).

## Notes for DSM

- DSM 7.1 and 7.2 run a 4.x kernel with an old glibc; a musl static binary does not care. `statx`
  is missing there, so `ctime_ns` is the inode change time rather than the birth time; the
  protocol allows both.
- DSM has no `lsblk` or `findmnt`: those `run` entries report `available: false` in
  `capabilities` and the collectors use `/proc`, `/sys` and `/etc/space` instead. `smartctl`,
  `mdadm`, `btrfs` and `blkid` are there.
- Large trees: a walk is bound by `lstat`; allow minutes for millions of files and use the
  client's `progress_ms` rather than a long timeout.
