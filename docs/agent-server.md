# The agent workflow and the central server

How a filecat-agent is enrolled and checked (`filecat agents enroll`, `filecat agents status`), and
`filecat server`, the long-running coordinator that keeps the agents healthy and runs the scans and
storage collections on a schedule. Related: [agent-protocol.md](agent-protocol.md) (the wire
protocol, `capabilities`), [agent-deploy.md](agent-deploy.md) (the NAS side),
[scanning.md](scanning.md) section 6 (scanning through an agent),
[storage-topology.md](storage-topology.md) section 7 (the catalog store),
[rollups.md](rollups.md) (`store_resum`, the output-channel rules).

## 1. Pieces and names

| command | what it is |
|---|---|
| `filecat agents list / test` | existing: the configured `[[agents]]`; connect and say hello |
| `filecat agents enroll NAME --host H` | new: make a token, print what goes on each host, fetch the certificate fingerprint |
| `filecat agents fingerprint HOST[:PORT]` | new: the certificate fingerprint an agent presents (for after it started) |
| `filecat agents status [NAME..]` | new: hello + capabilities, and whether the agent is the build this filecat expects |
| `filecat server` | new: the coordinator (health checks, scheduled jobs, job history, optional viewer) |
| `filecat serve` | existing: the read-only web viewer. `filecat server --serve` runs it in the same process |
| `ScanServer.ps1` | existing PowerShell script: SMB-only, see section 9 |

`filecat serve` stays a viewer: it never starts a scan, never needs agents and has no state of its
own. `filecat server` is the process that does things.

## 2. Enrolling an agent

```
filecat agents enroll nas3 --host nas3.lan[:9876] [--alias \\nas3] [--write] [--cert-sha256 HEX] [--no-connect]
```

1. A token: 32 random bytes from `secrets` as 64 hex digits.
2. It prints, for the **agent host**, the `.env` lines (`FILECAT_AGENT_TOKEN=...` and a commented
   `FILECAT_AGENT_ALLOW_ROOTS=...` example) and for the **filecat host** how to set
   `FILECAT_NAS3_TOKEN` (the variable is `FILECAT_<NAME>_TOKEN`, name upper-cased, anything that is
   not a letter or digit becomes `_`) in PowerShell and in sh, and the `[[agents]]` stanza. The stanza
   holds `token = "${FILECAT_NAS3_TOKEN}"`, never the token. **The token is printed this once** and
   stored nowhere: lose it and enrol again (a new token, a new `.env`).
3. It connects once, without verifying the certificate, and prints the SHA-256 of the certificate
   the other end presented (trust on first use). The admin compares it with the `cert_sha256` the
   agent printed at its first start; a difference means something else answered. If the agent is not
   running yet (the usual order: token first, then deploy, then start) the stanza carries a
   placeholder and `filecat agents fingerprint HOST` gives the value later.
4. Nothing is written to `filecat.toml` unless `--write`. Then the stanza is appended (a blank line
   before it), only when a fingerprint is known (fetched, or `--cert-sha256`), and enrol refuses with
   exit 2, before generating anything, when `NAME` is already an `[[agents]]` name in that file.
   There is no `--write` without a file: `filecat config init` makes one.

`NAME` is letters, digits, `.`, `_`, `-`. `--alias` is the server name SMB scans record the shares
under (the existing `alias` key; default `\\NAME`).

## 3. `filecat agents status`

One probe per agent (`agent_status.probe`, shared with the server's health check): TLS and
certificate pin, hello, auth, `capabilities`. Per agent: version, protocol, host and platform;
reachable; certificate pin ok/mismatch; `allow_roots` and `allow_roots_source`; `product_type`
(Windows agents); the `run` ids that are available and those the host lacks; the agent's
`allowlist_sha256` and `deny_sha256` and whether each matches what this filecat expects.
`--json` is one object per agent. An error text never contains a path (section 8).

Exit code: 1 when an agent is unreachable, its pin or token fails; with `--strict` also 1 on a hash
mismatch or any warning; otherwise 0 (a mismatch is a warning, not an outage).

### Expected hashes and how they stay in step

An agent built from the sources of another filecat version (older) or edited reports another
`allowlist_sha256` (the compiled command table) or `deny_sha256` (the compiled deny list). The
mismatch warning reads: *agent built from a different allowlist/deny list (outdated or modified)*.

`src/filecat/data/agent_expected.json`, per protocol version:

```json
{"1": {"deny_sha256": "bc79...", "allowlist_sha256": {"linux": "1421...", "windows": null}}}
```

* `deny_sha256` is **computed in Python**: `filecat.agent_expected` holds the deny list (path rules,
  env-file exceptions, Windows rules, key signature lines) and `deny_sha256()` hashes it; the fake
  agent in the tests imports the same function. A test recomputes it and compares with the file.
* `allowlist_sha256` comes from the **Rust build**: the table lives in `agent/src/allowlist.rs`.
  A `null` (Windows until phase 2) or missing value means "not known": no warning for that side.
* Drift is caught on both sides: the Python test above, and a **cargo test**
  (`allowlist::tests::expected_json_matches_this_build`) that `include_str!`s the JSON and fails
  when the Rust hashes differ from it. `agent/build.sh hashes` prints the Rust values.
* Update procedure when the allowlist or deny list changes: bump `ALLOWLIST_VERSION`/`PINNED` in the
  Rust test as before; `./build.sh hashes`; copy the printed values into `agent_expected.json` (and
  the deny lists in `agent_expected.py` if they moved); `./build.sh test` and the Python suite are
  green again. A protocol version bump adds a new top-level key.

## 4. `filecat server`

```
filecat server [--serve [HOST:PORT]] [--once] [--dry-run] [--job NAME ...] [--backend/--out/--dsn]
```

A long-running process. It holds the configured `[[agents]]`, checks their health, runs the jobs
of `[[server.jobs]]` on their schedules against the catalog (`--backend`, `--out`, `--dsn` or
`filecat.toml`, as every command), records every run, and (optionally) serves the viewer.

* `--once` runs every job that is due now once and exits (for Task Scheduler or cron: start it every
  15 minutes and the jobs run when due, because "due" is computed from the persisted history).
  `--job NAME` (with `--once`, repeatable) runs only the named jobs, whatever their schedules say. Exit 0 when every run
  ended `ok`, 1 when one ended `errors`, `failed` or `cancelled`, 4 when another server holds the
  lease.
* `--dry-run` prints the plan (agents, jobs, next due times, what each job would do) and exits; it
  touches nothing and takes no lease.
* `--serve [HOST:PORT]` (default `127.0.0.1:8765`, or `[server] serve`) also runs the viewer in a
  thread of this process, with `/api/agents` and `/api/jobs` live.
* Ctrl+C and SIGTERM stop it gracefully (section 7).

### Agents: health

Every `health_interval` (default 60 s) each agent is probed (`agent_status.probe`: hello +
capabilities, certificate pin, token). State per agent: `up` or `down`, since when, the last error
(scrubbed), version, platform, the hash match flags, warnings, consecutive failures, next check. A
down agent is probed with exponential backoff from `health_interval` up to `health_backoff_max`
(default 10 min), and back to the normal interval on the first success. A probe is one short
connection of its own and never waits for a job; it runs in a worker thread so a timeout does not
stall the scheduler. State changes (up to down and back, a new mismatch) are logged once.

A job for a down agent is not started: it is recorded `skipped` ("agent down since ...").

### Jobs: kinds

All run **in-process** (a thread of the server), calling the functions the commands call:

| kind | does | the same as |
|---|---|---|
| `storage-collect` | `storage_cmd.collect_agent` then `topology_store.save_snapshot` for the job's agent | `filecat storage collect --agent NAME` |
| `scan` | `scan.scan_roots` over the job's roots, forced through the job's agent | `filecat scan --agent NAME ROOT...` |
| `store-resum` | a `scan` of the roots whose last finished scan is older than `min_age` | see below |

Why in-process and not a subprocess: the commands are library functions already (`scan_roots`,
`collect_agent`), a server needs the result (counts, outcome) and cancellation without parsing
output, one catalog connection policy is easier to keep, and tests run on the fake agent without a
second Python. What a subprocess would buy is isolation from a crash (a native library fault, memory
growth in a scan of millions of files). The mitigation is `--once` driven by an external scheduler,
which is a fresh process per run; the server's own state is entirely in the catalog, so a restart
loses nothing.

**`store-resum`.** Rollups of backup and database stores are carried forward while their
fingerprint is unchanged and the sum is younger than `[rollups] store_resum` (30 days, rollups.md
section 7); an ordinary scan past that age re-sums them. The job guarantees that happens for a
catalog whose roots are not scanned often: for each root it selects it reads the root index
(`rootinfo`), and scans (without `--force`) those whose `last_scan.finished_at` is older than
`min_age` (default `store_resum` minus one day); when none is that old it ends `ok` with
`stale_roots: 0` and does nothing. Typical: `every = "24h"`.

**Roots.** `scan` and `store-resum` take `roots = [...]` or, when omitted, every root that agent
covers: the catalog's roots for which `config.agent_for` picks that agent, plus the shares of the
agent's stored topology snapshot (`unc_roots`), so a new share is scanned after the first
`storage-collect`.

**Options.** `options = [...]` is a list of command-line words of the equivalent command, parsed by
the real parser (`--hash none`, `--workers 8`, `--rollup cache=automatic`, `--exclude PATH`;
`--measure-shares` for `storage-collect`), so they mean exactly what they mean there. The catalog
(`--backend --out --dsn`), `--agent`, `--no-agent` and `--check` are the server's to decide and
rejected in `options`. `[rollups]`, `[aliases]` and `[[agents]]` are the file's, as for any scan.

### Scheduling

Per job exactly one of `every = "24h"` (units `s m h d`) or `at = "02:30"` (a daily local time; a list
of times is allowed). A job's **anchor** is when it last started (from the persisted history; none
means never, so it is due at once). Interval: due when `anchor + every <= now`. Daily: due when the
most recent slot at or before `now` is later than the anchor (a missed slot runs once, late, not
once per missed day). Rules, in this order for each due job (config order):

1. **Same job still running: skip.** Recorded as a `skipped` run ("previous run still running"),
   logged, and the anchor moves to now so it is not logged again every tick.
2. **At most one job per agent at a time.** If another job of the same agent runs (or was just
   chosen this round) the job **waits**; it stays due and starts when the agent is free. Jobs of other
   agents are not held up.
3. **Global limit** `max_concurrent` (default 2; 1 for the file backends `sqlite` and `jsonl`, whose
   writers do not like company). Over the limit a job waits.
4. A job for an agent that is `down` is skipped (above). `max_runtime` (optional, per job) cancels a
   run that takes longer.

The clock is injectable, so the whole thing is tested with a fake clock.

### The single-instance lease

Two servers on one catalog would run every job twice. The catalog holds one row in `server_state`
(key `lease`): `holder` (a random id per process), `host`, `pid`, `started_at`, `renewed_at`,
`expires_at`. A server acquires it when the row is missing, expired, or its own; renews it every
`lease_ttl / 3` (default ttl 90 s); releases (deletes) it on a clean exit. If a renewal finds
another holder (it stalled past the ttl and was replaced) it stops everything and exits 3 (cancel,
no more jobs). A server that cannot acquire exits 4 and says who holds it and until when. On
acquiring, runs left `running` by a dead server are marked `lost`.

It is "check, write, read back": simple, portable to every backend, but not an atomic
compare-and-swap, so two processes starting in the same few milliseconds could both think they won;
the read-back makes that very unlikely and the renewal check repairs it within `ttl / 3`. A real
atomic acquire per SQL backend is a possible refinement (section 11).

### Shutdown

Ctrl+C or SIGTERM: stop starting jobs; set every running job's cancel event (`ScanOptions.cancel`:
the scan raises `ScanCancelled`, a `KeyboardInterrupt`, at the next entry or progress line, so the
root is marked interrupted, the resume file is kept, and an in-flight `sum_subtree` is stopped with
the protocol's `cancel` on a second connection, which `fsource` already does for any interrupt);
wait up to `shutdown_grace` (default 30 s) for the job threads; record each unfinished run
`cancelled`; save the agent states; release the lease; stop the viewer. Exit code 0 for a requested stop. (If the process is killed outright the
lease simply expires after `lease_ttl`, and the next server marks the unfinished runs `lost`.)

## 5. Configuration

```toml
[server]
health_interval     = "60s"     # agent probe every...
health_timeout      = "5s"
health_backoff_max  = "10m"     # a down agent is probed less often, up to this
max_concurrent      = 2         # jobs at once (default 1 on sqlite/jsonl catalogs)
lease_ttl           = "90s"
shutdown_grace      = "30s"
history_keep        = 500       # job runs kept, newest first...
history_days        = 90        # ...and none older than this
serve               = "127.0.0.1:8765"   # optional: same as --serve

[[server.jobs]]
name      = "nas3-topology"     # unique; shown in history and the viewer
kind      = "storage-collect"   # storage-collect | scan | store-resum
agent     = "nas3"              # an [[agents]] name, or "*" for one job per agent
every     = "24h"               # or: at = "02:30"  (or at = ["02:30", "14:30"])
options   = ["--measure-shares"]

[[server.jobs]]
name      = "nas3-nightly"
kind      = "scan"
agent     = "nas3"
roots     = ['\\nas3\Backup', '\\nas3\Photos']   # omit: every root the agent covers
at        = "02:30"
options   = ["--hash", "auto", "--workers", "4"]
max_runtime = "6h"
# enabled = false

[[server.jobs]]
name      = "all-stores"
kind      = "store-resum"
agent     = "*"
every     = "24h"
min_age   = "28d"               # default: [rollups] store_resum minus one day
```

Validation (all errors name the table and key): unknown keys; a `name` used twice; `agent` not in
`[[agents]]`; neither or both of `every` and `at`; `every` below 1 minute; `at` not `HH:MM`;
`options` not a list of strings or containing a forbidden option; `roots` on `storage-collect`;
`min_age` on a kind other than `store-resum`. With `agent = "*"` a job expands to one job per agent
named `NAME@agent`.

## 6. Where the state lives

Two stores of whole documents, in every backend, built on the storage topology's row primitives
(`Backend._topology_rows/put/remove`, commit 276b474) with the same table shape (`doc_key`, `host`,
`scanned_at`, `document`); `Backend.DOC_STORES = TOPOLOGY_STORES + SERVER_STORES` and
`put_server_doc`, `server_docs`, `delete_server_doc` expose them. Implemented for **all backends the
catalog supports**: SQLite, PostgreSQL, MySQL, SQL Server (two tables each, created with the others),
MongoDB (two collections with a unique `key`), the memory backend, and the JSONL file and directory
layouts (in the same `*.storage.json` / `storage.json` file as the topology). The SQL, MongoDB and
JSONL code paths are the topology ones with another table name; SQLite and memory are exercised by
the tests, the server backends need a running server (`FILECAT_TEST_*` variables) and are not run
here.

* `server_jobs`: one document per run, key `<started_at>#<job>`, host = the agent, scanned_at =
  started_at:
  `{key, job, kind, agent, host, scanned_at, started_at, ended_at, outcome, exit_code, trigger,
  roots, counts, error, server}`. `outcome` is `running`, `ok`, `errors` (the run completed, some
  records carry errors: the exit code 1 of `scan`), `failed`, `cancelled`, `skipped` (with `error`
  holding the reason) or `lost`. `counts`: scan, files/dirs/bytes/errors summed from the root index
  after the run and `roots`; storage-collect, `nodes`, `changed`; store-resum, `stale_roots`. The row is
  written when the run starts (`running`) and replaced when it ends. Pruned to `history_keep` rows and
  `history_days` days at start and once a day.
* `server_state`: key `lease` (section 4) and key `agents`, the last agent states, saved when one
  changes so a viewer that is not the server (a `filecat serve` somewhere else, on the same catalog)
  can still show them with their age.

JSONL caveat: the JSONL layouts keep these in one small JSON file rewritten whole; another process
writing the topology at the same moment (a manual `filecat storage collect` while the server runs)
can lose one of the two updates. Use SQLite or a server backend for a long-running server.

## 7. The web viewer and its API

`filecat serve` and `filecat server --serve` share the handler. Two read-only JSON endpoints:

* `GET /api/agents` -> `{"source": "live" | "catalog", "server": {holder, host, pid, started_at,
  renewed_at, expires_at, alive}, "agents": [{name, endpoint, state, since, last_check, last_error,
  version, platform, allowlist_match, deny_match, warnings, failures, next_check, running}]}`. From
  the running coordinator when there is one in the process, else the last saved state (`catalog`).
* `GET /api/jobs?limit=50&job=&agent=` -> `{"source", "server", "jobs": [configured jobs: name, kind,
  agent, schedule, next_due, running, last_outcome], "recent": [run documents, newest first]}`.
  `jobs` is empty when the server is not in this process.

A **Server** view in the page (nav link next to Roots) shows both as two tables, refreshed every 15
seconds. No endpoint starts, stops or edits anything: the viewer has no authentication.

## 8. What is logged and stored (rollups.md section 3)

The server writes to stderr and to the catalog. Neither may carry the name of a folder under a
`[REDACTED]` rollup, nor a path from a private rule. So: log lines and stored fields hold only job
names, agent names, kinds, counts, outcomes, times and the **root** (a configured share such as
`\\nas3\Backup`, which the root index shows anyway). Errors are `Type: message` with every
path-looking substring (UNC, drive, POSIX) replaced by `<path>` and cut at 300 characters
(`agent_status.scrub`); an `OSError`'s file name is never repeated. A scan running in-process prints
its usual progress lines to stderr (redaction-safe by their own rules, rollups.md 3.2/3.3); the server sets their
interval to 60 s. Each scan job keeps its own resume file next to the catalog
(`<catalog>.<job>.resume.json`), so jobs that run side by side do not overwrite each other's.

## 9. ScanServer.ps1

Kept, as **legacy**, not replaced: it solves a different problem. It discovers the disk shares of a
Windows or SMB server with `net view`, maps credentials with `net use`, and scans them over SMB on
a machine that has no agent, once, by hand or from Task Scheduler. `filecat server` knows nothing
about `net use` or share discovery: it works with agents (a NAS) and with roots you name. Use
`ScanServer.ps1` for an SMB-only server with no agent; use `[[agents]]` plus `[[server.jobs]]` for
anything that runs an agent. The roadmap item "Windows agent" is what would retire it. The script's
header now says so.

## 10. Tests

Fake-clock scheduler (due, skip-while-running, per-agent exclusivity, global limit, interval versus
daily time, a missed slot, down agents); health state and backoff; lease acquire, refuse, expiry,
renewal, loss, release; `--once` running a `storage-collect` and a `scan` through the fake agent
into a SQLite catalog, with the history rows; `--dry-run`; the API endpoints on the same handler as
`serve`; shutdown cancelling a running job, marking it `cancelled` and releasing the lease; the
config schema errors; no path in a stored error; plus the `agents enroll|status` tests and the
expected-hash tests.

## 11. Open questions

* An atomic lease acquire per backend (`INSERT ... WHERE expired` on SQL, `findOneAndUpdate` on
  MongoDB). The portable read-back is enough for one admin and two accidental starts.
* `ScanServer.ps1`: retire it with the Windows agent, or fold `net view` share discovery into a
  `scan` job kind (`shares = "discover"`)?
* A manual trigger from the viewer ("run now") is deliberately absent: the viewer has no
  authentication. A `filecat server --once --job NAME` does it from the shell.
* Alerting (mail, webhook) on an agent going down or a job failing: not designed here.
* The anchor of a first-ever run is "now": a freshly configured `scan` job starts a full scan the
  first time the server runs. `--dry-run` shows it before.
