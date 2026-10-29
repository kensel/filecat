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
filecat agents enroll nas3 --host nas3.lan[:9876] [--alias \\nas3] [--write] [--cert-sha256 HEX] [--no-connect] [--token HEX|-]
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

With an agent 0.2.1 or newer it also asks `activity` and lists the **other** connections (its own is
left out): the client's label, address, how long it has been connected, the command it runs, and
files, data read and files/s:

```
ok   nas3     192.0.2.13:9876  filecat-agent 0.2.1, protocol 1, host nas3 (linux/x86_64)
  ...
  sessions     1 other connection(s)
    scan \\nas3\Apps by kense@DESKTOP  192.0.2.20:51234  connected 12m  sum_subtree for 3m  41234 files, 12.40 GB read, 57.3 files/s
```

`no other connections` when the agent is otherwise idle; `activity not supported (agent 0.2.0)` for
an older one (not a failure). In `--json` the object has `sessions` (a list, or `null`) and
`activity_note`. Every `filecat` connection carries a label: `scan <roots> by user@host` (the CLI
scan), `storage collect by user@host`, `job <name>: <kind>` (the server's jobs), and `health check`,
`busy check`, `agents status` and `viewer` for the ones that look rather than work.

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
| `summaries` | rebuild the stored summaries of the roots whose records changed since they were built | `filecat summaries` |

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

**`summaries`.** Reads each root's records once and stores its aggregates and its depth-2 treemap
(section 7, "Stored summaries"), for the roots with no summary or whose records changed after it
was built; the others, and a root a scan is walking, are skipped. It reads the catalog, not an
agent, so it has no `agent` (naming one is an error) and counts as the pseudo-agent `(local)`,
like a scan no agent covers: it does not run beside one. `roots = [...]` limits it, `options =
["--all"]` rebuilds every selected root whatever its state. The run's counts are `roots`,
`refreshed`, `skipped`, `failed`; `failed` makes the outcome `errors`. A scan already ends by
summarising the roots it changed, so this job is for what scans do not cover: records changed by
other tools, a catalog restored or migrated, summaries lost to `--no-save` viewers. Typical:
`every = "6h"`.

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
of times is allowed). A job's **anchor** is when it last started (from the persisted history).
Interval: due when `anchor + every <= now`. Daily: due when the most recent slot at or before `now`
is later than the anchor (a missed slot runs once, late, not once per missed day).

**First run.** A job that never ran **waits for its first slot**: `at = "02:30"` runs at the next
02:30; `every = "24h"` runs 24 h after the server first saw the job. "First saw" is saved in the
catalog (`server_state`, key `first_seen`) the first time the server starts with the job, and is the
anchor until the job has a run in the history; so restarting the server does not keep pushing the
first run away. (A job whose runs were all skipped has no start in the history either, so its first
run is still anchored on that saved time.) Per job `run_on_start = true` restores the old
behaviour: a never-run job is due at once when the server starts. `--dry-run` says which applies
("first run 1d after the server first starts", "first run 2026-10-29 02:30", "at server start").
`--once` follows the same rule (use `--job NAME` to force a job).

Rules, in this order for each due job (config order):

1. **Same job still running: skip.** Recorded as a `skipped` run ("previous run still running"),
   logged, and the anchor moves to now so it is not logged again every tick.
2. **At most `max_jobs` jobs per agent at a time** (an `[[agents]]` key, default 1). If that many of
   the agent's jobs run (or were just chosen this round) the job **waits**; it stays due and starts
   when the agent is free. Jobs of other agents are not held up.
   **Busy deferral.** The limit counts the agent's other clients too: just before a job that uses an
   agent would start, the server asks the agent's `activity` and counts the other sessions that are
   *working*: authenticated, and either running a command now or labelled and with a request in the
   last 60 s. Health checks, the busy check itself, `agents status` and the viewer are labelled so they
   never count, and the server's own jobs (label `job <name>: <kind>`) are counted once, not twice.
   When our own running jobs plus the other working sessions reach `max_jobs`, the job does **not**
   start, stays due, and is tried again on the next tick (the answer is reused for 5 s). One line is
   logged per busy spell, with who and for how long:
   `job nightly-apps waits: nas3 busy (scan \\nas3\Apps by kense@DESKTOP for 12m)` (and `and 2 more`).
   The viewer's Jobs table shows `waiting: nas3 busy (...)` for it. An agent older than 0.2.1, or one
   that cannot be asked, falls back to counting the server's own running jobs only. The ad-hoc scan
   of a root no agent covers (SMB) is never deferred.
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

Acquiring and renewing are **one atomic conditional write** in the backend
(`Backend.claim_server_doc`): the lease row is written only when it is absent, held by the caller,
or (acquire only) expired; the caller learns from the affected-row count whether it won. Renewal is
the same write with "expired" taken out: only the holder renews, and a server whose lease lapsed
and was taken over cannot take it back by renewing.

| backend | how |
|---|---|
| SQLite, PostgreSQL | one `INSERT ... ON CONFLICT (doc_key) DO UPDATE ... WHERE holder = me OR expires_at < now`; rowcount 1 = won |
| MySQL, SQL Server | `UPDATE ... WHERE doc_key = k AND (holder = me OR expires_at < now)`; when it matched nothing, `INSERT`; the primary key makes a racing second insert fail with a duplicate-key / integrity error = lost |
| MongoDB | `replace_one({key, $or: [{holder: me}, {expires_at: {$lt: now}}]}, doc, upsert=True)`; the unique index on `key` turns the upsert against a live holder into `DuplicateKeyError` = lost |
| memory | a lock |
| JSONL files | best-effort read-check-write (single host only: those layouts cannot arbitrate between machines anyway) |

The holder and expiry are compared as the UTC ISO strings the server writes (same width, so text
order is time order); the comparison uses the claiming server's clock, so servers sharing a catalog
need clocks within a few seconds of each other (the ttl is 90 s by default). The PostgreSQL, MySQL,
SQL Server and MongoDB paths run only in CI (`tests/test_lease_contract.py` under the `backends`
job: two holders racing on separate connections, expiry takeover, renewal by a non-holder).

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
progress_interval   = "10m"     # a log line and a stored progress per running job; 0 turns it off
lease_ttl           = "90s"
shutdown_grace      = "30s"
history_keep        = 500       # job runs kept, newest first...
history_days        = 90        # ...and none older than this
serve               = "127.0.0.1:8765"   # optional: same as --serve
# "Run now" in the viewer (section 7): off unless a password hash is set. Never the password itself.
# control_password_hash = "${FILECAT_SERVER_PASSWORD_HASH}"   # or the scrypt$... line `set-password` prints
# login_max_failures = 5         # failed logins per address within login_window, then blocked...
# login_window = "15m"
# login_block = "15m"            # ...for this long (doubling on every try while blocked, up to 24h)
# login_global_max_failures = 20 # across all addresses within login_window: every login refused
# login_required_for_view = false  # true: the whole viewer needs a login, not only "run now"
# [server.tls] serves the viewer over HTTPS itself (self-signed, your certificate, or ACME DNS-01): section 7, "TLS"

[[server.jobs]]
name      = "nas3-topology"     # unique; shown in history and the viewer
kind      = "storage-collect"   # storage-collect | scan | store-resum | summaries
agent     = "nas3"              # an [[agents]] name, or "*" for one job per agent
every     = "24h"               # or: at = "02:30"  (or at = ["02:30", "14:30"])
# run_on_start = true           # a never-run job runs at server start, not at its first slot
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

[[server.jobs]]
name      = "summaries"
kind      = "summaries"         # no agent: it reads the catalog
every     = "6h"
```

`[[agents]]` takes one key for the server: `max_jobs = 1` (a whole number from 1 to 64): how many jobs,
the server's and other clients' together, the agent takes at once (rule 2 above).

**Progress.** Every `progress_interval` (default `10m`; `0`, a number and not `"0s"`, turns it off) each
running job gets one log line and one small write to its run in the catalog: 

```
job nightly-apps progress: scan on nas3, 10m elapsed, 1200 files, 5.00 GB, 2.0 files/s, root \\nas3\Apps
```

and `progress` = `{"at": ..., "files": ..., "bytes": ..., "rate": files per second since the last
one, "root": the root being scanned}` in the run's record (`/api/jobs` `recent`, and `progress` of a
running job in `jobs`, which the Server page shows under "running"). The counters are the scan's own
(`scan.LiveProgress`: files and bytes of the roots done plus the one in progress), so it costs the scan
nothing; a `storage-collect` has no file count and reports 0. Only the root, never a path inside it.
The final record keeps the last progress.

Validation (all errors name the table and key): unknown keys; a `name` used twice; `agent` not in
`[[agents]]`; neither or both of `every` and `at`; `every` below 1 minute; `at` not `HH:MM`;
`options` not a list of strings or containing a forbidden option; `roots` on `storage-collect`;
`min_age` on a kind other than `store-resum`; `agent` on `summaries`. With `agent = "*"` a job expands to one job per agent
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
  after the run and `roots`; storage-collect, `nodes`, `changed`; store-resum, `stale_roots`; summaries,
  `roots`, `refreshed`, `skipped`, `failed`. The row is
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
seconds. `/api/jobs` also carries `control: {available, reason}`. An ad-hoc scan from the Roots page
(below) appears in `jobs` while it is queued or running, marked `"adhoc": true`.

### Run now (and the login it needs)

Each configured job has a **Run now** button on the Server page. The rest of the viewer has no
authentication, so this is the one action that starts work, and it is guarded:

* **Only inside `filecat server --serve`.** A plain `filecat serve` has no coordinator: the
  endpoints answer 404 and the button is disabled with that reason.
* **Off unless a password hash is configured.** `[server] control_password_hash` takes a hash, never
  the password: `filecat server set-password` asks twice (`getpass`, no echo, at least 12
  characters) and prints the line for filecat.toml (or `${FILECAT_SERVER_PASSWORD_HASH}` and the
  environment line, to keep the hash out of the file); `--write` puts it into the `[server]` table
  of filecat.toml itself. The hash is `scrypt$n$r$p$salt_b64$hash_b64` (`hashlib.scrypt`, n=2^14,
  r=8, p=1, 16-byte random salt, 32-byte key), checked with `hmac.compare_digest`. **Decision: no
  hash means disabled, with no loopback exception.** A loopback bind does not stop other local users,
  other local software, or a web page that rebinds its DNS name to 127.0.0.1.
* **Login, then a session.** `POST /api/login {"password": ...}` (JSON; the CSRF checks below).
  Success sets cookie `filecat_session=<secrets.token_urlsafe(32)>; HttpOnly; SameSite=Strict;
  Path=/` (plus `Secure` when the connection is TLS served by filecat itself, or the request's Origin is
  https, i.e. behind a TLS proxy). Sessions are
  kept in the server's memory (a restart logs everyone out), expire after 30 minutes idle and 12
  hours absolute, and end with `POST /api/logout`. The page shows a login form when Run now is
  clicked without a session; no password or token goes into `sessionStorage`/`localStorage`.
* **Run now** is `POST /api/jobs/<name>/run` and needs a valid session **and** the CSRF checks. `GET`
  is 405. Unknown job 404, disabled job 409, already running or queued 409, the agent down 409,
  accepted 202. The job is queued with the scheduler: the next tick starts it subject to the
  per-agent exclusivity and the global limit (a job whose agent is busy shows `queued` until it can
  start). The run is stored with `trigger: "manual"` and `requested_from`: the caller's address,
  nothing else.
* **CSRF.** Login, logout and run require the header `X-Filecat-Control: run`, a JSON content type
  (form posts get 415), an `Origin` (when sent) whose host:port equals the request's `Host`, and,
  when bound to loopback, a loopback `Host` (DNS rebinding). The server answers no CORS preflight
  and sends no CORS headers, so another site's page cannot send the header; the cookie is
  `SameSite=Strict` as a second line.
* **Rate limiting** (in memory; a restart resets it; thresholds in `[server]`):
  per address, `login_max_failures` (5) failed logins within `login_window` (15 min) block that
  address for `login_block` (15 min): 429 with `Retry-After`; every further try while blocked doubles
  the block, up to 24 h. Globally, `login_global_max_failures` (20) failures across all addresses in
  the window refuse every login for `login_block` (429); sessions already logged in keep working.
  Every failed attempt waits 0.5 s; scrypt runs even for a malformed body, so timing says nothing. A
  success clears that address's counter, not the global one. Each failure and block is logged with
  the remote address only, the global block as a warning; the attempted password is never logged.
  Behind a reverse proxy every client has the proxy's address: a shared counter (a few typos block
  everyone for 15 minutes). That is the safe direction; this server does not trust
  `X-Forwarded-For`.
* **`login_required_for_view = true`** makes the whole viewer need a session: every API route answers
  401 until login (the page itself is only the shell and shows the login form). It needs a password
  hash (the server refuses to start without).
* **Re-anchoring.** A manual run is a start, so an `every` job counts its interval from it (the
  anchor is the last start); an `at` job is unaffected (its next slot still comes). Shell
  equivalent: `filecat server --once --job NAME`. Not done: picking up a manual trigger written by
  another process (the viewer and the coordinator share a process, so it is not needed).

### Scan now and Remove (the Roots page)

Two more actions use exactly the guards above: only inside `filecat server --serve` (a plain
`filecat serve` answers 404), disabled without `control_password_hash` (403), a valid session (401,
`"login": true`: the page opens the same password form and repeats the action), the CSRF checks
(header, JSON, same origin, loopback `Host`), `GET` is 405, nothing happens otherwise. `GET
/api/roots` carries the same `control: {available, reason}` as `/api/jobs`, and per root `busy` (why
a scan of it is running or queued here) and `removable` (see below), so the buttons are disabled
with the reason, or absent.

* **Scan** is `POST /api/roots/scan {"root": ...}`. The root must be in the root index (404). The
  coordinator's `request_scan(root, remote)` queues an ad-hoc job named `scan:<root>`, kind
  `scan-root`, for exactly that root. The agent is the one `filecat scan` would choose: the
  `[[agents]]` entry with the longest alias or share match (`config.agent_for`), run as `scan ROOT
  --agent NAME`; a root no agent covers is read over SMB or from the local disk (`--no-agent`) and
  counts as the pseudo-agent `(local)`, so those scans do not overlap each other. It goes through
  the scheduler like a scheduled job, so the per-agent exclusivity and the global limit apply (a scan
  whose agent is busy shows as queued). 202 queued; 409 when that root is already being scanned
  or queued (an ad-hoc scan, or a running job that names the root or whose agent covers it), the
  agent is down, or the server is stopping; 400 for a bad body. The run is stored in the job
  history like any other (`trigger: "manual"`, `requested_from`, `kind: "scan-root"`,
  `roots: [root]`) and shows on the Server page (Jobs while it is queued or running, then Recent runs);
  an ad-hoc job leaves no trace in the configuration or the schedule.
* **Remove** is `POST /api/roots/remove {"root": ..., "confirm": <the root string>}`, for the root
  nobody wanted (a typo, a folder that did not exist, scanned with nothing in it). `confirm` must
  repeat `root` (400), the root must exist (404). **409 unless the root has no records at all**
  (files, folders and rollups are all counted, by the backend) **and no scan is running** here or
  elsewhere (root index state `in_progress`). Then it deletes the root's index entry
  (`Backend.delete_root_info`), its stored aggregates and treemap snapshots (pins too), its dropped
  and sticky-redaction entries, and its entry in the resume files beside the catalog. The web never
  deletes records. The page offers the button only where `removable` is true (the row's totals and
  last scan say nothing is there; no query is made, and the request checks the records again) and asks with a `confirm()` dialog naming the
  root. Shell equivalent: `filecat roots remove ROOT [--force [--yes]] [--dry-run]`; `--force` also
  deletes the records (after typing the root to confirm, unless `--yes`; without a terminal `--yes`
  is required), never while a scan runs. Samples and member sets that only those records named stay
  until `filecat samples prune` / `member-sets prune`.

### Stored summaries (the Roots, Summary and Graph pages)

On a catalog of tens of millions of records the pages the viewer is opened for most must not read
the records. Each root therefore has one **stored summary**, built by `summaries.refresh` in a
single pass over its records (`Backend.summary_docs`: only the fields a summary reads, and for
MongoDB no directory or rollup records): the aggregates behind the Summary page
(`aggregate.Aggregator`: totals, by extension, by type, by folder) and the treemap behind the Graph
page (`treemap.build` over the root's top, rollups included), both at **depth 2**, stored with the
same `built_at`, taken before the first record is read.

* **Fresh by change, not by age.** The summary is current while it was built after the root's
  *change stamp*: `changed_at` in the root-index document (`rootinfo.touch`), which every writer of a
  root's records sets. `--graph-max-age` does not apply to it; it only decides how long a treemap of a
  folder or of another depth, built on demand, is reused. States: `fresh`, `stale` (the root changed
  after the build), `scanning` (a scan is walking the root: what is stored is served marked stale and
  is rebuilt when the scan ends, not while it writes) and `missing`.
* **Who stamps.** A scan, in `rootinfo.finish`, when it wrote or removed a file or a rollup
  (`ScanTracker.changed`; folder records are rewritten by every scan and no summary reads them, so a
  scan that found nothing leaves the stamp, and the summary, as they were; this includes the
  `store-resum` job, which is a scan); `roots case-merge`; `rollups migrate`; the purge of a
  redacted folder (`redaction.cleanup`); `enrich`; `import` and `migrate` (the roots they wrote).
  `roots remove` needs none: it deletes the summary with the root. Releasing or approving a
  redaction changes no record (the next scan does). A root-index entry from before the stamp uses its
  last scan's end; a "running" attempt counts from its last heartbeat, so a scan that was killed
  after writing is stale too.
* **Who builds.** The end of a scan (`summaries.after_scan`, only roots that need it, replacing the
  aggregates rebuild it did), the `summaries` job above, `filecat summaries [refresh] [--root R]
  [--all | --stale]` and `filecat summaries status [--json]`, and the viewer: opening the Summary or
  the Graph of a stale or missing root queues **one** rebuild per root on a single background thread
  with a backend connection of its own (a JSONL catalog, one file, rebuilds on the backend thread
  instead), so several stale roots queue instead of all reading the catalog at once, and a page load
  never waits for a pass.
* **What a page gets.** `GET /api/summary?root=` at depth 2 and `GET /api/treemap?root=` (no
  prefix, depth 2) answer from what is stored at once, with `stale`, `state`, `refreshing` and
  `refresh_error`; with nothing stored they answer `building: true` and the page asks again every
  few seconds. `?rebuild=1` / `?refresh=1` queue a rebuild and still serve what is stored. Any other
  depth or folder is built on demand as before. With `--no-save`, or a backend that cannot store
  treemaps, the old in-memory path is used for every view.
* **The Roots page** reads the root index, `Backend.stored_totals` (the aggregate totals without
  their tables) and nothing per root: no `DISTINCT` over the records, no record lookup for
  `removable` (judged from the totals and the last scan; the remove action checks the records
  itself and answers 409 if any remain). A root that has records but neither an index entry nor
  stored totals, which only a hand-made catalog can have (`import` and `migrate` build totals), is
  found by the distinct roots of the records, listed once in the background, trusted for ten
  minutes, and waited for at most two seconds the first time. Each row carries `summary_state`,
  `refreshing` and the age of the summary; **Refresh** (`POST /api/summaries/refresh {"root"}`, 202
  queued) has the guards of Scan now: only inside `filecat server --serve`, the login, the CSRF checks.
* **Responses** carry `Server-Timing: app;dur=` and `X-Filecat-Time`, the access log line ends with
  the time, JSON over 8 KiB is gzipped when the client accepts it, and a stored summary has a weak
  `ETag` (its build and state) with 304 on `If-None-Match`.

Residual risk: over plain HTTP the password and the cookie travel in clear text. Bind to loopback
(the default), or turn on the viewer's own TLS (next subsection), before using this over a network.
A TLS reverse proxy in front still works; the login's rate limit then sees the proxy's address.

### TLS

`filecat serve` and `filecat server --serve` can serve HTTPS themselves (`tls.py`, `acme.py`). It is
meant for a LAN-only service and never needs to be reachable from the internet. Off by default.

```toml
[server.tls]                       # the table turns TLS on; mode = "off" turns it off again
# mode  = "self-signed"            # self-signed | acme | cert | off
#                                  # default: acme if [server.tls.acme] exists, cert if cert is set, else self-signed
# cert  = "${FILECAT_TLS_DIR}/viewer.crt"   # your own certificate chain (PEM) and key: mode "cert"
# key   = "${FILECAT_TLS_DIR}/viewer.key"   # (with acme: where the issued pair is written)
# dir   = "D:/filecat/tls"         # generated certificates and the ACME account key
#                                  # default: .filecat-tls next to the catalog file (mode 0700)
names = ["filecat.lan", "192.168.1.20"]   # extra SANs (self-signed) / the certificate's names (acme)

[server.tls.acme]                  # mode = "acme": a publicly trusted certificate by DNS-01 only
dns         = "cloudflare"         # cloudflare | exec
api_token   = "${CLOUDFLARE_API_TOKEN}"   # Zone:Read + DNS:Edit on the zone, nothing else
# zone      = "example.org"        # default: found from the name (or a 32-hex zone id)
# dns       = "exec"
# command   = "/usr/local/bin/dns-hook"   # called as: command add|remove <fqdn> <value>
agree_tos   = true                 # required: you accept the CA's terms of service
email       = "admin@example.org"  # optional contact
# staging   = true                 # Let's Encrypt staging (untrusted certificates, generous limits)
# directory = "https://ca.lan/acme/acme/directory"   # another CA (step-ca); ca_bundle = "root.pem" to trust it
# propagation_delay = "30s"        # wait after publishing the TXT record...
# resolvers = ["1.1.1.1", "8.8.8.8"]  # ...or poll these until they see it (propagation_timeout = "5m")
```

Flags override the table, on both commands: `--tls self-signed|acme|off`, `--tls-cert FILE
--tls-key FILE` (a configured certificate). TLS 1.2 is the minimum. The listening socket is plain;
each accepted connection is wrapped and handshakes in its own handler thread, so one stalled client
cannot block the others.

* **Configured certificate** (`cert` and `key`, `${VAR}` expanded): loaded as is. `filecat server`
  notices changed files (once a day) and reloads them into the live context.
* **Self-signed** (TLS on, nothing configured): an ECDSA P-256 certificate and key (mode 0600) are
  generated into `dir` with the `cryptography` package (`pip install 'filecat[tls]'`), or the
  `openssl` command when that is not importable; neither is a clear error and the viewer does not
  start. SANs: the bind host (unless it is `0.0.0.0` or `::`), `localhost`, `127.0.0.1`, `::1`, this
  machine's hostname and FQDN, and `names`; an IP in `names` becomes an IP SAN. It is valid for a
  year, reused on later starts, and regenerated when it is within 30 days of expiry or the SANs
  differ. **The SHA-256 fingerprint is printed at start-up**; the browser warns, and the fingerprint
  it shows must equal that line before you accept it. (Or install `selfsigned.crt` as a trusted
  certificate on your own machines.)
* **ACME, DNS-01 only.** A built-in RFC 8555 client (ES256 account key stored 0600 in `dir`, one per
  CA): new-account (contact email, terms agreed), new-order for `names` (wildcards such as
  `*.example.org` work), then for each name a TXT record `_acme-challenge.<name>` =
  `base64url(sha256(token.thumbprint))` is published by the DNS provider, waited for (`propagation_delay`,
  or `resolvers` polled by UDP), answered, polled, and the order is finalized with a CSR and the chain
  downloaded. The records are removed again, success or not. **No HTTP-01 and no TLS-ALPN-01: nothing
  listens for the CA, so the viewer can sit on a private address; only DNS and the CA's API are used,
  outbound.** Default CA: Let's Encrypt production; `staging = true` or `directory` change it.
  Providers: `cloudflare` (zone looked up by name, TXT created and deleted through the v4 API) and
  `exec` (any other provider, e.g. through lego or acme.sh hooks: `script add|remove <fqdn> <value>`,
  exit 0 when done; no shell, so quote nothing).
* **Renewal.** Checked at start-up and, in `filecat server`, once a day in a background thread; a
  certificate within 30 days of expiry (or for other names) is renewed, then `load_cert_chain` runs
  on the live context: new connections get the new certificate, no restart. If ACME fails and a
  previous certificate exists it keeps being served and the failure is logged; with none, the viewer
  falls back to a self-signed certificate with a loud warning and tries ACME again daily.
* **Never logged:** the API token, the account key, private keys (and `repr` of the config hides the
  token). The `exec` script's own stderr (last 200 characters) is, on failure: keep secrets out of it.
* The session cookie gets `Secure` on a TLS connection; the CSRF `Origin` check then also requires an
  `https:` origin. No HSTS header is sent (a self-signed name must stay overridable).

Not done: OCSP stapling, client certificates, a second (HTTP) listener that redirects, ACME
external account binding, reloading `[server.tls]` without a restart (a changed table needs one).

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

* `ScanServer.ps1`: retire it with the Windows agent, or fold `net view` share discovery into a
  `scan` job kind (`shares = "discover"`)?
* The login is for one admin (one password). Per-user accounts and persisted sessions/counters are
  not designed. (TLS in the viewer itself is done: section 7, "TLS".)
* Alerting (mail, webhook) on an agent going down or a job failing: not designed here.
* (Settled: a never-run job waits for its first slot unless `run_on_start = true`, section 4.)
