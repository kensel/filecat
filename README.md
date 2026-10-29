# filecat

Walks local drives and NAS shares, writes one record per file and per
directory, and measures what the bytes support: hashes, a probed kind,
encodings, image and texture sizes, PE headers and toolchain, archive listings,
and freedesktop/libmagic types. Optional Ollama summaries for a bounded set of
files. The `programs` command inventories the software installed on this PC.

The requirements are in [`file-catalog-requirements.md`](file-catalog-requirements.md).
That note is the specification; this README covers installing and running the tool.

## Install

```
uv sync                        # base install: JSONL and SQLite backends
uv sync --extra dev            # plus pytest
uv sync --all-extras           # every backend driver, Magika and pytest
```

Database extras (each adds one backend's driver):

| extra | backend | driver |
|---|---|---|
| `filecat[postgres]` | `--backend postgres` | psycopg 3 |
| `filecat[mysql]` | `--backend mysql` | PyMySQL |
| `filecat[mssql]` | `--backend mssql` | pyodbc (needs an ODBC driver for SQL Server) |
| `filecat[mongo]` | `--backend mongodb` | PyMongo |
| `filecat[magika]` | `--magika` identifier | Magika |

Server backends take `--dsn` or `FILECAT_DSN`. filecat creates its tables or
collections but not the database or the login.

## Configuration

`filecat.toml` holds the default backend, catalog paths, DSNs and the Ollama
model, so commands don't need `--backend`/`--out`/`--dsn`/`--model` every time.

```
filecat config init                 # writes ./filecat.toml; database servers on 127.0.0.1 are filled in
filecat config init --backend mongodb --dsn mongodb://127.0.0.1:27017/filecat --force
filecat config init --user          # %APPDATA%\filecat\filecat.toml instead
filecat config show                 # file in use and effective settings, passwords masked (--reveal)
filecat config test                 # read-only: driver, connect, version, database, user, tables
filecat config test postgres --dsn "postgresql://filecat:pw@db01/filecat"   # try a DSN before saving it
filecat config verify               # test, then create the schema and put/get/delete one record
```

The file is found at `--config PATH` (before the subcommand: `filecat --config x.toml scan ...`),
then `$FILECAT_CONFIG`, `./filecat.toml`, then `%APPDATA%\filecat\filecat.toml`
(`~/.config/filecat/` elsewhere). `FILECAT_CONFIG=none` ignores every file.
Command-line flags win over `FILECAT_DSN` / `OLLAMA_HOST`, which win over the file.

```toml
backend = "mongodb"                 # used when --backend is not given

[sqlite]
out = "catalogs/catalog.sqlite"

[mongodb]
dsn = "mongodb://127.0.0.1:27017/filecat"

[postgres]
dsn = "postgresql://filecat:${FILECAT_PG_PASSWORD}@127.0.0.1:5432/filecat"

[ollama]
url = "http://127.0.0.1:11434"
model = "gemma4:31b-cloud"
```

`${NAME}` is read from the environment when the value is used, so a password can
stay out of the file (`$env:FILECAT_PG_PASSWORD = '...'`). In URL-form DSNs
a password containing `@ : / %` must be percent-encoded; the keyword form
(`host=127.0.0.1 dbname=filecat user=filecat password=${FILECAT_PG_PASSWORD}`)
avoids that. `./filecat.toml` is gitignored.

`config verify` writes one record and two member rows under the root
`filecat-config-verify:` and deletes them again; the tables, collections and
indexes it creates are the ones the first scan would create. For PostgreSQL
15+, `config test` warns when the login cannot `CREATE` in the schema (PostgreSQL 15
stopped granting that on `public` by default). Fix it with
`GRANT CREATE ON SCHEMA public TO filecat`, or make the login the database owner.
`config test ollama` checks the server and that the model is pulled.
`config verify ollama` also asks it for a 4-token reply.

## Commands

```
filecat scan ROOT [ROOT ...] --out catalog.sqlite        # sqlite is the default backend
filecat scan \\nas-vm\share --identify always --workers 8
filecat scan D:\Games --ollama --model gemma4:31b-cloud
filecat scan \\192.0.2.13\home --alias \\192.0.2.13=\\nas-main   # read by IP, record as \\nas-main\home
filecat summary --out catalog.sqlite [--by extension|mime|dir] [--depth 2] [--root R] [--top 50]
filecat summary --disagree                                # name says one type, bytes another
filecat show "sub/dir/file.txt" --root D:\Games
filecat roots                                             # last scan, in progress, newest file, last error
filecat roots case-check                                  # one share recorded as two roots (server\share case)?
filecat roots remove ROOT [--force [--yes]] [--dry-run]   # forget a root with no records (typo); --force deletes its records too
filecat dropped                                           # records of files that vanished (kept 90 days)
filecat backups [--versions]                              # backup stores: machines, versions, problems, copies
filecat databases                                         # database data folders: engine, version, databases, quiet?
filecat scan-everything [--list] [--unfinished]           # every share of [everything] servers + local drives
filecat agents enroll nas3 --host nas3 [--write]           # token + .env lines + [[agents]] stanza, fingerprint (docs/agent-server.md)
filecat agents status [--strict]                          # version, pin, allowed roots, run ids, allowlist/deny hashes
filecat server [--serve] [--once] [--dry-run]             # coordinator: agent health + scheduled scans and storage collects
filecat programs                                          # registry, PATH, Start Menu
filecat programs --reg uninstall-export.reg               # from a regedit export instead
filecat signatures status
filecat import NAS-VM\*.jsonl --out catalog.sqlite         # PowerShell or filecat JSONL
filecat enrich --out catalog.sqlite [--root \\nas-vm\share] [--what names,hash,probe,identify]
```

What a scan reads from each file, how files over 64 MiB are hashed, and
which files (backup and database data, cloud placeholders) are never opened
is summarised in [docs/scanning.md](docs/scanning.md).

ZIP- and gzip-based application files (`.docx`, `.xlsx`, `.odt`, `.epub`,
`.jar`, `.apk`, savegames ...) are compound documents, not archives: only
their anomalies, such as macros, embedded objects or a hidden `.exe`, are
stored as members. `--expand-compound` stores every entry. The
classification is in `src/filecat/data/compound_formats.toml`, described in
[docs/compound-formats.md](docs/compound-formats.md). Planned releases are
in [docs/roadmap.md](docs/roadmap.md); the NAS agent's wire protocol is
[docs/agent-protocol.md](docs/agent-protocol.md).

A scan exits 0 when every entry was recorded cleanly and 1 when any record has
an `errors` entry. Reruns skip files whose size and mtime are unchanged
(`--force` remeasures).

A scan that stops part way through (Ctrl+C, a crash, a reboot) resumes.
`<catalog>.resume.json` records the finished folders of each unfinished
root, and the rerun skips them without listing them if their modified time
is unchanged. Only the top-most finished folders are kept, so a fan-out
like `Mail/D6/01/<id>/` collapses to `Mail/D6` once that folder is done.
The file is saved every 30 s and on exit, so a crash costs at most 30 s of
walking. A folder that could not be listed is retried by the next run. The
entry is cleared once the root finishes cleanly, so the next scan checks
everything again.

The progress line shows files and MB per second:

```
\\nas-vm\share: 243455 files, 7245011012 bytes | 18.4 files/s, measuring 3.1 files/s 2.1 MB/s (avg 12.0 files/s) | 1203 measured, 242252 unchanged | last: ...
```

## Scan everything

`filecat scan-everything` scans every disk share of a list of servers and
then a list of local drives, all in one scan run. It takes every `scan`
option (`--backend`, `--workers`, `--measure-backups`, ...). The set
comes from `filecat.toml`:

```toml
[aliases]
'\\192.0.2.13' = '\\nas-main'   # read nas-main by IP, record as \\nas-main\<share>

[everything]
servers = ["nas-vm", "nas-old", "192.0.2.13", "nas-zfs"]
drives = ["C:", "D:", "E:", "I:"]
exclude = ['\\nas-old\vm-nfs', 'C:\code\filecat']   # roots or folders inside them

[[everything.login]]                   # connect first with other credentials
server = "192.0.2.13"
user = 'nas-main\admin'
```

or from the command line, where `--server` / `--drive` replace the configured set:

```
filecat scan-everything --list                             # show the roots, scan nothing
filecat scan-everything --server nas-vm --drive C --workers 8
filecat scan-everything --unfinished [--list]              # only roots whose last scan did not finish
```

`--unfinished` finishes a stopped run without walking every finished share
again: it keeps the roots left in the resume file (stopped part way, or a
folder could not be listed) and those whose last attempt was not clean
(never scanned, interrupted, failed, unreachable); `--list` shows why each
one is kept. Ctrl+C stops a scan with a message saying how to resume.

Shares are listed with NetShareEnum. Only disk shares count; `C$`, `ADMIN$`,
`IPC$` and printers are left out. When a server refuses the listing and has
a `login` entry, `net use \\server\IPC$ /user:...` asks for the password
once and the listing is retried. A server that still can't be listed is
reported and skipped. The rest are scanned, and the exit code is 1.

`exclude` (and `--exclude`, which `scan` takes too) names whole paths. It
matches case-insensitively, either as read (`\\192.0.2.13\home\tmp`) or
as recorded (`\\nas-main\home\tmp`). An excluded root is not scanned at all,
and an excluded folder or file inside a root is not walked or recorded.
Records an earlier scan made there are kept. Only administrative shares
are skipped automatically: a share that is merely called `Admin` is an
ordinary share and is scanned unless you exclude it.

### Preflight and accounts

Before reading anything, every scan (`scan` and `scan-everything`) opens
each root in parallel. It reports which account each server is read with
and warns about problems. The scan then goes ahead anyway; `--check`
stops after the preflight.

```
preflight: 68 roots
  \\nas-vm       20 roots  as admin (connection)
  \\nas-old      28 roots  as jdoe (saved credential)
  \\192.0.2.13   16 roots  as scanuser (connection)
  local           4 roots  as winuser
! \\nas-old\O365: cannot open: [WinError 5] Access is denied: '\\\\nas-old\\O365'
! \\nas-main\home: read as winuser (windows logon); the last scan used scanuser (2026-10-17)
```

Windows uses one account per server name, so `\\192.0.2.13` and `\\nas-main`
are separate servers to it. The account comes from, in order:
1. a connection opened with an explicit account (`net use /user:`, a mapped
   drive, Explorer's login prompt);
2. the server's saved Windows credential (`cmdkey /list`, `Domain:target=nas-old`);
3. your Windows sign-in.

It is recorded with each scan in the root index (`filecat roots` shows it),
and a later scan warns when a root is read with a different account than
its last scan, since a different account can see different files.

## Backup stores

A scan recognises folders written by backup programs and treats them as
backups rather than as ordinary files:

| format | recognised by | data recorded from the listing only | manifest read |
|---|---|---|---|
| Synology Active Backup for Business | `@ActiveBackup` with `@data` and `storage_info.json` | `@data/**` (the dedup pool) | `storage.cache`, `@data/repo_size`, `@data/file_map.db`, each task's `config.json` + `target.db` |
| ABB virtual view | `ActiveBackupData` | not walked at all: full-size virtual images, not disk space | lists tasks and versions |
| Active Backup for Google Workspace | a `task_<n>` folder holding `@ActiveBackupGSuite-Databases` | every user's `Mail`, `Calendar` and `Contact` items, Drive's `#SynoVersionRepo` / `#SynoRepo`, the databases' search indexes (`MyDrive` files themselves are measured) | `task-config.sqlite`, `account.sqlite`, `service-log.sqlite`, each user's `mail.sqlite`, `calendar-event.sqlite`, `contact.sqlite` |
| Synology Hyper Backup | `*.hbk` with `Config` and `Pool`, or `SynologyHyperBackup.bkpi` | everything in its subfolders (`Pool`, `Config`, `Guard`, `Versionlog`) | `_Syno_TaskConfig`, `Config/version_info.db`, `storage_statistics.db`, `last_status.conf`, `Guard/` manifest and integrity-check log |
| Thunderbird profile copy (ImportExportTools NG) | `Backup.log` with `ExternalMailFolders`, in a `<profile>-<yyyymmdd>-<hhmm>` folder | everything except the files read | `Backup.log` (date, saved files, copy errors), `compatibility.ini`, `prefs.js` |
| Veeam Agent / Backup & Replication | a `*.vbm` with `*.vbk`/`*.vib`/`*.vrb`, or Veeam's timestamped `…2024-04-01T003011.vbk` names | `*.vbk`, `*.vib`, `*.vrb`, `*.vlb`, `*.vsb` | the `.vbm` (job, restore points, files and sizes, machine, OS, disks) |
| Windows Backup and Restore | `<PC>/Backup Set <date>` | `Backup files N.zip`, `*.wbcat`, `*.wbverify` | layout: zips vs their per-zip catalogs |
| Windows system image | `WindowsImageBackup/<PC>` with `Backup <date>` | `*.vhd`, `*.vhdx` | `*_Components.xml` (machine, OS) |
| duplicity / deja-dup | `duplicity-*` files | `*.difftar*`, `*.sigtar*` | plain `*.manifest` (host, source folder, volumes) |

"Recorded from the listing only" means name, size and times, kind `data`,
`probe.backup_data = <format>`, and the file is never opened, so a 1 TB ABB
pool takes about a minute instead of hours and the space totals stay
right. `--measure-backups` reads and hashes them like any other file (and
walks the ABB view).

The store's folder record gets `probe.backup`: machines, every version
with its times and status, sizes, and `problems`, meaning what the manifest
says should exist but doesn't. For ABB that covers failed versions (status
4), volume images missing from the pool or stopped part way (`.suspend`),
small files missing or of the wrong size, and version folders that
`target.db` doesn't know. ABB's figures are the ones its Storage page
shows: backed-up size, storage usage, saved by deduplication, saved by
compression, and the reduction ratio. For Hyper Backup it covers versions
with a failed status, every file in the target's own `Guard` manifest
that is missing or of another size (checked against the scan's listing, so
it costs no extra reads), and errors in the last integrity check's log;
the summary has the task, source NAS and folders, each version's size and
file counts, and source vs target size. With the target's `Pool/` rolled up
into one `[BACKUP]` record (`--rollup backup=automatic`, see
[docs/rollups.md](docs/rollups.md)) `scan --verify-backups` compares the
pool's total bytes and file count with Guard's (`probe.backup.checked` is
`totals`); Guard's per-file CRC32 read of the whole target is verify level 2,
not in v0.2.0. What is known of the format itself, enough to build a reader, is in
[docs/formats/synology-hyperbackup.md](docs/formats/synology-hyperbackup.md).
For Veeam it covers every backup file the job's `.vbm` lists that is
missing or of another size, restore points Veeam marked corrupt (and how
many later increments depend on a missing or corrupt one), and backup files
in the folder that the `.vbm` no longer lists; `scan --verify-backups` also
reads each backup file's own metadata (header, snapshot slots, metadata
banks: well under 1% of the file) and checks their CRC32C, without reading
the data blocks. The format is in
[docs/formats/veeam-vbk.md](docs/formats/veeam-vbk.md).
For Google Workspace it covers every message, event and contact version in
a user's databases that has no folder or no META (or SKEL) fragment on
disk, item folders the databases don't list, `MyDrive` files with no
version history or of another size than their latest version, and the
latest run of each user and service when it failed, with the log's text;
the summary has the domain, every user with their used size per service,
and the item counts. Removed users are listed but not reported as
problems, and items the live task backed up after the walk listed them are
counted, not reported. On Windows, event folders past 260 characters are
listed again with long paths before anything is called missing. `--verify-backups` reads every META and Drive `.metadata` and
checks the size and MD5 of every fragment and version they name. The
layout is in [docs/formats/synology-abg.md](docs/formats/synology-abg.md).
For a Thunderbird profile copy (ImportExportTools NG's profile backup) it
covers every file the copy's `Backup.log` says it saved that is not in the
copy, files in a dated copy the log does not name, and the log's own copy
errors; the summary has the profile and its source path, the Thunderbird
version, the accounts, the host (from maildir file names) and the backup
date. The log has no sizes or checksums, so presence is all it can check.
The summary is read when a scan
finishes the store's folder, so a store inside a folder that an
interrupted scan had already finished is summarised by the next full scan.

```
filecat backups [--root R] [--versions] [--json]
```

lists every store, then groups them. **Copies** are stores holding the same
backed-up data, by version UUID or set timestamps, for example a backup folder
copied to another share. **Separate jobs** are stores backing up the same
machine independently, by device UUID or host name. Each of those keeps
its own full copy, because deduplication never spans two stores (two ABB
destination shares have two pools).

Backups copy their own data by design (every generation of a profile copy,
every copy of a job folder), so `filecat dupes` drops a cluster made only of
backup data, without reading those files, and keeps one where a backup file
matches a file outside the backups, marking the backup copies.
`--include-backups` shows the backup-only clusters too.

## Database folders

Database servers' data folders are recognised the same way. Their data files
are recorded from the listing only (kind `data`, `probe.db_data = <engine>`),
since they change while the server runs and mean nothing outside it:

| engine | recognised by | data recorded from the listing only | metadata read |
|---|---|---|---|
| PostgreSQL | `PG_VERSION` + `base/` + `global/` | `base/`, `global/`, `pg_wal/`, `pg_xact/`, ... | `PG_VERSION`, `global/pg_control` (system id, cluster state), `postmaster.pid` |
| MySQL / MariaDB | `ibdata1`, `mysql.ibd`, `ib_logfile0` or `aria_log_control`, with `mysql/` | schema folders, `ibdata*`, redo/undo, binlogs | `auto.cnf` (server-uuid), `mysql_upgrade_info`; tables per schema from file names |
| MongoDB | `WiredTiger` + `_mdb_catalog.wt` or `storage.bson`; MMAPv1 `*.ns` | `*.wt`, `journal/`, `diagnostic.data/` | `WiredTiger` (version), `storage.bson` (directoryPerDB), `mongod.lock` |
| SQL Server | any `.mdf` (not one with an Alcohol `.mds` beside it) | `.mdf`, `.ndf`, `.ldf` | version from the `MSSQLnn.NAME` folder; data and log files paired by name |

Config files, logs and the like in those folders are measured as usual. The
folder's record gets `probe.database`: version, running or not, databases
(PostgreSQL by OID; MySQL with table counts; MongoDB when directoryPerDB
names them; SQL Server per .mdf with its log), files, bytes, the newest
file's time and whether the folder is `quiet`. A PostgreSQL folder whose
pg_control says "in production" with no postmaster.pid is flagged: a copy
taken while the server ran, or a crash.

`--measure-databases` reads and hashes a data file only when it is quiet,
so the server is never caught mid-write:

| engine | not modified for | and at least |
|---|---|---|
| PostgreSQL, MySQL, MongoDB | 90 days | 1 MiB (skips the many small relation files) |
| SQL Server | 1 hour | any size |

A file that is listed now and goes quiet later is unchanged to a rescan;
`filecat enrich` measures it (checking again against the file just before
reading; `--force` does not override that). A file a server holds open is
recorded as `probe.db_in_use` instead of an error. filecat only reads.

```
filecat databases [--root R] [--json]
```

lists every folder, then the folders sharing a PostgreSQL system identifier
or a MySQL server-uuid: copies of one instance's data, or a physical replica.

[`src/filecat/data/store_formats.json`](src/filecat/data/store_formats.json)
catalogs every database and backup format: detection, which files are listed
or measured, the metadata read, actions and thresholds, problems reported,
notes and real examples, plus the backup formats planned next. The measure
thresholds above are read from it, so they can be tuned there.

## Cloud files (OneDrive, iCloud Drive, Dropbox ...)

OneDrive Files On-Demand, iCloud Drive for Windows, Dropbox, Box and other
providers built on the Windows Cloud Files API leave **placeholders**: files
with their real size and times whose data stays in the cloud until something
reads them. Reading one makes the provider download it. Windows hides their
reparse point from programs, so filecat goes by the file's attributes
(`RECALL_ON_DATA_ACCESS`, `RECALL_ON_OPEN`, `OFFLINE`, which also covers
files a NAS or Azure File Sync has tiered off).

A scan never opens such a file, even with `--force`. It records it from the
directory entry (name, size, times, and the type its name suggests) with

```json
"probe": {"cloud": {"provider": "OneDrive - Personal", "state": "online-only", "unpinned": true}}
```

and counts it as `cloud-only` on the progress line. Files under a sync root
that are on the device are measured as usual and get `state` `local` or
`pinned` ("Always keep on this device"). `unpinned` means "Free up space"
was asked for. The provider comes from the sync roots Windows has registered
(`HKLM\...\Explorer\SyncRootManager`); an offline file outside them has
`provider: null`. A rescan measures a file recorded while cloud-only once
it is on the device.

Downloading is only done when you ask for it, and only for what you select:

```
filecat enrich                                        # cloud-only files are left unread
filecat enrich --hydrate --root C:\Users\me\OneDrive --path "Work/DA" --limit 50
filecat enrich --hydrate --path "Work/*.pdf" --free-after
```

`--path` takes a glob on the path within the root, or a folder. `--free-after`
marks each downloaded file "Free up space" again (it sets `UNPINNED`, as
Explorer does), so the provider removes the local copy; the record then says
`"freed": true`. Without it, downloaded files stay on the device. Downloads
have no timeout unless `--timeout` is given.

## Root aliases

Windows allows only one set of credentials per server name. To scan a NAS
with an admin account while your own account keeps its mapping, connect
through the IP address and record the shares under the usual name:

```
net use \\192.0.2.13\home /user:nas-main\admin
filecat scan \\192.0.2.13\home \\192.0.2.13\media --alias \\192.0.2.13=\\nas-main
```

The records land under `\\nas-main\home` and `\\nas-main\media`, the same roots a scan
through `\\nas-main` writes. An alias is a path prefix matched on whole components,
ignoring case; the longest match wins. Keep permanent ones in filecat.toml
(literal strings need no escaping):

```toml
[aliases]
'\\192.0.2.13' = '\\nas-main'
```

`enrich` applies the table in reverse, so it reads `\\nas-main\...` records
through the IP. `filecat roots --json` shows the path a scan read from as
`last_attempt.path`.

## Root index

Every scan records, for each root, when it started and finished, how it
ended, what it wrote, the last error, and the most recently modified file.
While a scan runs, it updates that entry every 30 s with its progress. A
scan that has gone quiet (killed or hung) is reported as *stalled*, not as
still running. The possible states are ok, errors, unreachable,
interrupted, failed, scanning, stalled and not scanned.

```
filecat roots [--root R] [--json]
filecat roots remove ROOT [--force [--yes]] [--dry-run]
```

The web viewer's Roots page shows the same table, refreshing while a scan
runs. Roots scanned before the index existed, or added by `import`, show
"not scanned". Their newest file is read from the records.

`roots remove ROOT` forgets a root that should not be there, such as a typo
or a folder that did not exist: its index entry, summary, treemap snapshots
and resume state. It refuses while a scan runs and while the root still has
records; `--force` deletes the records too (it asks you to type the root
unless `--yes`). `--dry-run` says what would go. Under `filecat server
--serve` the Roots page has a **Scan** button per root and, for a root with
no records, **Remove**, behind the same password login as "Run now" (see
[docs/agent-server.md](docs/agent-server.md) section 7).

## Dropped records

When a rescan finds that a file or folder is gone, its record is moved to a
`dropped` table rather than deleted. A vanished folder takes every record
beneath it. Each entry is the record as it was, plus `dropped_at` (UTC)
and `drop_reason`. Dropped records no longer appear in browse, query or
summary results. At the end of every scan, entries dropped more than 90 days
earlier are purged (`--keep-dropped DAYS` changes that). The progress line
counts drops (`..., 40 dropped | last: ...`).

```
filecat dropped [--root R] [--limit 100] [--json]   # newest first
filecat dropped --purge [--days 90]                 # purge now; --days 0 empties it
```

The table is `dropped` in SQLite and the server databases, a `dropped`
collection in MongoDB, and `<stem>.dropped.jsonl` next to each JSONL
catalog file. `migrate` copies it. A dropped archive's member rows are
deleted, though its own record keeps the member summary.

## JSONL layout

`--backend jsonl --out catalog-jsonl` (the default) writes one file per
root into a directory:

```
catalog-jsonl/
  nas-vm-admin.85290d640ed4bdbb.jsonl            documents of \\nas-vm\admin, one per line
  nas-vm-admin.85290d640ed4bdbb.members.jsonl    its archive members
  nas-vm-admin.85290d640ed4bdbb.summary.json     its stored summary
  programs.jsonl
```

Flushing during a scan rewrites only the scanned root's file, not every
share in the catalog. An `--out` ending in `.jsonl` keeps the older
single-file layout. To convert between the layouts:

```
filecat migrate --from jsonl --from-out old.jsonl --to jsonl --to-out catalog-jsonl --verify
```

To copy catalogs, use `migrate`, not `import`: `import`ing a directory's
`*.jsonl` would also pick up the members and programs files. Splitting one
huge root into size-capped parts is planned in `docs/jsonl-parts-plan.md`.

## Web viewer

```
filecat serve [--backend B --out F | --dsn DSN] [--port 8765] [--host 127.0.0.1] [--open]
              [--no-save] [--graph-max-age MINUTES]
```

Serves a read-only page at http://127.0.0.1:8765/ for any backend. The page
has these views:

- **Summary:** the `filecat summary` tables per root. Clicking a row lists
  exactly the files that row counted.
- **Graph:** a WinDirStat-style treemap of every root, grouped by server
  (`\\nas-vm`) or drive (`C:`), two folder levels deep per root by default.
  Each folder tile is split by the files in it, coloured by the top 20
  extensions, types, or folders (roots in the overview). Hover a colour in the
  legend to pick out its tiles. Click a tile to zoom in on that folder: the
  server then summarises that folder from its records, which takes a few
  seconds for a large share. Roots without a summary yet are sized from the
  root index until theirs arrives.

  Each treemap is saved in the catalog as a snapshot and reused until it is
  `--graph-max-age` minutes old (default 120). After that, the next viewer
  gets a fresh one. **Refresh** re-reads the records now. **📌 Pin** keeps
  the snapshots on screen indefinitely, with the time and an optional label.
  On the overview one pin covers every root. **Snapshot** switches the page
  between the latest and any pin. **Compare with** picks a pin to measure
  against. It adds a **Change** colouring (blue shrank, red grew, grey about
  the same), each folder's size then and now in the tooltip, and a table of
  the biggest changes. Comparisons are per folder at the snapshot's depth,
  not per file. A pin of the overview also applies when you zoom into one of
  its roots. Deeper folders need their own pin. `--no-save` keeps treemaps
  in memory instead and turns pins off.
- **Browse:** a folder tree. Each folder shows the files and bytes beneath it,
  derived from file paths, so it works mid-scan and for imports without
  directory records.
- **Records:** filter, sort and page the files, then open one to see every
  field, its errors and its archive members.
- **Search:** file and folder names across every root, Everything-style and
  case-insensitive: `eve*.exe` (`*` any run, `?` one character, the whole name
  must match), plain text is a substring (`setup` is `*setup*`), and `ext:exe;dll`,
  `size:>10mb` (or `1mb..1gb`), `after:2024-01-01`, `before:`, `kind:dir`,
  `root:` and `host:nas-*` narrow it. Results show the name, its folder (a link
  to Browse), root, size, modified time and kind, 100 at a time (up to 1000 per
  page) with the time the query took; click one to open the record. Only names
  are matched, and the lookup scans the catalog (no name index yet), so a
  substring search of tens of millions of records takes seconds. A rolled-up
  folder (`[CACHE]`, `[REDACTED]`) is found by its own name only; nothing inside
  it is stored. `GET /api/search` is the same query as JSON.

The **Backend** selector in the top-right corner switches the viewer to
another catalog without a restart. It lists every backend with a location in
`filecat.toml` (or the `--config` file), plus the one the server started with;
DSN passwords are masked, a backend whose `${VAR}` is unset or whose file does
not exist is listed as unavailable, and if the new backend cannot be opened
the current one stays and the error is shown.

Summaries are stored in the catalog for each root, with the depth they were
built at and when (the `agg_*` tables, or `<stem>.summary.json` for JSONL).
`scan` and `enrich --root` rebuild only the roots they touched, and
`summary --rebuild --root R` rebuilds one root. The viewer reads the stored
summary and marks it stale when the records have changed since. When a root
has no stored summary, the viewer computes it and saves it. Rebuild & save
recomputes at the selected depth. Graph snapshots go in a `treemaps` table
(`<stem>.treemaps.json` for JSONL). `--no-save` keeps the viewer from writing
anything. There
is no authentication, so keep the default `--host 127.0.0.1` unless the
network is trusted. The JSON API is under `/api/` (see `serve.py`).

## Import and enrich

`filecat import` loads listings made elsewhere and records them under the same
root a scan would use. A record imported from `\\nas-vm\git\x\y` lands under root
`\\nas-vm\git`, so a later `filecat scan \\nas-vm\git` updates the same records.

* **PowerShell listings.** One JSON object per line with `FullName`, `Length`,
  `Attributes`, `CreationTimeUtc`, `LastWriteTimeUtc`, and `LinkTarget`. For example:

  ```powershell
  Get-ChildItem -LiteralPath \\nas-vm\share -Recurse -File -Force |
    Select-Object Name,BaseName,Extension,FullName,DirectoryName,Length,IsReadOnly,
      @{n='Attributes';e={"$($_.Attributes)"}},
      @{n='CreationTimeUtc';e={$_.CreationTimeUtc.ToString('o')}},
      @{n='LastWriteTimeUtc';e={$_.LastWriteTimeUtc.ToString('o')}},
      @{n='LastAccessTimeUtc';e={$_.LastAccessTimeUtc.ToString('o')}},LinkTarget |
    ForEach-Object { $_ | ConvertTo-Json -Compress } |
    Out-File -Encoding utf8 share.jsonl
  ```

  The import also creates directory records from the file paths, with their
  child counts. Timestamps are kept to the 100 ns tick.
* **filecat JSONL.** The output of `--backend jsonl` is put as-is. `--root`
  re-roots it.

Imported files have size and times but no hash, kind, or type yet. `filecat enrich` fills those in:

* `--what names` uses the glob table only and reads no files. A large
  catalog takes seconds, and it is enough for `summary --by extension` descriptions.
* `--what hash,probe,identify` opens each file and runs the same measurement
  as `scan`. Use `--path-map "\\nas-vm\share=Z:\"` to read a share through a
  mapped drive while keeping the recorded root. `--limit N` and `--kind unknown`
  narrow a run. A file whose size or mtime changed since the import is
  remeasured in full.

## Disk images

QCOW2, VHD (fixed, dynamic), VHDX, VDI, VMDK (sparse and text descriptor), raw
images with a partition table or volume boot sector, and ISO 9660 / UDF discs
get `kind` `disk`. Only headers, a few sectors and mapping tables are read (no
bulk reads), so it is safe on SMB. `probe` reports: `format`, `variant`,
`virtual_size`, `sparse`, `partition_table` (MBR/GPT), `filesystems`
(NTFS, exFAT, FAT, ext, XFS, Btrfs, HFS+, APFS, swap, ReFS, SquashFS), `encryption`
(LUKS, BitLocker with FVE metadata, qcow2 crypt), `lvm`, container details
(block size, backing/parent file, VMDK extents), ISO volume id, Joliet,
El Torito and hybrid flags, and `bytes_read`. Partitions are member rows
(role `volume`, `partitionN`, with offset, size, filesystem and type name); ISO
images list their files as members (`filecat members`); when a disc also
carries UDF (Windows setup media, game images, Blu-ray metadata partitions) the
larger of the two trees is used and `listing` says which. A bounded content scan
of each unencrypted volume adds `os_hint`, `volume_role` and
`volume_summaries` (NTFS volumes are read through their MFT: root entries and
`Users` names). `--disk-scan-cap MIB` limits the per-volume read (default 8, 0
turns the scan off); ISO listings use `--archive-scan-cap` and `--max-members`.
Differencing images and compressed/encrypted qcow2 are described but their
guest is not mapped. The reference script this is built from (disk_inspector
v2.1) is kept in `contrib/disk_inspector/`.

## Ollama

`--ollama --model NAME` sends records that the probe could not classify
(kind `unknown`, at most 256 KiB, non-empty text sample, at most 200 per scan)
to `POST /api/chat` at `--ollama-url`, `$OLLAMA_HOST`, or `http://127.0.0.1:11434`.
Only the record with its 4 KiB sample is sent, never the file itself. The reply goes in
`llm` and never overrides a measurement. Tested with `gemma4:31b-cloud`.

The database backends keep each text sample once per content hash, with
its Ollama result, so copies of a file share one sample and one model call;
the record keeps a `sample_id`. Records from before v0.1.2 move over with
`filecat samples migrate`, which is batched, resumable and safe to stop at
any point. See [docs/samples.md](docs/samples.md).

Archive members are kept the same way: one member set per archive content
hash, however many copies of the archive the catalog holds, named on each
record by `members_id`. Records from before v0.1.3 move over with
`filecat member-sets migrate`, which also trims compound documents listed
before v0.1.1 to their anomalies. `filecat samples prune` and
`filecat member-sets prune` remove what no record names any more. See
[docs/members.md](docs/members.md).

## Tests

```
uv sync --all-extras
uv run pytest
```

Fixtures are built under `tests\_fixtures` by the tests themselves. SQLite and
JSONL backends always run the contract test. Set `FILECAT_TEST_POSTGRES`,
`FILECAT_TEST_MYSQL`, `FILECAT_TEST_MSSQL`, or `FILECAT_TEST_MONGODB` to a DSN to
include those backends, and `FILECAT_TEST_SMB` to a writable share (UNC path,
or a CIFS mount point) to scan a real SMB share. `FILECAT_EXE=path\to\some.exe`
enables the Rich-header cross-check. Tests that need Windows (cloud-file
attributes, junctions, drive letters, long paths) skip elsewhere.

[`compose.yaml`](compose.yaml) runs throwaway Postgres, MySQL, SQL Server,
MongoDB and Samba servers; [`.env.example`](.env.example) has the matching
variables. Copy it to `.env` (gitignored), which `tests/conftest.py` loads:

```
docker compose up -d
cp .env.example .env
uv run pytest
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the suite on
Ubuntu and Windows with Python 3.11 and 3.13, the server backends against the
same images as service containers, and the SMB test against the Samba
container mounted over CIFS.

### Keeping internal names out of the repo

Examples, tests and docs use generic names (`\\nas-main`, `192.0.2.13`,
`jdoe`). [`scripts/sanitize.py`](scripts/sanitize.py) maps real names to them
from a gitignored `sanitize-aliases.local.toml` (format in
[`sanitize-aliases.example.toml`](sanitize-aliases.example.toml)); run
`uv run python scripts/sanitize.py --check` before committing.

## Layout

```
src/filecat/
  cli.py            argument parsing; each command is run(args) in its module
  scan.py walker.py hashing.py resume.py ollama.py
  probe/            built-in kind probe (text, images, archives, PE, media, X3 formats)
  identify/         freedesktop globs + magic, libmagic, PRONOM, TrID, Magika
  backends/         jsonl, sqlite, postgres, mysql, mssql, mongodb (+ memory for tests)
  aggregate.py summary.py show.py
  browse.py serve.py web/   drill-through queries, `filecat serve` and its page
  treemap.py        folder sizes split by extension/type for the Graph view
  rootinfo.py roots_cmd.py  root index (scan history) and `filecat roots`
  root_remove.py    `roots remove` and the viewer's Remove button
  search.py         the Search page's query language (patterns, LIKE and regex translations)
  programs.py reg.py lnk.py
  importer.py enrich.py
  data/             vendored freedesktop.org.xml and richprint comp_id.txt
signatures/         user-supplied signature files (never downloaded by a scan)
```
