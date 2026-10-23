# What a scan reads

A summary of how `filecat scan` (and `scan-everything`) walks a root, what it
reads from each file, how files over 64 MiB are hashed, and which files are
never opened. The specification is
[`file-catalog-requirements.md`](../file-catalog-requirements.md); this note is
the short version, with pointers to the code.

## 1. How a scan runs

1. **Preflight.** Every root is opened in parallel and the account each server
   is read with is reported (`preflight.py`). `--check` stops here.
2. **Walk.** Each root is walked with `os.scandir`, one folder at a time
   (`walker.py`). Reparse points (junctions, symlinks) are recorded as `link`
   and never followed, so a scan never leaves the root's volume or share.
   Skipped: `$Recycle.Bin` and `System Volume Information` everywhere, and
   `pagefile.sys`, `hiberfil.sys` and `swapfile.sys` at a drive's root
   (`--no-default-skips` keeps them), plus anything under `exclude` /
   `--exclude`. A root covered by a `[[agents]]` entry is walked through
   `filecat-agent` instead of SMB (section 6).
3. **Detect stores.** When a folder is listed, its entries are checked against
   the backup formats (`backup/`) and the database engines (`dbfiles/`). A
   match marks the folder's data files as *listed only* (section 4).
4. **Measure.** Each new or changed file is measured by `scan.measure_file` in
   a pool of `--workers` threads (default 4), with a per-file timeout of 30 s
   locally and 120 s on UNC paths (`--timeout`). A file that times out or
   fails gets an `errors` entry on its record; the scan carries on.
5. **Write.** One record per file and per folder, folders after their
   children. When a store's folder is finished, its manifest is read and the
   summary goes on the folder's record as `probe.backup` or `probe.database`.
6. **Finish.** Records of files that vanished move to the `dropped` table,
   the root index is updated, and the exit code is 1 if any record has an
   error.

**Reruns.** A file whose size and mtime match its record is not opened again
and keeps its old hashes (`--force` remeasures everything). An interrupted
scan resumes from `<catalog>.resume.json`, skipping folders it had finished
without even listing them.

## 2. What is read from an ordinary file

| step | reads | notes |
|---|---|---|
| head | the first 8 KiB | one read, shared by the probe and libmagic |
| probe | usually only the head | some kinds read more, see section 3 |
| identify | the head, or nothing | libmagic on local roots only; `--identify always` adds UNC roots, `never` turns it off. The name-based type (freedesktop globs) needs no read |
| sample | the first 4 KiB of text files | stored in the record |
| hash | see the table below | |

### Hash policy (`hashing.py`)

| size | default (`--hash auto`) | `--hash full` | `--hash none` |
|---|---|---|---|
| 0 bytes | no hash | `sha256` of empty | no hash |
| 1 B to 64 MiB | `sha256` of the whole file | `sha256` | no hash |
| over 64 MiB | `sha256_partial` | `sha256` (whole file) | no hash |

`sha256_partial` is **one** SHA-256 fed, in this order:

1. the first 1 MiB of the file,
2. the last 1 MiB of the file,
3. the size, 8 bytes big-endian unsigned,
4. the mtime in nanoseconds, 8 bytes big-endian signed.

So a file over 64 MiB costs 2 MiB of reads however large it is. A partial
digest is never stored in the `sha256` field, and a record has one or the
other, never both.

What the partial hash means:

* Two equal `sha256_partial` values mean the same size, the same mtime and
  the same first and last MiB. That is strong evidence of a copy, **not
  proof**: a change in the middle of the file goes unseen.
* Because the mtime is in it, a copy that did not keep its timestamp (a
  plain Explorer copy to some shares, a download) gets a different partial
  hash even when the bytes are identical. `filecat dupes` covers that case by
  matching on size alone and hashing sample windows (see
  [dupes.md](dupes.md)).
* Touching a file (changing its mtime only) changes its partial hash.
* Upgrading big files to a full hash later: `filecat enrich --what hash
  --hash full --force` (with `--root`, `--path` or `--limit` to keep it
  bounded). Without `--force` enrich skips records that already have a hash.

## 3. Bigger reads made by the probe

Some kinds are read past the 8 KiB head, but each read is capped:

| kind | what is read | cap |
|---|---|---|
| ZIP and similar | the central directory at the end of the file | the directory only; compound documents (`.docx`, `.jar` ...) store only anomalies, see [compound-formats.md](compound-formats.md) |
| `.gz`, `.bz2`, `.xz` | decompressed from the start to classify the content | 4 MiB |
| `.tar.gz` / `.tar.bz2` / `.tar.xz` | decompressed to list members | `--archive-scan-cap` (64 MiB); `--deep-archives` reads to the end |
| 7z, MPQ, X3 `.cat/.dat`, Godot `.pck` | their headers and file tables | `--max-members` rows stored |
| disk images (VHD, VHDX, VMDK, QCOW2, VDI, raw, ISO) | headers, mapping tables, a few sectors per volume | `--disk-scan-cap` (8 MiB) per volume; ISO/UDF listings use `--archive-scan-cap` |
| PE (`.exe`, `.dll`) | headers and selected data directories, through `pefile` | not the whole file (`fast_load`) |

## 4. Files that are not opened

| what | how it is recorded | to read it anyway |
|---|---|---|
| **Backup data**: ABB pools, Hyper Backup `Pool/` etc., Veeam `.vbk/.vib/.vrb`, Windows Backup zips, system-image VHDs, duplicity volumes, Google Workspace items, Thunderbird profile copies | name, size, times, `kind: data`, `probe.backup_data: <format>`; no hash | `--measure-backups` |
| **ABB virtual view** (`ActiveBackupData`) | the folder only, not walked | `--measure-backups` |
| **Database data files** (PostgreSQL, MySQL/MariaDB, MongoDB, SQL Server) | the same, with `probe.db_data: <engine>` | `--measure-databases`, and only quiet files: unmodified for 90 days and at least 1 MiB (SQL Server: 1 hour) |
| **Cloud placeholders** (OneDrive, iCloud, Dropbox online-only, offline/tiered files) | from the directory entry, with `probe.cloud` | `filecat enrich --hydrate`; never during a scan, even with `--force` |
| Skipped and excluded paths | not recorded | `--no-default-skips`; remove the `exclude` |
| Unchanged files on a rerun | the old record is kept | `--force` |

Backup and database data is left unread because it is huge, it copies other
data by design, and (for databases) it changes while the server runs. Listing
only keeps the space totals right: a 1 TB ABB pool takes about a minute
instead of hours.

### What is read from a backup store

Only the store's own metadata, which is small. The full list per format is in
the README's "Backup stores" table and in
[`data/store_formats.json`](../src/filecat/data/store_formats.json). Examples:
ABB's `storage.cache`, `file_map.db` and each task's `target.db`; Hyper
Backup's `Config/` databases and `Guard/` manifest; Veeam's `.vbm`;
Thunderbird's `Backup.log`, `prefs.js` and `compatibility.ini`.

The default check compares the manifest against the scan's listing: files
that should exist and don't, or have the wrong size. That costs no extra
reads. `--verify-backups` goes further and reads data to check the store's
own checksums:

| format | what `--verify-backups` reads |
|---|---|
| Hyper Backup | every file Guard lists, checked against its CRC32 (reads the whole target) |
| Veeam | each backup file's header, snapshot slots and metadata banks, checked against CRC32C (well under 1% of the file) |
| Google Workspace | every META and Drive `.metadata`, then the size and MD5 of each fragment and version they name |
| Thunderbird, ABB, Windows Backup, duplicity | nothing more (no checksums to check) |

## 5. After the scan

* `filecat dupes` reads only files in its size bands (1 GiB and up by
  default): 6 windows of 1 MiB per file, or the whole file with `--full` (up
  to `--full-max`). Size groups made only of backup data are not read, and
  clusters made only of backup copies are not reported (`--include-backups`
  shows them). See [dupes.md](dupes.md).
* `filecat enrich` runs the same measurement as a scan on records that lack
  it, for example ones brought in by `import`.

## 6. Scanning through filecat-agent

A UNC root that a configured `[[agents]]` entry covers (its `alias` server,
or a `[agents.shares]` root; `agent_for` picks the longest match) is read
through that agent instead of over SMB. `--no-agent` reads every root over
SMB; `--agent NAME` uses that agent for the roots it covers; an agent that
cannot be reached fails its root like an unreachable share (a `stat` error on
the root record, exit code 1) unless `--agent-fallback` is given, which reads
that root over SMB instead. The preflight lists the root through the agent, and
the start line, the progress lines and the root index's account (`as
filecat-agent`) say that an agent is in use.

The walk is the same walk (`walker.py`): `fsource.AgentSource` hands it
listing entries and stats shaped like `os.DirEntry` and `os.stat_result`, so
record identity (`root`, `rel_path`), sizes, `mtime_ns` (100 ns), hashes and
probe results are the ones an SMB scan gives. Per file:

| step | through the agent |
|---|---|
| listing | one `list_dir` per folder, with lstat for every child; read ahead in the same background threads |
| unchanged? | size and `mtime_ns` from the listing against the stored record; no call at all for a file that matches (`--force` remeasures) |
| head, size, mtime, hash | one `measure` call (`hash` from `--hash`); the record keeps the size and mtime it returns |
| probe | the head from `measure`; more (ZIP directories, PE, tar, 7z, disk images, gzip/xz tails, MPQ, PCK, X3 catalogues, CSV counts) through `read_range`, via `fsource.fopen`; a PE is read whole up to 64 MiB |
| identify | as over SMB: the head is only given to libmagic with `--identify always` |

Every thread that reads (the walker, the 8 listing threads, the `--workers`
measuring threads) has its own connection, since a connection carries one
request at a time. The agent's `exclude` is sent as the connection's policy.

Extra fields on agent records (absent from SMB scans, so optional):
`allocated_size` (the space used, `st_blocks * 512`), and `ino`, `dev` and
`nlink`. The size of a file with `nlink` above 1 is counted once per
`(dev, ino)` in the progress line and in the root index's byte count; the
stored aggregates (`filecat summary`) still add every name.

Special entries: a link is a `link` record with `probe.link_target`; a FIFO,
socket or device is a record with `probe.special_file` and is never opened; a
`rollup` entry (only present when the agent is given rollup groups) is skipped
today. Planned: folders and files a rule sends to `[REDACTED]`, `[CACHE]`,
`[SYNOLOGY]`, `[BACKUP]` or a tag of your own become one `rollup` record per
parent folder and tag, holding only totals and no names, and a backup or
database store's bulk data folder is summed instead of listed
([rollups.md](rollups.md)).
A name that is not valid UTF-8 is stored with each bad byte `b` as the
private-use character U+F700 + b (`fsource.to_storage`), which is valid in
JSON and every database, and is turned back into the exact bytes when the
path is sent to the agent.

Not yet through the agent: a backup store's or database folder's manifest
(`backup/`, `dbfiles/` read their folder with `os` calls), so such a folder
is detected, its data files are listed only, and its record carries
`probe.store_note` instead of `probe.backup` / `probe.database`; `enrich`;
the sibling-file probes other than X3's `.cat`/`.dat`.

### One share, two spellings

Roots are stored as spelled. Windows and SMB ignore the case of a server and
share name; a Linux NAS does not, and an agent reports the NAS's own spelling.
`\\nas-main\backup` scanned over SMB and `\\nas-main\Backup` scanned through
the agent are one share but two roots. Only `server\share` is case-insensitive
here; everything below it (`rel_path` and folders in a root such as
`\\nas-main\Backup\sub`) stays case-sensitive, as the NAS's file system is.

New scans avoid the split (`rootcase.reconcile`):

- through an agent, the root is recorded under the NAS's spelling: the share as
  `[agents.shares]` spells it, else the matching entry of the volume folder
  (`/volume1`) the agent lists, whatever was typed (a Synology share is not found
  under another case, so the typed spelling could not be read anyway);
- over SMB, a root whose `server\share` matches a root already in the catalog
  ignoring case is recorded under that spelling and the start line says so
  (`recorded as ..., the spelling the catalog already holds`). With several
  spellings the agent-scanned one wins, else the most recently scanned;
- when the catalog still holds the share under a spelling that was not used, one
  line points at `filecat roots case-check`.

For a catalog that is already split:

```
filecat roots case-check [--sample N] [--json]     # exit 1 when there are pairs
filecat roots case-merge [OLD NEW] [--sample N] [--force] [--dry-run]
```

`case-check` lists each group of roots that differ only in the case of
`server\share`, names the canonical (NAS) spelling when it is known, and
verifies that the roots are one share by comparing files:

- the sample is the N files (default 500; 200 to 1000) with the smallest SHA-1
  of their `rel_path` across both roots, so a rerun checks the same files; each
  is looked up in both roots;
- kind, size, `mtime_ns` (within 100 ns, the agent's resolution) and the
  `sha256` / `sha256_partial` that both records have must agree; otherwise the
  file is a mismatch with its reasons, and a file only one root has is missing
  on the other side;
- a file modified at or after the start of the older of the two scans (looking at
  the records on both sides) is left out and counted as changed since, because
  two scans taken at different times legitimately differ there; without scan
  times in the root index nothing is left out;
- the roots are the same share when at least 95% of the files judged match and at
  least 10 (or all, when the sample has fewer) were judged. The 5% covers files
  deleted or replaced without a newer `mtime`; two different shares under one
  name match almost nothing.

The canonical spelling is the one `[agents.shares]` gives, else the one root that
was scanned through an agent (`agent` in the root index). When neither is known
`case-merge OLD NEW` names it: NEW's spelling is kept, and the NAS's spelling
needs `--force` to be overruled. `case-merge` with no names merges every pair
whose canonical spelling is known.

`case-merge` verifies first (`--force` skips the verdict, `--dry-run` stops after
it) and refuses while a scan of either root is running (`--force`, as with
`samples prune`). It moves the records of OLD to NEW in batches, writing a batch
before deleting it from OLD, with their archive members. A path both roots have
keeps the record of the root scanned later (the canonical root on a tie). Then it
removes OLD's root-index entry, stored aggregates, treemaps and resume state and
rebuilds NEW's aggregates. A marker on NEW's root-index entry records the merge
in progress, so a merge that was killed is finished by running the command again
(without verifying again, since half-moved roots no longer compare), and a
finished merge run twice moves nothing. Dropped-record entries of OLD are left to
expire (`--keep-dropped`).

## Backup data and `enrich`

`filecat enrich` leaves backup data as the scan left it: a record with
`probe.backup_data` is not opened or hashed, whatever `--what` and
`--force` say, unless `enrich --measure-backups` is given.
