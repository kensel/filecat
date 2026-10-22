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
   `--exclude`.
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

## Known gap

`filecat enrich` does not yet skip backup data. A record with
`probe.backup_data` has no hash, so `enrich` with its default `--what`
(which includes `hash`) would open and hash it, ABB pools included. Until
that is fixed, run `enrich` with `--root` / `--path` limits that leave the
backup shares out, or with `--what names`.
