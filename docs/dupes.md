# Finding duplicate big files

Files above 64 MiB are not hashed whole (`hashing.py`), so duplicates of big
files are found by a ladder of cheaper checks. Each rung is stronger and
slower than the one before. None except a full hash is proof.

Timings below are single runs against the author's catalog (4.4M records, MongoDB
on the same PC) and files on `\\nas-old\Backup` over SMB. Treat them as orders of
magnitude, not benchmarks.

| # | Method | Reads | Time seen | Strength |
|---|---|---|---|---|
| 1 | `sha256_partial` match (MongoDB query) | nothing | seconds | candidate |
| 2 | `filecat dupes`: same size, sparse windows | 6 x 1 MiB per file | 39 s for 1 GiB and up | strong candidate |
| 3 | `filecat dupes --full` | whole file | not run on real data | proof (up to `--full-max`) |
| 4 | `filecat dupes --dissect`: image file listings | file system metadata | about 3 h for one 208 GiB pair | strong for disk images |

## 1. `sha256_partial` (catalog only)

The scan stores, for each file above 64 MiB, a SHA-256 of the first MiB, the
last MiB, the size and the **mtime**. Equal digests therefore mean equal size,
equal mtime and equal ends. That suits copies that keep their timestamps
(robocopy, `cp -p`, restores) and misses copies that do not. The queries are in
[backends/mongodb.md](backends/mongodb.md). No file is opened.

## 2. `filecat dupes` (sparse windows)

```
filecat dupes                      # bands >100, 50-100, 20-50, 10-20, 1-10 GiB
filecat dupes --bands 100,10       # >100 and 10-100 GiB
filecat dupes --samples 8 --window 4
```

Files are grouped by **exact size only** (mtime is ignored, unlike method 1).
Within a size group, each file's start, end and `--samples - 2` evenly spaced
interior windows of `--window` MiB are hashed; files whose windows all match
form a cluster. A change that falls between the windows goes unseen, so a
cluster is labelled `sparse`.

Bands (lower edge exclusive, upper inclusive, largest first) let MongoDB select
each size range from an index on `size` (`Backend.list_sized`) instead of
streaming all 4.4M records. The first version, which listed every record and
filtered in Python, took 13 minutes (816 clusters of 100 MiB and up); the banded
run over 1 GiB and up took 39 seconds and found 95 clusters (682 GB apparent
waste). The cost is the window reads, 6 MiB per file, over SMB.

### Backup data

Files a scan recorded as backup data (`probe.backup_data`: ABB pools, Veeam
backup files, Thunderbird profile copies, ...) copy each other by design:
every generation of a profile copy repeats the last one. So a size group
with no file outside the backups is not read at all, and a cluster made only
of backup data is dropped. A backup file that matches a file outside the
backups is reported, together with its backup copies, each marked
`[backup: <format>]`. `--include-backups` reports the backup-only clusters
too. (The MongoDB `list_sized` query returns `probe.backup_data` for this.)

## 3. `--full`

Adds a full SHA-256 of every file in a cluster up to `--full-max` (default
1 GiB), which splits a cluster into true copies. Larger clusters stay labelled
`sparse (over --full-max)`. A full hash of the 208 GiB `LT-01.VHD` pair would
read about 416 GiB, which is why it is capped.

## 4. Disk image file listings (`--dissect`)

For clusters made only of disk images (`.vhd .vhdx .vmdk .vdi .qcow2 .img .raw
.dd`), the copies' file listings are compared instead of their bytes: path, size
and mtime of every file, from the image's own file system metadata (for NTFS the
MFT). Two images that hold the same files with the same timestamps are copies
for practical purposes, without reading the file data.

```
filecat dupes --bands 100 --dissect C:\code\filecat\.venv-dissect\Scripts\target-query.exe
```

(or `$FILECAT_DISSECT`). The listings are read from
[dissect](https://github.com/fox-it/dissect)'s `target-query -f walkfs --json`
and walked **in step**: filecat holds one entry per image, stops and kills both
processes at the first difference, and for identical images ends with a SHA-256
digest of the listing. The result is `listing: identical | differs |
unavailable` plus `listing_detail`.

### Measured on `LT-01.VHD` (208 GiB, two copies on `\\nas-old\Backup`)

| Run | Result | Time | Read |
|---|---|---|---|
| sparse windows (method 2) | match | seconds | 12 MiB per file |
| prototype: dissect libraries imported, MFT walk | 826,266 files, listings identical | 19 min per copy (the two ran at once) | 16.7 GiB per copy |
| `--dissect`: `target-query walkfs`, streamed in step | 1,312,656 entries, identical, digest `3d599ffb...8229` | 3 h 4 min for the pair | not measured |

The prototype's file count differs from `walkfs`'s because they count different
things (`walkfs` also lists NTFS system files, data streams and the second
partition). Each pair is internally consistent; the two tools were not
reconciled with each other. The prototype is not in the repository.

The MFT walk is about 10 times faster than `walkfs`, which opens each entry
through dissect's file system layer. The libraries read 16.7 GiB (8%) of the
image, more than the MFT alone needs; a path cache would likely cut that.

An earlier attempt that kept both full listings in memory (about 826k to 1.3M
entries each, plus dissect's own process) was stopped by Claude Code's low-memory
guard; the in-step comparison replaced it and runs in constant memory.

## AGPL

dissect is AGPL-3.0-or-later. filecat never imports it: `imagelist.py` runs the
`target-query` executable as a separate process and reads its JSON output with
the standard library. Install dissect in its own environment, not filecat's:

```
uv venv --python 3.13 .venv-dissect
uv pip install --python .venv-dissect\Scripts\python.exe dissect.target colorama
```

Python 3.13 is needed because `dissect.target` 3.25.1 does not import on 3.14
(`glob._Globber`), and `colorama` because its console logging requires it on
Windows. This is not legal advice; check the licence before distributing a
package that bundles or depends on dissect.

## Not done

- Reconciling the library walk with `walkfs` entry for entry.
- Storing the listing digest in the catalog so a later run can skip the walk.
- A faster helper (path cache) run as its own process.
- `--full` on real data, and non-NTFS images (the listing needs a file system
  dissect can read).
