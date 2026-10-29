# Synology Hyper Backup target format (`.hbk`)

What is known about the on-disk layout of a Hyper Backup "multi-version"
target, written so that a reader or explorer can be built without
Synology's software. Synology does not publish the format.

filecat itself only needs part of this (`src/filecat/backup/hyperbackup.py`):
it lists the target, reads the task and version metadata, and checks the
files against the target's own `Guard` manifest. Everything else here is for
a future reader.

## Sources and confidence

Each statement carries one of these tags:

| tag | meaning |
|---|---|
| **[F]** | checked here, against real targets written by Hyper Backup 4.2.1-4228 on DSM (see "Targets examined") |
| **[H]** | from hbkit's FORMAT.md, verified there on a Hyper Backup 4.1.2 target and also consistent with what was seen here |
| **[h]** | from hbkit only, not checked here |
| **[I]** | inferred from the data, not proven |
| **[?]** | unknown |

- hbkit, MIT licence: <https://github.com/YordiLorenzo/hbkit>, spec
  <https://raw.githubusercontent.com/YordiLorenzo/hbkit/main/FORMAT.md>. It
  restores files byte-exact and documents encryption.
- Prior art cited by hbkit (not read here): TeamDman/teamy-hyper-backup-explorer
  (Rust, MPL-2.0) and mistersandman/hyperbackup_decrypt (Python 2, older
  encrypted targets).
- Synology only says that `.hbk` is "the Synology .hbk backup format", which
  Hyper Backup Explorer can browse
  (<https://www.synology.com/en-us/dsm/7.4/software_spec/hyper_backup>).

### Targets examined [F]

| | target A | target B |
|---|---|---|
| Hyper Backup | 4.2.1-4228 | 4.2.1-4228 |
| `Config/index_ver.json` | 0.9.0 | 0.9.0 |
| `Config/target_ver.json` | 0.3.0 | 0.3.0 |
| destination | local share on another NAS | the same share |
| versions | 257 kept (ids 3..497), rotation "smart recycle" | 2 |
| source | 5.86 TB in 1.6 M files | 2.75 TB in 737 k files |
| target size | ~3.4 TB, ~1 M files | ~1.7 TB, ~300 k files |
| buckets | 62 698 live (ids 69 337..172 389) | 32 500 (ids 0..32 499) |
| compression / encryption | LZ4 (`data_compress_type=1`) / none | LZ4 / none |

On target B the whole manifest was checked: all 121 027 files Guard lists
were present with the listed size. A whole-file CRC32 was checked on a
sample of every Guard type, and three files were restored with MD5-checked
chunks.

## 1. Conventions

- Every integer in the binary files is **big-endian** [H][F].
- Every SQLite database and most index files are written twice: `name` and
  `name_dup`. The `_dup` copy is the previous commit, kept for rollback [I].
  On target A, `candidate_chunk.db_dup` was older than `candidate_chunk.db`
  but the same size.
  - hbkit's 4.1.2 target used generation suffixes `name.<n>` instead (read
    the highest) [h]. A reader should accept both.
- Times in SQLite and the INI files are Unix seconds, UTC [F].
- Byte counts in `storage_statistics.db` and `last_status.conf` are KiB
  [I, see section 3.3]. Everywhere else they are bytes.
- macOS AppleDouble `._*` files may appear on targets copied through a Mac;
  ignore them [h].

## 2. Directory tree [F]

```
<host>_<n>.hbk/                       folder name = target_dir in _Syno_TaskConfig
  SynologyHyperBackup.bkpi            empty marker; Explorer opens this file
  _Syno_TaskConfig                    INI, the task's settings          (3.1)
  last_status.conf                    INI, last backup/suspend           (3.2)
  storage_statistics.db               SQLite, sizes per version          (3.3)
  synobkpinfo.db                      SQLite, task id and format flags   (3.4)
  discard.prog, version_delete.prog   INI, progress of rotation jobs     (3.5)
  Config/
    version_info.db[_dup]             SQLite, one row per version        (4.1)
    @Share/<share>/<version>.db       SQLite, file tree of one share in one version (4.2)
    @Share/<share>/complete_list.db[_dup]  versions that finished for this share (4.3)
    virtual_file.index/<n>.idx[_dup]  shard stream, 56-byte per-file records (6.1)
    file_chunk<k>.index/<n>.idx[_dup] shard streams, per-file chunk lists, k = 1..4 (6.2)
    file_chunk<k>.index/locker        empty
    @cand_file/<id>_<k>.cand[_dup]    dedup candidate lists, id < 4096   (4.5)
    @cand_file/<id // 4096>/<id>_<k>.cand[_dup]   id >= 4096
    @cand_file/fileID.counter[_dup]   u64: number of .cand files
    candidate_chunk.db[_dup]          large (GBs), dedup candidates; not read here [?]
    avai_file_chunk.db[_dup]          SQLite avai_file_chunk(id INTEGER PRIMARY KEY) [?]
    dedup.db                          empty on both targets
    target_info.db                    SQLite, target state               (4.6)
    index_ver.json, target_ver.json   {"major":0,"minor":9,"sub_minor":0}
    target_recover.info               8 bytes: "R-I_" 00 00 0f ff [?]
    read_locker/<version>             one empty file per version
    writer_locker/backup_worker.lock  empty
    cand_vacuum_locker, version_list_vacuum_locker   empty
  Pool/
    0/<id >> 11>/<id & 0x7ff>.bucket  chunk data, about 50 MiB each        (5.1)
    0/<id >> 11>/<id & 0x7ff>.index   the bucket's chunk directory        (5.2)
    0/<id >> 11>/<id & 0x7ff>.lock    empty
    chunk_index/<n>.idx[_dup]         shard stream, 29-byte chunk records (6.3)
    file_pool/<n>.file                whole-file store, small files       (5.4)
    file_pool/file_pool_map.db        SQLite (5.4)
    file_pool/file_id.counter         u64: next file_pool id
    bucketID.counter[_dup]            u64: number of bucket ids handed out
    del_list.db                       SQLite del_list(id INTEGER PRIMARY KEY): buckets queued for deletion [I]
  Guard/                              integrity bookkeeping                (7)
    local_bucket.db[_dup]             every bucket and bucket index, with size and CRC32
    local_file.db[_dup]               every other data file, with size and CRC32
    config.json                       {"state": "committed"|"ready", "last_write_begin": t, ...}
    bucket_id.prog                    {"bucket_id": n}
    detect.prog                       INI, the last integrity check
    detect/error.log                  that check's error log
    detect/bad_chunk/                 header, unique.db (ref_count table), unique_config
    detect/bad_chunk.lock
  Control/                            empty on both targets
  Versionlog/log_<version>.zip        change log of one version          (8)
```

`Pool/0` is the only pool seen. The `0` is a pool number [I]. hbkit writes
it as `<pool>`.

Size breakdown of target A, as a rough guide:

- `Config/@Share` 107 GB (16 shares × 257 version databases);
- `Config/@cand_file` 44 GB in ~300 k files;
- `Config/file_chunk*.index` 36 GB, counting `_dup`;
- `Config/candidate_chunk.db` 2 × 6.7 GB;
- the buckets ~3.2 TB.

## 3. Top-level files

### 3.1 `_Syno_TaskConfig` [F]

An INI file with one section, `[task_config]`. Each value is JSON (a
number, `true`, `"string"`, `[...]`, `{...}`) or a JSON string that itself
holds JSON, such as `schedule`. Split each line on the first `=`, because
values contain `:`.

| key | example / meaning |
|---|---|
| `name` | task name shown in DSM, `"Synology NAS 1"` |
| `host_name` | source NAS host name |
| `source_model` | `"DS1823xs+"` (absent on older tasks) |
| `ip` | source NAS IP |
| `unikey` | `"<12 hex>_<repo id>_<create_time>"`, the task's unique key; also the salt input for encryption [h]. The 12 hex digits are the same for every task of one source NAS (a MAC address or serial [I]). |
| `linkkey` | `"<host>_<12 hex>_<repo id>"` |
| `repo_id`, `sched_id`, `incheck_sched_id` | DSM-side ids |
| `create_time` | task creation, Unix seconds |
| `target_dir` | the `.hbk` folder name |
| `backup_folders` | `["/Software", "/homes", ...]` shared folders backed up (absent on some older tasks; then use the latest version's `share` column) |
| `backup_apps`, `backup_apps_config` | DSM packages whose settings are backed up |
| `backup_data_type` | `"data"` |
| `backup_filter` | `{"exclude_list": [...], "whitelist": [...]}` |
| `backup_volumes` | `[]` |
| `compatible_info` | `{"source_hb_version": "4.2.1-4228", "source_product": "DSM"}` |
| `data_compress_type` | 1 = LZ4 [H]; 2 = LZ4-HC, 4 = zlib [h] |
| `enable_data_encrypt` | `true`: encrypted target, section 10 |
| `support_cross_file_dedup` | `true` |
| `enable_version_rotation`, `rotate_option`, `rotate_action`, `rotate_condition`, `rotate_customized_rules` | retention: `"rotate_smart_recycle"`, rules `[[seconds, keep-every-seconds, n], ...]` |
| `schedule`, `schedule_enable`, `incheck_schedule`, `incheck_schedule_enable`, `incheck_info` | backup and integrity-check schedules (JSON in a string) |
| `enable_notify`, `enable_version_file_log`, `enable_xattr`, `trans_encrypt`, `max_auto_resume_retry`, `enable_target_growth`, `target_growth_value`, `enable_target_max_size`, `target_max_size_value`, `enable_*_count`, `*_count_percent`, `delete_count_percent` | other settings |

No password or key was found in it on unencrypted targets [F].

### 3.2 `last_status.conf` [F]

```
[last_status_local]
last_size=3372648839          KiB [I]
size=3371719934               KiB [I]
[last_suspend]                the last interrupted run (same keys as last_backup)
[last_backup]
action="idle"
auth_id=1026
auth_name="<DSM user>"
client_ip="192.0.2.141"
start=1792314321
end=1792314985
version=["497"]               version_info.id of that run
```

Only `[last_backup]` exists on a target that was never interrupted.

### 3.3 `storage_statistics.db` [F]

```sql
CREATE TABLE source_table (start_time INTEGER, end_time INTEGER, source_size INTEGER,
  total_count INTEGER, modify_count INTEGER, new_count INTEGER, unchange_count INTEGER,
  remove_count INTEGER, file_size_distribution TEXT, version_id INTEGER,
  compress_size INTEGER, uncompress_size INTEGER, PRIMARY KEY (end_time));
CREATE TABLE target_table (start_time INTEGER, end_time INTEGER, action_type INTEGER,
  target_size INTEGER, version_id INTEGER, PRIMARY KEY (end_time));
CREATE TABLE versions (version_number INTEGER, PRIMARY KEY (version_number));   -- 3
```

- `source_table` has one row per backup run.
  - `source_size` is in KiB. It equals (share + app + ea `total_size` in
    `version_info.statistics`) / 1024 [F].
  - `file_size_distribution` is a JSON string, `'{"du_size_dist":{"2KB":3776,
    ...,"512GB":3}}'`, wrapped in single quotes.
- `target_table` has a row after each backup (`action_type` 1, with the
  `version_id`) and after each rotation or cleanup (`action_type` 2,
  `version_id` 0) [F]. `action_type` 3 was seen once [?].
  - `target_size` is the target's size in KiB [I]. Times 1024 it was a
    little above the bytes Guard lists (+1 % and +2 % on the two targets),
    which fits the `_dup` copies and other files Guard leaves out. This was
    not checked against a full du of the target.

### 3.4 `synobkpinfo.db` [F]

```sql
CREATE TABLE task_id_tb (task_id TEXT);                      -- = linkkey
CREATE TABLE backup_info_tb (info_name TEXT, info_value TEXT);
-- rows include formatType='image', dataComp='T', dataEnc='F'
```

### 3.5 `*.prog` [F]

These are INI `[progress]` files with `percent`, `pid` (-1 when idle),
`result`, `error_code`, `errPath` and `userName`.

- `version_delete.prog` also has `stage` ("compact"), `is_rotate`,
  `version_id` and `version_create_time` of the version being removed.
- `result=3` with `error_code=0` follows a normal finish [I].

## 4. Config: versions and file trees

### 4.1 `Config/version_info.db` [F]

```sql
CREATE TABLE version_info (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER,
  name TEXT, source TEXT, share TEXT, status TEXT, statistics TEXT, diff_size INTEGER,
  locked INTEGER NOT NULL default 0, share_info BLOB, missing_src TEXT,
  tag_db_magic BLOB, tag_db_file_size_thr INTEGER, has_suspend_dup INTEGER DEFAULT 0,
  bad_share TEXT DEFAULT '', internal_share TEXT DEFAULT '', suspend_history TEXT DEFAULT '',
  enc_cksum BLOB DEFAULT NULL, depose_time INTEGER DEFAULT -1);
```

- `id`: the version number used everywhere else (`<version>.db`,
  `log_<version>.zip`, `read_locker/<version>`). Rotated-away versions leave
  gaps.
- `timestamp`: when the run started.
- `name`: `"my_ver"` on every row seen.
- `status`: values seen are `Complete`, `Failure` and `Cancel`. A failed
  row keeps no `statistics`.
- `locked`: 1 = the user locked this version against rotation.
- `share`: the shares in this version, comma-terminated:
  `"@AppConfig,Archive,P,homes,"`. `internal_share` holds the `@AppShare_*`
  folders separately.
- `source`: JSON of what was selected: `share_path`, `user_backup_folder`,
  `app_backup_folder`, `app_list`, `app_share`, `path_filter`
  (per-share whitelists), `eaCtx`, `additional_info`.
- `statistics`: JSON with `compress_size`, `uncompress_size`,
  `new_chunk_size`, `unch_chunk_size`, `new_file_size`, `mod_file_size`,
  `unch_file_size` and `trg_increase_size` (KiB [I]). It also has `summary`:
  `{"share"|"app"|"ea": {total_cnt, total_size, new_cnt, new_size, mod_cnt,
  mod_size, del_cnt, del_size, unch_cnt, unch_size}}`.
  - "share" is user data, "app" is package settings, "ea" is extended
    attributes.
- `suspend_history`: a JSON list of `{client_time, server_time, event,
  event_desc}`. Events seen are 1 "create" and 6 "complete". An
  interrupted run has only "create".
- `depose_time`: the `timestamp` of the next version, when this one stopped
  being the newest [I]. It is 0 on the newest.
- `share_info`, `tag_db_magic`, `tag_db_file_size_thr` (1024),
  `has_suspend_dup`, `missing_src`, `bad_share`, `enc_cksum` [?].

### 4.2 `Config/@Share/<share>/<version>.db` [F]

There is one database per share per version. Each holds that share's full
file tree as it was in that version, not a delta.

```sql
CREATE TABLE version_list (name_id_v2 BLOB PRIMARY KEY, pname_id_v2 BLOB,
  off_virtual_file INTEGER, file_name TEXT, mtime_sec INTEGER, mtime_nsec INTEGER,
  size INTEGER, ctime_sec INTEGER, ctime_nsec INTEGER, mode INTEGER, dedup_id INTEGER,
  version_id INTEGER, cand_id INTEGER, status TEXT, inode INTEGER, tag BLOB,
  cr_time INTEGER, disk_entry_tag BLOB, nlink INTEGER, fs_id INTEGER,
  middle_file_path TEXT DEFAULT NULL);
CREATE INDEX parent_index ON version_list (pname_id_v2);
CREATE INDEX version_index ON version_list (version_id);
CREATE TABLE file_system_list (fs_id INTEGER PRIMARY KEY AUTOINCREMENT, version_id INTEGER,
  device INTEGER, fs_uuid TEXT);
CREATE UNIQUE INDEX fs_index ON file_system_list (device, fs_uuid);
CREATE TABLE setting (key TEXT PRIMARY KEY, value TEXT);   -- ('scan_all_file_attribute','done')
```

- `name_id_v2` is a 20-byte node id, and `pname_id_v2` is the parent's id.
  - The top-level entries of the share are the rows whose `pname_id_v2`
    matches no row's `name_id_v2` [F].
  - Build a path by walking parents [H][F].
- `mode` is a POSIX st_mode. A directory has `S_ISDIR(mode)`; `0o100700` is
  a regular file [F].
- `size` is in bytes. `mtime_*`, `ctime_*` and `cr_time` are times; `inode`
  and `nlink` are the source's [F].
- `off_virtual_file` is a byte offset into the virtual_file stream (6.1).
  `-1` means the file is in `Pool/file_pool` (5.4) [h].
- `version_id` is the version that wrote this row's content. A file left
  unchanged since an older version keeps the older id [I].
- `status`: `'U'` was seen [?]. The roles of `dedup_id`, `cand_id`, `tag`,
  `disk_entry_tag`, `fs_id` and `middle_file_path` are unknown [?].
- Synology metadata entries are named `@eaDir`, `*@SynoEAStream` or
  `*@SynoResource`. Hide them when browsing [h].

### 4.3 `Config/@Share/<share>/complete_list.db` [F]

```sql
CREATE TABLE complete_list (version_id INTEGER PRIMARY KEY);
```

This lists the versions in which this share finished. A version is
restorable for a share only if it is listed here [I].

### 4.4 Listing a version

1. Take the `id` values from `version_info` (status `Complete`).
2. For each share in that row's `share` column, open
   `Config/@Share/<share>/<id>.db`.
3. Walk `version_list`.

`Config/@Share/<share>/` can also contain only `complete_list.db` (a share
that was selected and later removed) [F].

### 4.5 `Config/@cand_file` [F]

`.cand` files are shard-style files: 64-byte header (section 9) with kind 0,
variant 1, record size 0. The files are dedup candidate lists [I]; the body
is not decoded [?].

- File `<id>_<k>.cand` holds candidate list `<id>`. Ids below 4096 sit in
  the folder itself, and the others in subfolder `<id // 4096>`.
- `<k>` was 1..5 on target B and 1 on target A [?].
- `fileID.counter` holds the count (54 830 on target B, the same as the
  number of `.cand` files Guard lists).
- They are not needed to restore files [I].

### 4.6 `Config/target_info.db` [F]

```sql
CREATE TABLE target_info (name TEXT, option TEXT, status TEXT, pid INTEGER, pcmd TEXT,
  save_pid INTEGER, save_pcmd TEXT, file_chunk_index_size TEXT, privilege BLOB);
-- status 'ready'; file_chunk_index_size '1:4619291436,2:5238374212,3:...,8:0,'
```

`file_chunk_index_size` gives the logical stream length of each
`file_chunk<k>.index`. Eight slots exist; four were in use [F].

## 5. Pool

### 5.1 Buckets [H][F]

```
dir  = bucket_id >> 11          # 2048 buckets per folder
file = bucket_id & 0x7ff
Pool/0/<dir>/<file>.bucket      concatenated compressed chunks, no header, ~50 MiB
Pool/0/<dir>/<file>.index       its chunk directory
Pool/0/<dir>/<file>.lock        empty
```

- The same file names occur in every folder, so the folder is needed [H].
- Bucket ids only grow: target A starts at 69 337 because older buckets
  were deleted by rotation and compaction [F].
- `Pool/bucketID.counter` is a u64 holding the number of ids handed out
  (32 500 on target B, ids 0..32 499) [F].

### 5.2 Bucket `.index` [H][F]

- A 64-byte header (section 9): kind 2, variant 1, record size 32, word 10
  `0x01010000` [?]. The stream length equals the file size.
- Then records of 32 bytes:

| offset | size | field |
|---|---|---|
| 0 | 4 | compressed length |
| 4 | 4 | offset of the chunk in the `.bucket` |
| 8 | 4 | uncompressed length |
| 12 | 16 | MD5 of the uncompressed chunk |
| 28 | 4 | CRC32 (zlib) of bytes 0..27 of this record |

- On target B, all 6952 records of one index passed the CRC check. The
  chunks follow each other in the bucket (offset = previous offset +
  previous compressed length) [F].
- Chunks are a few KB to tens of KB uncompressed [F].
- hbkit reports a 28-byte record without the CRC on older targets [h].

### 5.3 Chunk payload [H][F]

The bytes at `offset`, `compressed length` long, are one raw LZ4 block, with
no frame and no magic. Decompress it to exactly `uncompressed length` and
check the MD5.

- Verified here with a 30-line pure-Python LZ4 block decoder [F].
- zlib (`data_compress_type=4`) and encrypted payloads are described by
  hbkit only [h].

### 5.4 `Pool/file_pool` [F]

- `<n>.file` holds small whole files with their own 4-byte magic
  `e2 35 ab c8` and then zeros at the start [?]. They were 40–65 KB on
  target B.
- `file_pool_map.db`:

  ```sql
  CREATE TABLE file_pool_map (id INTEGER UNIQUE, checksum BLOB PRIMARY KEY NOT NULL,
    count INTEGER);   -- checksum 16 bytes (MD5 [I]), count = references
  ```

- Version rows with `off_virtual_file = -1` point here [h]. The link from a
  row to an id is not decoded [?].

## 6. Index streams

`virtual_file.index`, `file_chunk<k>.index` and `Pool/chunk_index` are
logical byte streams split into numbered files of 8 MiB (`0.idx`, `1.idx`,
...). Concatenate them in numeric order. Only `0.idx` starts with the
64-byte header, records begin at stream offset 64, and records may cross
from one file into the next [H][F].

### 6.1 `virtual_file.index`: one 56-byte record per file version [H][F]

| offset | size | field |
|---|---|---|
| 0 | 8 | chunk list pointer: `(k << 48) \| offset`. `k` selects `file_chunk<k>.index` and `offset` is the byte offset of the chunk list in that stream |
| 8 | 4 | ref count [h] |
| 12 | 4 | uid [h] |
| 16 | 4 | gid [h] |
| 20 | 8+4 | atime sec, nsec [h] |
| 32 | 8+4 | crtime sec, nsec [h] |
| 44 | 4 | mod_ver or CRC [h] |
| 48 | 8 | ACL pointer, same packing; it was the chunk list offset − 12 on every file seen [H][F] |

There is no size or name here. The size comes from `version_list.size`.

### 6.2 `file_chunk<k>.index`: chunk lists [H][F]

The pointer leads to a flat array of big-endian int64 values. Each is a
byte offset into the `Pool/chunk_index` stream.

- Read entries until the uncompressed lengths add up to the file's size;
  no count is stored [H].
- The 12 bytes just before the array (at the ACL pointer) are an 8-byte
  value plus a u32.
  - The u32 was `8 × (chunks + 1)`: `0x10` for a 1-chunk file, `0x18` for
    2 chunks [F, two files].
  - The 8-byte value was the same on both files, `00000089a93b0200` [?].
  - So the u32 is the size of this list record in bytes, counting the
    8-byte value [I].
- Header: kind 1, variant 0, record size 0 [F].

### 6.3 `Pool/chunk_index`: 29-byte chunk records [H][F]

| offset | size | field |
|---|---|---|
| 0 | 1 | flags; bit 0 set = indirect |
| 1 | 8 | if indirect: offset of another chunk_index record (deduplicated chunk; follow it, guard against loops) |
| 1 | 4 | if direct: bucket id (int32) |
| 5 | 4 | if direct: byte offset of the 32-byte record in that bucket's `.index` |
| 25 | 4 | CRC [?] |

Header: kind 1, variant 0, record size 29 [F]. hbkit describes a 16-byte
record on older targets [h].

### 6.4 Reading a file (verified on target B) [H][F]

```
row  = version_list row (size, off_virtual_file)
vf   = virtual_file stream[off_virtual_file : +56]
k, p = vf[0:8] >> 48, vf[0:8] & 0xffffffffffff
data = b""
while len(data) < row.size:
    c = int64(file_chunk<k> stream[p : p+8]); p += 8
    rec = chunk_index stream[c : c+29]
    while rec[0] & 1: rec = chunk_index stream[int64(rec[1:9]) : +29]
    bucket, ioff = int32(rec[1:5]), int32(rec[5:9])
    idx = Pool/0/<bucket>>11>/<bucket&0x7ff>.index [ioff : ioff+32]
    check crc32(idx[0:28]) == idx[28:32]
    clen, off, ulen = idx[0:4], idx[4:8], idx[8:12]
    chunk = lz4_block_decompress(bucket file[off : off+clen], ulen)
    check md5(chunk) == idx[12:28]
    data += chunk
```

This restored a 10-byte file (1 chunk) and a 28 KB file (2 chunks) from
target B. It read only the byte ranges it needed, and every chunk's MD5
matched.

## 7. Guard: the target's own manifest [F]

`Guard/local_bucket.db` and `Guard/local_file.db` share one schema:

```sql
CREATE TABLE file_info (type INTEGER NOT NULL, name TEXT, idx INTEGER, mtime INTEGER,
  size INTEGER, crc BLOB, status INTEGER, check_status INTEGER, mtime_nsec INTEGER);
```

Each row is one file of the target. `crc` is the **CRC32 (zlib/IEEE) of the
whole file, 4 bytes big-endian**. It matched on 11 of 11 sampled files,
covering every type. `size` is the file's size, and `mtime`/`mtime_nsec`
its modification time.

Where each row's file lives:

| db | type | path |
|---|---|---|
| bucket | 6 | `Pool/0/<idx >> 11>/<idx & 0x7ff>.index` |
| bucket | 7 | `Pool/0/<idx >> 11>/<idx & 0x7ff>.bucket` |
| file | 1 | `name` is the path itself: `Config/candidate_chunk.db`, `Config/avai_file_chunk.db`, `Config/@cand_file/fileID.counter`, `Pool/bucketID.counter`, `Pool/file_pool/file_id.counter`, `Pool/file_pool/file_pool_map.db` |
| file | 2 | `Config/@Share/<name>/<idx>.db` |
| file | 3 | `Config/virtual_file.index/<idx>.idx` |
| file | 4 | `Config/file_chunk<name>.index/<idx>.idx` |
| file | 5 | `Pool/chunk_index/<idx>.idx` |
| file | 8 | `Pool/file_pool/<idx>.file` |
| file | 9 | `Config/@cand_file/<idx>_<name>.cand` if idx < 4096, else `Config/@cand_file/<idx // 4096>/<idx>_<name>.cand` |
| file | 10 | `Versionlog/log_<idx>.zip` |

The `_dup` copies, lockers, `Config/version_info.db` and the top-level
files are not in Guard.

`status` values seen:

- on target B, 1 everywhere except buckets (type 7), which were all 5;
- on target A, buckets were mostly 1 with 1020 at 5, and 71 bucket indexes
  were 2.

Their meaning is unknown [?]. A status-2 index may be one scheduled for
deletion. `check_status` was 0 everywhere [?].

Other files in `Guard/`:

- `config.json`: `{"issue_fix": 3, "last_rollback": 0, "last_write_begin": t,
  "reentrant_action": 0, "reentrant_force_commit": false,
  "reentrant_no_rollback": false, "state": "committed" | "ready",
  "version": 1}`.
- `detect.prog` holds the last integrity check, which is time-limited and
  incremental:

  ```
  [progress]
  data_end="{\"checked_size\":398461920762,\"total_checked_size\":1440111159148,\"total_size\":3210153789731,\"version\":1711375358}\n"
  data_start=1711375358      launch_time=1792321213    end_time=1792342740
  percent=100  result=5  error_code=1  stage=1  pid=-1  pcmd=""
  ```

  - `checked_size` is the bytes checked this run and `total_checked_size`
    the total since `data_start`.
  - That run ended at the schedule's time limit, which may be what
    `result=5`/`error_code=1` means [?].
- `detect/error.log` is text: an `Error Detect Start: <date>` line, then any
  errors, then `Error Detect Finish: <date>`. Only empty runs were seen.
- `detect/bad_chunk/` holds `header` (64 bytes, magic `7053a86e`),
  `unique.db` and `unique_config`:

  ```sql
  CREATE TABLE ref_count (offset INTEGER PRIMARY KEY, old_count INTEGER, new_count INTEGER);
  ```

  The table was empty.
- `bucket_id.prog`: `{"bucket_id": n}`, the bucket the check reached [I].

## 8. `Versionlog/log_<version>.zip` [F]

This is a zip with one member, `log_<version>_<YYYY-MM-DD>_<HHMMSS>.csv`
(local time of the run). The member is UTF-8 with a BOM and CRLF line ends:

```
new,P/Proposals/2025/.../IMG_0902.JPEG,788 KB,2025-01-10 21:39:16
```

The columns are action (`new` and others [?]), path as `share/...`, size in
human units, and mtime. The log of the first version lists every file
(110 MB uncompressed for 737 k files). It needs `enable_version_file_log`.

## 9. The 64-byte header [H][F]

Sixteen big-endian u32 words begin `0.idx` of every index stream, every
bucket `.index`, every `.cand` and `Guard/detect/bad_chunk/header`.

| word | meaning |
|---|---|
| 0 | magic `0x7053A86E` |
| 1 | kind: 0 virtual_file and `.cand`, 1 chunk_index and file_chunk, 2 bucket index |
| 2 | variant: 2 virtual_file, 0 chunk_index and file_chunk, 1 bucket index and `.cand` |
| 4 | record size: 56, 29, 0 (flat array), 32, 0 |
| 5–6 | u64 logical stream length (for a bucket index or `.cand`, the file size) |
| 7 | `0x08000000`, or `0x09000000` on file_chunk [?] |
| 8 | `0x8000` on sharded streams, 0 on single files [?] |
| 10 | `0x01010000` on bucket indexes [?] |
| 15 | **CRC32 (zlib) of words 0–14 (bytes 0..59)**. This held on every header checked [F]; hbkit does not mention it. |

## 10. Encryption [h]

Encryption is described by hbkit for its 4.1.2 target and not checked here
(no encrypted target was available). In brief:

- `enable_data_encrypt=true`.
- The target also holds `Config/public.pem` (a raw 32-byte X25519 public
  key), `Config/encKeys` and `Pool/vkey.db`:

  ```sql
  vkey(version_id, rsa_vkey, rsa_vkey_iv, checksum, ref_count)
  ```

  The two blobs are libsodium sealed boxes.
- Key derivation:

  ```
  seed       = argon2i13(password, MD5(unikey), ops=4, mem=16 MiB, 32)
  pub, priv  = crypto_box_seed_keypair(seed)
  ```

  Comparing `pub` with `public.pem` checks the password.
- Chunks: `LZ4(PKCS7-strip(AES-256-CBC(ciphertext, key, iv)))`, where key
  and iv are the opened `vkey` boxes for that version.
- File names: each path component is encrypted with AES-256-CBC, key
  `SHA256(priv || unikey)` and IV
  `MD5(unikey || "kkE7sRZRvnbVlJFofhD7WCXumXBGyzki")`, then base64 with `/`
  replaced by `_`.

See hbkit's FORMAT.md for the details.

## 11. Checking a target, cheapest first

| level | reads | finds | filecat |
|---|---|---|---|
| listing vs Guard | the directory listing only | missing files, wrong sizes | default (`scan`, pool listed) |
| pool totals vs Guard | the sum of a rolled-up `Pool/` (no listing of it) | missing bytes or files in the pool as a whole | `scan --rollup backup=automatic --verify-backups=1` |
| Guard CRC32 | every data file once, sequentially | bit rot or truncation of any data file | verify level 2 (v0.2.x); not available in v0.2.0 |
| bucket index CRC + chunk MD5 | every chunk, decompressed | a bad chunk, and which files use it | not implemented; it is what a restore does (6.4) |

`--measure-backups` is different. It hashes the data files for the catalog
like any other file, and does not compare them with Guard.

## 12. Not known yet

- the body of `.cand` files, `candidate_chunk.db` and `avai_file_chunk.db`
  (dedup bookkeeping, not needed to restore);
- `Pool/file_pool/<n>.file` (magic `e235abc8`), and how a version row
  points into it;
- the 8-byte value before each chunk list, and the last 4 bytes of a
  chunk_index record;
- Guard `status` (1, 2, 5) and `check_status`, and `detect.prog`'s
  `result`/`error_code`;
- header words 7, 8 and 10;
- `version_list.status`, `dedup_id`, `cand_id`, `tag`, `disk_entry_tag`,
  `middle_file_path`;
- `Versionlog` action words other than `new`;
- single-version and cloud (C2, S3, rsync) targets, Hyper Backup Vault
  targets, zlib compression, and encryption on 4.2.

## 13. Building an explorer

1. Detect the folder: `SynologyHyperBackup.bkpi` or `*.hbk` with `Config`
   and `Pool`. Read `_Syno_TaskConfig` (3.1) and refuse an encrypted target
   unless given a password.
2. List versions from `Config/version_info.db` (4.1). Mark `locked`, and
   hide non-`Complete` versions or show them greyed out.
3. For a version, list shares from its `share` column. Check
   `complete_list.db` (4.3), open `@Share/<share>/<id>.db` and build the
   tree from `name_id_v2`/`pname_id_v2` (4.2). Hide `@eaDir` and
   `*@Syno*` entries.
4. To restore a file, follow 6.4 and check the bucket index CRC32 and chunk
   MD5 as you go. Open each bucket file once per run and read ranges.
5. Read SQLite files from a copy, as filecat does
   (`backup/util.sqlite_rows`), so a running backup is never locked. Fall
   back to `_dup` when the main file is unreadable.
6. To find what changed between versions, compare two versions'
   `version_list` rows by path, using `size` and `mtime_sec`. Or read
   `Versionlog/log_<id>.zip` (8).
