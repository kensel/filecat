# Roadmap

Planned releases, drawn from the [research notes](research/README.md).
Section numbers refer to those notes.

## v0.1.1: compound documents (done)

Note 05 §1. `data/compound_formats.toml` separates true archives from
ZIP/gzip-based application formats; a `.docx`, `.jar` or `.epub` stores
only its anomalies (macros, embedded objects, executables, unexpected
paths) as members. See [compound-formats.md](compound-formats.md).

## v0.1.2: content-addressed text samples (done)

Note 05 §2.A. See [samples.md](samples.md).

- [x] A `samples` store keyed by content hash (`sha256`, or
  `sha256_partial` above 64 MiB): one document per unique content holding
  the 4 KiB text sample and the Ollama result. File records keep a
  `sample_id` instead of the text. SQLite, PostgreSQL, MySQL, SQL Server,
  MongoDB and the in-memory backend; the JSONL backends keep samples inline.
- [x] Scans and `enrich` write new samples there; a record without a hash
  keeps its sample inline until it gets one.
- [x] Ollama runs once per unique content: copies of a file share the
  result, and content that already has one is not sent again.
- [x] `filecat show`, the web viewer's record view and `filecat migrate`
  (backend to backend) put the sample back in front of the reader.
- [x] Crash-safe migration of existing records, `filecat samples migrate`
  (more than 20 million records on the largest catalog): batched, resumable
  from a checkpoint, idempotent (a sample is committed before its record
  loses the inline copy), with progress.
- [x] MongoDB creates the new `samples` collection with zstd block
  compression (note 05 §2.C).
- [x] `filecat enrich` skips listed-only backup data (`probe.backup_data`)
  unless `--measure-backups`, closing what was a known gap in
  [scanning.md](scanning.md) (note 01 §5).

## v0.1.3: members keyed by archive hash (done)

Note 05 §2.B and §2.C. See [members.md](members.md).

- [x] Member sets: the members of an archive with a content hash are stored
  once per hash (`member_sets` headers, `set_members` rows) and the record
  names its set with `members_id`, so an archive present in four places
  stores its members once, and moving or renaming it orphans nothing.
  Archives without a hash, and the JSONL backends, keep rows under the path.
- [x] Crash-safe migration of the existing member rows,
  `filecat member-sets migrate`: batched, resumable, every archive shows its
  members at every point.
- [x] The same pass trims compound documents measured before v0.1.1 to
  their anomalies and gives them the `probe.compound` summary.
- [x] Pruning: `filecat samples prune` and `filecat member-sets prune`
  remove what no record names, one server-side pass each, and refuse while
  a scan is running.
- [x] MongoDB: collections created by the backend use zstd block
  compression, and a new catalog's `sha256` index is partial (only records
  that have one). `sha256_partial` gets no index: nothing looks it up.
  Existing collections are rebuilt this way by `filecat migrate` into a new
  database.

## v0.1.4: hardening before the agents

The storage changes of v0.1.2 and v0.1.3 settle on the real catalog before
the agent becomes a second writer.

- [x] CI green on GitHub: the fixes from the first run (Windows `\\?\` link
  targets, test ordering), and `actions/checkout@v5` /
  `astral-sh/setup-uv@v7` (Node 24). MongoDB 8.0 refuses to start on the
  runners' Linux 6.19+ kernels (SERVER-121912): CI and `compose.yaml` test
  against `mongo:9.0` with `GLIBC_TUNABLES=glibc.pthread.rseq=1`; testing 8.0
  again waits for a fixed 8.0.x.
- [x] A scan no longer stops at a Windows reparse point that is neither a
  symlink nor a junction (`os.readlink` raises `ValueError` there); it is
  recorded as a link without a target.
- [x] `filecat samples migrate` and `filecat member-sets migrate` run on the
  25-million-record catalog (MongoDB): samples in about an hour, 12.0M
  samples into 11.4M documents; member sets in 47 minutes, 48.4M member
  rows down to 8.8M (38,010 archive copies share a set, 113,899 compound
  documents trimmed).
- [x] `filecat scan-everything --unfinished`: only the roots whose last scan
  did not finish (left in the resume file, never scanned, interrupted,
  failed, unreachable), so finishing a stopped run does not walk every
  finished share again.
- [x] Ctrl+C ends a command with a one-line message (and, for a scan, how
  to resume) instead of a traceback; exit code 130.
- Rescans of unchanged trees are slow (about 50 files/s over SMB to a
  MongoDB catalog): the walker looks up stored records one at a time. Read
  each directory's stored records in one query.
- Prune on large tables: the anti-join over `sample_id` / `members_id` has
  no index behind it; add expression indexes (or MongoDB partial indexes)
  if the timing calls for it.
- Rebuild an existing MongoDB catalog in place (zstd collections, partial
  `sha256` index) one collection at a time, instead of only through
  `filecat migrate` into a second database.
- `filecat migrate` copies member sets before the records that name them.
- Maybe, if the trial or a review says it matters: archives above 64 MiB
  whose copies differ in mtime get separate member sets (`sha256_partial`
  includes the mtime); path mapping between NAS POSIX paths and SMB UNC
  roots, and allocated size (`st_blocks`), ahead of the agent.

## v0.2.0: Rust agents and embedded metadata

The Rust agents go in. Note 05 §3 sets the division of labour: the agent
does listing, hashing and storage topology on the NAS; the central Python
server keeps store detection, manifest verification, probing and Ollama.

- `filecat-agent` (note 02, draft sources in
  [research/rust-agent](research/rust-agent/)): NDJSON-over-TLS daemon,
  self-generated certificate with fingerprint pinning, bearer token;
  static musl builds for x86_64 and armv7, built in CI.
- Python side: `[[agents]]` in `filecat.toml`, `AgentClient`,
  `RemoteFileProxy` (bounded `read_range` for ZIP directories, disk images
  and PE headers), POSIX-to-UNC path mapping so records and treemap pins
  line up with SMB scans.
- RPCs: list a directory (lstat, inode, `st_blocks`), measure (hash plus
  the 8 KiB head), read a range, sum a subtree. The agent records
  allocated size and deduplicates hardlinks by inode.
- Backup store rollups across the boundary (note 05 §3): Python detects the
  store from the listing and has the agent sum the data pool instead of
  walking it.
- Rollup groups (note 01): `[REDACTED]`, `[CACHE]`, `[SYNOLOGY]`,
  `[BACKUP]` synthetic `kind: "rollup"` records that never carry the names
  beneath them; `enrich` never opens them.
- Synology storage topology (note 03): `iscsi_lun.conf` and `@Repository`
  parsing, SAN LUNs, VMM disks and image-library templates, physical usage
  from `st_blocks` (never the 512 GiB `ROD` size).
- A `storage_pools` store and the storage hierarchy in the web viewer
  (note 04): pool and volume capacity bars, SAN/VM tiles behind a toggle,
  inspector cards for backup stores, block storage and rollups, and a jump
  from a VM disk to its guest server's shares.
- Embedded metadata: creator, title, subject, revision and application
  version from Office and OpenDocument files (the `metadata` parts listed
  in `compound_formats.toml`), EXIF/XMP from images, and tags from audio
  and video.
