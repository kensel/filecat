# Roadmap

Planned releases, drawn from the [research notes](research/README.md).
Section numbers refer to those notes.

## v0.1.1: compound documents (done)

Note 05 §1. `data/compound_formats.toml` separates true archives from
ZIP/gzip-based application formats; a `.docx`, `.jar` or `.epub` stores
only its anomalies (macros, embedded objects, executables, unexpected
paths) as members. See [compound-formats.md](compound-formats.md).

## v0.1.2: content-addressed text samples

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

## v0.1.3: members keyed by archive hash

Note 05 §2.B and §2.C.

- The parent key of `members` changes from (root, archive path) to the
  archive's content hash, so an archive present in four places stores its
  members once, and moving or renaming it orphans nothing.
- Crash-safe migration of the existing member rows, as in v0.1.2.
- The same pass drops member rows that v0.1.1 no longer writes: the
  standard structure of compound documents measured before v0.1.1.
- Pruning: samples and member sets no file record refers to any more
  (`filecat samples prune`, and the same for members).
- MongoDB: partial indexes on `sha256` / `sha256_partial` (only records
  that have one), and zstd block compression for `files` and `members`
  when they are rebuilt.

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
