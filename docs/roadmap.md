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
- [x] Rescans of unchanged trees were slow (about 50 files/s over SMB to a
  MongoDB catalog): the walker looked up stored records one at a time, and
  each lookup flushed the write buffer first, so every folder record went
  out as its own write. Now each directory's stored records come from one
  `get_stats()` query that does not flush (writes go out 500 at a time),
  and subdirectory listings are read ahead in background threads, three
  levels down.
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
  - [x] The wire protocol, version 1, written down as the contract the agent
    is brought into line with: [agent-protocol.md](agent-protocol.md), with
    `hello`, error codes, `measure` that reproduces `hashing.py` (including
    the 100 ns mtime of an SMB scan) and `sum_subtree`.
  - [x] `[[agents]]` in `filecat.toml` (token via `${NAME}`, share map,
    exclude and rollup groups), shown by `filecat config show`, with the
    agent that covers a UNC path found by longest match.
  - [x] `AgentClient` (TLS with certificate pinning, thread-safe, reconnects
    once), `RemoteFileProxy` / `open_remote` (works under `zipfile`) and
    `ShareMap` (POSIX and UNC paths both ways), tested against a fake agent
    in Python.
  - [x] `filecat agents list` and `filecat agents test`.
  - [x] `filecat scan` and `scan-everything` read a UNC root through the
    agent that covers it: listing, stat, measuring and probing from an
    agent-backed source (`fsource.py`, [scanning.md](scanning.md#6-scanning-through-filecat-agent)),
    records that line up with an SMB scan, rescans that skip unchanged
    files, `--agent`, `--no-agent` and `--agent-fallback`. Allocated size,
    inode, device and link count are recorded (optional fields); hard links
    are totalled once per scan. Still to do: backup-store and database
    manifests (and `sum_subtree` rollups) through the agent, rollup groups,
    `enrich` through the agent, hard-link dedup in the stored aggregates.
  - [x] One share, two spellings: roots that differ only in the case of
    `server\share` (an SMB scan typed in lower case, the NAS's own spelling
    from an agent) are found, checked on a 200 to 1000 file sample, and merged
    under the NAS's spelling (`filecat roots case-check` / `case-merge`); new
    scans record the NAS spelling through an agent and reuse the catalog's over
    SMB ([scanning.md](scanning.md#one-share-two-spellings)).
  - [ ] `filecat-agent` itself changed to match the protocol page.
- RPCs: list a directory (lstat, inode, `st_blocks`), measure (hash plus
  the 8 KiB head), read a range, sum a subtree. The agent records
  allocated size and deduplicates hardlinks by inode.
- Backup store rollups across the boundary (note 05 §3): Python detects the
  store from the listing and has the agent sum the data pool instead of
  walking it.
- Rollup groups (note 01): `[REDACTED]`, `[CACHE]`, `[SYNOLOGY]`,
  `[BACKUP]` synthetic `kind: "rollup"` records that never carry the names
  beneath them; `enrich` never opens them.
  - [x] Design: [rollups.md](rollups.md). Everything opt-in with a mode per
    type (`automatic`, `manual`, `disabled`; default `manual`, `[REDACTED]`
    always on), suggestions for built-in rules that are not automatic, record
    model and readers, one ordered rule list (`[[rollups.rule]]`; agent,
    share and local path forms converted with `ShareMap`; case-sensitive below
    the share; `**`; first match; `keep`) that means the same through an agent
    and over SMB, marker files (`.filecat-redacted`, ...) found when the
    parent is listed, sticky `[REDACTED]` kept as keyed hashes and `(dev, ino)`
    with a two-step release, `[REDACTED]` guarantees on every output channel
    and the purge of already-cataloged names, store rollups (`[BACKUP]`,
    `[DATABASE]`) with verify levels and a migration command, the old default
    skips as `[WINDOWS]` only under `windows = "automatic"`, reporting,
    re-sum and fingerprint change detection, progress/deadline/cancel for long
    sums, the agent requirements (also in
    [agent-protocol.md](agent-protocol.md)), the Python work plan.
  - [x] Python stage A: `rollup.py` (matcher, path forms, `sum_tree`), modes
    and config, markers, `redaction.py` and the `redactions` store, walker,
    `fsource`/`agent_client`, the records and the readers that must skip
    them, the privacy test, the extended fake agent, and
    `filecat rollups rules|list|suggest|redacted list|release|approve`.
  - [ ] Python stage B: backup and database store rollups, verify levels 0
    and 1 (`--verify-backups[=N]`), `filecat rollups migrate`, summary,
    roots and treemap reporting, the web tiles and inspector card.
  - [ ] Manifests of backup and database stores read through the agent
    (`StoreFS`), replacing `probe.store_note`.
  - [ ] Rust agent: rules matcher with the shared vectors, markers, the
    `redaction` HMAC and `folded`, rollups and `suggest` in `list_dir`,
    `sum_subtree` options, progress/deadline/`cancel`.
- Synology storage topology (note 03): `iscsi_lun.conf` and `@Repository`
  parsing, SAN LUNs, VMM disks and image-library templates, physical usage
  from `st_blocks` (never the 512 GiB `ROD` size).
  - [x] Design: one generic hierarchy (disk, group, pool, volume, share, lun,
    vdisk) with Synology first and Windows, Proxmox and TrueNAS as later
    derivatives of the same layout, ids from platform-native keys, shares
    that feed `ShareMap`: [storage-topology.md](storage-topology.md), the
    `storage_topology` reply in [agent-protocol.md](agent-protocol.md), and
    `filecat.topology` (dataclasses, validation, `share_entries`) with
    fixtures in `tests/data`.
  - [x] Links between hosts: disks carry `backing`/`match`, snapshots of
    many hosts resolve into chains (TrueNAS pool -> Proxmox vdisk -> PVEC ->
    Synology LUN; Virtual DSM -> VMM vdisk), `vm` nodes and Proxmox cluster
    scope, a physical total that counts each backed disk once
    (`resolve_links`, `physical_summary`, the `lab_*` fixtures).
  - [x] Verified on nas3: a LUN's NAA id derives from `vpd_unit_serial`
    (`topology.naa_from_unit_serial`), matched exactly; the LUN ACL is
    `iscsi_lun_acl.conf` (`initiators: [{iqn, authority}]`, `default.acl` as the
    default).
  - [x] Storage written by hand: `[[storage.hosts]]` (hosts with no agent, e.g.
    truenas2) and `[[storage.links]]` (`host/node-id` or `host/type:name`) in
    filecat.toml, which win over automatic matches and report conflicts;
    `filecat storage links [--snapshot FILE ...]` checks them. Shaped for a
    later catalog store edited in the web viewer (config entries read-only).
  - [ ] Still to verify: what the ACL `authority` values mean (0 and 3 seen),
    and whether Virtual DSM sees its VMM vdisk uuid. Then Proxmox and TrueNAS
    readers, so truenas2's hand-written entry can go.
  - [ ] Review the design (open questions at the end of the page), then:
    `synology_storage.rs` brought into line, `AgentClient.storage_topology`
    returning `Topology`, derived entries merged into `ShareMap` (config
    wins), the `storage_topology` store (one document per host snapshot plus
    history) and the viewer drill-down.
- A `storage_pools` store and the storage hierarchy in the web viewer
  (note 04): pool and volume capacity bars, SAN/VM tiles behind a toggle,
  inspector cards for backup stores, block storage and rollups, and a jump
  from a VM disk to its guest server's shares.
- Embedded metadata: creator, title, subject, revision and application
  version from Office and OpenDocument files (the `metadata` parts listed
  in `compound_formats.toml`), EXIF/XMP from images, and tags from audio
  and video.

## v0.2.x: rollup follow-ups

After the v0.2.0 rollups (stages A and B of [rollups.md](rollups.md)):

- Web viewer: an **audit screen** with the counts of `filecat rollups list`
  (by tag and parent folder, `[REDACTED]` as counts only).
- Web viewer: **suggestions**, the folders a built-in rule would match for a
  type that is not automatic, with "add this rollup" writing the rule.
- Web viewer: **redaction approval**, the screen behind
  `filecat rollups redacted release|approve`, showing what becomes visible.
- Backup verify **level 2** (every file the manifest names exists with its
  size, through a new agent `check_files` command that returns counts and the
  few failing manifest ids, no per-file rows) and **level 3** (hashes as the
  backup application checks them, per-format recipes).
- A per-store level: `[[rollups.backup_store]] path = '...' verify = 2`.
- Optional rollup measures: size by extension, age buckets, largest matched
  children (never for private rules).
