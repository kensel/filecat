# 05 - Catalog Tuning, Deduped Collections & Agent Division of Labor

This document details the database tuning strategy to dramatically shrink the 67M+ document footprint in MongoDB (currently 22M in files at 46.14 GB and 45M in members at 19.62 GB), eliminate "compound document" member explosion (such as .docx, .xlsx, and X3 .sav files), deduplicate 4 KiB text samples and LLM tags by content hash, and establish the architectural boundary between the lightweight Rust agent and the central Python server.

## 1. Stopping the members Explosion: Compound Document Filtering

### A. The Problem: ZIP/Gzip-Wrapped Application Formats

Because the probe inspects magic bytes (seeing PK\x03\x04 for ZIP or \x1f\x8b for Gzip), any application format that uses ZIP or Gzip as a container is currently unpacked into the members collection. For example, a single Microsoft Word document (Economic paper reqs.docx) generated 10+ member rows (word/styles.xml, [Content_Types].xml, word/document.xml, etc.). Across hundreds of thousands of Office documents, JARs, and game saves, this multiplies the members collection by 10x–50x.

### B. Solution 1: Compound Document Extension & MIME Classification

Instead of treating all ZIP/Gzip files as generic archives that dump rows into members, split ZIP/Gzip-based formats into two categories in the probe:

- **True Archives (Unpack to members):** .zip, .7z, .rar, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz, .iso, .cat/.dat (X3 game archives), .mpq, .pck.
- **Compound Application Documents (Do NOT unpack standard structure to members):**
  - **Office OpenXML:** .docx, .docm, .xlsx, .xlsm, .pptx, .pptm, .vsdx
  - **OpenDocument:** .odt, .ods, .odp, .odg
  - **eBooks & Publishing:** .epub, .cbz, .xps
  - **Java / Android / Packages:** .jar, .war, .ear, .apk, .aab, .whl, .nupkg
  - **3D / Design / Apps:** .3mf, .kmz, .sketch, .fig, .ora
  - **Gzip-Wrapped Game Saves & Data:** X3: Terran Conflict / Albion Prelude / Farnham's Legacy savegames (.sav), Minecraft .dat / level.dat (NBT-in-Gzip), Blender compressed .blend.

### C. Solution 2: Anomaly-Only Member Recording for Compound Documents

When scanning a compound document like a .docx or .xlsx, the probe can still read the ZIP Central Directory in memory to verify integrity and extract document metadata (e.g., reading docProps/core.xml for author/title or word/document.xml to extract a clean text sample for Ollama), **without writing standard internal XML boilerplate to members**:

- **Skip Expected Internal Paths:** Ignore standard schema paths ([Content_Types].xml, _rels/**, word/**.xml, xl/**.xml, ppt/**.xml, docProps/**, META-INF/**).
- **Record Only Embedded Payloads or Anomalies:** Only write a row to members if an unexpected or high-value embedded file is found inside the container (e.g., word/embeddings/*.bin, vbaProject.bin macros, or an unexpected .exe/.zip hidden inside a .docx).

## 2. Content-Addressable samples and members Collections

### A. Moving 4 KiB Text Samples + Ollama Tags to a Content-Keyed samples Collection

Currently, storing the 4 KiB text sample inline inside the files collection inflates the average document size to **2.13 kB** (46.14 GB across 22M files). Furthermore, if the same document exists in 5 backup generations or across 3 NAS shares, storing the sample and running Ollama classification on each path wastes both storage and LLM inference time.

**Design of the new samples Collection:**

- **Primary Key / Shard Key (_id):** The file's content hash (sha256 for files ≤ 64 MiB, or sha256_partial for files > 64 MiB).
- **Deduplicated Storage:** 10 copies of a file across \\nas-alt, \\nas-old, and \\nas-main point to **one** samples document.
- **Run Ollama Once Per Unique File:** When Ollama classifies a file into tags (e.g., ["work", "finance", "tax-return"] or ["school", "economics", "paper"]) and generates a topic summary, that enrichment is saved on the content-keyed samples document (or an enrichments field on it). Every copy of that file across all NAS shares immediately inherits the classification without re-prompting the LLM!

```json
// Collection: samples (sharded/indexed by _id = content_hash)
{
  "_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hash_type": "sha256",
  "size": 16795,
  "encoding": "utf-8",
  "sample_text": " Economic Paper Requirements\n1. Introduction and Thesis...",
  "llm": {
    "model": "gemma4:31b-cloud",
    "classified_at": "2026-10-21T19:00:00Z",
    "category": "school",
    "topics": ["economics", "term-paper", "requirements"],
    "summary": "Course assignment rubric and topic requirements for an undergraduate economics paper."
  }
}
```

### B. Deduplicating members by Archive Content Hash

Right now, members uses (root_id, archive_rel_path, index), meaning every duplicate .zip or .iso across your backups duplicates thousands of member rows. By changing the parent key of members from (root_id, archive_rel_path) to **archive_hash** (the parent archive's sha256 or sha256_partial):

- If a 50,000-file archive exists in 4 places, members stores **50,000 rows instead of 200,000 rows**.
- Moving or renaming an archive never orphans or requires rewriting its member rows.
- Sharding members by { archive_hash: "hashed" } keeps all members of a given archive co-located on the same shard.

### C. MongoDB Index & Compression Tuning

- **Switch WiredTiger Compressor to zstd:** Creating/rebuilding the files, members, and samples collections with storageEngine: { wiredTiger: { configString: "block_compressor=zstd" } } shrinks on-disk storage by an extra 35–50% over default Snappy compression.
- **Partial Indexes on files:** Because millions of listed-only backup and database files have sha256: null and sha256_partial: null, define the hash indexes with partialFilterExpression: { "sha256": { "$type": "string" } }. This cuts the 2.49 GB index RAM footprint significantly.

## 3. Architecture Boundary: Rust Agent vs. Central Python Server

A critical design question is whether backup/database store detection (store_formats.json) and file probing belong in the Rust agent or on the central Python server. **The answer: Keep the intelligence on the Central Python Server, and keep the Rust Agent as a fast, dumb syscall & byte-range engine.**

| Responsibility | Where It Runs | Why |
|---|---|---|
| **lstat Directory Listing, Inodes, Physical Blocks (st_blocks)** | **Rust Agent** | Must run locally on the NAS to avoid SMB round-trips and read Linux inodes/blocks. |
| **Path/Glob exclude and rollup_groups ([REDACTED], [CACHE], [SYNOLOGY])** | **Rust Agent** (configured dynamically by Python at scan start via ConfigurePolicy RPC) | Allows the agent to sum millions of cache/redacted files in local RAM and never send secret filenames or @eaDir junk over the network. |
| **Full & Partial SHA-256 Hashing** | **Rust Agent** (triggered by Python Measure RPC) | Reads file bytes locally off the RAID array; only the 32-byte digest crosses the LAN. |
| **Synology Volume / SAN LUN / VMM Discovery** | **Rust Agent** (StorageTopology RPC) | Requires local root access to /proc/mounts, /volume1/@iSCSI/LUN, and /volume1/@Repository. |
| **Backup & Database Store Detection (store_formats.json)** | **Central Python Server** | When Python receives the ListDir response from the Rust agent, Python checks its existing store_formats.json rules against the child filenames. If it detects ABB, Hyper Backup, Veeam, Postgres, or MinIO, Python marks the data files as *listed-only* (simply never sending Measure RPCs for them) or instructs the agent to roll up the data pool folder! |
| **Manifest Verification (SQLite target.db, version_info.db, .vbm, Guard)** | **Central Python Server** (via RemoteFileProxy / ReadRange) | All of your complex Python manifest parsers, SQLite readers, and integrity verifiers stay 100% in Python—you never have to rewrite them in Rust or recompile the NAS binaries when adding a new backup format! |
| **File Kind Probing, Disk Image MFT Parsing, Archive Member Listing, Ollama** | **Central Python Server** | Python receives the 8 KiB head inside the Measure response (enough for 95% of probes) and uses RemoteFileProxy (ReadRange) for bounded random seeks on disk images, ZIP central directories, and PE headers. |

### How Backup Store Rollups Work Across the Boundary

Because Python controls the walk folder-by-folder:

- Python calls ListDir on /volume1/Backup/NAS-VM_1.hbk.
- The Rust agent returns the immediate children: Config, Pool, Guard, Versionlog, _Syno_TaskConfig.
- Python's existing detector recognizes synology_hyperbackup!
- Python reads the tiny manifest files in Config/ and Guard/ via RemoteFileProxy to build probe.backup (machines, versions, health problems).
- If --rollup-backups is enabled, instead of walking every subfolder inside Pool/0/0/*.bucket and inserting 500,000 rows into MongoDB, Python calls a single SumSubtree (or rollup_groups) RPC on Pool/, attaches the total physical & logical bytes to the parent NAS-VM_1.hbk record, and moves on in seconds!
