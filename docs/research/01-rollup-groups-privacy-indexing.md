# 01 - Rollup Groups & Privacy-Preserving Indexing

This document specifies the design for **Rollup Groups** (rollup_groups) and hard exclude rules in filecat and filecat-agent. It solves two core challenges across multi-NAS environments: protecting sensitive folder/file names while preserving accurate capacity tracking ([REDACTED]), and eliminating database inode bloat from millions of tiny ephemeral, OS, or backup files ([CACHE], [SYNOLOGY], [BACKUP]).

## 1. Core Design: Parent-Level Synthetic Rollup Entries

When walking a directory (such as /volume1/project), if a child folder matches a configured rollup group (e.g., /volume1/project/private-project under [REDACTED]):

- **Zero Name Leakage:** The scanner never sends or stores the matched folder's real name (private-project) or any child filenames beneath it.
- **Fast Local lstat Traversal:** The agent traverses the subtree locally using symlink_metadata (lstat) without opening any files, staying strictly on the same filesystem device (st_dev) and deduplicating hardlinks via st_ino.
- **Synthetic Child Record:** All matched children in the same parent folder that belong to the same tag are merged into a single synthetic record: e.g., \\nas-main\project\[REDACTED] with kind = "rollup".
- **Historical Snapshot Pin Diffing:** Because filecat serve compares pinned treemap snapshots per folder, synthetic rollup tiles participate natively in snapshot diffing. You can immediately see if \\nas-main\project\[REDACTED] or \\nas-main\homes\jdoe\[CACHE] grew by +10 GB between weekly pins without exposing individual files.

## 2. Standard Rollup Categories

| Rollup Tag | Purpose | Typical Matched Patterns | Web UI Click Behavior |
|---|---|---|---|
| [REDACTED] | Privacy-preserving size-only indexing for sensitive subtrees | /volume1/project/private-project, /volume1/homes/jdoe/vault | Displays aggregate logical size, physical allocated size (st_blocks * 512), file/folder counts, and snapshot growth delta. |
| [CACHE] | Prevents millions of transient cache/build files from bloating MongoDB | */.cache, */node_modules, */__pycache__, */AppData/Local/Temp | Displays cache footprint summary and growth since last pinned snapshot. |
| [SYNOLOGY] | Tracks DSM hidden metadata & package overhead without indexing thumbnails | */@eaDir, */#recycle, /volume1/@appstore, /volume1/@apphome, /volume1/@appdata | Shows Synology system & thumbnail overhead per share or volume. |
| [BACKUP] | Collapses massive chunk pools (Pool/*.bucket, ABB @data, Veeam, MinIO) into one interactive tile | Automatically triggered by store_formats.json detectors or explicit paths | Opens the **Backup Store Inspector Modal** (protected machines, versions, dedup savings, and manifest integrity health). |

## 3. Configuration Additions (filecat.toml)

```toml
[[agents]]
name = "nas-main"
host = "192.0.2.13:9876"
alias = "\\\\nas-main"
cert_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
token = "${FILECAT_NAS-MAIN_TOKEN}"

# Hard exclude: neither walked nor counted in size totals (or handled by storage_pools)
exclude = [
  "/volume1/@docker",
  "/volume1/@snap",
  "/volume1/@iSCSI",
  "/volume1/@Repository",
  "/volume1/Backup/scratch"
]

# Rollup groups: walked via lstat only; emits one synthetic <parent>\[TAG] record per matched tag
[agents.rollup_groups]
"[REDACTED]" = [
  "/volume1/project/private-project",
  "/volume1/homes/jdoe/vault"
]
"[CACHE]" = [
  "*/.cache",
  "*/node_modules",
  "*/__pycache__",
  "*/AppData/Local/Temp"
]
"[SYNOLOGY]" = [
  "*/@eaDir",
  "*/#recycle",
  "/volume1/@appstore",
  "/volume1/@apphome",
  "/volume1/@appdata"
]
```

## 4. Catalog Record Schema for Synthetic Rollups

When Python receives a kind: "rollup" entry from the Rust agent (see handle_list_dir in rust-agent/main.rs), it writes the following document into the records collection:

```json
{
  "root": "\\\\nas-main\\project",
  "path": "\\\\nas-main\\project\\[REDACTED]",
  "name": "[REDACTED]",
  "kind": "rollup",
  "extension": "[REDACTED]",
  "size": 48291049216,
  "allocated_size": 48295198720,
  "mtime_ns": 1761001200000000000,
  "probe": {
    "rollup": {
      "tag": "[REDACTED]",
      "matched_folders": 1,
      "total_files": 14820,
      "total_dirs": 312,
      "newest_mtime_ns": 1761001200000000000
    }
  }
}
```

## 5. Safeguarding filecat enrich

To resolve the known gap in scanning.md where filecat enrich could accidentally open and hash listed-only backup data, enrich.py must filter out any record where:

- kind == "rollup"
- probe.backup_data != null (unless --measure-backups is explicitly set)
- probe.db_data != null (unless --measure-databases is explicitly set)
