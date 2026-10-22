# Research

Design research for future work, imported from Word documents (21 Oct 2026).
None of it is implemented yet; where these notes and the code or
[`file-catalog-requirements.md`](../../file-catalog-requirements.md) disagree,
the code and the requirements win.

| Note | Covers |
|---|---|
| [01 - Rollup groups](01-rollup-groups-privacy-indexing.md) | `[REDACTED]` / `[CACHE]` / `[SYNOLOGY]` / `[BACKUP]` synthetic rollup records, hard excludes, keeping `enrich` off listed-only data |
| [02 - Rust agent](02-rust-agent-architecture.md) | `filecat-agent`: NDJSON-over-TLS daemon on the NAS, TOFU cert pinning, musl cross-builds, Python `AgentClient` / `RemoteFileProxy` |
| [03 - Synology VMM and SAN LUNs](03-synology-vmm-san-luns.md) | `iscsi_lun.conf` and `@Repository` layout, the 512 GiB `ROD` sparse file, NAS-MAIN block-storage audit |
| [04 - Web viewer and storage hierarchy](04-web-viewer-storage-hierarchy.md) | `storage_pools` collection, pool → volume → LUN/VM → guest server hierarchy, inspector cards in `filecat serve` |
| [05 - Catalog tuning and agent boundary](05-catalog-tuning-agent-boundary.md) | Compound documents vs. archives in `members`, content-keyed `samples`, zstd and partial indexes, what runs in the agent vs. Python |

[`rust-agent/`](rust-agent/) holds the draft agent sources referenced by notes
02 and 03 (`Cargo.toml`, `main.rs`, `tls.rs`, `synology_storage.rs`). They are
not part of the build.
