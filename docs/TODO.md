# To do

Planned work that is not scheduled yet. The open questions are in
file-catalog-requirements.md under "Open points".

## Cloud files: what is not covered yet

`cloudfiles.py` keeps scans from downloading Cloud Files API placeholders
(OneDrive, iCloud, Dropbox ...) and offline/tiered files; see README "Cloud
files". Still open:

- **Google Drive for desktop** in streaming mode is a virtual drive
  (`G:`, filesystem name reported by the DriveFS driver), not
  placeholders: its files carry no recall attributes, and reading one
  downloads it. Recognise the volume (GetVolumeInformation file system /
  label, or the `DriveFS` registry keys) and treat every file on it as
  cloud-only unless Drive marks it available offline.
- **Folder placeholders**: listing a folder the provider has not filled in
  yet (RECALL_ON_OPEN on the folder) fetches its file list. Names only,
  but a scan of a big never-opened OneDrive tree makes many requests;
  consider an option to record such folders without listing them.
- **Backup and database summaries** read small metadata files
  (`storage_info.json`, `PG_VERSION`, `storage.bson` ...); inside a
  cloud-only folder that downloads them. Check the attributes first.
- **Dehydrate exactly**: `--free-after` sets UNPINNED and leaves the
  provider to drop the copy when it gets to it. `CfDehydratePlaceholder`
  (cldapi.dll) frees it at once, but needs a handle opened with the right
  flags; worth it if UNPINNED proves slow.
- **Record the sync roots**: a folder record for each sync root (provider,
  account from the root id, e.g. `OneDrive!<SID>!Business1`), and a
  `filecat cloud` listing of online-only files and bytes per provider.
- **Stale state**: a file measured while local and later freed keeps
  `state: local` until it changes, since unchanged files are not rewritten.

## Database folders: names, manifests and a location index

`dbfiles/` recognises PostgreSQL, MySQL/MariaDB, MongoDB and SQL Server
data folders by layout and lists their files (see README "Database
folders"). Still to do:

**Database and table names from the files**
- PostgreSQL: database names from `pg_database` (heap file `global/1262`),
  table names per database from `pg_class` (`base/<oid>/1259`). Both are
  plain heap pages; read only from a quiet or stopped cluster.
- MongoDB: map `collection-*.wt` / `index-*.wt` to namespaces from
  `_mdb_catalog.wt` (a WiredTiger btree of BSON documents). The MongoDB
  server version is in `diagnostic.data` (FTDC, zlib-compressed BSON).
- SQL Server: database name, create/current version and collation from the
  boot page (page 9) of each `.mdf`; the file list from `sys.sysfiles1`
  would need the catalog. Only for quiet or detached files: an attached one
  is held open.
- MySQL 8.0+: version from the data dictionary (`mysql.ibd` SDI) or the
  `.err` log's "ready for connections. Version:" line.

**Manifests of database backups**
- `pg_basebackup` folders (`backup_label`, `backup_manifest` JSON), `pg_dump`
  custom/directory format (`toc.dat`: server and dump version, database,
  object list), plain `.sql` dump headers.
- `mysqldump` headers (server version, database), Percona XtraBackup /
  mariabackup folders (`xtrabackup_info`, `xtrabackup_checkpoints`).
- `mongodump` folders (`<db>/<coll>.bson` + `.metadata.json`, `prelude.json`).
- SQL Server `.bak` / `.trn`: the MTF header and `RESTORE HEADERONLY`
  fields (server version, database, backup type, LSNs, dates) without a server.
- These could be backup formats (`backup/`) with probe.backup, so
  `filecat backups` lists them alongside the others.

**An index of database and backup locations**
- A table (like the root index) of every recognised data folder and backup
  store: root, path, engine/format, instance key, last seen, last scan
  that saw it, so they can be listed without walking `kind = dir` records.
- Register locations from the servers' own configuration instead of
  waiting for a scan to find them: `postgresql.conf` `data_directory` and
  tablespaces, `my.ini` / `my.cnf` `datadir`, `mongod.cfg` `storage.dbPath`,
  SQL Server's registry (`HKLM\SOFTWARE\Microsoft\Microsoft SQL
  Server\<instance>\MSSQLServer` `DefaultData` / `DefaultLog` /
  `BackupDirectory`), and the Windows services' command lines (`-D`,
  `--datadir`, `--dbpath`). A registered folder outside the scanned roots
  would be reported as not covered.
- Per-engine overrides of the quiet age and minimum size
  (`[databases]` in filecat.toml) if the defaults turn out wrong.

**Also**
- `filecat enrich` hashes listed backup data (`probe.backup_data`, e.g. ABB
  pool chunks) when `--what` includes hash, since it has no
  `--measure-backups` check; it should skip them as it skips non-quiet
  database files.
- Show database folders in `filecat serve`.

## Backups and app stores to research

**Active Backup for Microsoft 365** (the share's
`ActiveBackupforBusinessO365` module)
- Seen at `\\nas-main\ActiveBackupforBusiness\ActiveBackupForMicrosoft365\task_1`,
  beside the Google Workspace task (`backup/abg.py`,
  docs/formats/synology-abg.md). The layout looks the same:
  - `@ActiveBackupOffice365-Databases/` has per-user folders named by
    GUID, plus `account`, `task-config`, `service-log` and per-service log
    databases, and extra `group`, `site`, `teams` databases;
  - user folders hold `Mail`, `Archive-Mail`, `Calendar`, `Contact` and
    `OneDrive`, next to `Groups/` and `Sites/`.
- Research: the item folder names and fragments (Exchange ids, not
  Gmail's), OneDrive's version repository, and the SharePoint site,
  Teams and group layouts. Then decide whether it is a second format in
  `abg.py` or a module of its own.
- Write the format into docs/formats as was done for Google Workspace, and
  give it the same default check (databases against the listing) and
  `--verify-backups` (sizes and MD5s from the metadata).

**Mylio** (photo library app)
- Seen at `\\nas-vm\CloudSync\Onedrive\Apps\Mylio\<40 hex>_Uv2\<3 hex>\`:
  - `t_<hash>_<hash>_v<n>.jpg`: thumbnails or previews (`_v0`, `_v13`);
  - `b_<hash>_<hash>.myb`: Mylio's own format;
  - `r_<hash>_<hash>.<ext>` (e.g. `.MOV`): probably the original media.

  This is Mylio's cloud vault, synced to OneDrive and copied into
  `CloudSync`. Tens of thousands of files and tens of GB.
- Research:
  - what the `t`/`b`/`r` prefixes and the two hashes are (a content hash?
    the original's?);
  - what `.myb` holds (metadata, edits, a catalog?);
  - whether the vault has an index naming the original files;
  - where the library catalog lives on a Mylio device (`Mylio.mylodb` /
    `Mylio Main Library` folders).
- Then decide:
  - whether the vault is a store, so thumbnails and `.myb` files are
    listed only and originals measured;
  - whether originals can be tied back to their names, so they show as
    duplicates of the same photos elsewhere.

## Appliance details from .ovf / .ova

Record what a VM appliance is, so the catalog can list appliances by
publisher, name, version and date instead of just "tar, 3 members".

**Where the data is**

- `.ova` is a tar (OVF standard, DMTF DSP0243) whose first member is the
  `.ovf` descriptor, followed by the disks (`.vmdk`, `.vhd`, ...), a `.mf`
  manifest of SHA checksums, and optionally a `.cert` signature. The tar
  probe already lists these members. The `.ovf` is usually a few KB,
  starting at byte 512, so reading it costs one more small read.
- `.ovf` on its own is the same XML descriptor, from an export left
  unpacked as a folder next to its disks.

**Fields to pull** (from `Envelope/VirtualSystem`, or each system of a
`VirtualSystemCollection`)

| field | OVF source |
|---|---|
| publisher | `ProductSection/Vendor` (+ `VendorUrl`); the `.cert` signer when signed |
| name | `ProductSection/Product`, else `VirtualSystem/Name`, else `ovf:id` |
| version | `ProductSection/Version` and `FullVersion` |
| product URL | `ProductSection/ProductUrl`, `AppUrl` |
| description | `AnnotationSection/Annotation` (shortened) |
| guest OS | `OperatingSystemSection` `ovf:osType` / `ovf:id` and `Description` |
| hardware | CPUs and memory from `VirtualHardwareSection`; `vssd:VirtualSystemType` (e.g. `vmx-11`, `virtualbox-2.2`) |
| disks | `DiskSection/Disk` capacity, format and file per disk |
| exported by | `vbox:` / `vmw:` extension elements when present (VirtualBox or VMware version) |

**Publish date:** OVF has no date field. Use, in order:
1. the `.cert` signing time, when present;
2. the mtime of the `.ovf` member inside the `.ova` (the export time);
3. the file's own mtime.

Record which of these was used.

**Shape:** store the fields as `probe.appliance = {publisher, name,
version, full_version, product_url, os, cpus, memory_mb, disks: [...],
date, date_source, systems}` on the `.ova` or `.ovf` record, so `summary`
and the web viewer can list and filter appliances. Archive members stay
as they are.

**Notes**
- Parse with the stdlib XML parser and refuse DTDs and entities, since
  descriptors come from untrusted downloads. Match elements by local name,
  because namespace prefixes differ between OVF 1.x and 2.x exporters.
- A descriptor that fails to parse is an `errors` entry on the record, not
  a scan failure.
- Existing records need `filecat enrich --what probe --force` (or a
  narrower re-probe) to pick this up, since rescans skip unchanged files.
- Test fixtures: a small hand-written `.ovf`, plus a `.ova` tarred from it
  together with a dummy disk.
- Real examples already in the catalog: `Juniper JunOS Olive12.1R1.9
  Virtualbox image.ova` on `\\nas-vm\home` and `GNS3 VM.ova` on
  `\\nas-vm\ISOs`.
