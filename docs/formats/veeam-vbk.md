# Veeam backup file format (`.vbm`, `.vbk`, `.vib`, `.vrb`)

What is known about the files Veeam Agent for Windows (and, by the same
storage engine, Veeam Backup & Replication) writes to a backup repository.
The goal is that a reader or explorer can be built without Veeam's
software. Veeam does not publish the format; a Veeam product manager has
said it is not public
(<https://forums.veeam.com/viewtopic.php?p=519709>).

filecat itself needs only part of this (`src/filecat/backup/veeam.py`). By
default it reads the job's `.vbm` and checks it against the folder listing.
With `scan --verify-backups` it also reads each backup file's header,
snapshot slots and metadata banks and checks their checksums. Everything
else here is for a future reader.

## Sources and confidence

Each statement carries one of these tags:

| tag | meaning |
|---|---|
| **[F]** | checked here, against the jobs listed under "Jobs examined" |
| **[D]** | from dissect.archive's VBK parser, and consistent with what was seen here |
| **[d]** | from dissect.archive only, not checked here |
| **[I]** | inferred from the data, not proven |
| **[?]** | unknown |

- dissect.archive 1.8 (Fox-IT), `dissect/archive/c_vbk.py` and `vbk.py`,
  AGPL-3.0-or-later: <https://github.com/fox-it/dissect.archive>. It reads
  full `.vbk` files (directory, files, LZ4 blocks) and leaves increments
  and encryption as TODO. It was used here as a map only. No code was
  copied, and every [F] statement was re-derived from the files. Where it
  disagrees with the files, this document says so.
- A data-recovery engineer's description of the same layout (header, two
  snapshot slots, metabanks):
  <https://community.veeam.com/discussion-boards-66/reverse-engineering-corrupted-vbk-files-insights-on-metabanks-snapshotslots-and-architectural-questions-for-veeam-r-d-14174>.

### Jobs examined [F]

Seven Veeam Agent for Windows jobs ("Job <HOST>") were examined, each
copied or moved from the share the agent wrote to (`\\nas-legacy\Backup`,
`\\192.0.2.141\Backup`) to `\\nas-old\Backup`.

| | |
|---|---|
| backup files | 105: 8 `.vbk`, 97 `.vib`, 2.7 TB in all; the largest is a 613 GB `.vbk` |
| storage format | `FormatVersion` 13, `SnapshotSlotFormat` 9, MD5 digests, 1 MiB blocks, LZ4, no encryption |
| sources | Windows 10 / 11 Pro desktops and laptops, one or two disks each, whole-machine (volume-level) backups |
| `.vbm` | `BackupMeta Version` 22 to 5140, `MetaSchemaVersion` 2 |

All 105 files were checked with filecat's verifier: header, both slots
and every metadata bank. On two of them, a full and an increment, the
directory, the `summary.xml` and `BackupComponents.xml` files and several
data blocks were read and decompressed, and their MD5 and CRC32C matched.

## 1. Conventions

- All integers are **little-endian** [F].
- The unit of metadata is the 4096-byte **page** [F].
- A **page reference** is an `int64`: the high 32 bits are a bank index,
  the low 32 bits a page within that bank; `-1` means none [F].
- Two checksums are used: **CRC-32C** (Castagnoli, reflected polynomial
  0x82F63B78, check value `crc32c(b"123456789") = 0xE3069283`) and plain
  CRC-32 (zlib) on older formats [F for CRC-32C, d for which formats use
  CRC-32].
- Times in the `.vbm` are `MM/DD/YYYY HH:MM:SS`. Attributes ending in
  `Utc` are UTC; the others are the writer's local time [F].

## 2. A job folder [F]

```
Job <HOST>/
    Job <HOST>.vbm                       XML manifest of the job (section 3)
    Job <HOST>2024-04-01T003011.vbk      full backup: a complete image of every disk
    Job <HOST>2024-04-02T003012.vib      forward increment: blocks changed since the previous point
    ...
```

- File names are `<job name><yyyy-mm-dd>T<hhmmss>.<ext>`, using the local
  time the point was started [F]. Backup & Replication puts a machine
  name and `D` before the stamp and a 4-hex-digit suffix after it
  (`srv01D2024-04-01T003011_8C1A.vbk`) [I].
- `.vbk` holds a full, `.vib` a forward increment, `.vrb` a reverse
  increment (B&R reverse-incremental chains) [I]. `.vlb`/`.vsb` hold
  transaction-log backups and are not described here [?].
- Forever-forward chains: when retention removes the oldest point, the
  first increment is merged into the `.vbk`, which keeps its name and
  creation date. The full's slot `Version` reached 3839 on one job
  (section 4.2) [I].
- One chain per job folder was seen. Folders with an "active full" have
  several `.vbk` files, each starting a chain [F].

## 3. The `.vbm` manifest [F]

UTF-8 XML without a declaration, rewritten after every job run. Its root
`CreationTimeUtc` is when it was written [I]. The parts a reader needs:

```xml
<BackupMeta Version="50" MetaSchemaVersion="2" CreationTimeUtc="04/17/2024 06:44:53">
  <Backup Id JobId JobName JobType="4000" SourceType="3" TargetType="0" BackupPlatform="6"
          DirPath="\\nas-legacy\Backup\Job DESKTOP-X" MetaFileName MetaVersion="49"
          CreationTime EncryptionState="0" ... />
  <BackupMetaInfo>
    <Hosts><Host Id Name="This server" Type="3" HostInstanceId /></Hosts>
    <Storages>
      <Storage Id BackupId HostId FilePath="\\nas-legacy\Backup\Job DESKTOP-X\Job DESKTOP-X2024-04-02T003012.vib"
               CreationTime CreationTimeUtc ModificationTime
               Stats="&lt;CBackupStats&gt;&lt;BackupSize&gt;10940370944&lt;/BackupSize&gt;
                      &lt;DataSize&gt;20640227380&lt;/DataSize&gt;&lt;DedupRatio&gt;99&lt;/DedupRatio&gt;
                      &lt;CompressRatio&gt;53&lt;/CompressRatio&gt;&lt;/CBackupStats&gt;"
               BlockSize="3" BlockAlignmentSize="4096" State="0" GfsPeriod="0" CreationMode="0"
               LinkId="<previous Storage Id>" PartialIncrement="False" ... />
    </Storages>
    <Points><Point Id LinkId="<previous Point Id>" Num="87" GroupId CreationTimeUtc Type="1" Algorithm="2" /></Points>
    <Oibs><OIB Id ObjectId PointId StorageId LinkId IsCorrupted="False" IsRecheckCorrupted="False"
               IsConsistent="True" Type="2" Algorithm="2" InsideDir="<HostId> (<object Uuid>)"
               CreationTimeUtc VmName="DESKTOP-X" ApproxSize="858093602816" GuestInfo="..." AuxData="..." /></Oibs>
    <Objects><Object Id Type="2" Name="DESKTOP-X" ObjectId="<BIOS UUID>" Uuid="<BIOS UUID>" Platform="6" /></Objects>
    ... empty: SqlOibs, OracleOibs, Keysets, RecoveryKeys, EncryptedOibs, ...
  </BackupMetaInfo>
</BackupMeta>
```

| field | meaning |
|---|---|
| `Backup DirPath`, `Storage FilePath` | where Veeam wrote the job, unchanged after the folder is moved; match files by base name [F] |
| `Backup MetaVersion` / root `Version` | update counter; `Version = MetaVersion + 1` [F] |
| `Backup JobType=4000`, `SourceType=3`, `BackupPlatform=6` | Veeam Agent backup job [I] (platform 6 = "EndPoint", the vendor name in `AuxData`) |
| `EncryptionState` | 0 = not encrypted [F]; other values untested [?] |
| `Storage Stats/BackupSize` | the backup file's size in bytes, equal to its length on disk [F, 87 of 91 files; see section 9] |
| `Storage Stats/DataSize` | bytes read from the source for this point [I] |
| `Storage Stats/DedupRatio`, `CompressRatio` | percent of the data left after dedup and after compression (100 = no saving) [I] |
| `Storage LinkId`, `Point LinkId` | the previous storage / point in the chain; absent on the full [F] |
| `Storage BlockSize=3` | `KbBlockSize1024` (1 MiB blocks); the name is in `summary.xml` [F] |
| `Storage State=0`, `GfsPeriod=0`, `CreationMode=0` | `Inactive`, `None`, `Normal` (names from `summary.xml`) [F] |
| `Point Type` | 0 full, 1 increment [F]; `Algorithm` 0 full, 2 forward increment [F], 1 presumably reverse [?] |
| `Point Num` | running restore-point number of the job, never reused [F] |
| `OIB IsCorrupted` | Veeam's verdict on the point. On the two corrupt points seen, the run had stopped (`BackupSize` and `DataSize` 0, `IsConsistent` False) while the file's own metadata was still valid [F] |
| `OIB IsRecheckCorrupted` | True on 4 points that were fine [?] |
| `OIB ApproxSize` | used bytes of the source machine (= `AuxData RealVmSize`) [I] |
| `OIB InsideDir` | the name of the backup file's root folder (section 6) [F] |
| `OIB GuestInfo` | escaped XML: OS name, IP, DNS name [F] |
| `OIB AuxData` | escaped XML `COibAuxData`: OS platform and version, `DesktopOibAuxData/OsName`, and per disk `<Disk FriendlyName Capacity BusType>` with GPT/MBR layout, partition ids and names, `MountPoint path`, `ValidProcessedOffset`, and a `DiskId` of `<JobId>:<ObjectId>:<disk id>:<OIB Id>` [F] |
| `Object Uuid` / `ObjectId` | the source's SMBIOS UUID (Dell ones start `4c4c4544`, "LLED") [F] |

Joining them: each `OIB` names one `Point`, one `Storage` (one backup
file) and one `Object` (the machine). With one machine per job, points,
storages and OIBs are one-to-one [F].

## 4. Backup file: header and snapshot slots

### 4.1 Storage header, page 0 [D][F]

| offset | type | field | seen |
|---|---|---|---|
| 0x000 | u32 | FormatVersion | 13 |
| 0x004 | u32 | Initialized | 1 |
| 0x008 | u32 | DigestTypeLength | 3 |
| 0x00C | char[251] | DigestType | `md5` |
| 0x107 | u32 | SnapshotSlotFormat | 9 (> 5 means slots use CRC-32C [D][F]) |
| 0x10B | u32 | StandardBlockSize | 1048576 |
| 0x10F | u8 | ClusterAlign | 3 |
| 0x120 | 16 bytes | ? | zero |
| 0x130 | 16 bytes | ExternalStorageId | zero |

The rest of the page is zero [F].

### 4.2 Snapshot slots [D][F]

There are two slots: slot 1 at offset 4096, slot 2 directly after it. A
slot's length is `round_up(124 + MaxBanks * 16, 4096)`; with
`MaxBanks = 0x7F00` that is 524288 bytes, so slot 2 is at 528384 [F]. For
an empty slot use `0xF8` banks if `SnapshotSlotFormat == 0`, else `0x7F00`
[d].

| slot offset | type | field |
|---|---|---|
| 0 | u32 | CRC over bytes `[4, 124 + MaxBanks*16)` of the slot: CRC-32C here [F] |
| 4 | u32 | ContainsSnapshot (1) |
| 8 | u64 | Version: a sequence number; the valid slot with the highest is active |
| 16 | u64 | StorageEOF: end of the file's used space |
| 24 | u32 | BanksCount |
| 28 | i64, u64 | DirectoryRoot: page of the root directory vector, entry count (1) |
| 44 | i64, u64, i64, i64, i64, i64 | BlocksStore: root page, count, free-blocks root, dedup root, ?, ? |
| 92 | i64 | CryptoStore root (-1: none) |
| 100 | u64, u64 | ? |
| 116 | u32, u32 | MaxBanks, StoredBanks |
| 124 | 16 bytes × MaxBanks | bank descriptors: u32 CRC, u64 file offset, u32 size |

- On every finished file here, both slots had the same Version and
  `StorageEOF` equal to the file size [F]. On a file the `.vbm` marks
  corrupt, `StorageEOF` was a little below the file size [F].
- A writer alternates slots, so one survives a crash mid-update [I].

### 4.3 Banks [D][F]

A bank is a run of metadata pages: one header page, then the data pages.
**Each slot has its own copy of every bank**, at a different offset with
the same CRC [F]. Bank sizes seen are 139264, 270336, 532480 and 1056768
bytes. The header page starts with `u16 PageCount, u16 Flags`, and the
bank size is `(PageCount + 2) * 4096` [F]; `Flags & 2` means encrypted
[d]. Data page `n` of a bank is at `offset + 4096 * (n + 1)` [F].

The bank descriptor's CRC is a CRC-32C of the whole bank (`size` bytes)
[F]. dissect uses CRC-32 for formats below 12 and for 0x10008 [d].

A 613 GB `.vbk` had 41 banks (138 MB of metadata, 0.023%); a 9.5 GB
`.vib` had 8 banks (3 MB) [F].

## 5. Metadata structures

### 5.1 Meta blob: a chain of pages [F]

Every page of a blob starts with a 12-byte header: `i64 next page` (-1 on
the last page) and an `i32`. On the first page the `i32` is the payload
length; on later pages it is 0. Each page carries 4084 bytes of payload.
(dissect skips only 12 bytes on the first page and keeps the headers of
later pages in the payload, so it misreads property blobs longer than one
page.)

### 5.2 Meta vector: a table of fixed-size entries

With `FormatVersion >= 12` (not 0x10008) a vector is a blob of page
references, the **page table**, plus the pages it lists. Data pages hold
`4096 // entry_size` entries packed from offset 0, with no header [F]. The
page table itself [F]:

- its pages are read as `int64` words in blob order;
- the pages come in **groups**. A group's first page holds `next` and then
  the page numbers of every page in its group, itself first; every later
  page of the group holds only `next`. All remaining words are references
  to data pages, in order;
- group sizes seen: 1, 3, 12, so the total is 1, 4, 16 pages (likely ×4 per
  group) [I]. On a 613 GB `.vbk` with 314 838 block descriptors the table
  was 16 pages.

This corrects dissect, which hard-codes the header lengths of the first
two groups (2, 4, 1, 1 words, then repeating) and so finds the wrong page
past about 2 000 data pages. That covers block descriptors on fulls larger
than about 130 GB.

Older formats use one plain blob with an 8-byte header per page and
entries after it [d].

### 5.3 Directory items: 192 bytes [D][F]

| offset | type | field |
|---|---|---|
| 0x00 | u32 | type: 1 folder, 2 external file, 3 internal file, 4 patch, 5 increment |
| 0x04 | u32 | name length |
| 0x08 | char[128] | name, UTF-8 |
| 0x88 | i64 | properties blob page (-1: none) |
| 0x90 | u32 | ? |
| 0x94 | 44 bytes | per type, below |

- Folder: `u64 root page, u32 count` of its own directory vector.
- Internal file (type 3): `u16 UpdateInProgress, u8 ?, u8 Format` (1),
  `u64 blocks-vector root, u64 count`, `u64 FibSize` (the file's size),
  `u64 Size` (all ones here).
- Increment (type 5): `u32 ?, u64 blocks-vector root, u64 count, u64
  FibSize` (the disk's size, = `AuxData Disk Capacity`), then `u64` equal to
  `count × block size` [F].

### 5.4 Properties [D][F]

A property blob's payload is a sequence of `i32 type, u32 name length,
name, value`, ending with type -1. Value types: 1 u32, 2 u64, 3 UTF-8
string, 4 UTF-16LE string, 5 binary (`u32 length` + bytes), 6 boolean
(u32) [d; types 5 and the end marker F].

`DefinedBlocksMask` (binary, on disk images and increments) is `u64 mask
length, u64 compressed length`, followed by a zlib stream of the mask:
one bit per block of the disk (61 069 bytes for a 512 GB disk = 488 552
bits for 488 374 blocks) [F]. A set bit is a block in use on the source
[I].

### 5.5 Block descriptors [D][F]

Each file's blocks vector is a vector of 24-byte table descriptors
(`i64 root page, u64 ?, u64 count`), each describing up to 1088 entries
[d]. The entries are `FibBlockDescriptorV7`, 46 bytes:
`u32 size, u8 type, u8[16] MD5, u64 block id, u8 flags, u8[16] key set id`.
Type 0 is a normal block, 1 sparse (zeros) [F for 0, d for 1]; 2
reserved, 3 archived, 4/5 block-in-blob [d].

The **blocks store** (slot `BlocksStore`) is a vector of
`StgBlockDescriptorV7`, 60 bytes [F]:

| offset | type | field |
|---|---|---|
| 0 | u8 | format (4) |
| 1 | u32 | usage counter (1 here) |
| 5 | u64 | file offset of the block |
| 13 | u32 | allocated bytes |
| 17 | u8 | dedup flag (1) |
| 18 | u8[16] | MD5 of the **decompressed** block, the same as the FIB entry's [F] |
| 34 | i8 | compression: 7 LZ4, -1 none [F]; 2 RL, 3 ZLH, 4 ZLL [d] |
| 35 | u8 | ? |
| 36 | u32 | compressed size |
| 40 | u32 | source size |
| 44 | u8[16] | key set id (zero) |

A FIB entry's `block id` is an index into the blocks store [F].

### 5.6 Data blocks [F]

At the descriptor's offset, `compressed size` bytes. An LZ4 block starts
with a 12-byte header, `u32 0xF800000F, u32 CRC-32C of the decompressed
data, u32 source size`, followed by a raw LZ4 block (no frame). dissect
says the CRC covers the compressed data, but here it covers the
decompressed data. Uncompressed blocks (type -1) are stored as they are;
the small XML files were.

## 6. What a backup file contains [F]

The root directory has one folder, named as the OIB's `InsideDir`:
`<JobTargetHostId> (<object Uuid>)`. In it:

| item | type | content |
|---|---|---|
| `summary.xml` | internal file | `<OibSummary>` with this point's `Backup`, `Point`, `Storage`, `OIB`, `Object`, `SourceHost`, `TargetHost`, `PlatformDetails`, `OibFiles`: the `.vbm` entries for this one file, with enum names spelled out (`BlockSize="KbBlockSize1024"`, `State="Inactive"`) |
| `BackupComponents.xml` | internal file | the VSS `BACKUP_COMPONENTS` document of the snapshot (writers, ASR disk layout) |
| `digest_<partition id>` | internal file, has properties | per-partition digests, 1–25 MB [?]; the ids are `AuxData` `PartitionId`s |
| `<disk id>` | internal file in a `.vbk`, increment in a `.vib` | the disk image. The id is `AuxData` `DriveLayout DiskId` (GPT disk GUID); `FibSize` is the disk's size |

So `summary.xml` makes each file self-describing: a lost `.vbm` can be
rebuilt from the backup files [I].

## 7. Reading a disk image

From a `.vbk` [F, block by block]:

1. Read the header (4.1) and both slots (4.2); take the valid slot with
   the highest Version.
2. `page(ref)` = bank `ref >> 32` from that slot's bank list, page
   `ref & 0xFFFFFFFF` (4.3).
3. Read the root directory vector (`DirectoryRoot`), then the one folder in
   it (5.2, 5.3).
4. For the disk item, open its blocks vector: the table descriptors, then
   the FIB entries (5.5). Entry `n` covers bytes
   `[n × block size, (n + 1) × block size)` of the disk.
5. For a normal entry, look up `block id` in the blocks store, read the
   block, LZ4-decompress it and check the MD5 or CRC-32C (5.6). A sparse
   entry is zeros.

From an increment [?]: its disk item lists `count` blocks, the ones
written in that run (17 117 blocks = 16.7 GiB on one `.vib`). How each
maps to a disk offset is not known yet; dissect leaves it as TODO.
Candidates are the table descriptors' second field and a per-increment
mask. A restore then starts from the `.vbk` and overlays each increment
of the chain in order [I].

## 8. Checking a job, cheapest first

| level | reads | finds |
|---|---|---|
| listing + `.vbm` (filecat default) | the `.vbm`, ~0.5 MB per job | missing files, size mismatches, points Veeam marked corrupt, broken chains, files the `.vbm` no longer lists |
| own metadata (`--verify-backups`) | header, both slots and the active slot's banks: ~0.02% of each file; 2.7 TB took 5 minutes here, most of it pure-Python CRC-32C | truncated files (`StorageEOF` > size), unusable slots, damaged metadata banks, and whether the other slot holds a good copy |
| `summary.xml` of each file | a few metadata pages and one small block per file | that each file belongs to the job and point the `.vbm` says |
| every data block | the whole file, plus LZ4 decompression | bad data blocks (CRC-32C / MD5 per block). Not implemented: it reads everything, and pure-Python LZ4 is slow |

## 9. What the examined jobs showed [F]

- 87 of 91 listed files had exactly the `BackupSize` the `.vbm` gives.
  Two were marked corrupt with `BackupSize` 0. One increment was 41 MB
  larger on disk than recorded, with consistent metadata. One increment
  was 6.5 GB on disk against 12.1 GB recorded, and 3 of its 7 metadata
  banks fail their CRC in both slots: the file is damaged.
- Two jobs had backup files on disk that the `.vbm` no longer lists: 2
  old increments in one, and in another a whole chain of 12 files (a
  `.vbk` and its increments) between two chains the `.vbm` does list. All
  of them have valid metadata. Veeam's restore wizard does not offer them,
  but they can be imported [I].

## 10. Not known yet

- encryption: `CryptoStore`, key sets, bank `Flags`, and `EncryptionState`
  values;
- how an increment's blocks map to disk offsets (section 7); reverse
  increments (`.vrb`); patch items (type 4);
- the free-blocks and dedup trees in `BlocksStore`;
- what is in the `digest_<partition>` files;
- formats other than 13, the pre-12 meta vector, and B&R per-machine
  chains (several `.vbm` or one `.vbm` with several objects);
- `IsRecheckCorrupted`.

## 11. Building an explorer

1. Parse the `.vbm` (section 3) to list jobs, chains and points; match
   files by base name.
2. For each file, check the slots and banks (4.2, 4.3) before trusting it.
3. Read a full's directory and disks (sections 5–7). Present each disk as
   a block device, then use a partition and NTFS reader on it (partition
   offsets are in `AuxData`).
4. For a point in a chain, overlay its increments once their block
   mapping is known.
5. Keep page and block caches. A disk image is a sparse table of 1 MiB
   blocks, so random reads cost one metadata lookup and one LZ4 block.
