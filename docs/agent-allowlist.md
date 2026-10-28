# filecat-agent: the command allowlist and native capabilities (for review)

**Status: to review before the Rust agent is built.** This page lists everything
`filecat-agent` is allowed to do beyond listing, stat, hashing, reading
ranges and summing subtrees: the commands `run` may start, the files Python
reads through `read_file`, the native libraries the agent links, and what was
considered and left out. The wire side is in [agent-protocol.md](agent-protocol.md)
(`run`, `read_file`, `statfs`, `capabilities`, `wmi`); the consumer is the
collectors in `src/filecat/topology_collect/` ([storage-topology.md](storage-topology.md)).

## 0. The principle

The agent stays a minimal primitive engine controlled by the central Python
server: scan (list and stat), read and hash, total a subtree, and the
primitives below. All rules, detections and parsing live in Python, so a new
rule, format or platform never needs an agent rebuild. Because a root
process that runs commands is exactly what an attacker wants, the commands are
a **hardcoded allowlist compiled into the binary**:

- A request names an entry by `id`. The agent builds the command from the
  entry: absolute candidate paths for the binary, a fixed argument vector.
- No shell, no globbing, no environment expansion, no argument text from
  the network. The one exception is an entry that declares an **argument
  kind**; its request carries one `arg`, which the agent validates itself
  against live host state (`btrfs_mount`: a path `/proc/self/mountinfo`
  lists at that moment as a btrfs mount). Anything else is `refused`.
- Environment `LC_ALL=C`, `LANG=C`, `PATH=/usr/sbin:/usr/bin:/sbin:/bin`;
  stdin `/dev/null`; stdout and stderr capped; a timeout per entry; at most
  two at once.
- Read-only. No entry mounts, repairs, scrubs, snapshots, imports, exports,
  sets a property or writes a file. Every entry below was checked against
  that; it is also the review question for a new one.
- Output is parsed in Python, in C locale, in machine formats (`-J`, `-H -p`,
  `--json`, `--raw`, `-b`). Never human-readable output (`-h`).

How an entry looks in the compiled table (Rust, for the review of the
shape; the content is the rest of this page):

```rust
struct Entry {
    id: &'static str,                 // "lsblk_json"
    candidates: &'static [&'static str], // absolute paths, tried in order
    args: &'static [&'static str],    // the whole argument vector, fixed
    arg_kind: Option<ArgKind>,        // BtrfsMount, BlockDevice, MdDevice, ZfsPool
    timeout_s: u64,                   // 20 unless it says otherwise
    version: Option<&'static [&'static str]>, // a fixed --version vector, for `capabilities`
}
```

`capabilities` returns, per entry, whether a candidate exists and runs, the
binary used, and the version where the entry declares a probe. The table's
hash is returned as `allowlist_sha256` so an audit can tell which table a
given agent build carries.

**Status labels.** `v0.2.0`: needed by the Synology collector or a generic
Linux basic that the first release ships. `v0.2.0 optional`: cheap, safe,
not needed by the Synology collector; include it if the build is easy.
`later`: designed so the review sees the shape, built when that platform's
collector is. Candidate directories: **std** = `/bin`, `/sbin`, `/usr/bin`,
`/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`; **syno** adds
`/usr/syno/bin`, `/usr/syno/sbin`. Platforms: **DSM** (Synology DSM 7),
**TN** (TrueNAS SCALE), **PVE** (Proxmox VE), **Linux** (any other), **Win**.

## 1. Summary

| Category | Entries | v0.2.0 | v0.2.0 optional | later |
|---|---|---|---|---|
| Block devices | 4 | 4 | 0 | 0 |
| Mounts | 1 | 1 | 0 | 0 |
| Btrfs | 2 | 0 | 2 | 0 |
| ZFS | 8 | 0 | 0 | 8 |
| RAID (md) | 2 | 1 | 0 | 1 |
| LVM | 6 | 0 | 0 | 6 |
| SMART | 5 | 4 | 0 | 1 |
| Proxmox | 5 | 0 | 0 | 5 |
| Synology | 2 | 0 | 0 | 2 |
| iSCSI initiator | 1 | 0 | 0 | 1 |
| TrueNAS middleware | 5 | 0 | 0 | 5 |
| Windows WMI (`wmi`) | 19 | 0 | 0 | 19 |
| **Total** | **60** | **10** | **2** | **48** |

The Windows agent has its own labels, *needed* 13, *optional* 4, *later* 2
(section 13); to the Linux release they are all `later`.

Plus, with no command at all: `read_file` of `/proc`, `/sys` and configuration
files (section 14), `statfs`, `list_dir` of `/sys/block`, `/dev/disk/by-id`
and similar, all within the agent's read scope (section 14a).

**What DSM can use** (checked on nas3, DSM 7, where `which` finds only
`/sbin/blkid`, `/sbin/mdadm`, `/bin/smartctl` and `/sbin/btrfs`): of the
v0.2.0 entries, `mdadm_detail_scan`, `blkid_export`, `smartctl_version`,
`smartctl_info` (smartmontools 6.5: no `--json`) and the optional
`btrfs_show` and `btrfs_usage`. **Not on DSM: `lsblk_json`,
`lsblk_json_legacy`, `lsblk_pairs`, `findmnt_json`** (they are for the generic
Linux collector). The Synology collector needs none of the four; it reads
`/proc/mounts`, `/sys/block` and DSM's own `/etc/space/space_history_*.xml`
(section 14), and runs only `mdadm_detail_scan` (the array UUIDs) and, for a
disk the space history does not name, `smartctl_version` and `smartctl_info`.
Its `smartctl_info_json` and `_sat` are for DSM releases with smartmontools 7.

## 2. Block devices

### `lsblk_json` (v0.2.0)

- Binaries: std.
- Arguments: `-J -b -o NAME,KNAME,PKNAME,MAJ:MIN,TYPE,FSTYPE,SIZE,ROTA,STATE,MODEL,SERIAL,WWN,MOUNTPOINTS`
- Argument kind: none.
- Needs: util-linux 2.27 for `-J`, 2.37 for the `MOUNTPOINTS` column (an older
  `lsblk` refuses the unknown column and exits non-zero). Falls back to
  `lsblk_json_legacy`, then `lsblk_pairs`; below all that, `/sys/block` and
  `/dev/disk/by-id` through `read_file` and `list_dir`.
- Platforms: Linux, TN, PVE. **Not on DSM** (checked on nas3: no `lsblk`; the
  Synology collector reads `/sys/block` and the space history).
- Purpose: the disk inventory and partition tree. Feeds `disk` nodes
  (`serial`, `model`, `size_bytes`, `media` from `ROTA`, `match: naa:` from
  `WWN`), the disk-to-volume link (`KNAME`, `PKNAME`, `MOUNTPOINTS`,
  `FSTYPE`).
- Output notes: with `-b`, sizes are bytes; versions before 2.37 print the
  numbers and `ROTA` as strings (`"1"`), later ones as numbers and booleans;
  Python accepts both.

### `lsblk_json_legacy` (v0.2.0)

- Binaries: std.
- Arguments: `-J -b -o NAME,KNAME,PKNAME,MAJ:MIN,TYPE,FSTYPE,SIZE,ROTA,STATE,MODEL,SERIAL,WWN,MOUNTPOINT`
- Argument kind: none.
- Needs: util-linux 2.27 to 2.36 (the singular `MOUNTPOINT`). Same fallbacks.
- Platforms: Linux, TN, PVE (Debian 10/11 era, Ubuntu 20.04).
- Purpose: as above where `MOUNTPOINTS` is missing.

### `lsblk_pairs` (v0.2.0)

- Binaries: std.
- Arguments: `-P -b -o NAME,KNAME,PKNAME,MAJ:MIN,TYPE,FSTYPE,SIZE,ROTA,MODEL,SERIAL,WWN,MOUNTPOINT`
- Argument kind: none.
- Needs: any util-linux with `-P` (one `KEY="value"` line per device;
  2.19 and later); no `STATE` (added later than `-P`).
- Platforms: Linux with an old util-linux, appliances with a stripped `lsblk`.
- Purpose: the non-JSON fallback for builds without `-J`. Parsed by a small
  quoted-pair reader in Python.

### `blkid_export` (v0.2.0)

- Binaries: std.
- Arguments: `-c /dev/null -o export` (no cache file, key=value output, one
  block per device separated by an empty line: `DEVNAME=`, `UUID=`,
  `UUID_SUB=`, `TYPE=`, `LABEL=`, `PARTUUID=`, `USAGE=`).
- Argument kind: none.
- Needs: `-o export` is util-linux (2.20 and later, the same output as the
  older `-o udev`) and e2fsprogs' `blkid`; *verify on the first host of each
  platform that `export` is accepted, else the entry's vector becomes
  `-o udev`*. Needs root to probe devices. Falls back to `/dev/disk/by-uuid`
  (`list_dir` shows each link's `link_target`) and `/sys/fs/btrfs/<uuid>`.
- Platforms: Linux, TN, PVE; DSM has `/sbin/blkid` (the Synology collector
  prefers `/sys/fs/btrfs` and `/dev/disk/by-uuid`, and asks `blkid` last).
- Purpose: file system UUIDs, the stable key of a `volume` node; `TYPE` for
  `fs_type`; `LABEL`.

## 3. Mounts

### `findmnt_json` (v0.2.0)

- Binaries: std.
- Arguments: `--json -b -o TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,FSROOT,UUID,LABEL`
  (`-b` has no effect with these columns; it keeps a future `SIZE` column in
  bytes).
- Argument kind: none.
- Needs: util-linux 2.27. Fallback, always available: `read_file`
  `/proc/self/mountinfo` (the better source: it has the major:minor and root of
  bind mounts and subvolumes) and `/proc/mounts`.
- Platforms: Linux, TN, PVE. **Not on DSM** (no `findmnt`; the Synology
  collector reads `/proc/mounts`).
- Purpose: mount point, source device, file system type, options (`ro`/`rw`
  gives a volume's `health`), UUID and label in one pass. Feeds `volume`
  `mount`, `device`, `fs_type`, `health`.
- **`df -T -B1` is not an entry.** `statfs` gives the same totals
  without a parser and without a process; see section 15.

## 4. Btrfs

### `btrfs_show` (v0.2.0 optional)

- Binaries: std.
- Arguments: `filesystem show --raw` (`--raw` prints sizes in bytes;
  `btrfs-filesystem(8)` lists it for `show`; *verify the flag on the oldest
  btrfs-progs in use: DSM 7 ships an old one*).
- Argument kind: none.
- Needs: btrfs-progs with `--raw` on `show`. Fallback: `/sys/fs/btrfs/<uuid>/`
  (`label`, `devices/` by `list_dir`, `allocation/*`) and `read_file` of the
  device size files.
- Platforms: DSM, Linux, PVE (a local btrfs storage). Not TN: its pools are ZFS.
- Purpose: label, UUID, member devices with size and used per device.
  Feeds `volume` `id` (UUID) and the disk-to-volume `members`.

### `btrfs_usage` (v0.2.0 optional)

- Binaries: std.
- Arguments: `filesystem usage -b` and then the validated argument.
- Argument kind: **`btrfs_mount`**: an absolute path that the agent finds,
  at that moment, in `/proc/self/mountinfo` as a mount point with file system
  type `btrfs`; anything else is `refused`. The check is the point: a
  request cannot make the agent run `btrfs` on an arbitrary path.
- Needs: btrfs-progs 3.18 or later (`usage`), `-b`/`--raw`. Fallback:
  `statfs` for the totals and `/sys/fs/btrfs/<uuid>/allocation/{data,metadata,system}/{total_bytes,bytes_used,disk_total}`
  for chunk allocation.
- Platforms: DSM, Linux, PVE.
- Purpose: allocated versus unallocated space, data/metadata profile
  (`single`, `DUP`, `RAID1`), the free-space estimate. Feeds `volume`
  `platform.btrfs` and `free_bytes` cross-checks. Not needed for the
  nas3 snapshot.

## 5. ZFS

All eight are `later` (TrueNAS and Proxmox collectors). Binaries:
`zpool` and `zfs` in std (`/usr/sbin`, `/sbin`, `/usr/local/sbin`). Argument
kind: none. Platforms: TN, PVE, Linux with ZFS.

### `zpool_list`

- Arguments: `list -H -p -v` (`-H` tab-separated, no header; `-p` exact numbers;
  `-v` the vdev tree, children indented by a leading tab).
- Needs: `-p` on `zpool list` (OpenZFS 0.7 and later; *verify*).
- Feeds: `pool` `size_bytes`, `allocated_bytes`, `free_bytes`, fragmentation,
  `health`; per-vdev sizes of `group` nodes.

### `zpool_status`

- Arguments: `status -P -p` (`-P` full device paths, `-p` exact numbers in the
  scan and error lines).
- Needs: `-P` any; `-p` on `status` is newer (*verify*); without it the entry's
  alternative is the same vector minus `-p`, which the agent would carry as a
  second id if the first host needs it.
- Feeds: the vdev layout (mirror, raidz1/2/3, draid), the **role** of each
  top-level vdev (the `logs`, `cache`, `spares`, `special`, `dedup` sections of
  the output), per-disk state, scan (scrub/resilver) state. `group`,
  `members` and `disk.health`.

### `zfs_list`

- Arguments: `list -H -p -t filesystem,volume -o name,type,used,avail,refer,volsize,refreservation,mountpoint,guid`
- Needs: any. Changed from the proposal (`-t all`): snapshots can number in the
  tens of thousands and are not topology; `refreservation` added because a
  zvol is thin when it is 0 or `none`.
- Feeds: `volume` (dataset) and `lun` (zvol, `kind: zvol`, `thin`) nodes,
  `used_bytes`, `free_bytes`, `size_bytes` (`volsize`), `mount`, the guid in
  the id.

### `zpool_get`

- Arguments: `get -H -p all` (tab-separated `name property value source`).
- Needs: any. Feeds: pool `guid` (the pool id), `ashift`, `health`,
  `capacity`, `fragmentation`, `autotrim`, `feature@*`.

### `zpool_list_json`, `zpool_status_json`, `zfs_list_json`, `zpool_get_json`

- Arguments: `list -j --json-int -v`; `status -j --json-int -P`;
  `list -j --json-int -t filesystem,volume -o name,type,used,avail,refer,volsize,refreservation,mountpoint,guid`;
  `get -j --json-int all`.
- Needs: **OpenZFS 2.3** or later (the `-j` / `--json` output). *Verify which
  releases ship it and the exact flags on the first host*: the expectation is
  that current TrueNAS SCALE (25.04 and later) and Proxmox VE 9 carry 2.3,
  while Proxmox VE 8 and TrueNAS SCALE 24.10 carry 2.2 and need the text
  entries. `capabilities` shows the version; Python picks JSON when it can.
- Feeds: the same nodes as the text entries, without a column parser.

## 6. RAID (md)

### `mdadm_detail_scan` (v0.2.0)

- Binaries: std (`/sbin/mdadm`, `/usr/sbin/mdadm`).
- Arguments: `--detail --scan` (one `ARRAY /dev/md2 metadata=1.2 name=nas3:2 UUID=...`
  line per active array).
- Argument kind: none.
- Needs: mdadm, any version. Fallback: none that gives the UUID (`/proc/mdstat`
  and `/sys/block/md*/md/` do not carry it); Python then keys the group by
  pool key plus member serials, hashed (the id table in
  [storage-topology.md](storage-topology.md)), and notes it.
- Platforms: DSM (md0 system, md1 swap, md2... data), Linux, PVE, TN (boot
  mirror).
- Purpose: the array UUID, the stable key of a `group` node.

### `mdadm_detail` (later)

- Binaries: std. Arguments: `--detail` and then the validated argument.
- Argument kind: **`md_device`**: `/dev/mdN` where `mdN` is listed in `/proc/mdstat`.
- Needs: mdadm. Purpose: per-member state and role (`active sync`, `spare`,
  `faulty`), event count, rebuild progress. Feeds disk `health` and `role`
  (`spare`). The sysfs files of section 14 give most of this without a
  process, so this is a cross-check.

## 7. LVM

All six are `later` (Proxmox; Synology volumes are read from
`/etc/lvm/backup/vgN`, a file, because DSM's old lvm2 may not have JSON
reports). Binaries: `pvs`, `vgs`, `lvs` in std. Argument kind: none. Platforms:
PVE, Linux, DSM (if its lvm2 is new enough; *verify*).

### `lvm_pvs`, `lvm_vgs`, `lvm_lvs`

- Arguments: `--reportformat json --units b --nosuffix -o <fixed columns>`,
  with these columns:
  - `pvs`: `pv_name,pv_uuid,vg_name,pv_size,pv_free,pv_attr`
  - `vgs`: `vg_name,vg_uuid,vg_size,vg_free,vg_extent_size,pv_count,lv_count,vg_attr`
  - `lvs`: `lv_name,lv_uuid,vg_name,lv_size,lv_attr,lv_path,lv_dm_path,pool_lv,segtype,data_percent,metadata_percent,devices`
- Needs: lvm2 2.02.158 for `--reportformat json`. Fallbacks:
  `lvm_pvs_sep`, `lvm_vgs_sep`, `lvm_lvs_sep`, the same columns with
  `--noheadings --separator | --units b --nosuffix` (three more ids, so six).
- Feeds: `pool` (VG, `pool_lv` thin pools as nested `pool` nodes,
  `kind: lvm_thin`), `volume`/`lun` from LVs (a file system or not), the
  PV-to-disk `members`. Sizes in bytes.

## 8. SMART

Binaries: `smartctl` in std and syno (`/bin/smartctl` on DSM, smartmontools
6.5 on DSM 7: no `--json`). Platforms: all Linux. Argument kind
**`block_device`**: `/dev/<name>` where `<name>` is a whole disk listed in
`/sys/block` (not a partition, not `loop*` or `ram*`), no other form; the
check reads the directory at the moment of the request. Exit status is a bit
mask (bit 3 and up mean a disk problem), not failure: the reply is `ok: true`
with `exit_code`, and Python reads both.

### `smartctl_version` (v0.2.0)

- Arguments: `--version`. Argument kind: none. Timeout 5 seconds.
- Purpose: the version, asked **once per host** by the collector
  (`smartctl 6.5 2016-05-07 r4318 [x86_64-linux-4.4.302+] (local build)`;
  Python reads the first two numbers). Below 7.0 the collector goes straight
  to `smartctl_info` instead of spending two JSON runs per disk on a binary
  that does not know `--json`. Unavailable or unreadable: the collector
  tries the JSON forms first, as before. (`capabilities` also reports a
  `version` for an entry with a probe, but one number per entry is not enough
  to choose between forms, so this is an entry of its own.)

### `smartctl_info_json` (v0.2.0)

- Arguments: `--json -i` and the argument.
- Needs: smartmontools 7.0 for `--json`; **DSM 7 ships 6.5, which has none**
  (checked on nas3). Fallback `smartctl_info_json_sat`, then `smartctl_info`.
- Platforms: DSM, Linux, PVE, TN.
- Purpose: identity: `serial_number` (the id of a `disk` node), `model_name`,
  `rotation_rate` (0 = SSD), `wwn` (an `naa:` match), capacity.

### `smartctl_info_json_sat` (v0.2.0)

- Arguments: `--json -d sat -i` and the argument.
- Needs: as above.

### `smartctl_info` (v0.2.0)

- Arguments: `-i` and the argument. The plain-text form (`Serial Number:
  ZR6N3A01`), parsed in Python: what smartmontools below 7.0 (DSM 7) uses.
  Whether a DSM disk needs `-d sat` here is not known yet (the DSM collector
  takes serials from the space history and `syno_disk_serial` first, so it
  rarely gets here).

### `smartctl_all_json` (later)

- Arguments: `--json -a` and the argument.
- Needs: smartmontools 7.0.
- Purpose: the overall health verdict, attributes (reallocated and pending
  sectors, wear), temperature, self-test log. Feeds disk `health` and
  `detail` ("Reallocated sectors: 8"). Exit status again a mask.

## 9. Proxmox VE

All `later`. Platforms: PVE only. Binaries: `pvesh`, `pvesm`, `qm`, `pvecm` in
`/usr/bin` and `/usr/sbin`.

| id | Arguments | Purpose and fields |
|---|---|---|
| `pvesh_cluster_status` | `get /cluster/status --output-format json` | cluster name, node list, quorum: `host.cluster`, `host.kind` |
| `pvesh_cluster_resources` | `get /cluster/resources --output-format json` | every VM, storage and node in one JSON: `vm` nodes (`vm:<vmid>`), `pvesm` storages with sizes |
| `pvesm_status` | `status` | text table of storages (type, status, total, used, avail in KiB): redundant with `pvesh_cluster_resources`; fallback for a PVE without it |
| `qm_list` | `list` | text table of VMs (vmid, name, status, memory, boot disk): fallback |
| `pvecm_status` | `status` | quorum and membership text: fallback |

None takes an argument. `pvesh` is allowed only with those two fixed paths: it
is a generic API client and the whole argument vector is the review item.
Most Proxmox topology comes from files (`/etc/pve/storage.cfg`, the VM
configs, `/etc/pve/.vmlist`, `/etc/pve/.members`), which need no command.

## 10. Synology tools

Both `later`, **arguments not committed**: the Synology collector reads files
and sysfs, and these are only to be added if the files turn out not to carry
something (the disk slot and SMART summary DSM shows in Storage Manager; the
SAN Manager target-to-LUN mapping). Binaries: syno. Platforms: DSM.

| id | Arguments | Purpose |
|---|---|---|
| `synodisk_enum` | *to verify on DSM* (`--enum -t internal` is the expectation) | internal disk list with slot and device |
| `synoiscsiep` | *to verify on DSM* | iSCSI endpoint (target, LUN, session) listing |

`synostgvolume` and `synospace` were considered and left out: they have
sub-commands that change state (volume creation, repair), and a fixed read-only
vector of them has not been verified.

## 11. iSCSI initiator

### `iscsiadm_session` (later)

- Binaries: `/sbin/iscsiadm`, `/usr/sbin/iscsiadm`, `/usr/bin/iscsiadm`.
- Arguments: `-m session -P 3` (sessions with target, portal, state and the
  attached disks with their `/dev/sdX`).
- Argument kind: none. Needs: open-iscsi.
- Platforms: PVE, Linux initiators, TN (as an initiator).
- Purpose: which LUN of which target a host sees, as which device: the link
  from a Synology `lun` to a Proxmox `disk` (`match: naa:` and the portal).
  Cheaper sources, no command: `/sys/class/iscsi_session/session*/{targetname,state}`,
  `/sys/class/iscsi_connection/connection*/persistent_address`,
  `/dev/disk/by-path/ip-*-iscsi-*-lun-*` (`list_dir`), and
  `/etc/iscsi/initiatorname.iscsi` for the host IQN.

## 12. TrueNAS middleware (optional, later)

Binary: `/usr/bin/midclt` (std). Each entry is `call <method>` with the method
fixed; none takes an argument. These return JSON that Python reads; they are
here because TrueNAS keeps shares and iSCSI extents in its database, and
reading the generated `smb4.conf`, `/etc/exports` and `scst`/`ctld` files is
the alternative. Platforms: TN. All read-only queries.

| id | Arguments |
|---|---|
| `midclt_pool_query` | `call pool.query` |
| `midclt_smb_shares` | `call sharing.smb.query` |
| `midclt_nfs_shares` | `call sharing.nfs.query` |
| `midclt_iscsi_extents` | `call iscsi.extent.query` |
| `midclt_iscsi_targets` | `call iscsi.target.query` |

Review question: `midclt` is a generic client of the middleware's API
(including calls that change the system). Allowlisted as a fixed vector it
cannot be made to call another method; the alternative is to drop these five
and read the generated configuration files.

## 13. Windows: `wmi {id}`

**Decision: a Windows agent is wanted**, to catalog a Windows file server
(shares, volumes, disks, Storage Spaces, and the iSCSI LUNs from nas3 that
back them). A Windows agent has no `run`: it answers `wmi` from the Rust `wmi`
crate (COM, read-only `SELECT` of a fixed property list from one class).
Nothing is written yet on the collector side; this section and the plan in
[storage-topology.md](storage-topology.md) ("Windows file server collector")
are the design.

Namespaces: **S** = `root\Microsoft\Windows\Storage`, **SMB** =
`root\Microsoft\Windows\SMB`, **C** = `root\cimv2`, **DFS** =
`root\Microsoft\Windows\DFSN`, **DD** = `root\Microsoft\Windows\Deduplication`.
Status: **needed** (the file-server collector cannot do without it),
**optional** (a fallback or extra detail, cheap), **later** (a feature not
planned for the first collector). Property names are WMI's; the lists are the
exact `SELECT` lists the agent compiles in, kept short on purpose (every
property is a column the server parses). Association class names and the
`DedupMode` / `FileSystem` properties are *to verify on a Windows Server
2019/2022 host*; a class missing from a namespace is reported by
`capabilities` as `available: false`, never an error.

| id | Status | Namespace and class | Properties | Why |
|---|---|---|---|---|
| `os_info` | needed | C `Win32_OperatingSystem` | CSName, Caption, Version, BuildNumber, LastBootUpTime | `host.name` (the machine name the catalog roots use) and `host.os` ("Windows Server 2022 10.0.20348") |
| `smb_share` | needed | SMB `MSFT_SmbShare` | Name, Path, Description, ScopeName, Special, Temporary, ShareState, ShareType, FolderEnumerationMode, CachingMode, ContinuouslyAvailable, EncryptData | the `share` nodes: the folder behind each name, with `ScopeName` (a clustered file server has one scope per role; `*` is the node itself) and `Special` (`ADMIN$`, `C$`, `IPC$`: skipped) |
| `win32_share` | needed | C `Win32_Share` | Name, Path, Type, Description | the same shares where the SMB namespace is missing, and `Type` (0 disk, 1 print queue, 2 device, 3 IPC, with 0x80000000 set for the administrative ones) to tell a folder share from a printer or `IPC$`; both are read and merged by name |
| `storage_volume` | needed | S `MSFT_Volume` | ObjectId, UniqueId, DriveLetter, FileSystem, FileSystemLabel, Size, SizeRemaining, HealthStatus, OperationalStatus, Path, DedupMode | the `volume` nodes: `mount` (`D:\` or the volume GUID path), `fs_type` (ntfs, refs), size and free space, health; `DedupMode` says whether Data Deduplication is on without the DD namespace |
| `storage_partition` | needed | S `MSFT_Partition` | DiskNumber, PartitionNumber, DriveLetter, Size, Offset, AccessPaths, Type, Guid, IsBoot, IsSystem | the join from a disk to a volume: `AccessPaths` holds the volume GUID path (`\\?\Volume{...}\`) that `MSFT_Volume.Path` has, and the drive letter |
| `storage_disk` | needed | S `MSFT_Disk` | Number, UniqueId, Guid, SerialNumber, Model, FriendlyName, Size, PartitionStyle, IsBoot, IsSystem, IsOffline, BusType, Location, Path | the disk the OS sees: `Number` (joins partitions), `UniqueId` (for an iSCSI disk this is its NAA identifier, the `naa:` match that links it to a nas3 LUN), `BusType` (iSCSI, SATA, SAS, Spaces: tells a physical disk from a LUN or a virtual disk) |
| `storage_physical_disk` | needed | S `MSFT_PhysicalDisk` | ObjectId, DeviceId, UniqueId, FriendlyName, SerialNumber, Model, Size, AllocatedSize, MediaType, BusType, HealthStatus, OperationalStatus, Usage, PhysicalLocation, SlotNumber, SpindleSpeed, CanPool | the `disk` nodes: serial (the id), model, `media` from `MediaType`/`SpindleSpeed`, `health`, bay from `SlotNumber`/`PhysicalLocation`, role from `Usage` (`AutoSelect`, `HotSpare`, `Journal`); `DeviceId` is the disk number, so it joins `MSFT_Disk` |
| `storage_pool` | needed | S `MSFT_StoragePool` | UniqueId, FriendlyName, Size, AllocatedSize, HealthStatus, OperationalStatus, IsPrimordial, IsReadOnly, ResiliencySettingNameDefault | the `pool` nodes (Storage Spaces); the primordial pool is not one |
| `storage_pool_to_physical_disk` | needed | S `MSFT_StoragePoolToPhysicalDisk` (association) | StoragePool, PhysicalDisk (references) | which physical disk is in which pool: pool `members` |
| `storage_virtual_disk` | needed | S `MSFT_VirtualDisk` | ObjectId, UniqueId, FriendlyName, Size, FootprintOnPool, ResiliencySettingName, NumberOfColumns, NumberOfDataCopies, PhysicalDiskRedundancy, ProvisioningType, HealthStatus, OperationalStatus | a Space: a `lun`-like node under its pool (`Size` logical, `FootprintOnPool` physical, `ProvisioningType` thin or fixed) and the pool's `level` (`simple`, `mirror`, `parity`; with `NumberOfDataCopies` / `PhysicalDiskRedundancy` for two-way versus three-way) |
| `storage_virtual_disk_to_disk` | needed | S `MSFT_VirtualDiskToDisk` (association) | VirtualDisk, Disk (references) | which `MSFT_Disk` is a Space, hence which volume is on it (name *to verify*) |
| `iscsi_session` | needed | S `MSFT_iSCSISession` | SessionIdentifier, TargetNodeAddress, InitiatorNodeAddress, InitiatorPortalAddress, IsConnected, IsPersistent | the iSCSI sessions of this file server to nas3: which target IQN each iSCSI disk comes from, so a Windows disk links to the Synology LUN behind it (with the disk's NAA id, `storage_disk.UniqueId`) |
| `initiator_port` | needed | S `MSFT_InitiatorPort` | NodeAddress, ConnectionType | `host.iqn`: the initiator IQN a nas3 LUN's ACL names (`initiator_ok` on the link) |
| `win32_volume` | optional | C `Win32_Volume` | DeviceID, DriveLetter, Name, FileSystem, Capacity, FreeSpace, Label, DriveType, BootVolume, SystemVolume | the `volume` nodes where `MSFT_Volume` is missing (Windows Server 2008 R2), and volumes mounted in a folder (`Name` is that path) |
| `iscsi_target` | optional | S `MSFT_iSCSITarget` | NodeAddress, IsConnected, IsPersistent | targets known to the initiator, connected or not (a persistent target that is down) |
| `iscsi_target_portal` | optional | S `MSFT_iSCSITargetPortal` | TargetPortalAddress, TargetPortalPortNumber, InitiatorInstanceName | the portal (nas3's address) of each target |
| `dedup_volume` | optional | DD `MSFT_DedupVolume` | Volume, VolumeId, Enabled, UsageType, Capacity, FreeSpace, UsedSpace, UnoptimizedSize, SavedSpace, SavingsRate, InPolicyFilesCount, OptimizedFilesCount | what Data Deduplication saves on a volume: a volume's `used_bytes` is the optimized size, not the sum of the files, which matters when the catalog's byte totals are compared with the volume's |
| `dfs_namespace` | later | DFS `MSFT_DFSNamespace` | Path, Type, State, Description, TimeToLiveSec | DFS namespaces hosted here (`\\domain\ns`): a catalog root may be a DFS path rather than a server share |
| `dfs_folder` | later | DFS `MSFT_DFSNamespaceFolder` (and `MSFT_DFSNamespaceFolderTarget` for the target paths; names *to verify*) | Path, State, Description, TimeToLiveSec | a namespace folder and the server shares it points at: the mapping from a DFS path to `\\server\share` |

Join keys, so the Python side needs no other query: share `Path` to volume
by drive letter or GUID path prefix (longest match); volume to partition by
`AccessPaths`; partition to disk by `DiskNumber`; disk to physical disk by
`DeviceId`; physical disk to pool by the association; disk to Space by
`MSFT_VirtualDiskToDisk`; iSCSI disk to nas3 LUN by the NAA id in
`UniqueId` against `lun.match`.

Windows needs its own path mapping for drive letters before shares derive a
`ShareMap` ([storage-topology.md](storage-topology.md) section 4); that is
part of the collector, not of the agent.

Read scope on Windows (section 14a, and the deny list in
[agent-protocol.md](agent-protocol.md)): the default allowed roots are every
**local fixed volume except the system volume** (`GetLogicalDrives` +
`GetDriveType` = `DRIVE_FIXED`, evaluated at each request), plus the paths of
every disk share (`Win32_Share` type 0, not special) even when it lies on the
system volume. A file server's data is almost never on `C:`; set
`FILECAT_AGENT_ALLOW_ROOTS` (`;` separated) in production to exactly the
volumes and folders to be cataloged. `wmi` is not affected by the roots: it
reads no files.

## 14. Files read with `read_file` (no command needed)

`read_file {path, max}` reads a file to its end up to `max` bytes (default
256 KiB, at most 4 MiB), which is what `/proc` and `/sys` need because they
report size 0. `list_dir` lists the directories. Nothing here needs an
allowlist entry. Every path below is inside the **default allowed roots** of
section 14a for its platform.

| Platform | Path | Read for | Status |
|---|---|---|---|
| Linux | `/proc/mounts`, `/proc/self/mountinfo` | mounts, bind mounts, subvolumes, `ro`/`rw` | v0.2.0 |
| Linux | `/proc/mdstat` | md arrays, members, `[UUU_]`, failed `(F)`, resync | v0.2.0 |
| Linux | `/sys/block/*/size`, `queue/rotational`, `removable`, `device/{model,vendor,serial,wwid}`, `<name>p<N>/size` (`<name><N>` for `sdX`) | disks and their partitions; `list_dir` of `/sys/block` shows each entry's link target (a `tcm_loop` device is not a disk) | v0.2.0 |
| Linux | `/sys/block/md*/md/{level,array_state,degraded,sync_action,sync_completed,raid_disks,metadata_version,chunk_size}`, `md/dev-*/{state,slot,size,errors}` | array level, state, member state and role | v0.2.0 |
| Linux | `/sys/block/dm-*/dm/{name,uuid}`, `slaves/` (list) | device-mapper chain (cachedev, LV, md) | v0.2.0 |
| Linux | `/sys/fs/btrfs/<uuid>/{label,devices/,allocation/*}` | btrfs UUID, label, members, allocation | v0.2.0 |
| Linux | `/dev/disk/by-uuid`, `by-id`, `by-path` (`list_dir`; the link target is in the entry) | UUID and WWN/serial to device; iSCSI by-path | v0.2.0 |
| Linux | `/etc/hostname`, `/etc/os-release`, `/etc/exports` | host, OS, NFS shares | v0.2.0 |
| Linux | `/proc/diskstats`, `/sys/block/*/stat` | I/O counters (telemetry) | later, not v0.2.0 |
| Linux | `/sys/class/iscsi_session/**`, `/etc/iscsi/initiatorname.iscsi` | initiator sessions and IQN | later |
| DSM | `/etc/VERSION` | DSM version (`productversion`) | v0.2.0 |
| DSM | `/etc/space/space_history_<YYYYMMDD_HHMMSS>.xml` (many; the newest by the stamp in the name is the current layout; `list_dir` of `/etc/space`) | DSM's own view of the pools: md arrays with RAID level, member partitions with disk model, serial, slot and bay (`physical_location`), the volumes, and the SSD cache spaces (`reference="@shared_cache"`), which name the volume they cache | v0.2.0 |
| DSM | `/sys/block/<dev>/device/syno_disk_serial` | a disk's serial when the space history does not name the disk (`device/serial` does not exist on DSM) | v0.2.0 |
| DSM | `/etc/lvm/backup/vgN` | VG UUID, PVs, LVs, extent size | v0.2.0 |
| DSM | `/usr/syno/etc/iscsi_lun.conf`, `iscsi_lun_acl.conf` | LUNs and VMM vdisks (`uuid`, `name`, `lid`, `bytes`, `devtype`, `vpd_unit_serial`, `rootpath`, `description`, `pre_alloc`) and each LUN's ACL (`initiator`, `lun_uuid`, `authority`): the host-wide union; `rootpath` is the volume holding the LUN | v0.2.0 |
| DSM | `<volume>/@iSCSI/LUN/iscsi_lun.conf`, `iscsi_lun_acl.conf` | only that volume's LUNs; read when the `/usr/syno/etc` files cannot be, and compared with them | v0.2.0 |
| DSM | `/usr/syno/etc/iscsi_target.conf`, `iscsi_mapping.conf` | targets (`tid`, `name`, `iqn`, `enabled`) and which LUN each maps (`tid`, `uuid`, `lun`). **The target file holds CHAP credentials** (`username`, `password`, `mutual_username`, `mutual_password`); they cross the wire in the file and are dropped in Python at once, never stored | v0.2.0 |
| DSM | `<volume>/@Repository/<vm>/{vguest.conf,vdisk.conf}` | VMM guests and their disks | v0.2.0 |
| DSM | `/etc/samba/smb.conf` | SMB share names and paths (confirmed on nas3; `/usr/syno/etc/smb.conf` does not exist) | v0.2.0 |
| DSM | `/etc/synoinfo.conf` | model, disk count | later |
| PVE | `/etc/pve/storage.cfg` | storages, `shared`, node lists, iSCSI/LVM/ZFS definitions | later |
| PVE | `/etc/pve/qemu-server/*.conf`, `/etc/pve/lxc/*.conf` | VMs and their disk lines | later |
| PVE | `/etc/pve/.vmlist`, `/etc/pve/.members`, `/etc/pve/corosync.conf` | VM placement, cluster nodes | later |
| TN | `/etc/smb4.conf`, `/etc/exports`, `/etc/scst.conf` or `ctl.conf` (*verify*) | shares and iSCSI extents without `midclt` | later |

DSM disks are named `sataN` on nas3 and `sdX` on NAS2 (an older model, ext4
volumes, partitions `sde5` without the `p`); the collector takes both, and
never `iscsiN`, `loopN`, `ramN`, `zramN`, `mtdblockN`, `dm-N`, `mdN` or
`synoboot`.

## 14a. The read scope: allowed roots and a deny list

**Decision (review question 4): yes.** Which files the agent will serve is
configured **on the agent host** and cannot be changed over the network, and a
hardcoded deny list sits above it. The rules are in
[agent-protocol.md](agent-protocol.md) ("Allowed roots and the deny list");
this is the part the allowlist review needs.

- `FILECAT_AGENT_ALLOW_ROOTS`: a path list (`:` on POSIX, `;` on Windows) in
  the environment, or the same key in the `.env` file next to the agent
  binary; the environment wins. Unset: a built-in default per OS.
- Applies to every command that takes a path: `read_file`, `read_range`,
  `measure` (content), `list_dir`, `sum_subtree`, `statfs` (names, sizes,
  totals). One check at the front of the dispatcher is cheaper to review than
  a per-command list, and listing `/home` is a leak too.
- **Default on DSM** (derived from every path the collectors and StoreFS
  read; `tests/test_synology_space.py` runs the nas3 collection through the
  fake agent with exactly this list and demands that nothing is refused):

      /volume*  /proc  /sys  /dev/disk  /etc/samba  /etc/space  /etc/VERSION
      /etc/exports  /etc/lvm/backup  /usr/syno/etc/iscsi_*.conf

  `/volume*` carries the cataloged data (shares, `@iSCSI`, `@Repository`);
  the rest is topology metadata. Other Linux: the metadata paths of the table
  above (`/proc`, `/sys`, `/dev/disk`, `/etc/hostname`, `/etc/os-release`,
  `/etc/exports`) plus `/mnt`, `/srv`, `/media`; data elsewhere must be added.
  Windows: section 13.
- Not a boundary against root on the host (root edits the `.env`); it is a
  boundary against a compromised central server or a stolen token.

## 15. Native capabilities and crates

| Crate or API | Used for | Why this and not another |
|---|---|---|
| `nix` (or plain `libc`) | `statvfs` and `statfs` for `statfs`; `uname`; `statx` for `btime`; `O_NOFOLLOW` opens; process-group kill for `run` | a thin, audited wrapper over the syscalls; `libc` alone is acceptable (the draft already uses it) and is the smaller dependency; `nix` only if its safe signatures are wanted |
| `std::process::Command` | `run`: absolute path, `env_clear`, fixed args, piped stdout/stderr, no shell | the standard library is enough; no `duct` or `shell-words` is needed because nothing is ever tokenized |
| `wmi` (the `wmi` crate, Windows only) | `wmi {id}`: COM initialisation per thread, `SELECT` of fixed properties, values as variants | the maintained Rust binding to WMI; the alternative is calling PowerShell, which is a shell and is exactly what this design avoids |
| `serde`, `serde_json` | the NDJSON protocol | already in the draft |
| `sha2` | `measure` digests, `allowlist_sha256` | pure Rust, no C, reproduces `hashing.py` |
| `hmac` (with `sha2`) | the sticky-redaction HMAC of [rollups.md](rollups.md) | same stack as `sha2` |
| `subtle` (or a hand-written fixed-time compare) | the token comparison | constant-time compare is the whole purpose |
| `base64` | `data_b64`, `path_b64`, `name_b64` | already in the draft |
| `rustls`, `rustls-pemfile` | TLS 1.2+/1.3 server | pure Rust, no OpenSSL, builds static for musl (note 02) |
| `rcgen` | the self-signed certificate on first start | pure Rust; the fingerprint is pinned by the client |

No async runtime, no `reqwest`, no regex crate in the agent (the rollup
matcher is its own, with shared test vectors). Target builds stay static musl
for x86_64 and armv7 (note 02); `nix` and `wmi` add no C library.

## 16. Considered and rejected

- **`libzetta`, `libzfs` bindings.** They would give typed access to pools and
  datasets, but the parsing would then live in Rust (a new pool property or
  a vdev role needs an agent rebuild), the libraries are thin wrappers over
  the `zpool`/`zfs` command line anyway (libzetta shells out), and `libzfs`
  needs the C `libzfs`/`libnvpair` libraries at link time, which does not go
  with a static musl build. The allowlist's `zpool`/`zfs` entries with their
  machine-readable flags (`-H -p`, `-j` on OpenZFS 2.3) give the same data and
  Python parses them.
- **`cat`** (and `head`, `tail`, `grep`, `sed`, `awk`, `find`, `ls`, `stat`).
  `read_file`, `read_range`, `list_dir` and `statfs` do these without a
  process, a path argument or a parser in the agent.
- **Human-readable output (`-h`, `--human-readable`, `df -h`, `lsblk` without
  `-b`).** Rounded, locale-dependent units cannot be summed or compared. Every
  entry uses exact bytes (`-b`, `-p`, `--raw`, `--units b`) in the C locale.
- **`df -T -B1`.** Duplicates `statfs`, needs a column parser, and its file
  system type names vary by build.
- **A shell wrapper (`sh -c`, `bash -lc`) or PowerShell, in any entry.** The
  point of the design is that no text from anywhere is ever interpreted as a
  command line.
- **`udevadm info`, `lsscsi`, `hdparm -I`, `sg_inq`, `nvme id-ctrl`.** Their
  data (serial, WWN, model) is in `lsblk`, `smartctl -i` and sysfs; each added
  tool is another binary to keep a parser for.
- **`zdb`.** Reads on-disk structures; slow and its output is for debugging.
- **`btrfs` sub-commands other than `filesystem show` and `filesystem usage`.**
  `scrub status`, `device stats`, `subvolume list` are plausible later; every
  btrfs sub-command beside these is a state-changing one a typo could reach.
- **Free-form arguments of any kind, including a "path to inspect" for
  `lsblk` or `mdadm`.** Entries take fixed vectors or one validated kind.

## 17. Questions for the review

1. **Argument kinds.** Is the set `btrfs_mount`, `block_device`, `md_device`,
   `zfs_pool` the right size? `block_device` and `btrfs_mount` are used by
   the entries marked v0.2.0 and v0.2.0 optional; the other two only by `later`
   entries.
2. **`midclt`.** Keep the five fixed `call` vectors for TrueNAS, or read
   the generated configuration files only (section 12)?
3. **`pvesh`.** Allow the two fixed `get` paths of section 9, or only the
   files and the three text commands?
4. **`read_file` scope.** Decided: allowed roots from the agent host's
   environment or `.env`, and a hardcoded deny list (section 14a). Still
   open: the exact deny list (agent-protocol.md), and whether `.env.example`,
   `.env.sample` and `.env.template` should be readable (they are).
5. **`allowlist_sha256`.** Worth carrying (an audit aid, not a security
   boundary), or drop it?
6. **Windows.** Decided: a Windows agent with the `wmi` entries of section
   13, for a Windows file server. Open: confirm the association class names
   and the `DedupMode` / `FileSystem` properties on a Server 2019/2022 host,
   and the Windows default allowed roots (fixed volumes except the system
   volume, plus share paths).
7. **Synology tools** (`synodisk`, `synoiscsiep`): leave out unless the files
   prove insufficient (the recommendation), or specify them now?
8. **DSM facts.** Settled on nas3 and NAS2: the share file is
   `/etc/samba/smb.conf`; the iSCSI files are in `/usr/syno/etc` (targets,
   mapping, and the host-wide LUN list with `rootpath`); `lsblk` and
   `findmnt` are absent; smartmontools is 6.5; `/etc/space/space_history_*.xml`
   exists. Still open: whether a DSM disk needs `-d sat` for `smartctl -i`,
   which btrfs-progs flags are accepted, and the layout of ext4 LUN backing
   directories (`FILE`, `THIN`; NAS2).
