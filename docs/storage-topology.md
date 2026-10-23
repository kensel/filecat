# Storage topology

One generic description of how a host's storage is built, from its physical
disks up to the shares, LUNs and VM disks that hold the files filecat
catalogs. Synology is the first implementation; Windows, Proxmox and
TrueNAS are derivatives of the same layout, not new layouts. The code is
`src/filecat/topology.py`; the wire form is the `storage_topology` command of
[agent-protocol.md](agent-protocol.md); the inputs are notes
[03](research/03-synology-vmm-san-luns.md) and
[04](research/04-web-viewer-storage-hierarchy.md). Nothing here is stored yet
(section 7 is the proposal to review).

## 1. The hierarchy

```text
host (computer name)
 +- disk ......... physical disks, an inventory (role and slot per assignment)
 +- pool ......... SHR / RAID group / ZFS pool / Storage Space / LVM VG
     +- group .... optional: md array, ZFS vdev (the redundancy unit between disks and pool)
     +- volume ... volumeN / ZFS dataset / NTFS or ReFS volume / LV with a file system
         +- share  SMB or NFS share: a folder on the volume, and the catalog root for it
         +- lun .. iSCSI LUN, ZFS zvol, raw LV: a block device exported or consumed
         +- vdisk  VM disk, or an unattached image-library template
```

A response is one `host` plus a flat list of `nodes`. Seven node types,
`disk group pool volume share lun vdisk`; every node has `id`, `type`,
`name`, `parent` (or null), optional `health`/`detail`, capacity fields, and
a `platform` object.

Two things are optional levels, not platform special cases:

- **Groups.** Synology has md arrays, ZFS has vdevs, Storage Spaces and a
  plain LVM VG have neither. A pool without groups lists its disks in its own
  `members`. Nothing else changes.
- **Pools.** A basic Windows disk with an NTFS volume has no pool: the volume
  has `parent: null` and lists the disk in its `members`. A pool can sit in a
  pool (an LVM thin pool inside its volume group), and a volume in a volume (a
  ZFS child dataset), so those layers nest instead of needing new types.

### Disks are an inventory, `members` are the edges

`parent` is containment and forms a tree: group in pool, volume in pool or
volume, share in volume, lun/vdisk in a volume or a pool. Disks are *not* in
that tree. SHR slices one disk into several md arrays, a ZFS spare may serve
two pools, and the role belongs to the assignment, not the disk. So a group,
pool or volume lists `members: [{"disk": "<disk id>", "role": "data"}]`, and
a disk has no `parent`. The viewer draws disks first (the order of the
hierarchy above) by following `members` from the pool down; a disk that is in
no `members` is shown as unassigned.

Roles: `data parity spare log cache special dedup boot`. On a group, `role`
says what the group is for (a ZFS `logs` vdev has role `log`) and its members
repeat it; on a pool without groups it is per member. `parity` is for
platforms that name parity disks (ZFS and md do not, so their members are
`data`).

### Node fields

| Field | On | Meaning |
|---|---|---|
| `id`, `type`, `name`, `parent` | all | see section 2 for ids; `parent` is an id or null |
| `health` | all | `ok warning degraded failed unknown`; the native word goes in `detail` or `platform` |
| `detail` | all | one human line ("Reallocated sectors: 8") |
| `size_bytes` | all but share | disk: raw; group/pool/volume: usable; lun/vdisk: **logical**, as provisioned |
| `raw_bytes` | group, pool | before redundancy (5 x 16 TB in a 4 x 16 TB SHR) |
| `used_bytes` | volume, pool, share | in use; for a share, what filecat or the platform measured |
| `free_bytes` | volume, pool | available to a user (`statvfs` `f_bavail`, ZFS `avail`) |
| `allocated_bytes` | lun, vdisk, pool | **physical** bytes behind it (`st_blocks * 512`); pool: handed out to children |
| `thin` | pool, lun, vdisk | sparse or thin provisioned; false for thick; absent when unknown |
| `level` | group, pool | `raid5 raid1 shr mirror raidz2 single zfs` ... lowercase, normalized; the native name is in `platform` |
| `role`, `members` | group, pool, volume | above |
| `kind` | lun, pool, vdisk | lun: `iscsi zvol lv file`; pool: `lvm_thin` ...; free text |
| `mount`, `fs_type`, `device` | volume | `/volume1`, `btrfs`, `/dev/mapper/cachedev_0`; a ZFS dataset's `device` is `tank/media` |
| `path` | share, lun, vdisk | share: the folder on the host; lun/vdisk: the backing file or directory |
| `unc` | share | the catalog root the share's records use, `\\nas-main\Backup` |
| `protocols` | share | `smb`, `nfs` |
| `vm` | vdisk | `{"id", "name"}` of the VM it is attached to (absent for a template) |
| `attached` | vdisk | false for an image-library template or an orphaned disk |
| `guest_server` | lun, vdisk | the UNC server (`\\nas-vm`) whose own shares live inside this disk |
| `serial`, `model`, `slot`, `media` | disk | `media` is `hdd ssd nvme` |
| `platform` | all | namespaced extras, `{"synology": {...}}`; section 3 |

Allocated versus logical: `size_bytes` is what the consumer was promised,
`allocated_bytes` what it costs below. The gap is the thin-provisioning
saving; for a thick LUN they are equal. For a volume, `used_bytes` plus
`free_bytes` is `size_bytes` (a reserve may make the sum smaller, never
larger). Unknown is absent, never 0. Clients keep unknown fields (a newer
agent may add them without a protocol bump) and the validator only rejects
what it can check: types, enumerations, links.

### `platform`

An object keyed by platform name so a node can be read without knowing which
agent wrote it, and a host that is two things (TrueNAS on Proxmox) never
collides:

```json
"platform": {"synology": {"devtype": 5, "lid": 3, "kind": "BLUN", "extent_files": 2}}
```

Rules: nothing the viewer or ShareMap needs for the generic drill-down may
live only there; anything native (md device names, `vg1/volume_1`, SMART
attributes, ZFS guid and `ashift`, `devtype`) may. Values are plain JSON.

## 2. Ids

An id is `<type>:<platform-native key>`, a string, unique in the response
and stable across rescans. The global key is `(host, id)`, with host the
lowercased `host.name`. Array positions, `md2`, `sdb`, `volume1` and
`/dev/sataN` are **not** keys: they renumber when a disk is replaced or a
volume is deleted. They are fields (`name`, `mount`, `slot`, `platform`).

| Node | Key | Fallback when the key is unreadable |
|---|---|---|
| disk | serial number (`disk:ZR5A1B2C`) | WWN, then `by-path`; agent marks `platform.<p>.id_unstable: true` |
| group | the array UUID (md) or the vdev guid (ZFS) | pool key + member serials, hashed |
| pool | VG UUID (LVM), pool guid (ZFS), `UniqueId` (Storage Spaces), md UUID when no LVM | none; skip the node and report it |
| volume | file system UUID (`blkid`), dataset guid (ZFS), volume GUID path (Windows) | pool key + mount point |
| share | lowercased SMB name, else the NFS export path (`share:backup`) | none needed: a share is its name |
| lun | LUN UUID (Synology `iscsi_lun.conf`), zvol guid, LV UUID | backing path |
| vdisk | vdisk/image UUID (Synology), zvol guid / `vmid-disk-N` (Proxmox) | backing path |

Renaming a share is a new node; that is right, because the catalog root
changes with it. A replaced disk is a new `disk` node and its group's
`members` change, so a history diff (section 7) shows the swap.

## 3. Platform mappings

"Source" is where the agent (or, for Windows, a PowerShell helper) reads
it. Those marked *verify* are from memory or the draft and need checking on
a device before the agent relies on them.

### Synology (first implementation)

| Node | From | Notes |
|---|---|---|
| disk | `/sys/block/sata*`, `nvme*`; SMART identify for serial/model; DSM slot from the device name | `platform.synology.device = /dev/sataN`; *verify* where DSM keeps the slot and health (`synodisk`, `/run/synostorage`) |
| group | `/proc/mdstat`, `mdadm --detail` or `/sys/block/mdX/md` | `level` raid1/raid5/raid6/raid10; `[UUU_]` gives `degraded`; SHR with unequal disks gives several groups (md2, md3, ...) in one pool |
| pool | LVM VG over the md arrays (`/etc/lvm/backup/vgN`, `vgs`); no LVM: the md array itself | `level: shr` when the arrays are an SHR layout, else the md level; name "Storage Pool 1" is not stable, so it is a field |
| volume | `/proc/mounts` lines under `/volumeN`; `statvfs`; `blkid` | `device` is `/dev/mapper/cachedev_0` when SSD cache is on; `vg1/volume_1` in `platform` |
| share | share definitions (`/usr/syno/etc/synoshare.conf` or `smb.conf`, *verify*), not every top-level folder | skip `@*`, `#*`; `unc = \\<host>\<name>`; `path = /volumeN/<name>` |
| lun | `iscsi_lun.conf` stanzas, `devtype` 5 (BLUN, thin) and 11 (BLUN_THICK) | `kind: iscsi`; `thin` = devtype 5; `size_bytes` = `bytes=`; `allocated_bytes` = sum of `st_blocks * 512` in the UUID directory (never `st_size`: the 512 GiB `ROD` sparse file); `path` = `@iSCSI/LUN/BLUN[_THICK]/<uuid>` |
| vdisk | `devtype` 7 (VDISK_BLUN); `name=vdisk.<vm>.<vdisk>.<bus>.<unit>` attached, `name=image.<image>.<vol>...` template | attached: `vm` from `@Repository/<vm_uuid>/vguest.conf`, `attached: true`; image: `attached: false`, no `vm`; vCPU, RAM, `is_meta_disk`, `is_general_vm` go in `platform.synology` |
| `guest_server` | not known on the NAS (section 5) | |

NAS-MAIN is the fixture `tests/data/synology_nas_main.json`: five disks in
one `md2` RAID 5 group (SHR) of one pool; `volume1` (btrfs) and `volume2`
(ext4) in it; four SMB shares on `volume1`; LUN-3 (thin, 11.0 TiB allocated,
guest `\\nas-zfs`), LUN-2 (thick), LUN-7 (thin); the NAS-VM disk (guest
`\\nas-vm`) and an Image Library template (`attached: false`) that note 03
lists as a cleanup target. NAS-OLD (`synology_nas_old.json`) is two disks, one
RAID 1 array, one volume.

### TrueNAS (fixture `tests/data/truenas_tank.json`)

| Node | Source | Notes |
|---|---|---|
| disk | `zpool status -P` plus `lsblk`/`smartctl` | serial key; `media` from rotation |
| group | `zpool status -P` / `zpool list -v -p`: each top-level vdev | `role` data/log/cache/spare/special/dedup straight from the vdev class; `level` mirror/raidz1..3/draid/single |
| pool | `zpool list -p`, `zpool get guid` | `size_bytes`, `allocated_bytes`, `free_bytes`; `ashift`, fragmentation in `platform` |
| volume | `zfs list -p -t filesystem` | a dataset; `parent` is the parent dataset or the pool; `mount`, `device = tank/media` |
| share | `midclt call sharing.smb.query` / `sharing.nfs.query`, or `smb.conf` and `/etc/exports` | `path` is the dataset mount or a folder in it |
| lun | `zfs list -p -t volume` (zvol), `iscsi.extent.query`, targets | `kind: zvol`, `thin` from `refreservation`; the iSCSI target/extent is in `platform.truenas` (no second node for the extent) |

The vdev layer is needed here and is an ordinary `group`. Cache and spare
vdevs hold no data; they are groups with their own `role` and contribute no
`size_bytes` to the pool.

### Proxmox

| Node | Source | Notes |
|---|---|---|
| disk | `lsblk -J`, `smartctl` | |
| group | `zpool status -P` (ZFS); `mdadm`; Ceph OSDs are optional groups | |
| pool | `pvesm status` storages: ZFS pool, LVM VG, LVM-thin (a pool in the VG pool, `kind: lvm_thin`, `thin: true`), directory | Ceph pool: `kind: ceph`, members empty (OSDs live on other hosts) |
| volume | directory storage / mount with a file system; ZFS dataset | `/var/lib/vz` is a volume holding qcow2 files |
| lun | LVs and zvols without a file system | `kind: lv` or `zvol` |
| vdisk | `qm config <vmid>` disk lines (`scsi0: local-zfs:vm-101-disk-0`), `pvesm list <storage>`; qcow2/raw files | `vm = {"id": 101, "name": ...}`; `guest_server` from the guest's name; `attached: false` for unused disks and ISO/template images |

A vdisk is one of the three things: a file (qcow2) in a volume, an LV in a
thin pool, a zvol in a pool; its `parent` says which, and `path` the file or
device.

### Windows

| Node | Source | Notes |
|---|---|---|
| disk | `Get-PhysicalDisk` (SerialNumber, Usage -> role: `AutoSelect`/`HotSpare`/`Journal`), `Get-Disk` | `slot` from `PhysicalLocation` |
| group | none for Storage Spaces (the virtual disk's `NumberOfColumns` and `ResiliencySettingName` go on the pool or volume `level`); dynamic-disk mirrors/RAID 5 are groups | optional layer, usually absent |
| pool | `Get-StoragePool` (UniqueId) | `level` from the virtual disk's resiliency (`simple mirror parity`) |
| volume | `Get-Volume` (ObjectId); `Get-VirtualDisk` -> pool; plain NTFS/ReFS on a basic disk has no pool | `mount` `D:\`, `fs_type` ntfs/refs; a Space's virtual disk is a lun, with a volume on it |
| share | `Get-SmbShare` (Name, Path) | `path` is `D:\Data`; share_entries ignores non-POSIX paths, so a Windows agent needs its own path mapping (`to_catalog_path` for drive letters) before ShareMap is wired in. Windows shares already scan by UNC without an agent |
| vdisk | Hyper-V `Get-VMHardDiskDrive`, `Get-VHD` (`FileSize` vs `Size`) | `kind` vhdx, `thin` from `VhdType` |

Where a platform cannot say something (a `Get-StoragePool` has no physical
usage per volume) the field is absent. No platform needs a node type or a
parent rule the seven types do not have.

## 4. Shares and path mapping

A share node knows two names for one folder: `path` (`/volume1/Backup`) on
the host, and `unc` (`\\nas-main\Backup`) as the catalog root. That is
exactly what `ShareMap(alias, shares, volume)` needs, so
`topology.share_entries(topology, alias=None)` returns `{posix prefix: unc root}`
for every share on a POSIX path that is exported over SMB (or has an
explicit `unc`). The UNC root is the share's `unc`; without one it is
`<server>\<name>` with the `[[agents]]` alias if given, else
`host.unc_server`. Two shares with one path, or one name, keep the first.

Wiring (not done; `ShareMap` is untouched):

1. `AgentClient.storage_topology()` returns the parsed `Topology`
   (`from_response`) instead of a raw list. A reply without `topology` (an
   older agent) gives an empty result, not an error.
2. When a scan or `agents test` opens an agent, it asks for the topology
   once, ignores failure, and builds the map:
   `ShareMap(alias, merge_share_maps(share_entries(topo, alias), cfg.shares), cfg.volume)`.
3. **Config wins.** `merge_share_maps` drops a derived entry whose POSIX
   prefix *or* UNC root (case-insensitively) a configured entry also has, so
   a hand-written `[agents.shares]` can rename or repoint a share, and
   `ShareMap`'s "listed twice" check cannot fire between the two sources.
   Derived entries are exact, so they beat the Synology
   `/volumeN/<share>` guess, which stays as the fallback for paths the
   topology does not list.
4. The derived map is not stored with the config; it is rebuilt per run, so a
   renamed share follows the NAS without a config edit. Records keep the UNC
   root, so a stale map can only mis-name new files, never old records.

## 5. Links to the catalog

- **Roots.** A share's `unc` is a root as `roots` and `records` know it
  (`\\nas-main\Backup`). The viewer joins a share to its root by that string,
  compared case-insensitively like `aliases.py`. A share with no scanned
  root shows as "not cataloged".
- **Guests.** A `lun` or `vdisk` with `guest_server: "\\nas-vm"` says that
  server's own shares live inside this disk; the guest has its own topology
  document (host `nas-vm`) and its own roots. The upward link is *derived*:
  find the lun/vdisk, in any host's document, whose `guest_server` is this
  host's `unc_server`. No `parent_storage` is stored on the guest, so the two
  never disagree. This also gives the "net physical" total of note 04: skip
  a guest's pool bytes when its host is a `guest_server` of another.
- **Who fills `guest_server`.** The agent cannot: it knows the VM's name
  (`NAS-VM`), not the UNC server. The central side links them with
  `topology.link_guests(topo, {vm name or node id: unc server})` from
  a config table (`[storage.guests]`, proposed) and, as a hint, a VM name
  that matches an `[[agents]]` alias or a catalog server name case-
  insensitively. An agent may set it when it knows (a LUN's initiator is a
  known host).

## 6. Totals

`capacity_summary(topo)` returns disk, pool, volume (size/used/free), share,
and block-storage (provisioned vs allocated) totals, each node counted once
(nested pools and datasets are not added twice). `subtree_sum(topo, id, field,
*types)` sums under any node, e.g. the bytes in LUNs and VM disks on
`volume1`. For NAS-MAIN, volume used minus share used is the hidden block
storage of note 03: shares 29.7 TB, LUNs and VM disks the rest.

## 7. Storage in the catalog (proposal)

**One document per host snapshot**, in a `storage_topology` store (replacing
note 04's per-volume `storage_pools` document, whose pool/volume/LUN/VM lists
are all nodes here):

```json
{"_id": "nas-main", "host": "nas-main", "platform": "synology",
 "scanned_at": "...", "agent": {"version": "...", "protocol": 1},
 "topology": { ...the response... },
 "unc_roots": ["\\\\nas-main\\Backup", ...],
 "guest_servers": ["\\\\nas-vm", "\\\\nas-zfs"],
 "structure_hash": "<sha256 of the nodes without usage fields>"}
```

Plus a `storage_topology_history` store with one row `(host, scanned_at, ...)`
written only when `structure_hash` changes, or when used bytes moved by more
than a threshold (to be decided), so the history stays small.

Why not a document per node:

- A topology is small (tens, at most a few hundred nodes) and always read
  whole: the drill-down pool -> volume -> share, the capacity bars, and the
  hierarchy are all one host's tree. One read, no joins, and the backends
  without joins (JSONL, SQLite JSON column, MongoDB) store it the same way.
- A scan replaces a snapshot atomically. Per-node documents need
  upserts plus deletes of vanished nodes, and a reader can see half a scan:
  a volume whose pool is not written yet.
- History and diff are trivial on whole snapshots: compare two `nodes`
  lists by id (added/removed/changed disk, a group that went `degraded`,
  usage growth per volume). With per-node rows, history is per-node
  versioning plus reassembly.
- The cross-host queries are few, and covered by the denormalized
  `unc_roots` and `guest_servers` arrays (indexed): share -> root, root ->
  host, guest -> parent host. Anything else (search by disk serial) scans a
  few dozen documents.

The cost is that a very large host (hundreds of shares, a thousand VM disks)
makes a big document and a whole-document rewrite on each scan; at filecat's
scale that is kilobytes, and a hundred-fold margin is still under the
MongoDB 16 MiB limit. If it ever bites, shares are the node type to split
into their own store, since they are already keyed by root.

## 8. Open questions

1. Disks as an inventory with `members` edges (this design) versus disks as
   the top of the tree. The inventory handles SHR and shared spares; the cost
   is that "disk -> pool" is a join the viewer does.
2. `guest_server`: a `[storage.guests]` config table, name matching, or both.
3. History: keep every changed structure forever, or a fixed number per host;
   what usage movement counts as a change.
4. Windows: its agent (if any) needs drive-letter path mapping before shares
   derive; until then Windows hosts stay on SMB scans.
5. Replace `storage_pools` (note 04) outright, as proposed here, or keep that
   name for the store.
