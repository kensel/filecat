# Storage topology

One generic description of how a host's storage is built, from its physical
disks up to the shares, LUNs and VM disks that hold the files filecat
catalogs, and how hosts are built on each other (a LUN that is a VM's disk
that is another NAS's pool). Synology is the first implementation; Windows,
Proxmox and TrueNAS are derivatives of the same layout, not new layouts. The code is
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
 +- vm ........... a VM the host runs (hypervisors); its vdisks point to it
```

Between hosts, a `disk`, `lun` or `vdisk` links to the node on another host
that provides it (section 5).

A response is one `host` plus a flat list of `nodes`. Eight node types,
`disk group pool volume share lun vdisk vm`; every node has `id`, `type`,
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
| `vm` | vdisk | `{"id", "name"}` of the VM it is attached to: the id of a `vm` node (absent for a template) |
| `attached` | vdisk | false for an image-library template or an orphaned disk |
| `target`, `initiators` | lun | the iSCSI target name; the LUN's ACL, `[{"iqn", "authority", "default"?}]` (section 3, Synology) |
| `backing` | disk, lun, vdisk | `{"host", "id"}` of the node on another host that provides this one (section 5) |
| `match` | disk, lun, vdisk | `kind:value` identifiers to link nodes across hosts: `naa`, `uuid`, `serial`, `vmserial`, `volid`, `vmmdisk` |
| `virtual` | disk, lun, vdisk | something else provides it; a missing provider is then reported |
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

A `vm` node has `id`, `name`, `health` and `platform`; no parent, no capacity.
Host fields beyond `name`/`unc_server`/`os`: `kind: "cluster"` for a cluster
snapshot, `cluster: "<name>"` for a node that belongs to one, `iqn`/`iqns`
(the initiator names, used to check a LUN's ACL).

## 2. Ids

An id is `<type>:<platform-native key>`, a string, unique in the response
and stable across rescans. The global key is `(host, id)`, with host the
lowercased `host.name`. Array positions, `md2`, `sdb`, `volume1` and
`/dev/sataN` are **not** keys: they renumber when a disk is replaced or a
volume is deleted. They are fields (`name`, `mount`, `slot`, `platform`).

| Node | Key | Fallback when the key is unreadable |
|---|---|---|
| disk | serial number (`disk:ZR5A1B2C`); an iSCSI disk with none: its NAA id (`disk:naa.6001405...`) | WWN, then `by-path`; agent marks `platform.<p>.id_unstable: true` |
| group | the array UUID (md) or the vdev guid (ZFS) | pool key + member serials, hashed |
| pool | VG UUID (LVM), pool guid (ZFS), `UniqueId` (Storage Spaces), md UUID when no LVM | none; skip the node and report it |
| volume | file system UUID (`blkid`), dataset guid (ZFS), volume GUID path (Windows) | pool key + mount point |
| share | lowercased SMB name, else the NFS export path (`share:backup`) | none needed: a share is its name |
| lun | LUN UUID (Synology `iscsi_lun.conf`; also recorded as `uuid:` in `match`), zvol guid, LV UUID | backing path |
| vdisk | vdisk/image UUID (Synology), `vdisk:<vmid>:<slot>` (Proxmox, so it survives a move to another node) | backing path |
| vm | `vm:<guest uuid>` (Synology VMM), `vm:<vmid>` (Proxmox, unique in the cluster) | none |

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
| vm | `@Repository/<vm_uuid>/vguest.conf` | `vm:<uuid>`, name, vCPU and RAM in `platform.synology`; Virtual DSM has `is_general_vm: false` |
| links | LUN: `target`, `initiators` from the LUN ACL, `match: ["uuid:<uuid>", "naa:<derived>"]` and `platform.synology.vpd_unit_serial`; vdisk: `match: ["uuid:<uuid>", "vmmdisk:<uuid>"]` and `vm` | the NAA id derives from `vpd_unit_serial` by the rule below (verified on nas3); the ACL is `iscsi_lun_acl.conf` (found, `authority` still to verify) |

**The LUN files** (both in `/volume1/@iSCSI/LUN/`, found on nas3):

```ini
# iscsi_lun.conf, one stanza per LUN
[LUN_f48f1514-6072-4193-989e-9e7bfbe6d0e1]
uuid=f48f1514-6072-4193-989e-9e7bfbe6d0e1
vpd_unit_serial=f48f1514-6072-4193-989e-9e7bfbe6d0e1

# iscsi_lun_acl.conf, one stanza per (LUN, initiator)
[iSCSI_ACL_79494475-cb0a-4937-886c-ceeb8f894547_iqn.2000-01.com.synology:default.acl]
initiator=iqn.2000-01.com.synology:default.acl
lun_uuid=79494475-cb0a-4937-886c-ceeb8f894547
authority=0
```

- **NAA id.** What an initiator sees (Proxmox `scsi-36001405f48f1514d6072d4193d989ed9`) is
  LIO's NAA-6 id, derived from `vpd_unit_serial`: `6001405` plus the first 25
  characters of the serial, each character that is not a hex digit replaced by the hex
  digit of `ord(c) & 0xF` (a uuid's `-`, 0x2d, becomes `d`), hex digits kept, lowercase.
  `f48f1514-6072-4193-989e-9e7bfbe6d0e1` gives `6001405f48f1514d6072d4193d989ed9`
  (`topology.naa_from_unit_serial`, tested on exactly this pair). It is not the uuid
  with the hyphens stripped, which is what this page first guessed. `vpd_unit_serial`
  equals the uuid on every LUN seen, but the agent reads it and does not assume it.
  The agent records the serial in `platform.synology.vpd_unit_serial` and the result as
  a `naa:` match; a LUN reported without one is still matched, by deriving the id from
  its `vpd_unit_serial` or else its `uuid:` key.
- **ACL.** `initiators` is one entry per ACL stanza: `{"iqn": <initiator>, "authority":
  <integer as written>}`; the stanza for `iqn.2000-01.com.synology:default.acl` is the
  default for initiators not listed and is recorded with `"default": true`. `authority`
  is kept raw: 0 and 3 are the values seen. *Verify:* the guess is 0 = no access and 3 =
  read/write. Nothing relies on it: `initiator_ok` on a link only asks whether the
  consumer's host is named by an entry that is not the default, and is `None` when the
  ACL names no one.

NAS-MAIN is the fixture `tests/data/synology_nas_main.json`: five disks in
one `md2` RAID 5 group (SHR) of one pool; `volume1` (btrfs) and `volume2`
(ext4) in it; four SMB shares on `volume1`; LUN-3 (thin, 11.0 TiB allocated,
note 03's old name for the hosted ZFS), LUN-2 (thick), LUN-7 (thin); the
NAS-VM disk and an Image Library template (`attached: false`) that note 03
lists as a cleanup target. NAS-OLD (`synology_nas_old.json`) is two disks, one
RAID 1 array, one volume. The links between hosts are tested on the lab
instead: `lab_nas3.json` (Synology SAN Manager: Volume 1, seven LUNs with
targets and initiators, thin and thick, and NAS01's VMM vdisks),
`lab_pvec.json` (the Proxmox cluster, PVEC), `lab_pve2.json` (VM 155 with its
four disks, local-btrfs), `lab_truenas2.json`, `lab_nas01.json` (Virtual
DSM) and `lab_lkensel_g5_5090.json` (a Windows initiator, sketched). LUN-3's uuid
and NAA id are the real ones; the other LUN uuids, the serials and nas3's pool
layout are invented, with every LUN's NAA id derived from its uuid by the rule
above. The sizes, names and targets are the lab's.

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
| disk | `lsblk -J`, `smartctl` | serial and WWN (`lsblk -o SERIAL,WWN`) in `serial` and `match: ["naa:..."]`; an iSCSI storage's LUNs are `disk` nodes of the cluster snapshot with `virtual: true` and `match: ["naa:...", "volid:<storage>:<lun>"]` |
| cluster | `pvesh get /cluster/status`, `/etc/pve/storage.cfg` | `host.cluster` on each node; a snapshot of `kind: cluster` for storages with `shared 1` or no `nodes` restriction (PVEC, Ceph, NFS) |
| vm | `qm list`, `qm config <vmid>` | `vm:<vmid>`; machine, bios, cores, memory in `platform.proxmox` |
| group | `zpool status -P` (ZFS); `mdadm`; Ceph OSDs are optional groups | |
| pool | `pvesm status` storages: ZFS pool, LVM VG, LVM-thin (a pool in the VG pool, `kind: lvm_thin`, `thin: true`), directory | Ceph pool: `kind: ceph`, members empty (OSDs live on other hosts) |
| volume | directory storage / mount with a file system; ZFS dataset | `/var/lib/vz` is a volume holding qcow2 files |
| lun | LVs and zvols without a file system | `kind: lv` or `zvol` |
| vdisk | `qm config <vmid>` disk lines (`scsi0: local-zfs:vm-101-disk-0`), `pvesm list <storage>`; qcow2/raw files | `vm = {"id": "vm:101", "name": ...}`; `attached: false` for unused disks and ISO/template images. Links: `match: ["vmserial:<serial=>"]` when the config sets a `serial=`, `volid:<storage>:<volume>` when the storage is cluster-wide (no `parent`) |

A vdisk is one of the three things: a file (qcow2) in a volume, an LV in a
thin pool, a zvol in a pool; its `parent` says which, and `path` the file or
device.

### Windows

| Node | Source | Notes |
|---|---|---|
| disk | `Get-PhysicalDisk` (SerialNumber, Usage -> role: `AutoSelect`/`HotSpare`/`Journal`), `Get-Disk` | `slot` from `PhysicalLocation`; `UniqueId`/`Guid` for an iSCSI disk is its NAA id: `match: ["naa:..."]`, `virtual: true`; `serial:<SerialNumber>` for a VM's disk. `host.iqn` from `Get-InitiatorPort` |
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

## 5. Links

### Between hosts

A host's storage is often made of another host's: a LUN becomes a Proxmox
disk, which becomes a TrueNAS pool; a Synology VMM vdisk becomes the disk of
a Virtual DSM. The link is between **individual disks**, never between
servers, so one host can sit on several providers and a chain can run
through any number of hops.

- `backing: {"host": "nas3", "id": "lun:f48f..."}` on a `disk`, `lun` or
  `vdisk` names the node on another host that provides it. The agent sets it
  only when it knows (a hypervisor knows which storage a vdisk is on).
- `match: ["naa:...", "serial:..."]` lists identifiers the node can be
  recognised by (`kind:value`, lowercase kind). Most links are made from
  these, because the guest does not know the host it runs on.
- `virtual: true` marks a disk, lun or vdisk that something else provides
  (a QEMU disk, an iSCSI disk, a Virtual DSM disk). It says "a provider is
  expected", so a missing one is reported.
- A `lun` lists `initiators` (`{iqn, authority}` entries from its ACL) and its
  `target`; a `vdisk` names its `vm` (`{"id": <vm node id>, "name"}`).
- `topology.resolve_links(snapshots, overrides=None, manual=()) -> (links, unresolved)`
  works over any number of hosts' snapshots. The global key of a node is
  `(host, id)`, the host lowercased. A link always joins two hosts.
  `chain(links, key)` follows a node down to the real storage.

Order of resolution for each consumer: a manual link (`[[storage.links]]`, below),
then its own `backing`, then the automatic keys:

| Consumer `match` | Provider `match` | Used for |
|---|---|---|
| `naa:<NAA id>` on a disk, lun or vdisk | `naa:<NAA id>` on a Synology `lun` (else derived from its `vpd_unit_serial` or `uuid:`) | an initiator's or cluster's iSCSI disk -> the NAS LUN. Exact match on the hex (`naa.`, `scsi-3` and case ignored), no prefix matching |
| `serial:<serial>` on a `disk` | `vmserial:<serial=>` on a hypervisor `vdisk` | a guest's disk -> the Proxmox vdisk whose `serial=` the VM config set (case-insensitive) |
| `volid:<storage:volume>` on a `vdisk` | `volid:<same>` on the cluster storage's `disk` or `lun` | a VM's raw iSCSI volume -> the storage that is attached cluster-wide |
| `vmmdisk:<vdisk uuid>` on a `disk` | `vmmdisk:<uuid>` on a Synology `vdisk` | a Virtual DSM disk -> its VMM vdisk, when the guest can see the uuid |

A match must be exactly one provider on another host. Two candidates are
`ambiguous`, none is "no provider found". Manual links win over everything, so a
wrong guess is fixed in the config, not in the code.

**Unresolved is a report, not an error.** `resolve_links` returns
`Unresolved(node, reason, wanted)` for a named target that is missing (`no
snapshot for host nas9`, `nas3 has no node lun:...`), an ambiguous match, and
a node that expects a provider and finds none: `virtual: true`, or a
cluster-scope `vdisk` with a `volid`. A lab that changes over time is
normal: when truenas2 is torn down nothing is left dangling (its provider
simply has no consumer); when LUN-3 goes, the cluster's disk shows up as
unresolved and the viewer draws the chain up to the gap.

`guest_server` is gone. What it recorded is derived:
`guest_servers(snapshots, links)` maps each provider node to the UNC servers
of the hosts whose disks are made of it, at any depth (a cluster is not a
guest). This supersedes note 04's `parent_storage` and `child_server`: the
upward link is the `backing`/`match` on the guest's disk, the downward
"Jump to Guest Shares" button is `guest_servers` on the LUN or vdisk.

### Compute versus storage, and cluster scope

A `vm` node lives on the host that runs it (the hypervisor): id from the
platform (`vm:155`, Proxmox's vmid, unique in its cluster; `vm:<guest uuid>`
for Synology VMM), `parent: null`, outside the containment tree. Its `vdisk`s
point to it with `vm: {"id": "vm:155", "name": "truenas2"}`. A vdisk on
node-local storage has a `parent` (the volume it is a file in); a vdisk on
cluster storage has none and links to the cluster's disk by `volid`.

A Proxmox **cluster** is a snapshot of its own, `host: {"name": "pvec",
"kind": "cluster"}`, holding what belongs to the cluster: shared storage
(PVEC, an iSCSI storage: a `pool` with the attached LUNs as `disk` nodes,
`virtual: true`, linked to the NAS). Each node's snapshot says
`host.cluster: "pvec"` and holds the VMs and the node-local storage
(local-btrfs). The agent on a node may return the cluster snapshot in the
reply as `cluster_topology` (`snapshots_from_response`). A VM that migrates
moves its `vm` node and its vdisks to the other node's snapshot with the same
ids; the cluster-storage vdisk's `volid` and the guest's `serial` still match,
so no link changes and the storage did not move. Node-local disks do not
travel (a live migration copies them), which is why a guest's local disk may
be unresolved for a moment. Prefer `match` to explicit `backing` between a
guest and a hypervisor: a `backing` that names `pve2` is wrong after the move.

Generic rule, not Proxmox-specific: shared storage that several hosts see is a
snapshot (or a set of nodes) of its own; a host that lists the same storage
too is a consumer of it. A TrueNAS or Windows failover pair can use
`host.cluster` the same way.

### To the catalog

- **Roots.** A share's `unc` is a root as `roots` and `records` know it
  (`\\nas-main\Backup`). The viewer joins a share to its root by that string,
  compared case-insensitively like `aliases.py`. A share with no scanned
  root shows as "not cataloged".
- **Guests' roots** are found through the links: the shares of a host whose
  disks chain to a LUN are the "guest shares" of that LUN.

### Worked example: truenas2 on nas3

The lab, temporarily: a TrueNAS VM on a Proxmox cluster whose pool is one raw
iSCSI LUN of a Synology (`tests/data/lab_*.json`).

```text
truenas2   disk:TRUENASDISK002   match serial:TRUENASDISK002          (virtual)
   |  serial ~ vmserial: the VM config said serial=TRUENASDISK002
pve2       vdisk:155:scsi1       match vmserial:TRUENASDISK002, volid:PVEC:0.0.1.scsi-36001405f48f...
   |  volid ~ volid: the storage volume of the cluster-wide iSCSI storage PVEC
pvec       disk:naa.6001405f48f1514d6072d4193d989ed9   match naa:6001405f48f1..., volid:...
   |  naa ~ naa: the LUN's NAA id, 6001405 + its vpd_unit_serial by the rule in section 3
nas3       lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1    (LUN-3, target PVEC, match naa:6001405f48f1514d6072d4193d989ed9)
```

The boot disk, `TRUENASDISK001`, stops one hop earlier, at pve2's
`vdisk:155:scsi0` on local-btrfs. The hop from the cluster to the LUN is the
NAA rule of section 3, verified on nas3. Before any agent reports Proxmox, the
same relationship is one line of config: truenas2's disk linked to
`nas3/lun:LUN-3` (section 5, "Written by hand").

NAS01 is the same on a different axis: `nas3` has `vm:<guid>` NAS01 whose two
vdisks carry `vmmdisk:<vdisk uuid>`; NAS01's own snapshot has two virtual
disks carrying the same uuid, **if** Virtual DSM can see it (open question
4); otherwise a `[[storage.links]]` entry per disk. LUN-4..7 (target
`lkensel-g5-5090`, initiator its IQN) match the workstation's four iSCSI
disks by `naa`; the workstation's IQN being in the LUN's `initiators` is
reported on the link as `initiator_ok`, a hint and not a requirement.

### Written by hand: hosts and links in filecat.toml

Nothing here needs an agent. A host no agent reports (truenas2 until a TrueNAS reader
exists), and a link no rule can find, are written in `filecat.toml`:

```toml
[[storage.hosts]]
name = "truenas2"
unc_server = '\\truenas2'
platform = "truenas"               # free text
nodes = [
  { type = "disk",   name = "tank-disk", virtual = true, size = "10.74 TiB" },
  { type = "pool",   name = "tank", disks = ["tank-disk"] },
  { type = "volume", name = "tank" },
  { type = "share",  name = "Share1" },    # placeholder names; \\truenas2\Share1
  { type = "share",  name = "Share2" },
]

[[storage.links]]
from = "truenas2/disk:tank-disk"
to   = "nas3/lun:LUN-3"
note = "tank is one iSCSI LUN on nas3, through Proxmox"     # optional
```

**Refs.** `from` and `to` are `host/ref`. The host is everything before the first `/`
(case-insensitive). The ref is `type:...` with a node type, read two ways, in this order:
a node id (`lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1`, `disk:naa.6001...`), and when no
node has that id, `type:name`: the node of that type whose `name` is that, compared
case-insensitively (`lun:LUN-3`). The name must be unique: two nodes named alike make the link
`unresolved` with both ids in the reason, and the fix is the id. A ref with no type
(`nas3/LUN-3`) is a config error, as is a link inside one host or a disk linked twice.
Whether the host or node exists is not checked at load time: `resolve_links` reports
an unknown target as `unresolved` (the other host's agent may simply not have run yet).

**Where a link starts.** At the `disk`, `lun` or `vdisk`, and that is also what is
recorded: `physical_summary` counts bytes per disk, "a disk with a resolved link is not
physical on its own host", so the disk is the node that has to carry the link for the
pool above it to be left out. Naming a `pool`, `group`, `volume` or `share` is accepted
as a shortcut for the one disk beneath it; if there are several disks the link is
`unresolved` and says so, because linking one of them would leave the others counted
and linking all of them to one LUN would be false. The end (`to`) may be any node of
another host, though a lun, vdisk or disk is what chains and `guest_servers` expect.

**Hosts.** `nodes` are `type` (`disk group pool volume share lun vdisk`) and `name`, with
optional `id` (default `type:name`, shares lowercased), `parent`, `disks` (pool, group
and volume: the disks beneath, becoming `members`), `size`/`used`/`free` (bytes, or
`"10.74 TiB"`, `"500 GB"`; KiB is 1024, KB 1000), `unc`, `path`, `virtual`, `serial`,
`model`, `media`, `kind`, `health`, `detail`, `protocols`, `match`. `parent` and `disks`
name nodes of the same host by id, `type:name`, or a name only one node has. A volume
without `parent` goes in the host's only pool, a share in its only volume (a share with
neither is an error). A share's `unc` defaults to `<unc_server>\<name>` and its `protocols`
to `smb`. The result is an ordinary snapshot, `source: "manual"`, validated like an
agent's. If an agent later reports the same host name, its snapshot replaces the
manual one (agents are loaded after).

**Precedence.** A manual link beats `backing` and the automatic keys. If the automatic
result for that disk is a different provider, the result lists a `Conflict` and the manual
link is what is used; if it agrees, it is just marked `config`. A manual link whose
target is missing leaves its disk `unresolved` rather than falling back behind the
config's back. `topology.resolve(snapshots, overrides, manual)` returns links,
unresolved, conflicts and one `ManualResult` per link; `resolve_links` returns just the
first two.

**Checking.** `filecat config show` lists the hosts and links. `filecat storage links
[--snapshot FILE ...] [--json]` resolves them over the manual hosts plus any saved
`storage_topology` replies (or bare topologies) and prints each link as resolved,
unresolved or conflict, the other disks still expecting a provider, and the
`physical_summary` totals; exit status 1 when a link is unresolved or in conflict.
Truenas2 and nas3's snapshot are enough for the LUN-3 chain, no Proxmox needed.

**Later: the catalog, and the web viewer.** These records are shaped to move. `ManualLink`
and the manual snapshot (`Topology.source == "manual"`, `Topology.origin`) are the in-memory
form; the config loader fills them with `source`/`origin` `"config"`. A catalog store edited
in the web viewer would fill the same records with `"catalog"`, and `resolve` takes both
(a link's `via` says which won). Config entries stay read-only in the viewer (shown with
their origin, not editable), so a hand-edited file and the viewer never write the same
record. Neither the store nor the editor exists yet.

## 6. Totals

`capacity_summary(topo)` returns disk, pool, volume (size/used/free), share,
and block-storage (provisioned vs allocated) totals for one host, each node
counted once (nested pools and datasets are not added twice).
`subtree_sum(topo, id, field, *types)` sums under any node, e.g. the bytes in
LUNs and VM disks on `volume1`. For NAS-MAIN, volume used minus share used is
the hidden block storage of note 03: shares 29.7 TB, LUNs and VM disks the
rest.

### Physical bytes across hosts, counted once

`physical_summary(snapshots, links, unresolved)` is the global total, with
this rule: **a disk with a resolved link is not physical on its own host**,
because its bytes are already inside the provider. A top-level pool or volume
whose disks are all backed is `excluded` from the physical figures
(`pool_bytes`, `volume_*`, `disk_bytes`); a volume with at least one real disk
under it counts whole. The rule is per disk, not per server: a host can have
a real SSD and an iSCSI disk and only the latter's volumes drop out.

In the lab: nas3's Volume 1 (87.22% used) already contains LUN-3's 10.2 TB and
NAS01's VMM disks, so truenas2's `tank`, NAS01's `volume1`, the PVEC pool and
the workstation's E: to H: are excluded, and truenas2's 32 GiB boot disk is
counted once, inside pve2's local-btrfs. What is still reported are the
logical bytes: `share_used_bytes` sums every share of every host (truenas2's
migrated share, NAS01's Media), a different question than "how much disk is
in use". Virtual disks with no provider (the provider's snapshot is missing)
are counted, since nothing else holds them, and listed in
`unresolved_disk_bytes`. Thin provisioning is not unwound: a thin LUN counts
as the NAS volume's used bytes, not as its provisioned size.

## 7. Storage in the catalog (proposal)

**One document per host snapshot**, in a `storage_topology` store (replacing
note 04's per-volume `storage_pools` document, whose pool/volume/LUN/VM lists
are all nodes here):

```json
{"_id": "nas-main", "host": "nas-main", "platform": "synology",
 "scanned_at": "...", "agent": {"version": "...", "protocol": 1},
 "topology": { ...the response... },
 "unc_roots": ["\\\\nas-main\\Backup", ...],
 "attached_to": ["nas3"],
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
  `unc_roots` and `attached_to` arrays (indexed): share -> root, root ->
  host, guest -> provider hosts. The links themselves are not stored: they are
  recomputed from the latest snapshots with `resolve_links`, so a replaced
  host re-links without a rewrite. Anything else (search by disk serial) scans a
  few dozen documents.

The cost is that a very large host (hundreds of shares, a thousand VM disks)
makes a big document and a whole-document rewrite on each scan; at filecat's
scale that is kilobytes, and a hundred-fold margin is still under the
MongoDB 16 MiB limit. If it ever bites, shares are the node type to split
into their own store, since they are already keyed by root.

## 8. Open questions

1. Confirmed on nas3: (a) a LUN's NAA id is `6001405` plus the first 25 characters
   of `vpd_unit_serial` with non-hex characters mapped to `ord(c) & 0xF`
   (section 3); (b) the ACL is `iscsi_lun_acl.conf`, one stanza per LUN and
   initiator, with a `default.acl` entry. Still to verify: what `authority`
   means (0 and 3 seen; guess 0 = no access, 3 = read/write), whether the
   target-to-LUN mapping lives in the same file, and (c) that the `serial=` a
   Proxmox VM sets is what the guest reports (TrueNAS shows it as the disk
   serial: expected, check).
2. Disks as an inventory with `members` edges (this design) versus disks as
   the top of the tree. The inventory handles SHR and shared spares; the cost
   is that "disk -> pool" is a join the viewer does.
3. The `[[storage.links]]` and `[[storage.hosts]]` loader exists (section 5);
   the dict form of `resolve_links(overrides=...)` stays for code. Where the
   central side keeps the latest snapshot of each host for resolving, how
   stale a snapshot may be before its links are called unresolved, and the
   catalog store that would hold links and hosts edited in the viewer.
4. Can Virtual DSM see its VMM vdisk uuid? Unknown: the guest's disk model is
   "Virtual disk" and its serial may be generated. If not, link by config, or
   by size and boot order (not implemented, too weak to guess).
5. Does a cluster snapshot come from any one node's agent (as
   `cluster_topology`, duplicated across nodes, latest wins) or from a
   cluster-level entry in `[[agents]]`?
6. Thin provisioning is not unwound in the physical total; a LUN that is
   thin on the NAS and ZFS-formatted in the guest counts as what the NAS
   volume holds.
7. History: keep every changed structure forever, or a fixed number per host;
   what usage movement counts as a change.
8. Windows: its agent (if any) needs drive-letter path mapping before shares
   derive; until then Windows hosts stay on SMB scans.
9. Replace `storage_pools` (note 04) outright, as proposed here, or keep that
   name for the store.
