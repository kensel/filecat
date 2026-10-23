# 04 - Web Viewer UI & End-to-End Storage Hierarchy

> Design update: `parent_storage` and `child_server` below are superseded by links between individual disks (`backing` / `match` on the guest's disk, resolved across hosts' snapshots), and "Net Physical Storage Used" by the per-disk rule of `topology.physical_summary`. See [storage-topology.md](../storage-topology.md) section 5.

This document describes the schema for the new storage_pools collection and the updates to filecat serve (treemap.py, serve.py, and the frontend web UI) to present a unified picture from physical RAID pools and volumes down to SAN LUNs, VMM Virtual Machines, child NAS servers (NAS-VM, nas-zfs), backup stores, and individual files.

## 1. End-to-End Storage Hierarchy Model

```text
Physical Server (\\nas-main)
 └── Storage Pool 1 (/dev/md2, 55.8 TB total)
      └── Volume 1 (/volume1, Btrfs: 48.6 TB used / 7.2 TB free)
           ├── [File Shares Tier] (29.7 TB — existing roots & records collections)
           │    ├── \\nas-main\Backup (25.0 TB)
           │    │    ├── NAS-VM_1.hbk  ──> [BACKUP] Inspector Card
           │    │    └── minio        ──> Legacy MinIO FS-mode store
           │    ├── \\nas-main\ActiveBackupforBusiness (1.95 TB) ──> [BACKUP] Inspector Card
           │    ├── \\nas-main\Apps (1.55 TB)
           │    └── \\nas-main\homes (374.3 GB)
           │         └── jdoe\[CACHE] & [REDACTED] ──> Rollup Inspector Cards
           │
           ├── [SAN iSCSI Block Tier] (13.0 TB physical — stored in storage_pools)
           │    ├── LUN-3 (11.0 TiB allocated) ──(hosts ZFS via Proxmox VE 2)──> Child Server: \\nas-zfs
           │    ├── LUN-2 (1,000 GiB Thick LUN)
           │    ├── LUN-7 (932 GiB Thin LUN)
           │    └── LUN-4 / LUN-6 / LUN-5 / LUN-1 (86.2 GiB combined)
           │
           └── [Synology VMM Tier] (6.1 TB physical — stored in storage_pools)
                ├── VM: NAS-VM (2.3 TiB allocated) ──(Virtual DSM)──> Child Server: \\nas-vm
                ├── VM: vm-desktop-1 (932 GiB allocated)
                ├── VM: vm-desktop-2 (466 GiB allocated)
                ├── VM: vm-laptop-1 (120 GiB allocated)
                ├── VMs: pve-quorum (27G), VM-HOMEASSISTANT (21G), VM-GATEWAY (12G)
                └── VMM Image Library (2.22 TiB in unattached `image.*` templates!)
```

## 2. The storage_pools Collection Schema

Stored in a dedicated storage_pools collection in MongoDB (and a storage_pools table in SQLite/Postgres/MySQL) so existing roots and records schemas remain unchanged:

```json
{
  "_id": "\\\\nas-main/volume1",
  "server": "\\\\nas-main",
  "scanned_at": "2026-10-21T18:00:00Z",
  "pool_name": "Storage Pool 1",
  "volume_id": "volume1",
  "mount_point": "/volume1",
  "device": "/dev/mapper/cachedev_0",
  "fs_type": "btrfs",
  "total_bytes": 61352978841600,
  "used_bytes": 53436265234432,
  "free_bytes": 7916713607168,
  "parent_storage": null,
  "child_roots": [
    "\\\\nas-main\\Backup",
    "\\\\nas-main\\ActiveBackupforBusiness",
    "\\\\nas-main\\Apps",
    "\\\\nas-main\\homes"
  ],
  "san_luns": [
    {
      "uuid": "f48f1514-6072-4193-989e-9e7bfbe6d0e1",
      "name": "LUN-3",
      "kind": "san_blun",
      "provisioned_bytes": 11811160064000,
      "allocated_bytes": 12094627905536,
      "child_server": "\\\\nas-zfs",
      "host_bridge": "pve-node-2 (ZFS over iSCSI)"
    }
  ],
  "vm_disks": [
    {
      "uuid": "ff8a106f-f063-439f-85e9-e21abb402ae1",
      "vm_uuid": "dead21af-c947-4f6a-9b25-1535ccd2dd75",
      "vm_name": "NAS-VM",
      "kind": "vmm_vdisk",
      "is_meta_disk": false,
      "provisioned_bytes": 4398046511104,
      "allocated_bytes": 2528876743884,
      "child_server": "\\\\nas-vm"
    }
  ],
  "vmm_images": [
    {
      "uuid": "dc8c50db-f451-4367-966a-f6277ac5341b",
      "name": "[VMM_IMAGE: b9c5e9e5]",
      "kind": "vmm_image",
      "provisioned_bytes": 1000727379968,
      "allocated_bytes": 1000727379968
    }
  ]
}
```

For virtualized NAS instances like \\nas-vm and \\nas-zfs, their storage_pools document sets parent_storage to link upward to \\nas-main:

```json
"parent_storage": {
  "server": "\\\\nas-main",
  "volume": "/volume1",
  "backing_kind": "vmm_vdisk",
  "backing_uuid": "ff8a106f-f063-439f-85e9-e21abb402ae1",
  "backing_name": "NAS-VM"
}
```

## 3. Web Viewer Enhancements (filecat serve)

### A. Top Summary Ribbon: Physical vs. Logical De-Duplicated Totals

- **Physical Pool Capacity Bar:** Each server header in the Graph view displays its physical volume usage bar (e.g., \\nas-main — 48.6 TB used / 7.2 TB free [87% Warning]) broken into **Shares (29.7 TB)**, **SAN LUNs (13.0 TB)**, and **VMM Disks & Images (6.1 TB)**.
- **True Physical Total:** When \\nas-vm (2.52 TB) and \\nas-zfs have a parent_storage link to \\nas-main, the top global counter shows both **Total Scanned Share Bytes** and **Net Physical Storage Used** (excluding guest shares already accounted for inside parent LUNs/VDISKs).
- **Toolbar Toggle:** Add a [x] Include SAN / VM Block Storage toggle next to Folder depth to show or hide the synthetic $SAN and $VMM boxes inside each server's treemap.

### B. Interactive Inspector Modals (Clicking Special Tiles)

When clicking a tile in the Treemap Graph view, the UI checks the tile's type and opens an contextual Inspector Drawer instead of drilling into raw chunk folders:

- **Backup Store Inspector Card ([BACKUP] or probe.backup != null):**
  - **Header:** Format badge (Synology ABB, Hyper Backup, Veeam, Google Workspace, Thunderbird) + Store Path.
  - **Protected Machines / Tasks:** Table of hostnames/tasks (e.g., DESKTOP-X..., NAS-VM), OS, and latest backup timestamp.
  - **Version History & Retention:** Count of restore points, oldest vs. newest snapshot, and version timeline.
  - **Storage Efficiency:** Backed-up logical size vs. physical pool size (deduplication & compression ratio).
  - **Health & Integrity Banner:** Green badge if problems is empty; Red alert listing missing chunks, failed backup runs (status 4), or corrupt restore chains if problems are present. Includes a button to copy the filecat scan --verify-backups command for that root.
- **SAN / VMM Block Inspector Card ($SAN / $VMM tiles):**
  - Displays VM specs (vCPUs, RAM, description from vguest.conf), provisioned vs. Btrfs allocated bytes, and a warning badge if it is an unattached vmm_image template.
  - If child_server is set (e.g., \\nas-vm or \\nas-zfs), renders a **"Jump to Guest Shares (→ \\nas-vm)"** button that zooms the treemap directly into the guest server's shares.
- **Rollup Group Inspector Card ([REDACTED], [CACHE], [SYNOLOGY]):**
  - Displays total files, directories, logical size, physical allocated size, newest modification time, and the byte/percentage delta against any active pinned snapshot.
