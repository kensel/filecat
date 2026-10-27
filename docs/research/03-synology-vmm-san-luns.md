# 03 - Synology VMM & SAN LUN Storage Discovery Research

This document records the reverse-engineered layout of Synology SAN Manager (iSCSI) and Virtual Machine Manager (VMM) on NAS-MAIN, explaining the ~19.1 TB gap between SMB file shares (29.7 TB) and physical Volume 1 usage (48.6 TB / 55.8 TB). The parsing now lives in Python (`src/filecat/topology_collect/synology.py`; the Rust draft `synology_storage.rs` was deleted).

## 1. Key Architectural Findings on DSM 7.x

### A. The 512 GiB ROD Sparse File Trap

Inside every block LUN folder under /volume1/@iSCSI/LUN/BLUN/<uuid>/ and /volume1/@iSCSI/LUN/VDISK_BLUN/<uuid>/, Synology creates two files:

- <name>_00000: The actual virtual disk or LUN data extent.
- ROD: A Redirect-on-Write / Btrfs block mapping file whose logical st_size is always **549,755,813,888 bytes (512 GiB)**, but whose physical block allocation (st_blocks) is **0**.

**Rule:** Never sum st_size inside @iSCSI/LUN. Always read provisioned capacity from bytes= in iscsi_lun.conf and calculate physical usage by summing meta.blocks() * 512 across all files in the UUID directory.

### B. How /volume1/@iSCSI/LUN/iscsi_lun.conf Encodes SAN & VMM Objects

All block devices on the volume—both SAN iSCSI LUNs and VMM Virtual Disks—are registered as INI stanzas in /volume1/@iSCSI/LUN/iscsi_lun.conf:

- **devtype=5 (BLUN):** Thin-provisioned Btrfs iSCSI LUN stored at /volume1/@iSCSI/LUN/BLUN/<uuid>/.
- **devtype=11 (BLUN_THICK):** Thick-provisioned Btrfs iSCSI LUN stored at /volume1/@iSCSI/LUN/BLUN_THICK/<uuid>/.
- **devtype=7 (VDISK_BLUN) with name=vdisk.<vm_uuid>.<vdisk_uuid>.<bus>.<unit>:** An active VMM virtual disk attached to a guest VM in /volume1/@Repository/<vm_uuid>.
- **devtype=7 (VDISK_BLUN) with name=image.<image_uuid>.<vol_uuid>.<bus>.<unit>:** An unattached disk image or ISO stored in VMM's **Image Library** (*Virtual Machine Manager → Image → Disk Image / ISO file*).

### C. How /volume1/@Repository/<vm_uuid>/ Maps Guest Names to Disks

Each VM has a directory in /volume1/@Repository/<vm_uuid>/ containing two single-line JSON files:

- **vguest.conf:** Contains name (e.g., "NAS-VM", "pve-quorum"), desc, vcpu_num, vram_size, is_general_vm (false for Virtual DSM instances), and version.
- **vdisk.conf:** A JSON map keyed by vdisk_uuid with {"is_dummy": bool, "is_meta_disk": bool, "vdisk_mode": int}.

## 2. Complete Audit of NAS-MAIN Hidden Block Storage (19.1 TiB Total)

| Category | Name / VM Guest | LUN UUID | Provisioned | Physical Used (st_blocks) | Role & Cleanup Notes |
|---|---|---|---|---|---|
| **SAN (BLUN)** | LUN-3 | f48f1514-6072-4193-989e-9e7bfbe6d0e1 | 10.74 TiB (11.8 TB) | **11.0 TiB** | Backing ZFS disk for nas-zfs VM on Proxmox VE node 2. |
| **SAN (BLUN_THICK)** | LUN-2 | 47f5d7a8-5444-4932-93e3-c712f6aa0130 | 1,000 GiB | **1,000 GiB** | Thick-provisioned iSCSI LUN. |
| **SAN (BLUN)** | LUN-7 | bd85bc23-c5d3-459e-8801-39d17f096c57 | 1,000 GiB | **932 GiB** | Thin-provisioned iSCSI LUN. |
| **SAN (BLUN)** | LUN-4, LUN-6, LUN-5, LUN-1 | 2a93..., 83a1..., a006..., 7949... | 310 GiB total | **86.2 GiB** | LUN-4 (84G), LUN-6 (2.1G), LUN-5 (67M), LUN-1 (0B). |
| **VMM Active (vdisk.)** | **NAS-VM** (Virtual DSM 7.4.1) | ff8a106f-... (+ 0b10..., f734...) | 4.02 TiB | **2.3 TiB** (+ 3.1G) | Backing virtual disks for \\nas-vm SMB server. |
| **VMM Active (vdisk.)** | **vm-desktop-1** | eb0d3770-f240-43a7-93ab-c6325551d055 | 932 GiB | **932 GiB** | Active VM disk for vm-desktop-1. |
| **VMM Image (image.)** | [VMM_IMAGE: b9c5e9e5] | dc8c50db-f451-4367-966a-f6277ac5341b | 932 GiB | **932 GiB** | **Cleanup Target:** Imported source disk image for vm-desktop-1 in VMM Image Library. |
| **VMM Image (image.)** | [VMM_IMAGE: c9d790ad] | 3206ff49-515e-4b71-afaa-92ed5a3076c6 | 699 GiB | **699 GiB** | **Cleanup Target:** Unattached 700 GB disk image in VMM Image Library. |
| **VMM Active (vdisk.)** | **vm-desktop-2** | f058d4b4-6280-4b1f-bf01-5bde8828d0f7 | 466 GiB | **466 GiB** | Active VM disk for vm-desktop-2. |
| **VMM Image (image.)** | [VMM_IMAGE: ec219fcf] | 0d382951-7f15-48d3-a820-e012f8704e9b | 466 GiB | **466 GiB** | **Cleanup Target:** Imported source disk image for vm-desktop-2 in VMM Image Library. |
| **VMM Active (vdisk.)** | **vm-laptop-1** | dfb5a37c-7eb8-4891-9a65-5a93036b2a0c | 120 GiB | **120 GiB** | Active VM disk for vm-laptop-1. |
| **VMM Image (image.)** | [VMM_IMAGE: 8c7934df] | 6ad6deaa-9476-4c4f-9612-3f3fc873ee26 | 120 GiB | **120 GiB** | **Cleanup Target:** Imported source disk image for vm-laptop-1 in VMM Image Library. |
| **VMM Active (vdisk.)** | **pve-quorum**, **VM-HOMEASSISTANT**, **VM-GATEWAY** | 0bc6..., e1f4..., 26ac... | 115 GiB total | **60.1 GiB** | Proxmox quorum (27G), Home Assistant (21G), Gateway (12G). |

**Immediate Space Recovery Opportunity:** Removing the four leftover imported disk templates (image.*) in *VMM → Image → Disk Image* can reclaim up to **2.22 TiB (~2.44 TB)** on NAS-MAIN.
