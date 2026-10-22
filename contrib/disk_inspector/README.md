# Disk Image Inspector

A pure-Python 3 module that inspects the first 64 MiB of common virtual disk and disk image files.

## Versions

- **v1** (`disk_inspector.py` / `disk_inspector_v1.py`) — Original format + basic partition detection.
- **v2.1** (`disk_inspector_v2.1.py`) — Adds lightweight volume content scanning for OS/role identification and interesting paths (Windows Users, Linux /home, Docker) when volume data is accessible inside the 64 MiB window.

## Files

- `disk_inspector.py` — Original module (v1).
- `disk_inspector_v2.py` — Enhanced module (recommended).
- `disk_formats.json` — Updated catalog including filesystem, encryption, and LVM signatures (v2).
- `disk_formats_v1.json` — Backup of the original catalog.

## v2 Additions

- **Filesystem detection** at offset 0 (single-volume images) and at partition starts:
  NTFS, exFAT, FAT12/16/32, ext2/3/4, XFS, Btrfs, HFS+, APFS, Linux swap, ReFS.
- **Encryption**:
  - BitLocker fixed: `-FVE-FS-` at offset 3 + Device ID GUID at offset 160.
  - BitLocker To Go: scan for the identifier GUID.
  - LUKS: `LUKS\xba\xbe` + version/UUID/cipher when available.
- **LVM**: `LABELONE` + `LVM2 001` (typically at offset 512) on raw disks or partitions, including PV UUID.

## Usage (v2)

```bash
python disk_inspector_v2.py /path/to/image.img
```

```python
from disk_inspector_v2 import inspect_disk
info = inspect_disk("/path/to/disk.raw")
print(info["format"], info.get("encryption"), info.get("filesystems"), info.get("lvm"))
```

## Output Fields (v2)

- All v1 fields plus:
- `filesystems` — List of detected FS / volume types and locations
- `encryption` — BitLocker / LUKS details (including `device_id` for BitLocker)
- `lvm` — LVM physical volume info when present
- `version` — "2.0"

## Limitations

- Container formats (QCOW2, dynamic VHD/VDI/VMDK, VHDX) still require address mapping for guest content.
- Fixed VHD footers at end of large files may be missed.
- File lists are only hinted for ISO; other filesystems need dedicated parsers.
- Encryption detection is header-based only (no key recovery).
- LVM metadata text area is not fully parsed (label + UUID only).

See `disk_formats.json` for detailed signatures.

## In filecat

`disk_inspector_v2_1.py` (renamed from `disk_inspector_v2.1.py` so it can be imported),
`disk_formats.json` (v2.1 catalog) and this README are kept here as the reference the
built-in disk-image probe (`src/filecat/probe/disk.py`) was built from. filecat does not
import this script; it is standalone and still runs as
`python contrib/disk_inspector/disk_inspector_v2_1.py IMAGE`.
