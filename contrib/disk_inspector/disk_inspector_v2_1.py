#!/usr/bin/env python3
"""
Disk Image Inspector v2.1
=========================
Enhanced version of the disk image inspector.

Reads up to the first 64 MiB of a disk image and identifies:
- Container format (raw, qcow2, vhd, vhdx, vdi, vmdk, iso, ...)
- Virtual vs physical size, sparse vs thick
- Partition table (MBR/GPT)
- Filesystem signatures (even on raw single-partition images)
- Encryption (BitLocker with Device ID GUID, LUKS, etc.)
- LVM physical volume labels on raw disks
- Lightweight OS / role identification and path summary
  (Windows Users, Linux /home, Docker) when volume data is accessible

Supported formats and identification methods are in disk_formats.json.

Usage:
    python disk_inspector_v2.1.py path/to/image.img
    from disk_inspector_v2 import inspect_disk   # or rename as needed
    info = inspect_disk("image.vdi")
"""

import json
import os
import struct
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

MAX_READ = 64 * 1024 * 1024

PARTITION_TYPES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32M",
    0x05: "Extended",
    0x06: "FAT16",
    0x07: "NTFS/exFAT/BitLocker",
    0x0B: "FAT32",
    0x0C: "FAT32 LBA",
    0x0E: "FAT16 LBA",
    0x0F: "Extended LBA",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16",
    0x16: "Hidden FAT16",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32",
    0x1C: "Hidden FAT32 LBA",
    0x82: "Linux swap",
    0x83: "Linux",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA9: "NetBSD",
    0xAF: "HFS/HFS+",
    0xEB: "BeOS",
    0xEE: "GPT Protective",
    0xEF: "EFI System",
    0xFB: "VMware VMFS",
    0xFC: "VMware VMKCORE",
}

# BitLocker identifier GUID (fixed drive / To Go variants share the same family)
BITLOCKER_GUID_BYTES = bytes.fromhex("3bd66749292ed84a8399f6a339e3d001")


def read_header(path: str, max_bytes: int = MAX_READ) -> Tuple[bytes, int]:
    try:
        file_size = os.path.getsize(path)
    except OSError as e:
        raise RuntimeError(f"Cannot stat file: {e}") from e
    with open(path, "rb") as f:
        data = f.read(min(max_bytes, file_size))
    return data, file_size


def is_mbr(data: bytes) -> bool:
    return len(data) >= 512 and data[510:512] == b"\x55\xAA"


def parse_mbr(data: bytes) -> List[Dict[str, Any]]:
    if not is_mbr(data):
        return []
    partitions = []
    for i in range(4):
        off = 446 + i * 16
        entry = data[off : off + 16]
        if len(entry) < 16:
            continue
        status, ptype = entry[0], entry[4]
        if ptype == 0:
            continue
        start_lba = struct.unpack_from("<I", entry, 8)[0]
        sectors = struct.unpack_from("<I", entry, 12)[0]
        partitions.append(
            {
                "index": i,
                "bootable": bool(status & 0x80),
                "type": f"0x{ptype:02x}",
                "type_name": PARTITION_TYPES.get(ptype, "Unknown"),
                "start_lba": start_lba,
                "sectors": sectors,
                "size_bytes": sectors * 512,
                "start_bytes": start_lba * 512,
            }
        )
    return partitions


def is_gpt(data: bytes) -> bool:
    if not is_mbr(data) or len(data) < 1024:
        return False
    if data[450] != 0xEE:
        return False
    return data[512:520] == b"EFI PART"


def parse_gpt(data: bytes) -> List[Dict[str, Any]]:
    if not is_gpt(data) or len(data) < 1024:
        return []
    entries = []
    base = 1024
    for i in range(8):  # first few entries
        off = base + i * 128
        if off + 128 > len(data):
            break
        entry = data[off : off + 128]
        type_guid = entry[0:16]
        if type_guid == b"\x00" * 16:
            continue
        start_lba = struct.unpack_from("<Q", entry, 32)[0]
        end_lba = struct.unpack_from("<Q", entry, 40)[0]
        name = entry[56:128].decode("utf-16le", errors="replace").rstrip("\x00")
        entries.append(
            {
                "index": i,
                "type_guid": str(uuid.UUID(bytes_le=type_guid)),
                "name": name or "(unnamed)",
                "start_lba": start_lba,
                "end_lba": end_lba,
                "size_bytes": (end_lba - start_lba + 1) * 512,
                "start_bytes": start_lba * 512,
            }
        )
    return entries


def detect_filesystem(data: bytes, offset: int = 0) -> Optional[Dict[str, Any]]:
    """Detect filesystem or volume type starting at the given offset."""
    if offset + 512 > len(data):
        return None
    vol = data[offset:]

    # BitLocker (fixed drive)
    if vol[3:11] == b"-FVE-FS-":
        info = {"type": "bitlocker", "encryption": "BitLocker (fixed)"}
        # Device / volume identifier GUID at offset 160
        if len(vol) >= 176:
            guid_bytes = vol[160:176]
            try:
                info["device_id"] = str(uuid.UUID(bytes_le=guid_bytes))
            except Exception:
                info["device_id"] = guid_bytes.hex()
            info["notes"] = "BitLocker signature -FVE-FS- at offset 3; Device ID GUID at offset 160."
        return info

    # BitLocker To Go (look for the identifier GUID in the first 512 bytes)
    if BITLOCKER_GUID_BYTES in vol[:512]:
        pos = vol[:512].find(BITLOCKER_GUID_BYTES)
        info = {
            "type": "bitlocker_to_go",
            "encryption": "BitLocker To Go",
            "notes": f"BitLocker identifier GUID found at relative offset {pos}.",
        }
        try:
            info["device_id"] = str(uuid.UUID(bytes_le=BITLOCKER_GUID_BYTES))
        except Exception:
            pass
        return info

    # LUKS
    if vol[:6] == b"LUKS\xba\xbe":
        version = struct.unpack_from(">H", vol, 6)[0] if len(vol) >= 8 else 0
        info = {"type": "luks", "encryption": f"LUKS v{version}", "version": version}
        if version == 1 and len(vol) >= 168:
            uuid_str = vol[168:208].split(b"\x00")[0].decode("ascii", errors="replace")
            info["uuid"] = uuid_str
            cipher = vol[8:40].split(b"\x00")[0].decode("ascii", errors="replace")
            info["cipher"] = cipher
        elif version == 2 and len(vol) >= 168:
            # LUKS2 UUID is later; still report presence
            info["notes"] = "LUKS2 header (JSON metadata follows)."
        return info

    # NTFS
    if vol[3:11] == b"NTFS    ":
        return {"type": "ntfs", "filesystem": "NTFS"}

    # exFAT
    if vol[3:11] == b"EXFAT   ":
        return {"type": "exfat", "filesystem": "exFAT"}

    # FAT family
    if len(vol) >= 0x5A:
        fs_type = vol[0x36:0x3E].decode("ascii", errors="replace").strip()
        if fs_type in ("FAT12", "FAT16", "FAT"):
            return {"type": "fat", "filesystem": fs_type}
        fs_type32 = vol[0x52:0x5A].decode("ascii", errors="replace").strip()
        if fs_type32 == "FAT32":
            return {"type": "fat32", "filesystem": "FAT32"}

    # ext2/3/4
    if len(vol) >= 0x43A:
        magic = struct.unpack_from("<H", vol, 0x438)[0]
        if magic == 0xEF53:
            return {"type": "ext", "filesystem": "ext2/3/4"}

    # XFS
    if vol[:4] == b"XFSB":
        return {"type": "xfs", "filesystem": "XFS"}

    # HFS+
    if len(vol) >= 1026 and vol[1024:1026] in (b"H+", b"HX"):
        return {"type": "hfsplus", "filesystem": "HFS+/HFSX"}

    # APFS
    if len(vol) >= 36 and vol[32:36] == b"NXSB":
        return {"type": "apfs", "filesystem": "APFS"}

    # Btrfs (superblock at 64 KiB)
    if offset + 0x10048 <= len(data):
        if data[offset + 0x10040 : offset + 0x10048] == b"_BHRfS_M":
            return {"type": "btrfs", "filesystem": "Btrfs"}

    # Linux swap
    if len(vol) >= 0x1000 and vol[0xFF6:0x1000] == b"SWAPSPACE2":
        return {"type": "swap", "filesystem": "Linux swap"}

    # ReFS (common signature)
    if b"ReFS" in vol[:256] or (len(vol) > 3 and vol[3:7] == b"ReFS"):
        return {"type": "refs", "filesystem": "ReFS"}

    return None


def detect_lvm(data: bytes) -> Optional[Dict[str, Any]]:
    """Detect LVM2 physical volume label (usually at sector 1 / offset 512)."""
    for off in (512, 0, 1024, 1536):  # common label locations
        if off + 32 > len(data):
            continue
        if data[off : off + 8] == b"LABELONE":
            info = {"type": "lvm_pv", "volume_manager": "LVM2", "label_offset": off}
            if off + 32 <= len(data) and data[off + 24 : off + 32] == b"LVM2 001":
                info["confirmed"] = True
            # Try to extract UUID (32 bytes ASCII after the header)
            if off + 64 <= len(data):
                uuid_raw = data[off + 32 : off + 64]
                try:
                    info["pv_uuid"] = uuid_raw.decode("ascii", errors="replace").rstrip("\x00")
                except Exception:
                    pass
            info["notes"] = (
                "LVM2 physical volume label found. "
                "This is a raw disk (or partition) initialized as an LVM PV rather than a single filesystem."
            )
            return info
    return None


def detect_iso(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 0x8800:
        return None
    pvd = data[0x8000 : 0x8000 + 2048]
    if len(pvd) < 200:
        return None
    if pvd[0] == 1 and pvd[1:6] == b"CD001":
        vol_size = struct.unpack_from("<I", pvd, 80)[0]
        block_size = struct.unpack_from("<H", pvd, 128)[0] or 2048
        return {
            "format": "iso9660",
            "virtual_size": vol_size * block_size,
            "block_size": block_size,
            "volume_id": pvd[40:72].decode("ascii", errors="replace").strip(),
            "filesystem": "ISO 9660",
        }
    if pvd[1:6] in (b"NSR02", b"NSR03", b"BEA01"):
        return {"format": "udf", "filesystem": "UDF", "notes": "UDF volume descriptor found"}
    return None


def inspect_qcow2(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 72 or data[0:4] != b"QFI\xfb":
        return None
    version = struct.unpack_from(">I", data, 4)[0]
    if version not in (2, 3):
        return None
    virtual_size = struct.unpack_from(">Q", data, 24)[0]
    cluster_bits = struct.unpack_from(">I", data, 20)[0]
    return {
        "format": "qcow2",
        "version": version,
        "virtual_size": virtual_size,
        "cluster_size": 1 << cluster_bits if 9 <= cluster_bits <= 21 else None,
        "sparse": True,
        "notes": "Copy-on-write sparse format. Guest LBA 0 is not at file offset 0.",
    }


def inspect_vhd(data: bytes, file_size: int) -> Optional[Dict[str, Any]]:
    if data.startswith(b"conectix") and len(data) >= 48:
        virtual_size = struct.unpack_from(">Q", data, 40)[0]
        return {
            "format": "vhd",
            "variant": "dynamic",
            "virtual_size": virtual_size,
            "sparse": True,
            "notes": "Dynamic VHD. Footer also present at end.",
        }
    return None


def inspect_vhdx(data: bytes) -> Optional[Dict[str, Any]]:
    if not data.startswith(b"vhdxfile"):
        return None
    return {
        "format": "vhdx",
        "sparse": True,
        "notes": "VHDX identified. Virtual size is in metadata region.",
    }


def inspect_vdi(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 0x180:
        return None
    magic = struct.unpack_from("<I", data, 0x40)[0]
    if magic != 0xBEDA107F:
        return None
    virtual_size = struct.unpack_from("<Q", data, 0x170)[0]
    img_type = struct.unpack_from("<I", data, 0x4C)[0] if len(data) > 0x50 else 0
    sparse = img_type == 1
    return {
        "format": "vdi",
        "virtual_size": virtual_size,
        "image_type": img_type,
        "sparse": sparse,
        "notes": "VirtualBox VDI. Type 1 = dynamic (sparse), 2 = fixed.",
    }


def inspect_vmdk(data: bytes) -> Optional[Dict[str, Any]]:
    if data.startswith(b"KDMV") and len(data) >= 32:
        capacity_sectors = struct.unpack_from("<Q", data, 16)[0]
        return {
            "format": "vmdk",
            "variant": "sparse_header",
            "virtual_size": capacity_sectors * 512,
            "sparse": True,
            "notes": "VMDK sparse header. Descriptor may follow.",
        }
    if data.startswith(b"# Disk DescriptorFile") or b"createType=" in data[:512]:
        return {
            "format": "vmdk",
            "variant": "descriptor",
            "sparse": True,
            "notes": "VMDK text descriptor. Capacity often in DDB or extent lines.",
        }
    return None


def scan_volume_indicators(vol_data: bytes, max_scan: int = 8 * 1024 * 1024) -> Dict[str, Any]:
    """
    Lightweight scan of accessible volume data for OS/role indicators
    and interesting paths (Users, /home, Docker).

    Works on the raw bytes of a volume (or partition start) that falls
    inside the 64 MiB window. Uses string / UTF-16 searches rather than
    full filesystem parsers.
    """
    if not vol_data:
        return {}

    scan = vol_data[:max_scan]
    result: Dict[str, Any] = {
        "os_hint": None,
        "role": None,
        "users": [],
        "docker": [],
        "interesting_paths": [],
        "confidence": "low",
    }

    # Prefer UTF-16LE (common in NTFS) and ASCII
    def extract_utf16_strings(data: bytes, min_len: int = 4) -> List[str]:
        strings = []
        i = 0
        while i < len(data) - 1:
            if data[i + 1] == 0 and 32 <= data[i] < 127:
                start = i
                chars = []
                while i < len(data) - 1 and data[i + 1] == 0 and 32 <= data[i] < 127:
                    chars.append(chr(data[i]))
                    i += 2
                if len(chars) >= min_len:
                    strings.append("".join(chars))
            else:
                i += 1
        return strings

    utf16 = extract_utf16_strings(scan)
    ascii_text = scan.decode("ascii", errors="ignore")

    all_text = "\n".join(utf16) + "\n" + ascii_text

    # Windows indicators
    win_markers = [
        "Windows\\System32",
        "Windows\\System",
        "Program Files",
        "Program Files (x86)",
        "Users\\",
        "bootmgr",
        "NTLDR",
        "pagefile.sys",
        "hiberfil.sys",
    ]
    win_hits = sum(1 for m in win_markers if m.lower() in all_text.lower())

    # Linux indicators
    linux_markers = [
        "/etc/",
        "/home/",
        "/usr/",
        "/var/",
        "/boot/",
        "lost+found",
        "bin/bash",
        "etc/passwd",
        "etc/fstab",
    ]
    linux_hits = sum(1 for m in linux_markers if m in all_text or m.encode() in scan)

    if win_hits >= 2:
        result["os_hint"] = "windows"
        result["confidence"] = "medium" if win_hits >= 3 else "low"
    elif linux_hits >= 2:
        result["os_hint"] = "linux"
        result["confidence"] = "medium" if linux_hits >= 3 else "low"

    # Role
    if result["os_hint"] == "windows":
        if any(x in all_text for x in ("Windows\\System32", "bootmgr", "NTLDR", "pagefile.sys")):
            result["role"] = "system"
        elif "Users\\" in all_text or "Program Files" in all_text:
            result["role"] = "system_or_data"
        else:
            result["role"] = "data"
    elif result["os_hint"] == "linux":
        if any(x in all_text for x in ("/etc/", "/boot/", "lost+found", "bin/bash")):
            result["role"] = "system"
        elif "/home/" in all_text or "/var/" in all_text:
            result["role"] = "system_or_data"
        else:
            result["role"] = "data"

    # Extract potential usernames
    import re
    # Windows Users\<name>
    for m in re.finditer(r"Users\\([A-Za-z0-9_.\- ]{1,32})", all_text, re.IGNORECASE):
        name = m.group(1).strip(" \\/")
        if name and name.lower() not in ("public", "default", "all users", "default user") and name not in result["users"]:
            result["users"].append(name)
    # Linux /home/<name>
    for m in re.finditer(r"/home/([a-zA-Z0-9_.\-]{1,32})", all_text):
        name = m.group(1)
        if name and name not in ("lost+found",) and name not in result["users"]:
            result["users"].append(name)

    # Docker paths
    docker_paths = [
        "/var/lib/docker",
        "/var/lib/docker/overlay2",
        "/var/lib/docker/containers",
        "/var/lib/docker/image",
        "/var/lib/docker/volumes",
        "docker\\overlay2",
        "ProgramData\\Docker",
    ]
    for p in docker_paths:
        if p.lower() in all_text.lower():
            result["docker"].append(p)

    # Collect a few interesting paths (deduped, limited)
    interesting = set()
    for pat in (
        r"Users\\[A-Za-z0-9_.\- ]+",
        r"/home/[a-zA-Z0-9_.\-]+",
        r"/var/lib/docker[^\s\\]{0,40}",
        r"Windows\\[A-Za-z0-9_.\\ ]+",
        r"Program Files[^\\]{0,20}",
        r"/etc/[a-zA-Z0-9_.\-]+",
        r"/var/[a-zA-Z0-9_.\-]+",
    ):
        for m in re.finditer(pat, all_text, re.IGNORECASE):
            interesting.add(m.group(0)[:80])
            if len(interesting) >= 20:
                break
        if len(interesting) >= 20:
            break
    result["interesting_paths"] = sorted(interesting)[:15]

    if result["users"] or result["docker"] or result["os_hint"]:
        result["confidence"] = "medium" if (result["users"] or result["docker"]) else result["confidence"]

    return result


def inspect_disk(path: str) -> Dict[str, Any]:
    data, file_size = read_header(path)

    result: Dict[str, Any] = {
        "path": path,
        "file_size": file_size,
        "bytes_read": len(data),
        "format": "unknown",
        "virtual_size": None,
        "sparse": None,
        "partitions": [],
        "volumes": [],
        "filesystems": [],
        "encryption": None,
        "lvm": None,
        "notes": [],
        "early_file_hints": [],
        "volume_summaries": [],
        "version": "2.1",
    }

    # Container format detection
    for inspector in (
        inspect_qcow2,
        inspect_vdi,
        inspect_vmdk,
        inspect_vhdx,
        lambda d: inspect_vhd(d, file_size),
    ):
        info = inspector(data)
        if info:
            # Container inspectors return "notes" as a string; keep the list.
            note = info.pop("notes", None)
            result.update(info)
            if note:
                result["notes"].append(note)
            result["format"] = info["format"]
            break

    # ISO
    iso_info = detect_iso(data)
    if iso_info:
        result.update(iso_info)
        result["format"] = iso_info.get("format", "iso")
        result["sparse"] = False
        if "filesystem" in iso_info:
            result["filesystems"].append(iso_info)

    # Raw / partition table
    has_pt = False
    if result["format"] in ("unknown", "raw") or is_mbr(data) or is_gpt(data):
        if result["format"] == "unknown":
            result["format"] = "raw"
            result["virtual_size"] = file_size
            result["notes"].append("No container magic found; treated as raw disk image or single-volume image.")

        if is_gpt(data):
            result["partition_table"] = "GPT"
            result["partitions"] = parse_gpt(data)
            has_pt = True
            result["notes"].append("GPT protective MBR + EFI PART signature detected.")
        elif is_mbr(data):
            result["partition_table"] = "MBR"
            result["partitions"] = parse_mbr(data)
            has_pt = True
            result["notes"].append("MBR signature (0x55AA) detected.")

        if result["partitions"]:
            result["volumes"] = [
                {
                    "index": p["index"],
                    "type": p.get("type_name") or p.get("name"),
                    "size": p["size_bytes"],
                    "start_bytes": p.get("start_bytes"),
                }
                for p in result["partitions"]
            ]

    # Filesystem / encryption / LVM detection
    # 1. On the whole image (single partition / raw volume case)
    if not has_pt or result["format"] == "raw":
        fs = detect_filesystem(data, 0)
        if fs:
            result["filesystems"].append({"location": "offset 0 (raw/single-volume)", **fs})
            if "encryption" in fs:
                result["encryption"] = fs
            if fs.get("type") == "lvm_pv":
                result["lvm"] = fs

        lvm = detect_lvm(data)
        if lvm and not result["lvm"]:
            result["lvm"] = lvm
            result["filesystems"].append({"location": f"offset {lvm['label_offset']}", **lvm})
            result["notes"].append(lvm["notes"])

    # 2. Inside partitions (if their start is within the window)
    for p in result.get("partitions", []):
        start = p.get("start_bytes", 0)
        if 0 < start < len(data) - 512:
            fs = detect_filesystem(data, start)
            if fs:
                entry = {"location": f"partition {p['index']} @ LBA {p['start_lba']}", **fs}
                result["filesystems"].append(entry)
                if "encryption" in fs and not result["encryption"]:
                    result["encryption"] = fs

    # Lightweight volume content scan for OS / role / paths
    # Only when we have accessible volume data inside the window
    scan_targets = []
    if not has_pt and result["format"] == "raw":
        scan_targets.append(("offset 0 (raw/single-volume)", data))
    for p in result.get("partitions", []):
        start = p.get("start_bytes", 0)
        if 0 < start < len(data) - 4096:
            end = min(start + 8 * 1024 * 1024, len(data))
            scan_targets.append(
                (f"partition {p['index']} @ LBA {p['start_lba']}", data[start:end])
            )

    for loc, vol_bytes in scan_targets:
        # Skip obviously encrypted volumes
        is_encrypted = any(
            "encryption" in f and loc.split("@")[0].strip() in f.get("location", "")
            for f in result["filesystems"]
        )
        if is_encrypted:
            result["volume_summaries"].append(
                {"location": loc, "note": "Encrypted volume — content scan skipped"}
            )
            continue
        summary = scan_volume_indicators(vol_bytes)
        if summary and (summary.get("os_hint") or summary.get("users") or summary.get("docker")):
            summary["location"] = loc
            result["volume_summaries"].append(summary)
            if summary.get("os_hint") and not result.get("os_hint"):
                result["os_hint"] = summary["os_hint"]
                result["volume_role"] = summary.get("role")

    # Sparse determination
    if result["sparse"] is None and result["virtual_size"]:
        result["sparse"] = file_size < result["virtual_size"] * 0.95
        if result["sparse"]:
            result["notes"].append("File size much smaller than virtual size → sparse/dynamic.")
        else:
            result["notes"].append("File size close to virtual size → thick/fixed.")

    result["current_size"] = file_size
    result["max_size"] = result.get("virtual_size") or file_size

    if result["format"] in ("iso9660", "iso", "udf"):
        result["notes"].append(
            "ISO/UDF: root directory records can be parsed from the Primary Volume Descriptor for a file list."
        )
        result["early_file_hints"].append("Root directory location is in PVD.")

    if result["format"] in ("qcow2", "vhd", "vhdx", "vdi", "vmdk"):
        result["notes"].append(
            "Container format: first 64 MiB contains headers/tables. "
            "Guest partitions and filesystems live at virtual offsets requiring mapping."
        )

    if not result["filesystems"] and result["format"] == "raw" and not has_pt:
        result["notes"].append(
            "No filesystem or partition signature found in the first 64 MiB. "
            "May be empty, encrypted without a clear header, or data starts later."
        )

    return result


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python disk_inspector_v2.1.py <image-file>", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)
    info = inspect_disk(path)
    print(json.dumps(info, indent=2, default=str))


if __name__ == "__main__":
    main()
