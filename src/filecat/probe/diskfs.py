"""Partition tables (MBR with extended chains, GPT) and filesystem / volume
signature detection at the start of a volume. All reads go through a guest
object with read(offset, n), so the same code serves raw files and mapped
container images; each call reads a few KiB at most.
"""
from __future__ import annotations

import struct
import uuid
from datetime import datetime, timedelta
from typing import Any

SECTOR = 512
_EXT_TYPES = (0x05, 0x0F, 0x85)
_MAX_LOGICAL = 64
_MAX_GPT_ENTRIES = 128

MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended", 0x06: "FAT16", 0x07: "NTFS/exFAT/HPFS",
    0x0B: "FAT32", 0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA", 0x0F: "Extended LBA",
    0x11: "Hidden FAT12", 0x14: "Hidden FAT16", 0x16: "Hidden FAT16", 0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32 LBA", 0x27: "Windows Recovery",
    0x82: "Linux swap", 0x83: "Linux", 0x85: "Linux extended", 0x8E: "Linux LVM",
    0xA5: "FreeBSD", 0xA6: "OpenBSD", 0xA9: "NetBSD", 0xAF: "HFS/HFS+", 0xEB: "BeOS",
    0xEE: "GPT Protective", 0xEF: "EFI System", 0xFB: "VMware VMFS", 0xFC: "VMware VMKCORE",
    0xFD: "Linux RAID",
}

GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "Linux RAID",
    "21686148-6449-6e6f-744e-656564454649": "BIOS boot",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "e75caf8f-f680-4cee-afa3-b001e56efc2d": "Microsoft Storage Spaces",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "LDM metadata",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "LDM data",
}


# --- partition tables -------------------------------------------------

def _mbr_slots(sector: bytes) -> list[dict[str, int]]:
    out = []
    for i in range(4):
        e = sector[446 + 16 * i:462 + 16 * i]
        start, count = struct.unpack_from("<II", e, 8)
        out.append({"status": e[0], "type": e[4], "start": start, "sectors": count})
    return out


def mbr_is_strong(sector: bytes, file_size: int) -> bool:
    """0x55AA plus at least one plausible partition entry."""
    if len(sector) < SECTOR or sector[510:512] != b"\x55\xaa":
        return False
    return any(s["status"] in (0, 0x80) and s["type"] and s["start"] > 0
               and s["start"] * SECTOR < file_size for s in _mbr_slots(sector))


def _mbr_row(number: int, lba: int, sectors: int, ptype: int) -> dict[str, Any]:
    return {"number": number, "start": lba * SECTOR, "size": sectors * SECTOR,
            "type_code": f"0x{ptype:02x}", "type_name": MBR_TYPES.get(ptype, "Unknown")}


def parse_mbr(g: Any) -> list[dict[str, Any]]:
    sector = g.read(0, SECTOR)
    rows = []
    for i, s in enumerate(_mbr_slots(sector)):
        if not s["type"] or s["type"] == 0xEE:
            continue
        if s["type"] in _EXT_TYPES:
            rows.extend(_logicals(g, s["start"]))
        else:
            rows.append(_mbr_row(i + 1, s["start"], s["sectors"], s["type"]))
    rows.sort(key=lambda r: r["number"])
    return rows


def _logicals(g: Any, ext_start: int) -> list[dict[str, Any]]:
    """Follow the EBR chain; each EBR holds one logical partition (relative to
    itself) and a link to the next EBR (relative to the extended start)."""
    out: list[dict[str, Any]] = []
    lba, seen = ext_start, set()
    while len(out) < _MAX_LOGICAL and lba not in seen:
        seen.add(lba)
        sector = g.read(lba * SECTOR, SECTOR)
        if len(sector) < SECTOR or sector[510:512] != b"\x55\xaa":
            break
        first, link = _mbr_slots(sector)[:2]
        if first["type"] and first["sectors"]:
            out.append(_mbr_row(5 + len(out), lba + first["start"], first["sectors"], first["type"]))
        if link["type"] not in _EXT_TYPES or not link["start"]:
            break
        lba = ext_start + link["start"]
    return out


def parse_gpt(g: Any, sector_size: int = SECTOR) -> list[dict[str, Any]] | None:
    hdr = g.read(sector_size, 92)
    if hdr[:8] != b"EFI PART":
        return None
    entry_lba, count, esz = struct.unpack_from("<QII", hdr, 72)
    if not 128 <= esz <= 1024 or esz % 8:
        return None
    raw = g.read(entry_lba * sector_size, min(count, _MAX_GPT_ENTRIES) * esz)
    rows = []
    for i in range(len(raw) // esz):
        e = raw[i * esz:(i + 1) * esz]
        if not any(e[:16]):
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        type_guid = str(uuid.UUID(bytes_le=bytes(e[:16])))
        row: dict[str, Any] = {
            "number": i + 1, "start": first * sector_size,
            "size": max(0, last - first + 1) * sector_size,
            "type_guid": type_guid.upper(), "type_name": GPT_TYPES.get(type_guid, "Unknown"),
        }
        name = e[56:esz].decode("utf-16-le", "replace").split("\x00")[0]
        if name:
            row["name"] = name
        rows.append(row)
    return rows


# --- filesystems ------------------------------------------------------

_ENC_METHODS = {
    0x8000: "AES-128-CBC+Elephant diffuser", 0x8001: "AES-256-CBC+Elephant diffuser",
    0x8002: "AES-128-CBC", 0x8003: "AES-256-CBC", 0x8004: "AES-128-XTS", 0x8005: "AES-256-XTS",
}
_BL_GUID = bytes.fromhex("3bd66749292ed84a8399f6a339e3d001")


def _text(b: bytes) -> str:
    return b.split(b"\x00")[0].decode("ascii", "replace").strip()


def _guid_le(b: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(b)))


def _ntfs(vol: bytes) -> dict[str, Any]:
    bps, spc = struct.unpack_from("<HB", vol, 0x0B)
    total, mft = struct.unpack_from("<QQ", vol, 0x28)
    serial = struct.unpack_from("<Q", vol, 0x48)[0]
    cpr = struct.unpack_from("<b", vol, 0x40)[0]     # >0 clusters per record, <0 is 2**-n bytes
    return {"type": "ntfs", "mft_record_size": cpr * bps * spc if cpr > 0 else 1 << -cpr, "filesystem": "NTFS", "volume_serial": f"{serial:016X}",
            "bytes_per_sector": bps, "sectors_per_cluster": spc,
            "total_sectors": total, "mft_cluster": mft}


def _fat(vol: bytes) -> dict[str, Any] | None:
    if vol[510:512] != b"\x55\xaa":
        return None
    bps, spc = struct.unpack_from("<HB", vol, 0x0B)
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or spc & (spc - 1):
        return None
    if vol[0x52:0x5A] == b"FAT32   " and struct.unpack_from("<H", vol, 0x16)[0] == 0:
        kind, ser_off, lab_off = "fat32", 0x43, 0x47
    elif vol[0x36:0x3B] in (b"FAT12", b"FAT16", b"FAT  "):
        kind = {b"FAT12": "fat12", b"FAT16": "fat16"}.get(vol[0x36:0x3B], "fat")
        ser_off, lab_off = 0x27, 0x2B
    else:
        return None
    label = vol[lab_off:lab_off + 11].decode("ascii", "replace").strip()
    out = {"type": kind, "filesystem": kind.upper(), "bytes_per_sector": bps,
           "volume_serial": f"{struct.unpack_from('<I', vol, ser_off)[0]:08X}"}
    if label and label != "NO NAME":
        out["label"] = label
    return out


def _ext(vol: bytes) -> dict[str, Any] | None:
    if len(vol) < 0x500 or struct.unpack_from("<H", vol, 0x438)[0] != 0xEF53:
        return None
    log_bs = struct.unpack_from("<I", vol, 0x418)[0]
    rev = struct.unpack_from("<I", vol, 0x44C)[0]
    if log_bs > 6 or rev not in (0, 1):
        return None
    compat, incompat = struct.unpack_from("<II", vol, 0x45C)
    fs = "ext4" if incompat & 0x40 else ("ext3" if compat & 0x4 else "ext2")
    out = {"type": "ext", "filesystem": fs, "block_size": 1024 << log_bs,
           "uuid": str(uuid.UUID(bytes=bytes(vol[0x468:0x478])))}
    label = _text(vol[0x478:0x488])
    if label:
        out["label"] = label
    return out


def _luks(vol: bytes) -> dict[str, Any]:
    version = struct.unpack_from(">H", vol, 6)[0]
    out: dict[str, Any] = {"type": "luks", "filesystem": f"LUKS{version}",
                           "encryption": f"LUKS v{version}", "version": version,
                           "uuid": _text(vol[168:208])}
    if version == 1:
        out["cipher"] = _text(vol[8:40])
        out["cipher_mode"] = _text(vol[40:72])
        out["hash"] = _text(vol[72:104])
    elif version == 2:
        out["checksum_alg"] = _text(vol[72:104])
        label = _text(vol[24:72])
        if label:
            out["label"] = label
    return out


def _lvm(vol: bytes) -> dict[str, Any] | None:
    for i in range(4):
        s = vol[i * SECTOR:(i + 1) * SECTOR]
        if s[:8] == b"LABELONE" and s[24:32] == b"LVM2 001":
            raw = s[32:64].decode("ascii", "replace")
            parts, pos = [], 0
            for n in (6, 4, 4, 4, 4, 4, 6):
                parts.append(raw[pos:pos + n])
                pos += n
            return {"type": "lvm", "filesystem": "LVM2 PV", "pv_uuid": "-".join(parts),
                    "label_offset": i * SECTOR}
    return None


def _filetime(ft: int) -> str | None:
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
    except OverflowError:
        return None
    return dt.isoformat() + "Z" if 1990 <= dt.year <= 2100 else None


def _fve_metadata(g: Any, off: int, vol: bytes) -> dict[str, Any]:
    """FVE metadata block (libbde layout): located by the three u64 offsets
    in the boot sector, relative to the volume start."""
    for pos in struct.unpack_from("<QQQ", vol, 0xB0):
        if not pos or pos >= g.size - off:
            continue
        blk = g.read(off + pos, 128)
        if blk[:8] != b"-FVE-FS-":
            continue
        out: dict[str, Any] = {"fve_version": struct.unpack_from("<H", blk, 10)[0],
                               "volume_guid": _guid_le(blk[64 + 16:64 + 32])}
        method = struct.unpack_from("<H", blk, 64 + 36)[0]
        out["encryption_method"] = _ENC_METHODS.get(method, f"0x{method:04x}")
        created = _filetime(struct.unpack_from("<Q", blk, 64 + 40)[0])
        if created:
            out["created"] = created
        return out
    return {}


def _bitlocker(g: Any, off: int, vol: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "bitlocker", "filesystem": "BitLocker",
                           "encryption": "BitLocker", "identifier_guid": _guid_le(vol[160:176])}
    out.update(_fve_metadata(g, off, vol))
    out["notes"] = "FVE metadata per libbde layout"
    return out


def _small_fs(vol: bytes) -> dict[str, Any] | None:
    if vol[:4] == b"XFSB":
        bs = struct.unpack_from(">I", vol, 4)[0]
        if bs >= 512 and not bs & (bs - 1):
            out = {"type": "xfs", "filesystem": "XFS", "block_size": bs,
                   "uuid": str(uuid.UUID(bytes=bytes(vol[32:48])))}
            label = _text(vol[108:120])
            if label:
                out["label"] = label
            return out
    if vol[1024:1026] in (b"H+", b"HX"):
        return {"type": "hfsplus", "filesystem": "HFSX" if vol[1024:1026] == b"HX" else "HFS+"}
    if vol[32:36] == b"NXSB":
        return {"type": "apfs", "filesystem": "APFS"}
    if vol[:4] == b"hsqs":
        return _squashfs(vol)
    if len(vol) >= 0x1000 and vol[0xFF6:0x1000] == b"SWAPSPACE2":
        out = {"type": "swap", "filesystem": "Linux swap", "uuid": str(uuid.UUID(bytes=bytes(vol[1036:1052])))}
        label = _text(vol[1052:1068])
        if label:
            out["label"] = label
        return out
    return None


_SQUASH_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def _squashfs(vol: bytes) -> dict[str, Any] | None:
    """SquashFS 4.x superblock (little-endian 'hsqs'); live CDs ship one as *.img."""
    inodes, mkfs_time, block_size = struct.unpack_from("<III", vol, 4)
    comp, block_log = struct.unpack_from("<HH", vol, 20)
    major, minor = struct.unpack_from("<HH", vol, 28)
    if major != 4 or block_size != 1 << block_log:
        return None
    return {"type": "squashfs", "filesystem": f"SquashFS {major}.{minor}", "inodes": inodes,
            "block_size": block_size, "compression": _SQUASH_COMP.get(comp, str(comp)),
            "bytes_used": struct.unpack_from("<Q", vol, 40)[0], "created": mkfs_time}


def _btrfs(g: Any, off: int) -> dict[str, Any] | None:
    sb = g.read(off + 0x10000, 0x12B + 256)
    if sb[0x40:0x48] != b"_BHRfS_M":
        return None
    out = {"type": "btrfs", "filesystem": "Btrfs", "uuid": str(uuid.UUID(bytes=bytes(sb[0x20:0x30])))}
    label = _text(sb[0x12B:0x12B + 256])
    if label:
        out["label"] = label
    return out


def detect_filesystem(g: Any, off: int) -> dict[str, Any] | None:
    """Filesystem / volume type starting at `off` (4 KiB read, plus 8 KiB-ish
    for a Btrfs superblock when nothing else matched)."""
    vol = g.read(off, 4096)
    if len(vol) < SECTOR:
        return None
    if vol[3:11] == b"-FVE-FS-":
        return _bitlocker(g, off, vol)
    if vol[3:11] == b"NTFS    ":
        return _ntfs(vol)
    if vol[3:11] == b"EXFAT   ":
        return {"type": "exfat", "filesystem": "exFAT",
                "volume_serial": f"{struct.unpack_from('<I', vol, 100)[0]:08X}"}
    if vol[3:11] == b"ReFS\x00\x00\x00\x00":
        return {"type": "refs", "filesystem": "ReFS"}
    if vol[:6] == b"LUKS\xba\xbe":
        return _luks(vol)
    if _BL_GUID in vol[:SECTOR]:
        return {"type": "bitlocker_to_go", "filesystem": "BitLocker To Go",
                "encryption": "BitLocker To Go", "identifier_guid": _guid_le(_BL_GUID)}
    return _fat(vol) or _ext(vol) or _lvm(vol) or _small_fs(vol) or _btrfs(g, off)
