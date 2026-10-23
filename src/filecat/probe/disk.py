"""Disk images: QCOW2, VHD, VHDX, VDI, VMDK, raw images with a partition table
or volume boot sector, and ISO 9660 / UDF discs.

Everything is read with small targeted seeks (headers, a few sectors, mapping
tables), never the first N MiB: files are often on SMB. Containers get a guest
reader (diskio) so the same partition / filesystem detection runs on raw and
virtual disks. Partitions become member rows (role "volume"); ISO files become
member rows by name. Based on the disk_inspector v2.1 reference script
(contrib/disk_inspector), with its container-layout bugs fixed.

See file-catalog-requirements.md, "Probe order" step 4b.
"""
from __future__ import annotations

import struct
from typing import Any

from ..options import ScanOptions
from ..fsource import fopen
from ..record import suffix_of
from . import diskfs, diskio, diskscan, iso, members, udf

_SUFFIXES = frozenset(("iso", "img", "ima", "dd", "raw", "vhd", "vhdx", "vmdk", "vdi",
                       "qcow", "qcow2", "hdd", "udf", "squashfs", "sfs"))
_VDI_MAGIC = 0xBEDA107F
_MAX_SCANNED_VOLUMES = 8
_NO_SCAN = ("swap", "lvm", "squashfs")
_DESC_CAP = 64 * 1024


def _magic(head: bytes, name: str, size: int) -> str | None:
    """Container or volume magic in the head, or None."""
    if head[:4] == b"QFI\xfb":
        return "qcow2"
    if head[:8] == b"conectix":
        return "vhd"
    if head[:8] == b"vhdxfile":
        return "vhdx"
    if head[:4] == b"KDMV":
        return "vmdk"
    if head.startswith(b"# Disk DescriptorFile") or (
            suffix_of(name) == "vmdk" and size <= _DESC_CAP and b"createType=" in head[:1024]):
        return "vmdk-text"
    if len(head) >= 0x44 and struct.unpack_from("<I", head, 0x40)[0] == _VDI_MAGIC:
        return "vdi"
    if head[:6] == b"LUKS\xba\xbe" or head[3:11] == b"-FVE-FS-" or head[:4] == b"hsqs":
        return "volume"
    return None


def _strong_signature(head: bytes, size: int) -> bool:
    """A whole-disk signature that is unlikely in anything else."""
    if len(head) < 512 or head[510:512] != b"\x55\xaa":
        return False
    if head[512:520] == b"EFI PART" and head[450] == 0xEE:
        return True
    if head[4096:4104] == b"EFI PART" and head[450] == 0xEE:
        return True
    if head[3:11] in (b"NTFS    ", b"EXFAT   "):
        return True
    return diskfs.mbr_is_strong(head[:512], size)


def probe_disk(path: str, name: str, size: int, head: bytes, opts: ScanOptions, result: Any) -> bool:
    """Fill `result` and return True when the file is a disk image; return
    False (touching nothing but errors) when it is not, so dispatch continues."""
    magic = _magic(head, name, size)
    if not (magic or suffix_of(name) in _SUFFIXES or _strong_signature(head, size)):
        return False
    try:
        with fopen(path, "rb") as f:
            io = diskio.Io(f, size)
            rep = _inspect(io, head, name, magic, opts)
            if rep is not None:
                rep["bytes_read"] = io.bytes_read
    except Exception as exc:
        result.errors.append({"stage": "disk", "message": f"{type(exc).__name__}: {exc}"})
        if magic and magic != "volume":
            result.kind, result.container = "disk", "plain"
            return True
        return False
    if rep is None:
        return False
    _apply(rep, result, opts)
    return True


def _apply(rep: dict[str, Any], result: Any, opts: ScanOptions) -> None:
    rows = rep.pop("members", None)
    truncated = rep.pop("members_truncated", False)
    result.kind, result.container = "disk", "plain"
    result.probe.update({k: v for k, v in rep.items() if v is not None and v != [] and v != {}})
    if rows is not None:
        result.members = rows
        result.probe.update(members.summarize(rows, truncated=truncated, list_cap=opts.list_zip_cap))


# --- container / raw --------------------------------------------------

def _open(io: diskio.Io, head: bytes, magic: str | None) -> tuple[dict[str, Any], diskio.Guest | None]:
    if magic == "qcow2":
        return diskio.parse_qcow2(io)
    if magic == "vhd":
        return diskio.parse_vhd(io, io.read_at(0, 512), False)
    if magic == "vhdx":
        return diskio.parse_vhdx(io)
    if magic == "vdi":
        return diskio.parse_vdi(io)
    if magic == "vmdk":
        return diskio.parse_vmdk_sparse(io)
    if magic == "vmdk-text":
        return diskio.parse_vmdk_text(io), None
    footer = diskio.vhd_footer_at_end(io)      # fixed VHD: raw data, footer only at the end
    if footer:
        return diskio.parse_vhd(io, footer, True)
    return ({"format": "raw", "virtual_size": io.size, "sparse": False},
            diskio.RawGuest(io, io.size))


def _inspect(io: diskio.Io, head: bytes, name: str, magic: str | None, opts: ScanOptions
             ) -> dict[str, Any] | None:
    info, guest = _open(io, head, magic)
    rep: dict[str, Any] = {"notes": list(info.pop("notes", []))}
    rep.update(info)
    is_raw = info["format"] == "raw"
    if "encryption_method" in info:
        rep["encryption"] = {"type": info["format"], "method": info["encryption_method"]}
    if guest is None:
        if not is_raw and "encryption" not in rep and not rep["notes"]:
            rep["notes"].append("guest disk not mapped")
        return rep
    found = _analyze(guest, io, head, rep, opts, is_raw)
    if getattr(guest, "unreadable", False):
        rep["notes"].append("compressed clusters not read")
    if not found:
        if is_raw:
            return None
        rep["notes"].append("no partition table or filesystem found in guest")
    return rep


# --- guest analysis ---------------------------------------------------

def _gpt_rows(g: Any, sector0: bytes) -> tuple[list[dict[str, Any]] | None, int]:
    if sector0[510:512] != b"\x55\xaa" or sector0[450] != 0xEE:
        return None, 0
    for sector_size in (512, 4096):
        if g.read(sector_size, 8) == b"EFI PART":
            return diskfs.parse_gpt(g, sector_size), sector_size
    return None, 0


def _analyze(g: Any, io: diskio.Io, head: bytes, rep: dict[str, Any], opts: ScanOptions,
             is_raw: bool) -> bool:
    if is_raw and io.size >= 0x8800:
        found = iso.read_descriptors(io)
        if found.get("pvd") or found.get("udf"):
            _fill_iso(io, head, found, rep, opts)
            return True
    sector0 = g.read(0, 512)
    gpt, sector_size = _gpt_rows(g, sector0)
    fs0 = diskfs.detect_filesystem(g, 0)
    if gpt is not None:
        rep["partition_table"] = "GPT"
        if sector_size == 4096:
            rep["notes"].append("4096-byte sector GPT")
        _fill_partitions(g, gpt, rep)
    elif fs0 is None and diskfs.mbr_is_strong(sector0, g.size):
        rep["partition_table"] = "MBR"
        _fill_partitions(g, diskfs.parse_mbr(g), rep)
    elif fs0 is not None:
        _fill_volumes(rep, [("offset 0", 0, fs0)])
        if fs0["type"] == "squashfs" and rep.get("format") == "raw":
            rep["format"] = "squashfs"
    else:
        return False
    if opts.disk_scan_cap > 0:
        _scan_volumes(g, rep, opts.disk_scan_cap)
    rep.pop("_volumes", None)
    return True


def _fill_volumes(rep: dict[str, Any], vols: list[tuple[str, int, dict[str, Any] | None]]) -> None:
    rep["_volumes"] = [v for v in vols if v[2]]
    rep["filesystems"] = [{"location": loc, **fs} for loc, _, fs in rep["_volumes"]]
    for loc, _, fs in rep["_volumes"]:
        if fs.get("type") == "lvm" and "lvm" not in rep:
            rep["lvm"] = {"location": loc, "pv_uuid": fs["pv_uuid"], "label_offset": fs["label_offset"]}
        if fs.get("encryption") and "encryption" not in rep:
            rep["encryption"] = {"location": loc, **fs}


def _member_row(i: int, p: dict[str, Any], fs: dict[str, Any] | None) -> dict[str, Any]:
    row: dict[str, Any] = {"index": i, "path": f"partition{p['number']}", "size": p["size"],
                           "offset": p["start"], "role": "volume"}
    if fs:
        row["format"] = fs["type"]
        if fs.get("label"):
            row["label"] = fs["label"]
    for key in ("type_name", "type_guid", "type_code", "name"):
        if p.get(key):
            row[key] = p[key]
    return row


def _fill_partitions(g: Any, parts: list[dict[str, Any]], rep: dict[str, Any]) -> None:
    rows, vols = [], []
    for i, p in enumerate(parts):
        fs = diskfs.detect_filesystem(g, p["start"]) if 0 < p["start"] < g.size else None
        rows.append(_member_row(i, p, fs))
        vols.append((f"partition{p['number']}", p["start"], fs))
    rep["members"] = rows
    _fill_volumes(rep, vols)


def _scan_volumes(g: Any, rep: dict[str, Any], cap: int) -> None:
    summaries = []
    for loc, start, fs in rep["_volumes"][:_MAX_SCANNED_VOLUMES]:
        if fs.get("encryption"):
            summaries.append({"location": loc, "note": "encrypted volume — content scan skipped"})
            continue
        if fs["type"] in _NO_SCAN:
            continue
        summary = diskscan.scan_volume(g, start, fs, cap)
        if summary:
            summaries.append({"location": loc, **summary})
            if summary.get("os_hint") and "os_hint" not in rep:
                rep["os_hint"], rep["volume_role"] = summary["os_hint"], summary.get("role")
    rep["volume_summaries"] = summaries


# --- ISO --------------------------------------------------------------

def _fill_iso(io: diskio.Io, head: bytes, found: dict[str, Any], rep: dict[str, Any],
              opts: ScanOptions) -> None:
    info = iso.describe(found)
    rep.update(info)
    rep["virtual_size"] = info.get("virtual_size") or io.size
    rep["sparse"] = False
    name = "ISO 9660" if info["format"] == "iso9660" else "UDF"
    rep["filesystems"] = [{"location": "offset 0", "type": info["format"], "filesystem": name,
                           **({"volume_id": info["volume_id"]} if info.get("volume_id") else {})}]
    if head[512:520] == b"EFI PART":
        rep["hybrid"], rep["partition_table"] = True, "GPT"
    elif diskfs.mbr_is_strong(head[:512], io.size):
        rep["hybrid"], rep["partition_table"] = True, "MBR"
    rows, truncated = [], False
    if found.get("pvd"):
        rows, truncated = iso.list_files(io, found, budget=opts.archive_scan_cap,
                                         max_members=opts.max_members)
        rep["listing"] = "iso9660"
    # A UDF bridge disc (Windows setup media) shows only a README through
    # ISO 9660; take whichever tree is larger.
    if found.get("udf"):
        listed = udf.list_files(io, budget=opts.archive_scan_cap, max_members=opts.max_members)
        if listed is not None:
            urows, utrunc, uinfo = listed
            rep.update(uinfo)
            if len(urows) > len(rows):
                rows, truncated, rep["listing"] = urows, utrunc, "udf"
    if found.get("pvd") or rows:
        rep["members"] = rows
        rep["members_truncated"] = truncated
