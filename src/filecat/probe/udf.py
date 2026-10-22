"""UDF (ECMA-167 / OSTA UDF) directory listing.

Windows install media and many game images are "UDF bridge" or UDF-only:
the ISO 9660 view holds a README while the real tree lives here. Reads the
anchor, the volume descriptor sequence, the file set descriptor, then each
directory's File Entry and FID stream, and one File Entry per file for its
size. File data is never read. Type 1 partition maps and the UDF 2.5+
metadata partition are mapped; virtual (VAT) and sparable maps are reported
but not listed.
"""
from __future__ import annotations

import struct
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import members
from .diskio import Io

_SECTOR = 2048
_ANCHOR_LBA = 256
_MAX_VDS = 64
_CHUNK = 64 * 1024
_MAX_CHUNKS = 64

TAG_PD, TAG_LVD, TAG_TD, TAG_FSD, TAG_FID, TAG_FE, TAG_EFE = 5, 6, 8, 256, 257, 261, 266


class _Blocks:
    """Cached 64 KiB reads; File Entries of one directory sit next to each other."""

    def __init__(self, io: Io) -> None:
        self.io = io
        self.cache: dict[int, bytes] = {}

    def read(self, off: int, n: int) -> bytes:
        if n > _CHUNK:
            return self.io.read_at(off, n)
        base = off - off % _CHUNK
        if off + n > base + _CHUNK:
            return self.io.read_at(off, n)
        chunk = self.cache.get(base)
        if chunk is None:
            if len(self.cache) >= _MAX_CHUNKS:
                self.cache.clear()
            chunk = self.cache[base] = self.io.read_at(base, _CHUNK)
        return chunk[off - base:off - base + n]


def _tag(b: bytes) -> int | None:
    """Descriptor tag id after the tag checksum (byte 4 = sum of bytes 0-3, 5-15)."""
    if len(b) < 16 or (sum(b[0:4]) + sum(b[5:16])) & 0xFF != b[4]:
        return None
    return struct.unpack_from("<H", b, 0)[0]


def _dstring(b: bytes) -> str:
    """dstring: last byte is the used length."""
    used = b[-1] if b else 0
    return _dchars(b[:used])


def _dchars(b: bytes) -> str:
    if not b:
        return ""
    if b[0] == 16:
        return b[1:].decode("utf-16-be", "replace")
    if b[0] == 8:
        return b[1:].decode("latin-1")
    return b[1:].decode("latin-1", "replace")


def _timestamp_ns(b: bytes) -> int | None:
    tz_type, year = struct.unpack_from("<HH", b, 0)
    month, day, hour, minute, second = b[4:9]
    tz = tz_type & 0xFFF
    if tz & 0x800:
        tz -= 0x1000
    if tz == -2047 or tz_type >> 12 != 1:
        tz = 0
    try:
        dt = datetime(year, month, day, hour, minute, second,
                      tzinfo=timezone(timedelta(minutes=tz)))
        return int(dt.timestamp()) * 10**9
    except (ValueError, OverflowError, OSError):
        return None


class _Volume:
    def __init__(self, blocks: _Blocks, block: int, starts: dict[int, int],
                 maps: list[tuple[str, int]]) -> None:
        self.b = blocks
        self.block = block
        self.starts = starts            # partition number -> start sector
        self.maps = maps                # partition ref -> (kind, partition number)
        self.meta: list[tuple[int, int, int]] = []   # (lbn_from, count, physical lbn)

    def physical(self, ref: int, lbn: int) -> int | None:
        if ref >= len(self.maps):
            return None
        kind, number = self.maps[ref]
        start = self.starts.get(number)
        if start is None:
            return None
        if kind == "type1":
            return (start + lbn) * self.block
        if kind == "metadata":
            for first, count, phys in self.meta:
                if first <= lbn < first + count:
                    return (start + phys + lbn - first) * self.block
        return None

    def read(self, ref: int, lbn: int, n: int) -> bytes:
        off = self.physical(ref, lbn)
        return b"" if off is None else self.b.read(off, n)


def _entry(vol: _Volume, ref: int, lbn: int) -> dict[str, Any] | None:
    """File Entry or Extended File Entry: type, size, mtime, allocation."""
    fe = vol.read(ref, lbn, vol.block)
    tag = _tag(fe)
    if tag not in (TAG_FE, TAG_EFE):
        return None
    file_type = fe[27]
    flags = struct.unpack_from("<H", fe, 34)[0]
    size = struct.unpack_from("<Q", fe, 56)[0]
    if tag == TAG_FE:
        mtime, l_ea, l_ad, ad_at = fe[84:96], *struct.unpack_from("<II", fe, 168), 176
    else:
        mtime, l_ea, l_ad, ad_at = fe[92:104], *struct.unpack_from("<II", fe, 208), 216
    ads = fe[ad_at + l_ea:ad_at + l_ea + l_ad]
    return {"file_type": file_type, "ad_type": flags & 7, "size": size,
            "mtime": mtime, "ads": ads, "ref": ref}


def _extents(ent: dict[str, Any]) -> list[tuple[int, int, int]]:
    """(partition ref, lbn, bytes) of recorded extents."""
    ads, out = ent["ads"], []
    if ent["ad_type"] == 0:
        for i in range(0, len(ads) - 7, 8):
            length, pos = struct.unpack_from("<II", ads, i)
            if length >> 30 == 0 and length & 0x3FFFFFFF:
                out.append((ent["ref"], pos, length & 0x3FFFFFFF))
    elif ent["ad_type"] == 1:
        for i in range(0, len(ads) - 15, 16):
            length, pos, ref = struct.unpack_from("<IIH", ads, i)
            if length >> 30 == 0 and length & 0x3FFFFFFF:
                out.append((ref, pos, length & 0x3FFFFFFF))
    return out


def _data(vol: _Volume, ent: dict[str, Any], cap: int) -> bytes:
    if ent["ad_type"] == 3:                  # embedded in the entry itself
        return ent["ads"][:ent["size"]]
    parts, total = [], 0
    for ref, lbn, length in _extents(ent):
        length = min(length, cap - total)
        if length <= 0:
            break
        parts.append(vol.read(ref, lbn, length))
        total += length
    return b"".join(parts)[:ent["size"]]


def _fids(data: bytes):
    """(name, is_dir, icb_lbn, icb_ref) for each live, non-parent identifier."""
    pos = 0
    while pos + 38 <= len(data):
        if _tag(data[pos:pos + 16]) != TAG_FID:
            break
        chars, l_fi = data[pos + 18], data[pos + 19]
        _, lbn, ref = struct.unpack_from("<IIH", data, pos + 20)
        l_iu = struct.unpack_from("<H", data, pos + 36)[0]
        name_at = pos + 38 + l_iu
        if not chars & 0x0C:                 # not deleted, not the parent entry
            yield _dchars(data[name_at:name_at + l_fi]), bool(chars & 2), lbn, ref
        pos += (38 + l_iu + l_fi + 3) & ~3


def _volume(io: Io) -> tuple[_Volume, dict[str, Any], tuple[int, int, int]] | None:
    blocks = _Blocks(io)
    avdp = blocks.read(_ANCHOR_LBA * _SECTOR, 512)
    if _tag(avdp) != 2:
        return None
    vds_len, vds_loc = struct.unpack_from("<II", avdp, 16)
    starts: dict[int, int] = {}
    lvd = None
    for i in range(min(vds_len // _SECTOR, _MAX_VDS)):
        d = blocks.read((vds_loc + i) * _SECTOR, _SECTOR)
        tag = _tag(d)
        if tag == TAG_PD:
            starts[struct.unpack_from("<H", d, 22)[0]] = struct.unpack_from("<I", d, 188)[0]
        elif tag == TAG_LVD and lvd is None:
            lvd = d
        elif tag == TAG_TD or tag is None:
            break
    if lvd is None or not starts:
        return None
    block = struct.unpack_from("<I", lvd, 212)[0] or _SECTOR
    info: dict[str, Any] = {"udf_volume_id": _dstring(lvd[84:212])}
    nmaps = struct.unpack_from("<I", lvd, 268)[0]
    maps, meta_file, pos = [], None, 440
    for _ in range(min(nmaps, 8)):
        mtype, mlen = lvd[pos], lvd[pos + 1]
        if mtype == 1:
            maps.append(("type1", struct.unpack_from("<H", lvd, pos + 4)[0]))
        elif mtype == 2:
            ident = lvd[pos + 5:pos + 28].rstrip(b"\x00")
            number = struct.unpack_from("<H", lvd, pos + 38)[0]
            if ident == b"*UDF Metadata Partition":
                maps.append(("metadata", number))
                meta_file = struct.unpack_from("<I", lvd, pos + 40)[0]
            else:
                maps.append((ident.decode("latin-1", "replace").lstrip("*"), number))
        pos += mlen or 6
    vol = _Volume(blocks, block, starts, maps)
    kinds = sorted({k for k, _ in maps if k != "type1"})
    if kinds:
        info["udf_partition_maps"] = kinds
    if meta_file is not None:
        number = next(n for k, n in maps if k == "metadata")
        ref1 = next((i for i, (k, n) in enumerate(maps) if k == "type1" and n == number), None)
        ent = _entry(vol, ref1, meta_file) if ref1 is not None else None
        if ent is None:
            return None
        first = 0
        for _, lbn, length in _extents(ent):
            count = length // block
            vol.meta.append((first, count, lbn))
            first += count
    fsd_ref = struct.unpack_from("<H", lvd, 256)[0]
    fsd_lbn = struct.unpack_from("<I", lvd, 252)[0]
    fsd = vol.read(fsd_ref, fsd_lbn, block)
    if _tag(fsd) != TAG_FSD:
        return None
    _, root_lbn, root_ref = struct.unpack_from("<IIH", fsd, 400)
    return vol, info, (root_ref, root_lbn, 0)


def list_files(io: Io, *, budget: int, max_members: int
               ) -> tuple[list[dict[str, Any]], bool, dict[str, Any]] | None:
    """(rows, truncated, info), or None when no UDF tree could be read."""
    found = _volume(io)
    if found is None:
        return None
    vol, info, (root_ref, root_lbn, _) = found
    root = _entry(vol, root_ref, root_lbn)
    if root is None:
        return None
    rows: list[dict[str, Any]] = []
    queue = deque([(root, "")])
    seen = {(root_ref, root_lbn)}
    start = io.bytes_read
    while queue:
        ent, prefix = queue.popleft()
        data = _data(vol, ent, max(0, budget - (io.bytes_read - start)))
        for name, is_dir, lbn, ref in _fids(data):
            if len(rows) >= max_members or io.bytes_read - start > budget:
                return rows, True, info
            child = _entry(vol, ref, lbn)
            path = prefix + name + ("/" if is_dir else "")
            row: dict[str, Any] = {"index": len(rows), "path": path, "type": "dir" if is_dir else "file",
                                   "role": members.member_role(path)}
            if child is not None:
                row["size"] = 0 if is_dir else child["size"]
                mtime = _timestamp_ns(child["mtime"])
                if mtime is not None:
                    row["mtime_ns"] = mtime
                ext = _extents(child)
                if ext and not is_dir:
                    off = vol.physical(ext[0][0], ext[0][1])
                    if off is not None:
                        row["offset"] = off
            rows.append(row)
            if is_dir and child is not None and (ref, lbn) not in seen:
                seen.add((ref, lbn))
                queue.append((child, path))
    return rows, False, info
