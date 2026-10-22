"""Disk image containers (QCOW2, VHD, VHDX, VDI, VMDK) and guest readers.

Each parse_* function reads only the header and returns (info, guest). `guest`
is a Guest whose read(virtual_offset, n) maps blocks through the container's
tables (unallocated -> zeros) or None when the guest cannot be mapped
(differencing / backing file, compression, encryption, GD at end). Table
entries are read through a small page cache; nothing else is buffered.
"""
from __future__ import annotations

import re
import struct
import uuid
from typing import Any

MiB = 1024 * 1024
_PAGE = 4096
_MAX_PAGES = 64
_QCOW_OFF_MASK = 0x00FFFFFFFFFFFE00
_DESC_CAP = 64 * 1024


class Io:
    """Counting positional reader over an open file."""

    def __init__(self, f: Any, size: int) -> None:
        self.f = f
        self.size = size
        self.bytes_read = 0
        self._pages: dict[int, bytes] = {}

    def read_at(self, off: int, n: int) -> bytes:
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        self.f.seek(off)
        data = self.f.read(n)
        self.bytes_read += len(data)
        return data

    def entry(self, off: int, width: int) -> bytes:
        """`width` bytes of a table entry, via a cache of aligned 4 KiB pages."""
        base = off - off % _PAGE
        rel = off - base
        if rel + width > _PAGE:
            return self.read_at(off, width)
        page = self._pages.get(base)
        if page is None:
            if len(self._pages) >= _MAX_PAGES:
                self._pages.clear()
            page = self._pages[base] = self.read_at(base, _PAGE)
        return page[rel:rel + width]


def _be(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _le(b: bytes) -> int:
    return int.from_bytes(b, "little")


class Guest:
    """Virtual disk view: fixed-size mapping blocks, unmapped -> zeros."""

    def __init__(self, io: Io, size: int, block: int) -> None:
        self.io = io
        self.size = size
        self.block = max(block, 512)
        self.unreadable = False     # a mapped cluster was compressed

    def locate(self, vblock: int) -> int | None:
        raise NotImplementedError

    def read(self, off: int, n: int) -> bytes:
        if off < 0 or off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        out = []
        while n > 0:
            vb, inner = divmod(off, self.block)
            take = min(n, self.block - inner)
            loc = self.locate(vb)
            chunk = self.io.read_at(loc + inner, take) if loc is not None else b""
            out.append(chunk + bytes(take - len(chunk)))
            off += take
            n -= take
        return b"".join(out)


class RawGuest(Guest):
    """Identity mapping over [base, base+size) of the file (raw, fixed VHD)."""

    def __init__(self, io: Io, size: int, base: int = 0) -> None:
        super().__init__(io, size, 1 << 40)
        self.base = base

    def read(self, off: int, n: int) -> bytes:
        if off < 0 or off >= self.size or n <= 0:
            return b""
        return self.io.read_at(self.base + off, min(n, self.size - off))


# --- QCOW2 ------------------------------------------------------------

class Qcow2Guest(Guest):
    def __init__(self, io: Io, size: int, cluster: int, l1_size: int, l1_off: int, v3: bool) -> None:
        super().__init__(io, size, cluster)
        self.l2n = cluster // 8
        self.l1_size, self.l1_off, self.v3 = l1_size, l1_off, v3

    def locate(self, vb: int) -> int | None:
        l1i, l2i = divmod(vb, self.l2n)
        if l1i >= self.l1_size:
            return None
        l2_off = _be(self.io.entry(self.l1_off + l1i * 8, 8)) & _QCOW_OFF_MASK
        if not l2_off:
            return None
        e = _be(self.io.entry(l2_off + l2i * 8, 8))
        if e & (1 << 62):               # compressed cluster
            self.unreadable = True
            return None
        if self.v3 and e & 1:           # zero cluster
            return None
        return (e & _QCOW_OFF_MASK) or None


def parse_qcow2(io: Io) -> tuple[dict[str, Any], Guest | None]:
    h = io.read_at(0, 112)
    info: dict[str, Any] = {"format": "qcow2", "sparse": True}
    if len(h) < 72:
        return info, None
    (_, version, back_off, back_len, cbits, vsize, crypt, l1_size, l1_off) = struct.unpack_from(">4sIQIIQIIQ", h)
    info["version"] = version
    info["virtual_size"] = vsize
    if version not in (2, 3):
        info["notes"] = [f"unsupported qcow2 version {version}"]
        return info, None
    if 9 <= cbits <= 21:
        info["cluster_size"] = 1 << cbits
    snapshots = struct.unpack_from(">I", h, 60)[0]
    if snapshots:
        info["snapshots"] = snapshots
    parent = False
    if back_off and back_len:
        name = io.read_at(back_off, min(back_len, 1024)).decode("utf-8", "replace")
        info["backing_file"] = name
        info["variant"] = "differencing"
        parent = True
    if crypt:
        info["encryption_method"] = {1: "AES", 2: "LUKS"}.get(crypt, str(crypt))
    if crypt or parent or not 9 <= cbits <= 21:
        return info, None
    return info, Qcow2Guest(io, vsize, 1 << cbits, l1_size, l1_off, version == 3)


# --- VHD --------------------------------------------------------------

_VHD_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}


class VhdGuest(Guest):
    def __init__(self, io: Io, size: int, block: int, bat_off: int, entries: int) -> None:
        super().__init__(io, size, block)
        self.bat_off, self.entries = bat_off, entries
        self.bitmap = ((block // 512 + 7) // 8 + 511) // 512 * 512

    def locate(self, vb: int) -> int | None:
        if vb >= self.entries:
            return None
        raw = self.io.entry(self.bat_off + vb * 4, 4)
        if len(raw) < 4 or raw == b"\xff\xff\xff\xff":
            return None
        sector = _be(raw)
        return sector * 512 + self.bitmap


def vhd_footer_at_end(io: Io) -> bytes | None:
    if io.size < 512:
        return None
    tail = io.read_at(io.size - 512, 512)
    return tail if tail[:8] == b"conectix" else None


def parse_vhd(io: Io, footer: bytes, at_end: bool) -> tuple[dict[str, Any], Guest | None]:
    cur = struct.unpack_from(">Q", footer, 48)[0]
    dtype = struct.unpack_from(">I", footer, 60)[0]
    info: dict[str, Any] = {
        "format": "vhd", "virtual_size": cur,
        "variant": _VHD_TYPES.get(dtype, f"type{dtype}"),
        "sparse": dtype != 2,
        "unique_id": str(uuid.UUID(bytes=footer[68:84])),
    }
    if dtype == 2:
        if at_end:
            return info, RawGuest(io, min(cur, io.size - 512))
        return info, None
    data_off = struct.unpack_from(">Q", footer, 16)[0]
    hdr = io.read_at(data_off, 1024) if data_off != 0xFFFFFFFFFFFFFFFF else b""
    if hdr[:8] != b"cxsparse":
        info["notes"] = ["dynamic VHD header not found"]
        return info, None
    table_off = struct.unpack_from(">Q", hdr, 16)[0]
    entries, block = struct.unpack_from(">II", hdr, 28)
    info["block_size"] = block
    parent = hdr[64:576].decode("utf-16-be", "replace").rstrip("\x00")
    if parent:
        info["parent"] = parent
    if dtype == 4 or parent or block < 512 or block & (block - 1):
        return info, None
    return info, VhdGuest(io, cur, block, table_off, entries)


# --- VHDX -------------------------------------------------------------

_G_BAT = "2dc27766-f623-4200-9d64-115e9bfd4a08"
_G_META = "8b7ca206-4790-4b9a-b8fe-575f050f886e"
_G_FILE_PARAMS = "caa16737-fa36-4d43-b3b6-33f0aa44e76b"
_G_VSIZE = "2fa54224-cd1b-4876-b211-5dbed83bf4b8"
_G_LSECTOR = "8141bf1d-a96f-4709-ba47-f233a8faab5f"
_G_PSECTOR = "cda348c7-445d-4471-9cc9-e9885251c556"


def _guid_le(b: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(b)))


class VhdxGuest(Guest):
    def __init__(self, io: Io, size: int, block: int, bat_off: int, bat_len: int, lsector: int) -> None:
        super().__init__(io, size, block)
        self.bat_off, self.bat_len = bat_off, bat_len
        self.ratio = max(1, (1 << 23) * lsector // block)

    def locate(self, vb: int) -> int | None:
        bi = vb + vb // self.ratio     # a sector-bitmap entry follows every `ratio` payload entries
        if bi * 8 >= self.bat_len:
            return None
        e = _le(self.io.entry(self.bat_off + bi * 8, 8))
        if e & 7 in (6, 7):
            return (e >> 20) * MiB or None
        return None


def _vhdx_regions(io: Io) -> dict[str, tuple[int, int]]:
    for off in (0x30000, 0x40000):          # the table is stored twice
        t = io.read_at(off, _PAGE)
        if t[:4] != b"regi":
            continue
        regions = {}
        for i in range(min(_le(t[8:12]), 63)):
            e = t[16 + 32 * i:48 + 32 * i]
            regions[_guid_le(e[:16])] = (_le(e[16:24]), _le(e[24:28]))
        return regions
    return {}


def _vhdx_items(io: Io, meta_off: int) -> dict[str, tuple[int, int]]:
    t = io.read_at(meta_off, _PAGE)
    if t[:8] != b"metadata":
        return {}
    items = {}
    for i in range(min(_le(t[10:12]), (_PAGE - 32) // 32)):
        e = t[32 + 32 * i:64 + 32 * i]
        items[_guid_le(e[:16])] = (_le(e[16:20]), _le(e[20:24]))
    return items


def parse_vhdx(io: Io) -> tuple[dict[str, Any], Guest | None]:
    info: dict[str, Any] = {"format": "vhdx", "sparse": True}
    regions = _vhdx_regions(io)
    if _G_META not in regions or _G_BAT not in regions:
        info["notes"] = ["VHDX region table not found"]
        return info, None
    meta_off = regions[_G_META][0]
    items = _vhdx_items(io, meta_off)

    def item(guid: str, n: int) -> bytes:
        ent = items.get(guid)
        return io.read_at(meta_off + ent[0], n)[:n] if ent else b""

    fp = item(_G_FILE_PARAMS, 8)
    vs = item(_G_VSIZE, 8)
    if len(fp) < 8 or len(vs) < 8:
        info["notes"] = ["VHDX metadata incomplete"]
        return info, None
    block, flags = struct.unpack("<II", fp)
    vsize = _le(vs)
    lsector = _le(item(_G_LSECTOR, 4)) or 512
    psector = _le(item(_G_PSECTOR, 4))
    info.update(virtual_size=vsize, block_size=block, logical_sector_size=lsector)
    if psector:
        info["physical_sector_size"] = psector
    has_parent = bool(flags & 2)
    info["variant"] = "differencing" if has_parent else ("fixed" if flags & 1 else "dynamic")
    info["sparse"] = not flags & 1
    if has_parent or not block:
        return info, None
    bat_off, bat_len = regions[_G_BAT]
    return info, VhdxGuest(io, vsize, block, bat_off, bat_len, lsector)


# --- VDI --------------------------------------------------------------

_VDI_TYPES = {1: "dynamic", 2: "fixed", 3: "undo", 4: "differencing"}


class VdiGuest(Guest):
    def __init__(self, io: Io, size: int, block: int, map_off: int, data_off: int, blocks: int) -> None:
        super().__init__(io, size, block)
        self.map_off, self.data_off, self.blocks = map_off, data_off, blocks

    def locate(self, vb: int) -> int | None:
        if vb >= self.blocks:
            return None
        raw = self.io.entry(self.map_off + vb * 4, 4)
        idx = _le(raw)
        if len(raw) < 4 or idx >= 0xFFFFFFFE:
            return None
        return self.data_off + idx * self.block


def parse_vdi(io: Io) -> tuple[dict[str, Any], Guest | None]:
    h = io.read_at(0, 512)
    info: dict[str, Any] = {"format": "vdi"}
    if len(h) < 0x1C8:
        return info, None
    version, _, itype = struct.unpack_from("<III", h, 0x44)
    off_blocks, off_data = struct.unpack_from("<II", h, 0x154)
    cb_disk = struct.unpack_from("<Q", h, 0x170)[0]
    cb_block, _, blocks, allocated = struct.unpack_from("<IIII", h, 0x178)
    has_parent = any(h[0x1B8:0x1C8])
    info.update(version=f"{version >> 16}.{version & 0xFFFF}", virtual_size=cb_disk,
                variant=_VDI_TYPES.get(itype, f"type{itype}"), block_size=cb_block,
                allocated_size=allocated * cb_block, sparse=itype in (1, 4),
                unique_id=str(uuid.UUID(bytes_le=bytes(h[0x188:0x198]))))
    if itype in (3, 4) or has_parent or not cb_block:
        if has_parent:
            info["notes"] = ["has parent image"]
        return info, None
    return info, VdiGuest(io, cb_disk, cb_block, off_blocks, off_data, blocks)


# --- VMDK -------------------------------------------------------------

_EXTENT = re.compile(r'^(RW|RDONLY|NOACCESS)\s+(\d+)\s+(\w+)(?:\s+"([^"]*)")?(?:\s+(\d+))?', re.M)
_KV = re.compile(r'^\s*([A-Za-z.]+)\s*=\s*"?([^"\r\n]*)"?\s*$', re.M)


def parse_vmdk_descriptor(raw: bytes) -> dict[str, Any]:
    text = raw.split(b"\x00")[0].decode("utf-8", "replace")
    kv = {m.group(1): m.group(2) for m in _KV.finditer(text)}
    out: dict[str, Any] = {}
    if kv.get("createType"):
        out["create_type"] = kv["createType"]
    if kv.get("parentFileNameHint"):
        out["parent"] = kv["parentFileNameHint"]
    extents = [{"access": m.group(1), "sectors": int(m.group(2)), "type": m.group(3),
                **({"file": m.group(4)} if m.group(4) else {})}
               for m in _EXTENT.finditer(text)]
    if extents:
        out["extents"] = extents
        out["virtual_size"] = sum(e["sectors"] for e in extents) * 512
    return out


def _vmdk_sparse_flag(create_type: str | None) -> bool | None:
    if not create_type:
        return None
    t = create_type.lower()
    return not ("flat" in t or t in ("vmfs", "fulldevice", "partitioneddevice"))


def parse_vmdk_text(io: Io) -> dict[str, Any]:
    desc = parse_vmdk_descriptor(io.read_at(0, _DESC_CAP))
    info: dict[str, Any] = {"format": "vmdk", "variant": "descriptor", **desc}
    flag = _vmdk_sparse_flag(desc.get("create_type"))
    if flag is not None:
        info["sparse"] = flag
    return info


class VmdkGuest(Guest):
    def __init__(self, io: Io, size: int, grain: int, gtes: int, gd_off: int) -> None:
        super().__init__(io, size, grain)
        self.gtes, self.gd_off = gtes, gd_off

    def locate(self, vb: int) -> int | None:
        gti, j = divmod(vb, self.gtes)
        gt_sector = _le(self.io.entry(self.gd_off + gti * 4, 4))
        if not gt_sector:
            return None
        sector = _le(self.io.entry(gt_sector * 512 + j * 4, 4))
        return sector * 512 if sector > 1 else None    # 0 unallocated, 1 zero grain


def parse_vmdk_sparse(io: Io) -> tuple[dict[str, Any], Guest | None]:
    h = io.read_at(0, 512)
    info: dict[str, Any] = {"format": "vmdk", "variant": "sparse", "sparse": True}
    if len(h) < 80:
        return info, None
    version, flags, capacity, grain, d_off, d_size, gtes, _rgd, gd = struct.unpack_from("<IIQQQQIQQ", h, 4)
    compress = struct.unpack_from("<H", h, 77)[0]
    info.update(version=version, virtual_size=capacity * 512, grain_size=grain * 512)
    if d_off and d_size:
        desc = parse_vmdk_descriptor(io.read_at(d_off * 512, min(d_size * 512, _DESC_CAP)))
        desc.pop("virtual_size", None)
        info.update(desc)
    if "parent" in info:
        info["variant"] = "differencing"
    if compress:
        info["compression"] = {1: "deflate"}.get(compress, str(compress))
    if gd == 0xFFFFFFFFFFFFFFFF:
        info["notes"] = ["grain directory at end of file (streamOptimized); not mapped"]
        return info, None
    if compress or "parent" in info or not grain or not gtes:
        return info, None
    return info, VmdkGuest(io, capacity * 512, grain * 512, gtes, gd * 512)
