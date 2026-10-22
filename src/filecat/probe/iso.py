"""ISO 9660 (with Joliet and El Torito) and UDF volume descriptors, and a
breadth-first directory listing from the primary (or Joliet) root record.

Only the descriptor sectors and the directory extents are read; file data is
never touched. Rock Ridge names are not interpreted.
"""
from __future__ import annotations

import re
import struct
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from . import members
from .diskio import Io

_SECTOR = 2048
_VD_START = 0x8000
_MAX_DESCRIPTORS = 32
_JOLIET_ESCAPES = (b"%/@", b"%/C", b"%/E")
_UDF_IDS = (b"BEA01", b"NSR02", b"NSR03", b"TEA01")
_VERSION = re.compile(r";\d+$")


def _text(b: bytes) -> str:
    return b.decode("latin-1").strip(" \x00")


def _dec_datetime(b: bytes) -> str | None:
    """17-byte 'YYYYMMDDHHMMSScc' + timezone; all zeros means unset."""
    s = b[:16].decode("ascii", "replace")
    if not s.isdigit() or s.startswith("0000"):
        return None
    return f"{s[0:4]}-{s[4:6]}-{s[6:8]}T{s[8:10]}:{s[10:12]}:{s[12:14]}"


def _rec_mtime_ns(b: bytes) -> int | None:
    """7-byte recording date: years since 1900, month, day, h, m, s, tz (15 min)."""
    y, mo, d, h, mi, s = b[:6]
    tz = struct.unpack_from("<b", b, 6)[0]
    try:
        dt = datetime(1900 + y, mo, d, h, mi, s, tzinfo=timezone(timedelta(minutes=15 * tz)))
        return int(dt.timestamp()) * 10**9
    except (ValueError, OverflowError, OSError):
        return None


def read_descriptors(io: Io) -> dict[str, Any]:
    """Walk the volume descriptor set: PVD, Joliet SVD, El Torito, UDF markers."""
    found: dict[str, Any] = {}
    for i in range(_MAX_DESCRIPTORS):
        d = io.read_at(_VD_START + i * _SECTOR, _SECTOR)
        if len(d) < 7:
            break
        ident = d[1:6]
        if ident == b"CD001":
            if d[0] == 1 and "pvd" not in found:
                found["pvd"] = d
            elif d[0] == 2 and d[88:91] in _JOLIET_ESCAPES:
                found["joliet"] = d
            elif d[0] == 0 and d[7:30] == b"EL TORITO SPECIFICATION":
                found["bootable"] = True
        elif ident in _UDF_IDS:
            found["udf"] = True
        else:
            break
    return found


def describe(found: dict[str, Any]) -> dict[str, Any]:
    pvd = found.get("pvd")
    info: dict[str, Any] = {"format": "iso9660" if pvd else "udf"}
    if pvd:
        blocks = struct.unpack_from("<I", pvd, 80)[0]
        block = struct.unpack_from("<H", pvd, 128)[0] or _SECTOR
        info.update(block_size=block, virtual_size=blocks * block,
                    system_id=_text(pvd[8:40]), volume_id=_text(pvd[40:72]),
                    volume_set_id=_text(pvd[190:318]), publisher=_text(pvd[318:446]),
                    application=_text(pvd[574:702]), created=_dec_datetime(pvd[813:830]))
    for key in ("joliet", "udf", "bootable"):
        if found.get(key):
            info[key] = True
    return info


def _name(raw: bytes, joliet: bool) -> str:
    name = raw.decode("utf-16-be", "replace") if joliet else raw.decode("latin-1")
    name = _VERSION.sub("", name)
    return name[:-1] if name.endswith(".") and len(name) > 1 else name


def _records(data: bytes):
    pos = 0
    while pos < len(data):
        n = data[pos]
        if n == 0:                              # records never cross a sector
            pos = (pos // _SECTOR + 1) * _SECTOR
            continue
        if pos + n > len(data) or n < 34:
            break
        yield data[pos:pos + n]
        pos += n


def list_files(io: Io, found: dict[str, Any], *, budget: int, max_members: int
               ) -> tuple[list[dict[str, Any]], bool]:
    """(rows, truncated). Prefers the Joliet tree for long Unicode names."""
    vd = found.get("joliet") or found["pvd"]
    joliet = "joliet" in found
    block = struct.unpack_from("<H", found["pvd"], 128)[0] or _SECTOR
    root = vd[156:190]
    queue = deque([(struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], "")])
    seen = {queue[0][0]}
    rows: list[dict[str, Any]] = []
    spent = 0
    while queue:
        lba, length, prefix = queue.popleft()
        if spent + length > budget:
            return rows, True
        data = io.read_at(lba * block, length)
        spent += len(data)
        for rec in _records(data):
            nlen = rec[32]
            raw = rec[33:33 + nlen]
            if raw in (b"\x00", b"\x01") or not nlen:
                continue
            if len(rows) >= max_members:
                return rows, True
            ext, size = struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0]
            is_dir = bool(rec[25] & 2)
            path = prefix + _name(raw, joliet) + ("/" if is_dir else "")
            row: dict[str, Any] = {"index": len(rows), "path": path, "size": 0 if is_dir else size,
                                   "offset": ext * block, "type": "dir" if is_dir else "file",
                                   "role": members.member_role(path)}
            mtime = _rec_mtime_ns(rec[18:25])
            if mtime is not None:
                row["mtime_ns"] = mtime
            rows.append(row)
            if is_dir and ext not in seen:
                seen.add(ext)
                queue.append((ext, size, path))
    return rows, False
