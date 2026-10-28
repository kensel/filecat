"""The X3 pack formats: BOB1 meshes, the .cat/.dat catalogue pair, XSA3 saves.

A refinement of probe-order steps 6 (gzip), 8 (BOB1) and 11 (text). See
file-catalog-requirements.md, "Archives, images, models, data".
"""
from __future__ import annotations

import os
import re
import struct
from typing import Any

from ..options import ScanOptions
from .. import fsource
from ..fsource import fopen
from . import images, media
from . import members as members_mod

_VERTEX_TAG_SIZES = {0x001B: 38, 0x001F: 46}
_CAT_CAP = 10_000
_SAVE_TAGS = (b"XSA3", b"SYSB", b"TIME", b"STOR", b"/XSA")

_BOB_TAG_RE = re.compile(rb"^[A-Z0-9]{4}$")
_BOB_TEXTURE_RE = re.compile(rb"[A-Za-z0-9_./\\-]+\.(?:dds|tga|jpg|jpeg|bmp|png)", re.I)
_BOB_SHADER_RE = re.compile(rb"[A-Za-z0-9_./\\-]+\.fx", re.I)
_BOB_INFO_RE = re.compile(
    r"(PATH|SRC|VERS|TIME):\s*(.*?)(?=\s+(?:PATH|SRC|VERS|TIME|Copyright):|\s*\$|$)", re.S)
_BOB_LIST_CAP = 64


def _bob_info(blob: bytes) -> dict[str, str]:
    """INFO chunk: a `$`-delimited text block `PATH: .. SRC: .. VERS: .. TIME: ..`."""
    text = blob.decode("latin-1")
    a = text.find("$")
    if a != -1:
        b = text.find("$", a + 1)
        text = text[a + 1: b if b != -1 else len(text)]
    return {k.lower(): v.strip() for k, v in _BOB_INFO_RE.findall(text)}


def _sniff_bob1_chunked(data: bytes) -> dict[str, Any]:
    """BOB1 as found in X3 Reunion's .dat packs: `BOB1`, then chunks opened by
    a 4-character tag and closed by `/` + the first three characters
    (INFO .. /INF, MAT6 .. /MAT, BODY, POIN .. /POI, PART .. /PAR, /BOD, /BOB).

    Confirmed on the 15 .bob files in 02.dat: after `POIN` comes a big-endian
    u32 record count, then that many records that each start with a big-endian
    u16 vertex tag (0x001B = 38-byte records, 0x001F = 46-byte records), then `/POI`. The u32 after
    `MAT6` equals the number of shader-name strings in the MAT chunk in 13 of 15
    files (the other two list the name twice), so it is reported as
    `material_count` but its meaning is not certain. The remaining BODY / PART
    header fields are not interpreted.
    """
    n = len(data)
    pos = 4
    tags: list[str] = []
    counts = {0x001B: 0, 0x001F: 0}
    out: dict[str, Any] = {"bob1_layout": "chunked"}
    bodies = parts = points = 0
    unknown_vertex: int | None = None
    unknown_chunk: bytes | None = None
    closed = False
    skipped = 0

    while pos + 4 <= n:
        tag = data[pos:pos + 4]
        if tag == b"/BOB":
            closed = True
            break
        if tag.startswith(b"/"):
            pos += 4
            continue
        if not _BOB_TAG_RE.match(tag):
            # Multi-part bodies carry a few uninterpreted bytes between a /PAR
            # and the next POIN. Skip to the next POIN or /BOD; give up otherwise.
            cands = [i for i in (data.find(b"POIN", pos), data.find(b"/BOD", pos)) if i != -1]
            if not cands or skipped >= 64:
                unknown_chunk = tag
                break
            pos = min(cands)
            skipped += 1
            continue
        name = tag.decode("ascii")
        if name not in tags:
            tags.append(name)
        if tag == b"INFO" or tag.startswith(b"MAT"):
            end = data.find(b"/" + tag[:3], pos + 4)
            blob = data[pos + 4: end if end != -1 else n]
            if tag == b"INFO":
                info = _bob_info(blob)
                if info:
                    out["export_info"] = info
            else:
                if len(blob) >= 4:
                    out["material_count"] = struct.unpack_from(">I", blob, 0)[0]
                    out["material_version"] = name[3:]
                shaders = sorted({m.group(0).decode("latin-1") for m in _BOB_SHADER_RE.finditer(blob)})
                textures = sorted({m.group(0).decode("latin-1") for m in _BOB_TEXTURE_RE.finditer(blob)})
                out["shaders"] = shaders[:_BOB_LIST_CAP]
                out["textures"] = textures[:_BOB_LIST_CAP]
                out["texture_count"] = len(textures)
            if end == -1:
                break
            pos = end
        elif tag == b"BODY":
            bodies += 1
            pos += 14                      # tag + 10 header bytes, uninterpreted
        elif tag == b"POIN":
            # POIN, u32 BE record count, then `count` records that each begin
            # with their own u16 BE vertex tag (0x001B: 38 bytes, 0x001F: 46).
            if pos + 10 > n:
                break
            count = struct.unpack_from(">I", data, pos + 4)[0]
            pos += 8
            first = struct.unpack_from(">H", data, pos)[0]
            size = _VERTEX_TAG_SIZES.get(first)
            if size is None:
                unknown_vertex = first
                break
            last_at = pos + (count - 1) * size
            if count and last_at + 2 <= n and struct.unpack_from(">H", data, last_at)[0] == first:
                counts[first] += count          # uniform run: first and last agree
                points += count
                pos += count * size
            else:                               # mixed or cut off: walk record by record
                for _ in range(count):
                    if pos + 2 > n:
                        break
                    vtag = struct.unpack_from(">H", data, pos)[0]
                    size = _VERTEX_TAG_SIZES.get(vtag)
                    if size is None:
                        unknown_vertex = vtag
                        break
                    counts[vtag] += 1
                    points += 1
                    pos += size
                if unknown_vertex is not None:
                    break
        elif tag == b"PART":
            parts += 1
            end = data.find(b"/PAR", pos + 4)
            if end == -1:
                break
            pos = end
        else:
            unknown_chunk = tag
            break
    out["chunk_tags"] = tags
    out["bodies"] = bodies
    out["parts"] = parts
    out["points"] = points
    if skipped:
        out["gaps_skipped"] = skipped
    out["vertex_tag_0x001b"] = counts[0x001B]
    out["vertex_tag_0x001f"] = counts[0x001F]
    if unknown_vertex is not None:
        out["unknown_vertex_tag"] = f"0x{unknown_vertex:04x}"
    if unknown_chunk is not None:
        out["unknown_chunk_tag"] = unknown_chunk.decode("latin-1")
    if not closed and unknown_vertex is None and unknown_chunk is None:
        out["chunks_truncated"] = True
    return out


def sniff_bob1(data: bytes) -> dict[str, Any] | None:
    """BOB1 models.

    Real X3 files use named chunks (`INFO`, `MAT6`, `BODY`, `POIN`, `PART`);
    those are walked by _sniff_bob1_chunked. Anything else after the magic is
    walked as a run of little-endian u16 vertex tags (0x001B = 38 bytes,
    0x001F = 46 bytes); any other tag is recorded as `unknown_vertex_tag` and
    stops the walk -- its length isn't known so the rest of the buffer can't
    be skipped safely.
    """
    if not data.startswith(b"BOB1"):
        return None
    if _BOB_TAG_RE.match(data[4:8]):
        chunked = _sniff_bob1_chunked(data)
        chunked.update({"kind": "mesh", "format": "bob1"})
        return chunked
    pos = 4
    n = len(data)
    tags_seen: list[int] = []
    counts = {0x001B: 0, 0x001F: 0}
    unknown_tag: int | None = None
    while pos + 2 <= n:
        tag = struct.unpack_from("<H", data, pos)[0]
        if tag not in tags_seen:
            tags_seen.append(tag)
        size = _VERTEX_TAG_SIZES.get(tag)
        if size is None:
            unknown_tag = tag
            break
        if pos + size > n:
            break
        counts[tag] += 1
        pos += size
    out: dict[str, Any] = {
        "kind": "mesh",
        "format": "bob1",
        "chunk_tags": [f"0x{t:04x}" for t in tags_seen],
        "vertex_tag_0x001b": counts[0x001B],
        "vertex_tag_0x001f": counts[0x001F],
    }
    if unknown_tag is not None:
        out["unknown_vertex_tag"] = f"0x{unknown_tag:04x}"
    return out


def _decode_cat_bytes(raw: bytes) -> bytes:
    return bytes(b ^ ((0xDB + i) & 0xFF) for i, b in enumerate(raw))


def decode_cat_entries(path: str) -> list[dict[str, Any]] | None:
    """Decode a .cat file; None when it doesn't look like the x3 catalogue format.

    The first line names the .dat. A catalogue with only that line is an empty
    pack (03.cat .. 08.cat in X3 Reunion) and returns [].
    """
    try:
        with fopen(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if not raw:
        return None
    decoded = _decode_cat_bytes(raw)
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        text = decoded.decode("latin-1", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip() != ""]
    if not lines:
        return None
    if len(lines) == 1:
        return [] if lines[0].strip().lower().endswith(".dat") else None
    entries: list[dict[str, Any]] = []
    offset = 0
    for line in lines[1:]:
        stripped = line.strip()
        head_part, sep, size_part = stripped.rpartition(" ")
        if not sep or not size_part.strip().lstrip("-").isdigit():
            return None
        size_val = int(size_part.strip())
        entries.append({"path": head_part, "size": size_val, "offset": offset})
        offset += size_val
    return entries


def probe_cat(path: str, result: Any, options: ScanOptions | None = None) -> bool:
    entries = decode_cat_entries(path)
    if entries is None:
        return False
    opts = options if options is not None else ScanOptions()
    result.kind = "data"
    result.container = "plain"
    result.probe["format"] = "x3-cat"
    # original probe keys: entries (dicts, first _CAT_CAP) and truncated
    if len(entries) > _CAT_CAP:
        result.probe["entries"] = entries[:_CAT_CAP]
        result.probe["truncated"] = True
    else:
        result.probe["entries"] = entries
    # member rows: path, size, and offset into the sibling .dat
    rows = [
        {"index": i, "path": e["path"], "size": e["size"], "offset": e["offset"],
         "role": members_mod.member_role(e["path"])}
        for i, e in enumerate(entries)
    ]
    truncated = len(rows) > opts.max_members
    result.members = rows[: opts.max_members]
    summary = members_mod.summarize(result.members, truncated=truncated, list_cap=opts.list_zip_cap)
    summary.pop("entries")                  # probe.entries stays the dict list above
    result.probe.update(summary)
    result.probe["entries_total"] = len(entries)
    result.probe["x3_dat"] = os.path.splitext(fsource.basename(path))[0] + ".dat"
    return True


def _sibling_cat_path(path: str) -> str:
    base, _ = os.path.splitext(path)
    return base + ".cat"


def probe_dat_sibling(path: str, options: ScanOptions, result: Any) -> bool:
    """A .dat file is an x3-dat payload when its sibling .cat decodes."""
    cat_path = fsource.sibling(path, _sibling_cat_path(path))
    if cat_path is None or not fsource.isfile(cat_path):
        return False
    entries = decode_cat_entries(cat_path)
    if entries is None:
        return False
    result.kind = "data"
    result.container = "plain"
    result.probe["format"] = "x3-dat"
    result.probe["transform"] = "byte ^= 0x33"
    # pointer only: the entries are member rows on the .cat record
    result.probe["x3_cat"] = fsource.basename(cat_path)
    result.probe["entries_total"] = len(entries)
    if options.expand_dat:
        result.probe["members"] = _expand_members(path, entries, options.member_cap)
        if len(entries) > options.member_cap:
            result.probe["truncated"] = True
    return True


def _sniff_wrapper(header: bytes) -> dict[str, Any] | None:
    """gzip or XOR-gzip wrapped member (.pbd/.pbb/.pck inside a .dat)."""
    if header[:2] == b"\x1f\x8b":
        return {"format": "gzip"}
    if len(header) >= 3:
        key = header[0] ^ 0xC8
        if (header[1] ^ key) == 0x1F and (header[2] ^ key) == 0x8B:
            return {"format": "gzip_xored"}
    return None


def _expand_members(path: str, entries: list[dict[str, Any]], member_cap: int) -> list[dict[str, Any]]:
    """Sniff (not copy) up to `member_cap` payloads: a short header read per member,
    transformed with `byte ^= 0x33`, tagged with whatever magic it matches.

    The catalog stores measurements, not archive members, so each member's
    full bytes are never read or stored -- only a small header window.
    """
    members: list[dict[str, Any]] = []
    sniff_window = 64
    try:
        with fopen(path, "rb") as f:
            for entry in entries[:member_cap]:
                size = entry["size"]
                out: dict[str, Any] = {"path": entry["path"], "size": size, "offset": entry["offset"]}
                if size > 0:
                    f.seek(entry["offset"])
                    raw = f.read(min(size, sniff_window))
                    header = bytes(b ^ 0x33 for b in raw)
                    hit = images.sniff(header) or media.sniff(header) or sniff_bob1(header)
                    if not hit:
                        hit = _sniff_wrapper(header)
                    if hit:
                        if hit.get("kind"):
                            out["kind"] = hit["kind"]
                        if "format" in hit:
                            out["format"] = hit["format"]
                members.append(out)
    except OSError:
        pass
    return members


def sniff_save(data: bytes) -> dict[str, Any] | None:
    """A gzip-inflated body that opens with XSA3 and closes with /XSA is a save."""
    if not data.startswith(b"XSA3"):
        return None
    end = data.rfind(b"/XSA")
    if end == -1:
        return None
    window = data[: end + 4]
    positions = []
    for tag in _SAVE_TAGS:
        idx = window.find(tag)
        if idx != -1:
            positions.append((idx, tag.decode("ascii")))
    positions.sort()
    return {"kind": "save", "format": "xsa3", "tag_order": [name for _, name in positions]}
