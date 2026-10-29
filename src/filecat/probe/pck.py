""".pck files: tell which .pck this is (X3 XOR-gzip, Godot GDPC, or other)
and catalog any members it holds.

* Godot pack (`GDPC`): the directory is parsed, one member row per file.
* X3 pack: a gzip or XOR-gzip wrapper around one payload (an XML script, a
  language table, a model, ...). archive.probe_gzip inflates it and calls
  refine_x3_pck, which records `probe.pck_format = "x3"`, `probe.x3_payload`
  and a single member row.
* Anything else: identify_other() looks for Python pickle opcodes (never
  unpickles) and otherwise records `pck_format = "unknown"`.
"""
from __future__ import annotations

import re
import struct
from typing import Any

from ..options import ScanOptions
from ..fsource import fopen
from . import members as members_mod
from . import x3

_GODOT_MAGIC = b"GDPC"
_PACK_DIR_ENCRYPTED = 0x1
_PACK_REL_FILEBASE = 0x2
_FILE_ENCRYPTED = 0x1
_MAX_PATH = 4096


def detect_godot(head: bytes) -> bool:
    """Godot pack: 'GDPC' at offset 0 (an exe with an embedded pack is a PE
    and is handled there)."""
    return head[:4] == _GODOT_MAGIC


class _Reader:
    def __init__(self, f: Any) -> None:
        self.f = f

    def take(self, n: int) -> bytes:
        data = self.f.read(n)
        if len(data) < n:
            raise ValueError("pack directory truncated")
        return data

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]


def probe_godot(path: str, head: bytes, options: ScanOptions, result: Any) -> None:
    result.kind = "archive"
    result.container = "unknown"
    result.probe["pck_format"] = "godot"
    result.probe["format"] = "godot-pck"
    with fopen(path, "rb") as f:
        r = _Reader(f)
        r.take(4)
        pack_version = r.u32()
        major, minor, patch = r.u32(), r.u32(), r.u32()
        info: dict[str, Any] = {
            "pack_format": pack_version,
            "engine_version": f"{major}.{minor}.{patch}",
        }
        result.probe["godot"] = info
        flags = 0
        files_base = 0
        dir_offset = None
        if pack_version >= 2:
            flags = r.u32()
            files_base = r.u64()
            if pack_version >= 3:
                dir_offset = r.u64()
            info["flags"] = flags
            info["files_base"] = files_base
        r.take(64)                       # 16 reserved dwords
        if dir_offset:
            f.seek(dir_offset)
        if flags & _PACK_DIR_ENCRYPTED:
            info["encrypted_dir"] = True
            return
        count = r.u32()
        info["file_count"] = count
        entries_pos = f.tell()
        f.seek(0, 2)
        file_size = f.tell()
        f.seek(entries_pos)
        # every entry is at least 4+8+8+16 bytes
        if count > file_size // 36:
            raise ValueError(f"implausible Godot file count {count}")
        rows: list[dict[str, Any]] = []
        encrypted_files = 0
        for i in range(count):
            plen = r.u32()
            if plen > _MAX_PATH:
                raise ValueError(f"implausible path length {plen}")
            raw = r.take(plen)
            name = raw.rstrip(b"\x00").decode("utf-8", errors="replace")
            offset = r.u64()
            size = r.u64()
            md5 = r.take(16).hex()
            entry_flags = r.u32() if pack_version >= 2 else 0
            if pack_version >= 2 and (flags & _PACK_REL_FILEBASE):
                offset += files_base
            row: dict[str, Any] = {
                "index": i,
                "path": name,
                "size": size,
                "offset": offset,
                "md5": md5,
                "role": members_mod.member_role(_strip_res(name)),
            }
            if entry_flags:
                row["flags"] = entry_flags
                if entry_flags & _FILE_ENCRYPTED:
                    encrypted_files += 1
            rows.append(row)
        if encrypted_files:
            info["encrypted_files"] = encrypted_files
    truncated = len(rows) > options.max_members
    result.members = rows[: options.max_members]
    result.probe.update(members_mod.summarize(result.members, truncated=truncated,
                                              list_cap=options.list_zip_cap))


def _strip_res(name: str) -> str:
    return name[6:] if name.startswith("res://") else name


# ---------------------------------------------------------------------------
# X3 payloads
# ---------------------------------------------------------------------------

def _decode_text(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", errors="replace")


def _tag_text(text: str, tag: str, limit: int = 200) -> str | None:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.S)
    if not m:
        return None
    return m.group(1).strip()[:limit]


def describe_x3_payload(inflated: bytes, truncated: bool) -> dict[str, Any]:
    """Classify an inflated X3 pack body by its bytes. Returns role, format,
    ext (the inner file extension when evident) and format-specific counts."""
    out: dict[str, Any] = {"role": "unknown", "format": "unknown", "ext": ""}
    head = inflated[:8192]
    if inflated.startswith(b"BOB1"):
        out.update(role="model", format="bob1", ext=".bob")
        bob = x3.sniff_bob1(inflated) or {}
        for key in ("bob1_layout", "bodies", "parts", "points", "material_count", "texture_count",
                    "textures", "shaders", "export_info", "chunks_truncated"):
            if key in bob:
                out[key] = bob[key]
    elif inflated.startswith(b"CUT1"):
        # same chunk grammar as BOB1 (INFO .. /INF ...); .pbb in X3 Reunion
        out.update(role="data", format="cut1", ext=".pbb")
        m = re.search(rb"PATH:\s*(.*?)\s+SRC:", inflated[:2048], re.S)
        if m:
            out["source_path"] = m.group(1).decode("latin-1")
    elif inflated.startswith(b"DDS "):
        out.update(role="texture", format="dds", ext=".dds")
    elif inflated.startswith(b"XSA3"):
        out.update(role="save", format="xsa3", ext=".xsa")
    elif inflated[:2] in (b"\xff\xd8",) or inflated.startswith(b"\x89PNG"):
        out.update(role="image", format="image", ext=".jpg" if inflated[:2] == b"\xff\xd8" else ".png")
    elif b"\x00" in head:
        out.update(role="data", format="binary", ext=".bin")
    else:
        text = _decode_text(inflated)
        body = text.lstrip()
        if "<language" in text[:2048]:
            m = re.search(r'<language\s+id="(\d+)"', text)
            pages = len(re.findall(r"<page\b", text))
            entries = len(re.findall(r"<t\s", text))
            out.update(role="table", format="x3-tfile", ext=".xml", pages=pages, entries=entries)
            if m:
                out["language_id"] = int(m.group(1))
            if re.search(r'<page\b[^>]*\bstream="1"', text):
                out["stream"] = True      # offsets/lengths into a sibling stream (.dat)
        elif re.search(r"<script\b", text[:4096]):
            out.update(role="script", format="x3-script", ext=".xml")
            for tag in ("name", "version", "engineversion", "description"):
                val = _tag_text(text, tag)
                if val is not None:
                    out[tag] = val
            out["codearray"] = "<codearray" in text
            out["sourcetext"] = "<sourcetext" in text
            out["arguments"] = len(re.findall(r"<argument\b", text))
        elif body.startswith("<?xml") or body.startswith("<"):
            out.update(role="config", format="xml", ext=".xml")
        elif (re.match(r"VER:\s*\d+", body) or body.startswith("// ")
              or ("EGOSOFT Bodyfile" in body[:1024] and body.startswith("/"))):
            # scene / body text: `VER: n` or the `/ EGOSOFT Bodyfile exporter` comment
            # header followed by KEYWORDn: rows (MATERIAL5: ..., etc.)
            out.update(role="model", format="scene-text", ext=".pbd" if body.startswith("/") else ".txt")
            m = re.match(r"VER:\s*(\d+)", body)
            if m:
                out["scene_version"] = int(m.group(1))
            rows = re.findall(r"^([A-Z][A-Z0-9_]*):", text, re.M)
            if rows:
                from collections import Counter
                out["row_kinds"] = dict(Counter(rows).most_common(8))
        else:
            out.update(role="text", format="text", ext=".txt")
    if truncated:
        out["counts_are_lower_bounds"] = True
    return out


def refine_x3_pck(name: str, inflated: bytes, truncated: bool, result: Any) -> None:
    """Called by archive.probe_gzip for a .pck after inflating. Records
    probe.pck_format = "x3" and what the payload is (script, table, ...)."""
    desc = describe_x3_payload(inflated, truncated)
    result.probe["pck_format"] = "x3"
    payload = {
        "role": desc["role"],
        "format": desc["format"],
        "inflated_size": len(inflated),
        "truncated": bool(truncated),
    }
    for key, val in desc.items():
        if key not in ("role", "format", "ext"):
            payload[key] = val
    result.probe["x3_payload"] = payload
    stem = name[:-4] if name.lower().endswith(".pck") else name
    row: dict[str, Any] = {
        "index": 0,
        "path": stem + desc["ext"],
        "role": desc["role"],
        "format": desc["format"],
    }
    if not truncated:
        row["size"] = len(inflated)
    if result.kind and result.kind != "unknown":
        row["kind"] = result.kind
    result.members = [row]
    result.probe.update(members_mod.summarize(result.members, truncated=False, list_cap=100))


# ---------------------------------------------------------------------------
# Other .pck files
# ---------------------------------------------------------------------------

_PICKLE0_OPS = set("(clpgIFSVLRtdasbi0.JKMUXqrhjuBCT]}) ")


def sniff_pickle(head: bytes) -> dict[str, Any] | None:
    """Recognise a pickle stream from its opcodes without ever unpickling.

    protocol 2-5 starts with PROTO (0x80 n). Protocol 0/1 text pickles are
    newline-delimited opcodes: a printable head whose lines start with
    opcode letters, and, when the whole stream is in view, ends with '.'.
    """
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return {"protocol": head[1]}
    if not head or head[0] not in b"(clpgIFSVLRtdasbi0]}":
        return None
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text):
        return None
    lines = [ln for ln in text.replace("\r", "").split("\n") if ln]
    if len(lines) < 3:
        return None
    ok = sum(1 for ln in lines if ln[0] in _PICKLE0_OPS)
    if ok < 0.9 * len(lines):
        return None
    if len(head) < 8192 and not text.rstrip().endswith("."):
        return None
    return {"protocol": 0}


def identify_other(name: str, head: bytes, result: Any) -> str | None:
    """For a .pck that neither the Godot nor the gzip path claimed. Sets
    probe.pck_format to "pickle" or "unknown" and returns it. A no-op (None)
    for other suffixes or when pck_format is already set. The existing
    kind/container classification is left alone."""
    if not name.lower().endswith(".pck") or result.probe.get("pck_format"):
        return None
    hit = sniff_pickle(head)
    if hit is not None:
        result.probe["pck_format"] = "pickle"
        result.probe["pickle_protocol"] = hit["protocol"]
        return "pickle"
    result.probe["pck_format"] = "unknown"
    return "unknown"
