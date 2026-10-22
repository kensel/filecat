"""Minimal parser for regedit (.reg) text exports.

Supports the "Windows Registry Editor Version 5.00" header (UTF-16-LE with a
BOM) and the older "REGEDIT4" header (ANSI / UTF-8, no BOM). Only the subset
of value encodings regedit actually emits is handled: quoted strings,
``dword:``, ``hex(2):`` (REG_EXPAND_SZ), ``hex(7):`` (REG_MULTI_SZ), and
plain ``hex:`` (REG_BINARY). Line continuations with a trailing backslash
are joined before parsing.

This module does not touch the live registry and never writes anything.
"""
from __future__ import annotations

import re
from typing import Any, Iterator

_SECTION_RE = re.compile(r"^\[(-?)(.+)\]$")
_VALUE_RE = re.compile(r'^(@|"(?:[^"\\]|\\.)*")=(.*)$')


def load_text(path: str) -> str:
    """Read a .reg file, detecting its encoding from the header bytes."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16-le" if data[:2] == b"\xff\xfe" else "utf-16-be", errors="replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def _join_continuations(lines: list[str]) -> list[str]:
    out: list[str] = []
    buf: str | None = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if buf is not None:
            line = buf + line.lstrip()
            buf = None
        if line.endswith("\\"):
            buf = line[:-1]
            continue
        out.append(line)
    if buf is not None:
        out.append(buf)
    return out


def _unescape(s: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in ("\\", '"'):
            out.append(s[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _hex_bytes(s: str) -> bytes:
    tokens = [t.strip() for t in s.split(",")]
    return bytes(int(t, 16) for t in tokens if t)


def _decode_expand_sz(data: bytes) -> str:
    text = data.decode("utf-16-le", errors="replace")
    return text.rstrip("\x00")


def _decode_multi_sz(data: bytes) -> list[str]:
    text = data.decode("utf-16-le", errors="replace")
    parts = text.split("\x00")
    return [p for p in parts if p]


def _parse_value(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return _unescape(raw[1:-1])
    if raw.startswith("dword:"):
        return int(raw[len("dword:"):], 16)
    if raw.startswith("hex(2):"):
        return _decode_expand_sz(_hex_bytes(raw[len("hex(2):"):]))
    if raw.startswith("hex(7):"):
        return _decode_multi_sz(_hex_bytes(raw[len("hex(7):"):]))
    if raw.startswith("hex:"):
        return _hex_bytes(raw[len("hex:"):])
    m = re.match(r"^hex\(([0-9a-fA-F]+)\):(.*)$", raw)
    if m:
        return _hex_bytes(m.group(2))
    return raw


def iter_sections(text: str) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (key_path, {value_name: value}) for every section in a .reg export.

    key_path is the full path as written, e.g.
    ``HKEY_LOCAL_MACHINE\\SOFTWARE\\...\\Uninstall\\Foo``. A section whose
    header starts with ``[-`` (a delete marker) is skipped.
    """
    lines = _join_continuations(text.splitlines())
    current_key: str | None = None
    current_values: dict[str, Any] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        m = _SECTION_RE.match(stripped)
        if m:
            if current_key is not None:
                yield current_key, current_values
            deleted, key_path = m.groups()
            if deleted:
                current_key = None
                current_values = {}
                continue
            current_key = key_path
            current_values = {}
            continue
        if current_key is None:
            continue
        vm = _VALUE_RE.match(stripped)
        if not vm:
            continue
        raw_name, raw_value = vm.groups()
        name = "@" if raw_name == "@" else _unescape(raw_name[1:-1])
        current_values[name] = _parse_value(raw_value)
    if current_key is not None:
        yield current_key, current_values


def parse_file(path: str) -> list[tuple[str, dict[str, Any]]]:
    """Parse a .reg file into a list of (key_path, values) sections."""
    text = load_text(path)
    return list(iter_sections(text))
