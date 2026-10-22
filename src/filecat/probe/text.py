"""Encoding/newline detection, text sampling, and the text-kind refinements:
CSV / semicolon tables, XML declared encoding, scene-text, lang.dat.

See file-catalog-requirements.md, "Encoding and newlines" and "Probe order" step 11.
"""
from __future__ import annotations

import codecs
import re
from typing import Any

from ..options import SAMPLE_BYTES

_XML_DECL_RE = re.compile(rb'<\?xml[^>]{0,200}?encoding=["\']([^"\']+)["\']', re.IGNORECASE)
_SCENE_VER_RE = re.compile(r"^VER:\s*(\d+)\s*$")
_SEMI_HEADERS = {"version;count", "fields;count"}


def detect_encoding(data: bytes) -> tuple[dict[str, Any], str]:
    """Return (encoding dict, decoded text) per the BOM/UTF-8/Latin-1 rule.

    Latin-1 never fails to decode, so this always succeeds.
    """
    enc: dict[str, Any] = {}
    if data.startswith(b"\xef\xbb\xbf"):
        enc["bom"] = "utf-8"
        body, codec = data[3:], "utf-8"
    elif data.startswith(b"\xff\xfe"):
        enc["bom"] = "utf-16-le"
        body, codec = data[2:], "utf-16-le"
    elif data.startswith(b"\xfe\xff"):
        enc["bom"] = "utf-16-be"
        body, codec = data[2:], "utf-16-be"
    else:
        body, codec = data, None

    if codec is not None:
        text = body.decode(codec, errors="replace")
        return enc, text

    try:
        text = data.decode("utf-8")
        enc["detected"] = "utf-8"
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        enc["detected"] = "latin-1"
    return enc, text


def is_text(head: bytes, size: int) -> bool:
    """No NUL in the first 8 KiB counts as text, except a UTF-16 BOM (NULs expected)."""
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return True
    window = head[: min(size, len(head))]
    return b"\x00" not in window


def classify_newlines(text: str) -> str:
    has_crlf = "\r\n" in text
    rest = text.replace("\r\n", "")
    has_lf = "\n" in rest
    has_cr = "\r" in rest
    kinds = sum((has_crlf, has_lf, has_cr))
    if kinds == 0:
        return "none"
    if kinds > 1:
        return "mixed"
    if has_crlf:
        return "crlf"
    if has_lf:
        return "lf"
    return "cr"


def make_sample(text: str, cap: int = SAMPLE_BYTES) -> tuple[str, bool]:
    """Truncate decoded text to at most `cap` bytes of its UTF-8 encoding.

    Decision: `sample` is capped by bytes of the UTF-8 re-encoding (not by
    character count), since that is what every backend stores it as.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= cap:
        return text, False
    cut = encoded[:cap]
    while cut and (cut[-1] & 0xC0) == 0x80:
        cut = cut[:-1]
    return cut.decode("utf-8", errors="ignore"), True


def check_xml_declared_encoding(head: bytes, enc: dict[str, Any]) -> None:
    """Record encoding.declared / declared_matches when an XML declaration names one."""
    m = _XML_DECL_RE.search(head)
    if not m:
        return
    declared = m.group(1).decode("ascii", errors="ignore")
    enc["declared"] = declared
    actual = enc.get("bom") or enc.get("detected")
    try:
        matches = actual is not None and codecs.lookup(declared).name == codecs.lookup(actual).name
    except LookupError:
        matches = False
    enc["declared_matches"] = matches


def detect_scene_text(text: str) -> int | None:
    """First line `VER:<int>` marks the x3 scene-text grammar (refines text -> mesh)."""
    first_line = text.splitlines()[0] if text else ""
    m = _SCENE_VER_RE.match(first_line.strip())
    return int(m.group(1)) if m else None


def is_x3_bodyfile(text: str) -> bool:
    """Egosoft body text (.bod, or a .pbd once inflated): a `/`-comment
    header naming "EGOSOFT Bodyfile" near the top, before any VER: line."""
    top = text[:1024]
    return "EGOSOFT Bodyfile" in top and top.lstrip().startswith("/")


def detect_lang_dat(text: str) -> int | None:
    """lang.dat's entire body is an integer plus a newline."""
    stripped = text.strip("\r\n")
    if stripped and stripped.isdigit():
        return int(stripped)
    return None


_SEPARATORS = ((",", "comma"), (";", "semicolon"), ("\t", "tab"))


def detect_structured_text(text: str) -> tuple[str, str, int] | None:
    """First-line separator sniff for CSV / semicolon tables.

    Returns (format, separator_name, field_count) or None.
    """
    lines = text.splitlines()
    if not lines:
        return None
    first = lines[0]
    header = first.rstrip(";").strip()
    if header in _SEMI_HEADERS:
        return "semicolon", "semicolon", len(first.split(";"))
    for sep, sep_name in _SEPARATORS:
        parts = first.split(sep)
        if len(parts) >= 2:
            return "csv", sep_name, len(parts)
    return None


_SEP_CHAR = {"comma": ",", "semicolon": ";", "tab": "\t"}


def count_records(path: str, codec: str, cap: int = 10_000) -> tuple[int, bool]:
    """Stream the file as text (best-effort, same codec as the sample) and count
    data records (lines after the header), capped at `cap`."""
    count = 0
    try:
        with open(path, "r", encoding=codec, errors="replace", newline="") as f:
            for count, _ in enumerate(f, start=1):
                if count > cap + 1:
                    break
    except OSError:
        return 0, False
    records = max(count - 1, 0)
    truncated = records > cap
    if truncated:
        records = cap
    return records, truncated


def probe_pdf_version(head: bytes) -> str | None:
    first_line = head.split(b"\n", 1)[0]
    m = re.match(rb"%PDF-(\d+\.\d+)", first_line)
    return m.group(1).decode("ascii") if m else None


# Share of printable bytes above which an unclassified file still gets a
# text sample (used for the Ollama hand-off of kind "unknown").
PRINTABLE_SAMPLE_RATIO = 0.75
_ASCII_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_PRINTABLE = _ASCII_PRINTABLE | frozenset(range(0x80, 0x100))


def printable_sample(head: bytes) -> str | None:
    """Text sample for a file the probe could not classify, or None.

    UTF-16 without a BOM (every other byte NUL) is decoded as UTF-16;
    otherwise NULs and other control bytes become spaces and the rest is
    decoded as UTF-8, falling back to Latin-1, when at least
    PRINTABLE_SAMPLE_RATIO of the head is printable.
    """
    if not head:
        return None
    odd_nuls = head[1::2].count(0)
    if len(head) >= 16 and odd_nuls >= 0.9 * (len(head) // 2) and head[0::2].count(0) < 0.1 * (len(head) // 2):
        body = head[: len(head) // 2 * 2].decode("utf-16-le", errors="replace")
    else:
        # Ratio on ASCII alone: high bytes are as common in noise as in text.
        printable = sum(1 for b in head if b in _ASCII_PRINTABLE)
        if printable < PRINTABLE_SAMPLE_RATIO * len(head):
            return None
        # Control bytes (often NUL field separators) become single spaces.
        kept = re.sub(rb" {2,}", b" ", bytes(b if b in _PRINTABLE else 0x20 for b in head))
        try:
            body = kept.decode("utf-8")
        except UnicodeDecodeError:
            body = kept.decode("latin-1")
    body = body.strip()
    return body or None
