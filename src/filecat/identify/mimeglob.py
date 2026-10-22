"""Vendored freedesktop shared-mime-info database: globs, aliases,
sub-class-of, and magic rules, parsed from ``data/freedesktop.org.xml``.

Parsed once per process and cached (see get_mime_db). Exposes name lookup
(by_name glob matching) and byte-level magic matching, used by
filecat.identify.Identifier to build probe.mime_glob / probe.mime_magic and
to resolve the identify_basis rule (subclass relationships between the
glob type and the magic type).
"""
from __future__ import annotations

import fnmatch
import functools
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "freedesktop.org.xml"
LOCAL_PATH = Path(__file__).resolve().parent.parent / "data" / "filecat-globs.tsv"

# Implicit subclass rules (not written explicitly for every type in the XML).
TEXT_PLAIN = "text/plain"
OCTET_STREAM = "application/octet-stream"
APPLICATION_XML = "application/xml"

_WILDCARD_CHARS = set("*?[")


def _local(tag: str) -> str:
    """Strip the XML namespace from an ElementTree tag."""
    return tag.rsplit("}", 1)[-1]


def _unescape_magic_string(raw: str) -> bytes:
    """Decode a <match value="..."> string per shared-mime-info's C-style
    escaping: \\ddd octal, \\xHH hex, \\n \\r \\t etc., anything else literal."""
    out = bytearray()
    i = 0
    n = len(raw)
    simple = {"n": 0x0A, "r": 0x0D, "t": 0x09, "v": 0x0B, "f": 0x0C,
              "a": 0x07, "b": 0x08, "\\": 0x5C, "'": 0x27, '"': 0x22}
    while i < n:
        c = raw[i]
        if c == "\\" and i + 1 < n:
            nxt = raw[i + 1]
            if nxt == "x":
                j = i + 2
                hexdigits = ""
                while j < n and len(hexdigits) < 2 and raw[j] in "0123456789abcdefABCDEF":
                    hexdigits += raw[j]
                    j += 1
                if hexdigits:
                    out.append(int(hexdigits, 16))
                    i = j
                    continue
                out.append(ord("x"))
                i += 2
                continue
            if nxt in "01234567":
                j = i + 1
                octdigits = ""
                while j < n and len(octdigits) < 3 and raw[j] in "01234567":
                    octdigits += raw[j]
                    j += 1
                out.append(int(octdigits, 8) & 0xFF)
                i = j
                continue
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            # Unknown escape: drop the backslash, keep the character.
            out.extend(_encode_char(nxt))
            i += 2
            continue
        out.extend(_encode_char(c))
        i += 1
    return bytes(out)


def _encode_char(c: str) -> bytes:
    cp = ord(c)
    if cp < 256:
        return bytes([cp])
    return c.encode("utf-8")


def _parse_int_value(raw: str) -> int:
    raw = raw.strip()
    return int(raw, 0)


_WIDTH = {"byte": 1, "big16": 2, "little16": 2, "host16": 2,
          "big32": 4, "little32": 4, "host32": 4}


def _parse_numeric(kind: str, raw: str) -> bytes:
    n = _parse_int_value(raw) & ((1 << (8 * _WIDTH[kind])) - 1)
    width = _WIDTH[kind]
    if kind == "byte":
        return bytes([n])
    endian = "big" if kind.startswith("big") else "little"  # host assumed little (x86/Windows)
    return n.to_bytes(width, endian)


def _parse_value(kind: str, raw: str) -> bytes:
    if kind == "string":
        return _unescape_magic_string(raw)
    return _parse_numeric(kind, raw)


def _parse_mask(kind: str, raw: str, value_len: int) -> bytes | None:
    if raw is None:
        return None
    raw = raw.strip()
    if kind == "string":
        text = raw[2:] if raw.lower().startswith("0x") else raw
        try:
            mask = bytes.fromhex(text)
        except ValueError:
            return None
        if len(mask) < value_len:
            mask = mask + b"\xff" * (value_len - len(mask))
        return mask[:value_len]
    n = _parse_int_value(raw)
    width = _WIDTH[kind]
    n &= (1 << (8 * width)) - 1
    if kind == "byte":
        return bytes([n])
    endian = "big" if kind.startswith("big") else "little"
    return n.to_bytes(width, endian)


def _parse_offset(raw: str) -> tuple[int, int]:
    if ":" in raw:
        lo, hi = raw.split(":", 1)
        return int(lo), int(hi)
    o = int(raw)
    return o, o


@dataclass
class MatchNode:
    offset_lo: int
    offset_hi: int
    value: bytes
    mask: bytes | None
    children: list["MatchNode"] = field(default_factory=list)

    def matches(self, buf: bytes) -> bool:
        vlen = len(self.value)
        if vlen == 0:
            return False
        hi = min(self.offset_hi, max(0, len(buf) - vlen))
        if self.offset_lo > hi:
            return False
        for o in range(self.offset_lo, hi + 1):
            chunk = buf[o:o + vlen]
            if len(chunk) != vlen:
                continue
            if self.mask:
                ok = all((chunk[i] & self.mask[i]) == (self.value[i] & self.mask[i])
                         for i in range(vlen))
            else:
                ok = chunk == self.value
            if ok:
                if not self.children or any(c.matches(buf) for c in self.children):
                    return True
        return False


@dataclass
class MagicRule:
    priority: int
    matches: list[MatchNode]

    def matches_buffer(self, buf: bytes) -> bool:
        return any(m.matches(buf) for m in self.matches)


@dataclass
class MimeType:
    name: str
    comment: str | None = None
    globs: list[tuple[str, int, bool]] = field(default_factory=list)   # pattern, weight, case_sensitive
    magic: list[MagicRule] = field(default_factory=list)
    sub_class_of: list[str] = field(default_factory=list)  # explicit parents, canonical names
    aliases: list[str] = field(default_factory=list)
    has_root_xml: bool = False


def _build_match_node(el: ET.Element) -> MatchNode | None:
    kind = el.get("type")
    value_raw = el.get("value")
    offset_raw = el.get("offset")
    if kind is None or value_raw is None or offset_raw is None:
        return None
    try:
        value = _parse_value(kind, value_raw)
        lo, hi = _parse_offset(offset_raw)
    except (ValueError, KeyError):
        return None
    mask = _parse_mask(kind, el.get("mask"), len(value)) if el.get("mask") else None
    children = []
    for child in el:
        if _local(child.tag) == "match":
            node = _build_match_node(child)
            if node is not None:
                children.append(node)
    return MatchNode(offset_lo=lo, offset_hi=hi, value=value, mask=mask, children=children)


class _GlobIndex:
    """Name-glob lookup tables for one source (freedesktop or the local table).

    Tiers: literal names, then suffix globs (longest match), then other
    fnmatch patterns. Equal-weight conflicts on one literal/suffix key are
    kept in `ties` (only magic can settle them).
    """

    def __init__(self) -> None:
        self.literal: dict[str, tuple[int, str]] = {}      # exact name -> (weight, type)
        self.literal_ci: dict[str, tuple[int, str]] = {}   # lowered name -> (weight, type)
        self.suffix: dict[str, tuple[int, str]] = {}
        self.suffix_ci: dict[str, tuple[int, str]] = {}
        self.other: list[tuple[str, bool, int, str]] = []  # pattern, case_sensitive, weight, type
        self.ties: dict[tuple[int, str], list[str]] = {}

    def empty(self) -> bool:
        return not (self.literal or self.literal_ci or self.suffix or self.suffix_ci or self.other)

    def add(self, pattern: str, weight: int, cs: bool, name: str) -> None:
        if not any(ch in pattern for ch in _WILDCARD_CHARS):
            self._add_best(self.literal if cs else self.literal_ci,
                           pattern if cs else pattern.lower(), weight, name)
        elif pattern.startswith("*") and not any(ch in pattern[1:] for ch in _WILDCARD_CHARS):
            suffix = pattern[1:]
            self._add_best(self.suffix if cs else self.suffix_ci,
                           suffix if cs else suffix.lower(), weight, name)
        else:
            self.other.append((pattern, cs, weight, name))

    def finish(self) -> None:
        # Highest weight first within the "other" tier; stable sort keeps file order as tiebreak.
        self.other.sort(key=lambda t: t[2], reverse=True)

    def _add_best(self, table: dict[str, tuple[int, str]], key: str, weight: int, name: str) -> None:
        current = table.get(key)
        tie_key = (id(table), key)
        if current is None or weight > current[0]:
            table[key] = (weight, name)
            self.ties.pop(tie_key, None)
        elif weight == current[0] and name != current[1]:
            tied = self.ties.setdefault(tie_key, [current[1]])
            if name not in tied:
                tied.append(name)

    def lookup(self, filename: str) -> tuple[tuple[int, int, int], str] | None:
        """Best match as (rank, type); rank = (tier, length, weight), higher wins."""
        lowered = filename.lower()
        hit = self.literal.get(filename) or self.literal_ci.get(lowered)
        if hit:
            return (3, len(filename), hit[0]), hit[1]
        best: tuple[tuple[int, int, int], str] | None = None
        # Suffix patterns need not start at a '.' (e.g. "*,v" for RCS files),
        # so every start position is a candidate; this is bounded by the
        # filename length, not by the number of registered patterns.
        for i in range(len(filename)):
            candidate = filename[i:]
            hit = self.suffix.get(candidate)
            if hit is None:
                hit = self.suffix_ci.get(lowered[i:])
            if hit is not None:
                rank = (2, len(candidate), hit[0])
                if best is None or rank > best[0]:
                    best = (rank, hit[1])
        if best is not None:
            return best
        for pattern, cs, weight, name in self.other:
            if cs:
                ok = fnmatch.fnmatchcase(filename, pattern)
            else:
                ok = fnmatch.fnmatch(lowered, pattern.lower())
            if ok:
                return (1, 0, weight), name
        return None

    def all_for(self, filename: str, winner: str) -> list[str]:
        """Every type tied with `winner` on its literal/suffix key, winner first."""
        lowered = filename.lower()
        keys = [(self.literal, filename), (self.literal_ci, lowered)]
        keys += [(t, k[i:]) for i in range(len(filename))
                 for t, k in ((self.suffix, filename), (self.suffix_ci, lowered))]
        for table, key in keys:
            hit = table.get(key)
            if hit is not None and hit[1] == winner:
                ties = self.ties.get((id(table), key))
                if ties:
                    return [winner] + [t for t in ties if t != winner]
                break
        return [winner]


class MimeDB:
    """Parsed shared-mime-info database: globs, aliases, sub-class-of, magic,
    plus the optional local filecat-globs.tsv layered on top for name lookup."""

    def __init__(self, xml_path: Path = DATA_PATH, local_tsv: Path | str | None = LOCAL_PATH) -> None:
        self.types: dict[str, MimeType] = {}
        self.alias_to_type: dict[str, str] = {}
        self._fd = _GlobIndex()
        self._local = _GlobIndex()
        self._magic_flat: list[tuple[int, str, MagicRule]] = []  # priority, type, rule (sorted desc)
        self._ancestor_cache: dict[str, frozenset[str]] = {}
        self.local_types: set[str] = set()
        self.local_entries = 0
        self.local_errors: list[str] = []   # malformed tsv lines, "file:line: reason"
        self._parse(xml_path)
        self._build_indexes()
        if local_tsv is not None:
            self._load_local(Path(local_tsv))

    # -- parsing -----------------------------------------------------

    def _parse(self, xml_path: Path) -> None:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for mt_el in root:
            if _local(mt_el.tag) != "mime-type":
                continue
            name = mt_el.get("type")
            if not name:
                continue
            mt = MimeType(name=name)
            comment_candidates: dict[str | None, str] = {}
            for child in mt_el:
                tag = _local(child.tag)
                if tag in ("comment", "_comment"):
                    lang = child.get("{http://www.w3.org/XML/1998/namespace}lang") or child.get("xml:lang")
                    if child.text:
                        comment_candidates.setdefault(lang, child.text.strip())
                elif tag == "glob":
                    pattern = child.get("pattern")
                    if not pattern:
                        continue
                    weight = int(child.get("weight", "50"))
                    cs = child.get("case-sensitive", "false").lower() == "true"
                    mt.globs.append((pattern, weight, cs))
                elif tag == "magic":
                    priority = int(child.get("priority", "50"))
                    nodes = []
                    for match_el in child:
                        if _local(match_el.tag) == "match":
                            node = _build_match_node(match_el)
                            if node is not None:
                                nodes.append(node)
                    if nodes:
                        mt.magic.append(MagicRule(priority=priority, matches=nodes))
                elif tag == "sub-class-of":
                    parent = child.get("type")
                    if parent:
                        mt.sub_class_of.append(parent)
                elif tag == "alias":
                    a = child.get("type")
                    if a:
                        mt.aliases.append(a)
                elif tag == "root-XML":
                    mt.has_root_xml = True
            mt.comment = (comment_candidates.get(None) or comment_candidates.get("en")
                          or next(iter(comment_candidates.values()), None))
            self.types[name] = mt
            for a in mt.aliases:
                self.alias_to_type.setdefault(a, name)

    def _build_indexes(self) -> None:
        for name, mt in self.types.items():
            for pattern, weight, cs in mt.globs:
                self._fd.add(pattern, weight, cs, name)
            for rule in mt.magic:
                self._magic_flat.append((rule.priority, name, rule))
        self._fd.finish()
        self._magic_flat.sort(key=lambda t: t[0], reverse=True)

    # -- local table (filecat-globs.tsv) --------------------------------

    def _load_local(self, path: Path) -> None:
        """Columns: pattern, mime, description, weight, note[, sub-class-of].
        A malformed line is recorded in local_errors and skipped."""
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            self.local_errors.append(f"{path}: cannot read: {exc}")
            return
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            cols = line.split("\t")
            where = f"{path.name}:{lineno}"
            if len(cols) < 4:
                self.local_errors.append(f"{where}: expected at least 4 tab-separated columns, got {len(cols)}")
                continue
            pattern, mime, desc, weight_s = (c.strip() for c in cols[:4])
            parents = [p.strip() for p in cols[5].split(",") if p.strip()] if len(cols) > 5 else []
            try:
                weight = int(weight_s)
                if not 0 <= weight <= 100:
                    raise ValueError
            except ValueError:
                self.local_errors.append(f"{where}: bad weight {weight_s!r}")
                continue
            if not pattern or "/" not in mime or " " in mime:
                self.local_errors.append(f"{where}: bad pattern or mime type")
                continue
            mt = self.types.get(self.canon(mime))
            if mt is None:
                mt = MimeType(name=mime, comment=desc or None)
                self.types[mime] = mt
                self.local_types.add(mime)
            elif mime in self.local_types and desc and not mt.comment:
                mt.comment = desc
            for p in parents:
                if p not in mt.sub_class_of:
                    mt.sub_class_of.append(p)
            self._local.add(pattern, weight, False, mt.name)
            self.local_entries += 1
        self._local.finish()
        self._ancestor_cache.clear()

    # -- name lookup ---------------------------------------------------

    def lookup_name_all(self, filename: str) -> list[str]:
        """Every freedesktop type tied for the win on this name, winner first.

        Usually one entry. More than one means equal-weight globs on the same
        pattern (shared-mime-info calls this a conflict for magic to settle).
        Freedesktop only; see lookup_name_merged for the local layer.
        """
        winner = self.lookup_name(filename)
        if winner is None:
            return []
        return self._fd.all_for(filename, winner)

    def lookup_name(self, filename: str) -> str | None:
        """Winning freedesktop glob type for a file name, or None."""
        hit = self._fd.lookup(filename)
        return hit[1] if hit else None

    def lookup_name_merged(self, filename: str) -> tuple[list[str], dict[str, str], list[str]]:
        """Freedesktop + local table. Returns (candidates, source_of, hidden).

        candidates: winner first; several only for equal-rank ties.
        source_of: candidate type -> "freedesktop" | "filecat".
        hidden: freedesktop types that lost to a higher-weight local entry
        (callers keep them visible in mime_glob_alternatives).
        A local entry wins when its rank (tier, match length, weight) beats
        the freedesktop one; at equal rank both are candidates.
        """
        fd = self._fd.lookup(filename)
        loc = None if self._local.empty() else self._local.lookup(filename)
        if loc is None:
            if fd is None:
                return [], {}, []
            cands = self._fd.all_for(filename, fd[1])
            return cands, {c: "freedesktop" for c in cands}, []
        loc_all = self._local.all_for(filename, loc[1])
        if fd is None or loc[0] > fd[0]:
            fd_all = self._fd.all_for(filename, fd[1]) if fd else []
            return loc_all, {c: "filecat" for c in loc_all}, [t for t in fd_all if t not in loc_all]
        fd_all = self._fd.all_for(filename, fd[1])
        if loc[0] < fd[0]:
            return fd_all, {c: "freedesktop" for c in fd_all}, []
        merged = fd_all + [t for t in loc_all if t not in fd_all]
        sources = {c: ("freedesktop" if c in fd_all else "filecat") for c in merged}
        return merged, sources, []

    def comment(self, mime_type: str) -> str | None:
        mt = self.types.get(self.canon(mime_type))
        return mt.comment if mt else None

    # -- alias / subclass -----------------------------------------------

    def canon(self, mime_type: str) -> str:
        """Resolve an alias (e.g. libmagic's quirky names) to the canonical type."""
        seen = set()
        name = mime_type
        while name in self.alias_to_type and name not in seen:
            seen.add(name)
            name = self.alias_to_type[name]
        return name

    def _ancestors(self, type_name: str) -> frozenset[str]:
        cached = self._ancestor_cache.get(type_name)
        if cached is not None:
            return cached
        name = self.canon(type_name)
        mt = self.types.get(name)
        parents: set[str] = set()
        if mt is not None:
            parents.update(self.canon(p) for p in mt.sub_class_of)
            if mt.has_root_xml and name != APPLICATION_XML:
                parents.add(APPLICATION_XML)
        if name.startswith("text/") and name != TEXT_PLAIN:
            parents.add(TEXT_PLAIN)
        if name != OCTET_STREAM:
            parents.add(OCTET_STREAM)
        result: set[str] = set()
        # Guard against cycles via the cache (set before recursing).
        self._ancestor_cache[type_name] = frozenset()
        for p in parents:
            if p == type_name:
                continue
            result.add(p)
            result.update(self._ancestors(p))
        frozen = frozenset(result)
        self._ancestor_cache[type_name] = frozen
        return frozen

    def is_subclass(self, child: str, ancestor: str) -> bool:
        child = self.canon(child)
        ancestor = self.canon(ancestor)
        if child == ancestor:
            return True
        return ancestor in self._ancestors(child)

    # -- byte magic -------------------------------------------------------

    def magic_match_type(self, mime_type: str, buf: bytes) -> bool:
        """True when the named type's own vendored magic rules match buf."""
        mt = self.types.get(self.canon(mime_type))
        if not mt or not mt.magic:
            return False
        return any(rule.matches_buffer(buf) for rule in mt.magic)

    def guess_by_magic(self, buf: bytes) -> tuple[str, str | None] | None:
        """Highest-priority vendored magic match for buf, used when libmagic
        is unavailable. Returns (mime_type, comment)."""
        for priority, name, rule in self._magic_flat:
            if rule.matches_buffer(buf):
                return name, self.comment(name)
        return None


@functools.lru_cache(maxsize=1)
def get_mime_db(xml_path: str | None = None, local_tsv: str | None = None) -> MimeDB:
    """Parsed-once-per-process MimeDB. xml_path/local_tsv are for tests;
    normal callers use the vendored data files."""
    return MimeDB(Path(xml_path) if xml_path else DATA_PATH,
                  Path(local_tsv) if local_tsv else LOCAL_PATH)
