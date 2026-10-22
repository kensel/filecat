"""Compound documents: application formats that use ZIP or gzip as their
container (.docx, .odt, .epub, .jar, X3 savegames...). Their standard
internal structure is not stored as archive members; only anomalies are --
embedded objects, macros, executables, anything outside the expected paths.

The rules live in data/compound_formats.toml (see docs/compound-formats.md):
which extensions are true archives, which are compound formats, the
expected internal paths, the anomaly rules, and the parts that hold embedded
metadata.

for_file() picks the format for one file. filter_members() then decides,
entry by entry, what reaches `members` and returns the summary the document
keeps under probe.compound.
"""
from __future__ import annotations

import functools
import re
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..record import suffix_of

CONFIG_PATH = Path(__file__).resolve().parent.parent / "data" / "compound_formats.toml"

_CONTAINERS = ("zip", "gzip")
_METADATA_LIST_CAP = 10


def _glob_re(glob: str) -> re.Pattern[str]:
    """`*` within one segment, `**` across segments (`**/` also matches no
    segment at all), `?` one character; case-insensitive, whole path."""
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out) + r"\Z", re.IGNORECASE)


@dataclass(frozen=True)
class CompoundFormat:
    id: str
    description: str
    container: str
    kind: str | None
    types: dict[str, str]                 # extension -> MIME type
    names: frozenset[str]                 # exact file names, lower case
    markers: tuple[str, ...]              # entries that identify the format
    expected: tuple[re.Pattern[str], ...]
    anomalies: tuple[tuple[re.Pattern[str], str], ...]
    anomaly_roles: frozenset[str]
    record_unexpected: bool
    metadata: tuple[re.Pattern[str], ...]

    def mime_for(self, name: str) -> str | None:
        return self.types.get(suffix_of(name))

    def member_reason(self, path: str, role: str | None) -> str | None:
        """Why this entry is stored, or None when it is standard structure."""
        if path.endswith("/") or role == "dir":
            return None
        for pattern, reason in self.anomalies:
            if pattern.match(path):
                return reason
        if role in self.anomaly_roles:
            return f"embedded_{role}"
        if any(p.match(path) for p in self.expected):
            return None
        return "unexpected" if self.record_unexpected else None


@dataclass(frozen=True)
class Rules:
    archive_extensions: frozenset[str]
    formats: tuple[CompoundFormat, ...]

    def by_mime(self, mime: str) -> CompoundFormat | None:
        mime = mime.lower()
        return next((f for f in self.formats if mime in (m.lower() for m in f.types.values())), None)


def parse(cfg: dict[str, Any]) -> Rules:
    """Rules from the parsed TOML; ValueError on anything malformed."""
    if cfg.get("version") != 1:
        raise ValueError(f"compound formats: unsupported version {cfg.get('version')!r}")
    defaults = cfg.get("defaults", {})
    default_roles = defaults.get("anomaly_roles", [])
    default_unexpected = defaults.get("record_unexpected", True)
    formats = []
    for fid, f in cfg.get("compound", {}).items():
        container = f.get("container")
        if container not in _CONTAINERS:
            raise ValueError(f"compound format {fid}: container must be one of {_CONTAINERS}")
        if not f.get("types") and not f.get("names") and not f.get("markers"):
            raise ValueError(f"compound format {fid}: needs types, names or markers")
        formats.append(CompoundFormat(
            id=fid,
            description=f.get("description", ""),
            container=container,
            kind=f.get("kind"),
            types={ext.lower(): mime for ext, mime in f.get("types", {}).items()},
            names=frozenset(n.lower() for n in f.get("names", [])),
            markers=tuple(f.get("markers", [])),
            expected=tuple(_glob_re(g) for g in f.get("expected", [])),
            anomalies=tuple((_glob_re(a["glob"]), a["reason"]) for a in f.get("anomalies", [])),
            anomaly_roles=frozenset(f.get("anomaly_roles", default_roles)),
            record_unexpected=f.get("record_unexpected", default_unexpected),
            metadata=tuple(_glob_re(g) for g in f.get("metadata", [])),
        ))
    archive = frozenset(e.lower() for e in cfg.get("archive", {}).get("extensions", []))
    return Rules(archive_extensions=archive, formats=tuple(formats))


@functools.cache
def rules() -> Rules:
    with open(CONFIG_PATH, "rb") as fh:
        return parse(tomllib.load(fh))


def _suffixes(name: str) -> tuple[str, ...]:
    """'gz' and 'tar.gz' for 'x.tar.gz'."""
    last = suffix_of(name)
    if not last:
        return ()
    stem = name[: -len(last) - 1]
    prev = suffix_of(stem)
    return (last, f"{prev}.{last}") if prev else (last,)


def for_file(name: str, container: str, entries: Iterable[str] | None = None,
             table: Rules | None = None) -> CompoundFormat | None:
    """The compound format of one file, or None to treat it as an archive.

    An exact file name wins, then a true-archive extension (always None),
    then a format extension, then -- for a ZIP whose extension says nothing --
    the format whose markers are all among its entries (most markers wins).
    """
    table = table or rules()
    lname = name.lower()
    candidates = [f for f in table.formats if f.container == container]
    for f in candidates:
        if lname in f.names:
            return f
    suffixes = _suffixes(name)
    if any(s in table.archive_extensions for s in suffixes):
        return None
    for f in candidates:
        if any(s in f.types for s in suffixes):
            return f
    if entries is None:
        return None
    present = {e.lower() for e in entries}
    best, best_n = None, 0
    for f in candidates:
        if f.markers and all(m.lower() in present for m in f.markers) and len(f.markers) > best_n:
            best, best_n = f, len(f.markers)
    return best


def filter_members(fmt: CompoundFormat, name: str, rows: list[dict[str, Any]],
                   keep_all: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(rows to store, probe.compound summary). Every stored anomaly carries
    `anomaly: <reason>`; with keep_all the standard entries are stored too
    (--expand-compound), still marked."""
    kept: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    expected = 0
    for row in rows:
        reason = fmt.member_reason(row["path"], row.get("role"))
        if reason is None:
            expected += 1
            if keep_all:
                kept.append(row)
            continue
        reasons[reason] += 1
        kept.append({**row, "anomaly": reason})
    summary: dict[str, Any] = {"format": fmt.id, "entries": len(rows), "expected": expected,
                               "anomalies": sum(reasons.values())}
    mime = fmt.mime_for(name)
    if mime:
        summary["mime"] = mime
    if reasons:
        summary["reasons"] = dict(reasons.most_common())
    paths = [r["path"] for r in rows]
    present = {p.lower() for p in paths}
    if fmt.markers and not all(m.lower() in present for m in fmt.markers):
        summary["marker_missing"] = True   # the extension says one thing, the entries another
    meta = [p for p in paths if any(m.match(p) for m in fmt.metadata)]
    if meta:
        summary["metadata_parts"] = meta[:_METADATA_LIST_CAP]
    return kept, summary
