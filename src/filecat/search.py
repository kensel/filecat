"""File-name search: the query language of the viewer's Search page.

Everything-style (voidtools): the text is split at spaces, every term must
match (AND), and a term is either a name pattern or a `key:value` filter.

    eve*.exe            wildcards: `*` any run of characters, `?` one character;
                        a pattern with a wildcard must match the whole name
    setup               no wildcard: the name contains it (the same as `*setup*`)
    "my file"           quotes keep a space in one term
    ext:exe;dll         extensions (`;` or `,` separate several), no dot needed
    size:>10mb          `>`, `>=`, `<`, `<=`, `=`, or a range `1mb..1gb`;
                        units b, kb, mb, gb, tb (powers of 1024)
    after:2024-01-01    modified on or after / before (UTC dates or ISO times)
    before:2025-06-30
    kind:dir            dir (or folder), file (not a folder or a rollup),
                        rollup, or any stored kind (image, text, ...)
    root:homes          roots whose path contains the text (case-insensitive);
                        an exact root string is taken as is
    host:nas-*          roots on that host (the host of `\\\\host\\share`
                        or `//host/share`; wildcards allowed); local roots have
                        host "" and are chosen with `host:-`

Matching is case-insensitive and against the record's *name* only, never its
path or anything below it: a rolled-up folder (a `[CACHE]` or `[REDACTED]`
record) is found by its own name, and what it folds in is not stored, so
there is nothing else to find. Archive members and dropped records are not
searched.

This module only parses and translates. The filters themselves are part of
filecat.browse (`matches`, `sql_where`, Mongo's `_browse_filter`), which
every backend's `search_names()` runs, so one rule set drives all of them.
Case folding is the backend's: Python and MongoDB fold all of Unicode,
SQLite's LIKE only ASCII.
"""
from __future__ import annotations

import fnmatch
import functools
import re
from datetime import datetime, timezone
from typing import Any

KEYS = ("ext", "size", "after", "before", "kind", "root", "host")
ESCAPE = "!"                    # the LIKE escape character
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
SORTS = ("name", "size", "mtime_ns", "rel_path", "kind")
_UNITS = {"": 1, "b": 1, "k": 1024, "kb": 1024, "m": 1024 ** 2, "mb": 1024 ** 2,
          "g": 1024 ** 3, "gb": 1024 ** 3, "t": 1024 ** 4, "tb": 1024 ** 4}
_TERM = re.compile(r'(?:(\w+):)?(?:"([^"]*)"|(\S+))')
_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([a-z]*)\s*$", re.I)
_HOST = re.compile(r"^(?:\\\\|//)([^\\/]+)")


def empty() -> dict[str, Any]:
    return {"names": [], "exts": [], "min_size": None, "max_size": None, "after": None, "before": None,
            "kind": None, "root_terms": [], "host_terms": []}


# --- values ------------------------------------------------------------------
def parse_size(text: str) -> int:
    m = _SIZE.match(text or "")
    if not m or m.group(2).lower() not in _UNITS:
        raise ValueError(f"not a size: {text!r} (try 10mb, 500kb, 1.5gb)")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


def parse_time(text: str) -> int:
    """A UTC date or ISO time as nanoseconds since the epoch."""
    try:
        when = datetime.fromisoformat((text or "").strip())
    except ValueError:
        raise ValueError(f"not a date: {text!r} (try 2024-01-31 or 2024-01-31T12:00)") from None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return int(when.timestamp()) * 1_000_000_000 + when.microsecond * 1000


def _size_filter(spec: dict[str, Any], value: str) -> None:
    value = value.strip()
    if ".." in value:
        lo, _, hi = value.partition("..")
        bounds = [(">=", lo), ("<=", hi)] if lo and hi else [(">=", lo)] if lo else [("<=", hi)]
    else:
        m = re.match(r"^(>=|<=|>|<|=)?\s*(.+)$", value)
        bounds = [(m.group(1) or "=", m.group(2))] if m else []
    if not bounds:
        raise ValueError(f"not a size filter: {value!r}")
    for op, text in bounds:
        n = parse_size(text)
        if op in (">", ">="):
            lo = n + 1 if op == ">" else n
            spec["min_size"] = lo if spec["min_size"] is None else max(spec["min_size"], lo)
        if op in ("<", "<="):
            hi = n - 1 if op == "<" else n
            spec["max_size"] = hi if spec["max_size"] is None else min(spec["max_size"], hi)
        if op == "=":
            spec["min_size"] = spec["max_size"] = n


def _apply(spec: dict[str, Any], key: str, value: str) -> None:
    if key == "ext":
        spec["exts"] += [e.strip().lstrip(".").lower() for e in re.split(r"[;,]", value) if e.strip(". ")]
    elif key == "size":
        _size_filter(spec, value)
    elif key == "after":
        spec["after"] = parse_time(value)
    elif key == "before":
        spec["before"] = parse_time(value)
    elif key == "kind":
        spec["kind"] = {"folder": "dir", "directory": "dir", "folders": "dir", "dirs": "dir"}.get(
            value.lower(), value.lower())
    elif key == "root":
        spec["root_terms"].append(value)
    elif key == "host":
        spec["host_terms"].append(value)


def parse_query(text: str | None) -> dict[str, Any]:
    """The criteria in a query text (see the module docstring); ValueError for a bad one."""
    spec = empty()
    for m in _TERM.finditer(text or ""):
        key, quoted, bare = m.group(1), m.group(2), m.group(3)
        if key and key.lower() in KEYS and (quoted if quoted is not None else bare):
            _apply(spec, key.lower(), quoted if quoted is not None else bare)
        else:               # a name term; `c:\x` is a name pattern too, not an unknown filter
            term = quoted if quoted is not None else m.group(0)
            if term:
                spec["names"].append(term)
    return spec


def with_params(spec: dict[str, Any], p: dict[str, Any]) -> dict[str, Any]:
    """`spec` plus the separate URL parameters (ext, min_size, max_size, after, before,
    kind, root, host). A parameter narrows what the text already says."""
    spec = {k: (list(v) if isinstance(v, list) else v) for k, v in spec.items()}
    for key in ("ext", "after", "before", "kind", "root", "host"):
        if p.get(key):
            _apply(spec, key, str(p[key]))
    for key, field in (("min_size", ">="), ("max_size", "<=")):
        if p.get(key):
            _size_filter(spec, field + str(p[key]))
    return spec


def has_criteria(spec: dict[str, Any]) -> bool:
    return any(spec[k] for k in ("names", "exts", "kind", "root_terms", "host_terms")) or any(
        spec[k] is not None for k in ("min_size", "max_size", "after", "before"))


# --- roots -------------------------------------------------------------------
def host_of(root: str) -> str:
    """The host of a UNC root (`\\\\host\\share`, `//host/share`); "" for a local path."""
    m = _HOST.match(root)
    return m.group(1).lower() if m else ""


def resolve_roots(spec: dict[str, Any], roots: list[str]) -> list[str] | None:
    """The roots the `root:` and `host:` terms leave, or None when there are none.
    An empty list means no root matches (so the search finds nothing)."""
    if not spec["root_terms"] and not spec["host_terms"]:
        return None
    keep = list(roots)
    for term in spec["root_terms"]:
        exact = [r for r in keep if r.lower() == term.lower()]
        keep = exact or [r for r in keep if term.lower() in r.lower()]
    for term in spec["host_terms"]:
        want = "" if term == "-" else term.lower()
        keep = [r for r in keep if fnmatch.fnmatchcase(host_of(r), want)]
    return keep


# --- patterns ----------------------------------------------------------------
def has_wildcard(glob: str) -> bool:
    return "*" in glob or "?" in glob


def _glob_parts(glob: str) -> list[tuple[str, str]]:
    """[("lit", text) | ("any", "") | ("one", "")], runs of `*` merged."""
    parts: list[tuple[str, str]] = []
    for ch in glob:
        if ch == "*":
            if not parts or parts[-1][0] != "any":
                parts.append(("any", ""))
        elif ch == "?":
            parts.append(("one", ""))
        elif parts and parts[-1][0] == "lit":
            parts[-1] = ("lit", parts[-1][1] + ch)
        else:
            parts.append(("lit", ch))
    return parts


def regex_of(glob: str) -> str:
    """A regular expression (Python and PCRE) for one name term. Whole-name for a term with a
    wildcard, "contains" for plain text; anchored at an end only where the pattern is."""
    if not has_wildcard(glob):
        return re.escape(glob)
    parts = _glob_parts(glob)
    start, end = "" if parts[0][0] == "any" else "^", "" if parts[-1][0] == "any" else "$"
    while parts and parts[0][0] == "any":     # `.*` at an end says nothing to a search()
        parts.pop(0)
    while parts and parts[-1][0] == "any":
        parts.pop()
    body = "".join(re.escape(t) if k == "lit" else ".*" if k == "any" else "." for k, t in parts)
    return start + body + end


@functools.lru_cache(maxsize=256)
def compiled(glob: str) -> re.Pattern[str]:
    return re.compile(regex_of(glob), re.IGNORECASE | re.DOTALL)


def name_matches(name: str | None, glob: str) -> bool:
    return compiled(glob).search(name or "") is not None


def like_of(glob: str, brackets: bool = False) -> str:
    """The LIKE pattern for one name term, with `!` as the escape character. Plain text is
    wrapped in `%`; `brackets`: also escape `[` (SQL Server treats it as a wildcard)."""
    special = {"%", "_", ESCAPE} | ({"["} if brackets else set())

    def lit(text: str) -> str:
        return "".join(ESCAPE + c if c in special else c for c in text)

    if not has_wildcard(glob):
        return "%" + lit(glob) + "%"
    return "".join(lit(t) if k == "lit" else "%" if k == "any" else "_" for k, t in _glob_parts(glob))


# --- the query for Backend.search_names() ----------------------------------------
def to_query(spec: dict[str, Any], roots: list[str] | None, *, sort: str | None = None,
             desc: Any = None, offset: Any = 0, limit: Any = DEFAULT_LIMIT) -> dict[str, Any]:
    """A browse-style query (filecat.browse) for the criteria; `roots` as resolve_roots()
    returned them."""
    q: dict[str, Any] = {"depth": 2}
    if spec["names"]:
        q["names"] = list(spec["names"])
    if spec["exts"]:
        q["exts"] = sorted(set(spec["exts"]))
    for k in ("min_size", "max_size", "after", "before"):
        if spec[k] is not None:
            q[k] = spec[k]
    kind = spec["kind"]
    if kind == "file":
        q["not_kinds"] = ["dir", "rollup"]      # unlike files_only, unreadable files are found too
    elif kind:
        q["kind"] = kind
    if roots is not None:
        q["roots"] = list(roots)
    q["sort"] = sort if sort in SORTS else "name"
    q["desc"] = (q["sort"] in ("size", "mtime_ns")) if desc in (None, "") else \
        str(desc).lower() in ("1", "true", "yes", "on")
    q["offset"] = max(0, int(offset or 0))
    q["limit"] = min(MAX_LIMIT, max(1, int(limit or DEFAULT_LIMIT)))
    return q


def describe(spec: dict[str, Any]) -> dict[str, Any]:
    """The parsed criteria as the page shows them (no empty entries)."""
    return {k: v for k, v in spec.items() if v not in (None, [], "")}
