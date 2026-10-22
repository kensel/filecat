"""Record queries for `filecat serve`: filter, sort and page the catalog.

A query is a dict of filters (see FILTERS) plus sort / desc / offset / limit.
The filters mirror the keys `filecat summary` groups by, so drilling into a
summary row lists exactly the records that row counted:

* suffix  -- the agg_suffix key: the record's suffix, "(none)" for no suffix
* mime    -- the agg_mime key: mime, else kind, else "unknown"
* dir     -- the agg_dir key at `depth` (filecat.aggregate.dir_key)
* parent  -- exact parent directory, "" for the root's own children
             (the folder browser; dirs included)
* kind    -- record kind
* q       -- case-insensitive substring of rel_path
* files_only -- what the aggregates sum: kind != "dir" and not unreadable
* unreadable -- only the entries summary counts as unreadable
* errors  -- only records that carry an `errors` entry (dirs included)

`query_documents()` is the in-Python implementation every backend gets
from Backend.query(); SQL backends override it with `sql_where()` and
`sql_order()` so one rule set drives both paths.

`subtree_documents()` / `sql_subtree()` back Backend.subtree(): the child
folders of one directory with the files and bytes beneath each, derived
from file paths so folders show up (with WinDirStat-style totals) even
before a scan has written their dir records.

`size_rows()` / `sql_sizes()` back Backend.sizes(): path, size, suffix and
type of every readable file beneath a folder, for the treemap (treemap.py).
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, Iterator

from .aggregate import dir_key

FILTERS = ("root", "kind", "suffix", "mime", "dir", "parent", "q", "files_only", "unreadable", "errors")
SORTS = ("size", "name", "rel_path", "mtime_ns", "kind", "suffix")
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

Query = dict[str, Any]


def normalize(raw: dict[str, Any]) -> Query:
    """Clean a query from the web layer: drop empty values, clamp paging."""
    # parent="" is meaningful (the root's own children); other empty values are unset
    q: Query = {k: raw[k] for k in FILTERS
                if raw.get(k) is not None and (raw[k] != "" or k == "parent")}
    for flag in ("files_only", "unreadable", "errors"):
        if flag in q:
            q[flag] = str(q[flag]).lower() in ("1", "true", "yes", "on")
            if not q[flag]:
                del q[flag]
    q["depth"] = int(raw.get("depth") or 2)
    sort = raw.get("sort") or "size"
    q["sort"] = sort if sort in SORTS else "size"
    desc = raw.get("desc")
    q["desc"] = (q["sort"] in ("size", "mtime_ns")) if desc in (None, "") else \
        str(desc).lower() in ("1", "true", "yes", "on")
    q["offset"] = max(0, int(raw.get("offset") or 0))
    q["limit"] = min(MAX_LIMIT, max(1, int(raw.get("limit") or DEFAULT_LIMIT)))
    return q


# --- Python path ------------------------------------------------------
def is_unreadable(doc: dict[str, Any]) -> bool:
    """Same rule as aggregate.build_aggregates: errors and no size at all."""
    return bool(doc.get("errors")) and doc.get("size") is None


def parent_of(rel_path: str) -> str:
    return rel_path.rsplit("/", 1)[0] if "/" in rel_path else ""


def matches(doc: dict[str, Any], q: Query) -> bool:
    rel = doc.get("rel_path") or ""
    if "kind" in q and doc.get("kind") != q["kind"]:
        return False
    if q.get("files_only") and (doc.get("kind") == "dir" or is_unreadable(doc)):
        return False
    if q.get("unreadable") and (doc.get("kind") == "dir" or not is_unreadable(doc)):
        return False
    if q.get("errors") and not doc.get("errors"):
        return False
    if "suffix" in q and (doc.get("suffix") or "(none)") != q["suffix"]:
        return False
    if "mime" in q and (doc.get("mime") or doc.get("kind") or "unknown") != q["mime"]:
        return False
    if "dir" in q and (not rel or dir_key(rel, q["depth"]) != q["dir"]):
        return False
    if "parent" in q and (not rel or parent_of(rel) != q["parent"]):
        return False
    if "q" in q and q["q"].lower() not in rel.lower():
        return False
    return True


def _sort_key(sort: str) -> Callable[[dict[str, Any]], Any]:
    if sort in ("size", "mtime_ns"):
        return lambda d: d.get(sort) or 0
    return lambda d: d.get(sort) or ""


def query_documents(documents: Iterable[dict[str, Any]], q: Query) -> dict[str, Any]:
    """{"total": n, "bytes": sum of size, "rows": [documents of the page]}."""
    hits = [d for d in documents if matches(d, q)]
    hits.sort(key=lambda d: d.get("rel_path") or "")
    hits.sort(key=_sort_key(q["sort"]), reverse=q["desc"])
    if "parent" in q:  # folders first, like a file manager
        hits.sort(key=lambda d: d.get("kind") != "dir")
    page = hits[q["offset"]:q["offset"] + q["limit"]]
    return {"total": len(hits), "bytes": sum(d.get("size") or 0 for d in hits), "rows": page}


def subtree_documents(documents: Iterable[dict[str, Any]], parent: str) -> list[dict[str, Any]]:
    """[{"name", "files", "bytes"}] per child folder of `parent`, counting
    the readable files anywhere beneath it; biggest first."""
    prefix = parent + "/" if parent else ""
    counts: dict[str, list[int]] = {}
    for doc in documents:
        rel = doc.get("rel_path") or ""
        if doc.get("kind") == "dir" or is_unreadable(doc) or not rel.startswith(prefix):
            continue
        rest = rel[len(prefix):]
        if "/" not in rest:
            continue
        row = counts.setdefault(rest.split("/", 1)[0], [0, 0])
        row[0] += 1
        row[1] += doc.get("size") or 0
    return sorted(({"name": k, "files": f, "bytes": b} for k, (f, b) in counts.items()),
                  key=lambda r: (-r["bytes"], r["name"]))


def size_rows(documents: Iterable[dict[str, Any]], prefix: str) -> Iterator[tuple[str, int, str, str]]:
    """(rel_path, size, suffix, mime key) of each readable file beneath
    `prefix` ("" = the whole root): what Backend.sizes() returns. The mime
    key is the agg_mime one (mime, else kind, else "unknown")."""
    start = prefix + "/" if prefix else ""
    for doc in documents:
        rel = doc.get("rel_path") or ""
        if not rel or doc.get("kind") == "dir" or is_unreadable(doc) or not rel.startswith(start):
            continue
        yield (rel, doc.get("size") or 0, doc.get("suffix") or "",
               doc.get("mime") or doc.get("kind") or "unknown")


# --- SQL path ---------------------------------------------------------
class Dialect:
    """How one SQL server spells the few functions the filters need.

    ph: parameter placeholder. substr(expr, start) -> SQL for the rest of
    expr from a 1-based position. left(expr, n) -> its first n characters.
    instr(expr, needle) -> SQL giving the 1-based position of needle in
    expr, 0 when absent. has_errors: SQL true for a record whose stored
    document has `errors`. byte_ranges: text compares byte by byte, so
    "starts with P/" can also be said as the index-friendly range
    P/ <= rel_path < P0 ('0' follows '/'); only sqlite's default BINARY
    collation guarantees that. collate: suffix that makes a text column sort
    by code point, as Python does, rather than by the server's default
    language-aware collation (which skips punctuation and folds case).
    nulls_high: the server sorts NULL above every value (Postgres), so
    ORDER BY must say NULLS FIRST/LAST to keep it lowest, as Python's
    missing-is-0 sort and the other servers do.
    """

    def __init__(self, ph: str, substr: Callable[[str, str], str], left: Callable[[str, str], str],
                 instr: Callable[[str, str], str], lower: str, has_errors: str,
                 byte_ranges: bool = False, collate: str = "", nulls_high: bool = False) -> None:
        self.ph, self.substr, self.left, self.instr = ph, substr, left, instr
        self.lower, self.has_errors, self.byte_ranges = lower, has_errors, byte_ranges
        self.collate, self.nulls_high = collate, nulls_high


SQLITE = Dialect("?", lambda e, p: f"substr({e}, {p})", lambda e, n: f"substr({e}, 1, {n})",
                 lambda e, n: f"instr({e}, {n})",
                 "lower", "json_extract(document, '$.errors') IS NOT NULL", byte_ranges=True)
POSTGRES = Dialect("%s", lambda e, p: f"substr({e}, {p})", lambda e, n: f"substr({e}, 1, {n})",
                   lambda e, n: f"strpos({e}, {n})", "lower", "document ? 'errors'",
                   collate=' COLLATE "C"', nulls_high=True)
MYSQL = Dialect("%s", lambda e, p: f"SUBSTRING({e}, {p})", lambda e, n: f"SUBSTRING({e}, 1, {n})",
                lambda e, n: f"LOCATE({n}, {e})",
                "LOWER", "JSON_CONTAINS_PATH(document, 'one', '$.errors')", collate=" COLLATE utf8mb4_bin")
MSSQL = Dialect("?", lambda e, p: f"SUBSTRING({e}, {p}, 4000)", lambda e, n: f"SUBSTRING({e}, 1, {n})",
                lambda e, n: f"CHARINDEX({n}, {e})",
                "LOWER", "JSON_QUERY(document, '$.errors') IS NOT NULL", collate=" COLLATE Latin1_General_BIN2")


def sql_where(q: Query, d: Dialect, root_id_value: str | None) -> tuple[str, list[Any]]:
    """WHERE clause (with leading ' WHERE ', or '') and its parameters, over
    the `files` table columns every SQL backend shares."""
    ph = d.ph
    clauses: list[str] = []
    params: list[Any] = []

    def add(sql: str, *values: Any) -> None:
        clauses.append(sql)
        params.extend(values)

    def under(prefix: str) -> None:
        """rel_path starts with prefix + '/'. A plain comparison, not LIKE,
        so '_' and '%' in names need no escaping."""
        if d.byte_ranges:  # lets the (root_id, rel_path) index find the subtree
            add(f"rel_path >= {ph} AND rel_path < {ph}", prefix + "/", prefix + "0")
        add(f"{d.substr('rel_path', ph)} <> ''", len(prefix) + 2)  # something after the slash
        add(f"{d.instr('rel_path', ph)} = 1", prefix + "/")

    def no_slash_after(start: int) -> None:
        # '/' inline, not a parameter: LOCATE and CHARINDEX put the needle
        # first, which would hand the placeholders their values swapped
        slash = "'/'"
        add(f"{d.instr(d.substr('rel_path', ph), slash)} = 0", start)

    unreadable = f"(size IS NULL AND {d.has_errors})"
    if root_id_value is not None:
        add(f"root_id = {ph}", root_id_value)
    if "kind" in q:
        add(f"kind = {ph}", q["kind"])
    if q.get("files_only"):
        add(f"kind <> 'dir' AND NOT {unreadable}")
    if q.get("unreadable"):
        add(f"kind <> 'dir' AND {unreadable}")
    if q.get("errors"):
        add(d.has_errors)
    if "suffix" in q:
        if q["suffix"] == "(none)":
            add("(suffix IS NULL OR suffix = '')")
        else:
            add(f"suffix = {ph}", q["suffix"])
    if "mime" in q:
        add(f"COALESCE(NULLIF(mime, ''), kind, 'unknown') = {ph}", q["mime"])
    if "dir" in q:
        key, depth = q["dir"], q["depth"]
        if key == ".":
            add("rel_path <> ''")
            no_slash_after(1)
        else:
            under(key)
            if len(key.split("/")) < depth:  # a shallow key holds only direct children
                no_slash_after(len(key) + 2)
    if "parent" in q:
        if q["parent"] == "":
            add("rel_path <> ''")
            no_slash_after(1)
        else:
            under(q["parent"])
            no_slash_after(len(q["parent"]) + 2)
    if "q" in q:
        add(f"{d.instr(d.lower + '(rel_path)', d.lower + '(' + ph + ')')} > 0", q["q"])
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def sql_subtree(parent: str, d: Dialect, root_id_value: str) -> tuple[str, list[Any]]:
    """SELECT name, files, bytes for subtree_documents(), grouped in SQL.

    The child folder name is the text between parent + '/' and the next
    '/'; positions are computed here, so only the WHERE takes parameters.
    """
    q: Query = {"files_only": True, "depth": 1}
    if parent:  # a dir key as deep as parent itself covers everything beneath it
        q["dir"], q["depth"] = parent, len(parent.split("/"))
    where, params = sql_where(q, d, root_id_value)
    rest = d.substr("rel_path", str(len(parent) + 2 if parent else 1))
    cut = d.instr(rest, "'/'")
    # guarded so no server sees a negative length, whatever order it evaluates in
    name = d.left(rest, f"CASE WHEN {cut} > 0 THEN {cut} - 1 ELSE 0 END")
    sql = (f"SELECT {name}, COUNT(*), COALESCE(SUM(size), 0) FROM files{where} AND {cut} > 0 "
           f"GROUP BY {name}")
    return sql, params


def sql_sizes(prefix: str, d: Dialect, root_id_value: str) -> tuple[str, list[Any]]:
    """SELECT rel_path, size, suffix, mime key for size_rows(): only the
    columns, so the server never sends (or parses) the documents."""
    q: Query = {"files_only": True, "depth": 1}
    if prefix:
        q["dir"], q["depth"] = prefix, len(prefix.split("/"))
    where, params = sql_where(q, d, root_id_value)
    return (f"SELECT rel_path, COALESCE(size, 0), COALESCE(suffix, ''), "
            f"COALESCE(NULLIF(mime, ''), kind, 'unknown') FROM files{where}", params)


TEXT_SORTS = ("name", "rel_path", "kind", "suffix")


def sql_order(q: Query, d: Dialect = SQLITE) -> str:
    """ORDER BY body (column names are from SORTS, never from the request)."""
    col = q["sort"] if q["sort"] in SORTS else "size"
    direction = "DESC" if q["desc"] else "ASC"
    collate = d.collate if col in TEXT_SORTS else ""
    nulls = (" NULLS LAST" if q["desc"] else " NULLS FIRST") if d.nulls_high else ""
    parts = [f"{col}{collate} {direction}{nulls}"]
    if col != "rel_path":  # SQL Server rejects a column listed twice
        parts.append(f"rel_path{d.collate} ASC")
    if "parent" in q:
        parts.insert(0, "CASE WHEN kind = 'dir' THEN 0 ELSE 1 END")
    return ", ".join(parts)
