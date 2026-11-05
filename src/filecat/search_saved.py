"""Saved searches and the search export (the viewer's Search page).

Saved searches are shared by everyone who can open the viewer (one list; per-user lists wait for
RBAC). Each is one document of the backend's "server_state" store, key "saved_search:<id>", so they
work under plain `filecat serve` as under `filecat server` (Backend.put_server_doc and friends):

    {key, host: "", id, name, params: {q, root, host, ext, ..., sort, desc}, pinned,
     created_at, updated_at}

The export helpers turn search records into the rows of the CSV / JSONL download.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from . import search

STORE = "server_state"
PREFIX = "saved_search:"
MAX_SAVED = 200
MAX_NAME = 120
MAX_VALUE = 500
PARAM_KEYS = search.SEARCH_FIELDS + ("sort", "desc")
EXPORT_COLUMNS = ("host", "root", "path", "name", "ext", "size", "mtime", "kind", "sha256")
EXPORT_CHUNK = 5000
DEFAULT_EXPORT_MAX = 1_000_000


# --- saved searches ----------------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_params(raw: Any) -> dict[str, str]:
    """Only the known search keys, as short non-empty text; ValueError for anything else."""
    if not isinstance(raw, dict):
        raise ValueError("params must be an object")
    unknown = sorted(set(raw) - set(PARAM_KEYS))
    if unknown:
        raise ValueError(f"unknown search parameter: {unknown[0]}")
    out: dict[str, str] = {}
    for key, value in raw.items():
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            value = "1" if value else "0"
        if not isinstance(value, (str, int)):
            raise ValueError(f"{key} must be text")
        value = str(value).strip()
        if len(value) > MAX_VALUE:
            raise ValueError(f"{key} is too long (at most {MAX_VALUE} characters)")
        if value:
            out[key] = value
    spec = search.with_params(search.parse_query(out.get("q")), out)       # ValueError: a bad query
    if not search.has_criteria(spec):
        raise ValueError("a saved search needs a name pattern or a filter")
    return out


def clean_name(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("name is required")
    name = " ".join(raw.split())
    if len(name) > MAX_NAME:
        raise ValueError(f"name is too long (at most {MAX_NAME} characters)")
    return name


def _public(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: doc.get(k) for k in ("id", "name", "params", "pinned", "created_at", "updated_at")}


def _docs(backend: Any) -> list[dict[str, Any]]:
    try:
        rows = backend.server_docs(STORE)
    except NotImplementedError:
        raise ValueError("this catalog backend cannot store saved searches") from None
    return [d for d in rows if str(d.get("key", "")).startswith(PREFIX)]


def listing(backend: Any) -> list[dict[str, Any]]:
    """Every saved search, pinned first, then by name."""
    rows = [_public(d) for d in _docs(backend)]
    rows.sort(key=lambda d: (not d["pinned"], (d["name"] or "").lower(), d["id"]))
    return rows


def save(backend: Any, body: dict[str, Any]) -> dict[str, Any]:
    """Create (no id) or update (id) a saved search; an update may send any of name, params, pinned."""
    current = {d["id"]: d for d in _docs(backend) if d.get("id")}
    sid = body.get("id")
    if sid is not None:
        if not isinstance(sid, str) or sid not in current:
            raise ValueError("no such saved search")
        doc = dict(current[sid])
    else:
        if len(current) >= MAX_SAVED:
            raise ValueError(f"at most {MAX_SAVED} saved searches; delete some first")
        sid = uuid.uuid4().hex[:12]
        doc = {"key": PREFIX + sid, "host": "", "id": sid, "name": None, "params": None, "pinned": False,
               "created_at": _now()}
        if "name" not in body or "params" not in body:
            raise ValueError("name and params are required")
    if "name" in body:
        doc["name"] = clean_name(body["name"])
    if "params" in body:
        doc["params"] = clean_params(body["params"])
    if "pinned" in body:
        if not isinstance(body["pinned"], bool):
            raise ValueError("pinned must be true or false")
        doc["pinned"] = body["pinned"]
    doc["updated_at"] = _now()
    backend.put_server_doc(STORE, doc)
    return _public(doc)


def delete(backend: Any, sid: Any) -> bool:
    if not isinstance(sid, str) or not sid:
        raise ValueError("id is required")
    found = any(d.get("id") == sid for d in _docs(backend))
    if found:
        backend.delete_server_doc(STORE, PREFIX + sid)
    return found


# --- export ------------------------------------------------------------------------
def is_redacted(doc: dict[str, Any]) -> bool:
    return doc.get("kind") == "rollup" and ((doc.get("probe") or {}).get("rollup") or {}).get("tag") == "[REDACTED]"


def full_path(root: str, rel: str) -> str:
    """The record's path as a person would write it: the root, then the relative path."""
    if not rel:
        return root
    sep = "\\" if "\\" in root and "/" not in root.replace("\\", "") else "/"
    return root.rstrip("/\\") + sep + (rel.replace("/", sep) if sep == "\\" else rel)


def export_row(doc: dict[str, Any]) -> dict[str, Any]:
    root, rel = doc.get("root") or "", doc.get("rel_path") or ""
    ns = doc.get("mtime_ns")
    mtime = ""
    if ns is not None:
        try:
            mtime = datetime.fromtimestamp(int(ns) // 1_000_000_000, timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            mtime = ""
    return {"host": search.host_of(root), "root": root, "path": full_path(root, rel),
            "name": doc.get("name") or "", "ext": doc.get("suffix") or "", "size": doc.get("size"),
            "mtime": mtime, "kind": doc.get("kind") or "", "sha256": doc.get("sha256") or ""}


def export_rows(call: Any, q: dict[str, Any], max_rows: int) -> Iterator[dict[str, Any]]:
    """Every match of query `q` (offset and limit ignored) as export rows, paged through
    Backend.search_names in chunks of EXPORT_CHUNK; stops after max_rows records have been
    examined. [REDACTED] rollups are examined but never yielded. `call` runs a function on the
    backend (Catalog.call)."""
    seen = 0
    while seen < max_rows:
        page = {**q, "offset": seen, "limit": min(EXPORT_CHUNK, max_rows - seen)}
        found = call(lambda b: b.search_names(page))
        for doc in found["rows"]:
            if not is_redacted(doc):
                yield export_row(doc)
        seen += len(found["rows"])
        if not found["more"] or not found["rows"]:
            return


def has_more_after(call: Any, q: dict[str, Any], max_rows: int) -> bool:
    """Whether a record follows the first max_rows of the query (the export is cut short)."""
    found = call(lambda b: b.search_names({**q, "offset": max_rows, "limit": 1}))
    return bool(found["rows"])
