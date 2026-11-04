"""The data behind `GET /api/rollups?root=&tag=` of `filecat serve` (the Rollups page).

The audit screen of docs/rollups.md: the counts `filecat rollups list` prints,
from the same `Backend.rollup_totals`, one row per (root, tag, parent folder)
with files, folders, size, newest modification, the `partial` / errors flags
and how each was made (the kinds of rule, never a pattern).

Privacy (docs/rollups.md section 3): a `[REDACTED]` row is counts only, like
`rollups list` prints it: the folder it sits in, its totals and rule kinds.
It carries no `rel_path` (the page links nothing for it) and no modification
time (`rollups list` prints one; the page, like the inspector card, does not)
and nothing else derived from what is inside. The tag is the record's own tag, never a name.
"""
from __future__ import annotations

from typing import Any

from . import rollup
from .backends.base import Backend

SUM_FIELDS = ("folders", "matched", "total_files", "total_dirs", "size", "allocated_size", "errors", "partial")


def _row(root: str, r: dict[str, Any]) -> dict[str, Any]:
    tag, parent = r["tag"], r["parent"]
    redacted = tag == rollup.REDACTED
    row: dict[str, Any] = {
        "root": root, "tag": tag, "parent": parent, "redacted": redacted,
        "folders": r["folders"], "matched": r["matched"], "files": r["total_files"], "dirs": r["total_dirs"],
        "size": r["size"], "allocated_size": r["allocated_size"] or None,
        "newest_mtime_ns": None if redacted else (r["newest_mtime_ns"] or None), "errors": r["errors"], "partial": r["partial"],
        "rules": dict(r["rules"])}
    if not redacted:
        # the record `parent/[TAG]` (rollup.py: one record per parent and tag); a row of
        # several records has no single one to open
        row["rel_path"] = f"{parent}/{tag}" if parent else tag
    return row


def _sum(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    out: dict[str, Any] = {key: None, "rollups": 0, "files": 0, "dirs": 0, "size": 0, "newest_mtime_ns": None,
                           "partial": 0, "errors": 0}
    for r in rows:
        out["rollups"] += r["folders"]
        out["files"] += r["files"]
        out["dirs"] += r["dirs"]
        out["size"] += r["size"]
        out["partial"] += r["partial"]
        out["errors"] += r["errors"]
        if r["newest_mtime_ns"] and (out["newest_mtime_ns"] or 0) < r["newest_mtime_ns"]:
            out["newest_mtime_ns"] = r["newest_mtime_ns"]
    return out


def build(backend: Backend, root: str | None = None, tag: str | None = None) -> dict[str, Any]:
    """{"rows", "roots", "tags", "by_tag", "by_root", "totals", "filter", "stores"}: `roots` and
    `tags` list every choice (ignoring the filters) for the page's drop-downs. `stores` are the
    tagged backup and database store folders (Backend.store_folders) with the same filters, each
    saying whether its bulk folders rolled up (`rolled`): a Veeam job is a [BACKUP] whose files
    stay listed."""
    everything = backend.rollup_totals()
    all_rows = [_row(rt, r) for rt, rows in everything.items() for r in rows]
    wanted_tag = (tag or "").upper() or None
    rows = [r for r in all_rows if (not root or r["root"] == root) and (not wanted_tag or r["tag"].upper() == wanted_tag)]
    by_tag = []
    for t in sorted({r["tag"] for r in rows}):
        by_tag.append({**_sum([r for r in rows if r["tag"] == t], "tag"), "tag": t})
    by_root = []
    for rt in sorted({r["root"] for r in rows}):
        by_root.append({**_sum([r for r in rows if r["root"] == rt], "root"), "root": rt})
    totals = _sum(rows, "total")
    totals.pop("total")
    stores = []
    rolled = {(r["root"], r["parent"], r["tag"]) for r in all_rows}
    try:
        found = list(backend.store_folders())
    except NotImplementedError:
        found = []
    for s in sorted(found, key=lambda s: (s["root"] or "", s["rel_path"])):
        if (root and s["root"] != root) or (wanted_tag and s["store_tag"].upper() != wanted_tag):
            continue
        stores.append({"root": s["root"], "rel_path": s["rel_path"], "tag": s["store_tag"], "format": s["format"],
                       "rolled": (s["root"], s["rel_path"], s["store_tag"]) in rolled})
    return {"filter": {"root": root or None, "tag": tag or None}, "rows": rows, "stores": stores,
            "roots": sorted({r["root"] for r in all_rows} | {s["root"] for s in found if s["root"]}),
            "tags": sorted({r["tag"] for r in all_rows} | {s["store_tag"] for s in found}),
            "by_tag": by_tag, "by_root": by_root, "totals": totals}
