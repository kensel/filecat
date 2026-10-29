"""Treemap data for the Graph view of `filecat serve`.

`build(rows, prefix, depth)` takes Backend.sizes() rows of the files
beneath `prefix` and sums them into the folders `depth` levels below it,
with each folder's bytes split by extension and by type, the way
WinDirStat colours a folder by the files in it. Shape:

    {"prefix": str, "depth": int, "files": int, "bytes": int,
     "keys": {"suffix": [{"key", "files", "bytes"}, ...],
              "mime":   [{"key", "files", "bytes"}, ...]},
     "folders": [{"path", "files", "bytes",
                  "suffix": [[key index, bytes], ...], "mime": [[key index, bytes], ...]}, ...]}

Folder paths are relative to `prefix`, cut to `depth` components; "" is
the files directly in `prefix`, and "a" with depth 2 is the files directly
in a (a/b holds what is beneath a/b). The keys are the biggest KEEP_KEYS
extensions (or types) beneath `prefix`, biggest first, then "(other)" for
the rest when there is a rest; a folder's split refers to them by index.
Extension keys are as in the summary: "(none)" for no suffix.

Past MAX_FOLDERS folders the smallest are merged, per parent, into one
"<parent>/…" entry with "merged": n, so a share with a hundred thousand
folders at depth 2 still draws (and sends) quickly.

Snapshots. `filecat serve` stores each treemap it builds in the catalog
(Backend.put_treemap) and serves the newest one for a (root, prefix,
depth) while it is younger than its max age (2 hours by default), so a
restart or another viewer does not read every record again. Saving a new
one deletes the older unpinned ones of the same view. A pin keeps
snapshots for good: pin() marks them with {"at", "label"}, and every
snapshot pinned in one action (all the roots of the overview, say) shares
that "at", which is how they are listed and compared together. A snapshot
already in another pin is copied, so each pin keeps what it was given.
This is a size-per-folder record of the catalog at a time, not a history
of files: comparing two of them shows which folders grew or shrank.
Rollups (docs/rollups.md). `build(..., rollups=)` takes the rollup records
beneath `prefix`. One whose path has at most `depth` components below the
prefix is a folder entry of its own, named by that path ("proj/[CACHE]"),
with `files` = its total_files, `bytes` = its size, extension and type split
into one cell, the tag, and `"rollup": {"tag", "matched", "total_dirs",
"allocated_size", "newest_mtime_ns", "oldest_mtime_ns", "partial"}` (a merged
"..." entry keeps no rollup key). A deeper one is added to the folder it sits
in, as a file would be, under its tag. The `files` and `bytes` totals include
rollups, so a share's total matches `du`. A pin diff matches tiles by path,
which is stable between snapshots, so it works on rollup tiles as on folders.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Iterable

from .backends.base import Backend, Document
from .record import root_id

MAX_AGE = timedelta(hours=2)

KEEP_KEYS = 40      # the page colours the top 20; the rest of the list makes merging roots closer
MAX_FOLDERS = 4000
OTHER = "(other)"
MORE = "…"


def folder_of(rel_path: str, start: int, depth: int) -> str:
    """The folder a file is drawn in: its parent below the prefix (rel_path
    from `start` on), cut to `depth` components."""
    rest = rel_path[start:]
    cut = rest.rfind("/")
    if cut < 0:
        return ""
    parent = rest[:cut]
    if depth <= 0:
        return ""
    parts = parent.split("/", depth)
    return "/".join(parts[:depth])


def _keys(totals: dict[str, list[int]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    ranked = sorted(totals.items(), key=lambda kv: (-kv[1][1], kv[0]))
    kept = ranked[:KEEP_KEYS]
    rows = [{"key": k, "files": f, "bytes": b} for k, (f, b) in kept]
    index = {k: i for i, (k, _) in enumerate(kept)}
    rest = ranked[KEEP_KEYS:]
    if rest:
        rows.append({"key": OTHER, "files": sum(f for _, (f, _) in rest), "bytes": sum(b for _, (_, b) in rest)})
    return rows, index


def _split(cells: dict[str, int], index: dict[str, int], other: int) -> list[list[int]]:
    out: dict[int, int] = {}
    for key, nbytes in cells.items():
        i = index.get(key, other)
        out[i] = out.get(i, 0) + nbytes
    return sorted(([i, b] for i, b in out.items()), key=lambda c: (-c[1], c[0]))


def build(rows: Iterable[tuple[str, int, str, str]], prefix: str = "", depth: int = 2,
          rollups: Iterable[Document] = ()) -> dict[str, Any]:
    prefix = prefix.strip("/")
    start = len(prefix) + 1 if prefix else 0
    folders: dict[str, list[Any]] = {}  # path -> [files, bytes, {suffix: bytes}, {mime: bytes}]
    totals: dict[str, dict[str, list[int]]] = {"suffix": {}, "mime": {}}
    tiles: dict[str, dict[str, Any]] = {}   # path -> the "rollup" entry of a rollup's own tile

    def add(path: str, files: int, size: int, suffix: str, mime: str) -> None:
        f = folders.get(path)
        if f is None:
            f = folders[path] = [0, 0, {}, {}]
        f[0] += files
        f[1] += size
        f[2][suffix] = f[2].get(suffix, 0) + size
        f[3][mime] = f[3].get(mime, 0) + size
        for table, key in (("suffix", suffix), ("mime", mime)):
            t = totals[table].get(key)
            if t is None:
                totals[table][key] = [files, size]
            else:
                t[0] += files
                t[1] += size

    for rel, size, suffix, mime in rows:
        add(folder_of(rel, start, depth), 1, size or 0, suffix or "(none)", mime)
    for doc in rollups:
        rel = doc.get("rel_path") or ""
        if not rel.startswith(prefix + "/" if prefix else "") or rel == prefix:
            continue
        info = (doc.get("probe") or {}).get("rollup") or {}
        tag = info.get("tag") or doc.get("name") or "(rollup)"
        files, size = info.get("total_files", 0), doc.get("size") or 0
        below = rel[start:]
        if len(below.split("/")) <= depth:
            add(below, files, size, tag, tag)
            tiles[below] = {"tag": tag, "matched": info.get("matched", 0),
                            "total_dirs": info.get("total_dirs", 0),
                            "allocated_size": doc.get("allocated_size"),
                            "newest_mtime_ns": info.get("newest_mtime_ns"),
                            "oldest_mtime_ns": info.get("oldest_mtime_ns"),
                            "partial": bool(info.get("partial"))}
        else:
            add(folder_of(rel, start, depth), files, size, tag, tag)

    keys: dict[str, list[dict[str, Any]]] = {}
    indexes: dict[str, dict[str, int]] = {}
    for table in ("suffix", "mime"):
        keys[table], indexes[table] = _keys(totals[table])

    ordered = sorted(folders.items(), key=lambda kv: (-kv[1][1], kv[0]))
    if len(ordered) > MAX_FOLDERS:
        merged: dict[str, list[Any]] = {}
        for path, (files, nbytes, by_suffix, by_mime) in ordered[MAX_FOLDERS:]:
            parent = path.rsplit("/", 1)[0] + "/" + MORE if "/" in path else MORE
            m = merged.setdefault(parent, [0, 0, {}, {}, 0])
            m[0] += files
            m[1] += nbytes
            for into, cells in ((m[2], by_suffix), (m[3], by_mime)):
                for k, b in cells.items():
                    into[k] = into.get(k, 0) + b
            m[4] += 1
        ordered = ordered[:MAX_FOLDERS] + sorted(merged.items(), key=lambda kv: (-kv[1][1], kv[0]))

    out_folders = []
    for path, f in ordered:
        row: dict[str, Any] = {"path": path, "files": f[0], "bytes": f[1],
                               "suffix": _split(f[2], indexes["suffix"], len(indexes["suffix"])),
                               "mime": _split(f[3], indexes["mime"], len(indexes["mime"]))}
        if len(f) > 4:
            row["merged"] = f[4]
        elif path in tiles:
            row["rollup"] = tiles[path]
        out_folders.append(row)
    return {"prefix": prefix, "depth": depth,
            "files": sum(f[0] for f in folders.values()), "bytes": sum(f[1] for f in folders.values()),
            "keys": keys, "folders": out_folders}


# --- snapshots -------------------------------------------------------------
def _view(meta: Document) -> tuple[str, str, int]:
    return meta["root_id"], meta["prefix"], meta["depth"]


def age(meta: Document, now: datetime) -> timedelta:
    return now - datetime.fromisoformat(meta["built_at"])


def newest(metas: Iterable[Document], prefix: str, depth: int) -> Document | None:
    """The most recently built snapshot of (prefix, depth) among one root's metas."""
    same = [m for m in metas if m["prefix"] == prefix and m["depth"] == depth]
    return max(same, key=lambda m: m["built_at"], default=None)


def save(backend: Backend, root: str, data: Document, built_at: str) -> Document:
    """Store a snapshot and delete the older unpinned ones of the same view."""
    meta = {"id": uuid.uuid4().hex, "root_id": root_id(root), "root": root, "prefix": data["prefix"],
            "depth": data["depth"], "built_at": built_at, "files": data["files"], "bytes": data["bytes"],
            "pin": None}
    backend.put_treemap(meta, data)
    for old in backend.list_treemaps(root):
        if old["id"] != meta["id"] and _view(old) == _view(meta) and not old.get("pin"):
            backend.delete_treemap(old["id"])
    return meta


def pin(backend: Backend, ids: Iterable[str], label: str | None, at: str) -> list[Document]:
    """Pin these snapshots together as {"at", "label"}; returns their metas
    (a snapshot already pinned elsewhere is copied under a new id)."""
    stamp = {"at": at, "label": (label or "").strip() or None}
    out = []
    for tid in ids:
        found = backend.get_treemap(tid)
        if found is None:
            raise KeyError(f"no such snapshot {tid}")
        meta, data = found
        if meta.get("pin") and meta["pin"].get("at") != at:
            meta = {**meta, "id": uuid.uuid4().hex, "pin": stamp}
            backend.put_treemap(meta, data)
        else:
            meta = {**meta, "pin": stamp}
            backend.put_treemap(meta)
        out.append(meta)
    return out


def unpin(backend: Backend, ids: Iterable[str] = (), at: str | None = None) -> int:
    """Unpin snapshots by id, or every snapshot of the pin made at `at`.
    One that a newer snapshot of its view has replaced is deleted; the
    newest stays until it is too old, like any other. Returns how many."""
    metas = backend.list_treemaps()
    wanted = set(ids)
    hits = [m for m in metas if m.get("pin") and (m["id"] in wanted or (at and m["pin"].get("at") == at))]
    for meta in hits:
        current = newest((m for m in metas if m["root_id"] == meta["root_id"]), meta["prefix"], meta["depth"])
        if current is not None and current["id"] != meta["id"]:
            backend.delete_treemap(meta["id"])
        else:
            backend.put_treemap({**meta, "pin": None})
    return len(hits)


def pins(backend: Backend, prefix: str, depth: int, root: str | None = None) -> list[Document]:
    """The pins holding a snapshot of (prefix, depth), of `root` or of any
    root, newest first: [{"at", "label", "snapshots": [meta, ...]}]."""
    groups: dict[str, Document] = {}
    for m in backend.list_treemaps(root):
        if not m.get("pin") or m["prefix"] != prefix or m["depth"] != depth:
            continue
        g = groups.setdefault(m["pin"]["at"], {"at": m["pin"]["at"], "label": m["pin"].get("label"),
                                               "snapshots": []})
        g["snapshots"].append(m)
    for g in groups.values():
        g["snapshots"].sort(key=lambda m: m["root"])
    return sorted(groups.values(), key=lambda g: g["at"], reverse=True)
