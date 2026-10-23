"""Aggregates for `filecat summary` and the stored agg_* tables.

`build_aggregates(documents, depth)` groups file records **per root**,
because percent is "of the bytes successfully sized in that root" (see
file-catalog-requirements.md, "Overview") -- mixing roots together would
make that percentage meaningless. Shape returned:

    {"roots": {root_string: {
        "suffix": [{"suffix": str, "description": str | None,
                     "files": int, "bytes": int, "percent": float}, ...],
        "mime":   [{"mime": str, "files": int, "bytes": int, "percent": float}, ...],
        "dir":    [{"dir": str, "files": int, "bytes": int, "percent": float}, ...],
        "total_files": int, "total_bytes": int, "unreadable": int,
    }}}

Only file records are summed (`kind` not in record.NON_FILE_KINDS: neither
directories nor rollups, which stand for files the catalog does not list;
directories are not added
on top of their children, per spec). Design decisions worth writing down:

* A `link` record (symlink/junction -- never followed, so there is nothing
  more to size) counts as a file entry with 0 bytes: it is one visited
  entry, like WinDirStat shows a shortcut as a (tiny) leaf rather than
  omitting it.
* An entry that carries an `errors` value and has no `size` key at all --
  meaning the stat() that would have produced one failed outright, as
  opposed to a kind="empty" file which does have size=0 -- is counted in
  `unreadable` and left out of `total_bytes` and the percent base, but is
  still counted in `total_files` since it was a visited entry.
* `suffix` groups use `"(none)"` for an empty/missing suffix. `description`
  is the first non-empty `probe.mime_glob_desc` seen for that suffix.
* `mime` groups use `mime` when present, else `kind`.
* `dir` groups use the file's parent directory, cut to `depth` path
  components; a root-level file's parent is `.`.
* Percent is of `total_bytes` (the bytes successfully sized in that root),
  0.0 when there are no sized bytes yet.
* Rows are sorted by bytes descending, then by key ascending, so a `--top`
  slice in `filecat summary` shows the biggest contributors first.

`dir_key()` is exposed separately so filecat.backends.sqlite can register
it as a SQL function and GROUP BY the same key the Python path uses.
"""
from __future__ import annotations

from typing import Any, Iterable

from .record import NON_FILE_KINDS


def dir_key(rel_path: str, depth: int) -> str:
    """Parent directory of rel_path, cut to `depth` components.

    A root-level file (no '/' in rel_path) has parent ".".
    """
    rel_path = rel_path or ""
    parent = rel_path.rsplit("/", 1)[0] if "/" in rel_path else ""
    if not parent:
        return "."
    return "/".join(parent.split("/")[:depth])


def _bump(counts: dict[Any, list[int]], key: Any, size: int) -> None:
    row = counts.get(key)
    if row is None:
        counts[key] = [1, size]
    else:
        row[0] += 1
        row[1] += size


def _rows(counts: dict[Any, list[int]], total_bytes: int, key_name: str,
          descriptions: dict[Any, str] | None = None) -> list[dict[str, Any]]:
    rows = []
    for key, (files, nbytes) in counts.items():
        row: dict[str, Any] = {key_name: key}
        if descriptions is not None:
            row["description"] = descriptions.get(key)
        row["files"] = files
        row["bytes"] = nbytes
        row["percent"] = (nbytes / total_bytes * 100.0) if total_bytes else 0.0
        rows.append(row)
    rows.sort(key=lambda r: (-r["bytes"], str(r[key_name])))
    return rows


def _new_root_state() -> dict[str, Any]:
    return {
        "suffix_counts": {}, "suffix_desc": {},
        "mime_counts": {},
        "dir_counts": {},
        "total_files": 0, "total_bytes": 0, "unreadable": 0,
    }


def build_aggregates(documents: Iterable[dict[str, Any]], depth: int = 2) -> dict[str, Any]:
    """Sum file records (kind != "dir") into per-root suffix/mime/dir tables.

    See module docstring for the exact shape and the rules used for
    links, unreadable entries, and directory grouping.
    """
    per_root: dict[str, dict[str, Any]] = {}

    for doc in documents:
        if doc.get("kind") in NON_FILE_KINDS:
            continue
        root = doc.get("root", "")
        state = per_root.setdefault(root, _new_root_state())

        has_size = "size" in doc and doc["size"] is not None
        if doc.get("errors") and not has_size:
            state["unreadable"] += 1
            state["total_files"] += 1
            continue

        size = doc.get("size") or 0
        state["total_files"] += 1
        state["total_bytes"] += size

        suffix = doc.get("suffix") or "(none)"
        _bump(state["suffix_counts"], suffix, size)
        if suffix not in state["suffix_desc"]:
            desc = (doc.get("probe") or {}).get("mime_glob_desc")
            if desc:
                state["suffix_desc"][suffix] = desc

        mime_key = doc.get("mime") or doc.get("kind") or "unknown"
        _bump(state["mime_counts"], mime_key, size)

        dkey = dir_key(doc.get("rel_path", ""), depth)
        _bump(state["dir_counts"], dkey, size)

    roots_out: dict[str, Any] = {}
    for root, state in per_root.items():
        total_bytes = state["total_bytes"]
        roots_out[root] = {
            "suffix": _rows(state["suffix_counts"], total_bytes, "suffix", state["suffix_desc"]),
            "mime": _rows(state["mime_counts"], total_bytes, "mime"),
            "dir": _rows(state["dir_counts"], total_bytes, "dir"),
            "total_files": state["total_files"],
            "total_bytes": total_bytes,
            "unreadable": state["unreadable"],
        }
    return {"roots": roots_out}
