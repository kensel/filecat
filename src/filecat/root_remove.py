"""Remove a root from the catalog: `filecat roots remove ROOT` and the viewer's Remove button.

For the root nobody wanted: a typo, or a folder that did not exist and was scanned with
nothing in it. What goes:

* the root's index entry (`Backend.delete_root_info`)
* its stored summary / aggregates and every treemap snapshot of it (pins included)
* its entry in the resume files beside the catalog (the plain scan's and the server jobs')
* its dropped records and sticky-redaction entries
* with `force` only: its records (files, folders, rollups) with their archive members

Without `force` a root that still holds records is refused: the viewer never deletes
records. A root a scan is walking right now is refused either way. Samples and member sets
that only the removed records named stay until `filecat samples prune` / `member-sets prune`.
"""
from __future__ import annotations

import glob
import itertools
import os
from datetime import datetime, timezone
from typing import Any

from . import rootinfo
from .backends.base import Backend

BATCH = 1000


class RootError(Exception):
    """The removal was refused; `status` is the HTTP status the viewer answers with."""

    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


def count_records(backend: Backend, root: str) -> int:
    """Every record of the root: files, folders and rollups."""
    from .browse import normalize
    return int(backend.query(normalize({"root": root, "limit": 1}))["total"])


def has_records(backend: Backend, root: str) -> bool:
    """Whether the root holds any record, without counting them (one row is enough)."""
    it = backend.list(root=root)
    try:
        return next(iter(it), None) is not None
    finally:
        close = getattr(it, "close", None)
        if close:
            close()


def resume_files(backend: Backend) -> list[str]:
    """The resume files of this catalog that exist: the plain scan's, and the server jobs'
    (`<catalog>.<job>.resume.json`)."""
    from .resume import resume_path_for
    base = resume_path_for(getattr(backend, "name", "backend"), getattr(backend, "path", None))
    found = [base] if os.path.exists(base) else []
    if base.endswith(".resume.json"):
        found += sorted(glob.glob(glob.escape(base[:-len(".resume.json")]) + ".*.resume.json"))
    return found


def known(backend: Backend, root: str) -> bool:
    return any(r["root"] == root for r in rootinfo.index(backend))


def remove_root(backend: Backend, root: str, *, force: bool = False,
                resume_paths: list[str] | None = None) -> dict[str, Any]:
    """Remove `root` (see the module docstring); returns what was removed. Raises RootError."""
    if not known(backend, root):
        raise RootError(f"no root {root!r} in the catalog", 404)
    infos = {i["root"]: i for i in _infos(backend)}
    if rootinfo.state(infos.get(root)) == "in_progress":
        raise RootError(f"a scan is running on {root}; wait for it to finish", 409)
    records = count_records(backend, root)
    if records and not force:
        raise RootError(f"{root} still has {records:,} record{'s' if records != 1 else ''}; "
                        "only a root with none can be removed here "
                        "(`filecat roots remove ROOT --force` deletes the records too)", 409)
    removed: dict[str, Any] = {"root": root, "records": 0, "dropped": 0, "redactions": 0, "treemaps": 0,
                               "resume_files": 0}
    while records:                              # a page at a time: the next list() starts after the last delete
        page = [d["rel_path"] for d in _first(backend.list(root=root), BATCH)]
        if not page:
            break
        backend.delete_many(root, page)
        removed["records"] += len(page)
        backend.flush()
    try:
        gone = [d["rel_path"] for d in backend.list_dropped(root)]
        if gone:
            removed["dropped"] = backend.purge_dropped_paths(root, gone)
    except NotImplementedError:
        pass
    try:
        for entry in backend.redactions(root):
            backend.delete_redaction(entry["id"])
            removed["redactions"] += 1
    except NotImplementedError:
        pass
    try:
        backend.replace_aggregates({}, 2, datetime.now(timezone.utc).isoformat(), root)
    except NotImplementedError:
        pass
    try:
        for meta in backend.list_treemaps(root):
            backend.delete_treemap(meta["id"])
            removed["treemaps"] += 1
    except NotImplementedError:
        pass
    from .resume import ResumeState
    for path in (resume_files(backend) if resume_paths is None else resume_paths):
        state = ResumeState(path)
        if state.roots.get(root) is not None:
            state.forget_root(root)
            removed["resume_files"] += 1
    backend.delete_root_info(root)
    backend.flush()
    return removed


def _infos(backend: Backend) -> list[dict[str, Any]]:
    try:
        return list(backend.list_root_info())
    except NotImplementedError:
        return []


def _first(it: Any, n: int) -> list[dict[str, Any]]:
    try:
        return list(itertools.islice(it, n))
    finally:
        close = getattr(it, "close", None)
        if close:
            close()
