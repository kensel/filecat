"""Resume state: how far an unfinished scan of each root got.

Directory records are written post-order (a directory after all of its
children), so "this directory is marked done" means its whole subtree is
in the catalog. A rerun of an unfinished root skips a done directory --
without even listing it -- when its mtime still matches the marker.

Only the top-most done directories are kept: when a directory is marked
done, its subdirectories' markers are dropped, because the parent's marker
covers them. A fan-out such as Mail/D6/01/<message-id>/ therefore
collapses to Mail/D6 once D6 is finished, so the file stays small however
many directories the share has.

A directory that could not be listed is never marked, and neither is any
directory above it, so a rerun retries it while skipping what did finish.
When a root's walk ends with everything listed, its entry is removed: the
next scan is a full rescan, where unchanged files are recognised from
their stored records (size and mtime) and not remeasured.

The file is written at most every SAVE_SECONDS and on flush() (end of a
root, end of the scan, Ctrl+C, an exception), so an interrupted scan
loses at most that much progress -- those directories are walked again.
Every save first calls `before_save` (scan passes the backend's flush),
so a directory is never marked done while its records are still only in
the backend's write buffer.

The file lives next to the catalog: ``<catalog>.resume.json`` for jsonl
and sqlite backends, or ``.filecat-<backend>.resume.json`` in the current
directory for server backends (there is no single local catalog file to
sit beside). Shape on disk::

    {"version": 2, "roots": {root: {rel_path: {"mtime_ns": int, "child_count": int}}}}

Version 1 files (``{root: {rel_path: marker}}``, every directory ever
completed) are read too: a root whose own marker ("") is present had
finished and is dropped; the markers of an unfinished root are compacted
to the top-most ones.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Callable

from .fsutil import replace as _replace

VERSION = 2
SAVE_SECONDS = 30.0


def resume_path_for(backend_name: str, catalog_path: str | None) -> str:
    """Where the resume file for this backend/catalog should live."""
    if catalog_path:
        return f"{catalog_path}.resume.json"
    return f".filecat-{backend_name}.resume.json"


def _top_most(markers: dict[str, Any]) -> dict[str, Any]:
    """Drop markers that have a marked ancestor."""
    out = {}
    for rel, marker in markers.items():
        parts = rel.split("/")
        if not any("/".join(parts[:i]) in markers for i in range(1, len(parts))):
            out[rel] = marker
    return out


class ResumeState:
    def __init__(self, path: str, save_seconds: float | None = None,
                 before_save: Callable[[], None] | None = None) -> None:
        self.path = path
        self.before_save = before_save
        self.save_seconds = SAVE_SECONDS if save_seconds is None else save_seconds
        self.roots: dict[str, dict[str, dict[str, int]]] = {}
        self._dirty = False
        self._last_save = time.monotonic()
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        if data.get("version") == VERSION:
            self.roots = data.get("roots") or {}
            return
        for root, markers in data.items():  # version 1
            if isinstance(markers, dict) and "" not in markers and markers:
                self.roots[root] = _top_most(markers)

    def _save(self) -> None:
        if self.before_save is not None:
            self.before_save()
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": VERSION, "roots": self.roots}, f)
        _replace(tmp, self.path)
        self._dirty = False
        self._last_save = time.monotonic()

    def _changed(self) -> None:
        self._dirty = True
        if time.monotonic() - self._last_save >= self.save_seconds:
            self._save()

    def flush(self) -> None:
        """Write pending changes now."""
        if self._dirty:
            self._save()

    def get_dir(self, root: str, rel_path: str) -> dict[str, int] | None:
        """The marker of a done directory of an unfinished root, if any."""
        return self.roots.get(root, {}).get(rel_path)

    def resuming(self, root: str) -> bool:
        return bool(self.roots.get(root))

    def mark_dir_complete(self, root: str, rel_path: str, mtime_ns: int, child_count: int,
                          child_dirs: list[str] = ()) -> None:
        """Record directory `rel_path` as done and drop the markers of its
        subdirectories `child_dirs` (names), which this one now covers."""
        markers = self.roots.setdefault(root, {})
        prefix = f"{rel_path}/" if rel_path else ""
        for name in child_dirs:
            markers.pop(prefix + name, None)
        markers[rel_path] = {"mtime_ns": mtime_ns, "child_count": child_count}
        self._changed()

    def finish_root(self, root: str) -> None:
        """The root's walk ended with every directory listed: forget it."""
        if self.roots.pop(root, None) is not None:
            self._dirty = True
        self.flush()

    def forget_root(self, root: str) -> None:
        if self.roots.pop(root, None) is not None:
            self._dirty = True
            self.flush()

    def forget_beneath(self, root: str, rel_path: str) -> None:
        """Drop the markers at or beneath `rel_path` (a folder that is now
        rolled up: nothing about it may be kept)."""
        markers = self.roots.get(root)
        if not markers:
            return
        prefix = rel_path + "/"
        gone = [k for k in markers if k == rel_path or k.startswith(prefix)]
        for k in gone:
            del markers[k]
        if gone:
            self._dirty = True

    def done_count(self, root: str) -> int:
        return len(self.roots.get(root, {}))
