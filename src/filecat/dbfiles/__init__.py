"""Database data folders: a server's files on disk, recognised by layout.

A PostgreSQL cluster, a MySQL/MariaDB datadir or a MongoDB dbPath is
thousands of small files that change while the server runs, and an MSSQL
data folder is a few large .mdf/.ndf/.ldf files the server holds open.
None of them means anything byte by byte outside the server. They use the
backup-store hooks (backup/__init__.py): by default the walker records each
data file from the directory listing alone (name, size, mtimes, kind
"data", probe.db_data = engine) without opening it, and when the folder is
finished `summarize` reads the engine's own small metadata files and the
folder's record gets probe.database:

    {"engine": "postgres", "version": str | None, "running": bool | None,
     "databases": [...], "files": int, "bytes": int, "newest": iso,
     "quiet": bool, "instance_keys": [str], "problems": [str],
     ...engine-specific fields}

`quiet` is whether the newest data file is older than the engine's quiet
age (below). `instance_keys` identify the server instance the files belong
to (PostgreSQL's system identifier, MySQL's server-uuid): two folders
sharing one are copies of one instance, or a physical replica of it.
`filecat databases` lists the folders and groups them by these keys.

Measuring. A data file is read and hashed (scan --measure-databases, or
`filecat enrich` later) only when it is quiet and big enough to be worth
it, so a file the server is writing is never read part way:

    engine                    quiet age   smallest file read
    postgres, mysql, mongodb  90 days     1 MiB   (skips the many small relation files)
    mssql                     1 hour      any

These come from data/store_formats.json (actions.measure_when), which also
describes every database and backup format's detection and metadata.

A file a server holds open (Windows sharing or lock violation) is recorded
as probe.db_in_use instead of an error. filecat only ever reads.

Engines: postgres.py, mysql.py, mongodb.py, mssql.py.
"""
from __future__ import annotations

import functools
import json
import os
import time
from pathlib import Path
from typing import Any

from ..backup import Store
from ..backup.util import iso

# WinError 32 (sharing violation) and 33 (lock violation): the server has it open.
_IN_USE = ("[WinError 32]", "[WinError 33]")


CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "store_formats.json"


@functools.cache
def catalog() -> dict[str, dict[str, Any]]:
    """data/store_formats.json by format id: the reference for every
    database and backup format, and the source of the measure thresholds."""
    with open(CATALOG_PATH, encoding="utf-8") as f:
        return {fmt["id"]: fmt for fmt in json.load(f)["formats"]}


class Engine:
    """Base of the engine formats: the parts of backup.Format they share."""
    name = ""
    probe_key = "database"
    data_key = "db_data"
    tag_measured = True

    def _measure_when(self) -> dict[str, Any]:
        return catalog()[self.name]["actions"]["measure_when"]

    @property
    def quiet_seconds(self) -> float:
        return self._measure_when()["quiet_seconds"]

    @property
    def min_bytes(self) -> int:
        return self._measure_when()["min_bytes"]

    def eligible(self, size: int | None, mtime_ns: int | None, now: float | None = None) -> bool:
        """Quiet and big enough to read without catching the server mid-write."""
        if size is None or mtime_ns is None or size < self.min_bytes:
            return False
        now = time.time() if now is None else now
        return now - mtime_ns / 1e9 >= self.quiet_seconds

    def for_folder(self, names: set[str]) -> "Engine":
        """The engine as configured for one folder (default: itself)."""
        return self

    def measured(self, st: os.stat_result, options: Any) -> bool:
        return bool(getattr(options, "measure_databases", False)) \
            and self.eligible(st.st_size, st.st_mtime_ns)


def engines() -> list[Engine]:
    from . import mongodb, mssql, mysql, postgres
    return [postgres.ENGINE, mysql.ENGINE, mongodb.ENGINE, mssql.ENGINE]


def engine(name: str | None) -> Engine | None:
    return next((e for e in engines() if e.name == name), None)


def detect(rel_path: str, dir_name: str, names: set[str]) -> Store | None:
    """The database data folder rooted here, if its entries look like one."""
    for eng in engines():
        if eng.matches(dir_name, names):
            return Store(eng.for_folder(names), rel_path)
    return None


def settle_in_use(doc: dict[str, Any]) -> dict[str, Any]:
    """A measured data file the server holds open: the sharing errors
    become probe.db_in_use, since that is what they say."""
    errors = doc.get("errors") or []
    held = [e for e in errors if any(m in str(e.get("message")) for m in _IN_USE)]
    if held:
        rest = [e for e in errors if e not in held]
        if rest:
            doc["errors"] = rest
        else:
            doc.pop("errors", None)
        doc.setdefault("probe", {})["db_in_use"] = True
        if doc.get("kind") in (None, "unknown"):
            doc["kind"] = "data"
    return doc


# --- small listing helpers shared by the engines ----------------------------

def scan_tree(path: str, depth: int = 1) -> dict[str, Any]:
    """{"files", "bytes", "newest_ns"} of the regular files under `path`,
    `depth` folder levels down (1 = the folder's own files). Links and
    junctions are not followed."""
    out = {"files": 0, "bytes": 0, "newest_ns": 0}
    stack = [(path, 1)]
    while stack:
        here, level = stack.pop()
        try:
            with os.scandir(here) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if level < depth:
                        stack.append((e.path, level + 1))
                    continue
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            out["files"] += 1
            out["bytes"] += st.st_size
            out["newest_ns"] = max(out["newest_ns"], st.st_mtime_ns)
    return out


def add_totals(out: dict[str, Any], tree: dict[str, Any], eng: Engine) -> dict[str, Any]:
    """files / bytes / newest / quiet on a summary from a scan_tree result."""
    newest = tree["newest_ns"] or None
    out["files"] = tree["files"]
    out["bytes"] = tree["bytes"]
    out["newest"] = iso(newest / 1e9) if newest else None
    out["quiet"] = bool(newest) and time.time() - newest / 1e9 >= eng.quiet_seconds
    return out


def merge_trees(*trees: dict[str, Any]) -> dict[str, Any]:
    return {"files": sum(t["files"] for t in trees), "bytes": sum(t["bytes"] for t in trees),
            "newest_ns": max((t["newest_ns"] for t in trees), default=0)}


def read_text(path: str, limit: int = 64 * 1024) -> str | None:
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return None
