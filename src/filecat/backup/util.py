"""Small readers shared by the backup formats."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Any


def iso(epoch_seconds: int | float | None) -> str | None:
    if not epoch_seconds:
        return None
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).isoformat(timespec="seconds")


def iso_from_name(stamp: str, fmt: str) -> str | None:
    """A local-time stamp from a folder name, e.g. '2009-05-21 123957'
    with '%Y-%m-%d %H%M%S'. Kept naive: the writer's time zone is unknown."""
    try:
        return datetime.strptime(stamp, fmt).isoformat()
    except ValueError:
        return None


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def file_size(path: str) -> int | None:
    try:
        return os.stat(path).st_size
    except OSError:
        return None


def sqlite_rows(path: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Rows of a query on a SQLite file that may sit on a share and be in
    use by its writer: the file (and a non-empty -wal) are copied to a
    temporary folder first, so nothing is locked or written on the source."""
    with tempfile.TemporaryDirectory(prefix="filecat-backup-") as tmp:
        local = os.path.join(tmp, "db.sqlite")
        shutil.copyfile(path, local)
        wal = f"{path}-wal"
        if (file_size(wal) or 0) > 0:
            shutil.copyfile(wal, f"{local}-wal")
        conn = sqlite3.connect(local)
        try:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()


def listdir(path: str) -> dict[str, os.DirEntry]:
    try:
        with os.scandir(path) as it:
            return {e.name: e for e in it}
    except OSError:
        return {}
