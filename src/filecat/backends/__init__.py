"""Backend factory."""
from __future__ import annotations

import os

from .base import Backend

BACKENDS = ("jsonl", "sqlite", "postgres", "mysql", "mssql", "mongodb")
# A jsonl --out that is a directory (or does not end in .jsonl) holds one
# file per root (jsonl_dir.py); a .jsonl file is the single-file layout.
DEFAULT_OUT = {"jsonl": "catalog-jsonl", "sqlite": "catalog.sqlite"}


def open_backend(name: str | None = "sqlite", out: str | None = None, dsn: str | None = None) -> Backend:
    """Open a backend by name. jsonl/sqlite take a path (--out; for jsonl a
    directory of per-root files or one .jsonl file);
    the server backends take a DSN (--dsn or FILECAT_DSN)."""
    name = name or "sqlite"
    if name not in BACKENDS:
        raise ValueError(f"unknown backend {name!r}; choose from {', '.join(BACKENDS)}")
    if name in ("jsonl", "sqlite"):
        path = out or DEFAULT_OUT[name]
        if name == "jsonl":
            from .jsonl_dir import JsonlDirBackend, is_dir_layout
            if is_dir_layout(path):
                return JsonlDirBackend(path)
            from .jsonl import JsonlBackend
            return JsonlBackend(path)
        from .sqlite import SqliteBackend
        return SqliteBackend(path)
    dsn = dsn or os.environ.get("FILECAT_DSN")
    if not dsn:
        raise ValueError(f"backend {name} needs --dsn or FILECAT_DSN")
    if name == "postgres":
        from .postgres import PostgresBackend
        return PostgresBackend(dsn)
    if name == "mysql":
        from .mysql import MysqlBackend
        return MysqlBackend(dsn)
    if name == "mssql":
        from .mssql import MssqlBackend
        return MssqlBackend(dsn)
    from .mongodb import MongoBackend
    return MongoBackend(dsn)


__all__ = ["Backend", "BACKENDS", "open_backend"]
