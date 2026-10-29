"""The file system a store's manifests are read from.

Every backup/ and dbfiles/ reader takes a StoreFS instead of calling os.* and
open() on a path, so a store scanned through filecat-agent (fsource.py) gets
the same probe.backup / probe.database as one on a local disk or an SMB share
(docs/rollups.md section 4.3):

    join(base, *parts)    a path beneath `base`
    basename(path)        the last component
    listdir(path)         {name: entry} of a folder, {} when it cannot be read;
                          an entry answers is_dir / is_file / is_symlink / stat
                          (st_size, st_mtime_ns) like os.DirEntry
    stat(path)            an object with st_size and st_mtime_ns; OSError
    exists / isfile / isdir / file_size
    open(path, mode)      a seekable binary file, or text with a text mode
    readlink(path, entry) a link's target
    sizes(path)           {inner path: size} of every file beneath `path`
    sqlite_rows(path, sql, params)
                          rows of a query on a SQLite manifest (copied first)
    lpath(path)           the form `open` needs to pass MAX_PATH (local Windows)

LocalFS is today's behaviour, unchanged (paths are OS paths, SMB shares are
UNC paths). AgentFS reads through the agent with list_dir, measure
(`hash: "none"`, a stat) and read_range, and copies a SQLite manifest to a
temporary file under the size cap (`rollups.manifest_cap`). A manifest over the
cap raises ManifestTooLarge and is listed in AgentFS.oversize, which the
walker reports as probe.store_note in place of probe.backup. Nothing here logs
a path.
"""
from __future__ import annotations

import errno
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from .util import file_size as _local_file_size
from .util import listdir as _local_listdir
from .util import sqlite_rows as _local_sqlite_rows

COPY_CHUNK = 4 * 1024 * 1024        # per read_range request
DEFAULT_MANIFEST_CAP = 256 * 1024 * 1024
TEMP_PREFIX = "filecat-backup-"


class ManifestTooLarge(OSError):
    """A SQLite manifest bigger than rollups.manifest_cap, which an agent
    scan does not copy."""


def long_path(path: str) -> str:
    """The \\\\?\\ form of a Windows path, which opens past MAX_PATH (260
    characters): event folders cut into 64-character names often are longer."""
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    path = os.path.abspath(path)
    return "\\\\?\\UNC\\" + path[2:] if path.startswith("\\\\") else "\\\\?\\" + path


class StoreFS:
    local = False

    def join(self, base: str, *parts: str) -> str:
        raise NotImplementedError

    def basename(self, path: str) -> str:
        raise NotImplementedError

    def listdir(self, path: str) -> dict[str, Any]:
        raise NotImplementedError

    def stat(self, path: str) -> Any:
        raise NotImplementedError

    def open(self, path: str, mode: str = "rb", **kwargs: Any) -> Any:
        raise NotImplementedError

    def readlink(self, path: str, entry: Any = None) -> str:
        raise NotImplementedError

    def sqlite_rows(self, path: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        raise NotImplementedError

    def sqlite_many(self, path: str, queries: list[tuple[str, tuple]]) -> list[list[dict[str, Any]]]:
        """sqlite_rows for several queries on one file (the agent copies it once)."""
        return [self.sqlite_rows(path, sql, params) for sql, params in queries]

    def lpath(self, path: str) -> str:
        return path

    def file_size(self, path: str) -> int | None:
        try:
            return self.stat(path).st_size
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def isfile(self, path: str) -> bool:
        return self.exists(path)

    def isdir(self, path: str) -> bool:
        raise NotImplementedError

    def read_json(self, path: str) -> Any:
        with self.open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def sizes(self, path: str) -> dict[str, int]:
        """{inner path: size} of every file beneath `path` (links and
        special files are not followed or counted as folders)."""
        out: dict[str, int] = {}
        stack = [""]
        while stack:
            rel = stack.pop()
            for name, e in self.listdir(self.join(path, *rel.split("/")) if rel else path).items():
                inner = f"{rel}/{name}" if rel else name
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(inner)
                    else:
                        out[inner] = e.stat(follow_symlinks=False).st_size
                except OSError:
                    pass
        return out


class LocalFS(StoreFS):
    """A local disk or an SMB share: os calls, as before StoreFS."""
    local = True

    def join(self, base: str, *parts: str) -> str:
        return os.path.join(base, *parts)

    def basename(self, path: str) -> str:
        return os.path.basename(os.path.normpath(path))

    def listdir(self, path: str) -> dict[str, os.DirEntry]:
        return _local_listdir(path)

    def stat(self, path: str) -> os.stat_result:
        return os.stat(path)

    def file_size(self, path: str) -> int | None:
        return _local_file_size(path)

    def isfile(self, path: str) -> bool:
        return os.path.isfile(path)

    def isdir(self, path: str) -> bool:
        return os.path.isdir(path)

    def open(self, path: str, mode: str = "rb", **kwargs: Any) -> Any:
        return open(path, mode, **kwargs)

    def readlink(self, path: str, entry: Any = None) -> str:
        return os.readlink(path)

    def sqlite_rows(self, path: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        return _local_sqlite_rows(path, sql, params)

    def lpath(self, path: str) -> str:
        return long_path(path)


LOCAL = LocalFS()


class _Stat:
    __slots__ = ("st_size", "st_mtime_ns")

    def __init__(self, size: int, mtime_ns: int) -> None:
        self.st_size = size
        self.st_mtime_ns = mtime_ns


class AgentFS(StoreFS):
    """A store read through a filecat-agent (fsource.AgentSource). Paths are
    the catalog's UNC paths, as the walker has them. One AgentFS serves one
    store's summarize(); `oversize` collects the manifests it would not copy."""

    def __init__(self, source: Any, root: str = "", cap: int = DEFAULT_MANIFEST_CAP) -> None:
        self.source = source
        self.root = root
        self.cap = cap
        self.oversize: list[str] = []

    # --- paths ---
    def join(self, base: str, *parts: str) -> str:
        parts = tuple(p for p in parts if p)
        if not parts:
            return base
        return base.rstrip("\\/") + "\\" + "\\".join(p.replace("/", "\\") for p in parts)

    def basename(self, path: str) -> str:
        return path.rstrip("\\/").rsplit("\\", 1)[-1].rsplit("/", 1)[-1]

    def _inner(self, path: str) -> str:
        """`path` within the store, for messages (never the full path)."""
        root = self.root.rstrip("\\/")
        if root and path.lower().startswith(root.lower()):
            return path[len(root):].lstrip("\\/").replace("\\", "/") or "."
        return self.basename(path)

    # --- the agent ---
    def _fail(self, e: OSError) -> OSError:
        from ..fsource import _entry_error
        code = getattr(e, "code", None)
        if code in ("not_found", "permission_denied"):
            return _entry_error(code, getattr(e, "message", str(e)))
        return e

    def stat(self, path: str) -> _Stat:
        try:
            m = self.source.client().measure(self.source.posix(path), "none", 0)
        except ValueError as e:
            raise OSError(errno.EINVAL, str(e)) from None
        except OSError as e:
            raise self._fail(e) from None
        return _Stat(m.size, m.mtime_ns)

    def listdir(self, path: str) -> dict[str, Any]:
        try:
            return {e.name: e for e in self.source.list_dir(path)}
        except OSError:
            return {}

    def isdir(self, path: str) -> bool:
        try:
            self.source.client().list_dir(self.source.posix(path))
            return True
        except (OSError, ValueError):
            return False

    def open(self, path: str, mode: str = "rb", **kwargs: Any) -> Any:
        size = self.stat(path).st_size
        return self.source.file_path(path, size).open(mode, **kwargs)

    def readlink(self, path: str, entry: Any = None) -> str:
        target = getattr(entry, "link_target", None)
        if target is None:
            raise OSError(errno.EINVAL, "not a link")
        return target

    # --- SQLite ---
    def sqlite_rows(self, path: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        return self.sqlite_many(path, [(sql, params)])[0]

    def sqlite_many(self, path: str, queries: list[tuple[str, tuple]]) -> list[list[dict[str, Any]]]:
        """Rows of queries on a SQLite manifest on the agent: the file, and its
        -wal / -journal when present, are copied to a temporary folder (system
        temp dir, deleted afterwards whatever happens) and the copy is queried.
        A copy with no sidecar opens read-only; with one it is opened normally
        (SQLite must replay a log, which it can only do by writing -- to the
        copy, never to the NAS). A manifest over the cap is not copied."""
        with tempfile.TemporaryDirectory(prefix=TEMP_PREFIX) as tmp:
            local = os.path.join(tmp, "db.sqlite")
            sidecars = self._copy_snapshot(path, local)
            if sidecars:
                conn = sqlite3.connect(local)
            else:
                conn = sqlite3.connect(Path(local).as_uri() + "?mode=ro", uri=True)
            try:
                conn.row_factory = sqlite3.Row
                return [[dict(r) for r in conn.execute(sql, params)] for sql, params in queries]
            finally:
                conn.close()

    def _sidecars(self, path: str) -> list[tuple[str, Any]]:
        out = []
        for suffix in ("-wal", "-journal"):
            try:
                st = self.stat(path + suffix)
            except OSError:
                continue
            if st.st_size > 0:
                out.append((suffix, st))
        return out

    def _copy_snapshot(self, path: str, local: str) -> bool:
        """Copy the manifest and its sidecars to `local`; True when there are
        sidecars. Retried once when the files changed while being read."""
        for attempt in (0, 1):
            main = self.stat(path)
            sidecars = self._sidecars(path)
            total = main.st_size + sum(st.st_size for _, st in sidecars)
            if total > self.cap:
                self.oversize.append(f"{self._inner(path)} ({total} bytes, limit {self.cap})")
                raise ManifestTooLarge(
                    errno.EFBIG, f"manifest of {total} bytes is over the {self.cap} byte limit "
                                 "for files read through filecat-agent")
            self._copy(path, main.st_size, local)
            for suffix, st in sidecars:
                self._copy(path + suffix, st.st_size, local + suffix)
            moved = [(path, main)] + [(path + sfx, st) for sfx, st in sidecars]
            if all(self._same(p, st) for p, st in moved):
                return bool(sidecars)
            for name in os.listdir(os.path.dirname(local)):
                os.remove(os.path.join(os.path.dirname(local), name))
        raise OSError(errno.EBUSY, "changed while being copied")

    def _same(self, path: str, before: _Stat) -> bool:
        try:
            now = self.stat(path)
        except OSError:
            return False
        return (now.st_size, now.st_mtime_ns) == (before.st_size, before.st_mtime_ns)

    def _copy(self, path: str, size: int, local: str) -> None:
        client = self.source.client()
        posix = self.source.posix(path)
        with open(local, "wb") as out:
            offset = 0
            while offset < size:
                try:
                    data = client.read_range(posix, offset, min(COPY_CHUNK, size - offset))
                except OSError as e:
                    raise self._fail(e) from None
                if not data:
                    break
                out.write(data)
                offset += len(data)
            if offset != size:
                raise OSError(errno.EIO, "short read from the agent")


def for_store(source: Any, root: str, cap: int) -> StoreFS:
    """The StoreFS of a store at `root`: local when `source` is None."""
    return LOCAL if source is None else AgentFS(source, root, cap)
