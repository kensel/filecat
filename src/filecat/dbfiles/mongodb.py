"""MongoDB dbPath::

    WiredTiger                  text: "WiredTiger\\nWiredTiger 10.0.2: (December 21, 2021)"
    WiredTiger.turtle           text metadata
    storage.bson                {storage: {engine, options: {directoryPerDB, directoryForIndexes}}}
    mongod.lock                 holds the pid while mongod runs, empty after a clean stop
    mongod.lock, WiredTiger.lock                    -- listed only: mongod holds them locked
    WiredTiger.wt, WiredTigerHS.wt, _mdb_catalog.wt, sizeStorer.wt   -- data
    collection-<id>.wt, index-<id>.wt               -- data; <id> is <n>-<number> before 8.0,
                                                       a UUID since (inside <db>/ with
                                                       directoryPerDB, <db>/collection/ and
                                                       <db>/index/ with directoryForIndexes)
    journal/WiredTigerLog.N, WiredTigerPreplog.N    -- data
    diagnostic.data/metrics.*                       -- data (FTDC, binary)
    _tmp/spilldb/                                   -- data: a second WiredTiger for spills (8.0+)

The server version is not in the dbPath's plain files; it is taken from
the install folder when the dbPath sits under it (mongodb-win32-x86_64-
windows-9.0.4\\data\\db, MongoDB\\Server\\8.0\\data), as version_source
"folder".

MMAPv1 (MongoDB < 4.2): <db>.ns and <db>.0, <db>.1 ... per database, journal/.

Which collection a .wt file holds is in _mdb_catalog.wt (a WiredTiger
table) and is not read yet; databases are named only when directoryPerDB
gives each its folder, or from MMAPv1 file names.
"""
from __future__ import annotations

import re
import struct
from typing import Any

from ..backup.storefs import LOCAL, StoreFS
from . import Engine, add_totals, read_text, scan_tree

_DATA_DIRS = {"journal", "diagnostic.data", "_tmp"}
_LOCKS = {"mongod.lock", "WiredTiger.lock"}
_MMAP_FILE = re.compile(r"^(.+)\.(?:ns|\d+)$")
_WT_LOG = re.compile(r"^WiredTiger(?:Log|Preplog|TmplogXXX)\.\d+$")
_RELEASE_FOLDER = re.compile(r"^mongodb-[\w.-]*?-(\d+\.\d+\.\d+(?:-rc\d+)?)$", re.I)


def version_from_path(path: str) -> str | None:
    """mongodb-win32-x86_64-windows-9.0.4 -> 9.0.4; MongoDB\\Server\\8.0 -> 8.0."""
    parts = re.split(r"[\\/]+", path)
    for i, part in enumerate(parts):
        m = _RELEASE_FOLDER.match(part)
        if m:
            return m.group(1)
        if part.lower() == "server" and i > 0 and parts[i - 1].lower() == "mongodb" \
                and i + 1 < len(parts) and re.fullmatch(r"\d+\.\d+", parts[i + 1]):
            return parts[i + 1]
    return None


def read_bson(data: bytes) -> dict[str, Any]:
    """The subset of BSON storage.bson uses: documents, strings, booleans,
    int32/int64. Other types stop the parse of their document."""
    def doc(pos: int) -> tuple[dict[str, Any], int]:
        (length,) = struct.unpack_from("<i", data, pos)
        end, pos, out = pos + length, pos + 4, {}
        while pos < end - 1:
            kind = data[pos]
            key_end = data.index(b"\x00", pos + 1)
            key = data[pos + 1:key_end].decode("utf-8", errors="replace")
            pos = key_end + 1
            if kind == 0x02:
                (n,) = struct.unpack_from("<i", data, pos)
                out[key] = data[pos + 4:pos + 3 + n].decode("utf-8", errors="replace")
                pos += 4 + n
            elif kind in (0x03, 0x04):
                out[key], _ = doc(pos)
                pos += struct.unpack_from("<i", data, pos)[0]
            elif kind == 0x08:
                out[key] = bool(data[pos])
                pos += 1
            elif kind == 0x10:
                out[key] = struct.unpack_from("<i", data, pos)[0]
                pos += 4
            elif kind == 0x12:
                out[key] = struct.unpack_from("<q", data, pos)[0]
                pos += 8
            else:
                break
        return out, end
    try:
        return doc(0)[0]
    except (struct.error, ValueError, IndexError):
        return {}


class _MongoDB(Engine):
    name = "mongodb"

    def matches(self, dir_name: str, names: set[str]) -> bool:
        if "WiredTiger" in names and ("_mdb_catalog.wt" in names or "storage.bson" in names):
            return True
        return "mongod.lock" in names and any(n.endswith(".ns") for n in names)    # MMAPv1

    def opaque(self, inner: str) -> bool:
        parts = inner.split("/")
        name = parts[-1]
        return (len(parts) > 1 and parts[0] in _DATA_DIRS) or name.endswith(".wt") \
            or name in _LOCKS or bool(_WT_LOG.match(name)) or bool(_MMAP_FILE.match(name))

    def summarize(self, path: str, names: set[str], fs: StoreFS = LOCAL) -> dict[str, Any]:
        wt_version = None
        for line in (read_text(fs.join(path, "WiredTiger"), fs=fs) or "").splitlines():
            m = re.match(r"WiredTiger (\d[\w.\-]*)", line)
            if m:
                wt_version = m.group(1)
                break
        options: dict[str, Any] = {}
        storage_engine = "wiredTiger" if "WiredTiger" in names else "mmapv1"
        try:
            with fs.open(fs.join(path, "storage.bson"), "rb") as f:
                storage = read_bson(f.read(64 * 1024)).get("storage") or {}
            storage_engine = storage.get("engine") or storage_engine
            options = storage.get("options") or {}
        except OSError:
            pass
        try:
            running = fs.stat(fs.join(path, "mongod.lock")).st_size > 0
        except OSError:
            running = None

        entries = fs.listdir(path)
        databases = []
        if storage_engine == "mmapv1":
            stems = sorted({m.group(1) for n in names if (m := _MMAP_FILE.match(n))})
            databases = [{"name": s} for s in stems]
        elif options.get("directoryPerDB"):
            for name, e in sorted(entries.items()):
                if e.is_dir(follow_symlinks=False) and name not in _DATA_DIRS and not name.startswith("_tmp"):
                    t = scan_tree(fs.join(path, name), depth=2, fs=fs)
                    databases.append({"name": name, "files": t["files"], "bytes": t["bytes"]})

        collections = indexes = 0
        for _, e in self._wt_files(path, depth=3 if options.get("directoryPerDB") else 1, fs=fs):
            if e.name.startswith("collection-"):
                collections += 1
            elif e.name.startswith("index-"):
                indexes += 1
        tree = scan_tree(path, depth=3, fs=fs)
        version = version_from_path(path)
        out: dict[str, Any] = {
            "engine": self.name, "version": version,
            **({"version_source": "folder"} if version else {}), "storage_engine": storage_engine,
            "wiredtiger_version": wt_version, "options": options, "running": running,
            "databases": databases, "collections": collections, "indexes": indexes,
            "journal": scan_tree(fs.join(path, "journal"), fs=fs)["files"] if "journal" in names else 0,
            "instance_keys": [], "problems": [],
        }
        return add_totals(out, tree, self)

    def _wt_files(self, path: str, depth: int, fs: StoreFS = LOCAL):
        stack = [(path, 1)]
        while stack:
            here, level = stack.pop()
            for name, e in fs.listdir(here).items():
                if e.is_dir(follow_symlinks=False):
                    if level < depth and name not in _DATA_DIRS:
                        stack.append((fs.join(here, name), level + 1))
                elif name.endswith(".wt"):
                    yield here, e


ENGINE = _MongoDB()
