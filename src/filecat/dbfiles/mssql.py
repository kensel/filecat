"""SQL Server database files: any folder holding an .mdf.

    <instance root>\\MSSQL16.MSSQLSERVER\\MSSQL\\DATA\\
        master.mdf, mastlog.ldf, model.mdf, modellog.ldf,
        msdbdata.mdf, msdblog.ldf, tempdb.mdf, templog.ldf   system databases
        <db>.mdf                primary data file            -- data
        <db>_<n>.ndf            secondary data files         -- data
        <db>_log.ldf            transaction log              -- data

Also LocalDB / App_Data folders and detached copies anywhere. The .mdf,
.ndf and .ldf directly in the folder are data; a subfolder holding an .mdf
is a store of its own. An .mdf with an .mds of the same name is an Alcohol
120% disc image, not SQL Server's. Logs often sit on another drive, so an .mdf with no
matching .ldf here is normal, not a problem. The version comes from the
instance folder in the path (MSSQL16 = SQL Server 2022); reading the boot
page of each .mdf (database name, version) is not done yet.

Attached databases are held open by the server: they show as probe.db_in_use
when measured. Detached or offline copies are read once they have not been
modified for an hour.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any

from ..backup.util import iso, listdir
from . import Engine, add_totals

_DATA_EXT = (".mdf", ".ndf", ".ldf")
_INSTANCE = re.compile(r"^MSSQL(\d+)(?:_(\d+))?\.(.+)$", re.I)
_RELEASES = {9: "2005", 10: "2008", 11: "2012", 12: "2014", 13: "2016", 14: "2017",
             15: "2019", 16: "2022", 17: "2025"}
_SYSTEM_LOGS = {"master": "mastlog", "model": "modellog", "msdbdata": "msdblog", "tempdb": "templog"}
_SYSTEM = {"master", "model", "msdbdata", "tempdb", "mssqlsystemresource"}


def instance(path: str) -> dict[str, Any] | None:
    """{"folder", "major", "release", "name"} from an MSSQLnn.NAME component,
    else {"folder", "major", "release"} from the shared-features folder
    (Microsoft SQL Server\\170\\ for 2025, holding LocalDB among others)."""
    parts = re.split(r"[\\/]+", path)
    for part in reversed(parts):
        m = _INSTANCE.match(part)
        if m:
            major = int(m.group(1))
            release = _RELEASES.get(major)
            if major == 10 and m.group(2) == "50":
                release = "2008 R2"
            return {"folder": part, "major": major, "release": release, "name": m.group(3)}
    for parent, part in zip(parts, parts[1:]):
        if parent.lower() == "microsoft sql server" and re.fullmatch(r"\d{2,3}", part):
            major = int(part) // 10 if len(part) == 3 else int(part)
            return {"folder": part, "major": major,
                    "release": "2008 R2" if part == "105" else _RELEASES.get(major)}
    return None


def _disc_images(names: set[str]) -> frozenset[str]:
    """.mdf files that are Alcohol 120% disc images: they come with an .mds."""
    lower = {n.lower() for n in names}
    return frozenset(n.lower() for n in names
                     if n.lower().endswith(".mdf") and f"{n[:-4].lower()}.mds" in lower)


class _MSSQL(Engine):
    name = "mssql"

    def __init__(self, skip: frozenset[str] = frozenset()) -> None:
        self.skip = skip    # lower-cased names in this folder that are not SQL Server files

    def matches(self, dir_name: str, names: set[str]) -> bool:
        skip = _disc_images(names)
        return any(n.lower().endswith(".mdf") and n.lower() not in skip for n in names)

    def for_folder(self, names: set[str]) -> "_MSSQL":
        skip = _disc_images(names)
        return _MSSQL(skip) if skip else self

    def opaque(self, inner: str) -> bool:
        return "/" not in inner and inner.lower().endswith(_DATA_EXT) and inner.lower() not in self.skip

    def summarize(self, path: str, names: set[str]) -> dict[str, Any]:
        files: dict[str, dict[str, Any]] = {}
        tree = {"files": 0, "bytes": 0, "newest_ns": 0}
        now = time.time()
        for name, e in listdir(path).items():
            if not (e.is_file(follow_symlinks=False) and self.opaque(name)):
                continue
            try:
                st = e.stat()
            except OSError:
                continue
            files[name] = {"file": name, "bytes": st.st_size, "modified": iso(st.st_mtime_ns / 1e9),
                           "quiet": now - st.st_mtime_ns / 1e9 >= self.quiet_seconds}
            tree["files"] += 1
            tree["bytes"] += st.st_size
            tree["newest_ns"] = max(tree["newest_ns"], st.st_mtime_ns)

        by_lower = {n.lower(): n for n in files}
        used: set[str] = set()
        databases = []
        for name in sorted(n for n in files if n.lower().endswith(".mdf")):
            stem = name[:-4]
            low = stem.lower()
            log_names = [f"{_SYSTEM_LOGS[low]}.ldf"] if low in _SYSTEM_LOGS else \
                [f"{low}_log.ldf", f"{low}.ldf", f"{low}log.ldf", f"{low}_1.ldf"]
            log = next((by_lower[n] for n in log_names if n in by_lower), None)
            secondary = sorted(n for n in files if n.lower().endswith(".ndf")
                               and n.lower().startswith(low))
            used.update([name, *secondary] + ([log] if log else []))
            databases.append({"name": "msdb" if low == "msdbdata" else stem, "system": low in _SYSTEM,
                              "data": files[name], "log": files.get(log) if log else None,
                              "secondary": [files[n] for n in secondary]})
        out: dict[str, Any] = {
            "engine": self.name, "instance": instance(path), "running": None,
            "version": (instance(path) or {}).get("release"),
            "databases": databases, "unmatched": [files[n] for n in sorted(set(files) - used)],
            "instance_keys": [], "problems": [],
        }
        return add_totals(out, tree, self)


ENGINE = _MSSQL()
