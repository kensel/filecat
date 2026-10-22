"""MySQL / MariaDB data directory (datadir)::

    auto.cnf                    [auto] server-uuid=...      (MySQL 5.6+)
    mysql_upgrade_info          version of the last upgrade (MariaDB, MySQL < 8.0)
    ibdata1, ibdata2 ...        InnoDB system tablespace     -- data
    ib_logfile0/1, #innodb_redo/   redo log                  -- data
    undo_001, ibtmp1, #innodb_temp/, ib_buffer_pool           -- data
    mysql.ibd                   data dictionary (MySQL 8.0+) -- data
    aria_log_control, aria_log.N   Aria (MariaDB)            -- data
    binlog.000001, <host>-bin.000001, *.index, relay logs     -- data
    <host>.pid                  present while the server runs
    <host>.err, *.log, *.cnf, *.pem   text and certificates: measured as usual
    <schema>/                   one folder per database: every file is data
        <table>.ibd | .frm | .MYD .MYI | .MAD .MAI | .CSV .CSM | .ARZ | .sdi ...

Databases and their tables come from the listing: a schema folder's table
files share the table's name. The server-uuid is the instance key.
"""
from __future__ import annotations

import os
import re
from collections import defaultdict
from typing import Any

from ..backup.util import iso, listdir
from . import Engine, add_totals, merge_trees, read_text, scan_tree

_MEASURED_EXT = (".cnf", ".ini", ".err", ".pid", ".pem", ".log", ".txt", ".flag")
_BINLOG = re.compile(r"^(?:binlog|.+-(?:bin|relay-bin))\.(?:\d{6,}|index)$", re.I)
_TABLE_EXT = {".ibd": "InnoDB", ".frm": None, ".myd": "MyISAM", ".myi": "MyISAM",
              ".mad": "Aria", ".mai": "Aria", ".csv": "CSV", ".csm": "CSV", ".arz": "ARCHIVE",
              ".sdi": None, ".par": None, ".trg": None}
_SYSTEM = {"mysql", "performance_schema", "sys", "information_schema"}
_INNODB = re.compile(r"^(?:ibdata\d+|ib_logfile\d+|ibtmp\d+|undo_?\d+|mysql\.ibd)$", re.I)


class _MySQL(Engine):
    name = "mysql"

    def matches(self, dir_name: str, names: set[str]) -> bool:
        marker = names & {"ibdata1", "mysql.ibd", "ib_logfile0", "#innodb_redo", "aria_log_control"}
        return bool(marker) and ("mysql" in names or "mysql.ibd" in names)

    def opaque(self, inner: str) -> bool:
        if "/" in inner:
            return True     # schema folders, #innodb_redo, #innodb_temp
        return inner != "mysql_upgrade_info" and not inner.lower().endswith(_MEASURED_EXT)

    def summarize(self, path: str, names: set[str]) -> dict[str, Any]:
        entries = listdir(path)
        upgrade = (read_text(os.path.join(path, "mysql_upgrade_info")) or "").strip() or None
        flavor = "mariadb" if "aria_log_control" in names or "mariadb" in (upgrade or "").lower() else "mysql"
        uuid = None
        m = re.search(r"^\s*server-uuid\s*=\s*(\S+)", read_text(os.path.join(path, "auto.cnf")) or "", re.M)
        if m:
            uuid = m.group(1)

        databases, trees = [], []
        for name, e in sorted(entries.items()):
            if not e.is_dir(follow_symlinks=False) or name.startswith("#") or name == "lost+found":
                continue
            tables: set[str] = set()
            engines: set[str] = set()
            for fname in listdir(e.path):
                stem, ext = os.path.splitext(fname)
                ext = ext.lower()
                if ext in _TABLE_EXT:
                    tables.add(re.sub(r"#P#.*$", "", stem, flags=re.I))   # partitions
                    if _TABLE_EXT[ext]:
                        engines.add(_TABLE_EXT[ext])
            t = scan_tree(e.path)
            trees.append(t)
            databases.append({"name": name, "system": name in _SYSTEM, "tables": len(tables),
                              "engines": sorted(engines), "files": t["files"], "bytes": t["bytes"],
                              "newest": iso(t["newest_ns"] / 1e9) if t["newest_ns"] else None})

        def total(match) -> dict[str, int]:
            sizes = []
            for n, e in entries.items():
                if match(n) and e.is_file(follow_symlinks=False):
                    try:
                        sizes.append(e.stat().st_size)
                    except OSError:
                        pass
            return {"files": len(sizes), "bytes": sum(sizes)}

        top = {"files": 0, "bytes": 0, "newest_ns": 0}
        for n, e in entries.items():
            if e.is_file(follow_symlinks=False) and self.opaque(n):
                try:
                    st = e.stat()
                except OSError:
                    continue
                top["files"] += 1
                top["bytes"] += st.st_size
                top["newest_ns"] = max(top["newest_ns"], st.st_mtime_ns)
        for d in ("#innodb_redo", "#innodb_temp"):
            if d in names:
                trees.append(scan_tree(os.path.join(path, d)))
        running = any(n.lower().endswith(".pid") for n in names)
        out: dict[str, Any] = {
            "engine": self.name, "flavor": flavor, "version": upgrade,
            **({"version_hint": "8.0+"} if upgrade is None and "mysql.ibd" in names else {}),
            "server_uuid": uuid, "running": running, "databases": databases,
            "innodb": total(_INNODB.match), "binlogs": total(_BINLOG.match),
            "instance_keys": [f"mysql:{uuid}"] if uuid else [], "problems": [],
        }
        return add_totals(out, merge_trees(top, *trees), self)


ENGINE = _MySQL()
