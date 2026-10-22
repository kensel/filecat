"""PostgreSQL cluster data directory (PGDATA)::

    PG_VERSION                  major version, e.g. "16"
    postgresql.conf, pg_hba.conf, pg_ident.conf, postgresql.auto.conf
    postmaster.pid              present while the server runs: pid, datadir, start, port, ...
    postmaster.opts
    global/pg_control           8 KB: system identifier, cluster state, last checkpoint time
    global/<relfilenode>        shared catalogs                       -- data
    base/<db oid>/<relfilenode>[.N][_fsm|_vm]   one folder per database -- data
    pg_wal/ (pg_xlog/ before 10)  16 MB WAL segments                    -- data
    pg_xact/ pg_multixact/ pg_subtrans/ pg_commit_ts/ pg_logical/ ...   -- data
    pg_tblspc/<oid>             junctions to tablespaces elsewhere (recorded as links)
    log/ (pg_log/ before 10)    server logs, text: measured as usual

pg_control is read for the system identifier (the instance key: a copy or a
physical replica keeps it) and the cluster state. A cluster whose state
says "in production" while no postmaster.pid is present was not shut down
cleanly: a copy taken while it ran, or a crash. Database names live in the
pg_database catalog (global/1262) and are not read yet; databases are
listed by OID.
"""
from __future__ import annotations

import os
import struct
from typing import Any

from ..backup.util import iso, listdir
from . import Engine, add_totals, merge_trees, read_text, scan_tree

_DATA_DIRS = {"base", "global", "pg_wal", "pg_xlog", "pg_xact", "pg_clog", "pg_multixact",
              "pg_subtrans", "pg_commit_ts", "pg_twophase", "pg_logical", "pg_replslot",
              "pg_serial", "pg_snapshots", "pg_stat", "pg_stat_tmp", "pg_notify", "pg_dynshmem"}
_STATES = {0: "starting up", 1: "shut down", 2: "shut down in recovery", 3: "shutting down",
           4: "in crash recovery", 5: "in archive recovery", 6: "in production"}
_KNOWN_OIDS = {"1": "template1"}


def read_control(path: str) -> dict[str, Any]:
    """The fixed head of ControlFileData (unchanged since 9.x): system
    identifier, control and catalog versions, state, time of last update.
    Little-endian, as written by x86 and ARM servers."""
    try:
        with open(path, "rb") as f:
            head = f.read(32)
    except OSError:
        return {}
    if len(head) < 32:
        return {}
    sysid, ctl_ver, cat_ver, state = struct.unpack_from("<QIII", head, 0)
    (when,) = struct.unpack_from("<q", head, 24)
    return {"system_identifier": str(sysid), "control_version": ctl_ver,
            "catalog_version": cat_ver, "cluster_state": _STATES.get(state, state),
            "control_time": iso(when) if 0 < when < 2**33 else None}


def _postmaster(path: str) -> dict[str, Any] | None:
    text = read_text(path)
    if text is None:
        return None
    lines = text.splitlines()
    out: dict[str, Any] = {}
    if lines and lines[0].strip().isdigit():
        out["pid"] = int(lines[0])
    if len(lines) > 3 and lines[3].strip().isdigit():
        out["port"] = int(lines[3])
    return out


class _Postgres(Engine):
    name = "postgres"

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return {"PG_VERSION", "base", "global"} <= names

    def opaque(self, inner: str) -> bool:
        parts = inner.split("/")
        return len(parts) > 1 and parts[0] in _DATA_DIRS

    def summarize(self, path: str, names: set[str]) -> dict[str, Any]:
        problems: list[str] = []
        version = (read_text(os.path.join(path, "PG_VERSION")) or "").strip() or None
        control = read_control(os.path.join(path, "global", "pg_control"))
        if not control:
            problems.append("global/pg_control missing or unreadable")
        pid = _postmaster(os.path.join(path, "postmaster.pid")) if "postmaster.pid" in names else None
        if control.get("cluster_state") == "in production" and pid is None:
            problems.append("not shut down cleanly (pg_control says in production, no "
                            "postmaster.pid): a copy taken while running, or a crash")

        databases = []
        for oid, entry in sorted(listdir(os.path.join(path, "base")).items(),
                                 key=lambda kv: (len(kv[0]), kv[0])):
            if not entry.is_dir(follow_symlinks=False):
                continue
            t = scan_tree(entry.path)
            databases.append({"oid": oid, "name": _KNOWN_OIDS.get(oid), "files": t["files"],
                              "bytes": t["bytes"], "newest": iso(t["newest_ns"] / 1e9) if t["newest_ns"] else None,
                              "_tree": t})
        wal_dir = "pg_wal" if "pg_wal" in names else "pg_xlog" if "pg_xlog" in names else None
        wal = scan_tree(os.path.join(path, wal_dir)) if wal_dir else {"files": 0, "bytes": 0, "newest_ns": 0}
        if wal_dir is None:
            problems.append("pg_wal missing")
        tablespaces = []
        for oid, entry in sorted(listdir(os.path.join(path, "pg_tblspc")).items()):
            try:
                target = os.readlink(entry.path)
            except OSError:
                target = None
            tablespaces.append({"oid": oid, "target": target})

        trees = [d.pop("_tree") for d in databases]
        trees += [scan_tree(os.path.join(path, d), depth=3) for d in sorted(names & _DATA_DIRS - {"base"})]
        out: dict[str, Any] = {
            "engine": self.name, "version": version,
            "running": pid is not None, **({"postmaster": pid} if pid else {}),
            **control, "databases": databases, "tablespaces": tablespaces,
            "wal": {"folder": wal_dir, "segments": wal["files"], "bytes": wal["bytes"]},
            "instance_keys": [f"pg:{control['system_identifier']}"] if control else [],
            "problems": problems,
        }
        return add_totals(out, merge_trees(*trees), self)


ENGINE = _Postgres()
