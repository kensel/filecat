"""`filecat databases`: the database data folders scans have recognised (dbfiles/).

One block per folder -- engine, version, running or not, quiet or active,
its databases and the problems found -- then the folders that share an
instance key: copies of one server's data folder (or a physical replica).
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterator

from .backends import open_backend
from .record import join_root
from .summary import _human_bytes


def folders(backend: Any, roots: list[str] | None = None) -> Iterator[dict[str, Any]]:
    """{"root", "rel_path", "path", "database", "errors"} for every data folder record."""
    for root in roots or backend.roots():
        for d in backend.list(kind="dir", root=root):
            db = (d.get("probe") or {}).get("database")
            if db:
                yield {"root": d["root"], "rel_path": d["rel_path"],
                       "path": join_root(d["root"], d["rel_path"]), "database": db,
                       "errors": d.get("errors") or []}


def _when(iso: str | None) -> str:
    return (iso or "?").replace("T", " ")[:16]


def _postgres_lines(db: dict[str, Any]) -> list[str]:
    out = [f"  cluster   system id {db.get('system_identifier') or '?'}, state "
           f"{db.get('cluster_state') or '?'}, pg_control {_when(db.get('control_time'))}"]
    wal = db.get("wal") or {}
    out.append(f"  wal       {wal.get('segments', 0)} files, {_human_bytes(wal.get('bytes', 0))}")
    for d in db.get("databases", []):
        out.append(f"    oid {d['oid']:<8} {d.get('name') or '':<10} {d['files']:>7} files  "
                   f"{_human_bytes(d['bytes']):>10}  newest {_when(d.get('newest'))}")
    for t in db.get("tablespaces", []):
        out.append(f"    tablespace {t['oid']} -> {t.get('target') or '?'}")
    return out


def _mysql_lines(db: dict[str, Any]) -> list[str]:
    inno, binl = db.get("innodb") or {}, db.get("binlogs") or {}
    out = [f"  {db.get('flavor')}  server-uuid {db.get('server_uuid') or '?'}; innodb "
           f"{_human_bytes(inno.get('bytes', 0))}, binlogs {binl.get('files', 0)} "
           f"({_human_bytes(binl.get('bytes', 0))})"]
    for d in db.get("databases", []):
        tag = " (system)" if d.get("system") else ""
        out.append(f"    {d['name']:<24} {d['tables']:>5} tables  {_human_bytes(d['bytes']):>10}  "
                   f"{','.join(d.get('engines') or [])}{tag}")
    return out


def _mongodb_lines(db: dict[str, Any]) -> list[str]:
    opts = ", ".join(k for k, v in (db.get("options") or {}).items() if v)
    out = [f"  {db.get('storage_engine')}  WiredTiger {db.get('wiredtiger_version') or '?'}; "
           f"{db.get('collections', 0)} collections, {db.get('indexes', 0)} indexes"
           + (f"; {opts}" if opts else "")]
    for d in db.get("databases", []):
        out.append(f"    {d['name']}" + (f"  {_human_bytes(d['bytes'])}" if "bytes" in d else ""))
    return out


def _mssql_lines(db: dict[str, Any]) -> list[str]:
    inst = db.get("instance") or {}
    out = [f"  instance  {inst.get('folder')} (SQL Server {inst.get('release') or '?'})"] if inst else []

    def f(x: dict[str, Any] | None) -> str:
        if not x:
            return "-"
        return f"{x['file']} {_human_bytes(x['bytes'])} {_when(x.get('modified'))}" \
            + ("" if x.get("quiet") else " (active)")
    for d in db.get("databases", []):
        tag = " (system)" if d.get("system") else ""
        out.append(f"    {d['name']}{tag}: data {f(d['data'])}; log {f(d.get('log'))}"
                   + "".join(f"; {f(s)}" for s in d.get("secondary", [])))
    for x in db.get("unmatched", []):
        out.append(f"    unmatched {f(x)}")
    return out


_DETAIL = {"postgres": _postgres_lines, "mysql": _mysql_lines,
           "mongodb": _mongodb_lines, "mssql": _mssql_lines}


def _print_folder(fo: dict[str, Any]) -> None:
    db = fo["database"]
    problems = db.get("problems", [])
    flag = f"  {len(problems)} problems" if problems else ""
    print(f"{fo['path']}  [{db.get('engine')}]{flag}")
    running = {True: "running", False: "stopped", None: "running: unknown"}[db.get("running")]
    print(f"  version {db.get('version') or '?'}; {running}; {db.get('files', 0)} data files, "
          f"{_human_bytes(db.get('bytes', 0))}; newest {_when(db.get('newest'))} "
          f"({'quiet' if db.get('quiet') else 'active'})")
    for line in _DETAIL.get(db.get("engine"), lambda _: [])(db):
        print(line)
    for p in problems:
        print(f"  ! {p}")
    for e in fo["errors"]:
        if e.get("stage") == "database":
            print(f"  ! metadata not read: {e.get('message')}")
    print()


def copies(found: list[dict[str, Any]]) -> dict[str, list[str]]:
    """{instance key: folder paths} for keys shared by more than one folder."""
    by_key: dict[str, set[str]] = defaultdict(set)
    for fo in found:
        for k in fo["database"].get("instance_keys", []):
            by_key[k].add(fo["path"])
    return {k: sorted(v) for k, v in sorted(by_key.items()) if len(v) > 1}


def run(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        found = list(folders(backend, args.root))
    finally:
        backend.close()
    if args.json:
        for fo in found:
            print(json.dumps(fo, ensure_ascii=False))
        return 0
    if not found:
        print("(no database folders recorded; they are recognised when a scan walks them)")
        return 0
    for fo in found:
        _print_folder(fo)
    shared = copies(found)
    if shared:
        print("Copies of one instance (same system identifier / server-uuid):")
        for key, paths in shared.items():
            print(f"  {key}")
            for p in paths:
                print(f"    {p}")
        print()
    return 0
