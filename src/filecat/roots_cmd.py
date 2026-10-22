"""`filecat roots`: the root index -- every root with its last scan, whether
a scan is in progress, the newest file and the last error. See rootinfo.py."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from . import rootinfo
from .backends import open_backend
from .summary import _human_bytes

STATE_LABELS = {"in_progress": "SCANNING", "stalled": "STALLED", "never": "not scanned",
                "ok": "ok", "errors": "errors", "unreachable": "UNREACHABLE",
                "interrupted": "interrupted", "failed": "FAILED"}


def _local(iso: str | None) -> str:
    if not iso:
        return "?"
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return iso


def _mtime(ns: int | None) -> str:
    return datetime.fromtimestamp(ns / 1e9).strftime("%Y-%m-%d %H:%M:%S") if ns else "?"


def _duration(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s" if m else f"{s}s"


def _print_root(row: dict[str, Any]) -> None:
    info = row["info"] or {}
    state = row["state"]
    print(f"{row['root']}  [{STATE_LABELS.get(state, state)}]")
    attempt = info.get("last_attempt") or {}
    last = info.get("last_scan")
    if state in ("in_progress", "stalled"):
        p = attempt.get("progress") or {}
        print(f"  scanning    started {_local(attempt.get('started_at'))} on {attempt.get('host', '?')}"
              f" (pid {attempt.get('pid', '?')}), last heartbeat {_local(attempt.get('heartbeat_at'))}")
        if p:
            print(f"              so far {p.get('files', 0)} files, {p.get('dirs', 0)} dirs, "
                  f"{_human_bytes(p.get('bytes', 0))}, {p.get('errors', 0)} with errors; at {p.get('last_path') or '.'}")
        if state == "stalled":
            print("              no heartbeat recently: the scan was probably killed or is hung")
    elif attempt and attempt.get("status") in ("interrupted", "failed"):
        print(f"  last try    {_local(attempt.get('started_at'))} -> {_local(attempt.get('finished_at'))} "
              f"{attempt['status']}" + (f": {attempt['error']}" if attempt.get("error") else ""))
    account = (last or {}).get("account") or attempt.get("account")
    if account:
        print(f"  account     {account.get('user')} ({account.get('source')})")
    if last:
        print(f"  last scan   {_local(last.get('started_at'))} -> {_local(last.get('finished_at'))} "
              f"({_duration(last.get('seconds'))}) on {last.get('host', '?')}: {last.get('status')}, "
              f"{last.get('files', 0)} files + {last.get('dirs', 0)} dirs written, "
              f"{_human_bytes(last.get('bytes', 0))}, {last.get('errors', 0)} with errors")
    elif not attempt:
        print("  last scan   none recorded (imported, or scanned before the root index existed)")
    newest = info.get("newest_file")
    if newest:
        print(f"  newest file {_mtime(newest.get('mtime_ns'))}  {newest.get('rel_path')}")
    err = info.get("last_error")
    if err:
        where = f" at {err['rel_path'] or 'the root itself'}" if err.get("rel_path") is not None else ""
        print(f"  last error  {_local(err.get('at'))} {err.get('stage')}: {err.get('message')}{where}")
    totals = row["summary"]
    if totals:
        print(f"  summary     {totals.get('total_files')} files, {_human_bytes(totals.get('total_bytes') or 0)}, "
              f"{totals.get('unreadable')} unreadable (saved {_local(totals.get('built_at'))})")
    print()


def run(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        rows = rootinfo.index(backend)
    finally:
        backend.close()
    if args.root:
        rows = [r for r in rows if r["root"] in args.root]
    if args.json:
        for r in rows:
            print(json.dumps(r, ensure_ascii=False))
        return 0
    if not rows:
        print("(no roots)")
    for r in rows:
        _print_root(r)
    return 0
