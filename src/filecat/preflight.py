"""Before a scan reads anything: can every root be opened, which account
reads it, and is that the account its last scan used?

    preflight: 70 roots
      \\\\192.0.2.13  16 roots  as scanuser (connection)
      \\\\nas-vm         20 roots  as admin (connection)
      local            4 roots  as winuser
    ! \\\\nas-zfs\\x: cannot open: [WinError 5] Access is denied
    ! \\\\nas-old\\Backup: read as scanuser (connection); the last scan used jdoe (2026-10-16)

A root read through a filecat-agent is checked by listing it through the
agent (it has no SMB account to report: the line says `as filecat-agent`).

Roots are opened in parallel, each with the scan's per-entry timeout, so a
dead server costs one timeout rather than one per share. Problems are
warnings: the scan still runs, and an unreachable root is recorded as such.
"""
from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any

from . import netaccount


@dataclass
class RootCheck:
    path: str                       # read from
    root: str                       # recorded as
    account: dict[str, str] | None
    error: str | None = None        # could not be opened
    previous: dict[str, Any] | None = None   # account of the last scan, when different
    previous_at: str | None = None


def _open(path: str) -> None:
    with os.scandir(path) as it:
        next(it, None)


def _previous_account(backend: Any, root: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        info = backend.get_root_info(root) or {}
    except Exception:
        return None, None
    for key in ("last_scan", "last_attempt"):
        rec = info.get(key) or {}
        if rec.get("account"):
            return rec["account"], rec.get("started_at")
    return None, None


def check(paths: list[str], roots: list[str], backend: Any, timeout: float,
          agents: list[Any] | None = None) -> list[RootCheck]:
    """`agents` is aligned with `paths`: the (fsource.AgentSource, path it
    knows the root by) that reads each root, or None for an SMB or local root."""
    agents = agents or [None] * len(paths)
    out = [RootCheck(p, r, {"user": "filecat-agent", "source": a[0].name} if a
                     else netaccount.account_for(p)) for p, r, a in zip(paths, roots, agents)]
    if not out:
        return out
    pool = ThreadPoolExecutor(max_workers=min(16, len(out)))
    try:
        futures = [pool.submit(a[0].check, a[1]) if a else pool.submit(_open, c.path)
                   for c, a in zip(out, agents)]
        for c, fut in zip(out, futures):
            try:
                fut.result(timeout=timeout)
            except FutureTimeoutError:
                c.error = f"no answer in {timeout:.0f}s"
            except OSError as e:
                c.error = str(e)
    finally:
        pool.shutdown(wait=False)   # a hung open is abandoned, as in the walker
    for c, a in zip(out, agents):
        if a:
            continue        # switching between SMB and an agent is not a change of account
        prev, at = _previous_account(backend, c.root)
        if prev and not netaccount.same_user(prev, c.account):
            c.previous, c.previous_at = prev, at
    return out


def _who(account: dict[str, str] | None) -> str:
    if not account:
        return "as ?"
    src = account.get("source")
    return f"as {account['user']}" + (f" ({src})" if src and src != "local" else "")


def report(checks: list[RootCheck], stream: Any = None) -> int:
    """Print the summary; returns how many problems were found."""
    stream = stream or sys.stderr
    groups: dict[str, list[RootCheck]] = {}
    for c in checks:
        server = netaccount.server_of(c.path)
        groups.setdefault(f"\\\\{server}" if server else "local", []).append(c)
    print(f"preflight: {len(checks)} roots", file=stream)
    width = max((len(k) for k in groups), default=0)
    for key, items in groups.items():
        print(f"  {key:<{width}}  {len(items):>3} roots  {_who(items[0].account)}", file=stream)
    problems = 0
    for c in checks:
        if c.error:
            problems += 1
            print(f"! {c.path}: cannot open: {c.error}", file=stream)
        if c.previous:
            problems += 1
            when = f" ({c.previous_at[:10]})" if c.previous_at else ""
            print(f"! {c.root}: read {_who(c.account)}; the last scan used "
                  f"{c.previous.get('user')}{when}", file=stream)
    return problems
