"""`filecat scan-everything`: every disk share of every server plus local
drives, in one scan run (one resume file, one progress stream).

What "everything" is comes from filecat.toml, or --server / --drive::

    [everything]
    servers = ["nas-vm", "nas-old", "192.0.2.13", "nas-zfs"]
    drives = ["C:", "D:", "E:", "I:"]
    exclude = ['\\\\nas-vm\\scratch', 'C:\\code\\filecat']
                                           # roots, or folders inside them, to leave out

    # a server that needs other credentials: connect first as this account
    # (net use prompts for the password once; [aliases] records the shares
    # under another name, e.g. '\\\\192.0.2.13' = '\\\\nas-main')
    [[everything.login]]
    server = "192.0.2.13"
    user = 'nas-main\\admin'

Shares come from NetShareEnum (what `net view \\\\server /all` shows): disk
shares only; administrative ones (C$, ADMIN$, IPC$) and printers are left
out. A server whose shares cannot be listed is reported and skipped; the
other servers and drives are still scanned and the exit code is 1.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from typing import Any

from .aliases import recorded_root

STYPE_MASK = 0x0FFFFFFF
STYPE_DISKTREE = 0
STYPE_SPECIAL = 0x80000000     # C$, ADMIN$, IPC$
ERROR_ACCESS_DENIED = 5
ERROR_MORE_DATA = 234
MAX_PREFERRED_LENGTH = 0xFFFFFFFF


class ShareListError(OSError):
    pass


class _SHARE_INFO_1(ctypes.Structure):
    _fields_ = [("shi1_netname", ctypes.c_wchar_p), ("shi1_type", ctypes.c_uint32),
                ("shi1_remark", ctypes.c_wchar_p)]


def list_shares(server: str) -> list[str]:
    """Disk share names on `server` (a name or IP, with or without \\\\).
    Raises ShareListError carrying the Windows error code."""
    netapi = ctypes.WinDLL("netapi32")
    buf = ctypes.c_void_p()
    read = ctypes.c_uint32()
    total = ctypes.c_uint32()
    resume = ctypes.c_uint32()
    rc = netapi.NetShareEnum(ctypes.c_wchar_p("\\\\" + server.lstrip("\\/")), 1, ctypes.byref(buf),
                             MAX_PREFERRED_LENGTH, ctypes.byref(read), ctypes.byref(total),
                             ctypes.byref(resume))
    try:
        if rc not in (0, ERROR_MORE_DATA):
            raise ShareListError(rc, f"{ctypes.FormatError(rc).strip()} (error {rc})")
        rows = ctypes.cast(buf, ctypes.POINTER(_SHARE_INFO_1 * read.value)).contents if read.value else []
        return sorted((r.shi1_netname for r in rows
                       if r.shi1_type & STYPE_MASK == STYPE_DISKTREE and not r.shi1_type & STYPE_SPECIAL),
                      key=str.lower)
    finally:
        if buf:
            netapi.NetApiBufferFree(buf)


def _login(server: str, user: str) -> bool:
    """`net use \\\\server\\IPC$ /user:USER *` -- prompts for the password on
    this console. One IPC$ connection carries the credentials to every share."""
    print(f"connecting to \\\\{server} as {user}", file=sys.stderr)
    ok = subprocess.call(["net.exe", "use", f"\\\\{server}\\IPC$", f"/user:{user}", "*"]) == 0
    if ok:
        from . import netaccount
        netaccount.refresh()    # the preflight should see the new connection's account
    return ok


def drive_root(drive: str) -> str:
    """'C', 'c:', 'C:\\' -> 'C:\\'."""
    letter = drive.strip().rstrip("\\/").rstrip(":")
    if len(letter) != 1 or not letter.isalpha():
        raise ValueError(f"not a drive letter: {drive!r}")
    return f"{letter.upper()}:\\"


def plan(servers: list[str], drives: list[str], logins: dict[str, str], exclude: list[str],
         aliases: dict[str, str], lister=None, login=None) -> tuple[list[str], list[str]]:
    """(roots to scan in order, problems). Roots are the paths read; the
    scan records each under its alias."""
    lister = lister or list_shares
    login = login or _login
    roots: list[str] = []
    problems: list[str] = []
    for server in servers:
        server = server.strip().lstrip("\\/")
        try:
            names = lister(server)
        except ShareListError as e:
            user = logins.get(server.lower())
            if not (user and e.errno == ERROR_ACCESS_DENIED and login(server, user)):
                problems.append(f"\\\\{server}: shares not listed: {e.strerror}")
                continue
            try:
                names = lister(server)
            except ShareListError as e2:
                problems.append(f"\\\\{server}: shares not listed: {e2.strerror}")
                continue
        if not names:
            problems.append(f"\\\\{server}: no disk shares")
        roots += [f"\\\\{server}\\{n}" for n in names]
    for d in drives:
        try:
            roots.append(drive_root(d))
        except ValueError as e:
            problems.append(str(e))
    skip = {x.rstrip("\\/").lower() for x in exclude}
    kept = [r for r in roots
            if r.rstrip("\\/").lower() not in skip
            and recorded_root(r, aliases).rstrip("\\/").lower() not in skip]
    return list(dict.fromkeys(kept)), problems


def run(args: Any) -> int:
    cfg = getattr(args, "everything", None) or {}
    if args.server or args.drive:          # the command line names the whole set
        servers, drives = args.server or [], args.drive or []
    else:
        servers, drives = list(cfg.get("servers") or []), list(cfg.get("drives") or [])
    exclude = list(cfg.get("exclude") or []) + (args.exclude or [])
    args.exclude = exclude      # whole roots are dropped here, folders inside them by the walker
    logins = {str(x.get("server", "")).lstrip("\\/").lower(): x["user"]
              for x in cfg.get("login") or [] if isinstance(x, dict) and x.get("user")}
    if not servers and not drives:
        print("filecat: nothing to scan; give --server/--drive or set [everything] in filecat.toml",
              file=sys.stderr)
        return 2

    roots, problems = plan(servers, drives, logins, exclude, args.aliases or {})
    for p in problems:
        print(f"filecat: {p}", file=sys.stderr)
    if args.list:
        for r in roots:
            shown = recorded_root(r, args.aliases or {})
            print(r if shown == r else f"{r}  -> recorded as {shown}")
        return 1 if problems else 0
    if not roots:
        return 1
    if not getattr(args, "check_only", False):
        print(f"scanning {len(roots)} roots", file=sys.stderr)

    from . import scan
    args.roots = roots
    code = scan.run(args)
    return max(code, 1 if problems else 0)
