"""Which account a scan reads each root with.

Windows keeps one set of credentials per server name per logon session, so
the account belongs to the server (\\\\192.0.2.13 and \\\\nas-main are two
servers to Windows). For a UNC path it is, in order:

1. "connection": an open connection to that server (`net use`, a mapped
   drive, Explorer's login prompt) that was made with an explicit account.
   WNetGetUser reports it. A connection made with default credentials
   reports the Windows sign-in instead and does not count here.
2. "saved credential": Credential Manager's Windows credential for the
   server name (cmdkey /list: Domain:target=<server>), which Windows uses
   when no explicit account was given.
3. "windows logon": the signed-in Windows user.

A local path is read as the signed-in user ("local"). Returns None off
Windows or when nothing can be determined. Cached per server per process.
"""
from __future__ import annotations

import ctypes
import getpass
import sys
from ctypes import wintypes
from functools import lru_cache
from typing import Any

from .options import is_unc

RESOURCE_CONNECTED = 1
CRED_TYPE_DOMAIN_PASSWORD = 2
_MS = "microsoftaccount\\"


class _NETRESOURCE(ctypes.Structure):
    _fields_ = [("dwScope", wintypes.DWORD), ("dwType", wintypes.DWORD),
                ("dwDisplayType", wintypes.DWORD), ("dwUsage", wintypes.DWORD),
                ("lpLocalName", wintypes.LPWSTR), ("lpRemoteName", wintypes.LPWSTR),
                ("lpComment", wintypes.LPWSTR), ("lpProvider", wintypes.LPWSTR)]


class _CREDENTIAL(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.c_void_p),
                ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR)]


def server_of(path: str) -> str | None:
    """'\\\\nas-vm\\home\\x' -> 'nas-vm'; None for a local path."""
    if not is_unc(path):
        return None
    return path.replace("/", "\\").lstrip("\\").split("\\", 1)[0].lower() or None


def _clean(user: str) -> str:
    """WNetGetUser prefixes the sign-in's domain to a bare account name
    ('MicrosoftAccount\\admin'); the server only ever saw 'admin'."""
    if user.lower().startswith(_MS) and "@" not in user:
        return user[len(_MS):]
    return user


def _wnet_user(name: str | None) -> str | None:
    mpr = ctypes.WinDLL("mpr")
    buf = ctypes.create_unicode_buffer(512)
    size = wintypes.DWORD(512)
    if mpr.WNetGetUserW(name, buf, ctypes.byref(size)) != 0:
        return None
    return buf.value


@lru_cache(maxsize=1)
def logon_user() -> str:
    try:
        return _wnet_user(None) or getpass.getuser()
    except Exception:
        return getpass.getuser()


def _is_default(user: str) -> bool:
    """A connection made without an explicit account reports the sign-in:
    the local name, or the Microsoft account's address."""
    u = user.lower()
    return u == logon_user().lower() or (u.startswith(_MS) and "@" in u)


@lru_cache(maxsize=1)
def connections() -> dict[str, str]:
    """{server: account} for open connections made with an explicit account."""
    mpr = ctypes.WinDLL("mpr")
    handle = wintypes.HANDLE()
    if mpr.WNetOpenEnumW(RESOURCE_CONNECTED, 0, 0, None, ctypes.byref(handle)) != 0:
        return {}
    out: dict[str, str] = {}
    buf = (ctypes.c_byte * 65536)()
    try:
        while True:
            count, size = wintypes.DWORD(0xFFFFFFFF), wintypes.DWORD(len(buf))
            if mpr.WNetEnumResourceW(handle, ctypes.byref(count), buf, ctypes.byref(size)) != 0:
                break
            rows = ctypes.cast(buf, ctypes.POINTER(_NETRESOURCE))
            for i in range(count.value):
                r = rows[i]
                server = server_of(r.lpRemoteName or "")
                user = _wnet_user(r.lpLocalName or r.lpRemoteName)
                if server and user and not _is_default(user):
                    out.setdefault(server, _clean(user))
    finally:
        mpr.WNetCloseEnum(handle)
    return out


def saved_credential(server: str) -> str | None:
    adv = ctypes.WinDLL("advapi32")
    cred = ctypes.POINTER(_CREDENTIAL)()
    if not adv.CredReadW(server, CRED_TYPE_DOMAIN_PASSWORD, 0, ctypes.byref(cred)):
        return None
    try:
        return cred.contents.UserName
    finally:
        adv.CredFree(cred)


@lru_cache(maxsize=None)
def _for_server(server: str | None) -> dict[str, str] | None:
    if server is None:
        return {"user": logon_user(), "source": "local"}
    user = connections().get(server)
    if user:
        return {"user": user, "source": "connection"}
    user = saved_credential(server)
    if user:
        return {"user": user, "source": "saved credential"}
    return {"user": logon_user(), "source": "windows logon"}


def account_for(path: str) -> dict[str, str] | None:
    """{"user", "source"} for reading `path`, or None when unknown."""
    if sys.platform != "win32":
        return None
    try:
        return dict(_for_server(server_of(path)))
    except Exception:
        return None


def refresh() -> None:
    """Forget cached answers (after a `net use` login, for instance)."""
    for f in (logon_user, connections, _for_server):
        f.cache_clear()


def same_user(a: dict[str, Any] | None, b: dict[str, Any] | None) -> bool:
    if not a or not b:
        return True
    return _clean(a.get("user") or "").lower() == _clean(b.get("user") or "").lower()
