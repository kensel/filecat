"""Cloud placeholder files: OneDrive Files On-Demand, iCloud Drive, Dropbox,
Box, and anything else built on the Windows Cloud Files API, plus files a
NAS or Azure File Sync has tiered off to other storage.

Such a file is listed with its real size and times, but its data is not on
the device: opening it for reading makes the provider download it. The
cloud reparse point behind it is hidden from programs (Windows reports no
reparse tag), so the marker is the file's attributes:

    RECALL_ON_DATA_ACCESS  0x400000   data is fetched when read (OneDrive, iCloud, ...)
    RECALL_ON_OPEN         0x40000    fetched when opened at all (some providers, folders)
    OFFLINE                0x1000     moved to offline storage (HSM, tiering, over SMB too)
    PINNED                 0x80000    "Always keep on this device"
    UNPINNED               0x100000   "Free up space": the provider may drop the local copy

A file with any of the first three is not opened by a scan: it is recorded
from its directory entry (name, size, times, the type its name suggests)
with probe.cloud = {"provider", "state": "online-only" | "offline", ...}.
Files under a registered sync root that are on the device get
probe.cloud too, with state "local" or "pinned", so the catalog knows
where they come from.

Sync roots are read from HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
Explorer\\SyncRootManager\\<id>\\UserSyncRoots (path per user SID); the
provider is the root's display name ("OneDrive - Personal"), else the
first part of its id ("iCloudDrive", "Dropbox"). Folders are listed as
usual: listing a folder the provider has not filled in yet fetches its
file list (names, not data).

`filecat enrich` measures an online-only record once the file is on the
device; `enrich --hydrate` downloads it to measure it (only when asked,
and only the records --root/--path/--kind/--limit select), and
`--free-after` hands it back to the provider afterwards by marking it
UNPINNED, as Explorer's "Free up space" does.
"""
from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

RECALL_ON_DATA_ACCESS = 0x400000
RECALL_ON_OPEN = 0x40000
OFFLINE = 0x1000
PINNED = 0x80000
UNPINNED = 0x100000
NOT_LOCAL = RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
# Attributes SetFileAttributesW takes (the recall bits are the provider's to set).
_SETTABLE = 0x1 | 0x2 | 0x4 | 0x20 | 0x100 | 0x1000 | 0x2000 | PINNED | UNPINNED

_SYNC_ROOTS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager"


@dataclass(frozen=True)
class SyncRoot:
    path: str           # as registered, e.g. C:\Users\me\OneDrive
    provider: str       # display name or id prefix
    id: str


def not_local(attributes: int) -> bool:
    return bool(attributes & NOT_LOCAL)


def state_of(attributes: int) -> str:
    if attributes & (RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN):
        return "online-only"
    if attributes & OFFLINE:
        return "offline"
    return "pinned" if attributes & PINNED else "local"


def file_attributes(path: str) -> int | None:
    """GetFileAttributesW: reads the attributes without opening the file,
    so a recall-on-open placeholder is not fetched. None off Windows or
    when the file is gone."""
    if sys.platform != "win32":
        return None
    get = ctypes.windll.kernel32.GetFileAttributesW
    get.restype = ctypes.c_uint32
    value = get(ctypes.c_wchar_p(_long(path)))
    return None if value == INVALID_FILE_ATTRIBUTES else value


def free_up(path: str) -> bool:
    """Hand a downloaded file back to its provider: set UNPINNED and clear
    PINNED (Explorer's "Free up space"). The provider drops the local copy
    when it gets to it. Returns whether the attributes were set."""
    attrs = file_attributes(path)
    if attrs is None:
        return False
    new = ((attrs | UNPINNED) & ~PINNED) & _SETTABLE
    return bool(ctypes.windll.kernel32.SetFileAttributesW(ctypes.c_wchar_p(_long(path)), new))


def _long(path: str) -> str:
    if len(path) < 248 or path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


@lru_cache(maxsize=1)
def sync_roots() -> tuple[SyncRoot, ...]:
    """Every registered sync root, longest path first (all users' roots:
    a scan of C:\\Users reads everyone's)."""
    if sys.platform != "win32":
        return ()
    import winreg
    out: list[SyncRoot] = []
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SYNC_ROOTS_KEY)
    except OSError:
        return ()
    with base:
        for i in range(winreg.QueryInfoKey(base)[0]):
            sid_name = winreg.EnumKey(base, i)
            try:
                with winreg.OpenKey(base, sid_name) as key:
                    provider = _value(key, "DisplayNameResource") or sid_name.split("!", 1)[0]
                    if provider.startswith("@"):        # an indirect resource string
                        provider = sid_name.split("!", 1)[0]
                    with winreg.OpenKey(key, "UserSyncRoots") as users:
                        for j in range(winreg.QueryInfoKey(users)[1]):
                            _, path, _ = winreg.EnumValue(users, j)
                            if isinstance(path, str) and path:
                                out.append(SyncRoot(path.rstrip("\\/"), provider, sid_name))
            except OSError:
                continue
    return tuple(sorted(out, key=lambda r: len(r.path), reverse=True))


def _value(key: Any, name: str) -> str | None:
    import winreg
    try:
        value, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return None
    return value if isinstance(value, str) and value else None


def provider_for(path: str, roots: tuple[SyncRoot, ...] | None = None) -> str | None:
    """The sync root's provider for a path inside one, matched on whole
    components ignoring case."""
    low = path.replace("/", "\\").lower()
    for root in sync_roots() if roots is None else roots:
        prefix = root.path.lower()
        if low == prefix or low.startswith(prefix + "\\"):
            return root.provider
    return None


def describe(path: str, attributes: int, roots: tuple[SyncRoot, ...] | None = None
             ) -> dict[str, Any] | None:
    """probe.cloud for a file, or None for an ordinary local file outside
    any sync root."""
    provider = provider_for(path, roots)
    if provider is None and not not_local(attributes):
        return None
    out: dict[str, Any] = {"provider": provider, "state": state_of(attributes)}
    if attributes & UNPINNED:
        out["unpinned"] = True
    return out


def attributes_of(st: os.stat_result) -> int:
    return getattr(st, "st_file_attributes", 0) or 0
