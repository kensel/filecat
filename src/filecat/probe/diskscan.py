"""Volume content scan: OS / role / user hints for a detected, unencrypted
volume. NTFS volumes are read through their $MFT (real names); everything
else gets the string heuristic over the first `cap` bytes of the volume.
"""
from __future__ import annotations

import re
import struct
from typing import Any

_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_MFT_CHUNK = 1024 * 1024
_FIRST_USER_RECORD = 24         # records 0-23 are NTFS system files
_ROOT_RECORD = 5
_SKIP_USERS = {"public", "default", "default user", "all users", "desktop.ini"}
_ROOT_CAP = 100

_WIN_MARKERS = ("windows\\system32", "windows\\system", "program files", "program files (x86)",
                "users\\", "bootmgr", "ntldr", "pagefile.sys", "hiberfil.sys")
_LINUX_MARKERS = ("/etc/", "/home/", "/usr/", "/var/", "/boot/", "lost+found",
                  "bin/bash", "etc/passwd", "etc/fstab")
_DOCKER_PATHS = ("/var/lib/docker", "/var/lib/docker/overlay2", "/var/lib/docker/containers",
                 "/var/lib/docker/image", "/var/lib/docker/volumes", "docker\\overlay2",
                 "programdata\\docker")
_PATH_PATTERNS = (r"Users\\[A-Za-z0-9_.\- ]+", r"/home/[a-zA-Z0-9_.\-]+",
                  r"/var/lib/docker[^\s\\]{0,40}", r"Windows\\[A-Za-z0-9_.\\ ]+",
                  r"Program Files[^\\]{0,20}", r"/etc/[a-zA-Z0-9_.\-]+", r"/var/[a-zA-Z0-9_.\-]+")


# --- NTFS via $MFT ----------------------------------------------------

def _apply_fixups(rec: bytearray) -> bool:
    usa_off, usa_n = struct.unpack_from("<HH", rec, 4)
    if usa_n < 2 or usa_off + 2 * usa_n > len(rec) or usa_n * 512 - 512 > len(rec):
        return False
    usn = bytes(rec[usa_off:usa_off + 2])
    for i in range(1, usa_n):
        end = i * 512
        if bytes(rec[end - 2:end]) != usn:
            return False
        rec[end - 2:end] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
    return True


_NS_RANK = {1: 0, 3: 0, 0: 1, 2: 2}     # Win32 and Win32+DOS beat POSIX beat DOS


def _file_name(rec: bytes) -> tuple[int, str] | None:
    """(parent record number, name) from the best $FILE_NAME attribute."""
    pos = struct.unpack_from("<H", rec, 0x14)[0]
    best: tuple[int, int, str] | None = None
    while pos + 24 <= len(rec):
        atype, alen = struct.unpack_from("<II", rec, pos)
        if atype == 0xFFFFFFFF or alen < 24:
            break
        if atype == 0x30 and rec[pos + 8] == 0:
            vlen, voff = struct.unpack_from("<IH", rec, pos + 16)
            v = rec[pos + voff:pos + voff + vlen]
            if len(v) >= 0x42:
                rank = _NS_RANK.get(v[0x41], 3)
                name = v[0x42:0x42 + 2 * v[0x40]].decode("utf-16-le", "replace")
                if best is None or rank < best[0]:
                    best = (rank, struct.unpack_from("<Q", v, 0)[0] & 0xFFFFFFFFFFFF, name)
        pos += alen
    return (best[1], best[2]) if best else None


def _read_mft(g: Any, mft_off: int, rec_size: int, cap: int) -> tuple[dict[int, tuple[int, str, bool]], int]:
    """record number -> (parent, name, is_dir) for in-use records, and the
    number of FILE records seen. Reads $MFT contiguously from its first
    cluster in 1 MiB chunks and stops at the first chunk with no FILE record."""
    entries: dict[int, tuple[int, str, bool]] = {}
    seen = 0
    chunk = max(rec_size, _MFT_CHUNK // rec_size * rec_size)
    pos = 0
    while pos < cap:
        data = g.read(mft_off + pos, min(chunk, cap - pos))
        n = len(data) // rec_size
        found = 0
        for i in range(n):
            rec = bytearray(data[i * rec_size:(i + 1) * rec_size])
            if rec[:4] != b"FILE" or not _apply_fixups(rec):
                continue
            found += 1
            flags = struct.unpack_from("<H", rec, 0x16)[0]
            fn = _file_name(bytes(rec)) if flags & 1 else None
            if fn:
                entries[(pos // rec_size) + i] = (fn[0], fn[1], bool(flags & 2))
        seen += found
        if not found or n == 0:
            break
        pos += n * rec_size
    return entries, seen


def _ntfs_facts(g: Any, off: int, fs: dict[str, Any], cap: int) -> dict[str, Any] | None:
    rec_size = fs.get("mft_record_size", 0)
    cluster = fs["bytes_per_sector"] * fs["sectors_per_cluster"]
    if not 256 <= rec_size <= 65536 or not cluster:
        return None
    entries, seen = _read_mft(g, off + fs["mft_cluster"] * cluster, rec_size, cap)
    root = {n: e for n, e in entries.items() if e[0] == _ROOT_RECORD and n >= _FIRST_USER_RECORD}
    if not root:
        return None
    out: dict[str, Any] = {"source": "mft", "mft_records_scanned": seen, "confidence": "high",
                           "root_entries": [name + "/" if is_dir else name
                                            for _, name, is_dir in list(root.values())[:_ROOT_CAP]]}
    names = {name.lower() for _, name, _ in root.values()}
    users_rec = next((n for n, (_, name, d) in root.items() if d and name.lower() == "users"), None)
    out["users"] = [name for parent, name, is_dir in entries.values()
                    if parent == users_rec and is_dir and name.lower() not in _SKIP_USERS]
    if "windows" in names and "program files" in names:
        out["os_hint"], out["role"] = "windows", "system"
    return out


# --- string heuristic -------------------------------------------------

def _all_text(scan: bytes) -> str:
    wide = [m.group().decode("utf-16-le") for m in _UTF16.finditer(scan)]
    return "\n".join(wide) + "\n" + scan.decode("ascii", "ignore")


def _role(os_hint: str | None, text: str) -> str | None:
    if os_hint == "windows":
        if any(x in text for x in ("Windows\\System32", "bootmgr", "NTLDR", "pagefile.sys")):
            return "system"
        return "system_or_data" if "Users\\" in text or "Program Files" in text else "data"
    if os_hint == "linux":
        if any(x in text for x in ("/etc/", "/boot/", "lost+found", "bin/bash")):
            return "system"
        return "system_or_data" if "/home/" in text or "/var/" in text else "data"
    return None


def _users(text: str) -> list[str]:
    users: list[str] = []
    for m in re.finditer(r"Users\\([A-Za-z0-9_.\- ]{1,32})", text, re.I):
        name = m.group(1).strip(" \\/")
        if name and name.lower() not in _SKIP_USERS and name not in users:
            users.append(name)
    for m in re.finditer(r"/home/([a-zA-Z0-9_.\-]{1,32})", text):
        if m.group(1) != "lost+found" and m.group(1) not in users:
            users.append(m.group(1))
    return users


# A filesystem that only one OS family installs onto rules out the other:
# a Linux /boot (ext) carries GRUB scripts that name bootmgr and ntldr.
_LINUX_ONLY_FS = {"ext", "xfs", "btrfs"}
_WINDOWS_ONLY_FS = {"ntfs", "refs"}


def scan_strings(scan: bytes, fs_type: str | None = None) -> dict[str, Any]:
    text = _all_text(scan)
    low = text.lower()
    win_hits = sum(1 for m in _WIN_MARKERS if m in low)
    linux_hits = sum(1 for m in _LINUX_MARKERS if m in text or m.encode() in scan)
    if fs_type in _LINUX_ONLY_FS:
        win_hits = 0
    elif fs_type in _WINDOWS_ONLY_FS:
        linux_hits = 0
    out: dict[str, Any] = {"os_hint": None, "role": None, "users": _users(text), "docker": [],
                           "interesting_paths": [], "confidence": "low"}
    if win_hits >= 2:
        out["os_hint"], out["confidence"] = "windows", "medium" if win_hits >= 3 else "low"
    elif linux_hits >= 2:
        out["os_hint"], out["confidence"] = "linux", "medium" if linux_hits >= 3 else "low"
    out["role"] = _role(out["os_hint"], text)
    out["docker"] = [p for p in _DOCKER_PATHS if p in low]
    found: set[str] = set()
    for pat in _PATH_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            found.add(m.group(0)[:80])
            if len(found) >= 20:
                break
    out["interesting_paths"] = sorted(found)[:15]
    if out["users"] or out["docker"]:
        out["confidence"] = "medium"
    return out


def scan_volume(g: Any, off: int, fs: dict[str, Any], cap: int) -> dict[str, Any] | None:
    """Summary dict for one volume, or None when nothing was learned."""
    if fs.get("type") == "ntfs":
        facts = _ntfs_facts(g, off, fs, cap)
        if facts:
            return facts
    out = scan_strings(g.read(off, cap), fs.get("type"))
    if out["os_hint"] or out["users"] or out["docker"]:
        return out
    return None
