"""Windows' own backups.

Backup and Restore file backups (Windows Vista / 7, still in 10/11)::

    <COMPUTER>/                          <- the store root
        MediaID.bin                      16-byte id of the backup target
        Backup Set 2009-05-21 123957/    one per full backup
            Backup Files 2009-05-21 123957/   the full, then one per increment
                Backup files 1.zip ... N.zip  opaque
                Catalogs/Backup files N.wbcat, .wbverify   one pair per zip, opaque
            Catalogs/GlobalCatalog.wbcat      opaque (proprietary, not parsed)

The catalog format is not public, so the checks come from the layout: every
zip that has a per-zip catalog is there, zip numbers run 1..N without gaps,
every zip has its catalog, and each set has its GlobalCatalog.wbcat.

System images (WindowsImageBackup)::

    WindowsImageBackup/<COMPUTER>/       <- the store root
        MediaId
        Catalog/BackupGlobalCatalog, GlobalCatalog
        Backup 2009-06-13 010936/
            <guid>.vhd / .vhdx           opaque: one per backed-up disk
            <guid>_Components.xml        machine name, OS version (UTF-16)
            BackupSpecs.xml (Windows 8+), *_Writer*.xml ...

Checks: each Backup folder has at least one .vhd/.vhdx, and Catalog is there.
"""
from __future__ import annotations

import html
import re
from typing import Any

from .storefs import LOCAL, StoreFS
from .util import iso_from_name

_SET = re.compile(r"^Backup Set (\d{4}-\d{2}-\d{2} \d{6})$", re.I)
_FILES = re.compile(r"^Backup Files (\d{4}-\d{2}-\d{2} \d{6})$", re.I)
_ZIP = re.compile(r"^Backup files (\d+)\.zip$", re.I)
_ZIP_CATALOG = re.compile(r"^Backup files (\d+)\.wbcat$", re.I)
_IMAGE = re.compile(r"^Backup (\d{4}-\d{2}-\d{2} \d{6})$", re.I)
_STAMP = "%Y-%m-%d %H%M%S"


def _media_id(path: str, fs: StoreFS = LOCAL) -> str | None:
    try:
        with fs.open(path, "rb") as f:
            data = f.read(64)
    except OSError:
        return None
    return data[:16].hex() if len(data) >= 16 else None


def _size(entry: Any) -> int:
    try:
        return entry.stat().st_size
    except OSError:
        return 0


class _FileBackup:
    name = "windows-backup"

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return any(_SET.match(n) for n in names)

    def opaque(self, inner: str) -> bool:
        parts = inner.split("/")
        if len(parts) < 2 or not _SET.match(parts[0]):
            return False
        return bool(len(parts) == 3 and _FILES.match(parts[1]) and _ZIP.match(parts[2])) \
            or parts[-1].lower().endswith((".wbcat", ".wbverify"))

    def summarize(self, path: str, names: set[str], fs: StoreFS = LOCAL) -> dict[str, Any]:
        machine = fs.basename(path)
        problems: list[str] = []
        sets = []
        for set_name in sorted(n for n in names if _SET.match(n)):
            set_path = fs.join(path, set_name)
            entries = fs.listdir(set_path)
            parts = []
            for files_name in sorted(n for n in entries if _FILES.match(n)):
                files_path = fs.join(set_path, files_name)
                zips = {int(_ZIP.match(n).group(1)): _size(e)
                        for n, e in fs.listdir(files_path).items() if _ZIP.match(n)}
                cats = {int(m.group(1)) for n in fs.listdir(fs.join(files_path, "Catalogs"))
                        if (m := _ZIP_CATALOG.match(n))}
                part = {"folder": files_name,
                        "time": iso_from_name(_FILES.match(files_name).group(1), _STAMP),
                        "zips": len(zips), "bytes": sum(zips.values())}
                where = f"{set_name}/{files_name}"
                expected = cats | set(range(1, max(zips, default=0) + 1))
                missing = sorted(expected - set(zips))
                if not zips and not cats:
                    problems.append(f"{where}: no Backup files N.zip")
                elif missing:
                    part["missing_zips"] = missing
                    problems.append(f"{where}: missing Backup files {_ranges(missing)}.zip")
                uncataloged = sorted(set(zips) - cats) if cats else []
                if uncataloged:
                    problems.append(f"{where}: no Catalogs/Backup files {_ranges(uncataloged)}.wbcat")
                parts.append(part)
            catalog = fs.join(set_path, "Catalogs", "GlobalCatalog.wbcat")
            if not fs.isfile(catalog):
                problems.append(f"{set_name}: Catalogs/GlobalCatalog.wbcat missing")
            sets.append({"folder": set_name,
                         "time": iso_from_name(_SET.match(set_name).group(1), _STAMP),
                         "parts": parts, "bytes": sum(p["bytes"] for p in parts)})
        media = _media_id(fs.join(path, "MediaID.bin"), fs)
        times = [p["time"] for s in sets for p in s["parts"] if p["time"]]
        return {
            "format": self.name, "machines": [machine], "media_id": media,
            "sets": sets, "versions": sum(len(s["parts"]) for s in sets),
            "latest": max(times, default=None), "problems": problems,
            "copy_keys": [f"winbackup:{machine.lower()}:{p['folder']}" for s in sets for p in s["parts"]],
            "machine_keys": [f"host:{machine.lower()}"],
        }


class _ImageBackup:
    name = "windows-image-backup"

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return any(_IMAGE.match(n) for n in names) and ("Catalog" in names or "MediaId" in names)

    def opaque(self, inner: str) -> bool:
        parts = inner.split("/")
        return len(parts) == 2 and bool(_IMAGE.match(parts[0])) \
            and parts[1].lower().endswith((".vhd", ".vhdx"))

    def summarize(self, path: str, names: set[str], fs: StoreFS = LOCAL) -> dict[str, Any]:
        folder_machine = fs.basename(path)
        problems: list[str] = []
        if "Catalog" not in names:
            problems.append("Catalog folder missing")
        versions = []
        for name in sorted(n for n in names if _IMAGE.match(n)):
            entries = fs.listdir(fs.join(path, name))
            disks = [{"file": n, "bytes": _size(e)} for n, e in sorted(entries.items())
                     if n.lower().endswith((".vhd", ".vhdx"))]
            ver: dict[str, Any] = {"folder": name,
                                   "time": iso_from_name(_IMAGE.match(name).group(1), _STAMP),
                                   "disks": disks, "bytes": sum(d["bytes"] for d in disks)}
            comp = next((n for n in entries if n.endswith("_Components.xml")), None)
            if comp:
                ver.update(_components(fs.join(path, name, comp), fs))
            if not disks:
                problems.append(f"{name}: no .vhd/.vhdx disk image")
            versions.append(ver)
        # Components.xml names the machine; the folder name is the fallback
        machines = sorted({v["machine"] for v in versions if v.get("machine")} or {folder_machine})
        return {
            "format": self.name, "machines": machines,
            "media_id": _media_id(fs.join(path, "MediaId"), fs),
            "images": versions, "versions": len(versions),
            "latest": max((v["time"] for v in versions if v["time"]), default=None),
            "problems": problems,
            "copy_keys": [f"wib:{folder_machine.lower()}:{v['folder']}" for v in versions],
            "machine_keys": [f"host:{m.lower()}" for m in machines],
        }


def _components(path: str, fs: StoreFS = LOCAL) -> dict[str, Any]:
    """Machine name and OS version from <guid>_Components.xml (UTF-16 with
    or without a BOM; the ASR metadata inside is escaped XML)."""
    try:
        with fs.open(path, "rb") as f:
            raw = f.read(256 * 1024)
    except OSError:
        return {}
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    elif raw[1:2] == b"\x00":
        text = raw.decode("utf-16-le", errors="replace")
    elif raw[:1] == b"\x00":
        text = raw.decode("utf-16-be", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    text = html.unescape(text)
    out = {}
    for key, field in (("machine", "MachineName"), ("os_version", "OSVersion")):
        m = re.search(rf'{field}="([^"]+)"', text)
        if m:
            out[key] = m.group(1)
    return out


def _ranges(numbers: list[int]) -> str:
    out, start = [], None
    for i, n in enumerate(numbers):
        if start is None:
            start = n
        if i + 1 == len(numbers) or numbers[i + 1] != n + 1:
            out.append(str(start) if start == n else f"{start}-{n}")
            start = None
    return ", ".join(out)


FILE_BACKUP = _FileBackup()
IMAGE_BACKUP = _ImageBackup()
