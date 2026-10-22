"""`filecat programs`: inventory installed software.

See file-catalog-requirements.md, section "Installed programs".

Sources, each producing zero or more program records:

* Uninstall registry keys (HKLM, HKLM\\WOW6432Node, HKCU) -> type "uninstall"
* The per-user AppX package repository key -> type "appx"
* Each directory on PATH, and the .exe files directly inside it ->
  types "path_dir" and "path_exe"
* Start Menu .lnk shortcuts (per-user and all-users) -> type "shortcut"

Every record has a stable `program_id` (sha256 of a source tag plus the
key path / file path, hex digest truncated to 16 chars), a `type`, and an
`errors` list when something about that one record failed. Records never
cause the registry, PATH, or Start Menu themselves to be modified.
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys
from typing import Any, Iterable

from .backends import open_backend
from .record import add_error
from . import reg as regmod
from . import lnk as lnkmod

# --- uninstall / AppX roots -------------------------------------------------

UNINSTALL_ROOTS: dict[str, str] = {
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall": "HKLM",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall": "HKLM\\WOW6432Node",
    r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall": "HKCU",
}
APPX_ROOT = (
    r"HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft"
    r"\Windows\CurrentVersion\AppModel\Repository\Packages"
)

UNINSTALL_VALUE_NAMES = ("DisplayName", "Publisher", "DisplayVersion", "InstallLocation", "EstimatedSize")
APPX_VALUE_NAMES = ("DisplayName", "Publisher", "PackageRootFolder", "PackageID")


def program_id(source: str, path: str) -> str:
    """Stable id: sha256 of 'source|path', hex digest truncated to 16 chars."""
    return hashlib.sha256(f"{source}|{path}".encode("utf-8")).hexdigest()[:16]


def _normalize(name: str) -> str:
    return " ".join(name.split()).casefold()


def classify_key(key_path: str) -> tuple[str, str, str] | None:
    """Classify a full registry key path from a .reg export or a live walk.

    Returns (record_type, hive_label, subkey_name) when key_path is a direct
    child of one of the Uninstall roots or the AppX Packages root; None
    otherwise (including the roots themselves).
    """
    norm = key_path.replace("/", "\\").rstrip("\\")
    for root, hive in UNINSTALL_ROOTS.items():
        prefix = root + "\\"
        if norm.startswith(prefix):
            rest = norm[len(prefix):]
            if rest and "\\" not in rest:
                return "uninstall", hive, rest
    prefix = APPX_ROOT + "\\"
    if norm.startswith(prefix):
        rest = norm[len(prefix):]
        if rest and "\\" not in rest:
            return "appx", "HKCU-AppX", rest
    return None


def _uninstall_record(record_type: str, hive: str, key_name: str, values: dict[str, Any],
                       source: str) -> dict[str, Any] | None:
    display_name = values.get("DisplayName")
    if not display_name:
        return None
    rec: dict[str, Any] = {
        "program_id": program_id(source, f"{hive}\\{key_name}"),
        "type": record_type,
        "hive": hive,
        "key": key_name,
        "display_name": display_name,
    }
    if record_type == "uninstall":
        if values.get("Publisher"):
            rec["publisher"] = values["Publisher"]
        if values.get("DisplayVersion"):
            rec["display_version"] = values["DisplayVersion"]
        if values.get("InstallLocation"):
            rec["install_location"] = values["InstallLocation"]
        if values.get("EstimatedSize") is not None:
            rec["estimated_size"] = values["EstimatedSize"]
    else:  # appx
        if values.get("Publisher"):
            rec["publisher"] = values["Publisher"]
        if values.get("PackageRootFolder"):
            rec["install_location"] = values["PackageRootFolder"]
        if values.get("PackageID"):
            rec["package_id"] = values["PackageID"]
    return rec


# --- .reg file source --------------------------------------------------

def scan_reg_files(paths: Iterable[str]) -> list[dict[str, Any]]:
    """Parse one or more regedit exports; return uninstall/appx records.

    Only sections that are direct subkeys of one of the Uninstall roots or
    the AppX Packages root are taken. Nothing is written back to the file
    or anywhere under a scanned root.
    """
    records: list[dict[str, Any]] = []
    for path in paths:
        source = f"reg-file:{path}"
        try:
            sections = regmod.parse_file(path)
        except OSError as exc:
            err_rec = {
                "program_id": program_id(source, path),
                "type": "uninstall",
                "key": path,
            }
            add_error(err_rec, "reg-file", exc)
            records.append(err_rec)
            continue
        for key_path, values in sections:
            classified = classify_key(key_path)
            if classified is None:
                continue
            record_type, hive, key_name = classified
            rec = _uninstall_record(record_type, hive, key_name, values, source)
            if rec is not None:
                records.append(rec)
    return records


# --- live registry source ------------------------------------------------

def scan_registry_live() -> list[dict[str, Any]]:
    """Walk the live registry. Returns records; a root that cannot even be
    opened for a reason other than "does not exist" gets one error record
    for that root (hive open failure), not one per program."""
    import winreg

    records: list[dict[str, Any]] = []

    def read_values(key, names: tuple[str, ...]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in names:
            try:
                value, _ = winreg.QueryValueEx(key, name)
                out[name] = value
            except FileNotFoundError:
                continue
        return out

    def walk_root(hive_const: int, subkey: str, hive_label: str, record_type: str,
                   value_names: tuple[str, ...]) -> None:
        source = f"live:{hive_label}"
        try:
            root_key = winreg.OpenKey(hive_const, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            return  # root key absent on this machine; not an error
        except OSError as exc:
            err_rec = {
                "program_id": program_id(source, subkey),
                "type": record_type,
                "hive": hive_label,
                "key": subkey,
                "root_error": True,
            }
            add_error(err_rec, "registry", exc)
            records.append(err_rec)
            return
        with root_key:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(root_key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root_key, name, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as sub:
                        values = read_values(sub, value_names)
                except OSError as exc:
                    err_rec = {
                        "program_id": program_id(source, f"{subkey}\\{name}"),
                        "type": record_type,
                        "hive": hive_label,
                        "key": name,
                    }
                    add_error(err_rec, "registry", exc)
                    records.append(err_rec)
                    continue
                rec = _uninstall_record(record_type, hive_label, name, values, source)
                if rec is not None:
                    records.append(rec)

    walk_root(winreg.HKEY_LOCAL_MACHINE,
              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
              "HKLM", "uninstall", UNINSTALL_VALUE_NAMES)
    walk_root(winreg.HKEY_LOCAL_MACHINE,
              r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
              "HKLM\\WOW6432Node", "uninstall", UNINSTALL_VALUE_NAMES)
    walk_root(winreg.HKEY_CURRENT_USER,
              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
              "HKCU", "uninstall", UNINSTALL_VALUE_NAMES)
    walk_root(winreg.HKEY_CURRENT_USER,
              r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
              "HKCU-AppX", "appx", APPX_VALUE_NAMES)
    return records


# --- PATH source -----------------------------------------------------------

def scan_path() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    raw = os.environ.get("PATH", "")
    for entry in raw.split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry:
            continue
        dir_rec: dict[str, Any] = {
            "program_id": program_id("path_dir", entry),
            "type": "path_dir",
            "path": entry,
        }
        try:
            exists = os.path.isdir(entry)
        except OSError as exc:
            add_error(dir_rec, "path", exc)
            records.append(dir_rec)
            continue
        dir_rec["exists"] = exists
        records.append(dir_rec)
        if not exists:
            continue
        try:
            with os.scandir(entry) as it:
                entries = list(it)
        except OSError as exc:
            add_error(dir_rec, "path", exc)
            continue
        for de in entries:
            if not de.is_file(follow_symlinks=False):
                continue
            if not de.name.lower().endswith(".exe"):
                continue
            exe_path = de.path
            records.append({
                "program_id": program_id("path_exe", exe_path),
                "type": "path_exe",
                "path": exe_path,
                "dir": entry,
                "name": de.name,
            })
    return records


# --- Start Menu .lnk source -------------------------------------------------

def _start_menu_roots() -> list[str]:
    roots = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(os.path.join(appdata, "Microsoft", "Windows", "Start Menu"))
    programdata = os.environ.get("PROGRAMDATA")
    if programdata:
        roots.append(os.path.join(programdata, "Microsoft", "Windows", "Start Menu"))
    return roots


def scan_start_menu(roots: Iterable[str] | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for root in (roots if roots is not None else _start_menu_roots()):
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                if not name.lower().endswith(".lnk"):
                    continue
                full = os.path.join(dirpath, name)
                rec: dict[str, Any] = {
                    "program_id": program_id("shortcut", full),
                    "type": "shortcut",
                    "path": full,
                }
                try:
                    parsed = lnkmod.parse_file(full)
                except (OSError, ValueError, struct.error) as exc:
                    add_error(rec, "lnk", exc)
                    records.append(rec)
                    continue
                rec.update(parsed)
                records.append(rec)
    return records


# --- join: file records <-> installed program display name -----------------

def join_installed_programs(backend) -> int:
    """For every exe file record whose probe.version_info.product_name
    equals a program display_name (exact, then normalized), set
    probe.installed_program and write the record back. Returns the count
    of file records updated."""
    exact: dict[str, str] = {}
    normalized: dict[str, str] = {}
    for prog in backend.list_programs():
        name = prog.get("display_name")
        if not name or prog.get("errors"):
            continue
        exact.setdefault(name, name)
        normalized.setdefault(_normalize(name), name)

    updated = 0
    for doc in backend.list(kind="exe"):
        probe = doc.get("probe") or {}
        version_info = probe.get("version_info") or {}
        product_name = version_info.get("product_name")
        if not product_name:
            continue
        matched = exact.get(product_name)
        if matched is None:
            matched = normalized.get(_normalize(product_name))
        if matched is None:
            continue
        doc.setdefault("probe", {})["installed_program"] = matched
        backend.put(doc)
        updated += 1
    return updated


# --- entry point -------------------------------------------------------

def run(args) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    registry_unreadable = False
    counts: dict[str, int] = {}
    error_count = 0

    try:
        backend.clear_programs()

        if getattr(args, "reg", None):
            records = scan_reg_files(args.reg)
        else:
            try:
                records = scan_registry_live()
            except ImportError as exc:
                print(f"filecat programs: winreg unavailable ({exc})", file=sys.stderr)
                records = []
                registry_unreadable = True

        if not getattr(args, "no_path", False):
            records.extend(scan_path())
        if not getattr(args, "no_start_menu", False):
            records.extend(scan_start_menu())

        for rec in records:
            backend.put_program(rec)
            counts[rec["type"]] = counts.get(rec["type"], 0) + 1
            if rec.get("errors"):
                error_count += 1
                if rec.get("root_error"):
                    registry_unreadable = True

        updated = join_installed_programs(backend)
        backend.flush()
    finally:
        backend.close()

    print("filecat programs:")
    for t in ("uninstall", "appx", "path_dir", "path_exe", "shortcut"):
        if t in counts:
            print(f"  {t}: {counts[t]}")
    print(f"  errors: {error_count}")
    print(f"  file records matched to an installed program: {updated}")

    return 1 if registry_unreadable else 0
