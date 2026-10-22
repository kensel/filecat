"""`filecat signatures status`: list signature database files and the date
recorded inside each one. Never fetches anything -- see
file-catalog-requirements.md, "Signature files live under ...".
"""
from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path
from typing import Any

PEEK_BYTES = 64 * 1024
VENDORED_DATA_FILES = ("freedesktop.org.xml", "comp_id.txt")

_DATE_PATTERNS = [
    re.compile(rb'DateCreated\s*=\s*"([^"]+)"'),
    re.compile(rb"<DateCreated>\s*([^<]+?)\s*</DateCreated>"),
    re.compile(rb"(?:version|date|updated|created)\D{0,20}(\d{4}-\d{2}-\d{2})", re.I),
    re.compile(rb"(\d{4}-\d{2}-\d{2})"),
    re.compile(rb"(\d{1,2}/\d{1,2}/\d{4})"),
]


def default_signatures_dir() -> Path:
    """args.dir, else $FILECAT_SIGNATURES, else <repo>/signatures relative
    to this package."""
    env = os.environ.get("FILECAT_SIGNATURES")
    if env:
        return Path(env)
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "signatures"


def _scan_bytes_for_date(data: bytes) -> str | None:
    for pattern in _DATE_PATTERNS:
        m = pattern.search(data)
        if m:
            return m.group(1).decode("utf-8", errors="replace").strip()
    return None


def _date_in_file(path: Path) -> str | None:
    try:
        if path.suffix.lower() == ".zip" and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist()[:25]:
                    if info.is_dir() or info.file_size > 4_000_000:
                        continue
                    with zf.open(info) as fh:
                        found = _scan_bytes_for_date(fh.read(PEEK_BYTES))
                    if found:
                        return found
            return None
        with path.open("rb") as fh:
            return _scan_bytes_for_date(fh.read(PEEK_BYTES))
    except OSError:
        return None


def _date_in_dir(path: Path, depth: int = 0) -> str | None:
    if depth > 2:
        return None
    try:
        children = sorted(path.iterdir())
    except OSError:
        return None
    for child in children[:200]:
        if child.is_dir():
            found = _date_in_dir(child, depth + 1)
        else:
            found = _date_in_file(child)
        if found:
            return found
    return None


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for child in path.rglob("*"):
            if child.is_file():
                try:
                    total += child.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def describe(path: Path) -> dict[str, Any]:
    if path.is_dir():
        size = _dir_size(path)
        date = _date_in_dir(path)
    else:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        date = _date_in_file(path)
    return {"name": path.name, "size": size, "date": date}


def list_entries(signatures_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if signatures_dir.is_dir():
        for child in sorted(signatures_dir.iterdir()):
            entries.append(describe(child))
    data_dir = Path(__file__).resolve().parent / "data"
    for name in VENDORED_DATA_FILES:
        p = data_dir / name
        if p.exists():
            entries.append(describe(p))
    return entries


def run(args: Any) -> int:
    if getattr(args, "action", "status") != "status":
        print(f"filecat signatures: unknown action {args.action!r}", file=__import__("sys").stderr)
        return 2
    signatures_dir = Path(args.dir) if getattr(args, "dir", None) else default_signatures_dir()
    for entry in list_entries(signatures_dir):
        date = entry["date"] or "no date recorded"
        print(f"{entry['name']}\t{entry['size']}\t{date}")
    return 0
