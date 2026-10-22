"""`filecat members`: print the archive member rows recorded for one record.

See file-catalog-requirements.md and backends/base.py's "archive members"
section -- member rows are stored apart from the document itself
(`Backend.put_members` / `list_members`).
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Any

from .backends import open_backend

_HEADER = ("index", "role", "size", "csize", "path")
_NUMERIC_COLS = {0, 2, 3}  # index, size, csize are right-aligned


def _cell(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if value is None:
        return ""
    return str(value)


def _path_cell(row: dict[str, Any]) -> str:
    """Path, plus what the member is when the probe said (a volume's filesystem,
    label and partition type; a packed file's format)."""
    extra = [str(row[k]) for k in ("format", "label", "type_name") if row.get(k)]
    return _cell(row, "path") + (f"  ({', '.join(extra)})" if extra else "")


def _print_table(rows: list[dict[str, Any]]) -> None:
    lines = [list(_HEADER)]
    for row in rows:
        lines.append([
            _cell(row, "index"), _cell(row, "role"),
            _cell(row, "size"), _cell(row, "csize"), _path_cell(row),
        ])
    widths = [max(len(line[i]) for line in lines) for i in range(len(_HEADER))]
    for line in lines:
        cells = [cell.rjust(w) if i in _NUMERIC_COLS else cell.ljust(w)
                 for i, (cell, w) in enumerate(zip(line, widths))]
        print("  " + "  ".join(cells).rstrip())


def _footer(rows: list[dict[str, Any]]) -> list[str]:
    role_counts: Counter[str] = Counter()
    role_bytes: dict[str, int] = {}
    for row in rows:
        role = row.get("role") or "unknown"
        role_counts[role] += 1
        size = row.get("size")
        if isinstance(size, int):
            role_bytes[role] = role_bytes.get(role, 0) + size
    lines = [f"{len(rows)} member(s)"]
    for role, count in role_counts.most_common():
        nbytes = role_bytes.get(role)
        if nbytes is not None:
            lines.append(f"  {role}: {count} ({nbytes} bytes)")
        else:
            lines.append(f"  {role}: {count}")
    return lines


def run(args: Any) -> int:
    rel_path = args.rel_path.replace("\\", "/")
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        doc = backend.get(args.root, rel_path)
        if doc is None:
            print(f"filecat members: no record for root={args.root!r} rel_path={rel_path!r}",
                  file=sys.stderr)
            return 1

        try:
            rows = list(backend.list_members(args.root, rel_path))
        except NotImplementedError:
            print(f"filecat members: the {getattr(backend, 'name', 'this')} backend does not "
                  "store archive members", file=sys.stderr)
            return 1

        if args.role:
            wanted = set(args.role)
            rows = [r for r in rows if r.get("role") in wanted]

        if not rows:
            probe = doc.get("probe") or {}
            count = probe.get("members_count")
            if count:
                print(f"filecat members: {rel_path!r} has no stored member rows, but "
                      f"probe.members_count={count} was recorded (scanned with a backend or "
                      "a --max-members cap that didn't keep the rows)", file=sys.stderr)
            else:
                print(f"filecat members: {rel_path!r} has no recorded members", file=sys.stderr)
            return 1

        rows.sort(key=lambda r: r.get("index", 0))

        if args.json:
            for row in rows:
                print(json.dumps(row, ensure_ascii=False))
            for line in _footer(rows):
                print(line, file=sys.stderr)
        else:
            _print_table(rows)
            print()
            for line in _footer(rows):
                print(line)
        return 0
    finally:
        backend.close()
