"""`filecat summary`: the WinDirStat-style overview (extension / type /
directory totals and percentages), plus `--disagree` and `--rebuild`.

See file-catalog-requirements.md, "Overview".
"""
from __future__ import annotations

from typing import Any

from .backends import open_backend

# args.by uses the CLI's own names ("extension"); aggregate.py / Backend.summary()
# key their tables as "suffix".
_TABLE_KEYS = {"extension": "suffix", "mime": "mime", "dir": "dir"}
_TITLES = {"suffix": "Extensions", "mime": "Types", "dir": "Directories"}


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _print_table(table_key: str, rows: list[dict[str, Any]], top: int) -> None:
    print(f"-- {_TITLES[table_key]} --")
    if not rows:
        print("  (no entries)")
        print()
        return
    shown = rows if top <= 0 else rows[:top]
    header = [{"suffix": "extension", "mime": "type", "dir": "directory"}[table_key]]
    if table_key == "suffix":
        header.append("description")
    header += ["files", "bytes", "percent"]
    lines = [header]
    for row in shown:
        label = row.get(table_key)
        if table_key == "suffix" and not label:
            label = "(none)"
        cols = [str(label)]
        if table_key == "suffix":
            cols.append(row.get("description") or "")
        cols.append(str(row["files"]))
        cols.append(f"{_human_bytes(row['bytes'])} ({row['bytes']})")
        cols.append(f"{row['percent']:.1f}%")
        lines.append(cols)
    # Text columns left-aligned, the three numeric columns right-aligned.
    widths = [max(len(line[i]) for line in lines) for i in range(len(header))]
    numeric_from = len(header) - 3
    for line in lines:
        cells = [cell.rjust(w) if i >= numeric_from else cell.ljust(w)
                 for i, (cell, w) in enumerate(zip(line, widths))]
        print("  " + "  ".join(cells).rstrip())
    if top > 0 and len(rows) > top:
        print(f"  ... {len(rows) - top} more (--top 0 shows all)")
    print()


def by_tag(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Backend.rollup_totals() rows of one root summed per tag, biggest first."""
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        t = out.setdefault(r["tag"], {"tag": r["tag"], "folders": 0, "total_files": 0, "total_dirs": 0,
                                      "size": 0, "allocated_size": 0, "newest_mtime_ns": 0,
                                      "partial": 0, "errors": 0})
        for key in ("folders", "total_files", "total_dirs", "size", "allocated_size", "partial", "errors"):
            t[key] += r.get(key) or 0
        t["newest_mtime_ns"] = max(t["newest_mtime_ns"], r.get("newest_mtime_ns") or 0)
    return sorted(out.values(), key=lambda t: (-t["size"], t["tag"]))


def _ago(ns: int) -> str:
    from datetime import datetime
    return datetime.fromtimestamp(ns / 1e9).strftime("%Y-%m-%d") if ns else "-"


def _print_rollups(rows: list[dict[str, Any]]) -> None:
    """The Rollups table of one root: what the catalog counts but does not list."""
    tags = by_tag(rows)
    print("-- Rollups --")
    lines = [["tag", "rollups", "files", "bytes", "allocated", "newest"]]
    for t in tags:
        alloc = _human_bytes(t["allocated_size"]) if t["allocated_size"] else "-"
        lines.append([t["tag"] + (" (partial)" if t["partial"] else ""), str(t["folders"]),
                      str(t["total_files"]), f"{_human_bytes(t['size'])} ({t['size']})", alloc,
                      _ago(t["newest_mtime_ns"])])
    widths = [max(len(line[i]) for line in lines) for i in range(6)]
    for line in lines:
        cells = [cell.ljust(w) if i == 0 else cell.rjust(w) for i, (cell, w) in enumerate(zip(line, widths))]
        print("  " + "  ".join(cells).rstrip())
    print()


def _print_disagree(backend: Any, root: str | None) -> None:
    print("-- Disagreements (glob vs magic) --")
    found = False
    for doc in backend.list(root=root):
        probe = doc.get("probe") or {}
        if probe.get("identify_basis") != "disagree":
            continue
        found = True
        path = doc.get("rel_path") or "."
        suffix = doc.get("suffix") or "(none)"
        glob_type = probe.get("mime_glob") or ""
        magic_type = probe.get("mime_magic") or ""
        size = doc.get("size", 0)
        print(f"  {path}  suffix={suffix}  glob={glob_type}  magic={magic_type}  size={size}")
    if not found:
        print("  (none)")


def run(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        if args.rebuild:
            backend.rebuild_aggregates(depth=args.depth, root=args.root)

        if args.disagree:
            _print_disagree(backend, args.root)
            return 0

        tables = args.by or ["extension", "mime", "dir"]
        data = backend.summary(root=args.root, depth=args.depth)
        roots = data.get("roots", {})
        rollups = backend.rollup_totals(args.root)
        if not roots:
            print("(no records)")
            return 0

        for root_name in sorted(roots):
            root_data = roots[root_name]
            print(f"=== root: {root_name} ===")
            for by in tables:
                key = _TABLE_KEYS[by]
                _print_table(key, root_data.get(key, []), args.top)
            total_bytes = root_data.get("total_bytes", 0)
            tags = by_tag(rollups.get(root_name, []))
            if tags:
                _print_rollups(rollups[root_name])
            print(f"total files: {root_data.get('total_files', 0)}   "
                  f"total bytes: {_human_bytes(total_bytes)} ({total_bytes})")
            if tags:
                r_files, r_bytes = sum(t["total_files"] for t in tags), sum(t["size"] for t in tags)
                print(f"recorded files: {root_data.get('total_files', 0)}, {_human_bytes(total_bytes)}; "
                      f"rollups: {r_files}, {_human_bytes(r_bytes)}; "
                      f"together {_human_bytes(total_bytes + r_bytes)} ({total_bytes + r_bytes} bytes)")
            print(f"unreadable: {root_data.get('unreadable', 0)}")
            print()
        return 0
    finally:
        backend.close()
