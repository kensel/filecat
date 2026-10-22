"""`filecat dupes`: likely duplicates among big files, without reading them whole.

Files above 64 MiB carry no full SHA-256 (hashing.py), only sha256_partial,
which also mixes in mtime, so copies with different mtimes never match on it.
This groups the catalog's files by exact size, a --bands size band at a time
(largest first; MongoDB selects each band by an indexed range), then
hashes a few windows of each file: the start, --samples - 2 evenly spaced
interior windows and the end. Files of one size whose windows all match form
a cluster of probable copies. A sparse match is strong evidence, not proof:
a change between the windows goes unseen. `--full` settles it with a full
SHA-256 of every file in a cluster, up to --full-max.

The catalog is only read; the files themselves are read through the scan's
aliases and --path-map, as `enrich` does.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable

from . import imagelist
from .aliases import source_path
from .backends import open_backend
from .enrich import parse_path_map
from .hashing import _sha256_full
from .options import MiB
from .record import join_root
from .summary import _human_bytes

ALIGN = 4096        # interior windows start on a 4 KiB boundary


def sample_ranges(size: int, samples: int, window: int) -> list[tuple[int, int]]:
    """(offset, length) of each window: first, evenly spaced interior ones, last.
    A file no longer than the windows together is one range, the whole file."""
    if size <= samples * window:
        return [(0, size)]
    last = size - window
    return [(i * last // (samples - 1) // ALIGN * ALIGN if i < samples - 1 else last, window)
            for i in range(samples)]


def sparse_digests(path: str, size: int, samples: int, window: int) -> tuple[str, ...]:
    out = []
    with open(path, "rb") as f:
        for offset, length in sample_ranges(size, samples, window):
            f.seek(offset)
            out.append(hashlib.sha256(f.read(length)).hexdigest())
    return tuple(out)


def _in_backup(d: dict[str, Any]) -> bool:
    """Is the file backup data a scan recorded from the listing (probe.backup_data)?"""
    return bool((d.get("probe") or {}).get("backup_data"))


def find_duplicates(docs: Iterable[dict[str, Any]], local_path: Callable[[str, str], str], *,
                    min_size: int, samples: int, window: int, full: bool = False,
                    full_max: int = 1024 * MiB, workers: int = 4,
                    progress: Callable[[int, int], None] | None = None,
                    include_backups: bool = False,
                    ) -> tuple[list[dict[str, Any]], list[str]]:
    """(clusters, errors). A cluster is files of one size whose windows match;
    `confirmed` is "full" (equal SHA-256), "sparse" (windows only), or
    "sparse (over --full-max)" when --full left it unread for size.

    Backup data copies itself by design (every generation of a profile copy,
    every copy of a job folder), so unless `include_backups` a cluster made
    only of backup data is dropped, and a size group with no file outside a
    backup is never read; a backup file that matches a file elsewhere stays."""
    by_size: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for d in docs:
        size = d.get("size")
        if d.get("kind") != "dir" and isinstance(size, int) and size >= min_size:
            by_size[size].append(d)
    todo = [d for group in by_size.values() if len(group) > 1
            and (include_backups or not all(_in_backup(x) for x in group)) for d in group]
    errors: list[str] = []
    done = 0

    def measure(d: dict[str, Any], digest: Callable[[str], Any]) -> Any:
        nonlocal done
        try:
            return digest(local_path(d["root"], d["rel_path"]))
        except OSError as exc:
            errors.append(f"{d['root']} {d['rel_path']}: {exc}")
            return None
        finally:
            done += 1
            if progress:
                progress(done, len(todo))

    with ThreadPoolExecutor(max(1, workers)) as pool:
        prints = list(pool.map(
            lambda d: measure(d, lambda p: sparse_digests(p, d["size"], samples, window)), todo))
        clusters_by_key: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
        for d, fp in zip(todo, prints):
            if fp is not None:
                clusters_by_key[(d["size"], fp)].append(d)
        found = [(k[0], g) for k, g in clusters_by_key.items() if len(g) > 1
                 and (include_backups or not all(_in_backup(d) for d in g))]

        out: list[dict[str, Any]] = []
        for size, group in found:
            if not full:
                out.append(_cluster(size, group, "sparse"))
            elif size > full_max:
                out.append(_cluster(size, group, "sparse (over --full-max)"))
            else:
                done = 0
                todo = group
                sums = list(pool.map(lambda d: measure(d, _sha256_full), group))
                by_sum: dict[str, list[dict[str, Any]]] = defaultdict(list)
                for d, s in zip(group, sums):
                    if s is not None:
                        by_sum[s].append(d)
                out += [_cluster(size, g, "full") for g in by_sum.values() if len(g) > 1
                        and (include_backups or not all(_in_backup(d) for d in g))]
    out.sort(key=lambda c: (-c["wasted_bytes"], -c["copies"], c["paths"][0]["rel_path"]))
    return out, errors


def _cluster(size: int, group: list[dict[str, Any]], confirmed: str) -> dict[str, Any]:
    return {"size": size, "copies": len(group), "wasted_bytes": size * (len(group) - 1),
            "confirmed": confirmed,
            "paths": sorted(({"root": d["root"], "rel_path": d["rel_path"],
                              **({"backup": d["probe"]["backup_data"]} if _in_backup(d) else {})}
                             for d in group),
                            key=lambda p: (p["root"], p["rel_path"]))}


def _compare_images(exe: str, cluster: dict[str, Any], local_path: Callable[[str, str], str]) -> None:
    """Add cluster["listing"]: each copy's file listing (path, size, mtime) from
    dissect's target-query, walked in step with the first copy's and stopped at
    the first difference. Images only."""
    paths = cluster["paths"]
    if not all(p["rel_path"].lower().endswith(imagelist.IMAGE_SUFFIXES) for p in paths):
        return
    first = local_path(paths[0]["root"], paths[0]["rel_path"])
    try:
        results = [imagelist.compare_streams(exe, first, local_path(p["root"], p["rel_path"]))
                   for p in paths[1:]]
    except (imagelist.ListingError, OSError) as exc:
        cluster["listing"] = f"unavailable: {exc}"
        return
    cluster["listing"] = ("identical" if all(r["identical"] for r in results) else "differs")
    cluster["listing_detail"] = results


def run(args: Any) -> int:
    if args.samples < 2:
        print("filecat dupes: --samples must be at least 2", file=sys.stderr)
        return 2
    try:
        path_map = parse_path_map(args.path_map)
    except ValueError as exc:
        print(f"filecat dupes: {exc}", file=sys.stderr)
        return 2
    aliases = getattr(args, "aliases", None) or {}

    def local_path(root: str, rel_path: str) -> str:
        return join_root(path_map.get(root) or source_path(root, aliases), rel_path)

    last = [0.0]

    def progress(n: int, total: int) -> None:
        if time.monotonic() - last[0] >= 5 or n == total:
            last[0] = time.monotonic()
            print(f"dupes: read {n}/{total} files", file=sys.stderr)

    try:
        floors = sorted({int(float(b) * 1024 * MiB) for b in args.bands.split(",")}, reverse=True)
    except ValueError:
        print(f"filecat dupes: --bands wants GiB numbers like 100,50,20,10,1, got {args.bands!r}",
              file=sys.stderr)
        return 2
    started = time.monotonic()
    total = wasted = bad = 0
    with open_backend(args.backend, args.out, args.dsn) as backend:
        # one band at a time, largest first: files of one size share a band
        for i, floor in enumerate(floors):
            ceiling = floors[i - 1] if i else None
            label = (f"{_human_bytes(floor)} < size" if ceiling is None else
                     f"{_human_bytes(floor)} < size <= {_human_bytes(ceiling)}")
            docs = (d for r in args.root for d in backend.list_sized(floor, ceiling, root=r)) \
                if args.root else backend.list_sized(floor, ceiling)
            clusters, errors = find_duplicates(
                docs, local_path, min_size=floor + 1, samples=args.samples,
                window=int(args.window * MiB), full=args.full, full_max=int(args.full_max * MiB),
                workers=args.workers, progress=progress,
                include_backups=getattr(args, "include_backups", False))
            total += len(clusters)
            wasted += sum(c["wasted_bytes"] for c in clusters)
            bad += len(errors)
            if not args.json:
                print(f"== {label}: {len(clusters)} clusters")
            for c in clusters[:args.top] if args.top else clusters:
                if args.dissect and c["confirmed"] != "full":
                    _compare_images(args.dissect, c, local_path)
                if args.json:
                    print(json.dumps({**c, "band": label}, ensure_ascii=False))
                    continue
                print(f"{_human_bytes(c['size']):>10}  x{c['copies']}  wasted "
                      f"{_human_bytes(c['wasted_bytes'])}  [{c['confirmed']}]")
                for p in c["paths"]:
                    print(f"    {p['root']}  {p['rel_path']}" + (f"  [backup: {p['backup']}]" if p.get("backup") else ""))
                if "listing" in c:
                    print(f"    file listings: {c['listing']}")
            for e in errors[:20]:
                print(f"dupes: {e}", file=sys.stderr)
            sys.stdout.flush()
    print(f"dupes: {total} clusters, {_human_bytes(wasted)} wasted, {bad} unreadable, "
          f"in {time.monotonic() - started:.1f}s", file=sys.stderr)
    return 0
