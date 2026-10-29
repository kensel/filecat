"""filecat enrich: fill in what an import (or an older scan) left out.

Imported listings carry identity, size and times but no hash, no probed kind
and no type. This command finds those records and measures them in place:

* names    -- glob table lookup (mime_glob, mime_glob_desc, mime). No file I/O.
* hash / probe / identify -- open the file and run the same measurement as
  `filecat scan` (scan.measure_file). Needs the root to be reachable, either
  at its recorded path, through --path-map ROOT=LOCAL, or through the
  scan's alias (--alias / [aliases], applied in reverse; see aliases.py).

A file whose current size or mtime differs from the record is remeasured in
full; the record then reflects the file as it is now.

Data files of recognised backup stores (probe.backup_data: ABB pools,
Hyper Backup buckets, Veeam chunks ...) are left unread, as a scan leaves
them, unless --measure-backups; --force does not override that.

Database data files (probe.db_data, see dbfiles/) are measured only once
they are quiet and big enough, checked against the record and again
against the file just before it is read; --force does not override that.

Rollups (kind "rollup", docs/rollups.md) stand for files the catalog does not
list: nothing is opened for one, whatever --force, --what or --measure-backups say.

Cloud placeholders (see cloudfiles.py) whose data is not on this device
are left unread, whatever the record says: their attributes are checked
without opening the file. --hydrate reads them anyway, which makes the
provider download each one, so narrow it with --root, --path, --kind and
--limit; --free-after marks each downloaded file "Free up space" again.
"""
from __future__ import annotations

import fnmatch
import os
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Iterator

from . import cloudfiles, dbfiles, rootinfo, summaries
from .backends import open_backend
from .backends.base import Backend
from .options import ScanOptions
from .aliases import source_path
from .record import MEMBERS_KEY, NON_FILE_KINDS, add_error, is_file_kind, join_root
from .samples import key_of

STAGES = ("names", "hash", "probe", "identify")
NO_CONTENT_KINDS = ("dir", "link", "empty", "rollup")
# Fields from an import that a measurement does not produce and must not drop.
KEEP_TOP = ("source", "llm")
KEEP_PROBE = ("attributes", "readonly", "atime_ns", "installed_program", "db_data", "backup_data")


@dataclass
class EnrichStats:
    seen: int = 0
    named: int = 0
    measured: int = 0
    changed_on_disk: int = 0
    missing: int = 0
    db_active: int = 0          # database files that turned out not to be quiet when read
    cloud_only: int = 0         # cloud placeholders left unread (no --hydrate)
    downloaded: int = 0         # cloud placeholders read with --hydrate
    downloaded_bytes: int = 0
    freed: int = 0              # of those, handed back to the provider (--free-after)
    errors: int = 0
    skipped_roots: dict[str, str] = field(default_factory=dict)


def parse_path_map(items: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        root, sep, local = item.partition("=")
        if not sep or not root or not local:
            raise ValueError(f"--path-map wants ROOT=LOCAL, got {item!r}")
        out[root] = local
    return out


def needs(doc: dict[str, Any], stages: set[str], options: ScanOptions,
          force: bool) -> tuple[bool, bool]:
    """(needs_names, needs_measure) for one record."""
    probe = doc.get("probe") or {}
    kind = doc.get("kind")
    want_names = "names" in stages and (force or "mime_glob" not in probe) and kind not in NON_FILE_KINDS
    if kind in NO_CONTENT_KINDS or not doc.get("size"):
        return want_names, False
    if probe.get("backup_data") and not options.measure_backups:
        return want_names, False    # listed-only backup data, as the scan left it
    db_engine = probe.get("db_data")
    if db_engine and "sha256" not in doc and "sha256_partial" not in doc:
        # listed only so far: read it once it is quiet, whatever --force says
        eng = dbfiles.engine(db_engine)
        quiet = eng is not None and eng.eligible(doc.get("size"), doc.get("mtime_ns"))
        return want_names, quiet and bool(stages & {"hash", "probe", "identify"})
    want_probe = "probe" in stages and "container" not in doc
    want_hash = ("hash" in stages and options.hash != "none"
                 and "sha256" not in doc and "sha256_partial" not in doc)
    want_identify = ("identify" in stages and options.identify_bytes_for(doc["root"])
                     and "mime_magic" not in probe and "identify_basis" not in probe)
    return want_names, force or want_probe or want_hash or want_identify


def apply_names(doc: dict[str, Any], identifier: Any) -> None:
    result = identifier.by_name(doc["name"], doc.get("size"),
                                (doc.get("probe") or {}).get("format"))
    if not result:
        return
    probe = doc.setdefault("probe", {})
    probe.update(result)
    if "mime" not in doc and result.get("mime_glob"):
        doc["mime"] = result["mime_glob"]
    probe.setdefault("identify_basis", "name")


def merge_measured(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Measured document wins; carry over import-only facts."""
    for key in KEEP_TOP:
        if key in old and key not in new:
            new[key] = old[key]
    old_probe = old.get("probe") or {}
    carried = {k: old_probe[k] for k in KEEP_PROBE if k in old_probe}
    if carried:
        probe = new.setdefault("probe", {})
        for k, v in carried.items():
            probe.setdefault(k, v)
    # A member set stays named until a new listing of the archive replaces
    # it, unless the content changed.
    if old.get("members_id") and MEMBERS_KEY not in new:
        key = key_of(new)
        if key is None or key[0] == old["members_id"]:
            new["members_id"] = old["members_id"]
    return new


def path_matches(rel_path: str, patterns: list[str]) -> bool:
    """--path: a glob on the record's rel_path ('/'-separated, any case);
    a pattern without wildcards selects that file or everything under it."""
    low = rel_path.lower()
    for p in patterns:
        p = p.replace("\\", "/").strip("/").lower()
        if any(c in p for c in "*?["):
            if fnmatch.fnmatchcase(low, p):
                return True
        elif low == p or low.startswith(p + "/"):
            return True
    return False


def _candidates(backend: Backend, roots: list[str] | None, kinds: list[str] | None,
                paths: list[str] | None = None) -> Iterator[tuple[str, str]]:
    """Keys first, so writes never interleave with an open listing cursor."""
    keys: list[tuple[str, str]] = []
    for root in roots or [None]:
        for kind in kinds or [None]:
            for doc in backend.list(kind=kind, root=root):
                if is_file_kind(doc.get("kind")) and (not paths or path_matches(doc["rel_path"], paths)):
                    keys.append((doc["root"], doc["rel_path"]))
    keys.sort()
    yield from keys


def enrich(backend: Backend, options: ScanOptions, *, stages: set[str],
           roots: list[str] | None = None, kinds: list[str] | None = None,
           path_map: dict[str, str] | None = None, limit: int | None = None,
           force: bool = False, identifier: Any = None, paths: list[str] | None = None,
           hydrate: bool = False, free_after: bool = False) -> EnrichStats:
    from .identify import Identifier
    from .scan import measure_file

    path_map = path_map or {}
    identifier = identifier or Identifier(options)
    measure_options = ScanOptions(**{**options.__dict__})
    if "hash" not in stages:
        measure_options.hash = "none"
    if "identify" not in stages:
        measure_options.identify = "never"

    stats = EnrichStats()
    root_ok: dict[str, bool] = {}
    pending: list[tuple[dict[str, Any], Future]] = []
    last_progress = time.monotonic()

    def local_root(root: str) -> str:
        return path_map.get(root) or source_path(root, options.aliases)

    def reachable(root: str) -> bool:
        if root not in root_ok:
            local = local_root(root)
            try:
                os.stat(local)
                root_ok[root] = True
            except OSError as exc:
                root_ok[root] = False
                stats.skipped_roots[root] = f"{local}: {exc}"
        return root_ok[root]

    def job(doc: dict[str, Any], named: bool) -> dict[str, Any] | None:
        """The measured record, or None to leave the stored one as it is."""
        abs_path = join_root(local_root(doc["root"]), doc["rel_path"])
        # attributes first, without opening the file: a cloud placeholder
        # is downloaded by reading it, and some by opening it at all
        attrs = cloudfiles.file_attributes(abs_path)
        if attrs is not None and cloudfiles.not_local(attrs) and not hydrate:
            stats.cloud_only += 1
            return doc if named else None
        try:
            st = os.stat(abs_path)
        except FileNotFoundError as exc:
            stats.missing += 1
            add_error(doc, "enrich", exc)
            return doc
        except OSError as exc:
            add_error(doc, "stat", exc)
            return doc
        eng = dbfiles.engine((doc.get("probe") or {}).get("db_data"))
        if eng is not None and not eng.eligible(st.st_size, st.st_mtime_ns):
            stats.db_active += 1    # written to since it was listed: leave it for later
            return doc if named else None
        if st.st_size != doc.get("size") or st.st_mtime_ns != doc.get("mtime_ns", st.st_mtime_ns):
            stats.changed_on_disk += 1
        new = measure_file(doc["root"], doc["rel_path"], abs_path, st, measure_options, identifier)
        stats.measured += 1
        new = merge_measured(doc, new)
        if attrs is not None:
            if cloudfiles.not_local(attrs):
                stats.downloaded += 1
                stats.downloaded_bytes += st.st_size
            freed = cloudfiles.not_local(attrs) and free_after and cloudfiles.free_up(abs_path)
            stats.freed += bool(freed)
            cloud = cloudfiles.describe(abs_path, cloudfiles.file_attributes(abs_path) or 0)
            if cloud is not None:
                if freed:
                    cloud["freed"] = True       # handed back; the provider drops it soon
                new.setdefault("probe", {})["cloud"] = cloud
        return dbfiles.settle_in_use(new) if eng is not None else new

    def drain(block: bool) -> None:
        nonlocal pending
        keep = []
        for doc, fut in pending:
            if not block and not fut.done():
                keep.append((doc, fut))
                continue
            # a download (--hydrate) takes as long as it takes, unless --timeout says otherwise
            timeout = options.timeout if hydrate else options.timeout_for(doc["root"])
            try:
                new = fut.result(timeout=timeout)
            except Exception as exc:  # timeout or a bug in a measurement
                add_error(doc, "enrich", exc)
                new = doc
            if new is None:
                continue
            if new.get("errors"):
                stats.errors += 1
            backend.store(new)
        pending = keep

    with ThreadPoolExecutor(max_workers=max(1, options.workers)) as pool:
        for root, rel_path in _candidates(backend, roots, kinds, paths):
            if limit is not None and stats.seen >= limit:
                break
            doc = backend.get(root, rel_path)
            if doc is None:
                continue
            want_names, want_measure = needs(doc, stages, options, force)
            if not (want_names or want_measure):
                continue
            stats.seen += 1
            if want_names:
                apply_names(doc, identifier)
                stats.named += 1
            if want_measure and reachable(root):
                pending.append((doc, pool.submit(job, doc, want_names)))
                if len(pending) >= options.workers * 4:
                    drain(block=False)
                    if len(pending) >= options.workers * 8:
                        drain(block=True)
            else:
                backend.put(doc)
            now = time.monotonic()
            if now - last_progress >= options.progress_interval:
                last_progress = now
                print(f"enrich: {stats.seen} records, {stats.measured} measured, "
                      f"last {root}/{rel_path}", file=sys.stderr, flush=True)
        drain(block=True)

    identifier.close()
    backend.flush()
    return stats


def run(args) -> int:
    options = ScanOptions.from_args(args)
    stages = {s.strip() for s in args.what.split(",") if s.strip()}
    unknown = stages - set(STAGES)
    if unknown:
        print(f"filecat enrich: unknown --what stage(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    if args.free_after and not args.hydrate:
        print("filecat enrich: --free-after goes with --hydrate", file=sys.stderr)
        return 2
    try:
        path_map = parse_path_map(args.path_map)
    except ValueError as exc:
        print(f"filecat enrich: {exc}", file=sys.stderr)
        return 2
    started = time.monotonic()
    with open_backend(args.backend, args.out, args.dsn) as backend:
        stats = enrich(backend, options, stages=stages, roots=args.root, kinds=args.kind,
                       path_map=path_map, limit=args.limit, force=args.force, paths=args.path,
                       hydrate=args.hydrate, free_after=args.free_after)
        if stats.seen:
            try:
                for root in args.root or backend.roots():
                    rootinfo.touch(backend, root)       # sizes, types or hashes changed: stale summaries
                    summaries.after_scan(backend, root)
            except NotImplementedError:
                pass
    print(f"enrich: {stats.seen} records selected ({stats.named} named, {stats.measured} measured, "
          f"{stats.changed_on_disk} changed on disk, {stats.missing} missing, "
          f"{stats.errors} with errors) in {time.monotonic() - started:.1f}s")
    if stats.db_active:
        print(f"enrich: {stats.db_active} database files left unread: modified since they were listed")
    if stats.cloud_only:
        print(f"enrich: {stats.cloud_only} cloud-only files left unread (not on this device; "
              "--hydrate downloads them, --path narrows which)")
    if stats.downloaded:
        freed = f", {stats.freed} handed back to the provider" if args.free_after else \
            " (still on this device; --free-after hands them back)"
        print(f"enrich: {stats.downloaded} cloud files downloaded, "
              f"{stats.downloaded_bytes / 1e6:.1f} MB{freed}")
    for root, why in stats.skipped_roots.items():
        print(f"enrich: root not reachable, skipped: {root} ({why})")
    return 1 if stats.errors else 0
