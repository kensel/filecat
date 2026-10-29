"""`filecat summaries`: the stored summary of each root, for the web viewer's Roots, Summary and Graph pages.

One pass over a root's records (refresh) feeds both the aggregates behind the Summary page
(aggregate.Aggregator: totals, by extension, by type, by folder) and the treemap behind the Graph
page (treemap.build over the whole root, rollups included), both at DEPTH folders. They are stored
with the same `built_at`, taken before the first record is read, so a record written during the
pass makes the summary look stale rather than slip in unnoticed.

A stored summary is judged by the root, not by its age: it is fresh while it was built after the
root's change stamp (rootinfo.changed_stamp: the last scan that wrote or removed a file, or any
other writer that called rootinfo.touch). `--graph-max-age` plays no part in this; it only decides
how long a deeper or narrower treemap, built on demand, is reused.

    fresh      built after the last change
    stale      the root changed after it was built
    scanning   a scan is walking the root now; what is stored is served, marked stale, and rebuilt
               when the scan ends (scan.py), not while it writes
    missing    nothing stored at DEPTH yet

    filecat summaries [refresh] [--root R ...] [--all | --stale]    build them (default: the stale ones)
    filecat summaries status [--root R ...] [--json]                what is stored and how old
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable

from . import rootinfo, treemap
from .aggregate import Aggregator
from .backends import open_backend
from .backends.base import Backend, Document
from .browse import is_unreadable
from .record import NON_FILE_KINDS

DEPTH = 2           # the depth every root is summarised at; deeper views are built on demand
CHECK_EVERY = 20000  # records between looks at the cancel flag


class Cancelled(KeyboardInterrupt):
    """The caller's cancel flag was set during a pass (a KeyboardInterrupt, as scan.ScanCancelled is,
    so the server records the job as cancelled)."""


def state_of(info: Document | None, built_at: str | None) -> str:
    """fresh | stale | scanning | missing for a summary built at `built_at` of the root with this index entry."""
    if built_at is None:
        return "missing"
    if rootinfo.state(info) == "in_progress":
        return "scanning"
    built, changed = rootinfo.parse(built_at), rootinfo.changed_stamp(info)
    # a build stamped the same instant as a change may have missed it (Windows' clock ticks in ms)
    return "stale" if built is None or (changed is not None and built <= changed) else "fresh"


def needs_refresh(state: str) -> bool:
    """A scan in progress is rebuilt when it ends; the other two now."""
    return state in ("missing", "stale")


def status(backend: Backend, root: str, info: Document | None = None, totals: Document | None = None) -> dict[str, Any]:
    """What is stored for `root` and whether it is current. `info` and `totals` (the root index
    entry and Backend.stored_totals()[root]) are read when not given. `state` goes by the older of
    the two builds, and is "missing" when one is not there (a backend that stores no treemaps has
    only the aggregates to go by)."""
    if info is None:
        try:
            info = backend.get_root_info(root)
        except NotImplementedError:
            info = None
    if totals is None:
        totals = backend.stored_totals(root).get(root)
    agg_at = totals["built_at"] if totals and totals.get("depth") == DEPTH else None
    try:
        meta = treemap.newest(backend.list_treemaps(root), "", DEPTH)
        builds = [agg_at, meta["built_at"] if meta else None]
    except NotImplementedError:
        meta, builds = None, [agg_at]
    oldest = None if None in builds else min(builds)
    return {"root": root, "state": state_of(info, oldest), "aggregates_at": agg_at,
            "treemap_at": meta["built_at"] if meta else None, "treemap_id": meta["id"] if meta else None,
            "changed_at": _iso(rootinfo.changed_stamp(info)), "scanning": rootinfo.state(info) == "in_progress"}


def _iso(at: datetime | None) -> str | None:
    return at.isoformat() if at else None


def is_fresh(backend: Backend, root: str) -> bool:
    return status(backend, root)["state"] == "fresh"


def _after_change(backend: Backend, root: str) -> str:
    """Now, once the clock has moved past the root's change stamp: a pass that begins after a
    change is stamped later than it, even where the clock is coarse."""
    try:
        changed = rootinfo.changed_stamp(backend.get_root_info(root))
    except NotImplementedError:
        changed = None
    at = datetime.now(timezone.utc)
    for _ in range(100):
        if changed is None or at > changed:
            break
        time.sleep(0.001)
        at = datetime.now(timezone.utc)
    return at.isoformat()


def refresh(backend: Backend, root: str, *, cancel: Callable[[], bool] | None = None,
            depth: int = DEPTH) -> dict[str, Any]:
    """Read the records of `root` once and store the aggregates and the treemap of its top, both
    built_at the moment the pass began. Raises NotImplementedError when the backend stores neither."""
    began = time.monotonic()
    built_at = _after_change(backend, root)
    backend.flush()
    agg = Aggregator(depth)
    seen = 0

    def rows() -> Any:
        nonlocal seen
        for doc in backend.summary_docs(root):
            seen += 1
            if cancel is not None and seen % CHECK_EVERY == 0 and cancel():
                raise Cancelled()
            agg.add({**doc, "root": root})
            rel = doc.get("rel_path")
            if rel and doc.get("kind") not in NON_FILE_KINDS and not is_unreadable(doc):
                yield (rel, doc.get("size") or 0, doc.get("suffix") or "",
                       doc.get("mime") or doc.get("kind") or "unknown")

    data = treemap.build(rows(), "", depth, rollups=backend.rollups(root, ""))
    stored = []
    try:
        meta = treemap.save(backend, root, data, built_at)
        stored.append("treemap")
    except NotImplementedError:
        meta = None
    try:
        backend.replace_aggregates({root: agg.entry(root)}, depth, built_at, root)
        stored.append("aggregates")
    except NotImplementedError:
        if not stored:
            raise
    return {"root": root, "built_at": built_at, "files": data["files"], "bytes": data["bytes"],
            "seconds": round(time.monotonic() - began, 1), "stored": stored,
            "treemap_id": meta["id"] if meta else None}


def after_scan(backend: Backend, root: str, cancel: Callable[[], bool] | None = None) -> bool:
    """Called when a scan of `root` has finished: build its summaries unless they are still current
    (a scan that found nothing to write leaves the root as it was). A catalog that cannot hold the
    stored summaries gets the aggregates rebuilt in the way it always has. True when it built."""
    try:
        if not needs_refresh(status(backend, root)["state"]):
            return False
        refresh(backend, root, cancel=cancel)
    except NotImplementedError:
        backend.rebuild_aggregates(root=root)
    return True


def candidates(backend: Backend) -> list[dict[str, Any]]:
    """The status of every root the catalog knows: the root index, the stored summaries, and the
    roots the records name. For the CLI and the server job, which can afford the distinct."""
    try:
        infos = {i["root"]: i for i in backend.list_root_info()}
    except NotImplementedError:
        infos = {}
    totals = backend.stored_totals()
    roots = sorted(set(infos) | set(totals) | set(backend.roots()))
    return [status(backend, r, infos.get(r), totals.get(r)) for r in roots]


def refresh_stale(backend: Backend, roots: list[str] | None = None, *, force: bool = False,
                  cancel: Callable[[], bool] | None = None,
                  log: Callable[[str], None] | None = None) -> dict[str, int]:
    """refresh() the roots (default: every one) whose summaries need it, or all of them with
    `force`. Returns {"roots", "refreshed", "skipped", "failed"}."""
    rows = candidates(backend)
    wanted = {r.lower() for r in roots} if roots else None
    counts = {"roots": 0, "refreshed": 0, "skipped": 0, "failed": 0}
    for row in rows:
        if wanted is not None and row["root"].lower() not in wanted:
            continue
        counts["roots"] += 1
        if not force and not needs_refresh(row["state"]):
            counts["skipped"] += 1
            continue
        if cancel is not None and cancel():
            raise Cancelled()
        try:
            done = refresh(backend, row["root"], cancel=cancel)
        except (NotImplementedError, Cancelled):
            raise
        except Exception as exc:        # one bad root must not stop the rest
            counts["failed"] += 1
            if log:
                log(f"{row['root']}: {type(exc).__name__}: {exc}")
            continue
        counts["refreshed"] += 1
        if log:
            log(f"{row['root']}: {done['files']:,} files, {done['bytes']:,} bytes in {done['seconds']}s")
    return counts


# --- the command -----------------------------------------------------------------------------------
def run(args: Any) -> int:
    backend = open_backend(args.backend, getattr(args, "out", None), getattr(args, "dsn", None))
    try:
        roots = args.root or None
        if args.action == "status":
            rows = [r for r in candidates(backend) if not roots or r["root"] in roots]
            if args.json:
                for r in rows:
                    print(json.dumps(r))
                return 0
            for r in rows:
                built = r["aggregates_at"] or "-"
                print(f"{r['state']:9} {r['root']}  built {built}  changed {r['changed_at'] or '-'}")
            return 0
        if args.all and args.stale:
            print("filecat summaries: --all and --stale exclude each other", file=sys.stderr)
            return 2
        # named roots are rebuilt whatever their state; with none named, the stale ones (or all of them)
        force = args.all or bool(roots and not args.stale)
        try:
            counts = refresh_stale(backend, roots, force=force, log=print)
        except NotImplementedError:
            print(f"filecat summaries: the {backend.name} backend does not store summaries", file=sys.stderr)
            return 2
        print(f"{counts['refreshed']} of {counts['roots']} roots refreshed, {counts['skipped']} already current"
              + (f", {counts['failed']} failed" if counts["failed"] else ""))
        return 1 if counts["failed"] else 0
    finally:
        backend.close()
