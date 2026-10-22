"""Archive members filed by the archive's content hash. See docs/members.md.

An archive present in four places used to store its member rows four times,
under each copy's (root, rel_path), and moving or renaming it orphaned
them. A backend with `stores_member_sets` keeps them once per content hash
(the archive's `sha256`, or `sha256_partial` above 64 MiB) as a member set:

    header {"members_id": <hex digest>, "hash_type": "sha256" | "sha256_partial",
            "count": <rows>, "digest": <sha256 of the rows>}
    rows   {"members_id": ..., "index": 0, "path": "...", ...}

and the archive's record names it with `members_id`. An archive without a
hash keeps its rows under its path, as before.

store_rows()  -- file one archive's rows as a set (Backend.store calls it)
migrate()     -- move the path-keyed rows of existing records into sets,
                 batched and resumable; trims compound documents listed
                 before v0.1.1 to their anomalies on the way;
                 `filecat member-sets migrate`
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable

from . import rootinfo
from .backends.base import Backend, Document
from .options import ScanOptions
from .probe import compound, members as member_probe
from .samples import _load_checkpoint, _save_checkpoint, catalog_tag, checkpoint_path_for, key_of

# Keys a backend adds to the rows it stores; never part of a set's digest.
IDENTITY_KEYS = ("root_id", "root", "archive_rel_path", "members_id")
# Probe keys members.summarize() writes.
SUMMARY_KEYS = ("members_count", "member_roles", "entries", "members_size", "members_truncated")
CHECKPOINT_VERSION = 1


def clean_rows(rows: Iterable[Document]) -> list[Document]:
    """Rows without the keys a backend added, each with its index."""
    out = []
    for i, r in enumerate(rows):
        row = {k: v for k, v in r.items() if k not in IDENTITY_KEYS}
        row.setdefault("index", i)
        out.append(row)
    return out


def digest(rows: list[Document]) -> str:
    h = hashlib.sha256()
    for r in rows:
        h.update(json.dumps(r, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def header_for(key: tuple[str, str], rows: list[Document]) -> Document:
    return {"members_id": key[0], "hash_type": key[1], "count": len(rows), "digest": digest(rows)}


def store_rows(backend: Backend, doc: Document, rows: list[Document]) -> bool:
    """File `rows` as the member set of `doc` and name it on the record.
    False, with `doc` untouched, when there are no rows or no hash."""
    key = key_of(doc)
    if key is None or not rows:
        return False
    clean = clean_rows(rows)
    backend.put_member_set(header_for(key, clean), clean)
    doc["members_id"] = key[0]
    return True


def trim_compound(doc: Document, rows: list[Document], expand: bool = False) -> tuple[list[Document], bool]:
    """(rows, trimmed). A compound document (.docx, .jar, .epub...) listed
    before v0.1.1 has every entry stored; keep only what v0.1.1 keeps (its
    anomalies) and give the record the probe.compound summary a scan would.
    Records that already have probe.compound are left as they are."""
    probe = doc.get("probe") or {}
    container = {"zip": "zip", "gzip": "gzip", "gzip_xored": "gzip"}.get(doc.get("container") or "")
    if expand or "compound" in probe or container is None:
        return rows, False
    name = doc.get("name") or doc["rel_path"].rsplit("/", 1)[-1]
    paths = [r.get("path") or "" for r in rows] if container == "zip" else None
    fmt = compound.for_file(name, container, paths)
    if fmt is None:
        return rows, False
    probe = doc.setdefault("probe", {})
    for k in SUMMARY_KEYS:
        probe.pop(k, None)
    if container == "zip":
        kept, probe["compound"] = compound.filter_members(fmt, name, rows)
        doc["kind"] = fmt.kind or "archive"
        probe.update(member_probe.summarize(kept, truncated=False, list_cap=ScanOptions().list_zip_cap))
    else:
        kept = []       # a gzip compound document is no longer listed as a tarball
        probe["compound"] = {"format": fmt.id}
        if fmt.mime_for(name):
            probe["compound"]["mime"] = fmt.mime_for(name)
    return kept, True


# --- migration ------------------------------------------------------------

@dataclass
class MigrateStats:
    scanned: int = 0        # records read
    archives: int = 0       # records with member rows under their path
    moved: int = 0          # archives whose rows now live in a member set
    sets: int = 0           # sets written (a copy of a filed archive writes none)
    rows_read: int = 0      # path-keyed rows read
    rows_written: int = 0   # rows written to sets, or kept under a path
    compound: int = 0       # compound documents trimmed to their anomalies
    no_hash: int = 0        # archives without a hash: rows stay under the path
    batches: int = 0
    resumed_from: Any = None
    done: bool = False


_COUNTERS = ("scanned", "archives", "moved", "sets", "rows_read", "rows_written", "compound",
             "no_hash", "batches")


def migrate(backend: Backend, checkpoint: str, *, tag: str = "", batch: int = 1000,
            limit: int | None = None, expand_compound: bool = False,
            progress: Callable[[MigrateStats], None] | None = None) -> MigrateStats:
    """Move the path-keyed member rows of existing records into member sets.

    Crash-safe at every point. Per batch of records (in page_records order):
      1. the member sets are written, each committed with its header last;
         the trimmed rows of an archive without a hash are rewritten;
      2. the records are rewritten naming their sets, and flushed;
      3. the path-keyed rows of those records are deleted;
      4. the checkpoint is saved (temporary file, then renamed).
    A crash before 2 leaves sets nobody names yet; a crash during 2 or 3
    leaves records that name a set and still have path rows, which a rerun
    of the batch deletes. Without the checkpoint a rerun starts over and is
    still correct, only slower. `limit` stops after that many records.
    """
    if not backend.stores_member_sets:
        raise NotImplementedError(f"{backend.name} backend keeps members under each archive's path")
    stats = MigrateStats()
    state = _load_checkpoint(checkpoint, tag)
    after = None
    if state is not None:
        after = state["after"]
        stats.resumed_from = after
        for k in _COUNTERS:
            setattr(stats, k, state.get(k, 0))
    started_scanned = stats.scanned
    while True:
        size = batch if limit is None else min(batch, limit - (stats.scanned - started_scanned))
        if size <= 0:
            break
        docs, cursor = backend.page_records(after, size)
        if not docs:
            stats.done = True
            break
        changed: list[Document] = []        # records to rewrite
        drop_rows: list[Document] = []      # records whose path rows go
        for doc in docs:
            stats.scanned += 1
            if not (doc.get("probe") or {}).get("members_count"):
                continue
            if doc.get("members_id"):
                drop_rows.append(doc)       # left behind by an interrupted run, if any
                continue
            rows = clean_rows(backend.list_members(doc["root"], doc["rel_path"]))
            if not rows:
                continue
            stats.archives += 1
            stats.rows_read += len(rows)
            kept, trimmed = trim_compound(doc, rows, expand_compound)
            stats.compound += trimmed
            key = key_of(doc)
            if key is not None and kept:
                if backend.put_member_set(header_for(key, kept), kept):
                    stats.sets += 1
                    stats.rows_written += len(kept)
                doc["members_id"] = key[0]
                stats.moved += 1
                changed.append(doc)
                drop_rows.append(doc)
            elif trimmed:
                # Rows before the record: a crash in between leaves trimmed
                # rows, which trimming again keeps as they are.
                backend.put_members(doc["root"], doc["rel_path"], kept)
                stats.rows_written += len(kept)
                changed.append(doc)
            else:
                stats.no_hash += 1
                stats.rows_written += len(rows)
        for doc in changed:
            backend.put(doc)
        backend.flush()
        for doc in drop_rows:
            backend.delete_members(doc["root"], doc["rel_path"])
        stats.batches += 1
        after = cursor
        _save_checkpoint(checkpoint, {"version": CHECKPOINT_VERSION, "catalog": tag, "after": after,
                                      **{k: v for k, v in asdict(stats).items() if k in _COUNTERS}})
        if progress is not None:
            progress(stats)
    if stats.done:
        try:
            os.remove(checkpoint)
        except OSError:
            pass
    return stats


# --- prune (shared with `filecat samples prune`) ------------------------------

def prune(backend: Backend, what: str, remove: Callable[[], int], force: bool) -> int:
    """Run one prune, unless a scan is writing to the catalog: a scan files
    a sample or member set a moment before the record that names it."""
    busy = rootinfo.in_progress(backend)
    if busy and not force:
        print(f"filecat: a scan is running on {', '.join(busy)}; prune {what} when it has finished "
              "(--force to prune anyway)", file=sys.stderr)
        return 1
    removed = remove()
    print(f"{removed} {what} no record names any more removed")
    return 0


# --- command ----------------------------------------------------------------

def run(args: Any) -> int:
    from .backends import open_backend
    catalog = args.out if args.backend in ("sqlite", "jsonl", "jsonl_dir") else None
    with open_backend(args.backend, args.out, args.dsn) as backend:
        if args.action == "stats":
            return _stats(backend)
        if not backend.stores_member_sets:
            print(f"filecat member-sets: the {backend.name} backend keeps members under each "
                  "archive's path; nothing to do", file=sys.stderr)
            return 2
        if args.action == "prune":
            return prune(backend, "member sets", backend.prune_member_sets, args.force)
        path = args.checkpoint or checkpoint_path_for(backend.name, catalog, "members")
        tag = catalog_tag(backend.name, args.out or args.dsn)
        last = [time.monotonic()]
        started = time.monotonic()

        def progress(s: MigrateStats) -> None:
            now = time.monotonic()
            if now - last[0] >= args.progress_interval:
                last[0] = now
                print(f"member-sets: {s.scanned} records read, {s.moved} archives moved, "
                      f"{s.rows_read} rows read, {s.rows_written} kept ({now - started:.0f}s)",
                      file=sys.stderr, flush=True)

        try:
            stats = migrate(backend, path, tag=tag, batch=args.batch, limit=args.limit,
                            expand_compound=args.expand_compound, progress=progress)
        except KeyboardInterrupt:
            print(f"member-sets: interrupted; run it again to continue from {path}", file=sys.stderr)
            return 130
    resumed = ", resumed from a checkpoint" if stats.resumed_from is not None else ""
    print(f"member-sets: {stats.scanned} records read, {stats.archives} archives with member rows; "
          f"{stats.moved} moved into member sets ({stats.sets} sets written), "
          f"{stats.compound} compound documents trimmed, {stats.no_hash} kept under their path "
          f"(no hash); {stats.rows_read} rows became {stats.rows_written}{resumed}")
    if not stats.done:
        print(f"member-sets: stopped at --limit; run it again to continue ({path})")
    return 0


def _stats(backend: Backend) -> int:
    if not backend.stores_member_sets:
        print(f"{backend.name}: members are kept under each archive's path")
        return 0
    sets = rows = 0
    for h in backend.iter_member_sets():
        sets += 1
        rows += h.get("count") or 0
    print(f"{sets} member sets, {rows} rows")
    return 0
