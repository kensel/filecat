"""filecat migrate: copy a catalog from one backend to another.

Streams documents from the source (`Backend.list(root=...)`) into the target
with `put_many`, then installed-programs records (`list_programs` ->
`put_program`), then archive members (`iter_all_members`, grouped back into
one `put_members` call per archive) -- a source backend that predates
member storage raises `NotImplementedError` from `iter_all_members()`; that
is treated as "nothing to migrate there", not an error. The target's
aggregates are rebuilt once at the end with `rebuild_aggregates()`.

Text samples (filecat/samples.py) follow the target: when both backends
have a samples store, the sample documents are copied first; when only the
target has one, inline samples are split off on the way in; when only the
source has one, each record gets its sample back inline.

Member sets (filecat/member_sets.py) follow the target the same way: copied
set by set after the records when both backends store them, written out
under each archive's path when only the source does, and filed by hash when
only the target does.

Public API:
    migrate(src, dst, *, roots=None, batch=2000, programs=True, members=True,
            verify=False, progress=None) -> MigrateStats
    run(args) -> int
"""
from __future__ import annotations

import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from . import member_sets, samples
from .backends import open_backend
from .backends.base import Backend, Document

ProgressFn = Callable[["MigrateStats"], None]

# Keys put_members() itself adds back onto each member row; stripped before
# handing the group to the target's put_members() so it can add them again
# (possibly under a different root_id, if the target hashes roots the same
# way -- it does, root_id is a pure function of the root string).
_MEMBER_IDENTITY_KEYS = ("root_id", "root", "archive_rel_path")


@dataclass
class MigrateStats:
    documents: int = 0
    programs: int = 0
    root_infos: int = 0
    dropped: int = 0
    members_archives: int = 0
    members_rows: int = 0
    members_skipped: bool = False
    member_sets: int = 0
    samples: int = 0
    verify_checked: int = 0
    verify_mismatches: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.verify_mismatches and not self.errors


def _backend_identity(b: Backend) -> tuple[str, str] | None:
    """A value that is equal for two Backend objects addressing the same
    underlying storage: the same jsonl/sqlite file path, or the same DSN
    string for a server backend. None when nothing comparable is known."""
    path = getattr(b, "path", None)
    if path is not None:
        try:
            return ("path", os.path.normcase(os.path.abspath(str(path))))
        except OSError:
            return ("path", str(path))
    dsn = getattr(b, "dsn", None)
    if dsn:
        return ("dsn", dsn)
    return None


def _same_target(src: Backend, dst: Backend) -> bool:
    a, b = _backend_identity(src), _backend_identity(dst)
    return a is not None and a == b


def _readable(backend: Backend, doc: Document) -> Document:
    """A record as a reader sees it, wherever its sample is kept."""
    out = samples.attach(backend, [doc])[0]
    out.pop("sample_id", None)
    out.pop("members_id", None)
    return out


def migrate(src: Backend, dst: Backend, *, roots: list[str] | None = None,
            batch: int = 2000, programs: bool = True, members: bool = True,
            verify: bool = False, progress: ProgressFn | None = None) -> MigrateStats:
    """Copy src's catalog into dst. Raises ValueError when src and dst
    address the same file/DSN."""
    if _same_target(src, dst):
        raise ValueError("source and target are the same backend file/DSN")

    stats = MigrateStats()
    start = time.monotonic()
    last_progress = start

    def maybe_progress(force: bool = False) -> None:
        nonlocal last_progress
        if progress is None:
            return
        now = time.monotonic()
        if force or now - last_progress >= 3.0:
            last_progress = now
            stats.elapsed = now - start
            progress(stats)

    root_list = roots if roots else [None]

    # --- samples, before the records that name them ---------------------
    if src.stores_samples and dst.stores_samples:
        chunk: list[Document] = []
        for s in src.iter_samples():
            chunk.append(s)
            if len(chunk) >= batch:
                dst.add_samples(chunk)
                stats.samples += len(chunk)
                chunk = []
        if chunk:
            dst.add_samples(chunk)
            stats.samples += len(chunk)
        maybe_progress()

    # (root, rel_path, members_id, hash_type) of the records that name a set;
    # the sets are read once the listing is closed, as some servers allow no
    # second statement while it is open.
    named_sets: list[tuple[str, str, str, str]] = []

    def write(docs: list[Document]) -> None:
        for d in docs:
            if d.get("members_id") and src.stores_member_sets:
                key = samples.key_of(d)
                named_sets.append((d["root"], d["rel_path"], d["members_id"],
                                   key[1] if key else "sha256"))
                if not (dst.stores_member_sets and members):
                    del d["members_id"]
        if src.stores_samples and not dst.stores_samples:
            docs = samples.attach(src, docs)
            for d in docs:
                d.pop("sample_id", None)
        elif dst.stores_samples and not src.stores_samples:
            for d in docs:
                sample = samples.split(d)
                if sample is not None:
                    dst.queue_sample(sample)
                    stats.samples += 1
        dst.put_many(docs)

    # --- documents ----------------------------------------------------
    buf: list[Document] = []
    for root in root_list:
        for doc in src.list(root=root):
            buf.append(doc)
            stats.documents += 1
            if len(buf) >= batch:
                write(buf)
                buf = []
                maybe_progress()
    if buf:
        write(buf)
        buf = []
    dst.flush()
    maybe_progress()

    # --- member sets --------------------------------------------------------
    if members and named_sets:
        copied: set[str] = set()
        for root_str, rel_path, mid, hash_type in named_sets:
            if dst.stores_member_sets and mid in copied:
                continue
            rows = member_sets.clean_rows(src.list_member_set(mid))
            if dst.stores_member_sets:
                dst.put_member_set(member_sets.header_for((mid, hash_type), rows), rows)
                copied.add(mid)
                stats.member_sets += 1
            else:
                dst.put_members(root_str, rel_path, rows)
                stats.members_archives += 1
            stats.members_rows += len(rows)
            maybe_progress()

    # --- programs -------------------------------------------------------
    if programs:
        for p in src.list_programs():
            dst.put_program(p)
            stats.programs += 1
        dst.flush()
        maybe_progress()

    # --- root index (scan history) ---------------------------------------
    try:
        for info in src.list_root_info():
            if not roots or info.get("root") in roots:
                dst.put_root_info(info)
                stats.root_infos += 1
    except NotImplementedError:
        pass

    # --- dropped records (files that vanished, kept for --keep-dropped) ----
    try:
        for doc in src.list_dropped():
            if not roots or doc.get("root") in roots:
                dst.put_dropped(doc)
                stats.dropped += 1
    except NotImplementedError:
        pass

    # --- archive members --------------------------------------------------
    if members:
        root_set = set(roots) if roots else None
        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        group_root: dict[tuple[str, str], str] = {}
        try:
            for m in src.iter_all_members():
                if root_set is not None and m.get("root") not in root_set:
                    continue
                key = (m.get("root_id"), m.get("archive_rel_path"))
                groups[key].append(m)
                group_root.setdefault(key, m.get("root"))
        except NotImplementedError:
            stats.members_skipped = True
        else:
            for key, rows in groups.items():
                rid, archive_rel_path = key
                root_str = group_root[key]
                rows.sort(key=lambda m: m.get("index", 0))
                clean = [{k: v for k, v in m.items() if k not in _MEMBER_IDENTITY_KEYS}
                         for m in rows]
                try:
                    doc = dst.get(root_str, archive_rel_path) if dst.stores_member_sets else None
                    if doc is not None and not doc.get("members_id") \
                            and member_sets.store_rows(dst, doc, clean):
                        dst.put(doc)
                        stats.member_sets += 1
                    else:
                        dst.put_members(root_str, archive_rel_path, clean)
                except NotImplementedError:
                    stats.members_skipped = True
                    break
                stats.members_archives += 1
                stats.members_rows += len(clean)
                maybe_progress()
        dst.flush()
        maybe_progress()

    # --- aggregates -------------------------------------------------------
    try:
        dst.rebuild_aggregates()
    except NotImplementedError:
        pass

    # --- verify -------------------------------------------------------
    if verify:
        for root in root_list:
            for doc in src.list(root=root):
                stats.verify_checked += 1
                got = dst.get(doc["root"], doc["rel_path"])
                if got is None or _readable(src, doc) != _readable(dst, got):
                    stats.verify_mismatches.append(f"{doc['root']}::{doc['rel_path']}")
                maybe_progress()

    stats.elapsed = time.monotonic() - start
    maybe_progress(force=True)
    return stats


def run(args: Any) -> int:
    src = open_backend(args.src_backend, getattr(args, "src_out", None),
                        getattr(args, "src_dsn", None))
    try:
        dst = open_backend(args.dst_backend, getattr(args, "dst_out", None),
                            getattr(args, "dst_dsn", None))
    except Exception:
        src.close()
        raise

    def progress(stats: MigrateStats) -> None:
        extra = ""
        if stats.members_archives or stats.members_rows:
            extra = (f", {stats.members_rows} member rows "
                     f"({stats.members_archives} archives)")
        print(f"migrate: {stats.documents} documents, {stats.programs} programs{extra}, "
              f"{stats.elapsed:.1f}s", file=sys.stderr)

    try:
        if _same_target(src, dst):
            print("filecat migrate: source and target are the same backend file/DSN",
                  file=sys.stderr)
            return 1
        try:
            stats = migrate(
                src, dst, roots=args.root, batch=args.batch,
                programs=not args.no_programs, members=not args.no_members,
                verify=args.verify, progress=progress,
            )
        except ValueError as exc:
            print(f"filecat migrate: {exc}", file=sys.stderr)
            return 1
    finally:
        src.close()
        dst.close()

    if stats.members_skipped:
        print("filecat migrate: source backend does not store archive members; skipped",
              file=sys.stderr)
    if stats.verify_mismatches:
        print(f"filecat migrate --verify: {len(stats.verify_mismatches)} mismatch(es) "
              f"out of {stats.verify_checked} checked", file=sys.stderr)
        for key in stats.verify_mismatches[:20]:
            print(f"  mismatch: {key}", file=sys.stderr)
        if len(stats.verify_mismatches) > 20:
            print(f"  ... {len(stats.verify_mismatches) - 20} more", file=sys.stderr)
        return 1
    if stats.errors:
        for err in stats.errors:
            print(f"filecat migrate: {err}", file=sys.stderr)
        return 1
    return 0
