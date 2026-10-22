"""Content-keyed text samples. See docs/samples.md.

A probe leaves a 4 KiB decoded text sample (and Ollama may add an `llm`
result) on the file record. Ten copies of a file across shares and backup
generations would hold ten copies of both, and cost ten model calls. A
backend with `stores_samples` keeps one sample document per content hash
instead:

    {"sample_id": <hex digest>, "hash_type": "sha256" | "sha256_partial",
     "size": ..., "encoding": {...}, "sample": "...", "sample_truncated": true,
     "llm": {...}}

and the file record keeps only `sample_id`. A record without a hash keeps
its sample inline until it gets one.

split()    -- record -> sample document (Backend.store calls it)
attach()   -- put the sample back on a record for a reader (show, serve,
              Ollama, a migrate to a backend without a samples store)
migrate()  -- move inline samples of existing records into the store,
              batched and resumable; `filecat samples migrate`
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable

from .backends.base import Backend, Document
from .fsutil import replace as _replace

SAMPLE_KEYS = ("sample", "sample_truncated")
MOVED_KEYS = SAMPLE_KEYS + ("llm",)
CHECKPOINT_VERSION = 1


def key_of(doc: Document) -> tuple[str, str] | None:
    """(sample_id, hash_type): the content hash the sample is filed under."""
    for hash_type in ("sha256", "sha256_partial"):
        value = doc.get(hash_type)
        if isinstance(value, str) and value:
            return value, hash_type
    return None


def split(doc: Document) -> Document | None:
    """Move the inline sample (and llm) of `doc` into a new sample document
    and leave `sample_id` in their place. None, with `doc` untouched, when
    there is no inline sample or no hash to file it under."""
    if not doc.get("sample"):
        return None
    key = key_of(doc)
    if key is None:
        return None
    sample_id, hash_type = key
    sample: Document = {"sample_id": sample_id, "hash_type": hash_type, "size": doc.get("size")}
    if doc.get("encoding") is not None:
        sample["encoding"] = doc["encoding"]
    for k in MOVED_KEYS:
        if k in doc:
            sample[k] = doc.pop(k)
    doc["sample_id"] = sample_id
    return sample


def attach(backend: Backend, docs: Iterable[Document]) -> list[Document]:
    """Copies of `docs` with the stored sample and llm back on them (a
    record's own inline fields win). Records whose sample is missing from
    the store come back without one."""
    out = [dict(d) for d in docs]
    ids = {d["sample_id"] for d in out if d.get("sample_id") and not d.get("sample")}
    if not ids:
        return out
    try:
        stored = backend.get_samples(ids)
    except NotImplementedError:
        return out
    for d in out:
        s = stored.get(d.get("sample_id") or "")
        if s is not None:
            for k in MOVED_KEYS:
                if k in s and k not in d:
                    d[k] = s[k]
    return out


def attach_one(backend: Backend, doc: Document | None) -> Document | None:
    return None if doc is None else attach(backend, [doc])[0]


# --- migration ------------------------------------------------------------

@dataclass
class MigrateStats:
    scanned: int = 0        # records read
    moved: int = 0          # records whose inline sample moved to the store
    samples: int = 0        # distinct samples written (or already there)
    no_hash: int = 0        # records with a sample but no hash: kept inline
    batches: int = 0
    resumed_from: Any = None
    done: bool = False


def checkpoint_path_for(backend_name: str, catalog_path: str | None, what: str = "samples") -> str:
    """Beside the catalog file, or in the current directory for a server."""
    if catalog_path:
        return f"{catalog_path}.{what}-migrate.json"
    return f".filecat-{backend_name}.{what}-migrate.json"


def catalog_tag(backend_name: str, location: str | None) -> str:
    """Names the catalog a checkpoint belongs to, without storing a DSN
    (which may hold a password) in the file."""
    return hashlib.sha256(f"{backend_name}\0{location or ''}".encode()).hexdigest()[:16]


def _load_checkpoint(path: str, tag: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return None
    if state.get("version") != CHECKPOINT_VERSION or state.get("catalog") != tag:
        return None
    return state


def _save_checkpoint(path: str, state: dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
        fh.flush()
        os.fsync(fh.fileno())
    _replace(tmp, path)


def migrate(backend: Backend, checkpoint: str, *, tag: str = "", batch: int = 1000,
            limit: int | None = None, progress: Callable[[MigrateStats], None] | None = None
            ) -> MigrateStats:
    """Move inline samples of existing records into the samples store.

    Crash-safe at every point. Per batch: the samples are committed first
    (add_samples keeps any already there), then the records are rewritten
    without their inline copy and flushed, then the checkpoint is saved
    (written to a temporary file, then renamed over the old one). A crash
    before the records are flushed leaves samples nobody refers to yet,
    never a record pointing at a missing sample; a rerun of the batch finds
    the rewritten records without an inline sample and leaves them alone.
    Without the checkpoint a rerun starts over and is still correct, only
    slower. `limit` stops after that many records (for a trial run).
    """
    if not backend.stores_samples:
        raise NotImplementedError(f"{backend.name} backend keeps samples inline")
    stats = MigrateStats()
    state = _load_checkpoint(checkpoint, tag)
    after = None
    if state is not None:
        after = state["after"]
        stats.resumed_from = after
        for k in ("scanned", "moved", "samples", "no_hash", "batches"):
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
        moves: list[Document] = []
        found: dict[str, Document] = {}
        for doc in docs:
            stats.scanned += 1
            if not doc.get("sample"):
                continue
            sample = split(doc)
            if sample is None:
                stats.no_hash += 1
                continue
            moves.append(doc)
            kept = found.setdefault(sample["sample_id"], sample)
            if "llm" in sample and "llm" not in kept:
                kept["llm"] = sample["llm"]   # a later copy's result fills in
        if found:
            backend.add_samples(list(found.values()))
            _keep_llm(backend, found)
            stats.samples += len(found)
        for doc in moves:
            backend.put(doc)
        backend.flush()
        stats.moved += len(moves)
        stats.batches += 1
        after = cursor
        _save_checkpoint(checkpoint, {"version": CHECKPOINT_VERSION, "catalog": tag, "after": after,
                                      **{k: v for k, v in asdict(stats).items()
                                         if k in ("scanned", "moved", "samples", "no_hash", "batches")}})
        if progress is not None:
            progress(stats)
    if stats.done:
        try:
            os.remove(checkpoint)
        except OSError:
            pass
    return stats


def _keep_llm(backend: Backend, found: dict[str, Document]) -> None:
    """A sample that was already stored without an Ollama result gets the
    one a record carried inline; one that has a result keeps it."""
    with_llm = {sid: s for sid, s in found.items() if "llm" in s}
    if not with_llm:
        return
    stored = backend.get_samples(with_llm)
    for sid, s in with_llm.items():
        if "llm" not in stored.get(sid, {}):
            backend.set_sample_llm(sid, s["llm"])


# --- command ----------------------------------------------------------------

def run(args: Any) -> int:
    from .backends import open_backend
    catalog = args.out if args.backend in ("sqlite", "jsonl", "jsonl_dir") else None
    with open_backend(args.backend, args.out, args.dsn) as backend:
        if args.action == "stats":
            return _stats(backend)
        if not backend.stores_samples:
            print(f"filecat samples: the {backend.name} backend keeps samples inline; nothing to do",
                  file=sys.stderr)
            return 2
        if args.action == "prune":
            from .member_sets import prune
            return prune(backend, "samples", backend.prune_samples, args.force)
        path = args.checkpoint or checkpoint_path_for(backend.name, catalog)
        tag = catalog_tag(backend.name, args.out or args.dsn)
        last = [time.monotonic()]
        started = time.monotonic()

        def progress(s: MigrateStats) -> None:
            now = time.monotonic()
            if now - last[0] >= args.progress_interval:
                last[0] = now
                print(f"samples: {s.scanned} records read, {s.moved} moved, {s.samples} samples "
                      f"({now - started:.0f}s)", file=sys.stderr, flush=True)

        try:
            stats = migrate(backend, path, tag=tag, batch=args.batch, limit=args.limit, progress=progress)
        except KeyboardInterrupt:
            print(f"samples: interrupted; run it again to continue from {path}", file=sys.stderr)
            return 130
    resumed = ", resumed from a checkpoint" if stats.resumed_from is not None else ""
    print(f"samples: {stats.scanned} records read, {stats.moved} samples moved off records "
          f"into {stats.samples} sample documents, {stats.no_hash} kept inline (no hash){resumed}")
    if not stats.done:
        print(f"samples: stopped at --limit; run it again to continue ({path})")
    return 0


def _stats(backend: Backend) -> int:
    if not backend.stores_samples:
        print(f"{backend.name}: samples are kept inline on the records")
        return 0
    count = with_llm = text = 0
    for s in backend.iter_samples():
        count += 1
        with_llm += "llm" in s
        text += len(s.get("sample") or "")
    print(f"{count} samples, {with_llm} with an Ollama result, {text / 1e6:.1f} MB of sample text")
    return 0
