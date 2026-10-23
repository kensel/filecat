"""JSONL backend: UTF-8, one document per line. Base install, default
when --out has no sqlite extension is not inferred -- `filecat.backends`
picks this module whenever --backend jsonl is chosen.

Design for a large file (a 218 MB import is the first real stress test):

* `put()` only appends the document to an in-memory buffer; it never reads
  or rewrites the main file on every call. The buffer is flushed (merged
  into the main file) every BATCH_SIZE puts or BATCH_SECONDS, whichever
  comes first, and again at flush()/close(). This bounds how much of the
  file a flush has to reconcile against the in-flight buffer.
* A flush streams the *old* file line by line into a temp file next to it
  (never loading it whole into memory), skipping any line whose
  (root_id, rel_path) key is being superseded by a buffered document, and
  writing that buffered document in the old line's place so (root_id,
  rel_path) keeps appearing exactly once (the "rescan rewrites..."
  requirement). New keys not present in the old file are appended. The
  temp file then replaces the original via `os.replace` (atomic on both
  POSIX and Windows for files on the same volume).
* `get()` first checks the buffer (last write wins), then a lazily built
  offset index (key -> byte offset of that key's single line) so a single
  lookup does not need to scan the whole file.
* `delete()` flushes the buffer, then removes that one key from the main
  file with the same streaming merge.

Aggregates are stored in `<stem>.summary.json` beside the jsonl file (for
`foo.jsonl` that is `foo.summary.json`), and installed-programs records go
in `<stem>.programs.jsonl`, both per the spec. Records moved out by
`drop()` (their file vanished) are appended to `<stem>.dropped.jsonl`.
Treemap snapshots of the web viewer's Graph view are kept in
`<stem>.treemaps.json`, rewritten whole like the root index.
"""
from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..fsutil import replace as _replace
from ..record import root_id
from .base import Backend, Document, dropped_now

BATCH_SIZE = 2000
BATCH_SECONDS = 5.0


def _line_key(line: str) -> tuple[str, str] | None:
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None
    rid = doc.get("root_id")
    rel = doc.get("rel_path")
    if rid is None or rel is None:
        return None
    return (rid, rel)


def read_programs(path: Path) -> Iterator[Document]:
    """Installed-programs records from a programs .jsonl file (shared with
    the per-root directory layout in jsonl_dir.py)."""
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line:
                yield json.loads(line)


def put_program(path: Path, record: Document) -> None:
    """Insert or replace one program record, rewriting the file atomically."""
    programs = {p["program_id"]: p for p in read_programs(path)}
    programs[record["program_id"]] = record
    tmp_path = path.parent / (path.name + f".tmp{os.getpid()}")
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
            for p in programs.values():
                f.write(json.dumps(p, ensure_ascii=False) + "\n")
        _replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


class JsonlBackend(Backend):
    name = "jsonl"

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        self.summary_path = self.path.with_name(self.path.stem + ".summary.json")
        self.programs_path = self.path.with_name(self.path.stem + ".programs.jsonl")
        self.members_path = self.path.with_name(self.path.stem + ".members.jsonl")
        self.roots_path = self.path.with_name(self.path.stem + ".roots.json")
        self.dropped_path = self.path.with_name(self.path.stem + ".dropped.jsonl")
        self.treemaps_path = self.path.with_name(self.path.stem + ".treemaps.json")
        self._member_keys: set[tuple[str, str]] | None = None
        self._buffer: list[Document] = []
        self._last_flush = time.monotonic()
        self._index: dict[tuple[str, str], int] | None = None

    # --- documents -------------------------------------------------
    def put(self, document: Document) -> None:
        self._buffer.append(document)
        if (len(self._buffer) >= BATCH_SIZE
                or (time.monotonic() - self._last_flush) >= BATCH_SECONDS):
            self.flush()

    def _tmp_path(self) -> Path:
        return self.path.parent / (self.path.name + f".tmp{os.getpid()}")

    def _merge(self, new_docs: dict[tuple[str, str], Document],
               delete_keys: set[tuple[str, str]]) -> None:
        tmp_path = self._tmp_path()
        written: set[tuple[str, str]] = set()
        try:
            with open(tmp_path, "w", encoding="utf-8", newline="\n") as out:
                if self.path.exists():
                    with open(self.path, "r", encoding="utf-8") as src:
                        for raw in src:
                            line = raw.strip("\n")
                            if not line.strip():
                                continue
                            key = _line_key(line)
                            if key is None:
                                # Keep unparsable lines rather than silently drop data.
                                out.write(line + "\n")
                                continue
                            if key in delete_keys:
                                continue
                            if key in new_docs:
                                out.write(json.dumps(new_docs[key], ensure_ascii=False) + "\n")
                                written.add(key)
                                continue
                            out.write(line + "\n")
                for key, doc in new_docs.items():
                    if key not in written:
                        out.write(json.dumps(doc, ensure_ascii=False) + "\n")
            _replace(tmp_path, self.path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
        self._index = None  # offsets are invalid after a rewrite

    def flush(self) -> None:
        if not self._buffer:
            return
        new_docs: dict[tuple[str, str], Document] = {}
        for doc in self._buffer:
            new_docs[(doc["root_id"], doc["rel_path"])] = doc
        self._merge(new_docs, delete_keys=set())
        self._buffer.clear()
        self._last_flush = time.monotonic()

    def _ensure_index(self) -> None:
        if self._index is not None:
            return
        index: dict[tuple[str, str], int] = {}
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                offset = f.tell()
                line = f.readline()
                while line:
                    stripped = line.strip()
                    if stripped:
                        key = _line_key(stripped)
                        if key is not None:
                            index[key] = offset
                    offset = f.tell()
                    line = f.readline()
        self._index = index

    def get(self, root: str, rel_path: str) -> Document | None:
        rid = root_id(root)
        for doc in reversed(self._buffer):
            if doc["root_id"] == rid and doc["rel_path"] == rel_path:
                return copy.deepcopy(doc)
        self._ensure_index()
        offset = self._index.get((rid, rel_path)) if self._index else None
        if offset is None:
            return None
        with open(self.path, "r", encoding="utf-8") as f:
            f.seek(offset)
            line = f.readline()
        return json.loads(line) if line.strip() else None

    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        rid = root_id(root) if root is not None else None
        buffered: dict[tuple[str, str], Document] = {}
        for doc in self._buffer:
            buffered[(doc["root_id"], doc["rel_path"])] = doc

        def match(doc: Document) -> bool:
            if rid is not None and doc.get("root_id") != rid:
                return False
            if kind is not None and doc.get("kind") != kind:
                return False
            return True

        yielded: set[tuple[str, str]] = set()
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        doc = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = (doc.get("root_id"), doc.get("rel_path"))
                    if key in buffered:
                        doc = buffered[key]
                        yielded.add(key)
                    if match(doc):
                        yield copy.deepcopy(doc)
        for key, doc in buffered.items():
            if key in yielded:
                continue
            if match(doc):
                yield copy.deepcopy(doc)

    def delete(self, root: str, rel_path: str) -> None:
        key = (root_id(root), rel_path)
        self._buffer = [d for d in self._buffer
                        if (d["root_id"], d["rel_path"]) != key]
        self._merge({}, delete_keys={key})
        self.delete_members(root, rel_path)

    def roots(self) -> list[str]:
        return sorted({d["root"] for d in self.list()})

    # --- archive members -------------------------------------------
    def _members_tmp_path(self) -> Path:
        return self.members_path.parent / (self.members_path.name + f".tmp{os.getpid()}")

    def _merge_members(self, archive_key: tuple[str, str], new_rows: list[Document]) -> None:
        """Stream the members file, dropping every row for `archive_key`
        (root_id, archive_rel_path), then append `new_rows` in index order.
        Never loads the whole file into memory."""
        tmp_path = self._members_tmp_path()
        try:
            with open(tmp_path, "w", encoding="utf-8", newline="\n") as out:
                if self.members_path.exists():
                    with open(self.members_path, "r", encoding="utf-8") as src:
                        for raw in src:
                            line = raw.strip("\n")
                            if not line.strip():
                                continue
                            try:
                                doc = json.loads(line)
                            except json.JSONDecodeError:
                                out.write(line + "\n")
                                continue
                            key = (doc.get("root_id"), doc.get("archive_rel_path"))
                            if key == archive_key:
                                continue  # dropped; replaced below (or simply removed)
                            out.write(line + "\n")
                for row in new_rows:
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
            _replace(tmp_path, self.members_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def _stored_member_keys(self) -> set[tuple[str, str]]:
        """(root_id, archive_rel_path) of every archive with rows in the file,
        read once; a new archive's rows are then appended, and only replacing
        or deleting a stored archive rewrites the file."""
        if self._member_keys is None:
            keys: set[tuple[str, str]] = set()
            for doc in self.iter_all_members():
                keys.add((doc.get("root_id"), doc.get("archive_rel_path")))
            self._member_keys = keys
        return self._member_keys

    def put_members(self, root: str, rel_path: str, members: list) -> None:
        rid = root_id(root)
        rows = []
        for i, m in enumerate(members):
            rows.append({**m, "index": m.get("index", i), "root_id": rid, "root": root,
                         "archive_rel_path": rel_path})
        key = (rid, rel_path)
        keys = self._stored_member_keys()
        if key in keys:
            self._merge_members(key, rows)
        elif rows:
            with open(self.members_path, "a", encoding="utf-8", newline="\n") as out:
                for row in rows:
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
        if rows:
            keys.add(key)
        else:
            keys.discard(key)

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        rid = root_id(root)
        rows: list[Document] = []
        if self.members_path.exists():
            with open(self.members_path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        doc = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if doc.get("root_id") == rid and doc.get("archive_rel_path") == rel_path:
                        rows.append(doc)
        rows.sort(key=lambda m: m.get("index", 0))
        yield from rows

    def iter_all_members(self) -> Iterator[Document]:
        if not self.members_path.exists():
            return
        with open(self.members_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield doc

    def delete_members(self, root: str, rel_path: str) -> None:
        key = (root_id(root), rel_path)
        keys = self._stored_member_keys()
        if key in keys:
            self._merge_members(key, [])
            keys.discard(key)

    # --- aggregates --------------------------------------------------
    # <stem>.summary.json: {"roots": {root: entry + depth + built_at}}. Files
    # written before aggregates were per root carry one top-level depth and
    # built_at instead; those are read as applying to every root.
    def _read_summary(self) -> dict[str, Any]:
        try:
            with open(self.summary_path, "r", encoding="utf-8") as f:
                stored = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}
        roots = stored.get("roots") or {}
        return {r: {"depth": stored.get("depth"), "built_at": stored.get("built_at"), **e}
                for r, e in roots.items()}

    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        roots = self._read_summary()
        if root is not None:
            return {root: roots[root]} if root in roots else {}
        return roots

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        roots = {} if root is None else {r: e for r, e in self._read_summary().items() if r != root}
        for r, entry in entries.items():
            roots[r] = {**entry, "depth": depth, "built_at": built_at}
        tmp_path = self.summary_path.parent / (self.summary_path.name + f".tmp{os.getpid()}")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({"roots": roots}, f, ensure_ascii=False, indent=2)
            _replace(tmp_path, self.summary_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    # --- dropped records --------------------------------------------
    # <stem>.dropped.jsonl: appended to; purge_dropped() rewrites it.
    def put_dropped(self, document: Document) -> None:
        with open(self.dropped_path, "a", encoding="utf-8", newline="\n") as out:
            out.write(json.dumps(document, ensure_ascii=False) + "\n")

    def drop_many(self, root: str, rel_paths: Iterable[str], reason: str = "vanished") -> int:
        """One rewrite of the catalog for the whole batch, not one per record."""
        rid, at = root_id(root), dropped_now()
        keys: set[tuple[str, str]] = set()
        for rel_path in rel_paths:
            doc = self.get(root, rel_path)
            if doc is None:
                continue
            self.put_dropped({**doc, "dropped_at": at, "drop_reason": reason})
            keys.add((rid, rel_path))
        if keys:
            self._buffer = [d for d in self._buffer if (d["root_id"], d["rel_path"]) not in keys]
            self._merge({}, delete_keys=keys)
            for _, rel_path in keys:
                self.delete_members(root, rel_path)
        return len(keys)

    def _read_dropped(self) -> Iterator[Document]:
        if not self.dropped_path.exists():
            return
        with open(self.dropped_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        rid = root_id(root) if root is not None else None
        rows = [d for d in self._read_dropped() if rid is None or d.get("root_id") == rid]
        rows.reverse()  # appended in drop order; stable sort keeps newest first on ties
        yield from sorted(rows, key=lambda d: d.get("dropped_at") or "", reverse=True)

    def purge_dropped(self, before: str) -> int:
        if not self.dropped_path.exists():
            return 0
        removed = 0
        tmp_path = self.dropped_path.parent / (self.dropped_path.name + f".tmp{os.getpid()}")
        try:
            with open(tmp_path, "w", encoding="utf-8", newline="\n") as out:
                for doc in self._read_dropped():
                    if (doc.get("dropped_at") or "") < before:
                        removed += 1
                    else:
                        out.write(json.dumps(doc, ensure_ascii=False) + "\n")
            if removed:
                _replace(tmp_path, self.dropped_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
        return removed

    # --- root index ------------------------------------------------
    # <stem>.roots.json: {root_id: info}, rewritten whole (it is small).
    def _read_root_info(self) -> dict[str, Document]:
        try:
            with open(self.roots_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def put_root_info(self, info: Document) -> None:
        infos = self._read_root_info()
        infos[info["root_id"]] = info
        tmp_path = self.roots_path.parent / (self.roots_path.name + f".tmp{os.getpid()}")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(infos, f, ensure_ascii=False, indent=2)
            _replace(tmp_path, self.roots_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def list_root_info(self) -> Iterator[Document]:
        yield from self._read_root_info().values()

    def delete_root_info(self, root: str) -> None:
        infos = self._read_root_info()
        if infos.pop(root_id(root), None) is None:
            return
        tmp_path = self.roots_path.parent / (self.roots_path.name + f".tmp{os.getpid()}")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(infos, f, ensure_ascii=False, indent=2)
            _replace(tmp_path, self.roots_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    # --- stored treemaps ---------------------------------------------
    # <stem>.treemaps.json: {id: {"meta": ..., "data": ...}}, rewritten whole.
    def _read_treemaps(self) -> dict[str, Document]:
        try:
            with open(self.treemaps_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_treemaps(self, entries: dict[str, Document]) -> None:
        if not entries:
            if self.treemaps_path.exists():
                self.treemaps_path.unlink()
            return
        tmp_path = self.treemaps_path.parent / (self.treemaps_path.name + f".tmp{os.getpid()}")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, ensure_ascii=False)
            _replace(tmp_path, self.treemaps_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        entries = self._read_treemaps()
        if data is None:
            if meta["id"] not in entries:
                return
            data = entries[meta["id"]]["data"]
        entries[meta["id"]] = {"meta": meta, "data": data}
        self._write_treemaps(entries)

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        rid = root_id(root) if root is not None else None
        return [e["meta"] for e in self._read_treemaps().values() if rid is None or e["meta"]["root_id"] == rid]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        entry = self._read_treemaps().get(treemap_id)
        return (entry["meta"], entry["data"]) if entry else None

    def delete_treemap(self, treemap_id: str) -> None:
        entries = self._read_treemaps()
        if entries.pop(treemap_id, None) is not None:
            self._write_treemaps(entries)

    # --- installed programs -------------------------------------------
    def put_program(self, record: Document) -> None:
        put_program(self.programs_path, record)

    def list_programs(self) -> Iterator[Document]:
        yield from read_programs(self.programs_path)

    def clear_programs(self) -> None:
        if self.programs_path.exists():
            self.programs_path.unlink()

    # --- lifecycle -------------------------------------------------
    def close(self) -> None:
        self.flush()
