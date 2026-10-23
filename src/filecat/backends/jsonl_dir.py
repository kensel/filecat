"""JSONL catalog split into one file per root: `--backend jsonl --out DIR`.

`open_backend` picks this layout when --out is an existing directory or a
path that does not end in .jsonl; an existing or new `*.jsonl` file keeps
the single-file layout of jsonl.py. Inside DIR:

    <slug>.<root_id>.jsonl           that root's documents
    <slug>.<root_id>.members.jsonl   its archive members
    <slug>.<root_id>.summary.json    its stored aggregates
    <slug>.<root_id>.roots.json      its root-index entry (scan history)
    <slug>.<root_id>.dropped.jsonl   its dropped records (files that vanished)
    <slug>.<root_id>.treemaps.json   its Graph view snapshots (filecat serve)
    <slug>.<root_id>.redactions.json its sticky redactions (no names)
    programs.jsonl                   installed-programs records

Each root's three files are exactly a single-file jsonl catalog holding
one root, managed by a JsonlBackend, so the format (one document per line,
each (root, rel_path) once) is unchanged. The slug is the root made
filename-safe (\\\\nas-vm\\admin -> nas-vm-admin) for people browsing the
folder; root_id makes the name unique and is how a root's file is found,
so there is no index file to keep in step and two scans of different
roots never write the same file.

Why: a jsonl flush rewrites the whole file it merges into. With one file
per root, scanning a share rewrites only that share's file, not the
documents of every other share in the catalog. A single huge root is
still one file; splitting a root into size-capped parts is the next step
if that is needed (see docs/jsonl-parts-plan.md).
"""
from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..record import root_id
from .base import Backend, Document
from .jsonl import JsonlBackend, put_program, read_programs

# <slug>.<16 hex root_id>.jsonl -- the members file (".members.jsonl"),
# summaries (".json") and temp files ("...jsonl.tmpNNN") do not match.
_ROOT_FILE = re.compile(r"^.*\.(?P<rid>[0-9a-f]{16})\.jsonl$")
SLUG_MAX = 60


def slug(root: str) -> str:
    """Filename-safe, human-readable form of a root path string."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", root).strip("-.")[:SLUG_MAX] or "root"


def is_dir_layout(path: str) -> bool:
    """True when `path` names a per-root directory rather than one .jsonl file."""
    p = Path(path)
    if p.exists():
        return p.is_dir()
    return p.suffix.lower() != ".jsonl"


class JsonlDirBackend(Backend):
    name = "jsonl"

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.programs_path = self.path / "programs.jsonl"
        self._parts: dict[str, JsonlBackend] = {}  # root_id -> that root's catalog

    # --- per-root files ------------------------------------------------
    def _files(self) -> dict[str, Path]:
        """root_id -> document file, for every root file in the directory."""
        out = {}
        for p in self.path.iterdir():
            m = _ROOT_FILE.match(p.name)
            if m and p.is_file():
                out[m.group("rid")] = p
        return out

    def _part(self, root: str, create: bool) -> JsonlBackend | None:
        rid = root_id(root)
        part = self._parts.get(rid)
        if part is None:
            path = self._files().get(rid)
            if path is None:
                if not create:
                    return None
                path = self.path / f"{slug(root)}.{rid}.jsonl"
            part = self._parts[rid] = JsonlBackend(str(path))
        return part

    def _all_parts(self) -> list[JsonlBackend]:
        for rid, path in self._files().items():
            if rid not in self._parts:
                self._parts[rid] = JsonlBackend(str(path))
        return list(self._parts.values())

    # --- documents -------------------------------------------------
    def put(self, document: Document) -> None:
        self._part(document["root"], create=True).put(document)

    def get(self, root: str, rel_path: str) -> Document | None:
        part = self._part(root, create=False)
        return part.get(root, rel_path) if part else None

    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        if root is not None:
            part = self._part(root, create=False)
            return part.list(kind=kind, root=root) if part else iter(())
        return itertools.chain.from_iterable(p.list(kind=kind) for p in self._all_parts())

    def delete(self, root: str, rel_path: str) -> None:
        part = self._part(root, create=False)
        if part:
            part.delete(root, rel_path)

    def delete_many(self, root: str, rel_paths: Iterable[str]) -> int:
        part = self._part(root, create=False)
        return part.delete_many(root, rel_paths) if part else 0

    def roots(self) -> list[str]:
        roots = set()
        for part in self._all_parts():
            first = next(iter(part.list()), None)  # every line of a part has the same root
            if first is not None:
                roots.add(first["root"])
        return sorted(roots)

    # --- archive members -------------------------------------------
    def put_members(self, root: str, rel_path: str, members: list[Document]) -> None:
        self._part(root, create=True).put_members(root, rel_path, members)

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        part = self._part(root, create=False)
        return part.list_members(root, rel_path) if part else iter(())

    def iter_all_members(self) -> Iterator[Document]:
        return itertools.chain.from_iterable(p.iter_all_members() for p in self._all_parts())

    def delete_members(self, root: str, rel_path: str) -> None:
        part = self._part(root, create=False)
        if part:
            part.delete_members(root, rel_path)

    # --- aggregates --------------------------------------------------
    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        if root is not None:
            part = self._part(root, create=False)
            return part.stored_aggregates(root) if part else {}
        out: dict[str, Any] = {}
        for part in self._all_parts():
            out.update(part.stored_aggregates())
        return out

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        if root is not None:
            part = self._part(root, create=bool(entries))
            if part:
                part.replace_aggregates(entries, depth, built_at, root)
            return
        by_part: dict[str, dict[str, Any]] = {}
        for r, entry in entries.items():
            self._part(r, create=True)
            by_part.setdefault(root_id(r), {})[r] = entry
        for rid, part in self._parts.items():
            if by_part.get(rid) or part.summary_path.exists():
                part.replace_aggregates(by_part.get(rid, {}), depth, built_at, None)

    # --- dropped records --------------------------------------------
    def drop_many(self, root: str, rel_paths: Iterable[str], reason: str = "vanished") -> int:
        part = self._part(root, create=False)
        return part.drop_many(root, rel_paths, reason) if part else 0

    def put_dropped(self, document: Document) -> None:
        self._part(document["root"], create=True).put_dropped(document)

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        if root is not None:
            part = self._part(root, create=False)
            return part.list_dropped(root) if part else iter(())
        rows = [d for p in self._all_parts() for d in p.list_dropped()]
        return iter(sorted(rows, key=lambda d: d.get("dropped_at") or "", reverse=True))

    def purge_dropped(self, before: str) -> int:
        return sum(p.purge_dropped(before) for p in self._all_parts())

    def purge_dropped_paths(self, root: str, rel_paths: Iterable[str]) -> int:
        part = self._part(root, create=False)
        return part.purge_dropped_paths(root, rel_paths) if part else 0

    # --- root index ------------------------------------------------
    def put_root_info(self, info: Document) -> None:
        self._part(info["root"], create=True).put_root_info(info)

    def list_root_info(self) -> Iterator[Document]:
        return itertools.chain.from_iterable(p.list_root_info() for p in self._all_parts())

    def get_root_info(self, root: str) -> Document | None:
        part = self._part(root, create=False)
        return next(iter(part.list_root_info()), None) if part else None

    def delete_root_info(self, root: str) -> None:
        part = self._part(root, create=False)
        if part:
            part.delete_root_info(root)

    # --- stored treemaps ---------------------------------------------
    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        part = self._part(meta["root"], create=data is not None)
        if part:
            part.put_treemap(meta, data)

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        if root is not None:
            part = self._part(root, create=False)
            return part.list_treemaps(root) if part else []
        return [m for p in self._all_parts() for m in p.list_treemaps()]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        return next((t for p in self._all_parts() if (t := p.get_treemap(treemap_id))), None)

    def delete_treemap(self, treemap_id: str) -> None:
        for part in self._all_parts():
            part.delete_treemap(treemap_id)

    # --- sticky redactions ---------------------------------------------
    def _redaction_rows(self, root: str | None = None) -> list[Document]:
        if root is not None:
            part = self._part(root, create=False)
            return part._redaction_rows() if part else []
        return [r for p in self._all_parts() for r in p._redaction_rows()]

    def _redaction_put(self, entry: Document) -> None:
        self._part(entry["root"], create=True)._redaction_put(entry)

    def _redaction_remove(self, entry: Document) -> None:
        part = self._part(entry["root"], create=False)
        if part:
            part._redaction_remove(entry)

    # --- installed programs -------------------------------------------
    def put_program(self, record: Document) -> None:
        put_program(self.programs_path, record)

    def list_programs(self) -> Iterator[Document]:
        yield from read_programs(self.programs_path)

    def clear_programs(self) -> None:
        if self.programs_path.exists():
            self.programs_path.unlink()

    # --- lifecycle -------------------------------------------------
    def flush(self) -> None:
        for part in self._parts.values():
            part.flush()

    def close(self) -> None:
        self.flush()
