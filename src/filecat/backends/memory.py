"""In-process backend for tests and dry runs. Not selectable from the CLI."""
from __future__ import annotations

import copy
from typing import Any, Iterator

from ..record import root_id
from .base import Backend, Document


class MemoryBackend(Backend):
    name = "memory"

    def __init__(self) -> None:
        self.docs: dict[tuple[str, str], Document] = {}
        self.programs: dict[str, Document] = {}
        self.members: dict[tuple[str, str], list[Document]] = {}
        self.aggregates: dict[str, Any] = {}
        self.root_info: dict[str, Document] = {}
        self.dropped: list[Document] = []
        self.treemaps: dict[str, tuple[Document, Document]] = {}

    def put(self, document: Document) -> None:
        self.docs[(document["root_id"], document["rel_path"])] = copy.deepcopy(document)

    def get(self, root: str, rel_path: str) -> Document | None:
        doc = self.docs.get((root_id(root), rel_path))
        return copy.deepcopy(doc) if doc is not None else None

    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        rid = root_id(root) if root is not None else None
        for (r, _), doc in list(self.docs.items()):
            if rid is not None and r != rid:
                continue
            if kind is not None and doc.get("kind") != kind:
                continue
            yield copy.deepcopy(doc)

    def delete(self, root: str, rel_path: str) -> None:
        self.docs.pop((root_id(root), rel_path), None)
        self.delete_members(root, rel_path)

    def put_members(self, root: str, rel_path: str, members: list[Document]) -> None:
        rid = root_id(root)
        self.members[(rid, rel_path)] = [
            {**copy.deepcopy(m), "root_id": rid, "root": root, "archive_rel_path": rel_path}
            for m in members]

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        rows = self.members.get((root_id(root), rel_path), [])
        yield from (copy.deepcopy(m) for m in sorted(rows, key=lambda m: m["index"]))

    def iter_all_members(self) -> Iterator[Document]:
        for rows in list(self.members.values()):
            yield from (copy.deepcopy(m) for m in rows)

    def delete_members(self, root: str, rel_path: str) -> None:
        self.members.pop((root_id(root), rel_path), None)

    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        return copy.deepcopy({r: e for r, e in self.aggregates.items() if root is None or r == root})

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        if root is None:
            self.aggregates.clear()
        else:
            self.aggregates.pop(root, None)
        for r, entry in entries.items():
            self.aggregates[r] = {**copy.deepcopy(entry), "depth": depth, "built_at": built_at}

    def put_root_info(self, info: Document) -> None:
        self.root_info[info["root_id"]] = copy.deepcopy(info)

    def list_root_info(self) -> Iterator[Document]:
        yield from (copy.deepcopy(i) for i in list(self.root_info.values()))

    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        if data is None:
            if meta["id"] in self.treemaps:
                self.treemaps[meta["id"]] = (copy.deepcopy(meta), self.treemaps[meta["id"]][1])
            return
        self.treemaps[meta["id"]] = (copy.deepcopy(meta), copy.deepcopy(data))

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        rid = root_id(root) if root is not None else None
        return [copy.deepcopy(m) for m, _ in self.treemaps.values() if rid is None or m["root_id"] == rid]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        entry = self.treemaps.get(treemap_id)
        return copy.deepcopy(entry) if entry is not None else None

    def delete_treemap(self, treemap_id: str) -> None:
        self.treemaps.pop(treemap_id, None)

    def put_dropped(self, document: Document) -> None:
        self.dropped.append(copy.deepcopy(document))

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        rows = [d for d in reversed(self.dropped) if root is None or d.get("root_id") == root_id(root)]
        yield from (copy.deepcopy(d) for d in sorted(rows, key=lambda d: d["dropped_at"], reverse=True))

    def purge_dropped(self, before: str) -> int:
        n = len(self.dropped)
        self.dropped = [d for d in self.dropped if d["dropped_at"] >= before]
        return n - len(self.dropped)

    def put_program(self, record: Document) -> None:
        self.programs[record["program_id"]] = copy.deepcopy(record)

    def list_programs(self) -> Iterator[Document]:
        yield from (copy.deepcopy(p) for p in self.programs.values())

    def clear_programs(self) -> None:
        self.programs.clear()
