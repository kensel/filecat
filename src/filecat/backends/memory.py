"""In-process backend for tests and dry runs. Not selectable from the CLI."""
from __future__ import annotations

import copy
from typing import Any, Iterable, Iterator

from ..record import root_id
from .base import Backend, Document


class MemoryBackend(Backend):
    name = "memory"
    stores_samples = True
    stores_member_sets = True

    def __init__(self) -> None:
        self.docs: dict[tuple[str, str], Document] = {}
        self.programs: dict[str, Document] = {}
        self.members: dict[tuple[str, str], list[Document]] = {}
        self.aggregates: dict[str, Any] = {}
        self.root_info: dict[str, Document] = {}
        self.dropped: list[Document] = []
        self.treemaps: dict[str, tuple[Document, Document]] = {}
        self.samples: dict[str, Document] = {}
        self.member_sets: dict[str, Document] = {}
        self.set_rows: dict[str, list[Document]] = {}
        self._redactions: dict[str, Document] = {}

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

    def delete_root_info(self, root: str) -> None:
        self.root_info.pop(root_id(root), None)

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

    def purge_dropped_paths(self, root: str, rel_paths: Iterable[str]) -> int:
        rid, paths = root_id(root), list(rel_paths)
        keep = [d for d in self.dropped if d.get("root_id") != rid
                or not any(d["rel_path"] == p or d["rel_path"].startswith(p + "/") for p in paths)]
        n = len(self.dropped) - len(keep)
        self.dropped = keep
        return n

    def _redaction_rows(self, root: str | None = None) -> list[Document]:
        return [copy.deepcopy(r) for r in self._redactions.values()]

    def _redaction_put(self, entry: Document) -> None:
        self._redactions[entry["id"]] = copy.deepcopy(entry)

    def _redaction_remove(self, entry: Document) -> None:
        self._redactions.pop(entry["id"], None)

    def put_program(self, record: Document) -> None:
        self.programs[record["program_id"]] = copy.deepcopy(record)

    def list_programs(self) -> Iterator[Document]:
        yield from (copy.deepcopy(p) for p in self.programs.values())

    def clear_programs(self) -> None:
        self.programs.clear()

    def add_samples(self, samples: list[Document]) -> None:
        for s in samples:
            self.samples.setdefault(s["sample_id"], copy.deepcopy(s))

    def get_samples(self, ids: Iterable[str]) -> dict[str, Document]:
        return {i: copy.deepcopy(self.samples[i]) for i in ids if i in self.samples}

    def set_sample_llm(self, sample_id: str, llm: Document) -> None:
        if sample_id in self.samples:
            self.samples[sample_id]["llm"] = copy.deepcopy(llm)

    def iter_samples(self) -> Iterator[Document]:
        yield from (copy.deepcopy(s) for s in list(self.samples.values()))

    def page_records(self, after: Any, limit: int) -> tuple[list[Document], Any]:
        keys = sorted(k for k in self.docs if after is None or k > tuple(after))[:limit]
        return [copy.deepcopy(self.docs[k]) for k in keys], (list(keys[-1]) if keys else after)

    def prune_samples(self) -> int:
        named = {d.get("sample_id") for d in self.docs.values()}
        gone = [sid for sid in self.samples if sid not in named]
        for sid in gone:
            del self.samples[sid]
        return len(gone)

    def put_member_set(self, header: Document, rows: list[Document]) -> bool:
        mid = header["members_id"]
        if self.member_sets.get(mid, {}).get("digest") == header["digest"]:
            return False
        self.member_sets.pop(mid, None)
        self.set_rows[mid] = [{**copy.deepcopy(r), "members_id": mid} for r in rows]
        self.member_sets[mid] = copy.deepcopy(header)
        return True

    def list_member_set(self, members_id: str) -> Iterator[Document]:
        rows = self.set_rows.get(members_id, [])
        yield from (copy.deepcopy(r) for r in sorted(rows, key=lambda r: r["index"]))

    def iter_member_sets(self) -> Iterator[Document]:
        yield from (copy.deepcopy(h) for h in list(self.member_sets.values()))

    def prune_member_sets(self) -> int:
        named = {d.get("members_id") for d in self.docs.values()}
        gone = [mid for mid in self.member_sets if mid not in named]
        for mid in gone:
            del self.member_sets[mid]
            self.set_rows.pop(mid, None)
        return len(gone)
