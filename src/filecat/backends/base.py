"""The storage interface every backend implements.

Required by the spec: put(document), get(root, rel_path), list(kind), summary().
The rest are what scan, summary, programs, import and enrich need.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

# Paths per get_stats() query: well inside every server's parameter limit
# (SQL Server allows 2100).
STATS_CHUNK = 500


def root_id_of(root: str) -> str:
    from ..record import root_id
    return root_id(root)


def chunks(items: list[Any], size: int = STATS_CHUNK) -> Iterator[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]

Document = dict[str, Any]


def dropped_now(at: datetime | None = None) -> str:
    """dropped_at timestamp: UTC, seconds, so entries compare as strings."""
    return (at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")


class Backend(ABC):
    name: str = "base"

    # --- documents -----------------------------------------------------
    @abstractmethod
    def put(self, document: Document) -> None:
        """Insert or replace by (root_id, rel_path)."""

    def put_many(self, documents: Iterable[Document]) -> None:
        for doc in documents:
            self.put(doc)

    @abstractmethod
    def get(self, root: str, rel_path: str) -> Document | None:
        """root is the root path string (root_id is derived from it)."""

    @abstractmethod
    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        """Documents, optionally filtered by kind and/or root path string."""

    def get_stats(self, root: str, rel_paths: list[str]) -> dict[str, Document]:
        """The stored records of `rel_paths` under `root`, keyed by rel_path;
        paths with no record are left out. What a rescan compares: each has at
        least kind, size, mtime_ns and probe.child_count / probe.cloud, and a
        backend may leave out the rest. One query where the backend can, and
        unlike get() a server backend does not flush its write buffer first:
        buffered records are laid over what the query returns."""
        out = {}
        for p in rel_paths:
            doc = self.get(root, p)
            if doc is not None:
                out[p] = doc
        return out

    def _overlay_buffer(self, root: str, rel_paths: list[str], out: dict[str, Document]) -> None:
        """get_stats() helper for a backend whose write buffer is a list of
        documents: the newest buffered record of each path wins."""
        rid, wanted = root_id_of(root), set(rel_paths)
        for doc in getattr(self, "_buffer", ()):
            if doc.get("root_id") == rid and doc.get("rel_path") in wanted:
                out[doc["rel_path"]] = doc

    def list_sized(self, above: int, up_to: int | None = None,
                   root: str | None = None) -> Iterator[Document]:
        """Files (not folders) with above < size <= up_to (no upper bound when
        None). This default filters list() in Python; MongoDB selects them."""
        for d in self.list(root=root):
            size = d.get("size")
            if (d.get("kind") != "dir" and isinstance(size, int) and size > above
                    and (up_to is None or size <= up_to)):
                yield d

    @abstractmethod
    def delete(self, root: str, rel_path: str) -> None:
        """Remove one document; no error when absent."""

    def roots(self) -> list[str]:
        """Distinct root path strings in the catalog."""
        return sorted({d["root"] for d in self.list()})

    def query(self, q: dict[str, Any]) -> dict[str, Any]:
        """Filtered, sorted, paged records for `filecat serve`.

        q is a filecat.browse.normalize() query. Returns {"total": int,
        "bytes": int, "rows": [document, ...]} for the requested page. This
        default filters list() in Python; SQL backends push it into the server.
        """
        from ..browse import query_documents
        return query_documents(self.list(kind=q.get("kind"), root=q.get("root")), q)

    def subtree(self, root: str, parent: str) -> list[dict[str, Any]]:
        """Child folders of `parent` ("" = the root) with the readable files
        and bytes anywhere beneath each: [{"name", "files", "bytes"}],
        biggest first. Derived from file paths, so folders whose dir record
        is not written yet (mid-scan, imports with --no-dirs) still appear."""
        from ..browse import subtree_documents
        return subtree_documents(self.list(root=root), parent)

    def sizes(self, root: str, prefix: str = "") -> Iterator[tuple[str, int, str, str]]:
        """(rel_path, size, suffix, mime key) of every readable file beneath
        `prefix` ("" = the whole root), for the treemap. SQL backends select
        just these columns instead of reading the documents."""
        from ..browse import size_rows
        return size_rows(self.list(root=root), prefix)

    # --- aggregates ----------------------------------------------------
    # Stored aggregates are kept per root, each with the --depth its dir
    # table was cut at and when it was built, so one root can be saved or
    # rebuilt (a scan of one share, the web viewer) without touching the rest.
    def summary(self, root: str | None = None, depth: int = 2) -> dict[str, Any]:
        """Aggregates as built by filecat.aggregate.build_aggregates().

        Shape: {"roots": {root_string: {"suffix": [...], "mime": [...], "dir": [...],
                "total_files": int, "total_bytes": int, "unreadable": int}}}
        One entry per root, because percent is "of the bytes successfully
        sized in that root" -- mixing roots would make the percentages
        meaningless. `root=...` narrows the result to that one root's entry.
        A root whose stored aggregates were built at `depth` is read from
        storage (its entry also carries "depth" and "built_at"); any other
        root is computed from its documents.
        """
        out = {r: e for r, e in self.stored_aggregates(root).items() if e.get("depth") == depth}
        wanted = [root] if root is not None else self.roots()
        missing = [r for r in wanted if r not in out]
        if missing:
            from ..aggregate import build_aggregates
            if len(missing) == len(wanted):
                docs = self.list(root=root)
            else:
                docs = (d for r in missing for d in self.list(root=r))
            out.update(build_aggregates(docs, depth=depth)["roots"])
        return {"roots": out}

    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        """{root_string: summary entry + "depth" + "built_at"} for every root
        (or just `root`) with stored aggregates; {} when there are none."""
        return {}

    def rebuild_aggregates(self, depth: int = 2, root: str | None = None) -> None:
        """Recompute and store the aggregates of every root, or of `root` only
        (the other roots' stored aggregates are kept)."""
        from datetime import datetime, timezone
        from ..aggregate import build_aggregates
        self.flush()
        entries = build_aggregates(self.list(root=root), depth=depth)["roots"]
        self.replace_aggregates(entries, depth, datetime.now(timezone.utc).isoformat(), root)

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        """Store build_aggregates() entries. root=None replaces everything
        stored; otherwise only that root's stored aggregates are replaced."""
        raise NotImplementedError(f"{self.name} backend does not store aggregates")

    # --- archive members ----------------------------------------------
    # One row per member of an archive record (zip, tar, mpq, pck, x3 cat...),
    # stored apart from the document so a 200k-entry zip does not bloat it.
    # Member dict keys: index (int, order in the archive), path (str), and when
    # known: size, csize, mtime_ns, crc32, method, offset, flags, role, kind,
    # format, error. Backends add root_id / root / archive_rel_path.
    def put_members(self, root: str, rel_path: str, members: list[Document]) -> None:
        """Replace every stored member of archive (root, rel_path)."""
        raise NotImplementedError(f"{self.name} backend does not store archive members yet")

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        """Members of one archive, in index order."""
        raise NotImplementedError(f"{self.name} backend does not store archive members yet")

    def iter_all_members(self) -> Iterator[Document]:
        """Every stored member row (with root, archive_rel_path), for migrate."""
        raise NotImplementedError(f"{self.name} backend does not store archive members yet")

    def delete_members(self, root: str, rel_path: str) -> None:
        """Remove an archive's members; no error when none. delete() calls this too."""

    # --- member sets (filecat/member_sets.py) ----------------------------
    # A backend with stores_member_sets keeps the members of an archive that
    # has a content hash once per hash, however many copies of the archive
    # the catalog holds: a header {"members_id", "hash_type", "count",
    # "digest"} and rows carrying "members_id" instead of root and path. The
    # record names its set with "members_id". Archives without a hash keep
    # rows under (root, rel_path) as above.
    stores_member_sets: bool = False

    def put_member_set(self, header: Document, rows: list[Document]) -> bool:
        """Store `rows` as set header["members_id"], replacing a stored set
        unless that one has the same digest. Committed when this returns,
        header last, so a set with a header is complete. True when written."""
        raise NotImplementedError(f"{self.name} backend does not store member sets")

    def list_member_set(self, members_id: str) -> Iterator[Document]:
        """Rows of one set, in index order."""
        raise NotImplementedError(f"{self.name} backend does not store member sets")

    def iter_member_sets(self) -> Iterator[Document]:
        """Every set header."""
        raise NotImplementedError(f"{self.name} backend does not store member sets")

    def prune_member_sets(self) -> int:
        """Remove the sets no record names, with their rows; how many sets."""
        raise NotImplementedError(f"{self.name} backend does not store member sets")

    def prune_samples(self) -> int:
        """Remove the samples no record names; how many."""
        raise NotImplementedError(f"{self.name} backend does not store samples")

    def members_of(self, root: str, rel_path: str, doc: Document | None = None) -> Iterator[Document]:
        """Members of one archive record, wherever they are kept."""
        if doc is None:
            doc = self.get(root, rel_path)
        if doc is not None and doc.get("members_id") and self.stores_member_sets:
            return self.list_member_set(doc["members_id"])
        return self.list_members(root, rel_path)

    def store(self, document: Document) -> None:
        """put() a freshly measured document and its archive members.

        Measurement leaves members under document[MEMBERS_KEY]; they never
        go into the document itself. An archive with a hash files them as a
        member set before the record that names it is written.
        """
        from ..record import MEMBERS_KEY
        members = document.pop(MEMBERS_KEY, None)
        if self.stores_samples:
            from .. import samples
            sample = samples.split(document)
            if sample is not None:
                self.queue_sample(sample)   # reaches the store before the record does
        by_hash = False
        if members and self.stores_member_sets:
            from .. import member_sets
            by_hash = member_sets.store_rows(self, document, members)
        self.put(document)
        if members is not None:
            try:
                if by_hash:
                    # rows an earlier scan kept under the path
                    self.delete_members(document["root"], document["rel_path"])
                else:
                    self.put_members(document["root"], document["rel_path"], members)
            except NotImplementedError:
                pass  # backend predates member storage; the summary on probe remains

    # --- root index ----------------------------------------------------
    # One small document per root describing its scans (filecat.rootinfo):
    # {"root_id", "root", "last_attempt", "last_scan", "last_error",
    #  "newest_file", "updated_at"}. Stored apart from the file records and
    # written immediately (not buffered), so an interrupted scan still
    # leaves its "running" attempt behind.
    def put_root_info(self, info: Document) -> None:
        """Insert or replace by info['root_id']."""
        raise NotImplementedError(f"{self.name} backend does not store a root index yet")

    def list_root_info(self) -> Iterator[Document]:
        raise NotImplementedError(f"{self.name} backend does not store a root index yet")

    def get_root_info(self, root: str) -> Document | None:
        from ..record import root_id
        rid = root_id(root)
        return next((i for i in self.list_root_info() if i.get("root_id") == rid), None)

    def delete_root_info(self, root: str) -> None:
        """Remove a root's index entry; no error when absent. Its file
        records are not touched (roots_case moves them first)."""
        raise NotImplementedError(f"{self.name} backend does not store a root index yet")

    # --- stored treemaps ------------------------------------------------
    # Snapshots of treemap.build() for the Graph view of `filecat serve`
    # (policy in filecat.treemap): a small meta document {"id", "root_id",
    # "root", "prefix", "depth", "built_at", "files", "bytes", "pin"} and the
    # treemap itself, stored apart so listing snapshots never reads the data.
    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        """Insert or replace snapshot meta["id"] with its data; with data=None,
        replace only the meta of an existing snapshot (pin, unpin)."""
        raise NotImplementedError(f"{self.name} backend does not store treemaps")

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        """The metas of every stored snapshot, or of one root's."""
        raise NotImplementedError(f"{self.name} backend does not store treemaps")

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        """(meta, data) of one snapshot."""
        raise NotImplementedError(f"{self.name} backend does not store treemaps")

    def delete_treemap(self, treemap_id: str) -> None:
        """Remove one snapshot; no error when absent."""
        raise NotImplementedError(f"{self.name} backend does not store treemaps")

    # --- dropped records -----------------------------------------------
    # A record whose file or folder vanished from disk is moved to a
    # separate "dropped" store rather than deleted: the document as it was,
    # plus "dropped_at" (UTC ISO 8601, seconds) and "drop_reason". It no
    # longer shows in list/query/summary. Each drop is its own entry, so a
    # path that vanishes twice has two. purge_dropped() removes the entries
    # dropped before a cutoff; scan runs it with --keep-dropped (90 days).
    # Archive members of a dropped record are deleted, not kept.
    def drop(self, root: str, rel_path: str, reason: str = "vanished") -> bool:
        """Move one record to the dropped store; False when it is absent."""
        return self.drop_many(root, [rel_path], reason) == 1

    def drop_many(self, root: str, rel_paths: Iterable[str], reason: str = "vanished") -> int:
        """drop() each of `rel_paths` of `root`; returns how many existed.
        A backend without a dropped store just deletes them."""
        at = dropped_now()
        n = 0
        for rel_path in rel_paths:
            doc = self.get(root, rel_path)
            if doc is None:
                continue
            try:
                self.put_dropped({**doc, "dropped_at": at, "drop_reason": reason})
            except NotImplementedError:
                pass
            self.delete(root, rel_path)
            n += 1
        return n

    def put_dropped(self, document: Document) -> None:
        """Add one entry (a document carrying dropped_at) to the dropped store."""
        raise NotImplementedError(f"{self.name} backend does not keep dropped records")

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        """Dropped entries, optionally of one root, newest drop first."""
        raise NotImplementedError(f"{self.name} backend does not keep dropped records")

    def purge_dropped(self, before: str) -> int:
        """Remove entries whose dropped_at is earlier than `before` (same
        ISO format as dropped_now()); returns how many were removed."""
        raise NotImplementedError(f"{self.name} backend does not keep dropped records")

    # --- installed programs -------------------------------------------
    @abstractmethod
    def put_program(self, record: Document) -> None:
        """Insert or replace by record['program_id']."""

    @abstractmethod
    def list_programs(self) -> Iterator[Document]:
        ...

    def clear_programs(self) -> None:
        """Remove all program records before a fresh programs scan."""

    # --- content-keyed samples ------------------------------------------
    # One document per content hash (filecat/samples.py): {"sample_id",
    # "hash_type", "size", "encoding", "sample", "sample_truncated", "llm"}.
    # A file record with a hash keeps "sample_id" instead of the text. A
    # backend with stores_samples False keeps the text inline instead.
    stores_samples: bool = False
    # True when the backend's own record flush calls flush_samples() first,
    # so queued samples may wait for it; otherwise queue_sample writes at once.
    batches_samples: bool = False
    SAMPLE_BATCH = 500

    def add_samples(self, samples: list[Document]) -> None:
        """Insert each sample whose sample_id is not stored yet; a stored one
        is left as it is. Committed when this returns."""
        raise NotImplementedError(f"{self.name} backend does not store samples")

    def get_samples(self, ids: Iterable[str]) -> dict[str, Document]:
        """{sample_id: sample} for the ids that are stored."""
        raise NotImplementedError(f"{self.name} backend does not store samples")

    def set_sample_llm(self, sample_id: str, llm: Document) -> None:
        """Store an Ollama result on a stored sample (replacing any earlier one)."""
        raise NotImplementedError(f"{self.name} backend does not store samples")

    def iter_samples(self) -> Iterator[Document]:
        raise NotImplementedError(f"{self.name} backend does not store samples")

    def page_records(self, after: Any, limit: int) -> tuple[list[Document], Any]:
        """Up to `limit` records after cursor `after` (None: from the start),
        in an order that rewriting a record does not change, and the cursor
        of the last one. Cursors are JSON values, so a long pass over the
        records (samples.migrate) can checkpoint and resume."""
        raise NotImplementedError(f"{self.name} backend cannot page through records")

    def queue_sample(self, sample: Document) -> None:
        queue: dict[str, Document] = self.__dict__.setdefault("_sample_queue", {})
        queue.setdefault(sample["sample_id"], sample)
        if not self.batches_samples or len(queue) >= self.SAMPLE_BATCH:
            self.flush_samples()

    def flush_samples(self) -> None:
        queue = self.__dict__.get("_sample_queue")
        if queue:
            self.add_samples(list(queue.values()))
            queue.clear()

    # --- lifecycle -----------------------------------------------------
    def flush(self) -> None:
        """Commit / write buffered work. Called periodically and at close."""

    def close(self) -> None:
        self.flush()

    def __enter__(self) -> "Backend":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
