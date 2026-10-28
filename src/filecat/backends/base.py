"""The storage interface every backend implements.

Required by the spec: put(document), get(root, rel_path), list(kind), summary().
The rest are what scan, summary, programs, import and enrich need.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from ..record import is_file_kind

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
            if (is_file_kind(d.get("kind")) and isinstance(size, int) and size > above
                    and (up_to is None or size <= up_to)):
                yield d

    @abstractmethod
    def delete(self, root: str, rel_path: str) -> None:
        """Remove one document; no error when absent."""

    def delete_many(self, root: str, rel_paths: Iterable[str]) -> int:
        """Hard-delete each of `rel_paths` (and their archive members); not
        drop_many: these records are replaced, not vanished (a path now rolled
        up, docs/rollups.md section 1). Returns how many existed. This default
        goes one at a time; backends with a bulk delete override it."""
        n = 0
        for rel_path in rel_paths:
            if self.get(root, rel_path) is not None:
                self.delete(root, rel_path)
                n += 1
        return n

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

    def rollups(self, root: str, prefix: str = "") -> Iterator[Document]:
        """The rollup records of `root` beneath folder `prefix` ("" = all),
        full documents. `kind` is an indexed column, so this reads only them."""
        start = prefix + "/" if prefix else ""
        for doc in self.list(kind="rollup", root=root):
            if (doc.get("rel_path") or "").startswith(start):
                yield doc

    def rollup_totals(self, root: str | None = None) -> dict[str, list[dict[str, Any]]]:
        """{root: [{tag, parent, folders, matched, total_files, total_dirs, size,
        allocated_size, newest_mtime_ns, oldest_mtime_ns, errors, partial,
        rules}]} summed over rollup records, one row per (tag, parent folder);
        what `rollups list` and the reports read."""
        out: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}
        for doc in self.list(kind="rollup", root=root):
            info = (doc.get("probe") or {}).get("rollup") or {}
            tag = info.get("tag") or doc.get("name")
            rel = doc.get("rel_path") or ""
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            row = out.setdefault(doc["root"], {}).setdefault((tag, parent), {
                "tag": tag, "parent": parent, "folders": 0, "matched": 0, "total_files": 0,
                "total_dirs": 0, "size": 0, "allocated_size": 0, "newest_mtime_ns": 0,
                "oldest_mtime_ns": None, "errors": 0, "partial": 0, "rules": {}})
            row["folders"] += 1
            row["matched"] += info.get("matched", 0)
            row["total_files"] += info.get("total_files", 0)
            row["total_dirs"] += info.get("total_dirs", 0)
            row["size"] += doc.get("size") or 0
            row["allocated_size"] += doc.get("allocated_size") or 0
            row["newest_mtime_ns"] = max(row["newest_mtime_ns"], info.get("newest_mtime_ns") or 0)
            old = info.get("oldest_mtime_ns")
            if old is not None and (row["oldest_mtime_ns"] is None or old < row["oldest_mtime_ns"]):
                row["oldest_mtime_ns"] = old
            row["errors"] += info.get("errors", 0)
            row["partial"] += 1 if info.get("partial") else 0
            kind = (info.get("rule") or "").split(":", 1)[0] or "?"
            row["rules"][kind] = row["rules"].get(kind, 0) + 1
        return {r: sorted(rows.values(), key=lambda x: (x["tag"] or "", x["parent"]))
                for r, rows in out.items()}

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

    def purge_dropped_paths(self, root: str, rel_paths: Iterable[str]) -> int:
        """Remove the dropped entries of `root` at or beneath any of
        `rel_paths` (folders just replaced by a rollup: their old names must
        not survive in the dropped store). Returns how many entries."""
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

    # --- sticky redactions (filecat/redaction.py) ----------------------------
    # One entry per folder that was ever redacted, without its name:
    # {"id", "root_id", "root", "parent", "path_hash", "dev", "ino", "status",
    #  "source", "created", "last_seen", "released", "key_id"}. Unique by
    # (root_id, path_hash). A backend implements the three row primitives;
    # the contract below is written on top of them. Not in `dropped`, not in
    # treemap snapshots, not in exports.
    def _redaction_rows(self, root: str | None = None) -> list[Document]:
        raise NotImplementedError(f"{self.name} backend does not store redactions")

    def _redaction_put(self, entry: Document) -> None:
        """Insert or replace by entry["id"]."""
        raise NotImplementedError(f"{self.name} backend does not store redactions")

    def _redaction_remove(self, entry: Document) -> None:
        raise NotImplementedError(f"{self.name} backend does not store redactions")

    def put_redaction(self, entry: Document) -> None:
        """Add or replace the entry with this id. Another entry of the same
        root with the same path_hash is replaced too (one entry per folder)."""
        for other in self._redaction_rows():
            if (other["id"] != entry["id"] and other.get("root_id") == entry.get("root_id")
                    and other.get("path_hash") == entry.get("path_hash")):
                self._redaction_remove(other)
        self._redaction_put(dict(entry))

    def redactions(self, root: str | None = None, status: str | None = None) -> list[Document]:
        rows = self._redaction_rows(root)
        if root is not None:
            rid = root_id_of(root)
            rows = [r for r in rows if r.get("root_id") == rid]
        if status is not None:
            rows = [r for r in rows if r.get("status") == status]
        return sorted(rows, key=lambda r: (r.get("root") or "", r.get("created") or "", r["id"]))

    def _redaction(self, entry_id: str) -> Document:
        for row in self._redaction_rows():
            if row["id"] == entry_id:
                return row
        raise KeyError(entry_id)

    def touch_redaction(self, entry_id: str, last_seen: str) -> None:
        self._redaction_put({**self._redaction(entry_id), "last_seen": last_seen})

    def set_redaction_status(self, entry_id: str, status: str, released: str | None = None) -> None:
        row = {**self._redaction(entry_id), "status": status}
        if released is not None:
            row["released"] = released
        self._redaction_put(row)

    def update_redaction_identity(self, entry_id: str, path_hash: str, dev: int | None,
                                  ino: int | None, parent: str) -> None:
        """A rename: the folder has a new path (hash and parent), the same inode."""
        row = {**self._redaction(entry_id), "path_hash": path_hash, "parent": parent}
        if ino:
            row["dev"], row["ino"] = dev or 0, ino
        self.put_redaction(row)

    def delete_redaction(self, entry_id: str) -> None:
        for row in self._redaction_rows():
            if row["id"] == entry_id:
                self._redaction_remove(row)

    # --- storage topology (filecat/topology_store.py) -------------------------
    # Two small stores of whole documents, each keyed by a string "key" inside the document:
    # "storage_topology" (one document per host snapshot, key = the lowercased host name) and
    # "storage_topology_history" (one row per structure change, key = "<host>@<scanned_at>").
    # A backend implements the three row primitives; the rest is written on top of them.
    # Hosts written by hand in filecat.toml are not stored here (they are merged at read time).
    TOPOLOGY_STORES = ("storage_topology", "storage_topology_history")
    # The same row shape (key, host, scanned_at, document) also holds the filecat server's state:
    # "server_jobs" (one row per job run, key = "<started_at>#<job>") and "server_state" (the single
    # lease row and the last agent states). docs/agent-server.md section 6.
    SERVER_STORES = ("server_jobs", "server_state")
    DOC_STORES = TOPOLOGY_STORES + SERVER_STORES

    def _topology_rows(self, store: str) -> list[Document]:
        """Every document of `store` (one of TOPOLOGY_STORES)."""
        raise NotImplementedError(f"{self.name} backend does not store the storage topology")

    def _topology_put(self, store: str, doc: Document) -> None:
        """Insert or replace the document of `store` with this doc["key"]."""
        raise NotImplementedError(f"{self.name} backend does not store the storage topology")

    def _topology_remove(self, store: str, key: str) -> None:
        raise NotImplementedError(f"{self.name} backend does not store the storage topology")

    def put_topology(self, doc: Document) -> None:
        """Add or replace the snapshot of doc["host"]; its key is the lowercased host."""
        self._topology_put("storage_topology", {**doc, "key": doc["host"].lower()})

    def topologies(self) -> list[Document]:
        """The stored snapshot documents, by host."""
        return sorted(self._topology_rows("storage_topology"), key=lambda d: d["key"])

    def get_topology(self, host: str) -> Document | None:
        return next((d for d in self._topology_rows("storage_topology") if d["key"] == host.lower()), None)

    def delete_topology(self, host: str) -> None:
        """Forget a host's snapshot (its history rows stay)."""
        self._topology_remove("storage_topology", host.lower())

    def add_topology_history(self, row: Document) -> None:
        """A history row {"host", "scanned_at", ...}; one per (host, scanned_at)."""
        self._topology_put("storage_topology_history",
                           {**row, "key": f"{row['host'].lower()}@{row['scanned_at']}"})

    # --- the filecat server's state (filecat/server_store.py) -------------------------
    def put_server_doc(self, store: str, doc: Document) -> None:
        """Insert or replace a document of "server_jobs" or "server_state" (doc["key"], doc["host"])."""
        assert store in self.SERVER_STORES
        self._topology_put(store, doc)

    def server_docs(self, store: str) -> list[Document]:
        assert store in self.SERVER_STORES
        return self._topology_rows(store)

    def delete_server_doc(self, store: str, key: str) -> None:
        assert store in self.SERVER_STORES
        self._topology_remove(store, key)

    def topology_history(self, host: str | None = None) -> list[Document]:
        """History rows, oldest first, optionally of one host."""
        rows = self._topology_rows("storage_topology_history")
        if host is not None:
            rows = [r for r in rows if r["host"].lower() == host.lower()]
        return sorted(rows, key=lambda r: (r["scanned_at"], r["key"]))

    # --- lifecycle -----------------------------------------------------
    def scrub(self) -> None:
        """After a purge: make the storage forget what was deleted, where it
        can (SQLite's write-ahead log). Most backends have nothing to do."""

    def flush(self) -> None:
        """Commit / write buffered work. Called periodically and at close."""

    def close(self) -> None:
        self.flush()

    def __enter__(self) -> "Backend":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
