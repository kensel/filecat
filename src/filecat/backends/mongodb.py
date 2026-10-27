"""MongoDB backend: pymongo. Collection `files` stores the catalog document
itself (no extra wrapper -- root_id, rel_path, sha256, kind, suffix, mime
are already top-level document fields, so they are indexed directly).

The driver import happens inside __init__ so importing this module does
not require pymongo unless the mongodb backend is actually used.

Writes are batched with `bulk_write([ReplaceOne(..., upsert=True), ...])`
every BATCH_SIZE puts or BATCH_SECONDS. `list()`/`list_programs()` hand
back `find()` cursors directly -- pymongo already streams those in
server-side batches, it never materializes the whole collection.

Aggregates are computed in Python (`filecat.aggregate.build_aggregates`)
rather than with Mongo's aggregation pipeline: the directory-depth cut is
awkward to express as a pipeline stage, and the collections here are not
expected to be the million-row case that motivates SQL GROUP BY in the
sqlite backend. Results are still stored in agg_suffix/agg_mime/agg_dir/
agg_meta collections so `summary()` can read them back without recomputing.
"""
from __future__ import annotations

import json
import time
from typing import Any, Iterable, Iterator

from ..record import root_id
from .base import Backend, Document, chunks

BATCH_SIZE = 500
BATCH_SECONDS = 2.0
DEFAULT_DB = "filecat"     # when the DSN names no database (mongodb://host:27017/)


def ping(dsn: str, timeout: float = 5.0) -> dict[str, Any]:
    """Read-only connection check for `filecat config test`."""
    import pymongo
    ms = int(timeout * 1000)
    client = pymongo.MongoClient(dsn, serverSelectionTimeoutMS=ms, connectTimeoutMS=ms)
    try:
        db = client.get_default_database(DEFAULT_DB)
        build = client.admin.command("buildInfo")
        status = db.command("connectionStatus")
        users = [u.get("user") for u in status.get("authInfo", {}).get("authenticatedUsers", [])]
        info: dict[str, Any] = {"server": f"MongoDB {build.get('version')}", "database": db.name,
                                "user": ",".join(u for u in users if u) or "(no auth)"}
        names = set(db.list_collection_names())
        info["tables"] = sorted(names & {"files", "members"})
        if "files" in names:
            info["files_estimate"] = db["files"].estimated_document_count()
        return info
    finally:
        client.close()


_INT64 = 2 ** 63


def _bson_safe(value: Any) -> Any:
    """`value` with every int outside BSON's int64 range as a string."""
    if isinstance(value, dict):
        return {k: _bson_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_bson_safe(v) for v in value]
    if isinstance(value, int) and not isinstance(value, bool) and not -_INT64 <= value < _INT64:
        return str(value)
    return value


class MongoBackend(Backend):
    name = "mongodb"
    stores_samples = True
    batches_samples = True
    stores_member_sets = True

    def __init__(self, dsn: str) -> None:
        import pymongo  # lazy: only needed when this backend is used
        from pymongo import ReplaceOne
        self._pymongo = pymongo
        self._ReplaceOne = ReplaceOne
        self.dsn = dsn
        self.client = pymongo.MongoClient(dsn)
        self.db = self.client.get_default_database(DEFAULT_DB)
        self.files = self.db["files"]
        self.programs = self.db["programs"]
        self.members = self.db["members"]
        self.agg_suffix = self.db["agg_suffix"]
        self.agg_mime = self.db["agg_mime"]
        self.agg_dir = self.db["agg_dir"]
        self.agg_meta = self.db["agg_meta"]

        # Collections created here start out with zstd block compression
        # (research note 05, section 2.C); existing ones keep what they were
        # created with until `filecat migrate` copies them into a new database.
        existing = set(self.db.list_collection_names())
        for name in ("files", "members", "samples", "member_sets", "set_members"):
            if name not in existing:
                try:
                    self.db.create_collection(
                        name, storageEngine={"wiredTiger": {"configString": "block_compressor=zstd"}})
                except pymongo.errors.CollectionInvalid:
                    pass    # created meanwhile by another process
        self.samples = self.db["samples"]
        self.member_sets = self.db["member_sets"]
        self.set_members = self.db["set_members"]

        self.files.create_index([("root_id", 1), ("rel_path", 1)], unique=True)
        if "sha256_1" not in self.files.index_information():
            # Only records that have one: listed-only data has no hash.
            self.files.create_index("sha256", partialFilterExpression={"sha256": {"$type": "string"}})
        self.files.create_index("size")     # list_sized: `filecat dupes` size bands
        self.files.create_index("kind")
        self.files.create_index("suffix")
        self.files.create_index("mime")
        self.members.create_index(
            [("root_id", 1), ("archive_rel_path", 1), ("index", 1)], unique=True)
        self.members.create_index("role")
        self.members.create_index("path")
        self.set_members.create_index([("members_id", 1), ("index", 1)], unique=True)
        self.set_members.create_index("role")
        self.set_members.create_index("path")
        self.root_docs = self.db["roots"]
        self.root_docs.create_index("root_id", unique=True)
        self.dropped = self.db["dropped"]
        self.treemaps = self.db["treemaps"]
        self.redaction_docs = self.db["redactions"]
        self.redaction_docs.create_index("id", unique=True)
        self.redaction_docs.create_index([("root_id", 1), ("path_hash", 1)], unique=True)
        self.topology_docs = {store: self.db[store] for store in self.TOPOLOGY_STORES}
        for coll in self.topology_docs.values():
            coll.create_index("key", unique=True)
        self.topology_docs["storage_topology_history"].create_index([("host", 1), ("scanned_at", 1)])
        self.dropped.create_index("dropped_at")
        self.dropped.create_index([("root_id", 1), ("rel_path", 1)])
        self.agg_meta.create_index("root_id", unique=True)
        self.agg_suffix.create_index([("root_id", 1), ("suffix", 1)], unique=True)
        self.agg_mime.create_index([("root_id", 1), ("mime", 1)], unique=True)
        self.agg_dir.create_index([("root_id", 1), ("dir", 1)], unique=True)

        self._buffer: list[Document] = []
        self._last_flush = time.monotonic()

    # --- documents -------------------------------------------------
    # BSON integers are 64-bit; Python's are not, and a corrupt archive or
    # disk image can yield a value no field could really hold. Such a value
    # is stored as its decimal string instead of failing the whole write.
    def put(self, document: Document) -> None:
        self._buffer.append(document)
        if (len(self._buffer) >= BATCH_SIZE
                or (time.monotonic() - self._last_flush) >= BATCH_SECONDS):
            self.flush()

    def flush(self) -> None:
        self.flush_samples()    # a record never lands before the sample it names
        if not self._buffer:
            return
        ops = [
            self._ReplaceOne(
                {"root_id": doc["root_id"], "rel_path": doc["rel_path"]},
                _bson_safe(doc), upsert=True,
            )
            for doc in self._buffer
        ]
        self.files.bulk_write(ops, ordered=False)
        self._buffer.clear()
        self._last_flush = time.monotonic()

    def get(self, root: str, rel_path: str) -> Document | None:
        self.flush()
        doc = self.files.find_one({"root_id": root_id(root), "rel_path": rel_path}, {"_id": 0})
        return doc

    # What a rescan compares (Backend.get_stats); the rest of a record can be large.
    STAT_FIELDS = {"_id": 0, "root_id": 1, "rel_path": 1, "kind": 1, "size": 1, "mtime_ns": 1,
                   "probe.child_count": 1, "probe.cloud": 1}

    def get_stats(self, root: str, rel_paths: list[str]) -> dict[str, Document]:
        rid, out = root_id(root), {}
        for part in chunks(rel_paths):
            for doc in self.files.find({"root_id": rid, "rel_path": {"$in": part}}, self.STAT_FIELDS):
                out[doc["rel_path"]] = doc
        self._overlay_buffer(root, rel_paths, out)
        return out

    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        self.flush()
        query: dict[str, Any] = {}
        if kind is not None:
            query["kind"] = kind
        if root is not None:
            query["root_id"] = root_id(root)
        for doc in self.files.find(query, {"_id": 0}):
            yield doc

    def query(self, q: dict[str, Any]) -> dict[str, Any]:
        """Native filter: the same rules as browse.matches(), as a Mongo query."""
        self.flush()
        match = self._browse_filter(q)
        total = self.files.count_documents(match)
        agg = list(self.files.aggregate(
            [{"$match": match}, {"$group": {"_id": None, "bytes": {"$sum": "$size"}}}]))
        nbytes = int(agg[0]["bytes"]) if agg else 0
        pipeline: list[dict[str, Any]] = [{"$match": match}]
        sort: dict[str, int] = {}
        if "parent" in q:  # folders first, like a file manager
            pipeline.append({"$addFields": {"_notdir": {"$switch": {"branches": [
                {"case": {"$eq": ["$kind", "dir"]}, "then": 0},
                {"case": {"$eq": ["$kind", "rollup"]}, "then": 1}], "default": 2}}}})
            sort["_notdir"] = 1
        sort[q["sort"]] = -1 if q["desc"] else 1
        if q["sort"] != "rel_path":
            sort["rel_path"] = 1
        pipeline += [{"$sort": sort}, {"$skip": q["offset"]}, {"$limit": q["limit"]},
                     {"$project": {"_id": 0, "_notdir": 0}}]
        rows = list(self.files.aggregate(pipeline, allowDiskUse=True))
        return {"total": total, "bytes": nbytes, "rows": rows}

    def list_sized(self, above: int, up_to: int | None = None,
                   root: str | None = None) -> Iterator[Document]:
        self.flush()
        size: dict[str, int] = {"$gt": above}
        if up_to is not None:
            size["$lte"] = up_to
        query: dict[str, Any] = {"kind": {"$nin": ["dir", "rollup"]}, "size": size}
        if root is not None:
            query["root_id"] = root_id(root)
        yield from self.files.find(
            query, {"_id": 0, "root": 1, "rel_path": 1, "size": 1, "kind": 1, "probe.backup_data": 1})

    @staticmethod
    def _browse_filter(q: dict[str, Any]) -> dict[str, Any]:
        import re
        blank = [None, ""]
        has_errors = {"errors": {"$exists": True, "$nin": [None, [], "", {}]}}
        unreadable = {"$and": [{"size": None}, has_errors]}
        and_: list[dict[str, Any]] = []
        if q.get("root") is not None:
            and_.append({"root_id": root_id(q["root"])})
        if "kind" in q:
            and_.append({"kind": q["kind"]})
        if q.get("files_only"):
            and_ += [{"kind": {"$nin": ["dir", "rollup"]}}, {"$nor": [unreadable]}]
        if q.get("unreadable"):
            and_ += [{"kind": {"$nin": ["dir", "rollup"]}}, unreadable]
        if q.get("errors"):
            and_.append(has_errors)
        if "suffix" in q:
            and_.append({"suffix": {"$in": blank}} if q["suffix"] == "(none)"
                        else {"suffix": q["suffix"]})
        if "mime" in q:
            m = q["mime"]
            # key is mime, else kind, else "unknown" (a kind of "unknown" matches too)
            no_mime = {"mime": {"$in": blank}}
            alt = [{"mime": m}, {**no_mime, "kind": m}]
            if m == "unknown":
                alt.append({**no_mime, "kind": {"$in": blank}})
            and_.append({"$or": alt})

        def rel(pattern: str) -> dict[str, Any]:
            return {"rel_path": {"$regex": pattern, "$options": "s"}}

        if "dir" in q:
            key, depth = q["dir"], q["depth"]
            if key == ".":
                and_.append(rel(r"^[^/]+$"))
            elif len(key.split("/")) < depth:  # a shallow key holds only direct children
                and_.append(rel("^" + re.escape(key) + "/[^/]+$"))
            else:
                and_.append(rel("^" + re.escape(key) + "/.+"))
        if "parent" in q:
            p = q["parent"]
            and_.append(rel(r"^[^/]+$" if p == "" else "^" + re.escape(p) + "/[^/]+$"))
        if "q" in q:
            and_.append({"rel_path": {"$regex": re.escape(q["q"]), "$options": "i"}})
        return {"$and": and_} if and_ else {}

    def subtree(self, root: str, parent: str) -> list[dict[str, Any]]:
        """Child folders of `parent` with their readable files and bytes, grouped
        in Mongo by the path text between parent + '/' and the next '/'."""
        self.flush()
        q: dict[str, Any] = {"root": root, "files_only": True, "depth": 1}
        if parent:  # a dir key as deep as parent itself covers everything beneath it
            q["dir"], q["depth"] = parent, len(parent.split("/"))
        start = len(parent) + 1 if parent else 0
        rest = {"$substrCP": ["$rel_path", start, {"$strLenCP": "$rel_path"}]}
        cut = {"$indexOfCP": [rest, "/"]}
        pipeline = [
            {"$match": self._browse_filter(q)},
            {"$addFields": {"_cut": cut, "_rest": rest}},
            {"$match": {"_cut": {"$gt": 0}}},
            {"$group": {"_id": {"$substrCP": ["$_rest", 0, "$_cut"]},
                        "files": {"$sum": 1}, "bytes": {"$sum": "$size"}}},
        ]
        rows = self.files.aggregate(pipeline, allowDiskUse=True)
        return sorted(({"name": r["_id"], "files": int(r["files"]), "bytes": int(r["bytes"])}
                       for r in rows), key=lambda r: (-r["bytes"], r["name"]))

    def sizes(self, root: str, prefix: str = "") -> Iterator[tuple[str, int, str, str]]:
        """Only the fields the treemap needs, filtered in Mongo."""
        self.flush()
        q: dict[str, Any] = {"root": root, "files_only": True, "depth": 1}
        if prefix:
            q["dir"], q["depth"] = prefix, len(prefix.split("/"))
        fields = {"_id": 0, "rel_path": 1, "size": 1, "suffix": 1, "mime": 1, "kind": 1}
        for d in self.files.find(self._browse_filter(q), fields, batch_size=5000):
            if d.get("rel_path"):
                yield (d["rel_path"], int(d.get("size") or 0), d.get("suffix") or "",
                       d.get("mime") or d.get("kind") or "unknown")

    def delete(self, root: str, rel_path: str) -> None:
        self.flush()
        self.files.delete_one({"root_id": root_id(root), "rel_path": rel_path})
        self.delete_members(root, rel_path)

    def delete_many(self, root: str, rel_paths: Iterable[str]) -> int:
        self.flush()
        rid, n = root_id(root), 0
        for part in chunks(list(rel_paths)):
            n += self.files.delete_many({"root_id": rid, "rel_path": {"$in": part}}).deleted_count
            self.members.delete_many({"root_id": rid, "archive_rel_path": {"$in": part}})
        return n

    # --- archive members -------------------------------------------
    def put_members(self, root: str, rel_path: str, members: list) -> None:
        self.flush()
        rid = root_id(root)
        self.members.delete_many({"root_id": rid, "archive_rel_path": rel_path})
        docs = []
        for i, m in enumerate(members):
            full = {**m, "index": m.get("index", i), "root_id": rid, "root": root,
                     "archive_rel_path": rel_path}
            docs.append(full)
        if docs:
            self.members.insert_many(_bson_safe(docs), ordered=False)

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        self.flush()
        rid = root_id(root)
        cur = self.members.find(
            {"root_id": rid, "archive_rel_path": rel_path}, {"_id": 0}
        ).sort("index", 1)
        for doc in cur:
            yield doc

    def iter_all_members(self) -> Iterator[Document]:
        self.flush()
        for doc in self.members.find({}, {"_id": 0}):
            yield doc

    def delete_members(self, root: str, rel_path: str) -> None:
        rid = root_id(root)
        self.members.delete_many({"root_id": rid, "archive_rel_path": rel_path})

    def roots(self) -> list[str]:
        self.flush()
        return sorted(self.files.distinct("root"))

    # --- aggregates --------------------------------------------------
    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        self.flush()
        meta_query = {} if root is None else {"root": root}
        proj = {"_id": 0, "root_id": 0, "root": 0}
        roots_out: dict[str, Any] = {}
        for m in self.agg_meta.find(meta_query, {"_id": 0}):
            rid, rname = m["root_id"], m["root"]
            suffix = list(self.agg_suffix.find({"root_id": rid}, proj))
            mime = list(self.agg_mime.find({"root_id": rid}, proj))
            dirs = list(self.agg_dir.find({"root_id": rid}, proj))
            suffix.sort(key=lambda r: (-r["bytes"], str(r["suffix"])))
            mime.sort(key=lambda r: (-r["bytes"], str(r["mime"])))
            dirs.sort(key=lambda r: (-r["bytes"], str(r["dir"])))
            roots_out[rname] = {
                "suffix": suffix, "mime": mime, "dir": dirs,
                "total_files": m["total_files"], "total_bytes": m["total_bytes"],
                "unreadable": m["unreadable"], "depth": m.get("depth"), "built_at": m.get("built_at"),
            }
        return roots_out

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        query = {} if root is None else {"root_id": root_id(root)}
        for coll in (self.agg_suffix, self.agg_mime, self.agg_dir, self.agg_meta):
            coll.delete_many(query)
        for rname, e in entries.items():
            rid = root_id(rname)
            for coll, key in ((self.agg_suffix, "suffix"), (self.agg_mime, "mime"), (self.agg_dir, "dir")):
                if e[key]:
                    coll.insert_many([{**row, "root_id": rid, "root": rname} for row in e[key]])
            self.agg_meta.insert_one({
                "root_id": rid, "root": rname,
                "total_files": e["total_files"], "total_bytes": e["total_bytes"],
                "unreadable": e["unreadable"], "depth": depth, "built_at": built_at,
            })

    # --- dropped records ------------------------------------------------
    def put_dropped(self, document: Document) -> None:
        self.dropped.insert_one(_bson_safe(dict(document)))

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        query = {"root_id": root_id(root)} if root is not None else {}
        yield from self.dropped.find(query, {"_id": 0}).sort([("dropped_at", -1), ("_id", -1)])

    def purge_dropped(self, before: str) -> int:
        return self.dropped.delete_many({"dropped_at": {"$lt": before}}).deleted_count

    def purge_dropped_paths(self, root: str, rel_paths: Iterable[str]) -> int:
        import re
        rid, paths = root_id(root), list(rel_paths)
        if not paths:
            return 0
        pattern = "^(" + "|".join(re.escape(p) for p in paths) + ")(/|$)"
        return self.dropped.delete_many(
            {"root_id": rid, "rel_path": {"$regex": pattern}}).deleted_count

    # --- sticky redactions ---------------------------------------------
    def _redaction_rows(self, root: str | None = None) -> list[Document]:
        return list(self.redaction_docs.find({}, {"_id": 0}))

    def _redaction_put(self, entry: Document) -> None:
        self.redaction_docs.replace_one({"id": entry["id"]}, _bson_safe(dict(entry)), upsert=True)

    def _redaction_remove(self, entry: Document) -> None:
        self.redaction_docs.delete_one({"id": entry["id"]})

    # --- storage topology ------------------------------------------------
    def _topology_rows(self, store: str) -> list[Document]:
        return list(self.topology_docs[store].find({}, {"_id": 0}))

    def _topology_put(self, store: str, doc: Document) -> None:
        self.topology_docs[store].replace_one({"key": doc["key"]}, _bson_safe(dict(doc)), upsert=True)

    def _topology_remove(self, store: str, key: str) -> None:
        self.topology_docs[store].delete_one({"key": key})

    # --- root index ----------------------------------------------------
    def put_root_info(self, info: Document) -> None:
        self.root_docs.replace_one({"root_id": info["root_id"]}, _bson_safe(dict(info)), upsert=True)

    def list_root_info(self) -> Iterator[Document]:
        for doc in self.root_docs.find({}, {"_id": 0}).sort("root", 1):
            yield doc

    def get_root_info(self, root: str) -> Document | None:
        return self.root_docs.find_one({"root_id": root_id(root)}, {"_id": 0})

    def delete_root_info(self, root: str) -> None:
        self.root_docs.delete_one({"root_id": root_id(root)})

    # --- stored treemaps ---------------------------------------------
    # {_id: id, root_id, meta, data}; the data is kept as JSON text so its
    # size and keys never meet BSON's limits on numbers or field names.
    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        if data is None:
            self.treemaps.update_one({"_id": meta["id"]}, {"$set": {"meta": _bson_safe(dict(meta))}})
            return
        self.treemaps.replace_one(
            {"_id": meta["id"]},
            {"_id": meta["id"], "root_id": meta["root_id"], "meta": _bson_safe(dict(meta)),
             "data": json.dumps(data, ensure_ascii=False)}, upsert=True)

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        query = {} if root is None else {"root_id": root_id(root)}
        return [d["meta"] for d in self.treemaps.find(query, {"meta": 1})]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        d = self.treemaps.find_one({"_id": treemap_id})
        return (d["meta"], json.loads(d["data"])) if d else None

    def delete_treemap(self, treemap_id: str) -> None:
        self.treemaps.delete_one({"_id": treemap_id})

    # --- installed programs -------------------------------------------
    def put_program(self, record: Document) -> None:
        self.programs.replace_one({"program_id": record["program_id"]}, _bson_safe(record), upsert=True)

    def list_programs(self) -> Iterator[Document]:
        for doc in self.programs.find({}, {"_id": 0}):
            yield doc

    def clear_programs(self) -> None:
        self.programs.delete_many({})

    # --- samples ---------------------------------------------------
    def add_samples(self, samples: list[Document]) -> None:
        from pymongo import UpdateOne
        if samples:
            self.samples.bulk_write(
                [UpdateOne({"_id": x["sample_id"]}, {"$setOnInsert": _bson_safe(x)}, upsert=True)
                 for x in samples], ordered=False)

    def get_samples(self, ids: Iterable[str]) -> dict[str, Document]:
        ids = list(ids)
        if not ids:
            return {}
        return {d["sample_id"]: d for d in self.samples.find({"_id": {"$in": ids}}, {"_id": 0})}

    def set_sample_llm(self, sample_id: str, llm: Document) -> None:
        self.samples.update_one({"_id": sample_id}, {"$set": {"llm": _bson_safe(llm)}})

    def iter_samples(self) -> Iterator[Document]:
        self.flush_samples()
        yield from self.samples.find({}, {"_id": 0})

    def page_records(self, after: Any, limit: int) -> tuple[list[Document], Any]:
        from bson import ObjectId
        self.flush()
        query = {} if after is None else {"_id": {"$gt": ObjectId(after)}}
        docs = list(self.files.find(query).sort("_id", 1).limit(limit))
        if not docs:
            return [], after
        last = str(docs[-1]["_id"])
        for d in docs:
            d.pop("_id", None)
        return docs, last

    def _unnamed(self, field: str, coll: Any) -> Iterator[list[Any]]:
        """_ids of `coll`, in batches, that no record names in `field`. The
        names are gathered on the server into a scratch collection first."""
        scratch = f"prune_{field}"
        self.files.aggregate([{"$match": {field: {"$type": "string"}}},
                              {"$group": {"_id": "$" + field}}, {"$out": scratch}], allowDiskUse=True)
        try:
            cur = coll.aggregate([{"$lookup": {"from": scratch, "localField": "_id",
                                               "foreignField": "_id", "as": "named"}},
                                  {"$match": {"named": {"$size": 0}}}, {"$project": {"_id": 1}}],
                                 allowDiskUse=True)
            batch: list[Any] = []
            for d in cur:
                batch.append(d["_id"])
                if len(batch) >= 1000:
                    yield batch
                    batch = []
            if batch:
                yield batch
        finally:
            self.db.drop_collection(scratch)

    def prune_samples(self) -> int:
        self.flush()
        n = 0
        for ids in self._unnamed("sample_id", self.samples):
            n += self.samples.delete_many({"_id": {"$in": ids}}).deleted_count
        return n

    # --- member sets -------------------------------------------------
    # No transactions: the header is removed first and written last, so a
    # set with a header always has all its rows.
    def put_member_set(self, header: Document, rows: list[Document]) -> bool:
        mid = header["members_id"]
        old = self.member_sets.find_one({"_id": mid}, {"digest": 1})
        if old and old.get("digest") == header["digest"]:
            return False
        self.member_sets.delete_one({"_id": mid})
        self.set_members.delete_many({"members_id": mid})
        if rows:
            self.set_members.insert_many(_bson_safe([{**r, "members_id": mid} for r in rows]), ordered=False)
        self.member_sets.replace_one({"_id": mid}, {**header, "_id": mid}, upsert=True)
        return True

    def list_member_set(self, members_id: str) -> Iterator[Document]:
        self.flush()
        yield from self.set_members.find({"members_id": members_id}, {"_id": 0}).sort("index", 1)

    def iter_member_sets(self) -> Iterator[Document]:
        yield from self.member_sets.find({}, {"_id": 0})

    def prune_member_sets(self) -> int:
        self.flush()
        n = 0
        for ids in self._unnamed("members_id", self.member_sets):
            n += self.member_sets.delete_many({"_id": {"$in": ids}}).deleted_count
            self.set_members.delete_many({"members_id": {"$in": ids}})
        return n

    # --- lifecycle -------------------------------------------------
    def close(self) -> None:
        self.flush()
        self.client.close()
