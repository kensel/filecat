"""`filecat mongo-rebuild`: rebuild MongoDB collections in place with zstd
block compression and the partial `sha256` index, one collection at a time.

A collection created by an older filecat keeps the compression it was
created with (snappy, MongoDB's default) and a `sha256` index over every
record; the backend only creates new collections the v0.1.3 way. This
rewrites an existing one (research note 05, section 2.C) without a second
database:

1. `<name>__rebuild` is created with zstd (a leftover from a stopped run is
   dropped first);
2. the documents are copied into it on the server (`$merge`, by `_id`);
3. its indexes are created as the original's are, with `files.sha256` made
   partial (only records that have a hash);
4. the counts are compared, and on a match `renameCollection` swaps it in
   for the original (dropTarget), which is dropped.

A collection already on zstd whose indexes are right is left alone; one on
zstd whose only fault is the `sha256` index gets that index rebuilt instead.
Nothing may write meanwhile: what reaches the original after step 2 is lost
with it. So the command refuses while a scan is running (`--force` to go
ahead) and should not run beside `filecat serve` edits or enrich. It needs
free disk space for a compressed copy of the largest collection rebuilt.
`--dry-run` prints the plan and the sizes.
"""
from __future__ import annotations

import sys
import time
from typing import Any

from . import rootinfo

COLLECTIONS = ("files", "members", "samples", "member_sets", "set_members")
ZSTD = {"wiredTiger": {"configString": "block_compressor=zstd"}}
SUFFIX = "__rebuild"
# Index options carried over to the copy.
INDEX_OPTIONS = ("name", "unique", "sparse", "partialFilterExpression", "expireAfterSeconds",
                 "collation", "hidden")
SHA256_PARTIAL = {"sha256": {"$type": "string"}}


def storage(db: Any, name: str) -> dict[str, Any]:
    """{"count", "size", "storage_size", "compressor"} of one collection."""
    try:
        stats = next(db[name].aggregate([{"$collStats": {"storageStats": {}}}]))["storageStats"]
    except StopIteration:
        stats = {}
    created = (stats.get("wiredTiger") or {}).get("creationString", "")
    compressor = next((part.split("=", 1)[1] for part in created.split(",")
                       if part.startswith("block_compressor=")), "")
    return {"count": stats.get("count", 0), "size": stats.get("size", 0),
            "storage_size": stats.get("storageSize", 0), "compressor": compressor or "?"}


def _index_specs(coll: Any) -> list[tuple[list[tuple[str, Any]], dict[str, Any]]]:
    """(keys, options) of every index but _id, as the copy should have them."""
    specs = []
    for ix in coll.list_indexes():
        if ix["name"] == "_id_":
            continue
        keys = list(ix["key"].items())
        opts = {k: ix[k] for k in INDEX_OPTIONS if k in ix}
        if coll.name == "files" and keys == [("sha256", 1)]:
            opts["partialFilterExpression"] = SHA256_PARTIAL
        specs.append((keys, opts))
    return specs


def _sha256_index_ok(coll: Any) -> bool:
    ix = coll.index_information().get("sha256_1")
    return ix is None or ix.get("partialFilterExpression") == SHA256_PARTIAL


def plan(db: Any, names: list[str]) -> list[tuple[str, str, dict[str, Any]]]:
    """[(collection, action, storage)]; action is "rebuild", "index" (only
    the sha256 index) or "ok"."""
    existing = set(db.list_collection_names())
    out = []
    for name in names:
        if name not in existing:
            continue
        info = storage(db, name)
        if info["compressor"] != "zstd":
            action = "rebuild"
        elif name == "files" and not _sha256_index_ok(db[name]):
            action = "index"
        else:
            action = "ok"
        out.append((name, action, info))
    return out


def rebuild(db: Any, name: str, say=print) -> dict[str, Any]:
    """Rebuild one collection in place; returns its storage() afterwards.
    Raises RuntimeError, with the original untouched, when the copy's count
    does not match."""
    src, tmp = db[name], db[name + SUFFIX]
    if name + SUFFIX in db.list_collection_names():
        tmp.drop()      # a stopped run's copy
    db.create_collection(name + SUFFIX, storageEngine=ZSTD)
    started = time.monotonic()
    say(f"  {name}: copying into {name + SUFFIX} (zstd)")
    src.aggregate([{"$merge": {"into": name + SUFFIX, "on": "_id",
                               "whenMatched": "replace", "whenNotMatched": "insert"}}],
                  allowDiskUse=True)
    for keys, opts in _index_specs(src):
        say(f"  {name}: index {opts.get('name', keys)}")
        tmp.create_index(keys, **opts)
    want, got = src.count_documents({}), tmp.count_documents({})
    if want != got:
        tmp.drop()
        raise RuntimeError(f"{name}: the copy has {got} documents, the original {want}; "
                           "left as it was (was something writing to it?)")
    tmp.rename(name, dropTarget=True)
    say(f"  {name}: swapped in ({time.monotonic() - started:.0f}s)")
    return storage(db, name)


def rebuild_sha256_index(db: Any, say=print) -> None:
    files = db["files"]
    say("  files: rebuilding the sha256 index as a partial index")
    files.drop_index("sha256_1")
    files.create_index("sha256", partialFilterExpression=SHA256_PARTIAL)


def _mib(n: int) -> str:
    return f"{n / 2**20:,.0f} MiB"


def run(args: Any) -> int:
    from .backends import open_backend
    if args.backend != "mongodb":
        print("filecat mongo-rebuild: only for the mongodb backend (--backend mongodb --dsn ...)",
              file=sys.stderr)
        return 2
    with open_backend(args.backend, None, args.dsn) as backend:
        db = backend.db
        names = args.collection or list(COLLECTIONS)
        steps = plan(db, names)
        print(f"{'collection':<14}{'documents':>14}{'data':>14}{'on disk':>14}  compression  action")
        for name, action, info in steps:
            print(f"{name:<14}{info['count']:>14,}{_mib(info['size']):>14}{_mib(info['storage_size']):>14}"
                  f"  {info['compressor']:<11}  {action}")
        todo = [(n, a, i) for n, a, i in steps if a != "ok"]
        if not todo:
            print("nothing to rebuild")
            return 0
        if args.dry_run:
            biggest = max((i["storage_size"] for _, a, i in todo if a == "rebuild"), default=0)
            print(f"dry run; a rebuild needs free disk space for a compressed copy of each "
                  f"collection in turn (the largest is {_mib(biggest)} on disk now)")
            return 0
        busy = rootinfo.in_progress(backend)
        if busy and not args.force:
            print(f"filecat mongo-rebuild: a scan is running on {', '.join(busy)}; what it writes "
                  "during a rebuild would be lost. Rebuild when it has finished (--force to go ahead)",
                  file=sys.stderr)
            return 1
        for name, action, info in todo:
            if action == "index":
                rebuild_sha256_index(db)
                continue
            try:
                after = rebuild(db, name)
            except RuntimeError as e:
                print(f"filecat mongo-rebuild: {e}", file=sys.stderr)
                return 1
            print(f"{name}: {_mib(info['storage_size'])} -> {_mib(after['storage_size'])} on disk, "
                  f"{after['compressor']}")
    return 0
