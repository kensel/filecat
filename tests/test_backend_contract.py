"""Contract test: every backend implements put/get/list/delete/programs/summary
the same way. CI always exercises MemoryBackend, SqliteBackend and
JsonlBackend; the four server backends only run when their DSN env var is
set (FILECAT_TEST_POSTGRES / _MYSQL / _MSSQL / _MONGODB), per the spec's
"Backends" section.
"""
from __future__ import annotations

import copy
import os

import pytest

from filecat.backends.jsonl import JsonlBackend
from filecat.backends.jsonl_dir import JsonlDirBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.record import root_id

ROOT = r"C:\contract-test-root"


def _make_docs(root: str) -> list[dict]:
    rid = root_id(root)
    return [
        {
            "root_id": rid, "root": root, "rel_path": "a/b/café.txt",
            "name": "café.txt", "size": 123, "mtime_ns": 1_700_000_000_000_000_000,
            "kind": "text", "suffix": "txt", "mime": "text/plain",
            "probe": {"mime_glob": "text/plain", "mime_glob_desc": "Plain text",
                      "nested": {"a": 1, "b": [1, 2, 3]}},
            "encoding": {"detected": "utf-8"}, "newlines": "lf",
        },
        {
            # missing optional field: no mtime_ns, no mime, no probe
            "root_id": rid, "root": root, "rel_path": "data/file2.bin",
            "name": "file2.bin", "size": 0, "kind": "empty", "suffix": "bin",
        },
        {
            "root_id": rid, "root": root, "rel_path": "dir/sub/img.png",
            "name": "img.png", "size": 2048, "mtime_ns": 1_700_000_000_000_000_001,
            "kind": "image", "suffix": "png", "mime": "image/png",
            "probe": {"width": 10, "height": 10},
            "errors": [{"stage": "probe", "message": "partial read"}],
        },
    ]


def _make_backend(name: str, fixture_dir):
    if name == "memory":
        return MemoryBackend()
    if name == "sqlite":
        return SqliteBackend(str(fixture_dir / "catalog.sqlite"))
    if name == "jsonl":
        return JsonlBackend(str(fixture_dir / "catalog.jsonl"))
    if name == "jsonl_dir":
        return JsonlDirBackend(str(fixture_dir / "catalog-jsonl"))
    if name == "postgres":
        from filecat.backends.postgres import PostgresBackend
        return PostgresBackend(os.environ["FILECAT_TEST_POSTGRES"])
    if name == "mysql":
        from filecat.backends.mysql import MysqlBackend
        return MysqlBackend(os.environ["FILECAT_TEST_MYSQL"])
    if name == "mssql":
        from filecat.backends.mssql import MssqlBackend
        return MssqlBackend(os.environ["FILECAT_TEST_MSSQL"])
    if name == "mongodb":
        from filecat.backends.mongodb import MongoBackend
        return MongoBackend(os.environ["FILECAT_TEST_MONGODB"])
    raise ValueError(name)


def pytest_generate_tests(metafunc):
    if "backend_name" not in metafunc.fixturenames:
        return
    names = ["memory", "sqlite", "jsonl", "jsonl_dir"]
    env_flags = {
        "postgres": "FILECAT_TEST_POSTGRES",
        "mysql": "FILECAT_TEST_MYSQL",
        "mssql": "FILECAT_TEST_MSSQL",
        "mongodb": "FILECAT_TEST_MONGODB",
    }
    for name, flag in env_flags.items():
        if os.environ.get(flag):
            names.append(name)
    metafunc.parametrize("backend_name", names)


@pytest.fixture
def backend(backend_name, fixture_dir):
    be = _make_backend(backend_name, fixture_dir)
    _clear_root(be)   # a server database keeps rows from earlier runs and tests
    yield be
    _clear_root(be)
    be.close()


def _clear_root(be) -> None:
    for doc in list(be.list(root=ROOT)):
        be.delete(doc["root"], doc["rel_path"])
    be.flush()


def test_contract(backend, backend_name):
    docs = _make_docs(ROOT)

    for doc in docs:
        backend.put(copy.deepcopy(doc))
    backend.flush()

    # get() round-trips every field, including the unicode name, the nested
    # probe dict, and the doc that omits an optional field.
    for doc in docs:
        got = backend.get(ROOT, doc["rel_path"])
        assert got is not None, f"missing after put: {doc['rel_path']}"
        assert got == doc

    # list(kind=...) filters correctly.
    texts = [d for d in backend.list(kind="text", root=ROOT)]
    assert [d["rel_path"] for d in texts] == [docs[0]["rel_path"]]

    images = [d for d in backend.list(kind="image", root=ROOT)]
    assert [d["rel_path"] for d in images] == [docs[2]["rel_path"]]

    # Rescan semantics: put the same (root_id, rel_path) again -> one record.
    updated = copy.deepcopy(docs[0])
    updated["size"] = 999
    updated["probe"]["nested"]["a"] = 42
    backend.put(updated)
    backend.flush()
    matches = [d for d in backend.list(root=ROOT) if d["rel_path"] == updated["rel_path"]]
    assert len(matches) == 1
    assert matches[0] == updated

    # delete()
    backend.delete(ROOT, docs[1]["rel_path"])
    assert backend.get(ROOT, docs[1]["rel_path"]) is None
    remaining = {d["rel_path"] for d in backend.list(root=ROOT)}
    assert docs[1]["rel_path"] not in remaining

    # Installed-programs round trip.
    program = {
        "program_id": "contract-test-prog", "display_name": "Contract Tester",
        "publisher": "ACME", "display_version": "1.0", "hive": "HKLM",
    }
    backend.put_program(copy.deepcopy(program))
    backend.flush()
    programs = {p["program_id"]: p for p in backend.list_programs()}
    assert programs.get("contract-test-prog") == program

    # summary(): bytes sum over the two remaining files for this root
    # (docs[1] was deleted; docs[0] is now "updated").
    summary = backend.summary(root=ROOT)
    root_summary = summary["roots"][ROOT]
    assert root_summary["total_bytes"] == updated["size"] + docs[2]["size"]
    assert root_summary["total_files"] == 2
    assert root_summary["unreadable"] == 0


def _make_members(n: int, start: int = 0) -> list[dict]:
    members = []
    for i in range(start, start + n):
        members.append({
            "index": i, "path": f"assets/file_{i:06d}.dat",
            "size": 100 + i, "csize": 50 + i, "role": "texture" if i % 2 == 0 else "script",
            "kind": "unknown", "crc32": i & 0xFFFFFFFF, "method": "deflate", "offset": i * 100,
        })
    return members


def test_members_contract(backend, backend_name):
    archive = {
        "root_id": root_id(ROOT), "root": ROOT, "rel_path": "packs/data.zip",
        "name": "data.zip", "size": 4096, "kind": "archive", "suffix": "zip",
        "probe": {"members_count": 3},
    }
    backend.put(copy.deepcopy(archive))
    backend.flush()

    members = _make_members(3)
    backend.put_members(ROOT, archive["rel_path"], copy.deepcopy(members))

    def expected(m):
        return {**m, "root_id": root_id(ROOT), "root": ROOT,
                "archive_rel_path": archive["rel_path"]}

    got = list(backend.list_members(ROOT, archive["rel_path"]))
    assert [g["index"] for g in got] == [0, 1, 2]  # index order
    assert got == [expected(m) for m in members]

    # iter_all_members sees the same rows (any order), each carrying root +
    # archive_rel_path.
    all_rows = {(r["root_id"], r["archive_rel_path"], r["index"]): r
                for r in backend.iter_all_members()}
    for m in members:
        key = (root_id(ROOT), archive["rel_path"], m["index"])
        assert all_rows[key] == expected(m)

    # Replace semantics: put_members again with fewer/different rows drops
    # the old ones entirely, no leftovers.
    replacement = _make_members(2, start=10)
    backend.put_members(ROOT, archive["rel_path"], copy.deepcopy(replacement))
    got2 = list(backend.list_members(ROOT, archive["rel_path"]))
    assert [g["index"] for g in got2] == [10, 11]
    assert got2 == [expected(m) for m in replacement]

    # A second archive's rows are independent.
    other_rel = "packs/other.zip"
    backend.put({**copy.deepcopy(archive), "rel_path": other_rel, "name": "other.zip"})
    backend.flush()
    other_members = _make_members(2, start=100)
    backend.put_members(ROOT, other_rel, copy.deepcopy(other_members))
    assert len(list(backend.list_members(ROOT, archive["rel_path"]))) == 2
    assert len(list(backend.list_members(ROOT, other_rel))) == 2

    total_rows = list(backend.iter_all_members())
    assert len(total_rows) == 4

    # delete() cascades to members.
    backend.delete(ROOT, archive["rel_path"])
    assert list(backend.list_members(ROOT, archive["rel_path"])) == []
    assert len(list(backend.list_members(ROOT, other_rel))) == 2
    remaining_rows = list(backend.iter_all_members())
    assert len(remaining_rows) == 2

    backend.delete_members(ROOT, other_rel)
    assert list(backend.list_members(ROOT, other_rel)) == []
    assert list(backend.iter_all_members()) == []


def test_members_sqlite_200k_performance(fixture_dir):
    """A 200k-member synthetic zip must put/list in a few seconds, not
    minutes: executemany in one transaction, no per-row commits."""
    import time

    backend = SqliteBackend(str(fixture_dir / "catalog.sqlite"))
    try:
        root = ROOT
        archive_rel = "big/archive.zip"
        backend.put({
            "root_id": root_id(root), "root": root, "rel_path": archive_rel,
            "name": "archive.zip", "size": 10_000_000, "kind": "archive", "suffix": "zip",
        })
        backend.flush()

        n = 200_000
        members = _make_members(n)

        t0 = time.monotonic()
        backend.put_members(root, archive_rel, members)
        put_elapsed = time.monotonic() - t0

        t0 = time.monotonic()
        got = list(backend.list_members(root, archive_rel))
        list_elapsed = time.monotonic() - t0

        assert len(got) == n
        assert [g["index"] for g in got[:5]] == [0, 1, 2, 3, 4]
        assert got[-1]["index"] == n - 1

        print(f"\n[members perf] put_members({n}): {put_elapsed:.2f}s, "
              f"list_members: {list_elapsed:.2f}s")
        assert put_elapsed < 20.0, f"put_members({n}) took {put_elapsed:.2f}s"
        assert list_elapsed < 20.0, f"list_members({n}) took {list_elapsed:.2f}s"
    finally:
        backend.close()


def test_aggregates_per_root_contract(backend, backend_name):
    import uuid
    from filecat.aggregate import build_aggregates

    tag = uuid.uuid4().hex[:8]
    root_a, root_b = rf"C:\agg-contract-{tag}-a", rf"C:\agg-contract-{tag}-b"

    def total(root):
        return build_aggregates(backend.list(root=root), depth=2)["roots"][root]

    try:
        for root in (root_a, root_b):
            for doc in _make_docs(root):
                backend.put(doc)
        backend.flush()
        backend.rebuild_aggregates(depth=2)

        stored = backend.stored_aggregates()
        assert root_a in stored and root_b in stored
        for root in (root_a, root_b):
            assert stored[root]["depth"] == 2
            assert stored[root]["built_at"]
            assert stored[root]["total_files"] == total(root)["total_files"]
        b_before = backend.stored_aggregates(root_b)[root_b]
        assert set(backend.stored_aggregates(root_b)) == {root_b}

        extra = {"root_id": root_id(root_a), "root": root_a, "rel_path": "x/y/big.dat",
                 "name": "big.dat", "size": 5000, "kind": "data", "suffix": "dat"}
        backend.put(extra)
        backend.flush()
        backend.rebuild_aggregates(depth=3, root=root_a)

        stored = backend.stored_aggregates()
        assert stored[root_b] == b_before
        assert stored[root_b]["depth"] == 2
        assert stored[root_a]["depth"] == 3
        want_a = build_aggregates(backend.list(root=root_a), depth=3)["roots"][root_a]
        assert stored[root_a]["total_files"] == want_a["total_files"]
        assert stored[root_a]["total_bytes"] == want_a["total_bytes"] == 123 + 2048 + 5000

        roots = backend.summary(depth=2)["roots"]
        assert "built_at" in roots[root_b]                       # stored (depth matches)
        assert roots[root_b]["total_files"] == b_before["total_files"]
        assert "built_at" not in roots[root_a]                   # stored at depth 3 -> computed
        assert roots[root_a]["total_bytes"] == 123 + 2048 + 5000

        for doc in list(backend.list(root=root_a)):
            backend.delete(doc["root"], doc["rel_path"])
        backend.flush()
        backend.rebuild_aggregates(root=root_a)
        stored = backend.stored_aggregates()
        assert root_a not in stored
        assert root_b in stored
    finally:
        for root in (root_a, root_b):
            for doc in list(backend.list(root=root)):
                backend.delete(doc["root"], doc["rel_path"])
            backend.flush()
            backend.rebuild_aggregates(root=root)


def test_root_info_contract(backend, backend_name):
    """put_root_info upserts by root_id; get/list read it back; other roots untouched."""
    import uuid
    roots = [f"C:\root-info-{uuid.uuid4().hex[:8]}", f"\\nas\root-info-{uuid.uuid4().hex[:8]}"]
    infos = [{"root_id": root_id(r), "root": r, "last_attempt": {"status": "running", "started_at": "t0"},
              "newest_file": {"rel_path": "a/ü.txt", "mtime_ns": 1_700_000_000_000_000_123}}
             for r in roots]
    for info in infos:
        backend.put_root_info(copy.deepcopy(info))
    assert backend.get_root_info(roots[0]) == infos[0]
    done = {**infos[0], "last_attempt": {"status": "ok", "started_at": "t0", "finished_at": "t1"},
            "last_scan": {"status": "ok", "files": 3}}
    backend.put_root_info(copy.deepcopy(done))
    assert backend.get_root_info(roots[0]) == done
    assert backend.get_root_info(roots[1]) == infos[1]
    listed = {i["root_id"]: i for i in backend.list_root_info()}
    assert listed[root_id(roots[0])] == done and listed[root_id(roots[1])] == infos[1]
    assert backend.get_root_info("C:\never-scanned") is None
    backend.delete_root_info(roots[0])
    backend.delete_root_info(roots[0])      # absent: no error
    assert backend.get_root_info(roots[0]) is None
    assert backend.get_root_info(roots[1]) == infos[1]
    assert root_id(roots[0]) not in {i["root_id"] for i in backend.list_root_info()}
    backend.delete_root_info(roots[1])


def test_treemap_contract(backend, backend_name):
    """put_treemap stores meta + data; data=None replaces only the meta;
    list_treemaps returns metas (per root or all); delete is idempotent."""
    import uuid
    roots = [rf"C:\treemap-{uuid.uuid4().hex[:8]}", rf"\\nas\treemap-{uuid.uuid4().hex[:8]}"]
    data = {"prefix": "", "depth": 2, "files": 2, "bytes": 5_000_000_000,
            "keys": {"suffix": [{"key": "mkv", "files": 2, "bytes": 5_000_000_000}], "mime": []},
            "folders": [{"path": "Ünï/卷", "files": 2, "bytes": 5_000_000_000, "suffix": [[0, 5_000_000_000]],
                         "mime": []}]}
    metas = [{"id": uuid.uuid4().hex, "root_id": root_id(r), "root": r, "prefix": "", "depth": 2,
              "built_at": "2026-10-18T01:00:00.123456+00:00", "files": 2, "bytes": 5_000_000_000, "pin": None}
             for r in roots]
    for meta in metas:
        backend.put_treemap(copy.deepcopy(meta), copy.deepcopy(data))
    try:
        assert backend.list_treemaps(roots[0]) == [metas[0]]
        assert backend.get_treemap(metas[1]["id"]) == (metas[1], data)
        pinned = {**metas[0], "pin": {"at": "2026-10-18T02:00:00+00:00", "label": "før"}}
        backend.put_treemap(copy.deepcopy(pinned))
        assert backend.get_treemap(metas[0]["id"]) == (pinned, data)
        backend.put_treemap({**metas[0], "id": "never-stored"})  # meta only: nothing to update
        assert backend.get_treemap("never-stored") is None
        ids = {m["id"] for m in backend.list_treemaps()}
        assert {metas[0]["id"], metas[1]["id"]} <= ids
        backend.delete_treemap(metas[0]["id"])
        backend.delete_treemap(metas[0]["id"])
        assert backend.list_treemaps(roots[0]) == [] and backend.get_treemap(metas[0]["id"]) is None
    finally:
        for meta in metas:
            backend.delete_treemap(meta["id"])


def test_dropped_contract(backend, backend_name):
    """drop_many moves records out of the catalog into the dropped store with
    dropped_at/drop_reason; list_dropped is newest first; purge_dropped
    removes only entries dropped before the cutoff."""
    import uuid
    root = rf"C:\dropped-{uuid.uuid4().hex[:8]}"
    docs = _make_docs(root)
    for doc in docs:
        backend.put(copy.deepcopy(doc))
    backend.flush()
    gone = [docs[1]["rel_path"], docs[2]["rel_path"]]
    assert backend.drop_many(root, gone + ["never/existed.txt"]) == 2
    backend.flush()
    assert all(backend.get(root, rp) is None for rp in gone)
    assert {d["rel_path"] for d in backend.list(root=root)} == {d["rel_path"] for d in docs} - set(gone)
    dropped = list(backend.list_dropped(root))
    assert sorted(d["rel_path"] for d in dropped) == sorted(gone)
    for d in dropped:
        assert d["drop_reason"] == "vanished" and d["dropped_at"] >= "2026"
        orig = next(o for o in docs if o["rel_path"] == d["rel_path"])
        assert {k: v for k, v in d.items() if k not in ("dropped_at", "drop_reason")} == orig

    old = {**docs[0], "dropped_at": "1999-01-01T00:00:00+00:00", "drop_reason": "vanished"}
    backend.put_dropped(copy.deepcopy(old))
    assert next(iter(reversed(list(backend.list_dropped(root)))))["dropped_at"] == old["dropped_at"]
    assert backend.purge_dropped("2000-01-01T00:00:00+00:00") >= 1
    assert sorted(d["rel_path"] for d in backend.list_dropped(root)) == sorted(gone)
    assert backend.drop(root, docs[0]["rel_path"]) is True
    assert backend.drop(root, docs[0]["rel_path"]) is False
    assert list(backend.list_dropped(root))[0]["rel_path"] == docs[0]["rel_path"]  # newest first
    assert all(d["root"] == root for d in backend.list_dropped(root))


def test_mongo_bson_safe_turns_huge_ints_into_strings():
    pytest.importorskip("pymongo")
    from filecat.backends.mongodb import _bson_safe
    doc = {"size": 5, "ok": True, "m": [{"mtime_ns": 39592613215255611786192470368000000000}],
           "neg": -2 ** 63, "edge": 2 ** 63}
    assert _bson_safe(doc) == {"size": 5, "ok": True, "m": [{"mtime_ns": "39592613215255611786192470368000000000"}],
                               "neg": -2 ** 63, "edge": str(2 ** 63)}


def test_members_with_huge_ints_store(backend, backend_name):
    """A corrupt archive can yield an int past int64; storing it must not fail."""
    root = r"C:\contract-test-root"
    backend.put_members(root, "bad.tar", [{"index": 0, "path": "x", "mtime_ns": 10 ** 37}])
    rows = list(backend.list_members(root, "bad.tar"))
    assert len(rows) == 1 and int(rows[0]["mtime_ns"]) == 10 ** 37
    backend.delete_members(root, "bad.tar")


# --- content-keyed samples (filecat/samples.py) ----------------------------

def _sample_id() -> str:
    """A fresh id: a server database keeps samples from earlier runs."""
    import uuid
    return uuid.uuid4().hex + uuid.uuid4().hex


def test_samples_contract(backend, backend_name):
    if not backend.stores_samples:
        pytest.skip(f"{backend_name} keeps samples inline")
    a, b = _sample_id(), _sample_id()
    first = {"sample_id": a, "hash_type": "sha256", "size": 5, "sample": "héllo",
             "encoding": {"detected": "utf-8"}}
    backend.add_samples([first, {"sample_id": b, "hash_type": "sha256_partial", "size": 9, "sample": "x",
                                 "sample_truncated": True}])
    # a stored sample is kept as it is
    backend.add_samples([{**first, "sample": "changed"}])
    got = backend.get_samples([a, b, _sample_id()])
    assert set(got) == {a, b}
    assert got[a] == first and got[b]["sample_truncated"] is True
    assert backend.get_samples([]) == {}

    llm = {"model": "m", "prompt_version": "filecat-1", "summary": "s", "labels": ["x"], "unsure": False}
    backend.set_sample_llm(a, llm)
    assert backend.get_samples([a])[a] == {**first, "llm": llm}
    assert {a, b} <= {s["sample_id"] for s in backend.iter_samples()}


def test_store_files_the_sample_under_the_hash(backend, backend_name):
    sid = _sample_id()
    doc = {**_make_docs(ROOT)[0], "sha256": sid, "sample": "text", "sample_truncated": True}
    backend.store(copy.deepcopy(doc))
    backend.flush()
    got = backend.get(ROOT, doc["rel_path"])
    if not backend.stores_samples:
        assert got["sample"] == "text" and "sample_id" not in got
        return
    assert got["sample_id"] == sid and "sample" not in got and "sample_truncated" not in got
    assert backend.get_samples([sid])[sid]["sample"] == "text"
    # no hash: the sample stays on the record
    plain = {**_make_docs(ROOT)[2], "sample": "inline"}
    backend.store(copy.deepcopy(plain))
    backend.flush()
    assert backend.get(ROOT, plain["rel_path"])["sample"] == "inline"


def test_page_records_visits_every_record_once(backend, backend_name):
    try:
        backend.page_records(None, 1)
    except NotImplementedError:
        pytest.skip(f"{backend_name} cannot page")
    docs = _make_docs(ROOT)
    for doc in docs:
        backend.put(copy.deepcopy(doc))
    backend.flush()
    seen: list[str] = []
    after = None
    while True:
        page, after = backend.page_records(after, 2)
        if not page:
            break
        for d in page:
            if d["root"] == ROOT:
                seen.append(d["rel_path"])
                backend.put({**d, "size": (d.get("size") or 0) + 1})   # rewriting keeps the order
        backend.flush()
    assert sorted(seen) == sorted(d["rel_path"] for d in docs)
    assert all(backend.get(ROOT, d["rel_path"])["size"] == d["size"] + 1 for d in docs)


# --- member sets (filecat/member_sets.py) ----------------------------------

def test_member_sets_contract(backend, backend_name):
    from filecat import member_sets
    if not backend.stores_member_sets:
        pytest.skip(f"{backend_name} keeps members under each archive's path")
    mid = _sample_id()
    rows = member_sets.clean_rows(_make_members(3) + [{"path": "big", "mtime_ns": 10 ** 37, "role": "data"}])
    header = member_sets.header_for((mid, "sha256"), rows)
    assert backend.put_member_set(header, rows) is True
    assert backend.put_member_set(header, rows) is False          # same digest: left alone
    got = list(backend.list_member_set(mid))
    assert [r["path"] for r in got] == [r["path"] for r in rows] and all(r["members_id"] == mid for r in got)
    assert member_sets.clean_rows(got)[:3] == rows[:3] and int(got[3]["mtime_ns"]) == 10 ** 37
    fewer = rows[:2]
    assert backend.put_member_set(member_sets.header_for((mid, "sha256"), fewer), fewer) is True
    assert len(list(backend.list_member_set(mid))) == 2
    assert {"members_id": mid, "hash_type": "sha256", "count": 2,
            "digest": member_sets.digest(fewer)} in list(backend.iter_member_sets())


def test_store_files_members_under_the_hash_and_prune(backend, backend_name):
    from filecat.record import MEMBERS_KEY
    mid, sid = _sample_id(), _sample_id()
    docs = _make_docs(ROOT)
    copies = [{**docs[0], "sha256": mid, MEMBERS_KEY: _make_members(4)},
              {**docs[1], "sha256": mid, MEMBERS_KEY: _make_members(4)}]
    plain = {**docs[2], MEMBERS_KEY: _make_members(2)}           # no hash: rows under the path
    for d in copies + [plain]:
        backend.store(copy.deepcopy(d))
    backend.flush()
    for d in copies:
        rows = list(backend.members_of(ROOT, d["rel_path"]))
        assert [r["index"] for r in rows] == [0, 1, 2, 3]
    assert len(list(backend.members_of(ROOT, plain["rel_path"]))) == 2
    if not backend.stores_member_sets:
        assert "members_id" not in backend.get(ROOT, copies[0]["rel_path"])
        return
    assert {backend.get(ROOT, d["rel_path"])["members_id"] for d in copies} == {mid}
    assert list(backend.list_members(ROOT, copies[0]["rel_path"])) == []
    assert "members_id" not in backend.get(ROOT, plain["rel_path"])

    backend.add_samples([{"sample_id": sid, "hash_type": "sha256", "sample": "orphan"}])
    backend.delete(ROOT, copies[0]["rel_path"])
    backend.prune_member_sets()
    assert len(list(backend.list_member_set(mid))) == 4          # the other copy still names it
    backend.delete(ROOT, copies[1]["rel_path"])
    assert backend.prune_member_sets() >= 1
    assert list(backend.list_member_set(mid)) == []
    assert mid not in {h["members_id"] for h in backend.iter_member_sets()}
    assert backend.prune_samples() >= 1
    assert backend.get_samples([sid]) == {}


def test_get_stats_contract(backend, backend_name):
    docs = _make_docs(ROOT)
    for d in docs:
        backend.put(d)
    backend.flush()
    dir_doc = {"root_id": root_id(ROOT), "root": ROOT, "rel_path": "a/b", "name": "b",
               "kind": "dir", "mtime_ns": 5, "probe": {"child_count": 1}}
    backend.put(dir_doc)            # still buffered on a server backend
    wanted = ["a/b/café.txt", "data/file2.bin", "a/b", "no/such/file"]
    got = backend.get_stats(ROOT, wanted)
    assert set(got) == {"a/b/café.txt", "data/file2.bin", "a/b"}
    assert {k: got["a/b/café.txt"][k] for k in ("kind", "size", "mtime_ns")} == {
        "kind": "text", "size": 123, "mtime_ns": 1_700_000_000_000_000_000}
    assert got["data/file2.bin"]["size"] == 0 and "mtime_ns" not in got["data/file2.bin"]
    assert got["a/b"]["kind"] == "dir" and got["a/b"]["probe"]["child_count"] == 1
    assert backend.get_stats(ROOT, []) == {}
    assert backend.get_stats(r"C:\other-root", wanted) == {}
    # more paths than one query takes
    many = [f"bulk/{i:04d}" for i in range(1203)]
    for p in many:
        backend.put({"root_id": root_id(ROOT), "root": ROOT, "rel_path": p, "name": p[5:],
                     "kind": "empty", "size": 0})
    backend.flush()
    assert set(backend.get_stats(ROOT, many + ["a/b"])) == set(many) | {"a/b"}


# --- rollups and sticky redactions (filecat/rollup.py, redaction.py) ---------------------

def _rollup_doc(root: str, rel: str, size: int = 10, **info) -> dict:
    return {"root_id": root_id(root), "root": root, "rel_path": rel, "name": rel.rsplit("/", 1)[-1],
            "kind": "rollup", "suffix": "", "size": size, "mtime_ns": 5,
            "probe": {"rollup": {"tag": rel.rsplit("/", 1)[-1], "rule": "builtin:cache", "matched": 2,
                                 "total_files": 3, "total_dirs": 1, "newest_mtime_ns": 5,
                                 "oldest_mtime_ns": 1, "errors": 0, "partial": False, **info}}}


def test_rollups_do_not_count_as_files_and_are_read_back(backend, backend_name):
    from filecat import browse
    import uuid
    root = rf"C:\rollup-contract-{uuid.uuid4().hex[:8]}"
    docs = _make_docs(root) + [_rollup_doc(root, "a/b/[CACHE]", 500), _rollup_doc(root, "[REDACTED]", 70)]
    for d in docs:
        backend.put(copy.deepcopy(d))
    backend.flush()
    try:
        backend.rebuild_aggregates(root=root)
        summary = backend.summary(root=root)["roots"][root]
        assert summary["total_files"] == 3 and summary["total_bytes"] == 123 + 2048
        q = browse.normalize({"root": root, "files_only": "1", "limit": "100"})
        assert backend.query(q)["total"] == 3
        assert backend.query(browse.normalize({"root": root, "kind": "rollup"}))["total"] == 2
        assert backend.query(browse.normalize({"root": root, "unreadable": "1"}))["total"] == 0
        rows = backend.query(browse.normalize({"root": root, "parent": "a/b", "limit": "10"}))["rows"]
        assert [r["kind"] for r in rows][0] == "rollup"
        assert all(r[0] != "a/b/[CACHE]" for r in backend.sizes(root, ""))
        assert all(s["name"] != "[CACHE]" for s in backend.subtree(root, "a"))
        assert all(d["kind"] != "rollup" for d in backend.list_sized(0, root=root))
        assert [d["rel_path"] for d in backend.rollups(root, "a")] == ["a/b/[CACHE]"]
        assert len(list(backend.rollups(root))) == 2
        totals = backend.rollup_totals(root)[root]
        assert {(r["tag"], r["parent"]): r["size"] for r in totals} == {("[CACHE]", "a/b"): 500,
                                                                         ("[REDACTED]", ""): 70}
    finally:
        for d in docs:
            backend.delete(root, d["rel_path"])
        backend.flush()


def test_delete_many_is_a_hard_delete_with_members(backend, backend_name):
    import uuid
    root = rf"C:\delete-many-{uuid.uuid4().hex[:8]}"
    docs = _make_docs(root)
    for d in docs:
        backend.put(copy.deepcopy(d))
    backend.put_members(root, docs[2]["rel_path"], _make_members(2))
    backend.flush()
    assert backend.delete_many(root, [docs[0]["rel_path"], docs[2]["rel_path"], "never/there"]) == 2
    backend.flush()
    assert [d["rel_path"] for d in backend.list(root=root)] == [docs[1]["rel_path"]]
    assert list(backend.list_members(root, docs[2]["rel_path"])) == []
    assert list(backend.list_dropped(root)) == []          # nothing was moved to the dropped store
    assert backend.delete_many(root, []) == 0
    many = [f"bulk/{i:04d}" for i in range(1203)]
    for p in many:
        backend.put({"root_id": root_id(root), "root": root, "rel_path": p, "name": p[5:],
                     "kind": "empty", "size": 0})
    backend.flush()
    assert backend.delete_many(root, many) == 1203
    backend.delete(root, docs[1]["rel_path"])
    backend.flush()


def test_purge_dropped_paths_removes_entries_at_and_beneath(backend, backend_name):
    import uuid
    root = rf"C:\purge-dropped-{uuid.uuid4().hex[:8]}"
    other = rf"C:\purge-other-{uuid.uuid4().hex[:8]}"
    stamp = {"dropped_at": "2026-10-01T00:00:00+00:00", "drop_reason": "vanished"}
    rels = ["secret", "secret/a.txt", "secret/deep/b.txt", "secretive/c.txt", "open/d.txt"]
    for r in rels:
        backend.put_dropped({**_rollup_doc(root, r), "kind": "text", **stamp})
    backend.put_dropped({**_rollup_doc(other, "secret/a.txt"), "kind": "text", **stamp})
    assert backend.purge_dropped_paths(root, ["secret"]) == 3
    assert sorted(d["rel_path"] for d in backend.list_dropped(root)) == ["open/d.txt", "secretive/c.txt"]
    assert len(list(backend.list_dropped(other))) == 1
    assert backend.purge_dropped_paths(root, []) == 0
    backend.purge_dropped_paths(root, ["secretive", "open"])
    backend.purge_dropped_paths(other, ["secret"])


def _entry(root: str, n: int, **kw) -> dict:
    return {"id": f"{n:08x}", "root_id": root_id(root), "root": root, "parent": "jdoe",
            "path_hash": f"{n:032x}", "status": "active", "source": "marker",
            "created": "2026-10-23T00:00:00+00:00", "last_seen": "2026-10-23T00:00:00+00:00",
            "key_id": "1a2b3c4d", **kw}


def test_redactions_contract(backend, backend_name):
    import uuid
    root = rf"C:\redactions-{uuid.uuid4().hex[:8]}"
    other = rf"\\nas\redactions-{uuid.uuid4().hex[:8]}"
    a, b, c = _entry(root, 0xA1), _entry(root, 0xA2, dev=2049, ino=913442), _entry(other, 0xA3)
    try:
        for e in (a, b, c):
            backend.put_redaction(copy.deepcopy(e))
        assert sorted(e["id"] for e in backend.redactions(root)) == [a["id"], b["id"]]
        assert {e["id"] for e in backend.redactions(other)} == {c["id"]}
        assert {e["id"] for e in backend.redactions()} >= {a["id"], b["id"], c["id"]}
        got = next(e for e in backend.redactions(root) if e["id"] == b["id"])
        assert got == b
        backend.touch_redaction(a["id"], "2026-10-24T00:00:00+00:00")
        backend.set_redaction_status(a["id"], "pending", released="2026-10-24T01:00:00+00:00")
        assert [e["id"] for e in backend.redactions(root, status="pending")] == [a["id"]]
        got = next(e for e in backend.redactions(root) if e["id"] == a["id"])
        assert got["last_seen"] == "2026-10-24T00:00:00+00:00" and got["released"].endswith("01:00:00+00:00")
        # a rename: the same entry, a new hash, parent and inode
        backend.update_redaction_identity(b["id"], f"{0xB2:032x}", 2049, 913999, "jdoe/new")
        got = next(e for e in backend.redactions(root) if e["id"] == b["id"])
        assert (got["path_hash"], got["parent"], got["ino"]) == (f"{0xB2:032x}", "jdoe/new", 913999)
        # one entry per (root, path hash): a second id with the same hash replaces the first
        backend.put_redaction(_entry(root, 0xA9, path_hash=a["path_hash"]))
        ids = {e["id"] for e in backend.redactions(root)}
        assert a["id"] not in ids and f"{0xA9:08x}" in ids
        backend.delete_redaction(b["id"])
        backend.delete_redaction(b["id"])       # absent: no error
        assert b["id"] not in {e["id"] for e in backend.redactions(root)}
        # not part of the records, the dropped store or the root listing
        assert list(backend.list(root=root)) == [] and list(backend.list_dropped(root)) == []
    finally:
        for e in list(backend.redactions(root)) + list(backend.redactions(other)):
            backend.delete_redaction(e["id"])
