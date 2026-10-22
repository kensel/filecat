"""Tests for filecat.migrate: sqlite <-> jsonl round trips, --root filtering,
same-target refusal, idempotence, and --verify catching a corrupted target.
"""
from __future__ import annotations

import copy
import time

import pytest

from filecat.backends.jsonl import JsonlBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.migrate import migrate
from filecat.record import root_id

ROOT_A = r"C:\migrate-test\alpha"
ROOT_B = r"C:\migrate-test\beta"


def _docs() -> list[dict]:
    out = []
    for root in (ROOT_A, ROOT_B):
        rid = root_id(root)
        for i in range(5):
            out.append({
                "root_id": rid, "root": root, "rel_path": f"dir/file_{i}.txt",
                "name": f"file_{i}.txt", "size": 10 + i, "kind": "text", "suffix": "txt",
                "mime": "text/plain",
            })
        out.append({
            "root_id": rid, "root": root, "rel_path": "dir/archive.zip",
            "name": "archive.zip", "size": 999, "kind": "archive", "suffix": "zip",
        })
    return out


def _programs() -> list[dict]:
    return [{
        "program_id": "prog-1", "display_name": "Migrate Tester",
        "publisher": "ACME", "display_version": "1.0", "hive": "HKLM",
    }]


def _members() -> list[dict]:
    return [
        {"index": 0, "path": "a.lua", "size": 10, "role": "script"},
        {"index": 1, "path": "b.png", "size": 20, "role": "image"},
    ]


def _populate(backend) -> None:
    for doc in _docs():
        backend.put(copy.deepcopy(doc))
    backend.flush()
    for p in _programs():
        backend.put_program(copy.deepcopy(p))
    backend.put_members(ROOT_A, "dir/archive.zip", copy.deepcopy(_members()))
    backend.put_members(ROOT_B, "dir/archive.zip", copy.deepcopy(_members()))
    backend.rebuild_aggregates()


def _counts(backend) -> dict:
    docs = sorted(backend.list(), key=lambda d: (d["root"], d["rel_path"]))
    programs = sorted(backend.list_programs(), key=lambda p: p["program_id"])
    members_a = list(backend.list_members(ROOT_A, "dir/archive.zip"))
    members_b = list(backend.list_members(ROOT_B, "dir/archive.zip"))
    return {"docs": docs, "programs": programs, "members_a": members_a, "members_b": members_b}


def test_sqlite_jsonl_sqlite_round_trip(fixture_dir):
    src = SqliteBackend(str(fixture_dir / "src.sqlite"))
    _populate(src)
    src_counts = _counts(src)

    mid = JsonlBackend(str(fixture_dir / "mid.jsonl"))
    stats1 = migrate(src, mid)
    assert stats1.documents == len(_docs())
    assert stats1.programs == 1
    assert stats1.members_archives == 2
    assert stats1.members_rows == 4
    mid_counts = _counts(mid)
    assert mid_counts == src_counts

    dst = SqliteBackend(str(fixture_dir / "dst.sqlite"))
    stats2 = migrate(mid, dst)
    assert stats2.documents == len(_docs())
    dst_counts = _counts(dst)
    assert dst_counts == src_counts

    src.close()
    mid.close()
    dst.close()


def test_root_filter(fixture_dir):
    src = SqliteBackend(str(fixture_dir / "src.sqlite"))
    _populate(src)

    dst = JsonlBackend(str(fixture_dir / "dst.jsonl"))
    stats = migrate(src, dst, roots=[ROOT_A])
    assert stats.documents == 6  # only ROOT_A's docs
    assert stats.members_archives == 1
    assert stats.members_rows == 2
    assert {d["root"] for d in dst.list()} == {ROOT_A}
    assert list(dst.list_members(ROOT_B, "dir/archive.zip")) == []
    assert len(list(dst.list_members(ROOT_A, "dir/archive.zip"))) == 2

    src.close()
    dst.close()


def test_refuses_same_target(fixture_dir):
    path = str(fixture_dir / "same.sqlite")
    src = SqliteBackend(path)
    _populate(src)
    src.flush()
    dst = SqliteBackend(path)
    with pytest.raises(ValueError):
        migrate(src, dst)
    src.close()
    dst.close()


def test_idempotent(fixture_dir):
    src = SqliteBackend(str(fixture_dir / "src.sqlite"))
    _populate(src)

    dst = JsonlBackend(str(fixture_dir / "dst.jsonl"))
    stats1 = migrate(src, dst)
    counts1 = _counts(dst)

    stats2 = migrate(src, dst)
    counts2 = _counts(dst)

    assert stats1.documents == stats2.documents
    assert stats1.programs == stats2.programs
    assert stats1.members_rows == stats2.members_rows
    assert counts1 == counts2

    src.close()
    dst.close()


def test_verify_catches_corruption(fixture_dir, monkeypatch):
    src = SqliteBackend(str(fixture_dir / "src.sqlite"))
    _populate(src)

    dst = JsonlBackend(str(fixture_dir / "dst.jsonl"))

    real_get = dst.get

    def corrupting_get(root, rel_path):
        doc = real_get(root, rel_path)
        if doc is not None and rel_path == "dir/file_0.txt" and root == ROOT_A:
            doc = {**doc, "size": doc["size"] + 1}
        return doc

    stats = migrate(src, dst, verify=False)
    assert not stats.verify_mismatches

    monkeypatch.setattr(dst, "get", corrupting_get)
    stats2 = migrate(src, dst, verify=True)
    assert stats2.verify_mismatches == [f"{ROOT_A}::dir/file_0.txt"]
    assert not stats2.ok

    src.close()
    dst.close()


def test_run_cli(fixture_dir):
    """run(args) end to end via the argparse-produced namespace shape."""
    from argparse import Namespace

    from filecat import migrate as migrate_mod

    src_path = str(fixture_dir / "cli_src.sqlite")
    src = SqliteBackend(src_path)
    _populate(src)
    src.close()

    dst_path = str(fixture_dir / "cli_dst.jsonl")
    args = Namespace(
        src_backend="sqlite", src_out=src_path, src_dsn=None,
        dst_backend="jsonl", dst_out=dst_path, dst_dsn=None,
        root=None, batch=3, no_programs=False, no_members=False, verify=True,
    )
    rc = migrate_mod.run(args)
    assert rc == 0

    dst = JsonlBackend(dst_path)
    assert len(list(dst.list())) == len(_docs())
    dst.close()
