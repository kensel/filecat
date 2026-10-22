"""The per-root JSONL layout: one file per root inside a directory."""
from __future__ import annotations

import json

from filecat.backends import open_backend
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.jsonl_dir import JsonlDirBackend, is_dir_layout, slug
from filecat.migrate import migrate
from filecat.record import new_document, root_id

A = r"\nas-vm\admin"
B = r"D:\Games"


def _fill(b) -> None:
    b.put(new_document(A, "", kind="dir"))
    b.put(new_document(A, "x/a.txt", kind="text", size=5))
    b.put(new_document(B, "save/b.zip", kind="archive", size=7))
    b.put_members(B, "save/b.zip", [{"index": 0, "path": "m", "size": 1}])
    b.put_program({"program_id": "p1", "display_name": "Prog"})
    b.put_root_info({"root_id": root_id(B), "root": B, "last_scan": {"status": "ok"}})
    b.flush()


def test_layout_selection(tmp_path):
    assert is_dir_layout(str(tmp_path / "catalog-jsonl"))
    assert not is_dir_layout(str(tmp_path / "catalog.jsonl"))
    (tmp_path / "old.jsonl").touch()
    assert not is_dir_layout(str(tmp_path / "old.jsonl"))
    (tmp_path / "odd.jsonl").mkdir()
    assert is_dir_layout(str(tmp_path / "odd.jsonl"))
    assert isinstance(open_backend("jsonl", str(tmp_path / "c")), JsonlDirBackend)
    assert isinstance(open_backend("jsonl", str(tmp_path / "c.jsonl")), JsonlBackend)


def test_one_file_per_root(tmp_path):
    d = tmp_path / "cat"
    with JsonlDirBackend(str(d)) as b:
        _fill(b)
        b.rebuild_aggregates()
    names = sorted(p.name for p in d.iterdir())
    ra, rb = root_id(A), root_id(B)
    assert names == sorted([
        f"nas-vm-admin.{ra}.jsonl", f"nas-vm-admin.{ra}.summary.json",
        f"D-Games.{rb}.jsonl", f"D-Games.{rb}.members.jsonl", f"D-Games.{rb}.summary.json",
        f"D-Games.{rb}.roots.json",
        "programs.jsonl"])
    lines = (d / f"nas-vm-admin.{ra}.jsonl").read_text(encoding="utf-8").splitlines()
    assert {json.loads(x)["root"] for x in lines} == {A}

    # a fresh process finds everything from the file names alone
    b = JsonlDirBackend(str(d))
    assert b.roots() == sorted([A, B])
    assert b.get(B, "save/b.zip")["size"] == 7
    assert [m["path"] for m in b.list_members(B, "save/b.zip")] == ["m"]
    assert set(b.stored_aggregates()) == {A, B}
    assert b.summary(root=A)["roots"][A]["total_bytes"] == 5
    assert b.get(r"\other\x", "a") is None and list(b.list(root=r"\other\x")) == []


def test_rescan_rewrites_only_that_roots_file(tmp_path):
    d = tmp_path / "cat"
    with JsonlDirBackend(str(d)) as b:
        _fill(b)
    other = d / f"D-Games.{root_id(B)}.jsonl"
    before = other.stat().st_mtime_ns, other.read_bytes()
    with JsonlDirBackend(str(d)) as b:
        b.put(new_document(A, "x/c.txt", kind="text", size=1))
        b.rebuild_aggregates(root=A)
    assert (other.stat().st_mtime_ns, other.read_bytes()) == before


def test_slug():
    assert slug(r"\nas-vm\Backup-NAS-VM") == "nas-vm-Backup-NAS-VM"
    assert slug("C:\\") == "C"
    assert slug("/") == "root"


def test_migrate_single_file_to_directory(tmp_path):
    src = JsonlBackend(str(tmp_path / "old.jsonl"))
    _fill(src)
    dst = JsonlDirBackend(str(tmp_path / "new"))
    migrate(src, dst)
    dst.flush()
    assert sorted((d["root"], d["rel_path"]) for d in dst.list()) == \
        sorted((d["root"], d["rel_path"]) for d in src.list())
    assert [p["program_id"] for p in dst.list_programs()] == ["p1"]
    assert len(list(dst.iter_all_members())) == 1
    assert dst.get_root_info(B)["last_scan"] == {"status": "ok"}
