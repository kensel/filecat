"""JSONL member rows: new archives append, stored ones are replaced."""
from __future__ import annotations

import os

from filecat import fsutil
from filecat.backends.jsonl import JsonlBackend


def _rows(n, tag):
    return [{"path": f"{tag}{i}.txt", "size": i} for i in range(n)]


def test_append_replace_delete_and_reopen(fixture_dir):
    path = str(fixture_dir / "c.jsonl")
    b = JsonlBackend(path)
    b.put_members("R:\\", "a.zip", _rows(3, "a"))
    b.put_members("R:\\", "b.zip", _rows(2, "b"))
    b.put_members("R:\\", "a.zip", _rows(1, "new"))       # replace
    assert [m["path"] for m in b.list_members("R:\\", "a.zip")] == ["new0.txt"]
    assert [m["path"] for m in b.list_members("R:\\", "b.zip")] == ["b0.txt", "b1.txt"]
    b.close()
    b2 = JsonlBackend(path)                                 # keys rebuilt from the file
    b2.put_members("R:\\", "b.zip", _rows(1, "c"))
    b2.delete_members("R:\\", "a.zip")
    b2.delete_members("R:\\", "missing.zip")
    assert list(b2.list_members("R:\\", "a.zip")) == []
    assert [m["path"] for m in b2.list_members("R:\\", "b.zip")] == ["c0.txt"]
    assert sum(1 for _ in b2.iter_all_members()) == 1
    b2.close()


def test_replace_retries_a_brief_sharing_violation(tmp_path, monkeypatch):
    src, dst = tmp_path / "s", tmp_path / "d"
    src.write_text("x")
    real, calls = os.replace, []

    def flaky(a, b):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError(5, "Access is denied")
        real(a, b)

    monkeypatch.setattr(fsutil.os, "replace", flaky)
    monkeypatch.setattr(fsutil.time, "sleep", lambda s: None)
    fsutil.replace(src, dst)
    assert dst.read_text() == "x" and len(calls) == 3
