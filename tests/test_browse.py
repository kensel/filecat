"""filecat.browse: the drill-through query. Every backend's query() must
return what the in-Python reference (MemoryBackend) returns, and drilling
into a summary row must list exactly the files that row counted."""
from __future__ import annotations

import os

import pytest

from filecat import browse
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.jsonl_dir import JsonlDirBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.record import root_id

ROOT = r"C:\browse-root"
OTHER = r"D:\other"


def _doc(root: str, rel: str, size: int | None, kind: str = "data", suffix: str | None = None,
         mime: str | None = None, **extra) -> dict:
    name = rel.rsplit("/", 1)[-1] if rel else root
    if suffix is None:
        suffix = "" if kind == "dir" or "." not in name else name.rsplit(".", 1)[1].lower()
    doc = {"root_id": root_id(root), "root": root, "rel_path": rel, "name": name,
           "kind": kind, "suffix": suffix, **extra}
    if size is not None:
        doc["size"] = size
    if mime:
        doc["mime"] = mime
    return doc


DOCS = [
    _doc(ROOT, "", 0, "dir"),
    _doc(ROOT, "a", 0, "dir"),
    _doc(ROOT, "a/b", 0, "dir"),
    _doc(ROOT, "a/b/c", 0, "dir"),
    _doc(ROOT, "top.txt", 10, "text", mime="text/plain"),
    _doc(ROOT, "README", 5, "text", mime="text/plain"),
    _doc(ROOT, "a/one.txt", 100, "text", mime="text/plain"),
    _doc(ROOT, "a/two.BIN", 200, "data"),
    _doc(ROOT, "a/b/three.png", 300, "image", mime="image/png"),
    _doc(ROOT, "a/b/c/four.png", 400, "image", mime="image/png"),
    _doc(ROOT, "a/b/c/deep/five.txt", 500, "text", mime="text/plain"),
    _doc(ROOT, "a/b_x/six.txt", 600, "text", mime="text/plain"),   # '_' must not act as a wildcard
    _doc(ROOT, "a/b%/seven.txt", 700, "text", mime="text/plain"),  # nor '%'
    _doc(ROOT, "ab/eight.txt", 800, "text", mime="text/plain"),    # "a" must not match "ab/"
    _doc(ROOT, "a/gone.dat", None, "unknown", errors=[{"stage": "stat", "message": "denied"}]),
    _doc(ROOT, "a/empty.txt", 0, "empty", errors=[{"stage": "probe", "message": "x"}]),
    _doc(ROOT, "Ünïcode/naïve.TXT", 50, "text", mime="text/plain"),
    _doc(OTHER, "a/one.txt", 9999, "text", mime="text/plain"),
]

QUERIES = [
    {},
    {"files_only": True},
    {"unreadable": True},
    {"errors": True},
    {"errors": True, "files_only": True},
    {"suffix": "txt"},
    {"suffix": "(none)", "files_only": True},
    {"suffix": "bin"},
    {"mime": "text/plain"},
    {"mime": "data"},          # mime missing -> kind
    {"mime": "unknown"},
    {"dir": ".", "files_only": True},
    {"dir": "a", "files_only": True},
    {"dir": "a/b", "files_only": True},
    {"dir": "a/b", "depth": 3, "files_only": True},
    {"dir": "a/b/c", "depth": 3, "files_only": True},
    {"dir": "a/b_x", "files_only": True},
    {"dir": "a/b%", "files_only": True},
    {"parent": ""},
    {"parent": "a"},
    {"parent": "a/b"},
    {"parent": "a/b/c/deep"},
    {"parent": "nope"},
    {"kind": "image"},
    {"q": "ONE"},
    {"q": "b_"},
    {"q": "naïve"},
    {"sort": "name", "desc": "0"},
    {"sort": "rel_path", "desc": "1"},
    {"sort": "mtime_ns"},
    {"limit": 3},
    {"limit": 3, "offset": 4},
]


def _backends(tmp_path):
    out = [("memory", MemoryBackend()),
           ("sqlite", SqliteBackend(str(tmp_path / "c.sqlite"))),
           ("jsonl", JsonlBackend(str(tmp_path / "c.jsonl"))),
           ("jsonl_dir", JsonlDirBackend(str(tmp_path / "c-jsonl")))]
    for name, env in (("postgres", "FILECAT_TEST_POSTGRES"), ("mysql", "FILECAT_TEST_MYSQL"),
                      ("mssql", "FILECAT_TEST_MSSQL"), ("mongodb", "FILECAT_TEST_MONGODB")):
        if os.environ.get(env):
            from filecat.backends import open_backend
            out.append((name, open_backend(name, dsn=os.environ[env])))
    return out


@pytest.fixture
def loaded(tmp_path):
    backends = _backends(tmp_path)
    for _, b in backends:
        for root in (ROOT, OTHER):
            for doc in list(b.list(root=root)):  # server backends may hold an earlier run
                b.delete(root, doc["rel_path"])
        b.put_many([dict(d) for d in DOCS])
        b.flush()
    yield backends
    for _, b in backends:
        b.close()


def _keys(result):
    return [d["rel_path"] for d in result["rows"]]


@pytest.mark.parametrize("raw", QUERIES, ids=[str(q) for q in QUERIES])
def test_backends_agree_with_reference(loaded, raw):
    q = browse.normalize({"root": ROOT, **raw})
    ref = loaded[0][1].query(q)
    assert ref["total"] == len([d for d in DOCS if d["root"] == ROOT and browse.matches(d, q)])
    for name, b in loaded[1:]:
        got = b.query(q)
        assert (got["total"], got["bytes"]) == (ref["total"], ref["bytes"]), name
        if q["sort"] in ("size", "mtime_ns") or "parent" in q:
            # ties broken by rel_path; byte order of non-ASCII may differ by collation
            assert sorted(_keys(got)) == sorted(_keys(ref)), name
        else:
            assert _keys(got) == _keys(ref), name


def test_expected_matches():
    def keys(**raw):
        q = browse.normalize({"root": ROOT, **raw})
        return sorted(d["rel_path"] for d in DOCS if d["root"] == ROOT and browse.matches(d, q))

    assert keys(dir="a", files_only=True) == ["a/empty.txt", "a/one.txt", "a/two.BIN"]
    assert keys(dir="a/b", files_only=True) == ["a/b/c/deep/five.txt", "a/b/c/four.png", "a/b/three.png"]
    assert keys(dir="a/b", depth=3, files_only=True) == ["a/b/three.png"]
    assert keys(parent="") == ["README", "a", "top.txt"]
    assert keys(parent="a/b") == ["a/b/c", "a/b/three.png"]
    assert keys(unreadable=True) == ["a/gone.dat"]
    assert keys(errors=True) == ["a/empty.txt", "a/gone.dat"]


def test_drill_matches_summary_counts(loaded):
    for name, b in loaded:
        roots = b.summary(depth=2)["roots"]
        for table, field in (("suffix", "suffix"), ("mime", "mime"), ("dir", "dir")):
            for row in roots[ROOT][table]:
                got = b.query(browse.normalize({"root": ROOT, field: row[field], "files_only": "1"}))
                assert (got["total"], got["bytes"]) == (row["files"], row["bytes"]), (name, table, row)


def test_normalize_clamps():
    q = browse.normalize({"limit": "99999", "offset": "-5", "sort": "drop table", "kind": ""})
    assert q["limit"] == browse.MAX_LIMIT and q["offset"] == 0 and q["sort"] == "size"
    assert "kind" not in q and q["desc"] is True


@pytest.mark.parametrize("parent", ["", "a", "a/b", "a/b/c", "a/b%", "nope"])
def test_subtree(loaded, parent):
    ref = browse.subtree_documents([d for d in DOCS if d["root"] == ROOT], parent)
    for name, b in loaded:
        assert b.subtree(ROOT, parent) == ref, name


def test_subtree_expected():
    rows = {r["name"]: (r["files"], r["bytes"])
            for r in browse.subtree_documents([d for d in DOCS if d["root"] == ROOT], "a")}
    assert rows == {"b": (3, 1200), "b_x": (1, 600), "b%": (1, 700)}


@pytest.mark.parametrize("prefix", ["", "a", "a/b", "a/b%", "nope"])
def test_sizes(loaded, prefix):
    ref = sorted(browse.size_rows([d for d in DOCS if d["root"] == ROOT], prefix))
    for name, b in loaded:
        assert sorted(tuple(r) for r in b.sizes(ROOT, prefix)) == ref, name


def test_sizes_expected():
    rows = {r[0]: r[1:] for r in browse.size_rows([d for d in DOCS if d["root"] == ROOT], "a/b")}
    assert rows == {"a/b/three.png": (300, "png", "image/png"), "a/b/c/four.png": (400, "png", "image/png"),
                    "a/b/c/deep/five.txt": (500, "txt", "text/plain")}
    everything = list(browse.size_rows([d for d in DOCS if d["root"] == ROOT], ""))
    assert ("README", 5, "", "text/plain") in everything
    assert ("a/two.BIN", 200, "bin", "data") in everything  # no mime: the kind
    assert not any(r[0] == "a/gone.dat" for r in everything)  # unreadable
