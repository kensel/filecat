"""filecat.treemap: folders beneath a prefix, split by extension and type,
and the snapshot rules (save prunes, pins keep, unpin)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from filecat import treemap
from filecat.backends.memory import MemoryBackend

ROWS = [
    ("top.txt", 10, "txt", "text/plain"),
    ("a/one.txt", 100, "txt", "text/plain"),
    ("a/b/two.png", 200, "png", "image/png"),
    ("a/b/c/three.png", 300, "png", "image/png"),
    ("a/b/c/d/four", 400, "", "data"),
    ("z/five.txt", 5, "txt", "text/plain"),
]


def _folders(tm):
    return {f["path"]: (f["files"], f["bytes"]) for f in tm["folders"]}


def test_folders_cut_at_depth():
    tm = treemap.build(ROWS, "", 2)
    assert (tm["files"], tm["bytes"]) == (6, 1015)
    assert _folders(tm) == {"": (1, 10), "a": (1, 100), "a/b": (3, 900), "z": (1, 5)}
    assert [f["path"] for f in tm["folders"]] == ["a/b", "a", "", "z"]  # biggest first
    assert _folders(treemap.build(ROWS, "", 1)) == {"": (1, 10), "a": (4, 1000), "z": (1, 5)}


def test_prefix_is_relative():
    tm = treemap.build([r for r in ROWS if r[0].startswith("a/b/")], "a/b", 2)
    assert tm["prefix"] == "a/b"
    assert _folders(tm) == {"": (1, 200), "c": (1, 300), "c/d": (1, 400)}


def test_split_by_key():
    tm = treemap.build(ROWS, "", 2)
    suffix = [k["key"] for k in tm["keys"]["suffix"]]
    assert suffix == ["png", "(none)", "txt"]
    ab = next(f for f in tm["folders"] if f["path"] == "a/b")
    assert [(suffix[i], b) for i, b in ab["suffix"]] == [("png", 500), ("(none)", 400)]
    mime = [k["key"] for k in tm["keys"]["mime"]]
    assert [(mime[i], b) for i, b in ab["mime"]] == [("image/png", 500), ("data", 400)]
    assert sum(b for f in tm["folders"] for _, b in f["suffix"]) == tm["bytes"]


def test_rare_keys_fold_into_other(monkeypatch):
    monkeypatch.setattr(treemap, "KEEP_KEYS", 2)
    tm = treemap.build(ROWS, "", 2)
    keys = tm["keys"]["suffix"]
    assert [k["key"] for k in keys] == ["png", "(none)", "(other)"]
    assert (keys[2]["files"], keys[2]["bytes"]) == (3, 115)
    top = next(f for f in tm["folders"] if f["path"] == "")
    assert top["suffix"] == [[2, 10]]


def test_many_folders_are_merged_per_parent(monkeypatch):
    monkeypatch.setattr(treemap, "MAX_FOLDERS", 2)
    rows = [(f"p/f{i}/x.bin", 100 - i, "bin", "data") for i in range(5)] + [("q/y.bin", 1, "bin", "data")]
    tm = treemap.build(rows, "", 2)
    assert [(f["path"], f["bytes"], f.get("merged")) for f in tm["folders"]] == [
        ("p/f0", 100, None), ("p/f1", 99, None), ("p/…", 98 + 97 + 96, 3), ("…", 1, 1)]
    assert sum(f["bytes"] for f in tm["folders"]) == tm["bytes"]


# --- snapshots ---------------------------------------------------------------
ROOT, OTHER = r"\\nas\a", r"\\nas\b"
T0 = datetime(2026, 10, 18, 1, 0, tzinfo=timezone.utc)


def _at(minutes):
    return (T0 + timedelta(minutes=minutes)).isoformat()


def _save(b, root, minutes, rows=ROWS, prefix="", depth=2):
    return treemap.save(b, root, treemap.build(rows, prefix, depth), _at(minutes))


def test_save_keeps_only_the_newest_unpinned_per_view():
    b = MemoryBackend()
    first = _save(b, ROOT, 0)
    sub = _save(b, ROOT, 1, prefix="a")
    other = _save(b, OTHER, 2)
    second = _save(b, ROOT, 3)
    assert {m["id"] for m in b.list_treemaps()} == {sub["id"], other["id"], second["id"]}
    assert first["id"] not in {m["id"] for m in b.list_treemaps()}
    assert treemap.newest(b.list_treemaps(ROOT), "", 2)["id"] == second["id"]
    assert treemap.age(second, T0 + timedelta(minutes=63)) == timedelta(hours=1)


def test_pins_survive_saves_and_group_by_time():
    b = MemoryBackend()
    a, o = _save(b, ROOT, 0), _save(b, OTHER, 0)
    treemap.pin(b, [a["id"], o["id"]], "  before  ", _at(5))
    newer = _save(b, ROOT, 10, rows=ROWS[:2])
    [group] = treemap.pins(b, "", 2)
    assert (group["at"], group["label"]) == (_at(5), "before")
    assert [s["id"] for s in group["snapshots"]] == [a["id"], o["id"]]
    assert treemap.pins(b, "", 2, root=OTHER)[0]["snapshots"] == [b.list_treemaps(OTHER)[0]]
    assert treemap.pins(b, "a", 2) == []
    assert b.get_treemap(a["id"])[1]["bytes"] == 1015 and b.get_treemap(newer["id"])[1]["bytes"] == 110


def test_pinning_a_pinned_snapshot_copies_it():
    b = MemoryBackend()
    a = _save(b, ROOT, 0)
    treemap.pin(b, [a["id"]], "one", _at(1))
    [copy] = treemap.pin(b, [a["id"]], "two", _at(2))
    assert copy["id"] != a["id"] and b.get_treemap(a["id"])[0]["pin"]["label"] == "one"
    assert [g["label"] for g in treemap.pins(b, "", 2)] == ["two", "one"]
    with pytest.raises(KeyError):
        treemap.pin(b, ["missing"], None, _at(3))


def test_unpin_deletes_replaced_snapshots_and_keeps_the_newest():
    b = MemoryBackend()
    old = _save(b, ROOT, 0)
    treemap.pin(b, [old["id"]], None, _at(1))
    current = _save(b, OTHER, 0)
    treemap.pin(b, [current["id"]], None, _at(1))
    _save(b, ROOT, 5)  # replaces old as ROOT's newest
    assert treemap.unpin(b, at=_at(1)) == 2
    assert b.get_treemap(old["id"]) is None  # replaced: gone
    assert b.get_treemap(current["id"])[0]["pin"] is None  # still OTHER's newest: kept, unpinned
    assert treemap.pins(b, "", 2) == []
    assert treemap.unpin(b, ids=[current["id"]]) == 0
