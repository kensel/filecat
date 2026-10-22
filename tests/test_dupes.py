from __future__ import annotations

import os

from filecat.dupes_cmd import find_duplicates, sample_ranges
from filecat.options import MiB

SIZE = 3 * MiB
KW = dict(min_size=1 * MiB, samples=4, window=64 * 1024)


def _doc(name: str, size: int = SIZE) -> dict:
    return {"root": "r", "rel_path": name, "kind": "file", "size": size}


def _write(dir_, name: str, data: bytes) -> None:
    (dir_ / name).write_bytes(data)


def _find(dir_, names, **extra):
    return find_duplicates([_doc(n) for n in names], lambda root, rel: str(dir_ / rel),
                           **{**KW, **extra})


def test_sample_ranges_cover_start_and_end_without_overlap():
    r = sample_ranges(SIZE, 4, 64 * 1024)
    assert len(r) == 4 and r[0] == (0, 65536) and r[-1] == (SIZE - 65536, 65536)
    assert all(a[0] + a[1] <= b[0] for a, b in zip(r, r[1:]))
    assert all(off % 4096 == 0 for off, _ in r)


def test_sample_ranges_small_file_is_read_whole():
    assert sample_ranges(100_000, 4, 64 * 1024) == [(0, 100_000)]


def test_identical_files_cluster_and_unrelated_same_size_do_not(fixture_dir):
    data = os.urandom(SIZE)
    _write(fixture_dir, "a.bin", data)
    _write(fixture_dir, "b.bin", data)
    _write(fixture_dir, "c.bin", os.urandom(SIZE))
    clusters, errors = _find(fixture_dir, ["a.bin", "b.bin", "c.bin"])
    assert not errors and len(clusters) == 1
    c = clusters[0]
    assert c["copies"] == 2 and c["wasted_bytes"] == SIZE and c["confirmed"] == "sparse"
    assert [p["rel_path"] for p in c["paths"]] == ["a.bin", "b.bin"]


def test_difference_inside_a_window_splits_the_pair(fixture_dir):
    data = bytearray(os.urandom(SIZE))
    _write(fixture_dir, "a.bin", bytes(data))
    data[10] ^= 0xFF                      # first window
    _write(fixture_dir, "b.bin", bytes(data))
    assert _find(fixture_dir, ["a.bin", "b.bin"])[0] == []


def test_full_catches_a_difference_between_the_windows(fixture_dir):
    data = bytearray(os.urandom(SIZE))
    _write(fixture_dir, "a.bin", bytes(data))
    data[SIZE // 2 - 100_000] ^= 0xFF     # in the gap between windows 2 and 3
    _write(fixture_dir, "b.bin", bytes(data))
    sparse, _ = _find(fixture_dir, ["a.bin", "b.bin"])
    assert len(sparse) == 1 and sparse[0]["confirmed"] == "sparse"
    assert _find(fixture_dir, ["a.bin", "b.bin"], full=True)[0] == []


def test_full_confirms_and_full_max_leaves_big_clusters_sparse(fixture_dir):
    data = os.urandom(SIZE)
    for n in ("a.bin", "b.bin"):
        _write(fixture_dir, n, data)
    assert _find(fixture_dir, ["a.bin", "b.bin"], full=True)[0][0]["confirmed"] == "full"
    over = _find(fixture_dir, ["a.bin", "b.bin"], full=True, full_max=1 * MiB)[0]
    assert over[0]["confirmed"] == "sparse (over --full-max)"


def _backup(doc: dict, fmt: str = "thunderbird-ietng") -> dict:
    return {**doc, "kind": "data", "probe": {"backup_data": fmt}}


def _copies(fixture_dir, names):
    data = os.urandom(SIZE)
    for n in names:
        (fixture_dir / n).parent.mkdir(exist_ok=True)
        _write(fixture_dir, n, data)


def test_copies_only_among_backups_are_not_reported_or_read(fixture_dir):
    _copies(fixture_dir, ["b1/x.eml", "b2/x.eml"])
    read = []
    docs = [_backup(_doc("b1/x.eml")), _backup(_doc("b2/x.eml"))]

    def path(root, rel):
        read.append(rel)
        return str(fixture_dir / rel)

    assert find_duplicates(docs, path, **KW) == ([], [])
    assert read == []       # a size group with nothing outside the backups is never opened
    clusters, _ = find_duplicates(docs, path, **KW, include_backups=True)
    assert len(clusters) == 1 and [p["backup"] for p in clusters[0]["paths"]] == ["thunderbird-ietng"] * 2


def test_a_backup_file_matching_one_outside_is_reported_with_its_backup_copies(fixture_dir):
    _copies(fixture_dir, ["b1/x.eml", "b2/x.eml", "live/x.eml"])
    docs = [_backup(_doc("b1/x.eml")), _backup(_doc("b2/x.eml")), _doc("live/x.eml")]
    clusters, _ = find_duplicates(docs, lambda root, rel: str(fixture_dir / rel), **KW)
    assert len(clusters) == 1 and clusters[0]["copies"] == 3
    assert [p.get("backup") for p in clusters[0]["paths"]] == ["thunderbird-ietng", "thunderbird-ietng", None]


def test_min_size_dirs_and_unreadable_files_are_skipped(fixture_dir):
    data = os.urandom(SIZE)
    _write(fixture_dir, "a.bin", data)
    _write(fixture_dir, "b.bin", data)
    docs = [_doc("a.bin"), _doc("b.bin"), _doc("gone.bin"), {**_doc("d"), "kind": "dir"},
            _doc("tiny.bin", 10)]
    clusters, errors = find_duplicates(docs, lambda root, rel: str(fixture_dir / rel), **KW)
    assert len(clusters) == 1 and clusters[0]["copies"] == 2
    assert len(errors) == 1 and "gone.bin" in errors[0]


def test_list_sized_band_is_lower_exclusive_upper_inclusive():
    from filecat.backends.base import Backend

    class Fake:
        def list(self, root=None):
            return iter([_doc("lo", 10), _doc("mid", 20), _doc("hi", 30), _doc("over", 31),
                         {**_doc("dir", 25), "kind": "dir"}])

    assert [d["rel_path"] for d in Backend.list_sized(Fake(), 10, 30)] == ["mid", "hi"]
    assert [d["rel_path"] for d in Backend.list_sized(Fake(), 30)] == ["over"]


def _stub_target_query(monkeypatch, fixture_dir):
    """imagelist runs `EXE -f walkfs --json IMAGE`; the stub prints IMAGE's text."""
    import subprocess
    import sys
    from filecat import imagelist
    stub = fixture_dir / "stub_tq.py"
    stub.write_text("import sys\nsys.stdout.write(open(sys.argv[1]).read())\n")
    real = subprocess.Popen
    monkeypatch.setattr(imagelist.subprocess, "Popen",
                        lambda cmd, **kw: real([sys.executable, str(stub), cmd[-1]], **kw))


def _image(path, entries):
    import json
    rows = [{"_type": "recorddescriptor"}] + [
        {"_type": "record", "type": t, "path": p, "size": s, "mtime": m} for t, p, s, m in entries]
    path.write_text("\n".join(json.dumps(r) for r in rows))


def test_streams_match_stop_at_first_difference_and_ignore_folders(fixture_dir, monkeypatch):
    from filecat import imagelist
    _stub_target_query(monkeypatch, fixture_dir)
    base = [("dir", "\\sysvol", 0, "t0"), ("file", "\\sysvol\\a.txt", 5, "t1"),
            ("file", "\\sysvol\\b.txt", 7, "t2")]
    _image(fixture_dir / "a.vhd", base)
    _image(fixture_dir / "b.vhd", base)
    _image(fixture_dir / "c.vhd", base[:2] + [("file", "\\sysvol\\b.txt", 7, "t9")])
    _image(fixture_dir / "d.vhd", base + [("file", "\\sysvol\\z.txt", 1, "t3")])
    pair = lambda x, y: imagelist.compare_streams("x", str(fixture_dir / x), str(fixture_dir / y))
    same = pair("a.vhd", "b.vhd")
    assert same["identical"] and same["files"] == 2 and len(same["digest"]) == 64
    diff = pair("a.vhd", "c.vhd")
    assert not diff["identical"] and diff["compared"] == 1
    assert diff["first_difference"] == [("\\sysvol\\b.txt", 7, "t2"), ("\\sysvol\\b.txt", 7, "t9")]
    longer = pair("a.vhd", "d.vhd")                       # one listing ends first
    assert not longer["identical"] and longer["first_difference"][0] is None


def test_compare_images_marks_cluster_and_skips_non_images(fixture_dir, monkeypatch):
    from filecat.dupes_cmd import _compare_images
    _stub_target_query(monkeypatch, fixture_dir)
    entries = [("file", "\\v\\a", 1, "t")]
    _image(fixture_dir / "a.vhd", entries)
    _image(fixture_dir / "b.vhd", entries)

    def where(root, rel):
        return str(fixture_dir / rel)

    cluster = {"paths": [{"root": "r", "rel_path": "a.vhd"}, {"root": "r", "rel_path": "b.vhd"}]}
    _compare_images("x", cluster, where)
    assert cluster["listing"] == "identical"
    other = {"paths": [{"root": "r", "rel_path": "a.iso"}, {"root": "r", "rel_path": "b.iso"}]}
    _compare_images("x", other, where)
    assert "listing" not in other
    broken = {"paths": [{"root": "r", "rel_path": "a.vhd"}, {"root": "r", "rel_path": "gone.vhd"}]}
    _compare_images("x", broken, where)
    assert broken["listing"].startswith("unavailable")
