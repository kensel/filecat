"""Resume: top-most markers only, throttled saves, skipping finished folders
of an unfinished scan, retrying folders that could not be listed."""
from __future__ import annotations

import io
import json
import os

import pytest

import filecat.scan as scan
import filecat.walker as walker_mod
from filecat.backends.memory import MemoryBackend
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from tests._fakes import FakeIdentifier, fake_probe_file
from tests.test_scan import _resume_path


@pytest.fixture(autouse=True)
def _fakes(monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)


def _mail_tree(base, shards=("D6", "E1"), subs=("01", "02"), per=3):
    """Mail/<2 hex>/<2 hex>/<message id>/v1-SKEL, like Office 365 backups."""
    for a in shards:
        for b in subs:
            for i in range(per):
                d = base / "Mail" / a / b / f"{a}{b}{i:028X}"
                d.mkdir(parents=True)
                (d / "v1-SKEL").write_text(f"{a}{b}{i}")
    (base / "top.txt").write_text("top")
    # Fixed folder mtimes: NTFS updates the copy a parent's listing holds a
    # moment after a folder changes, so a tree scanned the instant it was
    # built could report different mtimes to the first and second scan.
    for dirpath, _, _ in os.walk(base, topdown=False):
        os.utime(dirpath, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))


def test_markers_collapse_to_the_top_most_folder(tmp_path):
    r = ResumeState(str(tmp_path / "r.json"), save_seconds=0)
    for leaf in ("x1", "x2"):
        r.mark_dir_complete("R", f"Mail/D6/01/{leaf}", 1, 1)
    r.mark_dir_complete("R", "Mail/D6/01", 1, 2, child_dirs=["x1", "x2"])
    r.mark_dir_complete("R", "Mail/D6/02", 1, 0)
    assert set(r.roots["R"]) == {"Mail/D6/01", "Mail/D6/02"}
    r.mark_dir_complete("R", "Mail/D6", 1, 2, child_dirs=["01", "02"])
    assert set(r.roots["R"]) == {"Mail/D6"}
    on_disk = json.loads((tmp_path / "r.json").read_text())
    assert on_disk == {"version": 2, "roots": {"R": {"Mail/D6": {"mtime_ns": 1, "child_count": 2}}}}


def test_saves_are_throttled_and_flush_backend_first(tmp_path):
    calls = []
    path = tmp_path / "r.json"
    r = ResumeState(str(path), save_seconds=3600, before_save=lambda: calls.append("flush"))
    r.mark_dir_complete("R", "a", 1, 0)
    r.mark_dir_complete("R", "b", 1, 0)
    assert not path.exists() and calls == []
    r.flush()
    assert set(json.loads(path.read_text())["roots"]["R"]) == {"a", "b"} and calls == ["flush"]
    r.flush()  # nothing new: no write
    assert calls == ["flush"]


def test_version_1_file_is_compacted_and_finished_roots_dropped(tmp_path):
    path = tmp_path / "r.json"
    m = {"mtime_ns": 1, "child_count": 1}
    path.write_text(json.dumps({
        "done-root": {"": m, "a": m},
        "unfinished": {"Mail/D6": m, "Mail/D6/01": m, "Mail/D6/01/x": m, "Mail/E1/01/y": m},
    }))
    r = ResumeState(str(path))
    assert r.roots == {"unfinished": {"Mail/D6": m, "Mail/E1/01/y": m}}


def test_rerun_of_an_interrupted_scan_skips_finished_folders(fixture_dir, monkeypatch):
    _mail_tree(fixture_dir)
    root = str(fixture_dir)
    resume_path = _resume_path()
    backend = MemoryBackend()

    measured = []
    real_measure = scan.measure_file

    def stop_in_e1(root_, rel, abs_path, *a):
        if "/E1/" in rel:
            raise KeyboardInterrupt  # Ctrl+C half way through
        measured.append(rel)
        return real_measure(root_, rel, abs_path, *a)
    monkeypatch.setattr(scan, "measure_file", stop_in_e1)
    with pytest.raises(KeyboardInterrupt):
        scan.scan_roots([root], backend, ScanOptions(workers=1), resume_path=resume_path)
    saved = ResumeState(resume_path).roots[root]
    assert "Mail/D6" in saved and not any(k.startswith("Mail/D6/") for k in saved)

    listed = []
    real_scandir = os.scandir
    monkeypatch.setattr(walker_mod.os, "scandir", lambda p: listed.append(p) or real_scandir(p))
    monkeypatch.setattr(scan, "measure_file", lambda *a: measured.append(a[1]) or real_measure(*a))
    measured.clear()
    assert scan.scan_roots([root], backend, ScanOptions(workers=1), resume_path=resume_path) == 0

    assert not any(os.sep + "D6" in p for p in listed)  # finished folder not even listed
    assert measured and all("/E1/" in r or r == "top.txt" for r in measured)
    files = {d["rel_path"] for d in backend.list(root=root) if d["kind"] != "dir"}
    assert len(files) == 2 * 2 * 3 + 1  # nothing lost across the interruption
    assert ResumeState(resume_path).roots == {}  # finished cleanly: forgotten


def test_unlistable_folder_keeps_the_root_unfinished(fixture_dir, monkeypatch):
    (fixture_dir / "ok").mkdir()
    (fixture_dir / "ok" / "a.txt").write_text("a")
    (fixture_dir / "flaky").mkdir()
    (fixture_dir / "flaky" / "b.txt").write_text("b")
    root, resume_path, backend = str(fixture_dir), _resume_path(), MemoryBackend()
    real_scandir = os.scandir

    def flaky(path):
        if os.path.basename(path) == "flaky":
            raise TimeoutError("NAS")
        return real_scandir(path)
    monkeypatch.setattr(walker_mod.os, "scandir", flaky)
    assert scan.scan_roots([root], backend, ScanOptions(), resume_path=resume_path) == 1
    assert set(ResumeState(resume_path).roots[root]) == {"ok"}  # flaky and the root not done

    monkeypatch.setattr(walker_mod.os, "scandir", real_scandir)
    assert scan.scan_roots([root], backend, ScanOptions(), resume_path=resume_path) == 0
    assert backend.get(root, "flaky/b.txt")["kind"] == "text"
    assert ResumeState(resume_path).roots == {}


def test_force_ignores_and_clears_resume(fixture_dir):
    _mail_tree(fixture_dir, shards=("D6",), subs=("01",), per=1)
    root, resume_path = str(fixture_dir), _resume_path()
    r = ResumeState(resume_path)
    r.mark_dir_complete(root, "Mail", os.stat(fixture_dir / "Mail").st_mtime_ns, 1)
    r.flush()
    backend = MemoryBackend()
    scan.scan_roots([root], backend, ScanOptions(force=True), resume_path=resume_path)
    assert any(d["rel_path"].endswith("v1-SKEL") for d in backend.list(root=root))
    assert ResumeState(resume_path).roots == {}


def test_vanished_folder_drops_everything_beneath_it(fixture_dir):
    _mail_tree(fixture_dir, shards=("D6", "E1"), subs=("01",), per=2)
    root, backend = str(fixture_dir), MemoryBackend()
    scan.scan_roots([root], backend, ScanOptions(), resume_path=_resume_path())
    import shutil
    shutil.rmtree(fixture_dir / "Mail" / "E1")
    scan.scan_roots([root], backend, ScanOptions(), resume_path=_resume_path())
    left = {d["rel_path"] for d in backend.list(root=root)}
    assert not any(p.startswith("Mail/E1") for p in left)
    assert any(p.startswith("Mail/D6/01/") for p in left)


def test_progress_line_has_rates_and_counts():
    out = io.StringIO()
    p = scan._Progress("R", interval=3600, stream=out)
    p("R/a", 1_000_000, "measured")
    p("R/b", 500, "unchanged")
    p("R/c", 0, "resumed")
    p.flush()
    line = out.getvalue()
    assert line.startswith("R: 2 files, 1000500 bytes | ")
    assert "files/s" in line and "MB/s" in line and "avg" in line
    assert "1 measured, 1 unchanged, 1 dirs resumed | last: R/c" in line


def test_vanished_records_go_to_the_dropped_store_and_are_purged(fixture_dir, capsys):
    _mail_tree(fixture_dir, shards=("D6", "E1"), subs=("01",), per=2)
    root, backend = str(fixture_dir), MemoryBackend()
    scan.scan_roots([root], backend, ScanOptions(progress_interval=0), resume_path=_resume_path())
    import shutil
    shutil.rmtree(fixture_dir / "Mail" / "E1")
    (fixture_dir / "top.txt").unlink()
    scan.scan_roots([root], backend, ScanOptions(progress_interval=0), resume_path=_resume_path())
    dropped = {d["rel_path"] for d in backend.list_dropped(root)}
    # E1, E1/01, two message folders and their two files, plus top.txt
    assert len(dropped) == 7 and "top.txt" in dropped and "Mail/E1" in dropped
    assert not any(d["rel_path"] in dropped for d in backend.list(root=root))
    assert ", 7 dropped |" in capsys.readouterr().err

    for d in backend.dropped:  # age them past the 90 days
        d["dropped_at"] = "2000-01-01T00:00:00+00:00"
    scan.scan_roots([root], backend, ScanOptions(), resume_path=_resume_path())
    assert backend.dropped == []
    assert "purged 7 dropped records older than 90 days" in capsys.readouterr().err
