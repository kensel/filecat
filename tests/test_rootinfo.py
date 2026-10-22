"""The root index: what `scan` records about each root's scans."""
from __future__ import annotations

import os

import pytest

import filecat.scan as scan
from filecat import rootinfo
from filecat.backends.memory import MemoryBackend
from filecat.options import ScanOptions
from tests._fakes import FakeIdentifier, fake_probe_file
from tests.test_scan import _build_tree, _resume_path


@pytest.fixture(autouse=True)
def _fakes(monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)


def _scan(backend, *roots):
    return scan.scan_roots([str(r) for r in roots], backend, ScanOptions(), resume_path=_resume_path())


def test_clean_scan_records_counts_and_newest_file(fixture_dir):
    _build_tree(fixture_dir)
    newest = fixture_dir / "dir2" / "f2.txt"
    os.utime(newest, ns=(2_000_000_000_000_000_000, 2_000_000_000_000_000_000))
    backend = MemoryBackend()
    assert _scan(backend, fixture_dir) == 0

    info = backend.get_root_info(str(fixture_dir))
    attempt, last = info["last_attempt"], info["last_scan"]
    assert attempt["status"] == last["status"] == "ok"
    assert attempt["finished_at"] == last["finished_at"] and attempt["host"]
    assert (last["files"], last["dirs"], last["errors"]) == (3, 3, 0)
    assert last["bytes"] == len("top level") + len("one") + len("two")
    assert info["newest_file"] == {"rel_path": "dir2/f2.txt", "mtime_ns": 2_000_000_000_000_000_000}
    assert "last_error" not in info


def test_errors_are_noted_and_kept_by_a_later_clean_scan(fixture_dir):
    bad = fixture_dir / "boom-probe.bin"
    bad.write_text("x")
    backend = MemoryBackend()
    assert _scan(backend, fixture_dir) == 1
    info = backend.get_root_info(str(fixture_dir))
    assert info["last_scan"]["status"] == "errors" and info["last_scan"]["errors"] == 1
    err = info["last_error"]
    assert err["rel_path"] == "boom-probe.bin" and err["stage"] == "probe" and err["at"]

    bad.unlink()
    (fixture_dir / "fine.txt").write_text("ok")
    _scan(backend, fixture_dir)
    info = backend.get_root_info(str(fixture_dir))
    assert info["last_scan"]["status"] == "ok"
    assert info["last_error"] == err  # still visible, with when it happened


def test_unreachable_root(fixture_dir):
    missing = fixture_dir / "no-such-share"
    backend = MemoryBackend()
    _scan(backend, missing)
    info = backend.get_root_info(str(missing))
    assert info["last_scan"]["status"] == "unreachable"
    assert info["last_error"]["stage"] == "stat" and info["last_error"]["rel_path"] == ""


@pytest.mark.parametrize("exc,status", [(KeyboardInterrupt(), "interrupted"),
                                        (RuntimeError("disk on fire"), "failed")])
def test_interrupted_or_failed_walk(fixture_dir, monkeypatch, exc, status):
    _build_tree(fixture_dir)
    backend = MemoryBackend()
    assert _scan(backend, fixture_dir) == 0
    before = backend.get_root_info(str(fixture_dir))["last_scan"]

    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(scan, "walk_root", boom)
    with pytest.raises(type(exc)):
        _scan(backend, fixture_dir)
    info = backend.get_root_info(str(fixture_dir))
    assert info["last_attempt"]["status"] == status and info["last_attempt"]["finished_at"]
    assert info["last_scan"] == before  # the last completed scan is still there
    if status == "failed":
        assert "disk on fire" in info["last_attempt"]["error"]
        assert info["last_error"]["stage"] == "scan"


def test_running_attempt_is_written_before_the_walk(fixture_dir, monkeypatch):
    backend = MemoryBackend()
    seen = {}

    def spy(root, *a, **k):
        seen.update(backend.get_root_info(root)["last_attempt"])
        return False
    monkeypatch.setattr(scan, "walk_root", spy)
    _scan(backend, fixture_dir)
    assert seen["status"] == "running" and seen["finished_at"] is None


def test_index_lists_imported_roots_without_info(fixture_dir):
    _build_tree(fixture_dir)
    backend = MemoryBackend()
    _scan(backend, fixture_dir)
    backend.put({"root_id": "x", "root": r"\\nas\imported", "rel_path": "a.txt", "name": "a.txt",
                 "kind": "text", "size": 1, "suffix": "txt"})
    backend.rebuild_aggregates(root=str(fixture_dir))
    rows = {r["root"]: r for r in rootinfo.index(backend)}
    assert rows[r"\\nas\imported"]["info"] is None and rows[r"\\nas\imported"]["summary"] is None
    assert rows[str(fixture_dir)]["info"]["last_scan"]["status"] == "ok"
    assert rows[str(fixture_dir)]["summary"]["total_files"] == 3


def test_heartbeat_writes_progress_while_walking(fixture_dir, monkeypatch):
    _build_tree(fixture_dir)
    monkeypatch.setattr(rootinfo, "HEARTBEAT_SECONDS", 0.0)
    backend = MemoryBackend()
    beats = []
    real_put_root_info = backend.put_root_info

    def spy(info):
        a = info["last_attempt"]
        if a["status"] == "running" and a.get("progress"):
            beats.append(a["progress"]["files"] + a["progress"]["dirs"])
        real_put_root_info(info)
    monkeypatch.setattr(backend, "put_root_info", spy)
    _scan(backend, fixture_dir)
    assert beats and beats == sorted(beats)  # progress only grows
    final = backend.get_root_info(str(fixture_dir))["last_attempt"]
    assert final["status"] == "ok" and final["progress"]["files"] == 3


def test_state():
    from datetime import datetime, timedelta, timezone
    t = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    running = {"last_attempt": {"status": "running", "started_at": "2026-10-17T11:00:00+00:00",
                                "heartbeat_at": "2026-10-17T11:59:30+00:00"}}
    assert rootinfo.state(running, t) == "in_progress"
    assert rootinfo.state(running, t + timedelta(minutes=10)) == "stalled"
    assert rootinfo.state({"last_attempt": {"status": "errors"}}, t) == "errors"
    assert rootinfo.state(None, t) == "never"
