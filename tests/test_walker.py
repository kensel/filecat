from __future__ import annotations

import os
import sys
import tempfile
import uuid

import pytest

import filecat.walker as walker_mod
from filecat import record
from filecat.backends.memory import MemoryBackend
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import is_drive_root, should_skip_dir, should_skip_root_file, walk_root


def _resume(_unused=None):
    # Resume bookkeeping must never land inside the tree being scanned, so
    # this uses the system temp dir rather than fixture_dir.
    path = os.path.join(tempfile.gettempdir(), f"filecat-test-resume-{uuid.uuid4().hex}.json")
    return ResumeState(path)


def _measure_stub(root, rel_path, abs_path, st, options, identifier):
    doc = record.new_document(root, rel_path, kind="text", size=st.st_size,
                              mtime_ns=st.st_mtime_ns, ctime_ns=st.st_mtime_ns)
    return doc


class FakeEntry:
    """Duck-typed stand-in for os.DirEntry; walker only calls these four
    methods plus `.name` on an entry."""

    def __init__(self, name, real_path, deny=False):
        self.name = name
        self._real_path = real_path
        self._deny = deny

    def stat(self, follow_symlinks=True):
        if self._deny:
            raise PermissionError(f"access denied: {self.name}")
        return os.stat(self._real_path, follow_symlinks=False)

    def is_symlink(self):
        return os.path.islink(self._real_path)

    def is_dir(self, follow_symlinks=True):
        return os.path.isdir(self._real_path)

    def is_file(self, follow_symlinks=True):
        return os.path.isfile(self._real_path)


class FakeScandir:
    def __init__(self, entries):
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *exc):
        return False


# --- pure helper functions -------------------------------------------------

@pytest.mark.skipif(sys.platform != "win32", reason="Windows drive letters")
def test_is_drive_root():
    assert is_drive_root("C:\\")
    assert is_drive_root("C:/")
    assert not is_drive_root("C:\\Users")
    assert not is_drive_root("\\\\server\\share")


def test_should_skip_dir_names():
    assert should_skip_dir("$Recycle.Bin", True)
    assert should_skip_dir("System Volume Information", True)
    assert not should_skip_dir("$Recycle.Bin", False)
    assert not should_skip_dir("normal", True)


def test_should_skip_root_file_only_at_drive_root():
    assert should_skip_root_file("pagefile.sys", True, True)
    assert not should_skip_root_file("pagefile.sys", False, True)
    assert not should_skip_root_file("pagefile.sys", True, False)
    assert not should_skip_root_file("notes.txt", True, True)


# --- walk_root ---------------------------------------------------------

def test_walk_basic_tree_post_order(fixture_dir):
    (fixture_dir / "a.txt").write_text("hello")
    sub = fixture_dir / "sub"
    sub.mkdir()
    (sub / "b.txt").write_text("world")

    backend = MemoryBackend()
    had_errors = walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
                           resume=_resume(fixture_dir), measure_file=_measure_stub)

    assert not had_errors
    docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir))}
    assert docs[""]["kind"] == "dir"
    assert docs[""]["probe"]["child_count"] == 2
    assert docs["a.txt"]["kind"] == "text"
    assert docs["sub"]["kind"] == "dir"
    assert docs["sub"]["probe"]["child_count"] == 1
    assert docs["sub/b.txt"]["kind"] == "text"


def test_access_denied_child_records_error_sibling_still_recorded(fixture_dir, monkeypatch):
    (fixture_dir / "ok.txt").write_text("fine")
    (fixture_dir / "denied.txt").write_text("blocked")
    real_scandir = os.scandir

    def fake_scandir(path):
        if os.path.abspath(path) == os.path.abspath(str(fixture_dir)):
            return FakeScandir([
                FakeEntry("ok.txt", str(fixture_dir / "ok.txt")),
                FakeEntry("denied.txt", str(fixture_dir / "denied.txt"), deny=True),
            ])
        return real_scandir(path)

    backend = MemoryBackend()
    with monkeypatch.context() as m:        # undone before fixture_dir's rmtree
        m.setattr(walker_mod.os, "scandir", fake_scandir)
        had_errors = walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
                               resume=_resume(fixture_dir), measure_file=_measure_stub)

    assert had_errors
    docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir))}
    assert docs["ok.txt"]["kind"] == "text"
    assert "errors" not in docs["ok.txt"] or not docs["ok.txt"]["errors"]
    assert docs["denied.txt"]["errors"][0]["stage"] == "stat"
    assert "PermissionError" in docs["denied.txt"]["errors"][0]["message"]


def test_directory_listing_failure_still_gets_its_own_record(fixture_dir, monkeypatch):
    sub = fixture_dir / "sub"
    sub.mkdir()
    (sub / "inner.txt").write_text("x")
    (fixture_dir / "sibling.txt").write_text("y")
    real_scandir = os.scandir

    def fake_scandir(path):
        if os.path.abspath(path) == os.path.abspath(str(sub)):
            raise PermissionError("cannot list sub")
        return real_scandir(path)

    backend = MemoryBackend()
    with monkeypatch.context() as m:        # undone before fixture_dir's rmtree
        m.setattr(walker_mod.os, "scandir", fake_scandir)
        had_errors = walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
                               resume=_resume(fixture_dir), measure_file=_measure_stub)

    assert had_errors
    docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir))}
    assert docs["sub"]["kind"] == "dir"
    assert docs["sub"]["errors"][0]["stage"] == "listdir"
    assert "probe" not in docs["sub"] or "child_count" not in docs["sub"].get("probe", {})
    assert docs["sibling.txt"]["kind"] == "text"


def test_default_skip_dirs_are_not_recorded(fixture_dir):
    (fixture_dir / "$Recycle.Bin").mkdir()
    (fixture_dir / "$Recycle.Bin" / "deleted.txt").write_text("gone")
    (fixture_dir / "System Volume Information").mkdir()
    (fixture_dir / "normal.txt").write_text("kept")

    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
              resume=_resume(fixture_dir), measure_file=_measure_stub)

    rels = {d["rel_path"] for d in backend.list(root=str(fixture_dir))}
    assert "$Recycle.Bin" not in rels
    assert "$Recycle.Bin/deleted.txt" not in rels
    assert "System Volume Information" not in rels
    assert "normal.txt" in rels


def test_no_default_skips_visits_everything(fixture_dir):
    (fixture_dir / "$Recycle.Bin").mkdir()
    (fixture_dir / "$Recycle.Bin" / "deleted.txt").write_text("gone")

    backend = MemoryBackend()
    options = ScanOptions(default_skips=False)
    walk_root(str(fixture_dir), options, backend, identifier=None,
              resume=_resume(fixture_dir), measure_file=_measure_stub)

    rels = {d["rel_path"] for d in backend.list(root=str(fixture_dir))}
    assert "$Recycle.Bin" in rels
    assert "$Recycle.Bin/deleted.txt" in rels


def test_pagefile_skipped_only_at_drive_root(fixture_dir, monkeypatch):
    (fixture_dir / "pagefile.sys").write_text("fake pagefile")
    (fixture_dir / "notes.txt").write_text("keep me")

    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
              resume=_resume(fixture_dir), measure_file=_measure_stub)
    rels = {d["rel_path"] for d in backend.list(root=str(fixture_dir))}
    # fixture_dir is not a drive root, so pagefile.sys is recorded normally.
    assert "pagefile.sys" in rels

    monkeypatch.setattr(walker_mod, "is_drive_root", lambda p: True)
    backend2 = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend2, identifier=None,
              resume=_resume(fixture_dir), measure_file=_measure_stub)
    rels2 = {d["rel_path"] for d in backend2.list(root=str(fixture_dir))}
    assert "pagefile.sys" not in rels2
    assert "notes.txt" in rels2


def test_hidden_and_dot_entries_are_visited(fixture_dir):
    (fixture_dir / ".hidden").write_text("dotfile")

    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
              resume=_resume(fixture_dir), measure_file=_measure_stub)
    rels = {d["rel_path"] for d in backend.list(root=str(fixture_dir))}
    assert ".hidden" in rels


def test_symlink_recorded_as_link_with_target(fixture_dir):
    target = fixture_dir / "target.txt"
    target.write_text("payload")
    link = fixture_dir / "link.txt"
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("symlink creation not permitted in this environment")

    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
              resume=_resume(fixture_dir), measure_file=_measure_stub)
    docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir))}
    assert docs["link.txt"]["kind"] == "link"
    assert docs["link.txt"]["probe"]["link_target"] == str(target)


@pytest.mark.skipif(sys.platform != "win32", reason="mklink /J is Windows only")
def test_directory_junction_recorded_as_link_not_recursed_into(fixture_dir):
    """Junctions don't need the elevated privilege symlinks do; this gives
    real reparse-point coverage even when the symlink test above skips."""
    import subprocess

    target_dir = fixture_dir / "jtarget"
    target_dir.mkdir()
    (target_dir / "inside.txt").write_text("should not be walked")
    junction = fixture_dir / "jlink"

    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        import pytest
        pytest.skip(f"junction creation not available: {result.stderr or result.stdout}")

    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
              resume=_resume(fixture_dir), measure_file=_measure_stub)
    docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir))}
    assert docs["jlink"]["kind"] == "link"
    assert "jlink/inside.txt" not in docs  # not recursed into
    assert docs["jtarget"]["kind"] == "dir"  # the real directory is walked normally


def test_reparse_point_that_is_not_a_link_has_no_target(monkeypatch):
    """os.readlink raises ValueError, not OSError, on Windows for a reparse
    point that is neither a symlink nor a junction (an app execution alias
    under WindowsApps, a dedup or cloud placeholder)."""
    def not_a_link(path):
        raise ValueError("not a symbolic link")

    monkeypatch.setattr(walker_mod.os, "readlink", not_a_link)
    assert walker_mod.read_link_target("C:/x/alias.exe") is None


def test_offline_root_records_single_error(fixture_dir, monkeypatch):
    missing = str(fixture_dir / "does-not-exist")
    backend = MemoryBackend()
    had_errors = walk_root(missing, ScanOptions(), backend, identifier=None,
                           resume=_resume(fixture_dir), measure_file=_measure_stub)
    assert had_errors
    docs = list(backend.list(root=missing))
    assert len(docs) == 1
    assert docs[0]["rel_path"] == ""
    assert docs[0]["errors"][0]["stage"] == "stat"


def test_offline_unc_root_fails_fast_without_touching_network(monkeypatch, fixture_dir):
    """A real unreachable UNC host can hang on name resolution for a long
    time; monkeypatch os.stat so the test stays fast and deterministic."""
    unc_root = r"\\nonexistent-host-filecat\share"
    real_stat = os.stat

    def fake_stat(path, *a, **kw):
        if path == unc_root:
            raise OSError(53, "The network path was not found")
        return real_stat(path, *a, **kw)

    monkeypatch.setattr(walker_mod.os, "stat", fake_stat)
    backend = MemoryBackend()
    had_errors = walk_root(unc_root, ScanOptions(), backend, identifier=None,
                           resume=_resume(fixture_dir), measure_file=_measure_stub)
    assert had_errors
    docs = list(backend.list(root=unc_root))
    assert len(docs) == 1
    assert docs[0]["errors"][0]["stage"] == "stat"


def test_exclude_skips_folders_and_files_as_read_or_as_recorded(fixture_dir):
    for d in ("keep", "tool", "tool2", "other"):
        (fixture_dir / d).mkdir()
        (fixture_dir / d / "f.txt").write_text(d)
    (fixture_dir / "keep" / "big.log").write_text("x")
    read = str(fixture_dir)
    recorded = "\\\\nas9\\share"
    opts = ScanOptions(exclude=[
        os.path.join(read, "TOOL") + "\\",            # as read; case and trailing slash ignored
        recorded + "\\other",                         # as recorded under the alias
        os.path.join(read, "keep", "big.log").replace("\\", "/"),
    ])
    backend = MemoryBackend()
    walk_root(recorded, opts, backend, identifier=None, resume=_resume(),
              measure_file=_measure_stub, path=read)
    assert sorted(d["rel_path"] for d in backend.list(root=recorded)) == [
        "", "keep", "keep/f.txt", "tool2", "tool2/f.txt"]


def test_unchanged_rescan_reads_stored_records_once_per_directory(fixture_dir):
    for d in ("a", "a/x", "b"):
        (fixture_dir / d).mkdir(parents=True)
        for i in range(3):
            (fixture_dir / d / f"f{i}.txt").write_text(d * (i + 1))
    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
              resume=_resume(), measure_file=_measure_stub)

    calls = {"get": 0, "get_stats": 0}

    class Counting(MemoryBackend):
        def get(self, root, rel_path):
            calls["get"] += 1
            return super().get(root, rel_path)

        def get_stats(self, root, rel_paths):
            calls["get_stats"] += 1
            return super().get_stats(root, rel_paths)

    again = Counting()
    again.docs = backend.docs
    seen = []
    walk_root(str(fixture_dir), ScanOptions(), again, identifier=None, resume=_resume(),
              measure_file=lambda *a: pytest.fail("an unchanged file was measured"),
              progress=lambda p, size, how: seen.append(how))
    assert seen.count("unchanged") == 9
    # the root's own record, then one call per directory (root, a, a/x, b);
    # MemoryBackend.get_stats is the default, which loops over get()
    assert calls["get_stats"] == 5
    assert calls["get"] == 1 + 2 + 4 + 3 + 3       # = the paths those calls asked for


def test_listing_read_ahead_failure_is_recorded_like_before(fixture_dir, monkeypatch):
    (fixture_dir / "ok").mkdir()
    (fixture_dir / "ok" / "f.txt").write_text("x")
    (fixture_dir / "locked").mkdir()
    real = walker_mod._list_dir

    def list_dir(path):
        if path.endswith("locked"):
            raise PermissionError(f"access denied: {path}")
        return real(path)

    monkeypatch.setattr(walker_mod, "_list_dir", list_dir)
    backend = MemoryBackend()
    had_errors = walk_root(str(fixture_dir), ScanOptions(), backend, identifier=None,
                           resume=_resume(), measure_file=_measure_stub)
    docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir))}
    assert had_errors
    assert docs["locked"]["errors"][0]["stage"] == "listdir"
    assert "ok/f.txt" in docs
