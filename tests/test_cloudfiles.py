"""Cloud placeholders. Real ones can only be made by a sync provider, so
the attributes are faked: the walker reads them from the directory entry
(cloudfiles.attributes_of), enrich with GetFileAttributesW
(cloudfiles.file_attributes)."""
from __future__ import annotations

import os
import sys
import tempfile
import uuid

import pytest

from filecat import cloudfiles, record
from filecat.backends.memory import MemoryBackend
from filecat.enrich import enrich, path_matches
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import walk_root

ONLINE = cloudfiles.RECALL_ON_DATA_ACCESS | 0x20       # + ARCHIVE, as OneDrive leaves it


def _resume():
    return ResumeState(os.path.join(tempfile.gettempdir(), f"filecat-test-resume-{uuid.uuid4().hex}.json"))


def _measure_stub(root, rel_path, abs_path, st, options, identifier):
    doc = record.new_document(root, rel_path, kind="text", size=st.st_size,
                              mtime_ns=st.st_mtime_ns, ctime_ns=st.st_mtime_ns)
    doc["sha256"] = "x"
    return doc


class _Ident:
    def by_name(self, name, size, fmt):
        return {"mime_glob": "application/pdf"} if name.endswith(".pdf") else None

    def close(self):
        pass


@pytest.fixture
def onedrive(fixture_dir, monkeypatch):
    """fixture_dir/OneDrive as a sync root holding one online-only, one
    local, one pinned file; plus an ordinary file outside it."""
    od = fixture_dir / "OneDrive"
    (od / "Work").mkdir(parents=True)
    (od / "Work" / "Paystub.pdf").write_bytes(b"%PDF cloud")
    (od / "Work" / "local.txt").write_text("here")
    (od / "Work" / "keep.txt").write_text("pinned")
    (fixture_dir / "plain.txt").write_text("plain")
    attrs = {"Paystub.pdf": ONLINE | cloudfiles.UNPINNED, "keep.txt": cloudfiles.PINNED}
    monkeypatch.setattr(cloudfiles, "sync_roots", lambda: (
        cloudfiles.SyncRoot(str(od), "OneDrive - Personal", "OneDrive!S-1!Personal"),))
    # attributes come from the directory entry; map them by file name
    real_scandir = os.scandir

    class _Entry:
        def __init__(self, e):
            self._e = e
            self.name, self.path = e.name, e.path

        def stat(self, follow_symlinks=True):
            st = self._e.stat(follow_symlinks=follow_symlinks)
            return _Stat(st, attrs.get(self.name, 0))

        def __getattr__(self, item):
            return getattr(self._e, item)

    class _Stat:
        def __init__(self, st, a):
            self._st, self.st_file_attributes = st, a

        def __getattr__(self, item):
            return getattr(self._st, item)

    class _Scandir:
        def __init__(self, path):
            self._it = real_scandir(path)

        def __enter__(self):
            return (_Entry(e) for e in self._it.__enter__())

        def __exit__(self, *a):
            return self._it.__exit__(*a)

    import filecat.walker
    monkeypatch.setattr(filecat.walker.os, "scandir", _Scandir)
    monkeypatch.setattr(cloudfiles, "file_attributes",
                        lambda p: attrs.get(os.path.basename(p), 0))
    return fixture_dir, attrs


def _walk(base, measure=_measure_stub, backend=None, options=None):
    backend = backend or MemoryBackend()
    walk_root(str(base), options or ScanOptions(), backend, _Ident(), _resume(), measure)
    return backend, {d["rel_path"]: d for d in backend.list(root=str(base))}


# --- state and provider -------------------------------------------------------

def test_state_of_attributes():
    assert cloudfiles.state_of(ONLINE) == "online-only"
    assert cloudfiles.state_of(cloudfiles.RECALL_ON_OPEN) == "online-only"
    assert cloudfiles.state_of(cloudfiles.OFFLINE) == "offline"
    assert cloudfiles.state_of(cloudfiles.PINNED) == "pinned"
    assert cloudfiles.state_of(0x20) == "local"
    assert cloudfiles.not_local(cloudfiles.OFFLINE) and not cloudfiles.not_local(cloudfiles.PINNED)


def test_provider_matches_whole_components():
    roots = (cloudfiles.SyncRoot(r"C:\Users\me\OneDrive", "OneDrive - Personal", "x"),)
    assert cloudfiles.provider_for(r"c:\users\me\onedrive\Work\a.pdf", roots) == "OneDrive - Personal"
    assert cloudfiles.provider_for(r"C:\Users\me\OneDrive", roots) == "OneDrive - Personal"
    assert cloudfiles.provider_for(r"C:\Users\me\OneDrive2\a.pdf", roots) is None


def test_describe():
    roots = (cloudfiles.SyncRoot(r"C:\OD", "OneDrive", "x"),)
    assert cloudfiles.describe(r"C:\OD\a", ONLINE | cloudfiles.UNPINNED, roots) == {
        "provider": "OneDrive", "state": "online-only", "unpinned": True}
    assert cloudfiles.describe(r"C:\OD\a", 0x20, roots) == {"provider": "OneDrive", "state": "local"}
    assert cloudfiles.describe(r"\\nas\share\a", cloudfiles.OFFLINE, roots) == {
        "provider": None, "state": "offline"}
    assert cloudfiles.describe(r"D:\a", 0x20, roots) is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry and attributes")
def test_real_attributes_and_sync_roots_do_not_fail(fixture_dir):
    f = fixture_dir / "a.txt"
    f.write_text("x")
    assert cloudfiles.file_attributes(str(f)) is not None
    assert cloudfiles.file_attributes(str(fixture_dir / "missing")) is None
    cloudfiles.sync_roots.cache_clear()
    assert isinstance(cloudfiles.sync_roots(), tuple)


# --- walker -------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "win32", reason="Windows sync roots and attributes")
def test_walker_never_opens_cloud_only_files(onedrive):
    base, _ = onedrive
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    _, docs = _walk(base, measure)
    assert "OneDrive/Work/Paystub.pdf" not in measured
    cloud = docs["OneDrive/Work/Paystub.pdf"]
    assert cloud["kind"] == "unknown" and cloud["size"] == 10 and "sha256" not in cloud
    assert cloud["probe"]["cloud"] == {"provider": "OneDrive - Personal", "state": "online-only",
                                       "unpinned": True}
    assert cloud["mime"] == "application/pdf" and cloud["probe"]["identify_basis"] == "name"
    assert docs["OneDrive/Work/local.txt"]["probe"]["cloud"] == {
        "provider": "OneDrive - Personal", "state": "local"}
    assert docs["OneDrive/Work/keep.txt"]["probe"]["cloud"]["state"] == "pinned"
    assert docs["OneDrive/Work/local.txt"]["sha256"] == "x"
    assert "cloud" not in (docs["plain.txt"].get("probe") or {})


def test_force_does_not_read_cloud_only_files(onedrive):
    base, _ = onedrive
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    _walk(base, measure, options=ScanOptions(force=True))
    assert "OneDrive/Work/Paystub.pdf" not in measured


@pytest.mark.skipif(sys.platform != "win32", reason="Windows sync roots and attributes")
def test_rescan_measures_a_file_that_came_down(onedrive):
    base, attrs = onedrive
    backend, _ = _walk(base)
    attrs["Paystub.pdf"] = 0x20                     # opened in Explorer: on the device now
    _, docs = _walk(base, backend=backend)
    doc = docs["OneDrive/Work/Paystub.pdf"]
    assert doc["sha256"] == "x" and doc["probe"]["cloud"]["state"] == "local"


def test_rescan_leaves_an_unchanged_cloud_only_file(onedrive):
    base, _ = onedrive
    backend, _ = _walk(base)
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    _walk(base, measure, backend=backend)
    assert measured == []


# --- enrich --------------------------------------------------------------------

def _patch_measure(monkeypatch):
    import filecat.scan
    calls = []

    def measure(root, rel_path, *a):
        calls.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    monkeypatch.setattr(filecat.scan, "measure_file", measure)
    return calls


def test_enrich_leaves_cloud_only_files_unread(onedrive, monkeypatch):
    base, _ = onedrive
    backend, _ = _walk(base)
    calls = _patch_measure(monkeypatch)
    stats = enrich(backend, ScanOptions(), stages={"hash", "probe"}, roots=[str(base)],
                   force=True, identifier=_Ident())
    assert "OneDrive/Work/Paystub.pdf" not in calls and stats.cloud_only == 1
    assert "sha256" not in backend.get(str(base), "OneDrive/Work/Paystub.pdf")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows sync roots and attributes")
def test_enrich_hydrate_reads_selected_files_and_frees_them(onedrive, monkeypatch):
    base, attrs = onedrive
    backend, _ = _walk(base)
    calls = _patch_measure(monkeypatch)
    freed = []

    def free_up(path):
        freed.append(os.path.basename(path))
        attrs["Paystub.pdf"] = ONLINE | cloudfiles.UNPINNED
        return True

    monkeypatch.setattr(cloudfiles, "free_up", free_up)
    stats = enrich(backend, ScanOptions(), stages={"hash"}, roots=[str(base)], identifier=_Ident(),
                   paths=["OneDrive/Work/*.pdf"], hydrate=True, free_after=True)
    assert calls == ["OneDrive/Work/Paystub.pdf"] and freed == ["Paystub.pdf"]
    assert stats.downloaded == 1 and stats.downloaded_bytes == 10 and stats.freed == 1
    doc = backend.get(str(base), "OneDrive/Work/Paystub.pdf")
    assert doc["sha256"] == "x"
    assert doc["probe"]["cloud"] == {"provider": "OneDrive - Personal", "state": "online-only",
                                     "unpinned": True, "freed": True}


def test_path_matches():
    assert path_matches("Work/DA/a.zip", ["Work/DA"])
    assert path_matches("Work/DA/a.zip", ["work\\da\\"])
    assert not path_matches("Work/DAX/a.zip", ["Work/DA"])
    assert path_matches("Work/Paystub.pdf", ["*.PDF"])
    assert not path_matches("Work/Paystub.pdf", ["Home/*"])
