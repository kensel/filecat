from __future__ import annotations

import os
import uuid

import filecat.scan as scan
import filecat.walker as walker_mod
from filecat.backends.memory import MemoryBackend
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from tests._fakes import FakeIdentifier, fake_probe_file
from tests.conftest import FIXTURE_ROOT


def _resume_path() -> str:
    # Resume bookkeeping must never land inside the tree being scanned, so it
    # sits beside the fixture directories (tests/_fixtures is removed by git clean only).
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    return str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")


def test_measure_file_builds_document_from_fakes(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    p = fixture_dir / "hello.txt"
    p.write_text("hello world")
    st = os.stat(p, follow_symlinks=False)
    identifier = FakeIdentifier(ScanOptions())

    doc = scan.measure_file(str(fixture_dir), "hello.txt", str(p), st, ScanOptions(), identifier)

    assert doc["kind"] == "text"
    assert doc["mime"] == "application/x-fake"
    assert doc["probe"]["fake_probed"] is True
    assert doc["probe"]["identify_basis"] == "name"
    assert doc["sample"] == "hello world"
    assert "sha256" in doc  # small file, auto policy
    assert "errors" not in doc


def test_measure_file_empty_file_skips_probe(fixture_dir, monkeypatch):
    called = []
    monkeypatch.setattr(scan, "probe_file", lambda *a, **k: called.append(1) or fake_probe_file(*a, **k))
    p = fixture_dir / "empty.bin"
    p.write_bytes(b"")
    st = os.stat(p, follow_symlinks=False)
    identifier = FakeIdentifier(ScanOptions())

    doc = scan.measure_file(str(fixture_dir), "empty.bin", str(p), st, ScanOptions(), identifier)

    assert doc["kind"] == "empty"
    assert not called  # probe_file never called for size 0
    assert "sha256" not in doc and "sha256_partial" not in doc


def test_measure_file_wraps_probe_exception_as_error(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    p = fixture_dir / "boom-probe.bin"
    p.write_text("whatever")
    st = os.stat(p, follow_symlinks=False)
    identifier = FakeIdentifier(ScanOptions())

    doc = scan.measure_file(str(fixture_dir), "boom-probe.bin", str(p), st, ScanOptions(), identifier)

    assert doc["errors"][0]["stage"] == "probe"
    assert doc["kind"] == "unknown"  # never crashed the scan


def test_measure_file_wraps_identify_exception_as_error(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    p = fixture_dir / "boom-identify.bin"
    p.write_text("whatever")
    st = os.stat(p, follow_symlinks=False)
    identifier = FakeIdentifier(ScanOptions())

    doc = scan.measure_file(str(fixture_dir), "boom-identify.bin", str(p), st, ScanOptions(), identifier)

    assert doc["errors"][0]["stage"] == "identify"
    assert "mime" not in doc


def _build_tree(fixture_dir):
    (fixture_dir / "a.txt").write_text("top level")
    dir1 = fixture_dir / "dir1"
    dir1.mkdir()
    (dir1 / "f1.txt").write_text("one")
    dir2 = fixture_dir / "dir2"
    dir2.mkdir()
    (dir2 / "f2.txt").write_text("two")
    return dir1, dir2


def test_scan_roots_exit_code_0_when_clean(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)
    _build_tree(fixture_dir)
    backend = MemoryBackend()
    code = scan.scan_roots([str(fixture_dir)], backend, ScanOptions(),
                           resume_path=_resume_path())
    assert code == 0


def test_scan_roots_exit_code_1_when_any_record_has_errors(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)
    (fixture_dir / "boom-probe.bin").write_text("x")
    backend = MemoryBackend()
    code = scan.scan_roots([str(fixture_dir)], backend, ScanOptions(),
                           resume_path=_resume_path())
    assert code == 1


def test_scan_roots_one_offline_root_does_not_block_other_roots(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)
    good = fixture_dir / "good"
    good.mkdir()
    (good / "ok.txt").write_text("fine")
    missing = str(fixture_dir / "does-not-exist-root")

    backend = MemoryBackend()
    code = scan.scan_roots([missing, str(good)], backend, ScanOptions(),
                           resume_path=_resume_path())
    assert code == 1  # the offline root is an error
    missing_docs = list(backend.list(root=missing))
    assert len(missing_docs) == 1
    assert missing_docs[0]["errors"][0]["stage"] == "stat"
    good_docs = {d["rel_path"]: d for d in backend.list(root=str(good))}
    assert good_docs["ok.txt"]["kind"] == "text"


def test_resume_skips_rehash_of_unchanged_dir_after_sibling_timeout(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)
    dir1, dir2 = _build_tree(fixture_dir)

    hash_calls = []
    real_hash_file = scan.hash_file

    def counting_hash_file(path, size, mtime_ns, policy):
        hash_calls.append(path)
        return real_hash_file(path, size, mtime_ns, policy)

    monkeypatch.setattr(scan, "hash_file", counting_hash_file)

    real_scandir = os.scandir

    def flaky_scandir(path):
        if os.path.abspath(path) == os.path.abspath(str(dir2)):
            raise TimeoutError("simulated NAS timeout listing dir2")
        return real_scandir(path)

    monkeypatch.setattr(walker_mod.os, "scandir", flaky_scandir)

    backend = MemoryBackend()
    resume_path = _resume_path()

    code1 = scan.scan_roots([str(fixture_dir)], backend, ScanOptions(), resume_path=resume_path)
    assert code1 == 1  # dir2's listing failure is an error

    dir1_docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir)) if d["rel_path"].startswith("dir1")}
    assert dir1_docs["dir1/f1.txt"]["kind"] == "text"
    assert not dir1_docs["dir1"].get("errors")

    dir2_doc = backend.get(str(fixture_dir), "dir2")
    assert dir2_doc["errors"][0]["stage"] == "listdir"

    resume = ResumeState(resume_path)
    assert resume.get_dir(str(fixture_dir), "dir1") is not None
    assert resume.get_dir(str(fixture_dir), "dir2") is None  # listing failed -> not marked complete

    first_scan_dir1_hash_calls = [p for p in hash_calls if "dir1" in p]
    assert len(first_scan_dir1_hash_calls) == 1

    # second scan: dir2 now lists fine (real scandir restored), dir1 is
    # unchanged on disk and must not be rehashed.
    monkeypatch.setattr(walker_mod.os, "scandir", real_scandir)
    hash_calls.clear()

    code2 = scan.scan_roots([str(fixture_dir)], backend, ScanOptions(), resume_path=resume_path)
    assert code2 == 0

    dir1_hash_calls_second_scan = [p for p in hash_calls if "dir1" in p]
    assert dir1_hash_calls_second_scan == []
    dir2_hash_calls_second_scan = [p for p in hash_calls if "dir2" in p]
    assert len(dir2_hash_calls_second_scan) == 1


def test_resume_force_remeasures_everything(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)
    _build_tree(fixture_dir)

    hash_calls = []
    real_hash_file = scan.hash_file
    monkeypatch.setattr(scan, "hash_file", lambda *a, **k: (hash_calls.append(a[0]), real_hash_file(*a, **k))[1])

    backend = MemoryBackend()
    resume_path = _resume_path()
    scan.scan_roots([str(fixture_dir)], backend, ScanOptions(), resume_path=resume_path)
    hash_calls.clear()

    scan.scan_roots([str(fixture_dir)], backend, ScanOptions(force=True), resume_path=resume_path)
    assert len(hash_calls) == 3  # a.txt, dir1/f1.txt, dir2/f2.txt all remeasured
