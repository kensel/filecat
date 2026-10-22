"""Tests for filecat.importer: PowerShell Get-ChildItem exports and filecat jsonl,
streamed into a MemoryBackend. See file-catalog-requirements.md, "Record".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from filecat import importer
from filecat.backends.memory import MemoryBackend
from filecat.record import root_id as compute_root_id


def _ps_line(**kw) -> str:
    base = {
        "Name": "file.txt", "BaseName": "file", "Extension": ".txt",
        "FullName": r"\\nas-vm\share\file.txt", "DirectoryName": r"\\nas-vm\share",
        "Length": 10, "IsReadOnly": False, "Attributes": "Archive",
        "CreationTimeUtc": "2017-05-10T05:38:58.8237918Z",
        "LastWriteTimeUtc": "2017-05-10T05:38:58.8237918Z",
        "LastAccessTimeUtc": "2026-10-15T03:04:33.3230777Z",
        "LinkTarget": None,
    }
    base.update(kw)
    return json.dumps(base)


def write_jsonl(path: Path, lines: list[str], bom: bool = True) -> None:
    text = "\r\n".join(lines) + ("\r\n" if lines else "")
    data = text.encode("utf-8")
    if bom:
        data = b"\xef\xbb\xbf" + data
    path.write_bytes(data)


# --------------------------------------------------------------------------- timestamps

def test_parse_ts_exact_ns():
    ns = importer.parse_dotnet_ts_ns("2017-05-10T05:38:58.8237918Z")
    # 7 fractional digits are 100 ns ticks: 8237918 * 100 = 823791800
    assert ns % 1_000_000_000 == 823791800
    # Sanity: round-trips through datetime to the same whole second.
    import datetime as dt
    whole = dt.datetime(2017, 5, 10, 5, 38, 58, tzinfo=dt.timezone.utc)
    expected_s = int((whole - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)).total_seconds())
    assert ns == expected_s * 1_000_000_000 + 823791800


def test_parse_ts_no_fraction():
    ns = importer.parse_dotnet_ts_ns("2017-05-10T05:38:58Z")
    assert ns % 1_000_000_000 == 0


def test_parse_ts_offset():
    z = importer.parse_dotnet_ts_ns("2017-05-10T05:38:58Z")
    plus = importer.parse_dotnet_ts_ns("2017-05-10T07:38:58+02:00")
    assert z == plus


def test_parse_ts_missing():
    assert importer.parse_dotnet_ts_ns(None) is None
    assert importer.parse_dotnet_ts_ns("") is None


# --------------------------------------------------------------------------- root inference

def test_infer_root_unc():
    assert importer.infer_root(r"\\nas-vm\git\gitproject.git\config") == r"\\nas-vm\git"


def test_infer_root_drive():
    assert importer.infer_root(r"C:\Users\winuser\file.txt") == r"C:\\".rstrip("\\") + "\\"
    assert importer.infer_root(r"C:\Users\winuser\file.txt") == "C:\\"


def test_rel_path_under():
    assert importer.rel_path_under(r"\\nas-vm\git", r"\\nas-vm\git\gitproject.git\config") == \
        "gitproject.git/config"
    assert importer.rel_path_under("C:\\", r"C:\Users\winuser\file.txt") == "Users/winuser/file.txt"


def test_rel_path_boundary_not_prefix_collision():
    # "\\nas-vm\git" must not match "\\nas-vm\gitfoo\..." as a prefix
    assert importer.rel_path_under(r"\\nas-vm\git", r"\\nas-vm\gitfoo\x") is None


# --------------------------------------------------------------------------- basic import

def test_import_basic_file(fixture_dir: Path):
    jsonl = fixture_dir / "git.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="config", FullName=r"\\nas-vm\git\gitproject.git\config",
                 DirectoryName=r"\\nas-vm\git\gitproject.git", Length=67),
        _ps_line(Name="description", FullName=r"\\nas-vm\git\gitproject.git\description",
                 DirectoryName=r"\\nas-vm\git\gitproject.git", Length=73),
    ])
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend)
    assert stats.ok
    assert stats.lines == 2
    assert stats.malformed == 0
    assert stats.out_of_root == 0
    # 2 files + synthesized dirs: gitproject.git, "" (root)
    assert stats.records == 2
    assert stats.dirs_synthesized == 2

    root = r"\\nas-vm\git"
    doc = backend.get(root, "gitproject.git/config")
    assert doc is not None
    assert doc["size"] == 67
    assert doc["kind"] == "unknown"
    assert "container" not in doc
    assert doc["root"] == root
    assert doc["root_id"] == compute_root_id(root)
    assert doc["probe"]["attributes"] == ["Archive"]
    assert doc["probe"]["readonly"] is False
    assert doc["mtime_ns"] % 1_000_000_000 == 823791800
    assert doc["source"] == {"format": "powershell", "file": "git.jsonl", "line": 1}

    gitdir = backend.get(root, "gitproject.git")
    assert gitdir["kind"] == "dir"
    assert gitdir["probe"]["child_count"] == 2
    assert gitdir["source"]["format"] == "powershell-synth"
    assert "mtime_ns" not in gitdir

    rootdir = backend.get(root, "")
    assert rootdir["kind"] == "dir"
    assert rootdir["probe"]["child_count"] == 1  # one child: gitproject.git


def test_bom_only_file_is_zero_records(fixture_dir: Path):
    jsonl = fixture_dir / "empty.jsonl"
    jsonl.write_bytes(b"\xef\xbb\xbf")
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend)
    assert stats.ok
    assert stats.lines in (0, 1)
    assert stats.records == 0
    assert stats.malformed == 0


def test_malformed_line_counted_and_continues(fixture_dir: Path):
    jsonl = fixture_dir / "bad.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\share\a.txt"),
        "{not json",
        _ps_line(Name="b.txt", FullName=r"\\nas-vm\share\b.txt"),
    ])
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend, synthesize_dirs=False)
    assert stats.ok
    assert stats.malformed == 1
    assert stats.malformed_examples[0][0] == 2
    assert stats.records == 2


def test_every_line_malformed_is_not_ok(fixture_dir: Path):
    jsonl = fixture_dir / "allbad.jsonl"
    write_jsonl(jsonl, ["{not json", "also not json"])
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend)
    assert not stats.ok
    assert stats.records == 0


def test_hidden_file_attributes(fixture_dir: Path):
    jsonl = fixture_dir / "hidden.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="desktop.ini", FullName=r"\\nas-vm\share\#recycle\desktop.ini",
                 Attributes="Hidden, Archive"),
    ])
    backend = MemoryBackend()
    importer.import_file(str(jsonl), backend, synthesize_dirs=False)
    doc = backend.get(r"\\nas-vm\share", "#recycle/desktop.ini")
    assert doc["probe"]["attributes"] == ["Hidden", "Archive"]


def test_link_entry(fixture_dir: Path):
    jsonl = fixture_dir / "link.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="shortcut", FullName=r"\\nas-vm\share\shortcut",
                 Attributes="ReparsePoint, Archive", LinkTarget=r"\\nas-vm\share\target"),
    ])
    backend = MemoryBackend()
    importer.import_file(str(jsonl), backend, synthesize_dirs=False)
    doc = backend.get(r"\\nas-vm\share", "shortcut")
    assert doc["kind"] == "link"
    assert doc["probe"]["link_target"] == r"\\nas-vm\share\target"


def test_zero_length_file_is_empty(fixture_dir: Path):
    jsonl = fixture_dir / "zero.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="empty.txt", FullName=r"\\nas-vm\share\empty.txt", Length=0),
    ])
    backend = MemoryBackend()
    importer.import_file(str(jsonl), backend, synthesize_dirs=False)
    doc = backend.get(r"\\nas-vm\share", "empty.txt")
    assert doc["kind"] == "empty"
    assert doc["size"] == 0


def test_nested_path_dir_synthesis_and_child_counts(fixture_dir: Path):
    jsonl = fixture_dir / "nested.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\share\dir1\dir2\a.txt"),
        _ps_line(Name="b.txt", FullName=r"\\nas-vm\share\dir1\dir2\b.txt"),
        _ps_line(Name="c.txt", FullName=r"\\nas-vm\share\dir1\c.txt"),
    ])
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend)
    root = r"\\nas-vm\share"
    assert backend.get(root, "dir1/dir2")["probe"]["child_count"] == 2
    assert backend.get(root, "dir1")["probe"]["child_count"] == 2  # dir2 + c.txt
    assert backend.get(root, "")["probe"]["child_count"] == 1  # dir1
    assert stats.dirs_synthesized == 3  # dir1/dir2, dir1, root


def test_drive_letter_path(fixture_dir: Path):
    jsonl = fixture_dir / "drive.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="file.txt", FullName=r"C:\Users\winuser\file.txt"),
    ])
    backend = MemoryBackend()
    importer.import_file(str(jsonl), backend, synthesize_dirs=False)
    doc = backend.get("C:\\", "Users/winuser/file.txt")
    assert doc is not None
    assert doc["root"] == "C:\\"


def test_no_dirs_flag_suppresses_synthesis(fixture_dir: Path):
    jsonl = fixture_dir / "nodirs.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\share\dir1\a.txt"),
    ])
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend, synthesize_dirs=False)
    assert stats.dirs_synthesized == 0
    assert backend.get(r"\\nas-vm\share", "dir1") is None


# --------------------------------------------------------------------------- root override

def test_root_override(fixture_dir: Path):
    jsonl = fixture_dir / "root_override.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\share\sub\a.txt"),
    ])
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend, root=r"\\nas-vm\share\sub", synthesize_dirs=False)
    assert stats.ok
    doc = backend.get(r"\\nas-vm\share\sub", "a.txt")
    assert doc is not None
    assert doc["root"] == r"\\nas-vm\share\sub"


def test_out_of_root(fixture_dir: Path):
    jsonl = fixture_dir / "oor.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\other\a.txt"),
        _ps_line(Name="b.txt", FullName=r"\\nas-vm\share\b.txt"),
    ])
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend, root=r"\\nas-vm\share", synthesize_dirs=False)
    assert stats.out_of_root == 1
    assert stats.records == 1
    assert backend.get(r"\\nas-vm\share", "b.txt") is not None


# --------------------------------------------------------------------------- filecat format round trip

def test_filecat_format_round_trip(fixture_dir: Path):
    root = r"\\nas-vm\share"
    doc = {
        "root_id": compute_root_id(root), "root": root, "rel_path": "a/b.txt",
        "name": "b.txt", "size": 5, "kind": "unknown", "suffix": "txt",
        "mtime_ns": 123456789000000000,
    }
    jsonl = fixture_dir / "fc.jsonl"
    jsonl.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    backend = MemoryBackend()
    stats = importer.import_file(str(jsonl), backend, fmt="filecat")
    assert stats.ok
    assert stats.records == 1
    got = backend.get(root, "a/b.txt")
    assert got["size"] == 5
    assert got["mtime_ns"] == 123456789000000000


def test_filecat_format_reroot(fixture_dir: Path):
    old_root = r"\\nas-vm\share"
    new_root = r"\\nas-other\share"
    doc = {
        "root_id": compute_root_id(old_root), "root": old_root, "rel_path": "a.txt",
        "name": "a.txt", "size": 5, "kind": "unknown", "suffix": "txt",
    }
    jsonl = fixture_dir / "fc_reroot.jsonl"
    jsonl.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    backend = MemoryBackend()
    importer.import_file(str(jsonl), backend, fmt="filecat", root=new_root)
    assert backend.get(old_root, "a.txt") is None
    got = backend.get(new_root, "a.txt")
    assert got is not None
    assert got["root_id"] == compute_root_id(new_root)


# --------------------------------------------------------------------------- idempotency

def test_reimport_idempotent(fixture_dir: Path):
    jsonl = fixture_dir / "idem.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\share\dir1\a.txt"),
        _ps_line(Name="b.txt", FullName=r"\\nas-vm\share\dir1\b.txt"),
    ])
    backend = MemoryBackend()
    importer.import_file(str(jsonl), backend)
    count_after_first = len(backend.docs)
    importer.import_file(str(jsonl), backend)
    assert len(backend.docs) == count_after_first


def test_skip_already_probed_file(fixture_dir: Path):
    """A record with container set (already probed by enrich) and matching
    size/mtime is kept rather than clobbered by a re-import."""
    root = r"\\nas-vm\share"
    jsonl = fixture_dir / "skip.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\share\a.txt", Length=10,
                 LastWriteTimeUtc="2017-05-10T05:38:58.8237918Z"),
    ])
    backend = MemoryBackend()
    mtime_ns = importer.parse_dotnet_ts_ns("2017-05-10T05:38:58.8237918Z")
    backend.put({
        "root_id": compute_root_id(root), "root": root, "rel_path": "a.txt",
        "name": "a.txt", "size": 10, "kind": "text", "suffix": "txt",
        "container": "plain", "mtime_ns": mtime_ns, "sha256": "deadbeef",
    })
    stats = importer.import_file(str(jsonl), backend, synthesize_dirs=False)
    assert stats.skipped_existing == 1
    assert stats.records == 0
    doc = backend.get(root, "a.txt")
    assert doc["kind"] == "text"
    assert doc["sha256"] == "deadbeef"


def test_open_missing_file_reports_error(fixture_dir: Path):
    backend = MemoryBackend()
    stats = importer.import_file(str(fixture_dir / "does-not-exist.jsonl"), backend)
    assert not stats.ok
    assert stats.open_error is not None


# --------------------------------------------------------------------------- CLI run()

class _Args:
    def __init__(self, files, **kw):
        self.files = files
        self.format = "auto"
        self.root = None
        self.no_dirs = False
        self.backend = "memory"
        self.out = None
        self.dsn = None
        self.__dict__.update(kw)


def test_run_cli(monkeypatch, fixture_dir: Path):
    jsonl = fixture_dir / "cli.jsonl"
    write_jsonl(jsonl, [
        _ps_line(Name="a.txt", FullName=r"\\nas-vm\share\a.txt"),
    ])
    shared = {}

    def fake_open_backend(name, out, dsn):
        b = MemoryBackend()
        shared["backend"] = b
        return b

    monkeypatch.setattr(importer, "open_backend", fake_open_backend)
    args = _Args([str(jsonl)])
    rc = importer.run(args)
    assert rc == 0
    assert shared["backend"].get(r"\\nas-vm\share", "a.txt") is not None


def test_run_cli_all_malformed_exit_1(monkeypatch, fixture_dir: Path):
    jsonl = fixture_dir / "cli_bad.jsonl"
    write_jsonl(jsonl, ["{not json"])

    def fake_open_backend(name, out, dsn):
        return MemoryBackend()

    monkeypatch.setattr(importer, "open_backend", fake_open_backend)
    args = _Args([str(jsonl)])
    rc = importer.run(args)
    assert rc == 1
