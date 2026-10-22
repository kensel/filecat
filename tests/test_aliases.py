from __future__ import annotations

import argparse

import pytest

import filecat.scan as scan
from filecat import aliases, config, rootinfo
from filecat.backends.memory import MemoryBackend
from filecat.options import ScanOptions
from tests._fakes import FakeIdentifier, fake_probe_file
from tests.test_scan import _resume_path

NAS = {"\\\\192.0.2.13": "\\\\nas-main"}


@pytest.mark.parametrize("path, root", [
    ("\\\\192.0.2.13\\home", "\\\\nas-main\\home"),
    ("\\\\192.0.2.13\\Media\\Movies", "\\\\nas-main\\Media\\Movies"),
    ("//192.0.2.13/home/", "\\\\nas-main\\home"),
    ("\\\\192.0.2.13", "\\\\nas-main"),
    ("\\\\192.0.2.130\\home", "\\\\192.0.2.130\\home"),  # whole components only
    ("\\\\nas-main\\home", "\\\\nas-main\\home"),
    ("D:\\Games", "D:\\Games"),
])
def test_recorded_root(path, root):
    assert aliases.recorded_root(path, NAS) == root


def test_longest_prefix_wins_and_case_is_ignored():
    table = {"\\\\192.0.2.13": "\\\\nas-main", "\\\\192.0.2.13\\home": "\\\\nas-main\\users"}
    assert aliases.recorded_root("\\\\192.0.2.13\\HOME\\bob", table) == "\\\\nas-main\\users\\bob"
    assert aliases.recorded_root("\\\\192.0.2.13\\media", table) == "\\\\nas-main\\media"


def test_source_path_reverses():
    assert aliases.source_path("\\\\nas-main\\home", NAS) == "\\\\192.0.2.13\\home"
    assert aliases.source_path("\\\\nas-vm\\home", NAS) == "\\\\nas-vm\\home"


def test_drive_letter_alias():
    assert aliases.recorded_root("Z:\\docs", {"Z:\\": "\\\\nas-main\\share"}) == "\\\\nas-main\\share\\docs"


def test_parse_rejects_missing_side():
    assert aliases.parse(["\\\\1.2.3.4=\\\\nas"]) == {"\\\\1.2.3.4": "\\\\nas"}
    with pytest.raises(ValueError):
        aliases.parse(["\\\\1.2.3.4"])


def test_config_aliases_merge_under_command_line():
    cfg = {"aliases": {"\\\\192.0.2.13": "\\\\nas-main", "\\\\10.0.0.5": "\\\\nas-vm"}}
    args = argparse.Namespace(alias=["\\\\10.0.0.5=\\\\nas01b"])
    config.apply(args, cfg)
    assert args.aliases == {"\\\\192.0.2.13": "\\\\nas-main", "\\\\10.0.0.5": "\\\\nas01b"}
    assert ScanOptions.from_args(args).aliases == args.aliases


def test_scan_reads_path_records_alias(fixture_dir, monkeypatch):
    monkeypatch.setattr(scan, "probe_file", fake_probe_file)
    monkeypatch.setattr(scan, "Identifier", FakeIdentifier)
    share = fixture_dir / "share"
    (share / "sub").mkdir(parents=True)
    (share / "a.txt").write_text("hello")
    (share / "sub" / "b.txt").write_text("world")
    recorded = "\\\\nas-main\\share"
    options = ScanOptions(aliases={str(fixture_dir): "\\\\nas-main"})

    backend = MemoryBackend()
    assert scan.scan_roots([str(share)], backend, options, resume_path=_resume_path()) == 0
    assert backend.roots() == [recorded]
    docs = {d["rel_path"]: d for d in backend.list(root=recorded)}
    assert set(docs) == {"", "a.txt", "sub", "sub/b.txt"}
    assert docs["a.txt"]["size"] == 5
    info = backend.get_root_info(recorded)
    assert info["last_attempt"]["path"] == str(share)
    assert rootinfo.state(info) == "ok"

    # a rescan through the same path updates the same records
    (share / "a.txt").write_text("hello again")
    assert scan.scan_roots([str(share)], backend, options, resume_path=_resume_path()) == 0
    assert backend.get(recorded, "a.txt")["size"] == 11
