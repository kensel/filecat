"""Tests for `filecat signatures status` (src/filecat/signatures.py)."""
from __future__ import annotations

import argparse

from filecat import signatures


def test_status_lists_dir_files_and_vendored_data(fixture_dir, capsys):
    sig_dir = fixture_dir / "sigs"
    sig_dir.mkdir()
    (sig_dir / "plain.txt").write_text("no date in here at all\n", encoding="utf-8")
    (sig_dir / "droid.xml").write_text(
        '<FFSignatureFile DateCreated="2024-05-01T00:00:00" Version="109">'
        '</FFSignatureFile>', encoding="utf-8")

    args = argparse.Namespace(action="status", dir=str(sig_dir))
    rc = signatures.run(args)
    assert rc == 0

    out = capsys.readouterr().out
    lines = {line.split("\t")[0]: line for line in out.splitlines() if line.strip()}
    assert "plain.txt" in lines
    assert "no date recorded" in lines["plain.txt"]
    assert "droid.xml" in lines
    assert "2024-05-01" in lines["droid.xml"]
    # Vendored data files are always listed too.
    assert "freedesktop.org.xml" in lines
    assert "comp_id.txt" in lines


def test_describe_reports_size(fixture_dir):
    p = fixture_dir / "one.txt"
    p.write_bytes(b"0123456789")
    entry = signatures.describe(p)
    assert entry["name"] == "one.txt"
    assert entry["size"] == 10
    assert entry["date"] is None


def test_default_signatures_dir_env_override(fixture_dir, monkeypatch):
    monkeypatch.setenv("FILECAT_SIGNATURES", str(fixture_dir))
    assert signatures.default_signatures_dir() == fixture_dir
