"""Tests for `filecat members`."""
from __future__ import annotations

from argparse import Namespace

import pytest

from filecat.backends.sqlite import SqliteBackend
from filecat.members_cmd import run
from filecat.record import root_id

ROOT = r"C:\members-cmd-test"


def _args(fixture_dir, rel_path="packs/data.zip", role=None, as_json=False):
    return Namespace(
        rel_path=rel_path, root=ROOT, backend="sqlite",
        out=str(fixture_dir / "catalog.sqlite"), dsn=None,
        role=role, json=as_json,
    )


def _seed(fixture_dir, with_members=True, members_count_only=False):
    backend = SqliteBackend(str(fixture_dir / "catalog.sqlite"))
    probe = {}
    if members_count_only:
        probe["members_count"] = 3
    backend.put({
        "root_id": root_id(ROOT), "root": ROOT, "rel_path": "packs/data.zip",
        "name": "data.zip", "size": 4096, "kind": "archive", "suffix": "zip",
        "probe": probe,
    })
    backend.flush()
    if with_members:
        backend.put_members(ROOT, "packs/data.zip", [
            {"index": 0, "path": "script.lua", "size": 120, "csize": 80, "role": "script"},
            {"index": 1, "path": "tex.dds", "size": 4096, "csize": 2048, "role": "texture"},
            {"index": 2, "path": "tex2.dds", "size": 8192, "csize": 4096, "role": "texture"},
        ])
    backend.close()


def test_no_record(fixture_dir, capsys):
    rc = run(_args(fixture_dir, rel_path="missing.zip"))
    assert rc == 1
    captured = capsys.readouterr()
    assert "no record" in captured.err


def test_no_members_plain_message(fixture_dir, capsys):
    _seed(fixture_dir, with_members=False, members_count_only=False)
    rc = run(_args(fixture_dir))
    assert rc == 1
    captured = capsys.readouterr()
    assert "no recorded members" in captured.err


def test_no_members_mentions_probe_count(fixture_dir, capsys):
    _seed(fixture_dir, with_members=False, members_count_only=True)
    rc = run(_args(fixture_dir))
    assert rc == 1
    captured = capsys.readouterr()
    assert "members_count=3" in captured.err


def test_table_output(fixture_dir, capsys):
    _seed(fixture_dir)
    rc = run(_args(fixture_dir))
    assert rc == 0
    out = capsys.readouterr().out
    assert "script.lua" in out
    assert "tex.dds" in out
    assert "3 member(s)" in out
    assert "texture: 2" in out
    assert "script: 1" in out


def test_role_filter(fixture_dir, capsys):
    _seed(fixture_dir)
    rc = run(_args(fixture_dir, role=["texture"]))
    assert rc == 0
    out = capsys.readouterr().out
    assert "script.lua" not in out
    assert "tex.dds" in out
    assert "2 member(s)" in out


def test_json_output(fixture_dir, capsys):
    import json
    _seed(fixture_dir)
    rc = run(_args(fixture_dir, as_json=True))
    assert rc == 0
    captured = capsys.readouterr()
    lines = [l for l in captured.out.splitlines() if l.strip()]
    assert len(lines) == 3
    rows = [json.loads(l) for l in lines]
    assert [r["path"] for r in rows] == ["script.lua", "tex.dds", "tex2.dds"]
    # footer goes to stderr in JSON mode so stdout stays pure JSONL
    assert "3 member(s)" in captured.err
