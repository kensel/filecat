"""`filecat show` CLI test: prints the stored record as indented JSON,
normalizes backslashes in rel_path, and exits 1 when the record is absent.
"""
from __future__ import annotations

from filecat import cli
from filecat.backends.sqlite import SqliteBackend
from filecat.record import root_id


def test_show_prints_record_and_normalizes_backslashes(fixture_dir, capsys):
    root = str(fixture_dir)
    db_path = fixture_dir / "catalog.sqlite"
    backend = SqliteBackend(str(db_path))
    backend.put({
        "root_id": root_id(root), "root": root, "rel_path": "sub/dir/note.txt",
        "name": "note.txt", "size": 42, "kind": "text", "suffix": "txt",
    })
    backend.close()

    rc = cli.main(["show", r"sub\dir\note.txt", "--root", root,
                   "--backend", "sqlite", "--out", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"rel_path": "sub/dir/note.txt"' in out
    assert '"size": 42' in out


def test_show_missing_record_exits_1(fixture_dir, capsys):
    root = str(fixture_dir)
    db_path = fixture_dir / "catalog.sqlite"
    backend = SqliteBackend(str(db_path))
    backend.close()

    rc = cli.main(["show", "nope.txt", "--root", root,
                   "--backend", "sqlite", "--out", str(db_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no record" in err
