"""`filecat summary` CLI test: three files, two suffixes, known sizes ->
`--by extension` totals equal the sum of those sizes. Drives
filecat.cli.main([...]) and captures stdout, per
file-catalog-requirements.md's Tests table.
"""
from __future__ import annotations

from filecat import cli
from filecat.backends.sqlite import SqliteBackend
from filecat.record import root_id

FILES = (
    # (name, suffix, kind, size)
    ("a.txt", "txt", "text", 100),
    ("b.txt", "txt", "text", 250),
    ("c.bin", "bin", "data", 777),
)


def _seed_catalog(db_path, root: str) -> int:
    backend = SqliteBackend(str(db_path))
    for name, suffix, kind, size in FILES:
        backend.put({
            "root_id": root_id(root), "root": root, "rel_path": name, "name": name,
            "size": size, "kind": kind, "suffix": suffix,
        })
    backend.close()
    return sum(size for _, _, _, size in FILES)


def test_summary_by_extension_totals_match_sum_of_sizes(fixture_dir, capsys):
    root = str(fixture_dir)
    db_path = fixture_dir / "catalog.sqlite"
    total_bytes = _seed_catalog(db_path, root)

    rc = cli.main([
        "summary", "--backend", "sqlite", "--out", str(db_path),
        "--by", "extension", "--root", root,
    ])
    assert rc == 0

    out = capsys.readouterr().out
    assert f"total bytes: " in out
    assert f"({total_bytes})" in out
    assert "txt" in out
    assert "bin" in out

    # Hand count: two suffixes, 350 bytes in .txt and 777 in .bin.
    txt_bytes = FILES[0][3] + FILES[1][3]
    bin_bytes = FILES[2][3]
    assert f"({txt_bytes})" in out
    assert f"({bin_bytes})" in out


def test_summary_disagree_lists_mismatched_files(fixture_dir, capsys):
    root = str(fixture_dir)
    db_path = fixture_dir / "catalog.sqlite"
    backend = SqliteBackend(str(db_path))
    backend.put({
        "root_id": root_id(root), "root": root, "rel_path": "note.pdf", "name": "note.pdf",
        "size": 10, "kind": "image", "suffix": "pdf",
        "probe": {"mime_glob": "application/pdf", "mime_magic": "image/png",
                  "identify_basis": "disagree"},
    })
    backend.close()

    rc = cli.main(["summary", "--backend", "sqlite", "--out", str(db_path),
                   "--disagree", "--root", root])
    assert rc == 0
    out = capsys.readouterr().out
    assert "note.pdf" in out
    assert "glob=application/pdf" in out
    assert "magic=image/png" in out
