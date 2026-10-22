"""End-to-end checks from the "Done when" list in file-catalog-requirements.md,
driven through the CLI with the real probe, identifier and backends."""
from __future__ import annotations

import gzip
import json
import sqlite3
import time
import zipfile
from pathlib import Path

from filecat import cli


def _build_tree(root: Path) -> dict[str, int]:
    files = {
        "docs/a.txt": b"hello\r\nworld\r\n",
        "docs/b.csv": b"x,y\n1,2\n3,4\n",
        "docs/note.pdf": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x08\x08\x02\x00\x00\x00" + b"\0" * 40,
        "deep/er/data.gz": gzip.compress(b"plain text inside gzip\n"),
        "settings.zzq": b"CFGv2\0name=alpha\0size=12\0mode=fast\0" * 4,
    }
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    with zipfile.ZipFile(root / "two.zip", "w") as z:
        z.writestr("one.txt", "1")
        z.writestr("two.txt", "2")
    # NTFS updates directory mtimes lazily after a child is written; let it
    # settle so two scans of the same tree see the same directory times.
    time.sleep(0.5)
    return {str(p.relative_to(root)).replace("\\", "/"): p.stat().st_size
            for p in root.rglob("*") if p.is_file()}


def test_jsonl_and_sqlite_documents_compare_equal(fixture_dir: Path):
    tree = fixture_dir / "tree"
    _build_tree(tree)
    jsonl, db = fixture_dir / "c.jsonl", fixture_dir / "c.sqlite"
    assert cli.main(["scan", str(tree), "--backend", "jsonl", "--out", str(jsonl)]) == 0
    assert cli.main(["scan", str(tree), "--backend", "sqlite", "--out", str(db)]) == 0
    from_jsonl = {d["rel_path"]: d for d in map(json.loads, jsonl.read_text(encoding="utf-8").splitlines())}
    with sqlite3.connect(db) as conn:
        from_sqlite = {r: json.loads(d) for r, d in conn.execute("SELECT rel_path, document FROM files")}
        stored = {i: json.loads(d) for i, d in conn.execute("SELECT sample_id, document FROM samples")}
    # sqlite files text samples and archive members under the content hash;
    # put the samples back to compare
    assert from_sqlite["two.zip"].pop("members_id") == from_sqlite["two.zip"]["sha256"]
    for doc in from_sqlite.values():
        sid = doc.pop("sample_id", None)
        if sid is not None:
            doc.update({k: v for k, v in stored[sid].items() if k in ("sample", "sample_truncated")})
    assert any(d.get("sample") for d in from_jsonl.values()) and stored
    assert from_jsonl == from_sqlite
    assert from_sqlite["docs/note.pdf"]["kind"] == "image"
    assert from_sqlite["docs/note.pdf"]["probe"]["identify_basis"] == "disagree"


def test_ollama_refused_port_keeps_measurements(fixture_dir: Path):
    tree = fixture_dir / "tree"
    _build_tree(tree)
    db = fixture_dir / "c.sqlite"
    rc = cli.main(["scan", str(tree), "--out", str(db), "--ollama", "--model", "any",
                   "--ollama-url", "http://127.0.0.1:9"])
    assert rc == 0
    with sqlite3.connect(db) as conn:
        doc = json.loads(conn.execute(
            "SELECT document FROM files WHERE rel_path = 'settings.zzq'").fetchone()[0])
        sample = json.loads(conn.execute(
            "SELECT document FROM samples WHERE sample_id = ?", (doc["sample_id"],)).fetchone()[0])
    assert doc["kind"] == "unknown" and doc["sample_id"] == doc["sha256"]
    assert sample["sample"] and sample["llm"]["error"]    # the result is kept with the sample


def test_summary_by_extension_matches_hand_count(fixture_dir: Path, capsys):
    tree = fixture_dir / "tree"
    sizes = _build_tree(tree)
    db = fixture_dir / "c.sqlite"
    cli.main(["scan", str(tree), "--out", str(db)])
    capsys.readouterr()
    assert cli.main(["summary", "--out", str(db), "--by", "extension", "--top", "0"]) == 0
    out = capsys.readouterr().out
    assert f"total files: {len(sizes)}" in out
    assert f"({sum(sizes.values())})" in out
    by_suffix: dict[str, int] = {}
    for rel, size in sizes.items():
        by_suffix[rel.rsplit(".", 1)[-1]] = by_suffix.get(rel.rsplit(".", 1)[-1], 0) + size
    for suffix, total in by_suffix.items():
        line = next(l for l in out.splitlines() if l.strip().startswith(suffix + " "))
        assert f"({total})" in line
