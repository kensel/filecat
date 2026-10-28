"""Archive members filed by content hash: scans, the crash-safe migration of
existing path-keyed rows (and the trimming of compound documents listed
before v0.1.1), pruning, enrich, and backend-to-backend migrate."""
from __future__ import annotations

import copy
import json
import zipfile
from pathlib import Path

import pytest

from filecat import cli, enrich, member_sets, rootinfo
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.migrate import migrate as copy_catalog
from filecat.probe import members as member_probe
from filecat.record import MEMBERS_KEY, root_id

ROOT = r"C:\members-root"
H1, H2, H3, H4 = "1" * 64, "2" * 64, "3" * 64, "4" * 64

PACK = [{"path": "x.txt", "size": 1, "role": "text"}, {"path": "y.txt", "size": 2, "role": "text"},
        {"path": "tool.exe", "size": 3, "role": "exe"}]
DOCX = [{"path": "[Content_Types].xml", "role": "config"}, {"path": "_rels/.rels", "role": "unknown"},
        {"path": "word/", "role": "dir"}, {"path": "word/document.xml", "role": "config"},
        {"path": "word/vbaProject.bin", "role": "unknown"}]


def _doc(rel_path: str, rows: list[dict] | None, digest: str | None = None, *, partial: bool = False,
         container: str = "zip") -> dict:
    doc = {"root_id": root_id(ROOT), "root": ROOT, "rel_path": rel_path, "name": rel_path.rsplit("/", 1)[-1],
           "size": 100, "kind": "archive", "container": container, "probe": {}}
    if digest:
        doc["sha256_partial" if partial else "sha256"] = digest
    if rows is not None:
        doc["probe"].update(member_probe.summarize(rows, truncated=False, list_cap=100))
    return doc


def _legacy_catalog(backend) -> None:
    """Records as v0.1.2 left them: every archive's rows under its path."""
    entries = [(_doc("a/pack.zip", PACK, H1), PACK),
               (_doc("b/pack-copy.zip", PACK, H1), PACK),            # same content as a/pack.zip
               (_doc("c/big.iso", PACK[:2], H2, partial=True, container="iso"), PACK[:2]),
               (_doc("d/nohash.zip", PACK[:2]), PACK[:2]),           # stays under its path
               (_doc("e/report.docx", DOCX, H3), DOCX),              # listed before v0.1.1
               (_doc("f/nohash.docx", DOCX), DOCX),
               (_doc("g/plain.txt", None, H4, container="plain"), None),
               (_doc("h/rows-not-kept.zip", PACK, H4), None)]        # summary but no rows stored
    for doc, rows in entries:
        backend.put(copy.deepcopy(doc))
        if rows is not None:
            backend.put_members(ROOT, doc["rel_path"], [{**r, "index": i} for i, r in enumerate(rows)])
    backend.flush()


def _paths(backend, rel_path: str) -> list[str]:
    return [r["path"] for r in backend.members_of(ROOT, rel_path)]


def _check_migrated(be) -> None:
    for rel in ("a/pack.zip", "b/pack-copy.zip"):
        assert be.get(ROOT, rel)["members_id"] == H1
        assert _paths(be, rel) == ["x.txt", "y.txt", "tool.exe"]
        assert list(be.list_members(ROOT, rel)) == []
    assert be.get(ROOT, "c/big.iso")["members_id"] == H2
    assert "members_id" not in be.get(ROOT, "d/nohash.zip")
    assert _paths(be, "d/nohash.zip") == ["x.txt", "y.txt"]
    docx = be.get(ROOT, "e/report.docx")
    assert docx["kind"] == "document" and docx["members_id"] == H3
    assert docx["probe"]["compound"]["entries"] == 5 and docx["probe"]["compound"]["reasons"] == {"macros": 1}
    assert docx["probe"]["members_count"] == 1
    assert [(r["path"], r["anomaly"]) for r in be.members_of(ROOT, "e/report.docx")] == \
        [("word/vbaProject.bin", "macros")]
    assert _paths(be, "f/nohash.docx") == ["word/vbaProject.bin"]
    assert be.get(ROOT, "f/nohash.docx")["probe"]["compound"]["format"] == "ooxml"
    headers = {h["members_id"]: h for h in be.iter_member_sets()}
    assert set(headers) == {H1, H2, H3} and headers[H2]["hash_type"] == "sha256_partial"


def test_store_files_one_set_per_content(fixture_dir: Path):
    tree = fixture_dir / "tree"
    for sub in ("one", "two"):
        (tree / sub).mkdir(parents=True)
        with zipfile.ZipFile(tree / sub / "pack.zip", "w") as zf:
            zf.writestr("a.txt", "alpha")
            zf.writestr("b/c.txt", "gamma")
    db = fixture_dir / "c.sqlite"
    assert cli.main(["scan", str(tree), "--backend", "sqlite", "--out", str(db)]) == 0
    be = SqliteBackend(str(db))
    one, two = be.get(str(tree), "one/pack.zip"), be.get(str(tree), "two/pack.zip")
    assert one["members_id"] == two["members_id"] == one["sha256"]
    assert [h["count"] for h in be.iter_member_sets()] == [2]
    assert [r["path"] for r in be.members_of(str(tree), "two/pack.zip")] == ["a.txt", "b/c.txt"]
    assert be.conn.execute("SELECT COUNT(*) FROM members").fetchone()[0] == 0
    be.close()
    assert cli.main(["members", "one/pack.zip", "--root", str(tree), "--backend", "sqlite",
                     "--out", str(db)]) == 0


def test_put_member_set_replaces_only_a_different_listing():
    be = MemoryBackend()
    doc = _doc("a.zip", PACK, H1)
    assert member_sets.store_rows(be, doc, PACK) and doc["members_id"] == H1
    assert be.put_member_set(member_sets.header_for((H1, "sha256"), member_sets.clean_rows(PACK)),
                             member_sets.clean_rows(PACK)) is False
    assert member_sets.store_rows(be, _doc("b.zip", PACK[:1], H1), PACK[:1])
    assert [r["path"] for r in be.list_member_set(H1)] == ["x.txt"]
    assert not member_sets.store_rows(be, _doc("c.zip", PACK), PACK)       # no hash
    assert not member_sets.store_rows(be, _doc("d.zip", [], H2), [])        # nothing to file


def test_migrate_moves_rows_into_sets_and_trims_compound_documents(fixture_dir: Path):
    be = SqliteBackend(str(fixture_dir / "c.sqlite"))
    _legacy_catalog(be)
    cp = str(fixture_dir / "c.sqlite.members-migrate.json")
    stats = member_sets.migrate(be, cp, batch=3)
    assert stats.done and not Path(cp).exists()
    assert (stats.scanned, stats.archives, stats.moved, stats.sets, stats.compound, stats.no_hash) == \
        (8, 6, 4, 3, 2, 1)
    assert stats.rows_read == 3 + 3 + 2 + 2 + 5 + 5
    assert stats.rows_written == 3 + 2 + 2 + 1 + 1          # one set for both packs
    _check_migrated(be)
    again = member_sets.migrate(be, cp, batch=3)
    assert again.done and again.moved == 0 and again.archives == again.no_hash == 2   # the hashless two
    be.close()


def test_migrate_can_keep_every_compound_entry():
    be = MemoryBackend()
    _legacy_catalog(be)
    stats = member_sets.migrate(be, "unused.json", expand_compound=True)
    assert stats.compound == 0
    assert len(_paths(be, "e/report.docx")) == 5 and "compound" not in be.get(ROOT, "e/report.docx")["probe"]


class _Crash(Exception):
    pass


class _CrashingSqlite(SqliteBackend):
    """Fails at a chosen step of the second migration batch."""
    crash_at: str | None = None
    batches = 0

    def put_member_set(self, header, rows):
        if self.crash_at == "sets" and self.batches == 2 and header["members_id"] == H3:
            raise _Crash
        return super().put_member_set(header, rows)

    def put(self, document):
        if self.crash_at == "records" and self.batches == 2 and document["rel_path"] == "e/report.docx":
            super().flush()                               # the batch's first record is already written
            raise _Crash
        super().put(document)

    def delete_members(self, root, rel_path):
        if self.crash_at == "rows" and self.batches == 2 and rel_path == "e/report.docx":
            raise _Crash
        super().delete_members(root, rel_path)

    def page_records(self, after, limit):
        out = super().page_records(after, limit)
        self.batches += 1
        return out


@pytest.mark.parametrize("crash_at", ["sets", "records", "rows"])
def test_migrate_survives_a_crash_and_resumes(fixture_dir: Path, crash_at: str):
    path = str(fixture_dir / f"crash-{crash_at}.sqlite")
    cp = path + ".members-migrate.json"
    be = _CrashingSqlite(path)
    _legacy_catalog(be)
    be.crash_at = crash_at                                  # the first batch succeeds
    with pytest.raises(_Crash):
        member_sets.migrate(be, cp, batch=3)
    be.conn.rollback()
    be._buffer.clear()
    be.close()

    # Whatever was written, every archive still shows its members.
    check = SqliteBackend(path)
    for doc in check.list():
        if doc.get("members_id"):
            assert list(check.list_member_set(doc["members_id"])), doc["rel_path"]
        elif doc["rel_path"] not in ("g/plain.txt", "h/rows-not-kept.zip"):
            assert list(check.list_members(ROOT, doc["rel_path"])), doc["rel_path"]
    check.close()
    assert json.loads(Path(cp).read_text())["batches"] == 1

    rerun = SqliteBackend(path)
    stats = member_sets.migrate(rerun, cp, batch=3)
    assert stats.resumed_from is not None and stats.done
    _check_migrated(rerun)
    rerun.close()


def test_prune_removes_what_no_record_names(capsys):
    be = MemoryBackend()
    _legacy_catalog(be)
    member_sets.migrate(be, "unused.json")
    be.add_samples([{"sample_id": H4, "hash_type": "sha256", "sample": "gone"}])
    be.delete(ROOT, "a/pack.zip")
    be.delete(ROOT, "e/report.docx")
    assert be.prune_member_sets() == 1                      # H3; b/pack-copy.zip still names H1
    assert {h["members_id"] for h in be.iter_member_sets()} == {H1, H2}
    assert be.prune_samples() == 1

    be.put_root_info({"root_id": root_id(ROOT), "root": ROOT,
                      "last_attempt": {"status": "running", "started_at": rootinfo.now(),
                                       "heartbeat_at": rootinfo.now()}})
    assert member_sets.prune(be, "member sets", be.prune_member_sets, force=False) == 1
    assert "a scan is running" in capsys.readouterr().err
    assert member_sets.prune(be, "member sets", be.prune_member_sets, force=True) == 0


def test_member_sets_command(fixture_dir: Path, capsys):
    db = fixture_dir / "c.sqlite"
    be = SqliteBackend(str(db))
    _legacy_catalog(be)
    be.close()
    args = ["--backend", "sqlite", "--out", str(db)]
    assert cli.main(["member-sets", "migrate", *args, "--limit", "4"]) == 0
    assert "stopped at --limit" in capsys.readouterr().out
    assert cli.main(["member-sets", "migrate", *args]) == 0
    out = capsys.readouterr().out
    assert "2 compound documents trimmed" in out and "resumed from a checkpoint" in out
    assert cli.main(["member-sets", "stats", *args]) == 0
    assert capsys.readouterr().out.startswith("3 member sets, 6 rows")
    assert cli.main(["members", "e/report.docx", "--root", ROOT, *args]) == 0
    assert "word/vbaProject.bin" in capsys.readouterr().out
    assert cli.main(["member-sets", "prune", *args]) == 0
    assert capsys.readouterr().out.startswith("0 member sets")
    assert cli.main(["samples", "prune", *args]) == 0
    jsonl = fixture_dir / "c.jsonl"
    JsonlBackend(str(jsonl)).close()
    assert cli.main(["member-sets", "migrate", "--backend", "jsonl", "--out", str(jsonl)]) == 2


def test_enrich_keeps_the_set_named():
    old = {**_doc("a.zip", PACK, H1), "members_id": H1}
    assert enrich.merge_measured(old, _doc("a.zip", PACK, H1))["members_id"] == H1
    assert "members_id" not in enrich.merge_measured(old, _doc("a.zip", PACK, H2))       # content changed
    assert "members_id" not in enrich.merge_measured(old, {**_doc("a.zip", PACK, H1), MEMBERS_KEY: []})


def test_copy_catalog_between_set_and_path_backends(fixture_dir: Path):
    src = SqliteBackend(str(fixture_dir / "src.sqlite"))
    _legacy_catalog(src)
    member_sets.migrate(src, str(fixture_dir / "cp.json"))
    out = JsonlBackend(str(fixture_dir / "out.jsonl"))
    stats = copy_catalog(src, out, verify=True)
    assert stats.ok, stats.verify_mismatches
    assert "members_id" not in out.get(ROOT, "a/pack.zip")
    assert _paths(out, "b/pack-copy.zip") == ["x.txt", "y.txt", "tool.exe"]
    assert _paths(out, "e/report.docx") == ["word/vbaProject.bin"]

    back = SqliteBackend(str(fixture_dir / "back.sqlite"))
    stats = copy_catalog(out, back, verify=True)
    assert stats.ok, stats.verify_mismatches
    _check_migrated(back)

    both = MemoryBackend()
    stats = copy_catalog(back, both, verify=True)
    assert stats.ok and stats.member_sets == 3
    _check_migrated(both)
    for b in (src, out, back):
        b.close()


def test_copy_catalog_writes_sets_before_the_records_that_name_them(fixture_dir: Path):
    src = SqliteBackend(str(fixture_dir / "src.sqlite"))
    _legacy_catalog(src)
    member_sets.migrate(src, str(fixture_dir / "cp.json"))
    order: list[str] = []

    class Watching(MemoryBackend):
        def put_member_set(self, header, rows):
            order.append("set")
            return super().put_member_set(header, rows)

        def put_many(self, docs):
            order.append("records")
            return super().put_many(docs)

    dst = Watching()
    stats = copy_catalog(src, dst, verify=True)
    assert stats.ok and stats.member_sets == 3
    assert order[:4] == ["set", "set", "set", "records"] and order.count("set") == 3
    _check_migrated(dst)

    # --root copies only the sets that root's records name
    other = r"C:\other-root"
    src.put({"root_id": root_id(other), "root": other, "rel_path": "z.txt", "name": "z.txt",
             "size": 1, "kind": "text"})
    src.flush()
    only = MemoryBackend()
    stats = copy_catalog(src, only, roots=[other])
    assert stats.member_sets == 0 and list(only.iter_member_sets()) == []
    src.close()


def test_trim_compound_covers_gzip_wrapped_saves():
    save = _doc("x3/quick.sav", PACK, H1, container="gzip_xored")
    kept, trimmed = member_sets.trim_compound(save, PACK)
    assert trimmed and kept == []
    assert save["probe"]["compound"] == {"format": "x3_save", "mime": "application/x-x3-savegame"}
    assert "members_count" not in save["probe"]
    tarball = _doc("x/data.tar.gz", PACK, H1, container="gzip")
    assert member_sets.trim_compound(tarball, PACK) == (PACK, False)
