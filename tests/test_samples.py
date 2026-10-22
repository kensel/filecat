"""Content-keyed text samples: split/attach, the crash-safe migration of
existing records, Ollama once per unique content, and backend-to-backend
migrate."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from filecat import cli, enrich, ollama, samples
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.migrate import migrate as copy_catalog
from filecat.options import ScanOptions
from filecat.record import root_id

ROOT = r"C:\samples-root"


def _doc(rel_path: str, text: str | None, digest: str | None, *, partial: bool = False,
         llm: dict | None = None, kind: str = "unknown") -> dict:
    doc = {"root_id": root_id(ROOT), "root": ROOT, "rel_path": rel_path, "name": rel_path.rsplit("/", 1)[-1],
           "size": 100, "kind": kind, "encoding": {"detected": "utf-8"}}
    if digest:
        doc["sha256_partial" if partial else "sha256"] = digest
    if text is not None:
        doc["sample"] = text
        doc["sample_truncated"] = False
    if llm is not None:
        doc["llm"] = llm
    return doc


H1, H2, H3 = "1" * 64, "2" * 64, "3" * 64
LLM = {"model": "m", "prompt_version": ollama.PROMPT_VERSION, "summary": "s", "labels": [], "unsure": False}


def _legacy_catalog(backend) -> list[dict]:
    """Records as v0.1.1 left them: samples inline."""
    docs = [_doc("a/one.txt", "alpha", H1, llm=LLM),
            _doc("b/one-copy.txt", "alpha", H1),            # same content as a/one.txt
            _doc("c/big.log", "beta", H2, partial=True),
            _doc("d/nohash.txt", "gamma", None),            # stays inline
            _doc("e/empty.bin", None, H3)]                  # nothing to move
    for d in docs:
        backend.put(copy.deepcopy(d))
    backend.flush()
    return docs


def test_split_and_attach():
    doc = _doc("x.txt", "hello", H1, llm=LLM)
    sample = samples.split(doc)
    assert sample == {"sample_id": H1, "hash_type": "sha256", "size": 100, "encoding": {"detected": "utf-8"},
                      "sample": "hello", "sample_truncated": False, "llm": LLM}
    assert doc["sample_id"] == H1 and "sample" not in doc and "llm" not in doc
    assert samples.split(_doc("y.txt", "hi", None)) is None
    assert samples.split(_doc("z.bin", None, H2)) is None
    partial = samples.split(_doc("big.iso", "x", H2, partial=True))
    assert partial["hash_type"] == "sha256_partial"

    be = MemoryBackend()
    be.add_samples([sample])
    back = samples.attach_one(be, doc)
    assert back["sample"] == "hello" and back["llm"] == LLM and back["sample_id"] == H1
    assert "sample" not in doc                               # attach works on a copy


def test_migrate_moves_inline_samples_and_dedups(fixture_dir: Path):
    be = SqliteBackend(str(fixture_dir / "c.sqlite"))
    _legacy_catalog(be)
    cp = str(fixture_dir / "c.sqlite.samples-migrate.json")
    stats = samples.migrate(be, cp, batch=2)
    assert stats.done and (stats.scanned, stats.moved, stats.no_hash) == (5, 3, 1)
    assert not Path(cp).exists()                            # removed once finished
    stored = be.get_samples([H1, H2])
    assert stored[H1]["sample"] == "alpha" and stored[H1]["llm"] == LLM
    assert stored[H2]["hash_type"] == "sha256_partial"
    assert len(list(be.iter_samples())) == 2
    one = be.get(ROOT, "a/one.txt")
    assert one["sample_id"] == H1 and "sample" not in one and "llm" not in one
    assert be.get(ROOT, "d/nohash.txt")["sample"] == "gamma"
    # a second run finds nothing left to move
    again = samples.migrate(be, cp, batch=2)
    assert again.moved == 0 and again.done
    be.close()


class _Crash(Exception):
    pass


class _CrashingSqlite(SqliteBackend):
    """Fails at a chosen step of the second migration batch."""
    crash_at: str | None = None
    batches = 0

    def add_samples(self, samples_):
        if self.crash_at == "samples" and self.batches == 2:
            raise _Crash
        super().add_samples(samples_)

    def put(self, document):
        if self.crash_at == "records" and self.batches == 2 and document["rel_path"] == "c/big.log":
            super().flush()                                 # the batch's first record is already written
            raise _Crash
        super().put(document)

    def page_records(self, after, limit):
        out = super().page_records(after, limit)
        self.batches += 1
        return out


@pytest.mark.parametrize("crash_at", ["samples", "records"])
def test_migrate_survives_a_crash_and_resumes(fixture_dir: Path, crash_at: str):
    path = str(fixture_dir / f"crash-{crash_at}.sqlite")
    cp = path + ".samples-migrate.json"
    be = _CrashingSqlite(path)
    _legacy_catalog(be)
    be.crash_at = crash_at                               # the first batch succeeds
    with pytest.raises(_Crash):
        samples.migrate(be, cp, batch=2)
    be.conn.rollback()
    be._buffer.clear()
    be.close()

    # Whatever was written, no record names a sample that is not stored.
    check = SqliteBackend(path)
    for doc in check.list():
        if doc.get("sample_id"):
            assert check.get_samples([doc["sample_id"]]), doc["rel_path"]
    check.close()

    state = json.loads(Path(cp).read_text())
    assert state["after"] is not None and state["batches"] == 1

    rerun = SqliteBackend(path)
    stats = samples.migrate(rerun, cp, batch=2)
    assert stats.resumed_from is not None and stats.done
    assert [d["rel_path"] for d in rerun.list() if d.get("sample")] == ["d/nohash.txt"]
    readable = {d["rel_path"]: d.get("sample") for d in samples.attach(rerun, rerun.list())}
    assert readable == {"a/one.txt": "alpha", "b/one-copy.txt": "alpha", "c/big.log": "beta",
                        "d/nohash.txt": "gamma", "e/empty.bin": None}
    rerun.close()


def test_migrate_limit_then_continue(fixture_dir: Path):
    be = SqliteBackend(str(fixture_dir / "c.sqlite"))
    _legacy_catalog(be)
    cp = str(fixture_dir / "cp.json")
    first = samples.migrate(be, cp, batch=2, limit=2)
    assert not first.done and first.scanned == 2 and Path(cp).exists()
    rest = samples.migrate(be, cp, batch=2)
    assert rest.done and rest.scanned == 5 and rest.moved == 3
    be.close()


def test_checkpoint_of_another_catalog_is_ignored(fixture_dir: Path):
    be = MemoryBackend()
    _legacy_catalog(be)
    cp = fixture_dir / "cp.json"
    cp.write_text(json.dumps({"version": 1, "catalog": "other", "after": ["zzz"], "scanned": 99}))
    stats = samples.migrate(be, str(cp), tag="mine")
    assert stats.resumed_from is None and stats.moved == 3


def test_ollama_runs_once_per_unique_content(monkeypatch):
    be = MemoryBackend()
    for rel in ("a.zzq", "copy/a.zzq", "copy2/a.zzq"):
        be.store(_doc(rel, "same text", H1))
    be.store(_doc("b.zzq", "other text", H2))
    be.store(_doc("inline.zzq", "no hash", None))
    calls: list[str] = []

    def fake(url, model, doc, timeout=60.0):
        calls.append(doc["sample"])
        return {"model": model, "prompt_version": ollama.PROMPT_VERSION, "summary": "x", "labels": [],
                "unsure": False}

    monkeypatch.setattr(ollama, "call_ollama", fake)
    opts = ScanOptions(ollama=True, model="m")
    ollama.annotate_backend(be, opts)
    assert sorted(calls) == ["no hash", "other text", "same text"]
    assert be.get_samples([H1])[H1]["llm"]["summary"] == "x"
    assert "llm" not in be.get(ROOT, "copy/a.zzq")             # shared through the sample
    assert be.get(ROOT, "inline.zzq")["llm"]["summary"] == "x"
    calls.clear()
    ollama.annotate_backend(be, opts)                          # nothing new to ask
    assert calls == []
    ollama.annotate_backend(be, ScanOptions(ollama=True, model="another"))
    assert len(calls) == 3                                     # a different model asks again


def test_copy_catalog_between_sample_and_inline_backends(fixture_dir: Path):
    src = SqliteBackend(str(fixture_dir / "src.sqlite"))
    for d in _legacy_catalog(MemoryBackend()):
        src.store(copy.deepcopy(d))
    src.flush()
    out = JsonlBackend(str(fixture_dir / "out.jsonl"))
    stats = copy_catalog(src, out, verify=True)
    assert stats.ok, stats.verify_mismatches
    one = out.get(ROOT, "a/one.txt")
    assert one["sample"] == "alpha" and one["llm"] == LLM and "sample_id" not in one

    back = SqliteBackend(str(fixture_dir / "back.sqlite"))
    stats = copy_catalog(out, back, verify=True)
    assert stats.ok, stats.verify_mismatches
    assert back.get(ROOT, "b/one-copy.txt")["sample_id"] == H1
    assert back.get_samples([H1])[H1]["sample"] == "alpha"

    both = MemoryBackend()
    stats = copy_catalog(back, both, verify=True)
    assert stats.ok and stats.samples == 2
    for b in (src, out, back):
        b.close()


def test_enrich_leaves_listed_backup_data_alone():
    doc = {**_doc("Pool/0/1.bucket", None, None), "size": 4096, "kind": "unknown",
           "probe": {"backup_data": "synology_hyperbackup"}}
    del doc["kind"]
    opts = ScanOptions()
    assert enrich.needs(doc, {"hash", "probe"}, opts, force=True) == (False, False)
    opts.measure_backups = True
    assert enrich.needs(doc, {"hash", "probe"}, opts, force=False)[1] is True


def test_samples_command(fixture_dir: Path, capsys):
    db = fixture_dir / "c.sqlite"
    be = SqliteBackend(str(db))
    _legacy_catalog(be)
    be.close()
    assert cli.main(["samples", "migrate", "--backend", "sqlite", "--out", str(db), "--batch", "2"]) == 0
    assert "3 samples moved off records into 2 sample documents, 1 kept inline" in capsys.readouterr().out
    assert cli.main(["samples", "stats", "--backend", "sqlite", "--out", str(db)]) == 0
    assert capsys.readouterr().out.startswith("2 samples, 1 with an Ollama result")
    assert cli.main(["show", "a/one.txt", "--root", ROOT, "--backend", "sqlite", "--out", str(db)]) == 0
    assert json.loads(capsys.readouterr().out)["sample"] == "alpha"
    jsonl = fixture_dir / "c.jsonl"
    JsonlBackend(str(jsonl)).close()
    assert cli.main(["samples", "migrate", "--backend", "jsonl", "--out", str(jsonl)]) == 2
