"""`filecat rollups migrate` (docs/rollups.md 4.4): listed-only store rows and
rule matches become rollups without a rescan; three phases, stopped and run
again at any point, refused while a scan runs.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from filecat import cli, rollup, rollup_migrate, rootinfo
from filecat.backends.memory import MemoryBackend
from filecat.options import ScanOptions
from tests.conftest import FIXTURE_ROOT
from tests.test_hyperbackup import make_hbk
from tests.test_rollup_walk import config, options, rollups_of, run_scan, write

HBK = "Backup/NAS-LEGACY_1.hbk"


@pytest.fixture
def old(fixture_dir):
    """A catalog made before rollups: a Hyper Backup store, a cache folder and a private one."""
    make_hbk(fixture_dir / "Backup")
    write(fixture_dir / "Backup" / "other.txt", b"o")
    write(fixture_dir / "proj" / "node_modules" / "pkg" / "a.js", b"12345")
    write(fixture_dir / "proj" / "node_modules" / "b.js", b"1234567")
    write(fixture_dir / "proj" / "src" / "m.py", b"print(1)\n")
    write(fixture_dir / "vault" / "ZXQ-secret.txt", b"private notes")
    backend, docs, _ = run_scan(str(fixture_dir), options(config()))
    assert f"{HBK}/Pool/0/1/5.bucket" in docs
    return fixture_dir, backend


def migrate(backend, root, cfg, **kw):
    opts = ScanOptions(rollup_config=cfg, identify="never")
    path = str(FIXTURE_ROOT / f"ck-{uuid.uuid4().hex}.json") if "checkpoint" not in kw else kw.pop("checkpoint")
    kw.setdefault("resume_path", str(FIXTURE_ROOT / "no-resume.json"))
    return rollup_migrate.migrate(backend, opts, path, roots=[str(root)], **kw), path


def docs_of(backend, root):
    return {d["rel_path"]: d for d in backend.list(root=str(root))}


def test_dry_run_reports_and_changes_nothing(old):
    root, backend = old
    before = docs_of(backend, root)
    said = []
    result, _ = migrate(backend, root, config({"backup": "automatic"}), dry_run=True, progress=said.append)
    assert docs_of(backend, root) == before
    assert result.targets == 1 and result.migrated == 1 and not result.done
    assert any("would fold 1 children" in m and "[BACKUP]" in m for m in said)
    assert result.bytes == 300 + 30 + 299 + 0


def test_a_store_migrates_to_a_rollup_and_the_store_record_stays(old):
    root, backend = old
    result, ck = migrate(backend, root, config({"backup": "automatic"}))
    docs = docs_of(backend, root)
    assert result.migrated == 1 and result.done and not os.path.exists(ck)
    roll = docs[f"{HBK}/[BACKUP]"]
    info = roll["probe"]["rollup"]
    assert roll["size"] == 629 and info["migrated"] is True and info["total_files"] == 4
    assert info["store"] == {"format": "synology-hyperbackup", "path": HBK} and info["matched"] == 1
    assert info["rule"] == "store:synology-hyperbackup" and "fp" not in info and "allocated_size" not in roll
    assert info["total_dirs"] == 3          # Pool, Pool/0, Pool/0/1
    assert not [r for r in docs if r.startswith(f"{HBK}/Pool")]
    assert f"{HBK}/Config/version_info.db" in docs                      # the small rows stay
    store = docs[HBK]
    assert store["probe"]["backup"]["task"] == "Synology NAS 1" and store["probe"]["rollup_tags"] == ["[BACKUP]"]
    assert store["probe"]["child_count"] == 9                            # Pool became the rollup: same count
    assert not list(backend.list_dropped(str(root)))
    totals = backend.rollup_totals(str(root))[str(root)]
    assert [(r["tag"], r["size"]) for r in totals] == [("[BACKUP]", 629)]


def test_migrate_twice_changes_nothing_more(old):
    root, backend = old
    migrate(backend, root, config({"backup": "automatic"}))
    once = docs_of(backend, root)
    result, _ = migrate(backend, root, config({"backup": "automatic"}))
    assert docs_of(backend, root) == once and result.migrated == 0 and result.targets == 0


def test_a_scan_after_a_migration_replaces_the_rollup_with_an_exact_sum(old):
    root, backend = old
    cfg = config({"backup": "automatic"})
    migrate(backend, root, cfg)
    backend, docs, _ = run_scan(str(root), options(cfg), backend)
    info = docs[f"{HBK}/[BACKUP]"]["probe"]["rollup"]
    assert "migrated" not in info and info["fp"] and docs[f"{HBK}/[BACKUP]"]["size"] == 629
    assert not [r for r in docs if r.startswith(f"{HBK}/Pool")]


def test_it_matches_what_a_scan_would_have_made(old, fixture_dir):
    root, backend = old
    cfg = config({"backup": "automatic"})
    migrate(backend, root, cfg)
    _, scanned, _ = run_scan(str(root), options(cfg))
    mine = docs_of(backend, root)[f"{HBK}/[BACKUP]"]
    theirs = scanned[f"{HBK}/[BACKUP]"]
    assert mine["size"] == theirs["size"]
    for key in ("total_files", "total_dirs", "matched", "rule", "store", "newest_mtime_ns", "oldest_mtime_ns"):
        assert mine["probe"]["rollup"][key] == theirs["probe"]["rollup"][key], key


class Boom(Exception):
    pass


def failing_delete(backend, after):
    """delete_many raises on its after+1st call (the process dying)."""
    real, calls = backend.delete_many, [0]

    def delete_many(root, rel_paths):
        if calls[0] >= after:
            raise Boom
        calls[0] += 1
        return real(root, rel_paths)

    backend.delete_many = delete_many
    return lambda: setattr(backend, "delete_many", real)


@pytest.mark.parametrize("after", [0, 1, 2])
def test_killed_between_batches_a_rerun_finishes(old, after):
    root, backend = old
    cfg = config({"backup": "automatic"})
    reference = MemoryBackend()
    for d in backend.list():
        reference.put(d)
    migrate(reference, root, cfg)
    restore = failing_delete(backend, after)
    with pytest.raises(Boom):
        migrate(backend, root, cfg, batch=2)
    restore()
    docs = docs_of(backend, root)
    roll = docs[f"{HBK}/[BACKUP]"]
    assert roll["probe"]["rollup"]["migrated"] is True and roll["size"] == 629      # phase 1 was done
    if after == 0:
        assert f"{HBK}/Pool/0/1/5.bucket" in docs      # nothing deleted yet
    result, _ = migrate(backend, root, cfg, batch=2)
    assert result.resumed or after >= 0
    done = docs_of(backend, root)
    assert done[f"{HBK}/[BACKUP]"]["size"] == 629
    ref = docs_of(reference, root)
    assert {k: v["kind"] for k, v in done.items()} == {k: v["kind"] for k, v in ref.items()}
    assert done[f"{HBK}/[BACKUP]"]["probe"]["rollup"]["total_files"] == 4


def test_killed_before_phase_one_ends_nothing_changed_and_a_rerun_recomputes(old, monkeypatch):
    root, backend = old
    cfg = config({"backup": "automatic"})
    before = docs_of(backend, root)
    real = backend.put

    def put(doc):
        if doc.get("kind") == "rollup":
            raise Boom
        return real(doc)

    monkeypatch.setattr(backend, "put", put)
    with pytest.raises(Boom):
        migrate(backend, root, cfg)
    monkeypatch.undo()
    assert docs_of(backend, root) == before
    result, _ = migrate(backend, root, cfg)
    assert result.migrated == 1 and docs_of(backend, root)[f"{HBK}/[BACKUP]"]["size"] == 629


def test_killed_before_cleanup_a_rerun_cleans_up(old, monkeypatch):
    root, backend = old
    cfg = config({"backup": "automatic"})
    real = backend.rebuild_aggregates

    def stop(**kw):
        raise Boom

    monkeypatch.setattr(backend, "rebuild_aggregates", stop)
    with pytest.raises(Boom):
        migrate(backend, root, cfg)
    monkeypatch.setattr(backend, "rebuild_aggregates", real)
    result, _ = migrate(backend, root, cfg)
    assert result.done
    assert backend.summary(root=str(root))["roots"][str(root)]["total_files"] == \
        len([d for d in backend.list(root=str(root)) if d["kind"] not in ("dir", "rollup")])


def test_refuses_while_a_scan_of_the_root_is_running(old):
    root, backend = old
    rootinfo.begin(backend, str(root))
    with pytest.raises(RuntimeError, match="a scan is running"):
        migrate(backend, root, config({"backup": "automatic"}))
    assert not rollups_of(docs_of(backend, root))


def test_files_that_were_read_are_not_migrated(old):
    root, backend = old
    backend, docs, _ = run_scan(str(root), options(config(), measure_backups=True, force=True), backend)
    result, _ = migrate(backend, root, config({"backup": "automatic"}))
    assert result.migrated == 0 and any("read, not just listed" in s for s in result.skipped)
    assert not rollups_of(docs_of(backend, root))


def test_a_store_that_is_not_asked_for_is_left_alone(old):
    root, backend = old
    result, _ = migrate(backend, root, config())
    assert result.targets == 0
    cfg = rollup.parse_config({"rollups": {"backup_store": [{"path": str(root / "Backup" / "NAS-LEGACY_1.hbk")}]}})
    result, _ = migrate(backend, root, cfg)
    assert result.migrated == 1


def test_rule_matches_are_folded_into_one_rollup_per_parent(old):
    root, backend = old
    cfg = config({"cache": "automatic"})
    result, _ = migrate(backend, root, cfg)
    docs = docs_of(backend, root)
    roll = docs["proj/[CACHE]"]
    assert roll["size"] == 12 and roll["probe"]["rollup"]["rule"] == "builtin:cache"
    assert roll["probe"]["rollup"]["matched"] == 1 and roll["probe"]["rollup"]["total_files"] == 2
    assert not [r for r in docs if r.startswith("proj/node_modules")]
    assert docs["proj"]["probe"]["rollup_tags"] == ["[CACHE]"] and docs["proj"]["probe"]["child_count"] == 2


def test_tags_limit_what_is_migrated(old):
    root, backend = old
    cfg = config({"cache": "automatic", "backup": "automatic"})
    result, _ = migrate(backend, root, cfg, tags={"[CACHE]"})
    docs = docs_of(backend, root)
    assert "proj/[CACHE]" in docs and f"{HBK}/[BACKUP]" not in docs


def test_a_redacted_rule_purges_and_registers_a_sticky_entry(old, tmp_path, monkeypatch):
    root, backend = old
    monkeypatch.setenv("FILECAT_REDACT_KEY_FILE", str(tmp_path / "redact.key"))
    cfg = config(rules=[{"tag": "[REDACTED]", "match": [str(root / "vault")]}])
    from filecat.samples import catalog_tag  # noqa: F401
    result, _ = migrate(backend, root, cfg)
    docs = docs_of(backend, root)
    assert result.migrated == 1
    roll = docs["[REDACTED]"]
    assert roll["size"] == 13 and roll["probe"]["rollup"]["rule"].startswith("user")
    assert not [r for r in docs if "vault" in r or "ZXQ" in r]
    assert len(backend.redactions(str(root))) == 1
    assert "ZXQ" not in repr(list(backend.list_dropped(str(root))))
    # a scan with no rule at all still keeps the folder redacted (sticky)
    _, scanned, _ = run_scan(str(root), options(config()), backend)
    assert "[REDACTED]" in scanned and "vault/ZXQ-secret.txt" not in scanned


def test_the_command_dry_run_and_real_run(old, capsys, monkeypatch):
    root, backend = old
    from filecat import rollups_cmd  # noqa: F401
    monkeypatch.setattr(backend, "close", lambda: None)
    monkeypatch.setattr("filecat.backends.open_backend", lambda *a, **k: backend)
    args = cli.build_parser().parse_args(["rollups", "migrate", "--dry-run", "--rollup", "backup=automatic",
                                          "--root", str(root)])
    from filecat import config as config_mod
    config_mod.apply(args, {})
    assert rollup_migrate.run(args) == 0
    out = capsys.readouterr()
    assert "would migrate 1 of 1 targets" in out.out and "would fold 1 children" in out.err
    assert not rollups_of(docs_of(backend, root))
    args = cli.build_parser().parse_args(["rollups", "migrate", "--rollup", "backup=automatic", "--root", str(root),
                                          "--checkpoint", str(FIXTURE_ROOT / f"c-{uuid.uuid4().hex}.json")])
    config_mod.apply(args, {})
    assert rollup_migrate.run(args) == 0
    assert "migrated 1 of 1 targets" in capsys.readouterr().out
    assert f"{HBK}/[BACKUP]" in docs_of(backend, root)


def test_the_same_on_sqlite_with_a_kill_and_a_rerun(fixture_dir):
    from filecat.backends.sqlite import SqliteBackend
    make_hbk(fixture_dir / "tree" / "Backup")
    db = str(fixture_dir / "cat.sqlite")
    backend = SqliteBackend(db)
    root = fixture_dir / "tree"
    run_scan(str(root), options(config()), backend)
    cfg = config({"backup": "automatic"})
    restore = failing_delete(backend, 1)
    with pytest.raises(Boom):
        migrate(backend, root, cfg, batch=2)
    restore()
    backend.close()
    backend = SqliteBackend(db)
    result, _ = migrate(backend, root, cfg, batch=2)
    docs = docs_of(backend, root)
    assert docs[f"{HBK}/[BACKUP]"]["size"] == 629 and result.done
    assert not [r for r in docs if r.startswith(f"{HBK}/Pool")]
    assert backend.rollup_totals(str(root))[str(root)][0]["tag"] == "[BACKUP]"
    backend.close()
