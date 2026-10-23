"""Store rollups (docs/rollups.md section 4): a backup store's or a database
folder's bulk folders become one [BACKUP] / [DATABASE] rollup while the store's
own record keeps probe.backup / probe.database; the manifest fingerprint that
carries a backup store's sum forward; verify levels 0 and 1; the same through
a filecat-agent.
"""
from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import filecat.walker as walker_mod
from filecat import cli, rollup
from filecat.backends.memory import MemoryBackend
from filecat.backup import detect
from _fake_agent import FakeAgent
from tests.test_backup import make_abb
from tests.test_dbfiles import make_pg
from tests.test_hyperbackup import make_hbk
from tests.test_rollup_walk import UNC, config, options, rollups_of, run_scan, write

HBK = "Backup/NAS-LEGACY_1.hbk"


def hbk_tree(base: Path) -> Path:
    make_hbk(base / "Backup")
    write(base / "Backup" / "other.txt", b"o")
    return base


def test_hyper_backup_pool_rolls_up_and_the_store_record_keeps_its_summary(fixture_dir):
    hbk_tree(fixture_dir)
    backend, docs, code = run_scan(str(fixture_dir), options(config({"backup": "automatic"})))
    assert code == 0
    roll = docs[f"{HBK}/[BACKUP]"]
    assert roll["kind"] == "rollup" and roll["size"] == 300 + 30 + 299 + 0     # 5.bucket 5.index 5.lock 6.bucket
    info = roll["probe"]["rollup"]
    assert info["rule"] == "store:synology-hyperbackup" and info["matched"] == 1
    assert info["store"] == {"format": "synology-hyperbackup", "path": HBK}
    assert info["total_files"] == 4 and len(info["fp"]) == 64 and info["via"] == "python"
    # nothing under Pool/ is recorded; the other folders are listed-only rows as before
    assert not [r for r in docs if r.startswith(f"{HBK}/Pool")]
    assert docs[f"{HBK}/Config/version_info.db"]["probe"] == {"backup_data": "synology-hyperbackup"}
    assert docs[f"{HBK}/Guard/local_file.db"]["kind"] == "data"
    store = docs[HBK]
    assert store["probe"]["rollup_tags"] == ["[BACKUP]"] and store["size"] == 0
    b = store["probe"]["backup"]
    assert b["task"] == "Synology NAS 1" and b["versions"] == 3 and b["checked"] == "none"
    assert "missing" not in b["guard"]      # level 0 compares nothing
    assert not any("Guard's manifest" in p for p in b["problems"])
    assert "Backup/other.txt" in docs


def test_the_default_changes_nothing_for_stores(fixture_dir):
    hbk_tree(fixture_dir)
    _, docs, _ = run_scan(str(fixture_dir), options(config()))
    assert not rollups_of(docs) and f"{HBK}/Pool/0/1/5.bucket" in docs
    assert "checked" not in docs[HBK]["probe"]["backup"]


def test_a_manual_store_is_listed_by_path_and_other_stores_are_untouched(fixture_dir):
    make_hbk(fixture_dir / "a")
    make_hbk(fixture_dir / "b")
    cfg = rollup.parse_config({"rollups": {"backup_store": [{"path": str(fixture_dir / "a" / "NAS-LEGACY_1.hbk")}]}})
    _, docs, _ = run_scan(str(fixture_dir), options(cfg))
    assert "a/NAS-LEGACY_1.hbk/[BACKUP]" in docs and "b/NAS-LEGACY_1.hbk/[BACKUP]" not in docs
    assert "b/NAS-LEGACY_1.hbk/Pool/0/1/5.bucket" in docs


def test_measure_backups_and_disabled_keep_per_file_rows(fixture_dir):
    hbk_tree(fixture_dir)
    _, docs, _ = run_scan(str(fixture_dir), options(config({"backup": "automatic"}), measure_backups=True,
                                                    identify="never"))
    assert not rollups_of(docs) and f"{HBK}/Pool/0/1/5.bucket" in docs
    # per-file rows keep Guard's per-file check, whatever the level
    guard = docs[HBK]["probe"]["backup"]["guard"]
    assert (guard["missing"], guard["size_mismatch"]) == (2, 1) and "checked" not in docs[HBK]["probe"]["backup"]
    _, docs, _ = run_scan(str(fixture_dir), options(config({"backup": "disabled"})))
    assert not rollups_of(docs) and f"{HBK}/Pool/0/1/5.bucket" in docs


def test_abb_rolls_up_its_pool_and_leaves_the_task_folders(fixture_dir):
    make_abb(fixture_dir / "share")
    pool = fixture_dir / "share" / "@ActiveBackup" / "@data" / "Pool" / "0"
    write(pool / "1.buk", b"b" * 50)
    _, docs, _ = run_scan(str(fixture_dir), options(config({"backup": "automatic"})))
    roll = docs["share/@ActiveBackup/[BACKUP]"]
    assert roll["probe"]["rollup"]["store"]["format"] == "synology-abb"
    assert not [r for r in docs if r.startswith("share/@ActiveBackup/@data/")]
    assert docs["share/@ActiveBackup"]["probe"]["backup"]["versions"] >= 1
    assert docs["share/@ActiveBackup"]["probe"]["backup"]["checked"] == "none"


def test_a_database_folder_rolls_up_into_database_and_keeps_probe_database(fixture_dir):
    make_pg(fixture_dir / "srv")
    _, docs, code = run_scan(str(fixture_dir), options(config({"database": "automatic"})))
    assert code == 0
    roll = docs["srv/pgdata/[DATABASE]"] if "srv/pgdata/[DATABASE]" in docs else next(
        d for d in docs.values() if d["kind"] == "rollup")
    assert roll["probe"]["rollup"]["tag"] == "[DATABASE]" and roll["probe"]["rollup"]["store"]["format"] == "postgres"
    folder = roll["rel_path"].rsplit("/", 1)[0]
    assert docs[folder]["probe"]["database"]["engine"] == "postgres"
    assert "fp" not in roll["probe"]["rollup"]         # a database is always summed
    assert "checked" not in docs[folder]["probe"]["database"]
    assert not [r for r in docs if "/base/" in r or "/pg_wal/" in r]


def test_a_rule_free_rescan_replaces_the_rollup_and_old_rows_are_deleted_not_dropped(fixture_dir):
    hbk_tree(fixture_dir)
    backend, docs, _ = run_scan(str(fixture_dir), options(config()))
    assert f"{HBK}/Pool/0/1/5.bucket" in docs
    backend, docs, _ = run_scan(str(fixture_dir), options(config({"backup": "automatic"})), backend)
    assert f"{HBK}/[BACKUP]" in docs and not [r for r in docs if r.startswith(f"{HBK}/Pool")]
    assert not list(backend.list_dropped(str(fixture_dir)))


# --- fingerprint and re-sum policy --------------------------------------------------------
def settle(root, cfg, fake=None):
    """One throwaway scan: NTFS shows a new folder's mtime late, which would change a fingerprint
    between the first two scans of a tree made a moment ago."""
    run_scan(root, options(cfg, fake))


def count_sums(monkeypatch):
    calls = []
    real = rollup.sum_tree

    def counting(path, **kw):
        calls.append(path)
        return real(path, **kw)

    monkeypatch.setattr(rollup, "sum_tree", counting)
    return calls


def test_an_unchanged_store_is_carried_forward_until_store_resum(fixture_dir, monkeypatch):
    hbk_tree(fixture_dir)
    cfg = config({"backup": "automatic"})
    settle(str(fixture_dir), cfg)
    calls = count_sums(monkeypatch)
    backend, docs, _ = run_scan(str(fixture_dir), options(cfg))
    first = docs[f"{HBK}/[BACKUP]"]["probe"]["rollup"]
    assert len(calls) == 1
    backend, docs, _ = run_scan(str(fixture_dir), options(cfg), backend)
    assert len(calls) == 1                     # fingerprint equal: not summed again
    assert docs[f"{HBK}/[BACKUP]"]["probe"]["rollup"]["summed_at"] == first["summed_at"]
    assert docs[HBK]["probe"]["backup"]["checked"] == "none"       # the store record is still rebuilt
    # --force re-sums
    backend, docs, _ = run_scan(str(fixture_dir), options(cfg, force=True), backend)
    assert len(calls) == 2
    # a new file in the pool folder changes its mtime: re-summed (a deeper change waits for store_resum)
    write(fixture_dir / HBK / "Pool" / "9.bucket", b"new")
    backend, docs, _ = run_scan(str(fixture_dir), options(cfg), backend)
    assert len(calls) == 3 and docs[f"{HBK}/[BACKUP]"]["size"] == 300 + 30 + 299 + 3


def test_a_changed_manifest_re_sums_even_when_the_pool_did_not_change(fixture_dir, monkeypatch):
    hbk_tree(fixture_dir)
    cfg = config({"backup": "automatic"})
    settle(str(fixture_dir), cfg)
    calls = count_sums(monkeypatch)
    backend, _, _ = run_scan(str(fixture_dir), options(cfg))
    cfg_file = fixture_dir / HBK / "last_status.conf"
    cfg_file.write_text(cfg_file.read_text() + "\n")
    run_scan(str(fixture_dir), options(cfg), backend)
    assert len(calls) == 2


def test_the_carried_sum_is_resummed_after_store_resum_days(fixture_dir, monkeypatch):
    hbk_tree(fixture_dir)
    cfg = rollup.parse_config({"rollups": {"backup": "automatic", "store_resum": "30d"}})
    settle(str(fixture_dir), cfg)
    calls = count_sums(monkeypatch)
    backend, docs, _ = run_scan(str(fixture_dir), options(cfg))
    stored = backend.get(str(fixture_dir), f"{HBK}/[BACKUP]")
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="seconds")
    stored["probe"]["rollup"]["summed_at"] = old
    backend.put(stored)
    run_scan(str(fixture_dir), options(cfg), backend)
    assert len(calls) == 2
    stored = backend.get(str(fixture_dir), f"{HBK}/[BACKUP]")
    assert stored["probe"]["rollup"]["summed_at"] > old
    # 29 days old is still carried
    stored["probe"]["rollup"]["summed_at"] = (datetime.now(timezone.utc) - timedelta(days=29)).isoformat(timespec="seconds")
    backend.put(stored)
    run_scan(str(fixture_dir), options(cfg), backend)
    assert len(calls) == 2


def test_a_database_is_summed_every_scan(fixture_dir, monkeypatch):
    make_pg(fixture_dir / "srv")
    cfg = config({"database": "automatic"})
    calls = count_sums(monkeypatch)
    backend, _, _ = run_scan(str(fixture_dir), options(cfg))
    n = len(calls)
    assert n >= 1
    run_scan(str(fixture_dir), options(cfg), backend)
    assert len(calls) == 2 * n


# --- verify levels ------------------------------------------------------------------------
def test_level_1_compares_the_pool_totals_with_guards_manifest(fixture_dir):
    hbk_tree(fixture_dir)
    # Guard lists the buckets 2053 (300) and 2054 (300) and their indexes (30 each); the pool holds 6.bucket
    # at 299 bytes and no 6.index
    _, docs, _ = run_scan(str(fixture_dir), options(config({"backup": "automatic"}), verify_backups=1))
    b = docs[HBK]["probe"]["backup"]
    assert b["checked"] == "totals"
    assert b["guard"]["rollup"] == {"guard_files": 4, "guard_bytes": 660, "files": 4, "bytes": 629}
    assert "the pool holds 629 bytes; Guard's manifest lists 660" in b["problems"]
    assert not any("pool holds 4 files" in p for p in b["problems"])      # 4 files, 4 listed
    # the files outside the pool are compared with the listing
    assert b["guard"]["missing"] == 1       # Config/@cand_file/1/5000_1.cand


def test_level_1_agrees_when_the_pool_matches(fixture_dir):
    store = make_hbk(fixture_dir / "Backup")
    (store / "Pool" / "0" / "1" / "6.bucket").write_bytes(b"b" * 300)
    (store / "Pool" / "0" / "1" / "6.index").write_bytes(b"i" * 30)
    (store / "Pool" / "0" / "1" / "5.lock").unlink()
    _, docs, _ = run_scan(str(fixture_dir), options(config({"backup": "automatic"}), verify_backups=1))
    b = docs[HBK]["probe"]["backup"]
    assert b["checked"] == "totals" and not any("pool holds" in p for p in b["problems"])


def test_verify_level_arguments(capsys):
    parser = cli.build_parser()
    assert parser.parse_args(["scan", "x"]).verify_backups is None
    assert parser.parse_args(["scan", "--verify-backups=0", "x"]).verify_backups == 0
    assert parser.parse_args(["scan", "--verify-backups=1", "x"]).verify_backups == 1
    for level in ("2", "3"):
        with pytest.raises(SystemExit):
            parser.parse_args(["scan", f"--verify-backups={level}", "x"])
        err = capsys.readouterr().err
        assert f"level {level} is not available in v0.2.0" in err and "--measure-backups" in err
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--verify-backups=7", "x"])


def test_a_bare_verify_backups_before_the_root_means_level_1(monkeypatch, fixture_dir):
    seen = {}

    class Mod:
        @staticmethod
        def run(args):
            seen["level"] = args.verify_backups
            seen["roots"] = args.roots
            return 0

    monkeypatch.setattr(cli.importlib, "import_module", lambda name: Mod)
    assert cli.main(["scan", "--verify-backups", str(fixture_dir)]) == 0
    assert seen == {"level": 1, "roots": [str(fixture_dir)]}
    assert cli.main(["scan", "--verify-backups=0", str(fixture_dir)]) == 0 and seen["level"] == 0


# --- through a filecat-agent --------------------------------------------------------------
@pytest.fixture
def nas(fixture_dir) -> Path:
    return fixture_dir / "nas"


def test_a_store_rolls_up_through_the_agent_with_sum_subtree(nas):
    make_hbk(nas / "volume1" / "Backup")
    cfg = config({"backup": "automatic"})
    with FakeAgent(nas) as fake:
        _, docs, code = run_scan(UNC, options(cfg, fake))
        sums = [r for r in fake.requests if r["cmd"] == "sum_subtree"]
    assert code == 0
    roll = docs["NAS-LEGACY_1.hbk/[BACKUP]"]
    info = roll["probe"]["rollup"]
    assert info["via"] == "agent" and info["store"]["format"] == "synology-hyperbackup"
    assert roll["size"] == 300 + 30 + 299 and "allocated_size" in roll
    assert [r["path"] for r in sums] == ["/volume1/Backup/NAS-LEGACY_1.hbk/Pool"]
    assert sums[0].get("progress_ms") and sums[0].get("id")
    assert not [r for r in docs if r.startswith("NAS-LEGACY_1.hbk/Pool")]
    store = docs["NAS-LEGACY_1.hbk"]["probe"]
    assert "manifest not read" in store["store_note"] and "backup" not in store
    assert docs["NAS-LEGACY_1.hbk/Config/version_info.db"]["kind"] == "data"


def test_the_agent_scan_carries_the_store_forward_by_its_fingerprint(nas):
    make_hbk(nas / "volume1" / "Backup")
    cfg = config({"backup": "automatic"})
    with FakeAgent(nas) as fake:
        settle(UNC, cfg, fake)
        backend, docs, _ = run_scan(UNC, options(cfg, fake))
        n = len([r for r in fake.requests if r["cmd"] == "sum_subtree"])
        run_scan(UNC, options(cfg, fake), backend)
        assert len([r for r in fake.requests if r["cmd"] == "sum_subtree"]) == n
        run_scan(UNC, options(cfg, fake, force=True), backend)
        assert len([r for r in fake.requests if r["cmd"] == "sum_subtree"]) == n + 1


def test_local_and_agent_store_rollups_agree(fixture_dir, nas):
    make_hbk(nas / "volume1" / "Backup")
    make_hbk(fixture_dir / "local")
    cfg = config({"backup": "automatic"})
    with FakeAgent(nas) as fake:
        _, a, _ = run_scan(UNC, options(cfg, fake))
    _, b, _ = run_scan(str(fixture_dir / "local"), options(cfg))
    ra, rb = a["NAS-LEGACY_1.hbk/[BACKUP]"], b["NAS-LEGACY_1.hbk/[BACKUP]"]
    assert ra["size"] == rb["size"]
    for key in ("total_files", "total_dirs", "matched", "rule", "store", "errors"):
        assert ra["probe"]["rollup"][key] == rb["probe"]["rollup"][key], key


def test_a_database_through_the_agent(nas):
    make_pg(nas / "volume1" / "Backup")
    with FakeAgent(nas) as fake:
        _, docs, code = run_scan(UNC, options(config({"database": "automatic"}), fake))
    assert code == 0
    roll = next(d for d in docs.values() if d["kind"] == "rollup")
    assert roll["probe"]["rollup"]["tag"] == "[DATABASE]" and roll["probe"]["rollup"]["via"] == "agent"
    assert roll["size"] > 0
