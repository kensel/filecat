"""Backup and database manifests read through a filecat-agent (backup/storefs.py,
docs/rollups.md 4.3): every format gives the same probe.backup / probe.database
from the fake agent as from the same folder on disk; SQLite manifests are
copied (with their -wal) under rollups.manifest_cap into a temp folder that is
always deleted; a store over the cap gets a note instead of a summary; migrate
finds stores an agent scan recorded.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import struct
import tempfile
import time
from pathlib import Path

import pytest

from filecat import fsource, rollup, rollup_migrate
from filecat.agent_client import AgentClient
from filecat.backends.memory import MemoryBackend
from filecat.backup import storefs
from filecat.options import ScanOptions
from _fake_agent import FakeAgent
from tests.conftest import FIXTURE_ROOT
from tests.test_abg import make_task
from tests.test_agent_scan import UNC, config_for, options, scan_into
from tests.test_backup import MANIFEST, make_abb
from tests.test_dbfiles import make_mongo, make_mssql, make_mysql, make_pg
from tests.test_hyperbackup import make_hbk
from tests.test_rollup_walk import config as rollup_config
from tests.test_rollup_walk import options as rollup_options
from tests.test_rollup_walk import run_scan, write
from tests.test_thunderbird import make_copy
from tests.test_veeam import make_job


# --- stores ---------------------------------------------------------------------------
def make_windows_file_backup(base: Path) -> None:
    pc = base / "HOMEPC"
    full = pc / "Backup Set 2009-05-21 123957" / "Backup Files 2009-05-21 123957"
    (full / "Catalogs").mkdir(parents=True)
    (pc / "Backup Set 2009-05-21 123957" / "Catalogs").mkdir()
    (pc / "Backup Set 2009-05-21 123957" / "Catalogs" / "GlobalCatalog.wbcat").write_bytes(b"c")
    (pc / "MediaID.bin").write_bytes(bytes(range(16)))
    for n in (1, 2, 4):
        (full / f"Backup files {n}.zip").write_bytes(b"z" * n)
    for n in (1, 2, 3, 4, 5):
        (full / "Catalogs" / f"Backup files {n}.wbcat").write_bytes(b"c")


def make_windows_image_backup(base: Path) -> None:
    pc = base / "WindowsImageBackup" / "Homepc"
    ver = pc / "Backup 2009-06-13 010936"
    ver.mkdir(parents=True)
    (pc / "Catalog").mkdir()
    (pc / "MediaId").write_bytes(b"\x01" * 16)
    (ver / "disk-guid.vhd").write_bytes(b"v" * 64)
    xml = ('<BACKUP_COMPONENTS><BACKUP_METADATA metadata="&lt;System MachineName=&quot;HOMEPC&quot; '
           'OSVersion=&quot;6.0&quot;/&gt;"/></BACKUP_COMPONENTS>')
    (ver / "b7b4_Components.xml").write_bytes(xml.encode("utf-16-le"))
    (pc / "Backup 2009-07-01 010000").mkdir()


def make_duplicity(base: Path) -> None:
    d = base / "dup"
    d.mkdir()
    t1, t2 = "20240101T020000Z", "20240102T020000Z"
    (d / f"duplicity-full.{t1}.manifest").write_text(MANIFEST)
    (d / f"duplicity-full.{t1}.vol1.difftar.gz").write_bytes(b"v")
    (d / f"duplicity-full-signatures.{t1}.sigtar.gz").write_bytes(b"s")
    (d / f"duplicity-inc.{t1}.to.{t2}.manifest.gpg").write_bytes(b"m")
    (d / f"duplicity-inc.{t1}.to.{t2}.vol1.difftar.gpg").write_bytes(b"v")


def make_mongo_per_db(base: Path) -> None:
    make_mongo(base, per_db=True)


def make_mssql_old(base: Path) -> None:
    d = make_mssql(base)
    for p in d.iterdir():
        os.utime(p, (time.time() - 7200,) * 2)


STORES = {
    "hyperbackup": (make_hbk, "backup"),
    "abb": (make_abb, "backup"),
    "abg": (make_task, "backup"),
    "veeam": (make_job, "backup"),
    "thunderbird": (make_copy, "backup"),
    "windows-file": (make_windows_file_backup, "backup"),
    "windows-image": (make_windows_image_backup, "backup"),
    "duplicity": (make_duplicity, "backup"),
    "postgres": (make_pg, "database"),
    "mysql": (make_mysql, "database"),
    "mongodb": (make_mongo_per_db, "database"),
    "mssql": (make_mssql_old, "database"),
}


def probes(docs: dict, key: str) -> dict[str, dict]:
    return {rel: d["probe"][key] for rel, d in docs.items() if key in (d.get("probe") or {})}


@pytest.fixture
def nas(fixture_dir) -> Path:
    share = fixture_dir / "nas" / "volume1" / "Backup"
    share.mkdir(parents=True)
    return fixture_dir / "nas"


def scan_both(nas: Path, **kw):
    share = nas / "volume1" / "Backup"
    _, local, code = scan_into(str(share), options(**kw))
    assert code == 0
    with FakeAgent(nas) as fake:
        _, remote, code = scan_into(UNC, options(fake, **kw))
        assert code == 0
        return local, remote, fake


@pytest.mark.parametrize("name", sorted(STORES))
def test_same_as_local(name, nas):
    build, key = STORES[name]
    build(nas / "volume1" / "Backup")
    local, remote, _ = scan_both(nas)
    want, got = probes(local, key), probes(remote, key)
    assert want, "the local scan found no store"
    assert got == want
    assert not [r for r, d in remote.items() if "store_note" in (d.get("probe") or {})]
    assert {r for r, d in remote.items() if d.get("errors")} == {r for r, d in local.items() if d.get("errors")}


def test_verify_levels_read_the_data_through_the_agent_too(nas):
    make_job(nas / "volume1" / "Backup")
    make_hbk(nas / "volume1" / "Backup")
    local, remote, _ = scan_both(nas, verify_backups=2)
    want = probes(local, "backup")
    assert len(want) == 2 and probes(remote, "backup") == want
    assert any("verified" in b or "crc_checked" in (b.get("guard") or {}) for b in want.values())


def test_rolled_up_stores_agree_too(nas):
    make_hbk(nas / "volume1" / "Backup")
    make_pg(nas / "volume1" / "Backup")
    cfg = rollup_config({"backup": "automatic", "database": "automatic"})
    _, local, _ = run_scan(str(nas / "volume1" / "Backup"), rollup_options(cfg))
    with FakeAgent(nas) as fake:
        _, remote, _ = run_scan(UNC, rollup_options(cfg, fake))
    for key in ("backup", "database"):
        want = probes(local, key)
        assert want and probes(remote, key) == want


# --- the cap, the copy and the temp folder -------------------------------------------------
@pytest.fixture
def temp_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "tmp"
    home.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(home))
    return home


def make_wal_db(path: Path) -> sqlite3.Connection:
    """A database whose newest rows are only in its -wal (the connection that
    wrote them is still open, as a running NAS service would have it)."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE t (n INTEGER)")
    conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(5)])
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(5, 12)])
    conn.commit()
    return conn


def agent_fs(fake: FakeAgent, root: str = UNC, cap: int = storefs.DEFAULT_MANIFEST_CAP) -> storefs.AgentFS:
    return storefs.AgentFS(fsource.AgentSource(config_for(fake)), root, cap)


def test_a_sqlite_manifest_is_copied_with_its_wal_and_deleted(nas, temp_home):
    db = nas / "volume1" / "Backup" / "m.db"
    conn = make_wal_db(db)
    try:
        assert os.path.getsize(f"{db}-wal") > 0
        with FakeAgent(nas) as fake:
            fs = agent_fs(fake)
            rows = fs.sqlite_rows(UNC + "\\m.db", "SELECT count(*) AS c, max(n) AS m FROM t")
            assert rows == [{"c": 12, "m": 11}]
            reads = [r for r in fake.requests if r["cmd"] == "read_range"]
            assert {r["path"].rsplit("/", 1)[-1] for r in reads} == {"m.db", "m.db-wal"}
        assert os.listdir(temp_home) == []
    finally:
        conn.close()


def test_a_plain_manifest_opens_read_only_and_two_queries_copy_it_once(nas, temp_home):
    db = nas / "volume1" / "Backup" / "m.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE t (n INTEGER)")
    c.execute("INSERT INTO t VALUES (1)")
    c.commit()
    c.close()
    with FakeAgent(nas) as fake:
        fs = agent_fs(fake)
        a, b = fs.sqlite_many(UNC + "\\m.db", [("SELECT n FROM t", ()), ("SELECT n + 1 AS n FROM t", ())])
        assert (a, b) == ([{"n": 1}], [{"n": 2}])
        assert len([r for r in fake.requests if r["cmd"] == "read_range"]) == 1
    assert os.listdir(temp_home) == []


def test_a_manifest_over_the_cap_is_not_copied(nas, temp_home):
    db = nas / "volume1" / "Backup" / "big" / "target.db"
    db.parent.mkdir()
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE t (n INTEGER)")
    c.commit()
    c.close()
    size = os.path.getsize(db)
    with FakeAgent(nas) as fake:
        fs = agent_fs(fake, UNC + "\\big", cap=size - 1)
        with pytest.raises(storefs.ManifestTooLarge):
            fs.sqlite_rows(UNC + "\\big\\target.db", "SELECT 1")
        assert fs.oversize == [f"target.db ({size} bytes, limit {size - 1})"]
        assert not [r for r in fake.requests if r["cmd"] == "read_range"]
        agent_fs(fake, cap=size).sqlite_rows(UNC + "\\big\\target.db", "SELECT 1")     # exactly the cap is fine
    assert os.listdir(temp_home) == []


def test_the_temp_folder_goes_after_a_read_error(nas, temp_home, monkeypatch):
    db = nas / "volume1" / "Backup" / "m.db"
    conn = make_wal_db(db)
    real = AgentClient.read_range
    calls = []

    def flaky(self, path, offset, length):
        calls.append(path)
        if len(calls) == 2:                     # the -wal, after the main file was written
            raise OSError("connection reset")
        return real(self, path, offset, length)

    monkeypatch.setattr(AgentClient, "read_range", flaky)
    try:
        with FakeAgent(nas) as fake:
            with pytest.raises(OSError, match="connection reset"):
                agent_fs(fake).sqlite_rows(UNC + "\\m.db", "SELECT 1")
    finally:
        conn.close()
    assert len(calls) == 2 and os.listdir(temp_home) == []


def test_a_query_error_also_leaves_nothing_behind(nas, temp_home):
    db = nas / "volume1" / "Backup" / "m.db"
    sqlite3.connect(db).close()
    write(db, b"not a database" * 100)
    with FakeAgent(nas) as fake, pytest.raises(sqlite3.DatabaseError):
        agent_fs(fake).sqlite_rows(UNC + "\\m.db", "SELECT * FROM t")
    assert os.listdir(temp_home) == []


def test_a_manifest_that_changes_while_it_is_copied_is_retried_then_refused(nas, temp_home, monkeypatch):
    db = nas / "volume1" / "Backup" / "m.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE t (n INTEGER)")
    c.commit()
    c.close()
    real = AgentClient.read_range
    n = {"copies": 0}

    def touch(self, path, offset, length):
        n["copies"] += 1
        data = real(self, path, offset, length)
        os.utime(db, ns=(1, n["copies"] * 10**9))      # a writer got there during the copy
        return data

    monkeypatch.setattr(AgentClient, "read_range", touch)
    with FakeAgent(nas) as fake, pytest.raises(OSError, match="changed while being copied"):
        agent_fs(fake).sqlite_rows(UNC + "\\m.db", "SELECT 1")
    assert n["copies"] == 2 and os.listdir(temp_home) == []


def test_a_scan_over_the_cap_notes_the_store_and_does_not_crash(nas, temp_home):
    make_hbk(nas / "volume1" / "Backup")
    cfg = rollup.parse_config({"rollups": {"manifest_cap": "1KiB"}})
    with FakeAgent(nas) as fake:
        _, docs, code = run_scan(UNC, rollup_options(cfg, fake))
    assert code == 0
    probe = docs["NAS-LEGACY_1.hbk"]["probe"]
    assert "backup" not in probe and "manifest_cap" in probe["store_note"]
    assert probe["store_note"].startswith("synology-hyperbackup:")
    assert "errors" not in docs["NAS-LEGACY_1.hbk"]
    assert os.listdir(temp_home) == []
    assert rollup.RollupConfig().manifest_cap == storefs.DEFAULT_MANIFEST_CAP == 256 * 1024 * 1024


def test_a_scan_leaves_the_system_temp_folder_empty(nas, temp_home):
    make_hbk(nas / "volume1" / "Backup")
    make_abb(nas / "volume1" / "Backup")
    _, remote_all, _ = scan_both(nas)
    assert probes(remote_all, "backup") and os.listdir(temp_home) == []


# --- the file system itself ------------------------------------------------------------------
def test_agent_fs_answers_what_the_readers_ask(nas):
    share = nas / "volume1" / "Backup"
    write(share / "d" / "a.txt", b"hello\n")
    write(share / "d" / "conf.json", json.dumps({"k": 1}))
    with FakeAgent(nas) as fake:
        fs = agent_fs(fake)
        d = fs.join(UNC, "d")
        assert d == UNC + "\\d" and fs.join(UNC + "\\", "d", "x/y") == UNC + "\\d\\x\\y"
        assert fs.basename(d + "\\") == "d"
        assert sorted(fs.listdir(d)) == ["a.txt", "conf.json"] and fs.listdir(d + "\\nope") == {}
        assert fs.stat(d + "\\a.txt").st_size == 6 and fs.file_size(d + "\\nope") is None
        assert fs.isfile(d + "\\a.txt") and not fs.isfile(d) and fs.isdir(d) and not fs.isdir(d + "\\a.txt")
        assert fs.exists(d + "\\a.txt") and not fs.exists(d + "\\nope")
        with fs.open(d + "\\a.txt") as f:
            f.seek(2)
            assert f.read(3) == b"llo"
        with fs.open(d + "\\a.txt", "r", encoding="utf-8") as f:
            assert f.read() == "hello\n"
        assert fs.read_json(d + "\\conf.json") == {"k": 1}
        with pytest.raises(FileNotFoundError):
            fs.stat(d + "\\nope")
        assert fs.sizes(UNC) == {"d/a.txt": 6, "d/conf.json": 8}


def test_local_fs_is_the_os(fixture_dir):
    write(fixture_dir / "d" / "a.txt", b"hello\n")
    fs = storefs.LOCAL
    d = str(fixture_dir / "d")
    assert fs.local and fs.join(d, "a.txt") == os.path.join(d, "a.txt") and fs.basename(d) == "d"
    assert fs.file_size(d + "\\a.txt".replace("\\", os.sep)) == 6 and fs.sizes(d) == {"a.txt": 6}
    assert fs.isfile(os.path.join(d, "a.txt")) and fs.isdir(d) and not fs.exists(os.path.join(d, "x"))


# --- privacy -------------------------------------------------------------------------------
def test_a_store_in_a_redacted_folder_is_never_read_or_logged(nas, caplog):
    share = nas / "volume1" / "Backup"
    make_hbk(share)
    make_hbk(share / "ZXQ-vault", "SECRET-NAME_1.hbk")
    write(share / "ZXQ-vault" / ".filecat-redacted")
    caplog.set_level(logging.DEBUG)
    with FakeAgent(nas) as fake:
        _, docs, code = scan_into(UNC, options(fake))
        paths = [r.get("path", "") for r in fake.requests]
    assert code == 0 and docs["NAS-LEGACY_1.hbk"]["probe"]["backup"]["task"] == "Synology NAS 1"
    assert not [p for p in paths if "ZXQ" in p or "SECRET" in p]
    assert not [r for r in caplog.records if "ZXQ" in r.getMessage() or "SECRET" in r.getMessage()]
    assert not [rel for rel in docs if "ZXQ" in rel or "SECRET" in rel]


# --- migrate -------------------------------------------------------------------------------
def test_migrate_finds_a_store_an_agent_scan_recorded(nas):
    make_hbk(nas / "volume1" / "Backup")
    write(nas / "volume1" / "Backup" / "other.txt", b"o")
    backend = MemoryBackend()
    with FakeAgent(nas) as fake:
        run_scan(UNC, rollup_options(rollup_config(), fake), backend)
    docs = {d["rel_path"]: d for d in backend.list(root=UNC)}
    assert docs["NAS-LEGACY_1.hbk"]["probe"]["backup"]["format"] == "synology-hyperbackup"
    assert "NAS-LEGACY_1.hbk/Pool/0/1/5.bucket" in docs
    opts = ScanOptions(rollup_config=rollup_config({"backup": "automatic"}), identify="never")
    ck = str(FIXTURE_ROOT / f"ck-{time.time_ns()}.json")
    result = rollup_migrate.migrate(backend, opts, ck, roots=[UNC], resume_path=str(FIXTURE_ROOT / "no-resume.json"))
    assert result.targets == 1 and result.migrated == 1 and result.done
    docs = {d["rel_path"]: d for d in backend.list(root=UNC)}
    roll = docs["NAS-LEGACY_1.hbk/[BACKUP]"]
    assert roll["probe"]["rollup"]["store"]["format"] == "synology-hyperbackup" and roll["size"] == 629
    assert docs["NAS-LEGACY_1.hbk"]["probe"]["backup"]["task"] == "Synology NAS 1"
    assert not [r for r in docs if r.startswith("NAS-LEGACY_1.hbk/Pool")]
