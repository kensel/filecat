from __future__ import annotations

import os
import struct
import tempfile
import time
import uuid

from filecat import databases_cmd, dbfiles, record
from filecat.backends.memory import MemoryBackend
from filecat.backup import summarize
from filecat.dbfiles import mongodb, mssql, mysql, postgres
from filecat.enrich import enrich
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import walk_root

MiB = 1024 * 1024
OLD = time.time() - 200 * 86400     # well past the 90-day quiet age


def _resume():
    return ResumeState(os.path.join(tempfile.gettempdir(), f"filecat-test-resume-{uuid.uuid4().hex}.json"))


def _measure_stub(root, rel_path, abs_path, st, options, identifier):
    doc = record.new_document(root, rel_path, kind="text", size=st.st_size,
                              mtime_ns=st.st_mtime_ns, ctime_ns=st.st_mtime_ns)
    doc["sha256"] = "x"
    return doc


def _age(path, when=OLD):
    os.utime(path, (when, when))


def _walk(base, options=None, measure=_measure_stub):
    backend = MemoryBackend()
    errors = walk_root(str(base), options or ScanOptions(), backend, None, _resume(), measure)
    return backend, {d["rel_path"]: d for d in backend.list(root=str(base))}, errors


# --- PostgreSQL ----------------------------------------------------------------

def make_pg(base, *, sysid=7300000000000000001, state=6, pid=True):
    d = base / "pgdata"
    (d / "base" / "1").mkdir(parents=True)
    (d / "base" / "16384").mkdir()
    (d / "global").mkdir()
    (d / "pg_wal" / "archive_status").mkdir(parents=True)
    (d / "log").mkdir()
    (d / "PG_VERSION").write_text("16\n")
    (d / "postgresql.conf").write_text("port = 5432\n")
    (d / "log" / "postgresql.log").write_text("LOG: ready\n")
    (d / "base" / "1" / "1259").write_bytes(b"\0" * 8192)
    (d / "base" / "16384" / "16385").write_bytes(b"\0" * (2 * MiB))
    (d / "base" / "16384" / "16386").write_bytes(b"\0" * 8192)
    (d / "pg_wal" / "000000010000000000000001").write_bytes(b"\0" * 4096)
    control = struct.pack("<QIII", sysid, 1300, 202307071, state) + b"\0" * 4 + struct.pack("<q", 1792000000)
    (d / "global" / "pg_control").write_bytes(control + b"\0" * (8192 - len(control)))
    if pid:
        (d / "postmaster.pid").write_text(f"4242\n{d}\n1792000000\n5432\n/tmp\n")
    return d


def test_pg_detect_and_opaque():
    assert dbfiles.detect("x", "x", {"PG_VERSION", "base", "global", "pg_wal"}).format is postgres.ENGINE
    assert dbfiles.detect("x", "x", {"PG_VERSION", "base"}) is None
    assert postgres.ENGINE.opaque("base/16384/16385")
    assert postgres.ENGINE.opaque("pg_wal/000000010000000000000001")
    assert not postgres.ENGINE.opaque("postgresql.conf")
    assert not postgres.ENGINE.opaque("log/postgresql.log")


def test_pg_summary(fixture_dir):
    d = make_pg(fixture_dir)
    s = postgres.ENGINE.summarize(str(d), set(os.listdir(d)))
    assert s["version"] == "16" and s["running"] and s["postmaster"] == {"pid": 4242, "port": 5432}
    assert s["system_identifier"] == "7300000000000000001"
    assert s["cluster_state"] == "in production" and s["catalog_version"] == 202307071
    assert s["instance_keys"] == ["pg:7300000000000000001"]
    assert [(x["oid"], x["name"], x["files"]) for x in s["databases"]] == [("1", "template1", 1),
                                                                          ("16384", None, 2)]
    assert s["wal"]["folder"] == "pg_wal" and s["wal"]["segments"] == 1
    assert s["files"] == 5 and s["problems"] == [] and s["quiet"] is False


def test_pg_copy_taken_while_running_is_a_problem(fixture_dir):
    d = make_pg(fixture_dir, pid=False)
    s = postgres.ENGINE.summarize(str(d), set(os.listdir(d)))
    assert not s["running"]
    assert s["problems"] and "not shut down cleanly" in s["problems"][0]
    d2 = make_pg(fixture_dir / "clean", pid=False, state=1)
    assert postgres.ENGINE.summarize(str(d2), set(os.listdir(d2)))["problems"] == []


def test_walker_lists_pg_data_and_summarizes(fixture_dir):
    make_pg(fixture_dir)
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    _, docs, errors = _walk(fixture_dir, measure=measure)
    rel = "pgdata/base/16384/16385"
    assert docs[rel]["kind"] == "data" and docs[rel]["probe"] == {"db_data": "postgres"}
    assert not any(r.startswith(("pgdata/base/", "pgdata/global/", "pgdata/pg_wal/")) for r in measured)
    assert {"pgdata/PG_VERSION", "pgdata/postgresql.conf", "pgdata/log/postgresql.log"} <= set(measured)
    assert docs["pgdata"]["probe"]["database"]["engine"] == "postgres"
    assert not errors


def test_measure_databases_reads_only_quiet_big_files(fixture_dir):
    d = make_pg(fixture_dir)
    for p in (d / "base" / "16384").iterdir():
        _age(p)
    _, docs, _ = _walk(fixture_dir, ScanOptions(measure_databases=True))
    big, small = docs["pgdata/base/16384/16385"], docs["pgdata/base/16384/16386"]
    assert big["kind"] == "text" and big["probe"]["db_data"] == "postgres"      # quiet, 2 MiB
    assert small["kind"] == "data" and "sha256" not in small                     # quiet but 8 KB
    assert docs["pgdata/pg_wal/000000010000000000000001"]["kind"] == "data"      # recent


# --- MySQL / MariaDB ------------------------------------------------------------

def make_mysql(base, *, mariadb=False):
    d = base / "mysqldata"
    (d / "mysql").mkdir(parents=True)
    (d / "shop").mkdir()
    (d / "#innodb_redo").mkdir()
    (d / "ibdata1").write_bytes(b"\0" * 4096)
    (d / "binlog.000001").write_bytes(b"\0" * 100)
    (d / "binlog.index").write_text("./binlog.000001\n")
    (d / "HOST1.err").write_text("ready for connections\n")
    (d / "HOST1.pid").write_text("99\n")
    (d / "auto.cnf").write_text("[auto]\nserver-uuid=0d6f2c3e-1111-2222-3333-444455556666\n")
    (d / "#innodb_redo" / "#ib_redo0").write_bytes(b"\0" * 10)
    (d / "mysql" / "user.MYD").write_bytes(b"\0")
    (d / "shop" / "orders.ibd").write_bytes(b"\0" * 64)
    (d / "shop" / "items#P#p0.ibd").write_bytes(b"\0" * 64)
    (d / "shop" / "items#P#p1.ibd").write_bytes(b"\0" * 64)
    if mariadb:
        (d / "aria_log_control").write_bytes(b"\0" * 52)
        (d / "mysql_upgrade_info").write_text("10.11.6-MariaDB")
    else:
        (d / "mysql.ibd").write_bytes(b"\0" * 1024)
    return d


def test_mysql_detect_opaque_and_summary(fixture_dir):
    d = make_mysql(fixture_dir)
    names = set(os.listdir(d))
    assert dbfiles.detect("m", "m", names).format is mysql.ENGINE
    assert mysql.ENGINE.opaque("ibdata1") and mysql.ENGINE.opaque("shop/orders.ibd")
    assert mysql.ENGINE.opaque("binlog.000001") and mysql.ENGINE.opaque("#innodb_redo/#ib_redo0")
    assert not mysql.ENGINE.opaque("HOST1.err") and not mysql.ENGINE.opaque("auto.cnf")
    s = mysql.ENGINE.summarize(str(d), names)
    assert s["flavor"] == "mysql" and s["version"] is None and s["version_hint"] == "8.0+"
    assert s["server_uuid"] == "0d6f2c3e-1111-2222-3333-444455556666" and s["running"]
    assert s["instance_keys"] == ["mysql:0d6f2c3e-1111-2222-3333-444455556666"]
    shop = next(x for x in s["databases"] if x["name"] == "shop")
    assert shop["tables"] == 2 and shop["engines"] == ["InnoDB"] and not shop["system"]
    assert next(x for x in s["databases"] if x["name"] == "mysql")["system"]
    assert s["binlogs"]["files"] == 2       # binlog.000001 and binlog.index
    assert s["innodb"]["files"] == 2


def test_mariadb_flavor_and_version(fixture_dir):
    d = make_mysql(fixture_dir, mariadb=True)
    s = mysql.ENGINE.summarize(str(d), set(os.listdir(d)))
    assert s["flavor"] == "mariadb" and s["version"] == "10.11.6-MariaDB"
    assert not mysql.ENGINE.opaque("mysql_upgrade_info")


# --- MongoDB ---------------------------------------------------------------------

def _bson(doc):
    def enc(d):
        body = b""
        for k, v in d.items():
            key = k.encode() + b"\0"
            if isinstance(v, bool):
                body += b"\x08" + key + (b"\x01" if v else b"\x00")
            elif isinstance(v, str):
                s = v.encode() + b"\0"
                body += b"\x02" + key + struct.pack("<i", len(s)) + s
            elif isinstance(v, dict):
                body += b"\x03" + key + enc(v)
        return struct.pack("<i", len(body) + 5) + body + b"\0"
    return enc(doc)


def make_mongo(base, *, per_db=False):
    d = base / "mongodb"
    (d / "journal").mkdir(parents=True)
    (d / "diagnostic.data").mkdir()
    (d / "WiredTiger").write_text("WiredTiger\nWiredTiger 10.0.2: (December 21, 2021)\n")
    (d / "WiredTiger.wt").write_bytes(b"\0" * 100)
    (d / "_mdb_catalog.wt").write_bytes(b"\0" * 100)
    (d / "mongod.lock").write_text("")
    (d / "storage.bson").write_bytes(_bson({"storage": {"engine": "wiredTiger", "options": {
        "directoryPerDB": per_db, "directoryForIndexes": False}}}))
    (d / "journal" / "WiredTigerLog.0000000001").write_bytes(b"\0" * 10)
    (d / "diagnostic.data" / "metrics.2026-10-18T00-00-00Z-00000").write_bytes(b"\0" * 10)
    where = d / "shop" if per_db else d
    where.mkdir(exist_ok=True)
    (where / "collection-0-123.wt").write_bytes(b"\0" * 200)
    (where / "index-1-123.wt").write_bytes(b"\0" * 50)
    return d


def test_mongo_detect_opaque_and_summary(fixture_dir):
    d = make_mongo(fixture_dir, per_db=True)
    names = set(os.listdir(d))
    assert dbfiles.detect("m", "m", names).format is mongodb.ENGINE
    assert mongodb.ENGINE.opaque("shop/collection-0-123.wt")
    assert mongodb.ENGINE.opaque("journal/WiredTigerLog.0000000001")
    assert mongodb.ENGINE.opaque("diagnostic.data/metrics.2026-10-18T00-00-00Z-00000")
    assert not mongodb.ENGINE.opaque("WiredTiger") and not mongodb.ENGINE.opaque("storage.bson")
    s = mongodb.ENGINE.summarize(str(d), names)
    assert s["wiredtiger_version"] == "10.0.2" and s["storage_engine"] == "wiredTiger"
    assert s["options"] == {"directoryPerDB": True, "directoryForIndexes": False}
    assert s["running"] is False and s["collections"] == 1 and s["indexes"] == 1
    assert [x["name"] for x in s["databases"]] == ["shop"] and s["journal"] == 1


def test_mongo_flat_layout_has_no_database_names(fixture_dir):
    d = make_mongo(fixture_dir)
    s = mongodb.ENGINE.summarize(str(d), set(os.listdir(d)))
    assert s["databases"] == [] and s["collections"] == 1


def test_mongo_lock_files_and_spill_db_are_listed_only():
    # mongod holds both lock files locked on Windows: opening them fails
    assert mongodb.ENGINE.opaque("mongod.lock") and mongodb.ENGINE.opaque("WiredTiger.lock")
    assert mongodb.ENGINE.opaque("_tmp/spilldb/WiredTiger.turtle")
    assert mongodb.ENGINE.opaque("WiredTigerHS.wt")
    assert mongodb.ENGINE.opaque("collection-5ee36dee-dc6f-4f37-8d84-8f032feef012.wt")
    assert not mongodb.ENGINE.opaque("WiredTiger.turtle")


def test_mongo_version_from_the_install_folder(fixture_dir):
    assert mongodb.version_from_path(r"C:\Apps\mongodb-win32-x86_64-windows-9.0.4\data\db") == "9.0.4"
    assert mongodb.version_from_path(r"C:\Program Files\MongoDB\Server\8.0\data") == "8.0"
    assert mongodb.version_from_path(r"D:\mongo\data") is None
    d = make_mongo(fixture_dir / "mongodb-windows-x86_64-8.2.1" / "data")
    s = mongodb.ENGINE.summarize(str(d), set(os.listdir(d)))
    assert s["version"] == "8.2.1" and s["version_source"] == "folder"


def test_read_bson_stops_on_garbage():
    assert mongodb.read_bson(b"\x01\x02") == {}


# --- SQL Server --------------------------------------------------------------------

def make_mssql(base):
    d = base / "MSSQL16.MSSQLSERVER" / "MSSQL" / "DATA"
    d.mkdir(parents=True)
    for name, size in (("master.mdf", 4096), ("mastlog.ldf", 1024), ("msdbdata.mdf", 4096),
                       ("msdblog.ldf", 1024), ("Sales.mdf", 8192), ("Sales_log.ldf", 2048),
                       ("Sales_2.ndf", 4096), ("Orphan.ldf", 512)):
        (d / name).write_bytes(b"\0" * size)
    (d / "readme.txt").write_text("not data")
    return d


def test_mssql_summary_pairs_logs_and_reads_the_instance(fixture_dir):
    d = make_mssql(fixture_dir)
    for p in d.iterdir():
        _age(p, time.time() - 7200)
    _age(d / "Sales_log.ldf", time.time())
    s = mssql.ENGINE.summarize(str(d), set(os.listdir(d)))
    assert s["instance"] == {"folder": "MSSQL16.MSSQLSERVER", "major": 16, "release": "2022",
                             "name": "MSSQLSERVER"}
    assert s["version"] == "2022"
    by = {x["name"]: x for x in s["databases"]}
    assert set(by) == {"master", "msdb", "Sales"} and by["master"]["system"]
    assert by["master"]["log"]["file"] == "mastlog.ldf"
    assert by["Sales"]["log"]["file"] == "Sales_log.ldf" and not by["Sales"]["log"]["quiet"]
    assert by["Sales"]["data"]["quiet"]
    assert [x["file"] for x in by["Sales"]["secondary"]] == ["Sales_2.ndf"]
    assert [x["file"] for x in s["unmatched"]] == ["Orphan.ldf"]
    assert s["files"] == 8 and not s["quiet"]


def test_mssql_instance_names():
    assert mssql.instance(r"C:\Program Files\Microsoft SQL Server\MSSQL10_50.SQLEXPRESS\MSSQL\DATA")[
        "release"] == "2008 R2"
    assert mssql.instance(r"D:\db") is None
    assert mssql.instance(r"C:\Program Files\Microsoft SQL Server\170\LocalDB\Binn\Templates") == {
        "folder": "170", "major": 17, "release": "2025"}


def test_alcohol_disc_images_are_not_sql_server(fixture_dir):
    assert dbfiles.detect("i", "i", {"Game.mdf", "Game.mds"}) is None
    store = dbfiles.detect("i", "i", {"Game.mdf", "Game.mds", "app.mdf"})
    assert store.format.opaque("app.mdf") and not store.format.opaque("Game.mdf")


def test_mssql_one_hour_rule_and_in_use(fixture_dir):
    d = make_mssql(fixture_dir)
    for p in d.iterdir():
        _age(p, time.time() - 7200)
    _age(d / "Sales.mdf", time.time() - 60)       # written a minute ago

    def measure(root, rel_path, abs_path, st, options, identifier):
        doc = _measure_stub(root, rel_path, abs_path, st, options, identifier)
        if rel_path.endswith("master.mdf"):     # held open by a running server
            doc.pop("sha256")
            doc["kind"] = "unknown"
            record.add_error(doc, "hash", PermissionError(32, "in use"))
            doc["errors"][-1]["message"] = "PermissionError: [WinError 32] The process cannot access the file"
        return doc

    _, docs, errors = _walk(fixture_dir, ScanOptions(measure_databases=True), measure)
    base = "MSSQL16.MSSQLSERVER/MSSQL/DATA/"
    assert docs[base + "Sales.mdf"]["kind"] == "data" and "sha256" not in docs[base + "Sales.mdf"]
    assert docs[base + "Sales_log.ldf"]["sha256"] == "x"
    master = docs[base + "master.mdf"]
    assert master["probe"] == {"db_data": "mssql", "db_in_use": True}
    assert "errors" not in master and master["kind"] == "data" and not errors
    assert docs[base.rstrip("/")]["probe"]["database"]["engine"] == "mssql"


# --- enrich -----------------------------------------------------------------------

def test_enrich_measures_only_quiet_listed_database_files(fixture_dir, monkeypatch):
    d = make_pg(fixture_dir)
    big = d / "base" / "16384" / "16385"
    _age(big)
    backend, docs, _ = _walk(fixture_dir)
    assert docs["pgdata/base/16384/16385"]["kind"] == "data"    # listed: no --measure-databases

    import filecat.scan
    calls = []

    def measure(root, rel_path, *a):
        calls.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    monkeypatch.setattr(filecat.scan, "measure_file", measure)
    stats = enrich(backend, ScanOptions(), stages={"hash", "probe"}, roots=[str(fixture_dir)],
                   kinds=["data"], force=True, identifier=_NoIdent())
    assert calls == ["pgdata/base/16384/16385"] and stats.measured == 1
    doc = backend.get(str(fixture_dir), "pgdata/base/16384/16385")
    assert doc["sha256"] == "x" and doc["probe"]["db_data"] == "postgres"


def test_enrich_skips_a_file_written_since_it_was_listed(fixture_dir, monkeypatch):
    d = make_pg(fixture_dir)
    big = d / "base" / "16384" / "16385"
    _age(big)
    backend, _, _ = _walk(fixture_dir)
    os.utime(big)       # written again after the scan
    import filecat.scan
    monkeypatch.setattr(filecat.scan, "measure_file", lambda *a: (_ for _ in ()).throw(AssertionError))
    stats = enrich(backend, ScanOptions(), stages={"hash"}, roots=[str(fixture_dir)],
                   kinds=["data"], identifier=_NoIdent())
    assert stats.db_active == 1 and stats.measured == 0


class _NoIdent:
    def by_name(self, *a):
        return None

    def close(self):
        pass


# --- filecat databases ---------------------------------------------------------------

def test_databases_command_lists_folders_and_copies(fixture_dir, capsys):
    make_pg(fixture_dir / "a")
    make_pg(fixture_dir / "b")
    make_mssql(fixture_dir)
    backend, _, _ = _walk(fixture_dir)
    found = list(databases_cmd.folders(backend))
    assert sorted(f["database"]["engine"] for f in found) == ["mssql", "postgres", "postgres"]
    assert list(databases_cmd.copies(found)) == ["pg:7300000000000000001"]
    for fo in found:
        databases_cmd._print_folder(fo)
    out = capsys.readouterr().out
    assert "[postgres]" in out and "SQL Server 2022" in out and "msdb (system)" in out


def test_backup_summary_has_no_database_keys():
    store = dbfiles.detect("x", "x", {"Sales.mdf"})
    assert store.probe_key == "database" and store.data_key == "db_data"
    s = summarize(store, os.path.join(tempfile.gettempdir(), "nope-" + uuid.uuid4().hex), {"Sales.mdf"})
    assert "copy_keys" not in s and s["engine"] == "mssql"
