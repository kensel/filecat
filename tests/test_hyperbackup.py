from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid
import zlib

from filecat import backups_cmd, record
from filecat.backends.memory import MemoryBackend
from filecat.backup import detect, hyperbackup, summarize
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import walk_root

UNIKEY = "9009D0261C0A_18_1710456389"


def _resume():
    return ResumeState(os.path.join(tempfile.gettempdir(), f"filecat-test-resume-{uuid.uuid4().hex}.json"))


def _measure_stub(root, rel_path, abs_path, st, options, identifier):
    return record.new_document(root, rel_path, kind="text", size=st.st_size,
                               mtime_ns=st.st_mtime_ns, ctime_ns=st.st_mtime_ns)


def _db(path, script, rows):
    conn = sqlite3.connect(path)
    conn.executescript(script)
    for sql, values in rows:
        conn.executemany(sql, values)
    conn.commit()
    conn.close()


def _stats(total, files, new=1, mod=2, dele=0):
    part = {"total_size": total, "total_cnt": files, "new_cnt": new, "mod_cnt": mod, "del_cnt": dele}
    return json.dumps({"compress_size": 77, "summary": {
        "share": part, "app": {"total_size": 10, "total_cnt": 1}, "ea": {"total_size": 5, "total_cnt": 9}}})


def make_hbk(base, name="NAS-LEGACY_1.hbk", *, unikey=UNIKEY, host="NAS-LEGACY"):
    """A Hyper Backup target with three versions (the second failed) and a
    Guard manifest of two buckets, one share database and one change log."""
    store = base / name
    for d in ("Config/@Share/Z", "Control", "Guard/detect", "Pool/0/1", "Versionlog"):
        (store / d).mkdir(parents=True)
    (store / "SynologyHyperBackup.bkpi").write_bytes(b"")
    (store / "_Syno_TaskConfig").write_text("\n".join([
        "[task_config]",
        'backup_apps=["HyperBackup"]',
        'backup_folders=["/Z","/homes"]',
        'compatible_info={"source_hb_version":"4.2.1-4228","source_product":"DSM"}',
        "create_time=1710456389",
        "data_compress_type=1",
        "enable_data_encrypt=false",
        f'host_name="{host}"',
        'incheck_info="{\\"data_enable\\":true}\\n"',
        'ip="192.0.2.141"',
        'name="Synology NAS 1"',
        'rotate_option="rotate_smart_recycle"',
        'source_model="DS1823xs+"',
        f'unikey="{unikey}"', ""]))
    (store / "last_status.conf").write_text(
        '[last_backup]\naction="idle"\nend=1792314985\nstart=1792314321\nversion=["3"]\n')
    _db(str(store / "storage_statistics.db"),
        "CREATE TABLE target_table (start_time INTEGER, end_time INTEGER, action_type INTEGER,"
        " target_size INTEGER, version_id INTEGER, PRIMARY KEY (end_time));",
        [("INSERT INTO target_table VALUES (?,?,?,?,?)", [(1, 2, 1, 1, 1), (3, 4, 1, 2, 3)])])
    _db(str(store / "Config" / "version_info.db"),
        "CREATE TABLE version_info (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, name TEXT,"
        " source TEXT, share TEXT, status TEXT, statistics TEXT, locked INTEGER NOT NULL default 0,"
        " suspend_history TEXT DEFAULT '');",
        [("INSERT INTO version_info (id, timestamp, name, share, status, statistics, locked, suspend_history)"
          " VALUES (?,?,?,?,?,?,?,?)", [
              (1, 1792141215, "my_ver", "Z,homes,", "Complete", _stats(4000, 30), 1,
               json.dumps([{"event_desc": "create", "server_time": 1792141215},
                           {"event_desc": "complete", "server_time": 1792142280}])),
              (2, 1792227616, "my_ver", "Z,homes,", "Failure", None, 0, "[]"),
              (3, 1792314021, "my_ver", "Z,homes,", "Complete", _stats(4096, 31), 0, "[]")])])
    (store / "Config" / "@Share" / "Z" / "3.db").write_bytes(b"s" * 64)
    (store / "Config" / "version_info.db_dup").write_bytes((store / "Config" / "version_info.db").read_bytes())
    (store / "Pool" / "0" / "1" / "5.bucket").write_bytes(b"b" * 300)   # bucket 2053
    (store / "Pool" / "0" / "1" / "5.index").write_bytes(b"i" * 30)
    (store / "Pool" / "0" / "1" / "5.lock").write_bytes(b"")
    (store / "Pool" / "0" / "1" / "6.bucket").write_bytes(b"b" * 299)   # manifest says 300
    (store / "Versionlog" / "log_3.zip").write_bytes(b"PK" + b"z" * 8)
    file_info = ("CREATE TABLE file_info (type INTEGER NOT NULL, name TEXT, idx INTEGER, mtime INTEGER,"
                 " size INTEGER, crc BLOB, status INTEGER, check_status INTEGER, mtime_nsec INTEGER);")
    insert = "INSERT INTO file_info (type, name, idx, size, status) VALUES (?,?,?,?,?)"
    _db(str(store / "Guard" / "local_bucket.db"), file_info, [(insert, [
        (7, "", 2053, 300, 1), (6, "", 2053, 30, 1), (7, "", 2054, 300, 1), (6, "", 2054, 30, 1)])])
    _db(str(store / "Guard" / "local_file.db"), file_info, [(insert, [
        (2, "Z", 3, 64, 1), (10, "", 3, 10, 1), (9, "1", 5000, 12, 1), (99, "", 0, 1, 1)])])
    (store / "Guard" / "config.json").write_text('{"state": "committed", "version": 1}')
    (store / "Guard" / "detect.prog").write_text(
        '[progress]\ndata_end="{\\"checked_size\\":100,\\"total_checked_size\\":300,\\"total_size\\":900}\\n"\n'
        "end_time=1792342740\nerror_code=0\nlaunch_time=1792321213\npercent=100\nresult=5\n")
    (store / "Guard" / "detect" / "error.log").write_text(
        "Error Detect Start: Sun Oct 18 04:00:17 2026\n\nbucket 2054: chunk crc mismatch\n\n"
        "Error Detect Finish: Sun Oct 18 09:59:00 2026\n")
    return store


def test_hyperbackup_is_detected_and_its_subfolders_are_listed_only():
    st = detect("x/NAS-LEGACY_1.hbk", "NAS-LEGACY_1.hbk", {"Config", "Pool", "Guard", "_Syno_TaskConfig"})
    assert st is not None and st.format is hyperbackup.FORMAT
    assert st.opaque("x/NAS-LEGACY_1.hbk/Pool/0/1/5.bucket")
    assert st.opaque("x/NAS-LEGACY_1.hbk/Config/@cand_file/27/112960_1.cand_dup")
    assert not st.opaque("x/NAS-LEGACY_1.hbk/_Syno_TaskConfig")
    assert detect("t", "target", {"SynologyHyperBackup.bkpi"}).format is hyperbackup.FORMAT
    assert detect("p", "photos.hbk", {"Config"}) is None
    assert detect("p", "Projects", {"Config", "Pool"}) is None


def test_hyperbackup_summary(fixture_dir):
    store = make_hbk(fixture_dir)
    names = set(os.listdir(store))
    b = summarize(detect("NAS-LEGACY_1.hbk", "NAS-LEGACY_1.hbk", names), str(store), names)

    assert b["format"] == "synology-hyperbackup"
    assert (b["task"], b["source_host"], b["source_model"]) == ("Synology NAS 1", "NAS-LEGACY", "DS1823xs+")
    assert b["folders"] == ["/Z", "/homes"] and b["apps"] == ["HyperBackup"]
    assert b["encrypted"] is False and b["compressed"] is True
    assert b["hyper_backup_version"] == "4.2.1-4228"
    assert b["machines"] == ["NAS-LEGACY"] and b["versions"] == 3
    v1, v2, v3 = b["version_list"]
    assert v1 == {"id": 1, "start": "2026-10-16T09:00:15+00:00", "end": "2026-10-16T09:18:00+00:00",
                  "status": "Complete", "locked": True, "shares": ["Z", "homes"], "source_bytes": 4010,
                  "files": 31, "new": 1, "modified": 2, "deleted": 0, "stored_new_bytes": 77}
    assert v2["status"] == "Failure" and "source_bytes" not in v2
    assert b["latest"] == v3["start"] and b["latest_complete"] == v3["start"]
    assert b["last_backup"]["version"] == "3"
    assert b["storage"] == {"source_bytes": 4106, "target_bytes": 2048, "stored_bytes": 2 * 300 + 2 * 30 + 64 + 10 + 12,
                            "reduction_ratio": 2.0}
    assert b["guard"] == {"files": 7, "unknown_entries": 1, "state": "committed", "missing": 2, "size_mismatch": 1}
    assert b["integrity_check"]["checked_bytes"] == 100
    assert b["integrity_check"]["errors"] == ["bucket 2054: chunk crc mismatch"]
    assert b["problems"] == [
        "version 2 (2026-10-17 09:00): Failure",
        "2 of 7 files in Guard's manifest are missing, e.g. Config/@cand_file/1/5000_1.cand, "
        "Pool/0/1/6.index",
        "1 files differ in size from Guard's manifest, e.g. Pool/0/1/6.bucket (299 bytes, manifest 300)",
        "integrity check: bucket 2054: chunk crc mismatch"]
    assert b["copy_keys"] == [f"hyperbackup:{UNIKEY}:1", f"hyperbackup:{UNIKEY}:3"]
    assert b["machine_keys"] == ["host:nas-legacy", "synology:9009d0261c0a"]


def test_verify_backups_checks_guard_crc32_and_only_then(fixture_dir):
    store = make_hbk(fixture_dir)
    good = zlib.crc32((store / "Pool" / "0" / "1" / "5.bucket").read_bytes()).to_bytes(4, "big")
    conn = sqlite3.connect(str(store / "Guard" / "local_bucket.db"))
    conn.execute("UPDATE file_info SET crc=? WHERE type=7 AND idx=2053", (good,))
    conn.execute("UPDATE file_info SET crc=? WHERE type=6 AND idx=2053", (b"\0\0\0\1",))
    conn.commit()
    conn.close()
    names = set(os.listdir(store))
    st = detect("", store.name, names)

    assert "crc_checked" not in summarize(st, str(store), names)["guard"]
    b = summarize(st, str(store), names, verify=True)
    assert {k: b["guard"][k] for k in ("crc_checked", "crc_mismatch", "crc_unreadable")} == \
        {"crc_checked": 2, "crc_mismatch": 1, "crc_unreadable": 0}
    assert "1 files do not match Guard's CRC32, e.g. Pool/0/1/5.index" in b["problems"]


def test_hyperbackup_reads_the_dup_copy_of_a_broken_database(fixture_dir):
    store = make_hbk(fixture_dir)
    (store / "Config" / "version_info.db").write_bytes(b"not a database" * 100)
    names = set(os.listdir(store))
    b = summarize(detect("", store.name, names), str(store), names)
    assert b["versions"] == 3


def test_walker_lists_the_target_and_checks_guard_against_its_own_listing(fixture_dir, monkeypatch):
    make_hbk(fixture_dir / "Backup")
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    def no_second_listing(path):
        raise AssertionError("the store was listed again")

    monkeypatch.setattr(hyperbackup, "_os_listing", no_second_listing)
    backend = MemoryBackend()
    root = str(fixture_dir)
    walk_root(root, ScanOptions(), backend, None, _resume(), measure)
    docs = {d["rel_path"]: d for d in backend.list(root=root)}

    bucket = docs["Backup/NAS-LEGACY_1.hbk/Pool/0/1/5.bucket"]
    assert bucket["kind"] == "data" and bucket["probe"] == {"backup_data": "synology-hyperbackup"}
    assert not any("/Pool/" in r or "/Config/" in r or "/Guard/" in r for r in measured)
    assert "Backup/NAS-LEGACY_1.hbk/_Syno_TaskConfig" in measured
    b = docs["Backup/NAS-LEGACY_1.hbk"]["probe"]["backup"]
    assert b["guard"]["missing"] == 2 and b["guard"]["size_mismatch"] == 1


def test_backups_command_prints_a_hyperbackup_target(fixture_dir, capsys, monkeypatch):
    make_hbk(fixture_dir)
    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, None, _resume(), _measure_stub)
    monkeypatch.setattr(backups_cmd, "open_backend", lambda *a: backend)
    monkeypatch.setattr(backend, "close", lambda: None)

    class Args:
        backend = out = dsn = root = None
        versions = True
        json = False

    assert backups_cmd.run(Args()) == 0
    out = capsys.readouterr().out
    assert "[synology-hyperbackup]  4 problems" in out
    assert "task      Synology NAS 1 from NAS-LEGACY (DS1823xs+): /Z, /homes + 1 apps" in out
    assert "guard     7 files in the manifest, 2 missing, 1 differ in size  (committed)" in out
    assert "#2     Failure" in out and "locked" in out


def test_two_targets_of_one_nas_are_separate_jobs_and_a_copy_is_a_copy(fixture_dir):
    make_hbk(fixture_dir / "a")
    make_hbk(fixture_dir / "b" / "old")
    make_hbk(fixture_dir / "c", "NAS-LEGACY_2.hbk", unikey="9009D0261C0A_19_1720000000")
    backend = MemoryBackend()
    for sub in ("a", "b", "c"):
        walk_root(str(fixture_dir / sub), ScanOptions(), backend, None, _resume(), _measure_stub)
    copies, jobs = backups_cmd.groups(list(backups_cmd.stores(backend)))
    pa = os.path.join(str(fixture_dir / "a"), "NAS-LEGACY_1.hbk")
    pb = os.path.join(str(fixture_dir / "b"), "old", "NAS-LEGACY_1.hbk")
    pc = os.path.join(str(fixture_dir / "c"), "NAS-LEGACY_2.hbk")
    assert copies == [sorted([pa, pb])]
    assert jobs["host:nas-legacy"] == sorted([pa, pb, pc])
