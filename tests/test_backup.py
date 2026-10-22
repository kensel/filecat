from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid

from filecat import backups_cmd, record
from filecat.backends.memory import MemoryBackend
from filecat.backup import abb, detect, duplicity, summarize, windows
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import walk_root

GiB = 1024 ** 3


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


# --- Synology Active Backup for Business ---------------------------------

def make_abb(base, *, task="PC-HOST1-Default", version_uuids=("u1", "u2"), device_uuid="DEV-1"):
    """An @ActiveBackup store with one task and two versions: the first
    complete, the second failed part way (C: suspended, D: never sent)."""
    store = base / "@ActiveBackup"
    data = store / "@data"
    (data / "Pool" / "0" / "1").mkdir(parents=True)
    (data / "Pool" / "0" / "1" / "1.buk").write_bytes(b"chunk" * 100)
    (data / "repo_size").write_bytes(b"sIze\x00\x01junk" + b"[600,0,250]")
    (store / "storage_info.json").write_text('{"db_serial": "install-1", "version": [0, 2]}')
    (store / "storage.cache").write_text(json.dumps({"size": {task: [1100, 7]}}))
    v1, v2 = "ActiveBackup_2026-10-15_030001", "ActiveBackup_2026-10-16_030001"
    _db(str(data / "file_map.db"), "CREATE TABLE file_map (path TEXT PRIMARY KEY, size INTEGER);",
        [("INSERT INTO file_map VALUES (?, ?)", [
            (f"{task}/{v1}/1.img", 128), (f"{task}/{v1}/2.img", 1000),
            (f"{task}/{v2}/1.img.suspend", 25)])])
    t = store / task
    for v in (v1, v2):
        (t / v).mkdir(parents=True)
        (t / v / "device_spec").write_bytes(b"x" * 42)
    (t / v1 / "1.img.delta").write_bytes(b"d" * 10)
    (t / "ActiveBackup_2026-10-17_030001").mkdir()     # not in target.db
    (t / "config.json").write_text(json.dumps({
        "device_table": [{"host_name": "HOST1", "os_name": "Windows 11(64-bit)",
                          "device_uuid": device_uuid, "agent_token": "secret"}],
        "task_table": [{"task_name": "Default", "unikey": f"task-{task}", "enable_dedup": True,
                        "enable_compress_transfer": True, "retention_policy": {"keep_all": True}}]}))
    mount = json.dumps({"C:": {"image_path": "1.img"}, "D:": {"image_path": "2.img"}})
    _db(str(t / "target.db"), """
        CREATE TABLE version_table (version_id INTEGER, status INTEGER, folder_name TEXT,
            time_start INTEGER, time_end INTEGER, version_uuid TEXT, full_backup INTEGER);
        CREATE TABLE object_table (object_id INTEGER, version_id INTEGER, file_path TEXT,
            dedup_object BOOLEAN, file_size INTEGER, object_meta TEXT);
        CREATE TABLE device_table (version_id INTEGER, host_name TEXT, os_name TEXT, mount_map TEXT);
    """, [
        ("INSERT INTO version_table VALUES (?,?,?,?,?,?,?)", [
            (1, 5, v1, 1792054803, 1792073966, version_uuids[0], 1),
            (2, 4, v2, 1792141203, 1792141829, version_uuids[1], 2)]),
        ("INSERT INTO object_table VALUES (?,?,?,?,?,?)", [
            (1, 1, f"{v1}/1.img", 1, 128, '{"capacity": 128, "trans_size": 100}'),
            (2, 1, f"{v1}/2.img", 1, 1000, '{"capacity": 1000, "trans_size": 900}'),
            (3, 1, f"{v1}/1.img.delta", 0, 10, "null"),
            (4, 1, f"{v1}/device_spec", 0, 42, "null"),
            (5, 2, f"{v2}/1.img", 1, 25, '{"capacity": 128, "trans_size": 20}'),
            (6, 2, f"{v2}/2.img", 1, 1000, '{"capacity": 1000}'),
            (7, 2, f"{v2}/2.img.delta", 0, 0, "null"),          # empty: never written
            (8, 2, f"{v2}/device_spec", 0, 40, "null")]),        # 42 on disk
        ("INSERT INTO device_table VALUES (?,?,?,?)", [
            (1, "HOST1", "Windows 11(64-bit)", mount), (2, "HOST1", "Windows 11(64-bit)", mount)]),
    ])
    return store


def test_abb_summary_storage_versions_and_problems(fixture_dir):
    store = make_abb(fixture_dir)
    names = set(os.listdir(store))
    st = detect("@ActiveBackup", "@ActiveBackup", names)
    assert st is not None and st.format is abb.FORMAT
    b = summarize(st, str(store), names)

    assert b["install_id"] == "install-1"
    assert b["storage"] == {"backed_up_bytes": 1100, "usage_bytes": 600, "compression_saved_bytes": 250,
                            "dedup_saved_bytes": 250, "reduction_ratio": 1.83}
    task = b["tasks"][0]
    assert task["machine"] == "HOST1" and task["task"] == "Default"
    assert "agent_token" not in json.dumps(b)
    v1, v2 = task["versions"]
    assert v1["status"] == "succeeded" and v1["problems"] == []
    assert v1["start"] == "2026-10-15T09:00:03+00:00"
    assert [(x["mount"], x["capacity"]) for x in v1["volumes"]] == [("C:", 128), ("D:", 1000)]
    assert v1["transferred_bytes"] == 1000
    assert v2["status"] == "failed"
    assert v2["problems"] == ["backup failed", "1.img (C:): stopped at 25 of 128 bytes",
                              "2.img (D:): not in the pool",
                              "device_spec: 42 bytes on disk, manifest 40"]
    assert "PC-HOST1-Default: ActiveBackup_2026-10-17_030001: folder not in target.db" in b["problems"]
    assert b["machines"] == ["HOST1"] and b["versions"] == 2
    assert b["copy_keys"] == ["abb-version:u1", "abb-version:u2"]
    assert b["machine_keys"] == ["device:DEV-1", "host:host1"]


def test_abb_opaque_is_the_pool_only():
    st = detect("x/@ActiveBackup", "@ActiveBackup", {"@data", "storage_info.json"})
    assert st.opaque("x/@ActiveBackup/@data/Pool/0/1/1.buk")
    assert st.opaque("x/@ActiveBackup/@data/sample.index")
    assert not st.opaque("x/@ActiveBackup/PC-A/target.db")
    assert not st.opaque("y/@ActiveBackup/@data/Pool/0/1/1.buk")
    assert detect("@ActiveBackup", "@ActiveBackup", {"@data"}) is None


# --- walker ---------------------------------------------------------------

def test_walker_lists_backup_data_without_reading_and_summarizes_the_store(fixture_dir):
    make_abb(fixture_dir)
    (fixture_dir / "notes.txt").write_text("ordinary")
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, None, _resume(), measure)
    docs = {d["rel_path"]: d for d in backend.list(root=str(fixture_dir))}

    buk = docs["@ActiveBackup/@data/Pool/0/1/1.buk"]
    assert buk["kind"] == "data" and buk["size"] == 500
    assert buk["probe"] == {"backup_data": "synology-abb"}
    assert not any(r.startswith("@ActiveBackup/@data/") for r in measured)
    assert "notes.txt" in measured
    assert "@ActiveBackup/PC-HOST1-Default/config.json" in measured
    b = docs["@ActiveBackup"]["probe"]["backup"]
    assert b["format"] == "synology-abb" and b["versions"] == 2
    assert docs["@ActiveBackup"]["probe"]["child_count"] == 4


def test_walker_measure_backups_reads_them(fixture_dir):
    make_abb(fixture_dir)
    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(measure_backups=True), backend, None, _resume(), _measure_stub)
    assert backend.get(str(fixture_dir), "@ActiveBackup/@data/Pool/0/1/1.buk")["kind"] == "text"
    assert backend.get(str(fixture_dir), "@ActiveBackup")["probe"]["backup"]["versions"] == 2


def test_walker_records_a_broken_manifest_as_an_error(fixture_dir, monkeypatch):
    make_abb(fixture_dir)

    def boom(*a):
        raise ValueError("bad manifest")

    monkeypatch.setattr(abb.FORMAT, "summarize", boom)
    backend = MemoryBackend()
    had_errors = walk_root(str(fixture_dir), ScanOptions(), backend, None, _resume(), _measure_stub)
    doc = backend.get(str(fixture_dir), "@ActiveBackup")
    assert had_errors
    assert doc["errors"] == [{"stage": "backup", "message": "ValueError: bad manifest"}]


# --- Windows Backup and Restore / WindowsImageBackup -------------------------

def test_windows_file_backup_gaps_and_catalogs(fixture_dir):
    pc = fixture_dir / "HOMEPC"
    full = pc / "Backup Set 2009-05-21 123957" / "Backup Files 2009-05-21 123957"
    inc = pc / "Backup Set 2009-05-21 123957" / "Backup Files 2009-06-12 212930"
    (full / "Catalogs").mkdir(parents=True)
    (inc / "Catalogs").mkdir(parents=True)
    (pc / "Backup Set 2009-05-21 123957" / "Catalogs").mkdir()
    (pc / "Backup Set 2009-05-21 123957" / "Catalogs" / "GlobalCatalog.wbcat").write_bytes(b"c")
    (pc / "MediaID.bin").write_bytes(bytes(range(16)))
    for n in (1, 2, 4):
        (full / f"Backup files {n}.zip").write_bytes(b"z" * n)
    for n in (1, 2, 3, 4, 5):                       # 5 has a catalog but no zip
        (full / "Catalogs" / f"Backup files {n}.wbcat").write_bytes(b"c")
    (inc / "Backup files 1.zip").write_bytes(b"z")  # no per-zip catalogs at all

    names = set(os.listdir(pc))
    st = detect("HOMEPC", "HOMEPC", names)
    assert st.format is windows.FILE_BACKUP
    assert st.opaque("HOMEPC/Backup Set 2009-05-21 123957/Backup Files 2009-05-21 123957/Backup files 1.zip")
    assert st.opaque("HOMEPC/Backup Set 2009-05-21 123957/Backup Files 2009-05-21 123957/Catalogs/Backup files 1.wbverify")
    assert not st.opaque("HOMEPC/MediaID.bin")
    b = summarize(st, str(pc), names)
    assert b["machines"] == ["HOMEPC"] and b["media_id"] == bytes(range(16)).hex()
    assert b["versions"] == 2 and b["latest"] == "2009-06-12T21:29:30"
    assert b["sets"][0]["parts"][0] == {"folder": "Backup Files 2009-05-21 123957",
                                        "time": "2009-05-21T12:39:57", "zips": 3, "bytes": 7,
                                        "missing_zips": [3, 5]}
    assert b["problems"] == ["Backup Set 2009-05-21 123957/Backup Files 2009-05-21 123957: "
                             "missing Backup files 3, 5.zip"]


def test_windows_image_backup(fixture_dir):
    pc = fixture_dir / "WindowsImageBackup" / "Homepc"
    ver = pc / "Backup 2009-06-13 010936"
    ver.mkdir(parents=True)
    (pc / "Catalog").mkdir()
    (pc / "MediaId").write_bytes(b"\x01" * 16)
    (ver / "disk-guid.vhd").write_bytes(b"v" * 64)
    xml = ('<BACKUP_COMPONENTS><BACKUP_METADATA metadata="&lt;System MachineName=&quot;HOMEPC&quot; '
           'OSVersion=&quot;6.0&quot;/&gt;"/></BACKUP_COMPONENTS>')
    (ver / "b7b4_Components.xml").write_bytes(xml.encode("utf-16-le"))
    (pc / "Backup 2009-07-01 010000").mkdir()      # no disk image

    names = set(os.listdir(pc))
    st = detect("WindowsImageBackup/Homepc", "Homepc", names)
    assert st.format is windows.IMAGE_BACKUP
    assert st.opaque("WindowsImageBackup/Homepc/Backup 2009-06-13 010936/disk-guid.vhd")
    assert not st.opaque("WindowsImageBackup/Homepc/Backup 2009-06-13 010936/b7b4_Components.xml")
    b = summarize(st, str(pc), names)
    assert b["machines"] == ["HOMEPC"]
    img = b["images"][0]
    assert (img["machine"], img["os_version"], img["bytes"]) == ("HOMEPC", "6.0", 64)
    assert b["problems"] == ["Backup 2009-07-01 010000: no .vhd/.vhdx disk image"]
    assert b["machine_keys"] == ["host:homepc"]


# --- duplicity ------------------------------------------------------------

MANIFEST = """Hostname myhost
Localdir "/home/me"
Volume 1:
    StartingPath   .
    EndingPath     "docs/a file" 3
    Hash SHA1 4f0b
Volume 2:
    StartingPath   "docs/a file" 4
    EndingPath     zz
    Hash SHA1 9a9a
Filelist 1
    new  docs/a file
"""


def test_duplicity_chains_volumes_and_signatures(fixture_dir):
    d = fixture_dir / "dup"
    d.mkdir()
    T1, T2, T3, T9 = "20240101T020000Z", "20240102T020000Z", "20240103T020000Z", "20240109T020000Z"
    files = {
        f"duplicity-full.{T1}.manifest": MANIFEST,
        f"duplicity-full.{T1}.vol1.difftar.gz": "v",          # vol2 missing
        f"duplicity-full-signatures.{T1}.sigtar.gz": "s",
        f"duplicity-inc.{T1}.to.{T2}.manifest.gpg": "m",
        f"duplicity-inc.{T1}.to.{T2}.vol1.difftar.gpg": "v",
        f"duplicity-new-signatures.{T1}.to.{T2}.sigtar.gpg": "s",
        f"duplicity-inc.{T2}.to.{T3}.vol1.difftar.gz": "v",    # no manifest, no signatures
        f"duplicity-inc.{T9}.to.20240110T020000Z.manifest": "",  # continues nothing
        "readme.txt": "x",
    }
    for name, text in files.items():
        (d / name).write_text(text)
    names = set(os.listdir(d))
    st = detect("dup", "dup", names)
    assert st.format is duplicity.FORMAT
    assert st.opaque(f"dup/duplicity-full.{T1}.vol1.difftar.gz")
    assert st.opaque(f"dup/duplicity-full-signatures.{T1}.sigtar.gz")
    assert not st.opaque(f"dup/duplicity-full.{T1}.manifest")
    assert not st.opaque("dup/readme.txt")

    b = summarize(st, str(d), names)
    assert b["machines"] == ["myhost"]
    assert b["chains"] == [{"start": "2024-01-01T02:00:00+00:00", "end": "2024-01-03T02:00:00+00:00", "sets": 3}]
    full = b["sets"][0]
    assert (full["hostname"], full["localdir"], full["manifest_volumes"]) == ("myhost", "/home/me", 2)
    assert b["sets"][1]["encrypted"] is True
    assert b["problems"] == [
        f"full {T1}: volumes 2 listed in the manifest are missing",
        f"inc {T2} to {T3}: no manifest (the set did not finish)",
        f"inc {T2} to {T3}: signatures missing",
        f"inc {T9} to 20240110T020000Z: no volumes",
        f"inc {T9} to 20240110T020000Z: signatures missing",
        f"inc {T9} to 20240110T020000Z: does not continue any chain",
    ]


def test_read_manifest_unquotes():
    m = duplicity.read_manifest(MANIFEST)
    assert m == {"hostname": "myhost", "localdir": "/home/me", "volumes": {1: "sha1:4f0b", 2: "sha1:9a9a"}}


# --- filecat backups ---------------------------------------------------------

def test_backups_groups_copies_and_separate_jobs(fixture_dir):
    a, b, c = (fixture_dir / n for n in ("shareA", "shareB", "shareC"))
    for p in (a, b, c):
        p.mkdir()
    make_abb(a)
    make_abb(b / "old-copy")                              # same version UUIDs: a copy
    make_abb(c, task="PC-HOST1-Task-1", version_uuids=("u7", "u8"))  # same device, other job
    backend = MemoryBackend()
    for p in (a, b, c):
        walk_root(str(p), ScanOptions(), backend, None, _resume(), _measure_stub)

    found = list(backups_cmd.stores(backend))
    assert len(found) == 3
    copies, jobs = backups_cmd.groups(found)
    pa = os.path.join(str(a), "@ActiveBackup")
    pb = os.path.join(str(b), "old-copy", "@ActiveBackup")
    pc = os.path.join(str(c), "@ActiveBackup")
    assert copies == [sorted([pa, pb])]
    assert jobs == {"device:DEV-1": sorted([pa, pb, pc])}


def test_backups_command_prints_stores(fixture_dir, capsys, monkeypatch):
    make_abb(fixture_dir)
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
    assert "[synology-abb]  5 problems" in out
    assert "storage   backed up 1.1 KB, stored 600 B (dedup saved 250 B, compression saved 250 B), 1.83x" in out
    assert "HOST1  task Default" in out
    assert "failed" in out and "! PC-HOST1-Default: ActiveBackup_2026-10-16_030001: backup failed" in out


def test_abb_virtual_view_is_recorded_not_walked(fixture_dir):
    make_abb(fixture_dir)
    view = fixture_dir / "ActiveBackupData" / "PC-HOST1-Default" / "ActiveBackup_2026-10-15_030001"
    view.mkdir(parents=True)
    (view / "1.img").write_bytes(b"i" * 128)
    root = str(fixture_dir)
    backend = MemoryBackend()
    # what a scan before this feature left behind
    backend.put(record.new_document(root, "ActiveBackupData/PC-HOST1-Default", kind="dir"))
    backend.put(record.new_document(root, "ActiveBackupData", kind="dir"))
    walk_root(root, ScanOptions(), backend, None, _resume(), _measure_stub)

    docs = {d["rel_path"]: d for d in backend.list(root=root)}
    assert not any(r.startswith("ActiveBackupData/") for r in docs)
    d = docs["ActiveBackupData"]
    assert d["probe"]["child_count"] == 0
    assert d["probe"]["backup"] == {
        "format": "synology-abb-view", "virtual": True, "tasks": ["PC-HOST1-Default"],
        "versions": 1, "apparent_bytes": 128, "problems": [], "copy_keys": [], "machine_keys": [],
        "note": "virtual images of the @ActiveBackup versions; not walked, not disk space"}

    backend2 = MemoryBackend()
    walk_root(root, ScanOptions(measure_backups=True), backend2, None, _resume(), _measure_stub)
    assert backend2.get(root, "ActiveBackupData/PC-HOST1-Default/ActiveBackup_2026-10-15_030001/1.img")
