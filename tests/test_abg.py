from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import uuid

import pytest

from filecat import backups_cmd, record
from filecat.backends.memory import MemoryBackend
from filecat.backup import abg, detect, summarize
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import walk_root

DB = "@ActiveBackupGSuite-Databases"
FOREVER = 4294967295
ANN, BOB = "1001", "1002"


def _resume():
    return ResumeState(os.path.join(tempfile.gettempdir(), f"filecat-test-resume-{uuid.uuid4().hex}.json"))


def _measure_stub(root, rel_path, abs_path, st, options, identifier):
    return record.new_document(root, rel_path, kind="text", size=st.st_size,
                               mtime_ns=st.st_mtime_ns, ctime_ns=st.st_mtime_ns)


def _db(path, script, rows=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(script)
    for sql, values in rows:
        conn.executemany(sql, values)
    conn.commit()
    conn.close()


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def _mail(user, mid, bucket, attachments=(), meta=True, skel=True, att_size=None):
    folder = user / "Mail" / bucket[:2] / bucket[2:] / mid
    content = [{"fragment_id": "ID-skel", "path_postfix": "SKEL", "type": 0}]
    if skel:
        _write(folder / "v1-1-SKEL", f"Subject: {mid}\n\nbody\n")
    for n, data in enumerate(attachments):
        _write(folder / f"v1-{n + 2}-ATT_{n}", data)
        content.append({"path_postfix": f"ATT_{n}", "size": att_size or len(data),
                        "hash": hashlib.md5(data).hexdigest(), "type": 4})
    if meta:
        _write(folder / f"v1-{len(content) + 1}-META",
               json.dumps({"content_list": content, "version": "2.0"}))


def _drive_version(user, item, stamp, n, data, md5=None):
    vdir = user / "MyDrive" / "#SynoVersionRepo" / item / "#SynoVersions"
    _write(vdir / f"GMT-{stamp}-v{n}", data)
    _write(vdir / f"GMT-{stamp}-v{n}.metadata",
           json.dumps({"hash": md5 or hashlib.md5(data).hexdigest(), "is_dir": False, "size": str(len(data))}))
    _write(vdir / "cached_info", json.dumps({"latest_version": {"id": str(n)}, "version_count": n}))


def make_task(base, *, domain="example.org", created=1763188928):
    """A Google Workspace task with two users: ann (active, mail, calendar,
    contacts and Drive, with one of each kind of problem) and bob (removed
    from the domain, whose runs fail)."""
    task = base / "task_1"          # (under ActiveBackupForGoogleWorkspace/ on a real share)
    db = task / DB
    _db(db / "task-config.sqlite",
        "CREATE TABLE task_info_table (task_id INTEGER PRIMARY KEY, timestamp DATETIME, task_name TEXT,"
        " backup_policy INTEGER, schedule_id INTEGER, schedule_json TEXT, enable_schedule INTEGER,"
        " enable_dedup INTEGER, retention_policy INTEGER, retention_days INTEGER, enc_private_key TEXT,"
        " admin_unique_id TEXT, admin_primary_email TEXT, domain TEXT)",
        [("INSERT INTO task_info_table VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          [(1, created, "Example-free", 0, 9, "{}", 0, 0, 0, 30, "SECRETKEY", "9000", f"admin@{domain}", domain)])])
    _db(db / "account.sqlite",
        "CREATE TABLE user_info_table (row_id INTEGER PRIMARY KEY, timestamp DATETIME, user_id TEXT, name TEXT,"
        " email TEXT, department TEXT, account_status INTEGER, dsm_uid INTEGER, user_repo_name TEXT,"
        " local_used_storage INTEGER, drive_used_storage INTEGER, mail_used_storage INTEGER,"
        " contact_used_storage INTEGER, calendar_used_storage INTEGER, enable_drive INTEGER, enable_mail INTEGER,"
        " enable_contact INTEGER, enable_calendar INTEGER, root_folder_id TEXT, access_token TEXT,"
        " next_page_token TEXT)",
        [("INSERT INTO user_info_table VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          [(1, created, ANN, "Ann A", f"ann@{domain}", "", 1, 1024, f"ann@{domain}", 5000, 3000, 1900, 50, 50,
            1, 1, 1, 1, "root", "ya29.TOKEN", ""),
           (2, created, BOB, "Bob B", f"bob@{domain}", "", -2, 1025, f"bob@{domain}", 100, 0, 100, 0, 0,
            0, 0, 0, 0, "root", "ya29.TOKEN", "")])])
    _db(db / "service-log.sqlite",
        "CREATE TABLE service_log_table (row_id INTEGER PRIMARY KEY, task_execution_id INTEGER,"
        " execution_status INTEGER, error_code INTEGER, job_type INTEGER, service_type INTEGER,"
        " backup_policy INTEGER, start_run_time INTEGER, end_run_time INTEGER, timestamp DATETIME,"
        " user_id TEXT, item_success_count INTEGER, item_warning_count INTEGER, item_error_count INTEGER,"
        " transfered_size INTEGER)",
        [("INSERT INTO service_log_table VALUES (?,?,?,?,0,?,0,?,?,?,?,1,0,0,10)",
          [(1, 1, 1, 0, 1, 1790000000, 1790000060, 1790000060, ANN),
           (2, 1, 1, 0, 0, 1790000000, 1790000060, 1790000060, ANN),
           (3, 1, 1, 0, 1, 1790000000, 1790000060, 1790000060, BOB),
           (4, 2, 5, -2, 1, 1790600000, 1790600030, 1790600030, ANN),
           (5, 3, 6, -89, 1, 1790700000, 1790700030, 1790700030, BOB)])])
    _db(db / "mail-log.sqlite",
        "CREATE TABLE mail_log_table (row_id INTEGER PRIMARY KEY, timestamp DATETIME, task_execution_id INTEGER,"
        " task_id INTEGER, user_id TEXT, job_type INTEGER, log_status INTEGER, descript_string TEXT,"
        " error_code INTEGER)",
        [("INSERT INTO mail_log_table VALUES (?,?,?,1,?,0,?,?,?)",
          [(1, 1790600030, 2, ANN, 5, f"No mail data of user [ann@{domain}] was backed up. Connection failure", -2)])])
    _db(db / ANN / "mail.sqlite",
        "CREATE TABLE mail_table (row_id INTEGER PRIMARY KEY, mail_id TEXT, thread_id TEXT, sender TEXT,"
        " subject TEXT, snippet TEXT, has_attachments INTEGER, version_number INTEGER, remote_timestamp INTEGER,"
        " is_latest_version INTEGER, start_time INTEGER, end_time INTEGER)",
        [("INSERT INTO mail_table VALUES (NULL,?,?,'s','subj','snip',0,1,0,?,0,?)",
          [("m1", "m1", 1, FOREVER), ("m2", "m2", 1, FOREVER), ("m3", "m3", 0, 1790500000),
           ("m4", "m4", 1, FOREVER), ("m5", "m5", 1, FOREVER)]),
         ("UPDATE mail_table SET start_time = ? WHERE mail_id = ?", [(1790800000, "m5")])])  # m5: backed up after the listing
    cal_id, event = "c", "e" * 45                # the encoded name is 65 chars: cut into two folders
    _db(db / ANN / "calendar-event.sqlite",
        "CREATE TABLE calendar_event_table (row_id INTEGER PRIMARY KEY, event_id TEXT, calendar_id TEXT,"
        " version_number INTEGER, is_latest_version INTEGER, start_time INTEGER, end_time INTEGER)",
        [("INSERT INTO calendar_event_table VALUES (NULL,?,?,1,1,0,?)", [(event, cal_id, FOREVER)])])
    _db(db / ANN / "contact.sqlite",
        "CREATE TABLE contact_table (row_id INTEGER PRIMARY KEY, contact_id TEXT, version_number INTEGER,"
        " is_latest_version INTEGER, start_time INTEGER, end_time INTEGER)",
        [("INSERT INTO contact_table VALUES (NULL,?,1,1,0,?)",
          [("people/c1", FOREVER), ("people/c2", FOREVER)])])
    (db / "single-instancing.db").mkdir()
    _write(db / "single-instancing.db" / "CURRENT", "MANIFEST-000001\n")
    _write(db / ANN / "mail-content-search" / "_0.fdt", b"\0" * 10)

    ann = task / f"ann@{domain}"
    _mail(ann, "m1", "0A1B", attachments=[b"PNGDATA" * 10])     # whole
    _mail(ann, "m2", "0C2D", skel=False)                         # SKEL missing
    _mail(ann, "m3", "0E3F")                                     # deleted in Google, kept
    _mail(ann, "m4", "1A4B", meta=False)                         # META missing
    _mail(ann, "m9", "1C5D")                                     # not in mail.sqlite
    name = f"{_b64(cal_id)}-{_b64(event)}"
    _write(ann / "Calendar" / "01" / "2E" / name[:64] / name[64:] / "v1-1-META", "{}")
    _write(ann / "Contact" / "32" / "99" / _b64("people/c1") / "v1-1-META", "{}")
    # people/c2 has no folder
    _write(ann / "MyDrive" / "notes" / "a.txt", "alpha")
    _drive_version(ann, "notes/a.txt", "2026.09.23-21.29.52", 1, b"alpha")
    _write(ann / "MyDrive" / "b.txt", "bravo!")
    _drive_version(ann, "b.txt", "2026.09.23-21.29.52", 1, b"brav")
    _drive_version(ann, "b.txt", "2026.09.24-08.00.00", 2, b"bravo", md5="0" * 32)
    _write(ann / "MyDrive" / "c.txt", "charlie")                 # no version history
    _drive_version(ann, "old.txt", "2026.01.01-00.00.00", 1, b"gone")   # deleted in Google, kept
    folder_v = ann / "MyDrive" / "#SynoVersionRepo" / "notes" / "#SynoVersions"     # a folder's version
    _write(folder_v / "GMT-2026.09.23-21.29.52-v1-DIR", b"")
    _write(folder_v / "GMT-2026.09.23-21.29.52-v1.metadata", json.dumps({"hash": "", "is_dir": True, "size": "0"}))
    _write(folder_v / "GMT-2026.09.24-08.00.00-v2-DEL", b"")
    _write(ann / "MyDrive" / "#SynoRepo" / "id-path-mapping.db" / "CURRENT", "x")
    bob = task / f"bob@{domain}"
    _mail(bob, "b1", "0101")
    _db(db / BOB / "mail.sqlite",
        "CREATE TABLE mail_table (row_id INTEGER PRIMARY KEY, mail_id TEXT, version_number INTEGER,"
        " start_time INTEGER, end_time INTEGER)", [("INSERT INTO mail_table VALUES (NULL,?,1,0,?)", [("b1", FOREVER)])])
    return task


def _summary(task, **kw):
    names = set(os.listdir(task))
    return summarize(detect(task.name, task.name, names), str(task), names, **kw)


def test_abg_is_detected_and_its_items_are_listed_only():
    st = detect("x/task_1", "task_1", {DB, "ann@example.org"})
    assert st is not None and st.format is abg.FORMAT
    assert st.opaque("x/task_1/ann@example.org/Mail/0A/1B/m1/v1-1-SKEL")
    assert st.opaque("x/task_1/ann@example.org/Calendar/01/2E/abc/v1-1-META")
    assert st.opaque("x/task_1/ann@example.org/MyDrive/#SynoVersionRepo/a.txt/#SynoVersions/GMT-x-v1")
    assert st.opaque("x/task_1/ann@example.org/MyDrive/#SynoRepo/id-path-mapping.db/CURRENT")
    assert st.opaque(f"x/task_1/{DB}/1001/mail-content-search/_0.fdt")
    assert st.opaque(f"x/task_1/{DB}/single-instancing.db/CURRENT")
    assert not st.opaque(f"x/task_1/{DB}/1001/mail.sqlite")
    assert not st.opaque("x/task_1/ann@example.org/MyDrive/notes/Mail/a.txt")
    assert not st.opaque("x/task_1/ann@example.org/MyDrive/a.txt")
    assert detect("p", "Projects", {"Mail", "MyDrive"}) is None


def test_abg_summary(fixture_dir):
    b = _summary(make_task(fixture_dir))
    assert b["format"] == "synology-abg"
    assert (b["task"], b["domain"], b["admin"]) == ("Example-free", "example.org", "admin@example.org")
    assert b["machines"] == ["example.org"] and b["versions"] == 3
    assert b["first"] == "2026-09-21T14:13:20+00:00" and b["latest"] == "2026-09-29T16:40:30+00:00"
    assert b["user_count"] == 2 and b["removed_users"] == ["bob@example.org"]
    assert b["items"] == {"mail": 6, "mail_deleted": 1, "calendar": 1, "contacts": 2, "drive_files": 3,
                          "drive_versions": 4}
    assert b["files"] == {"missing": 3, "incomplete": 1, "unlisted": 1, "size_mismatch": 1,
                          "after_listing": 1}
    assert b["storage"]["used_bytes"] == 5100
    ann = b["users"][0]
    assert ann["email"] == "ann@example.org" and ann["items"]["drive_deleted"] == 1
    assert ann["last_run"]["mail"]["status"] == "failed"
    assert b["problems"] == [
        "ann@example.org: 1 of 5 messages in mail.sqlite have no files: m4 v1",
        "ann@example.org: 1 messages lack their SKEL fragment: m2 v1",
        "ann@example.org: 1 messages folders are not in mail.sqlite: m9",
        "ann@example.org: 1 of 2 contacts in contact.sqlite have no files: cGVvcGxlL2My v1",
        "ann@example.org: 1 MyDrive files have no version in #SynoVersionRepo: c.txt",
        "ann@example.org: 1 MyDrive files differ in size from their latest version: b.txt (6 bytes, latest version 5)",
        "ann@example.org: mail: last run 2026-09-28T12:53:50+00:00 failed: No mail data of user "
        "[ann@example.org] was backed up. Connection failure; last success 2026-09-21T14:14:20+00:00"]
    assert b["copy_keys"] == ["abg-task:9000:1:1763188928"]
    assert b["machine_keys"] == ["google-workspace:example.org"]
    text = json.dumps(b)
    assert "ya29" not in text and "SECRETKEY" not in text


@pytest.mark.skipif(sys.platform != "win32", reason="Windows MAX_PATH long-path listing")
def test_items_a_listing_could_not_open_are_listed_again_before_they_count_as_missing(fixture_dir, monkeypatch):
    """A walk without long paths cannot open event folders past 260
    characters, so its listing lacks them; the summary lists that service
    again with long paths before reporting anything missing."""
    task = make_task(fixture_dir)
    monkeypatch.setattr(abg.os, "name", "nt")
    monkeypatch.setattr(abg.FORMAT, "_too_long", lambda *a: True)     # the fixture's paths are short
    full = abg._relist(str(task))
    short = {k: v for k, v in full.items() if "/Calendar/" not in k}
    names = set(os.listdir(task))
    b = summarize(detect(task.name, task.name, names), str(task), names, listing=lambda: short)
    assert not any("calendar events" in p for p in b["problems"])
    assert b["files"]["missing"] == 3


def test_verify_backups_checks_fragments_and_versions_and_only_then(fixture_dir):
    task = make_task(fixture_dir)
    att = next((task / "ann@example.org" / "Mail" / "0A" / "1B" / "m1").glob("v1-2-ATT_0"))
    att.write_bytes(b"PNGDATX" * 10)        # same size, other content
    assert "verified" not in _summary(task)
    b = _summary(task, verify=True)
    assert b["verified"] == {"files": 12, "bad": 3}
    bad = [p for p in b["problems"] if "fail their metadata" in p]
    assert bad == ["ann@example.org: 3 files fail their metadata's size or MD5: "
                   "Mail/0A/1B/m1/v1-2-ATT_0: MD5 differs, Mail/0C/2D/m2/v1-1-SKEL: missing, "
                   "MyDrive/#SynoVersionRepo/b.txt/#SynoVersions/GMT-2026.09.24-08.00.00-v2: "
                   "MD5 differs"]


def test_walker_lists_the_items_measures_mydrive_and_passes_its_listing(fixture_dir, monkeypatch):
    make_task(fixture_dir)
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    def no_second_listing(path):
        raise AssertionError("the store was listed again")

    monkeypatch.setattr(abg, "_os_listing", no_second_listing)
    backend = MemoryBackend()
    root = str(fixture_dir)
    walk_root(root, ScanOptions(), backend, None, _resume(), measure)
    docs = {d["rel_path"]: d for d in backend.list(root=root)}
    t = "task_1"
    skel = docs[f"{t}/ann@example.org/Mail/0A/1B/m1/v1-1-SKEL"]
    assert skel["kind"] == "data" and skel["probe"] == {"backup_data": "synology-abg"}
    assert not any("/Mail/" in r or "#Syno" in r for r in measured)
    assert f"{t}/ann@example.org/MyDrive/notes/a.txt" in measured
    assert f"{t}/{DB}/{ANN}/mail.sqlite" in measured
    b = docs[t]["probe"]["backup"]
    assert b["files"]["missing"] == 3 and b["items"]["mail"] == 6


def test_backups_command_prints_a_google_workspace_task(fixture_dir, capsys, monkeypatch):
    make_task(fixture_dir)
    backend = MemoryBackend()
    walk_root(str(fixture_dir), ScanOptions(), backend, None, _resume(), _measure_stub)
    monkeypatch.setattr(backups_cmd, "open_backend", lambda *a: backend)
    monkeypatch.setattr(backend, "close", lambda: None)

    class Args:
        backend = out = dsn = root = None
        versions = False
        json = False

    assert backups_cmd.run(Args()) == 0
    out = capsys.readouterr().out
    assert "[synology-abg]  7 problems" in out
    assert "task      Example-free for example.org (admin admin@example.org), 2 users (1 removed), 3 runs" in out
    assert "items     6 messages (1 deleted in Google, kept), 1 events, 2 contacts, 3 Drive files (4 versions)" in out
    assert "files     3 missing, 1 incomplete, 1 not in the databases, 1 differ in size" in out
    assert "last run failed: mail" in out and "removed" in out


def test_a_copied_task_is_a_copy_and_another_task_of_the_domain_is_a_separate_job(fixture_dir):
    make_task(fixture_dir / "a")
    make_task(fixture_dir / "b" / "old")
    make_task(fixture_dir / "c", created=1790000000)
    backend = MemoryBackend()
    for sub in ("a", "b", "c"):
        walk_root(str(fixture_dir / sub), ScanOptions(), backend, None, _resume(), _measure_stub)
    copies, jobs = backups_cmd.groups(list(backups_cmd.stores(backend)))
    rel = "task_1"
    pa = os.path.join(str(fixture_dir / "a"), rel)
    pb = os.path.join(str(fixture_dir / "b"), "old", rel)
    pc = os.path.join(str(fixture_dir / "c"), rel)
    assert copies == [sorted([pa, pb])]
    assert jobs["google-workspace:example.org"] == sorted([pa, pb, pc])
