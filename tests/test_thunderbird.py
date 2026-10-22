from __future__ import annotations

import os
import tempfile
import uuid

from filecat import backups_cmd, record
from filecat.backends.memory import MemoryBackend
from filecat.backup import detect, summarize, thunderbird
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import walk_root

PROFILE = r"C:\Users\ann\AppData\Roaming\Thunderbird\Profiles\ab12cd34.default-release"
MSG = "1779339455.M55000P51452Q79977.DESKTOP-ANN.eml"
# one mbox account, one maildir account, Local Folders on the old default (mbox),
# and an account kept outside the profile
PREFS = "\n".join([
    '// Mozilla User Preferences',
    'user_pref("mail.server.server1.directory-rel", "[ProfD]Mail/Local Folders");',
    'user_pref("mail.server.server1.hostname", "Local Folders");',
    'user_pref("mail.server.server1.name", "Local Folders");',
    'user_pref("mail.server.server1.type", "none");',
    'user_pref("mail.server.server2.directory-rel", "[ProfD]ImapMail/imap.gmail.com");',
    'user_pref("mail.server.server2.hostname", "imap.gmail.com");',
    'user_pref("mail.server.server2.name", "ann@example.org (Gmail)");',
    'user_pref("mail.server.server2.storeContractID", "@mozilla.org/msgstore/berkeleystore;1");',
    'user_pref("mail.server.server2.type", "imap");',
    'user_pref("mail.server.server10.directory-rel", "[ProfD]ImapMail/imap.example.org");',
    'user_pref("mail.server.server10.hostname", "imap.example.org");',
    'user_pref("mail.server.server10.name", "ann@example.org");',
    'user_pref("mail.server.server10.storeContractID", "@mozilla.org/msgstore/maildirstore;1");',
    'user_pref("mail.server.server10.type", "imap");',
    'user_pref("mail.server.server11.directory", "D:\\\\Mail\\\\Archive");',
    'user_pref("mail.server.server11.name", "Archive");',
    'user_pref("mail.server.server11.storeContractID", "@mozilla.org/msgstore/maildirstore;1");',
    'user_pref("mail.server.server11.type", "none");', ""])


def _resume():
    return ResumeState(os.path.join(tempfile.gettempdir(), f"filecat-test-resume-{uuid.uuid4().hex}.json"))


def _measure_stub(root, rel_path, abs_path, st, options, identifier):
    return record.new_document(root, rel_path, kind="text", size=st.st_size,
                               mtime_ns=st.st_mtime_ns, ctime_ns=st.st_mtime_ns)


def _write(path, data=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def make_copy(base, stamp="20260808-0332", date="8/8/2026, 3:32:36 AM"):
    """One ImportExportTools NG run: the profile's files, an account kept
    outside the profile, a file the log saved that is missing, one the log
    does not name, and one copy error."""
    copy = base / f"ab12cd34_default-release-{stamp}"
    files = {
        "prefs.js": PREFS,
        "compatibility.ini": "[Compatibility]\nLastVersion=153.0.1_20260728090639/20260728090639\n",
        "global-messages-db.sqlite": b"\0" * 64,
        f"ImapMail/imap.example.org/INBOX/cur/{MSG}": "Subject: hi\n\nbody\n",
        "ImapMail/imap.example.org/INBOX.msf": "// mork\n",
        "Mail/Local Folders/Unsent Messages": "",
        "Mail/Local Folders/Unsent Messages.msf": "// mork\n",
        "ImapMail/imap.gmail.com/INBOX": "From - Mon Jan  1 00:00:00 2026\nSubject: a\n\nx\n",
        "ImapMail/imap.gmail.com/INBOX.msf": "// mork\n",
        "ImapMail/imap.gmail.com/[Gmail].sbd/All Mail": "From - Mon Jan  1 00:00:00 2026\nSubject: b\n\ny\n",
        "ImapMail/imap.gmail.com/[Gmail].sbd/All Mail.msf": "// mork\n",
        "ImapMail/imap.gmail.com/[Gmail].sbd/Trash.msf": "// mork\n",     # never downloaded
    }
    for rel, data in files.items():
        _write(copy / rel, data)
    _write(copy / "ExternalMailFolders" / "Archive" / "Old" / "cur" / MSG, "Subject: old\n\nbody\n")
    _write(copy / "stray.txt", "not in the log")
    saved = [PROFILE + "\\" + rel.replace("/", "\\") for rel in files]
    saved.append(PROFILE + "\\Mail\\Local Folders\\Trash")            # logged, not in the copy
    saved.append("D:\\Mail\\Archive\\Old\\cur\\" + MSG)                 # the external account
    log = (f"Backup date: {date}\r\n\r\nSaved files:\r\n" + "".join(p + "\r\n" for p in saved)
           + f"\r\n***Error with file {PROFILE}\\datareporting\\glean\\events\\events\r\n"
           "Error Type: [Exception... NS_ERROR_FILE_IS_LOCKED]\r\n\r\n")
    _write(copy / "Backup.log", log)
    return copy


def _summary(copy):
    names = set(os.listdir(copy))
    return summarize(detect(copy.name, copy.name, names), str(copy), names)


def test_profile_copy_is_detected_and_listed_only():
    st = detect("Mail/Backup/p-20260808-0332", "p-20260808-0332", {"Backup.log", "ExternalMailFolders", "prefs.js"})
    assert st is not None and st.format is thunderbird.FORMAT
    assert st.opaque("Mail/Backup/p-20260808-0332/ImapMail/imap.example.org/INBOX/cur/" + MSG)
    assert st.opaque("Mail/Backup/p-20260808-0332/global-messages-db.sqlite")
    assert not st.opaque("Mail/Backup/p-20260808-0332/Backup.log")
    assert not st.opaque("Mail/Backup/p-20260808-0332/prefs.js")
    assert detect("x", "x", {"Backup.log"}) is None
    assert detect("x", "x", {"ExternalMailFolders"}) is None


def test_profile_copy_summary(fixture_dir):
    b = _summary(make_copy(fixture_dir))
    assert b["format"] == "thunderbird-ietng" and b["mode"] == "dated folder per run"
    assert (b["profile"], b["source_path"], b["user"]) == ("ab12cd34.default-release", PROFILE, "ann")
    assert b["latest"] == "2026-08-08T03:32:36" and b["thunderbird_version"] == "153.0.1"
    assert b["host"] == "DESKTOP-ANN" and b["machines"] == ["DESKTOP-ANN"]
    assert [(a["name"], a["store"]) for a in b["accounts"]] == [
        ("Local Folders", "mbox"), ("ann@example.org (Gmail)", "mbox"), ("ann@example.org", "maildir"),
        ("Archive", "maildir")]
    gmail = b["accounts"][1]
    assert (gmail["mbox_folders"], gmail["indexes"]) == (2, 3)     # Trash.msf alone is not a folder
    assert {k: b["mail"][k] for k in ("maildir_messages", "mbox_folders", "stores")} == \
        {"maildir_messages": 2, "mbox_folders": 3, "stores": ["maildir", "mbox"]}
    assert b["files"] == {"logged": 14, "missing": 1, "unlisted": 1, "copy_errors": 1}
    assert b["problems"] == [
        "1 of 14 files Backup.log saved are not in the copy: Mail/Local Folders/Trash",
        "1 files in the copy are not in Backup.log: stray.txt",
        "1 files could not be copied: datareporting\\glean\\events\\events"]
    assert b["copy_keys"] == ["tb-profile-backup:ab12cd34.default-release:2026-08-08T03:32:36"]
    assert b["machine_keys"] == ["host:desktop-ann", "thunderbird-profile:ab12cd34.default-release"]


def test_date_falls_back_to_the_folder_name_for_another_locale(fixture_dir):
    b = _summary(make_copy(fixture_dir, date="8 août 2026 à 03:32:36"))
    assert b["backup_date"] == "8 août 2026 à 03:32:36" and b["latest"] == "2026-08-08T03:32:00"


def test_walker_lists_the_copy_and_reads_only_the_small_files(fixture_dir, monkeypatch):
    make_copy(fixture_dir / "Backup")
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    monkeypatch.setattr(thunderbird, "_os_listing", lambda path: (_ for _ in ()).throw(AssertionError("listed twice")))
    backend = MemoryBackend()
    root = str(fixture_dir)
    walk_root(root, ScanOptions(), backend, None, _resume(), measure)
    docs = {d["rel_path"]: d for d in backend.list(root=root)}
    c = "Backup/ab12cd34_default-release-20260808-0332"
    msg = docs[f"{c}/ImapMail/imap.example.org/INBOX/cur/{MSG}"]
    assert msg["kind"] == "data" and msg["probe"] == {"backup_data": "thunderbird-ietng"}
    assert sorted(r[len(c) + 1:] for r in measured) == ["Backup.log", "compatibility.ini", "prefs.js"]
    assert docs[c]["probe"]["backup"]["files"]["missing"] == 1


def test_backups_command_and_generations_of_one_profile(fixture_dir, capsys, monkeypatch):
    make_copy(fixture_dir / "Backup")
    make_copy(fixture_dir / "Backup", stamp="20260727-1232", date="7/27/2026, 11:52:43 AM")
    make_copy(fixture_dir / "old" / "Backup")       # the 08-08 run copied elsewhere
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
    assert "[thunderbird-ietng]  3 problems" in out
    assert "profile   ab12cd34.default-release (Thunderbird 153.0.1) from " + PROFILE in out
    assert "files     14 in Backup.log, 1 missing, 1 not in the log, 1 copy errors" in out
    copies, jobs = backups_cmd.groups(list(backups_cmd.stores(backend)))
    assert len(copies) == 1 and len(copies[0]) == 2
    assert len(jobs["host:desktop-ann"]) == 3
