from __future__ import annotations

import os
import struct
import tempfile
import uuid
from xml.sax.saxutils import escape

from filecat import backups_cmd, record
from filecat.backends.memory import MemoryBackend
from filecat.backup import detect, summarize, veeam
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from filecat.walker import walk_root

JOB = "Job DESKTOP-TEST"
HOST_UUID = "4C4C4544-004C-4B10-8052-B3C04F4B4832"


def _resume():
    return ResumeState(os.path.join(tempfile.gettempdir(), f"filecat-test-resume-{uuid.uuid4().hex}.json"))


def _measure_stub(root, rel_path, abs_path, st, options, identifier):
    return record.new_document(root, rel_path, kind="text", size=st.st_size,
                               mtime_ns=st.st_mtime_ns, ctime_ns=st.st_mtime_ns)


def make_backup_file(path, *, bank_ok=True, eof_extra=0, slot_ok=True):
    """A .vbk/.vib with what --verify-backups reads: the header page, two
    snapshot slots (one bank each) and the bank. 7 pages, 28 KiB."""
    page = 4096
    size = 7 * page
    bank_off, bank_len = 5 * page, 2 * page
    bank = bytes([1, 0]) + bytes(range(256)) * 31 + b"\x07" * (bank_len - 2 - 256 * 31)
    head = bytearray(page)
    struct.pack_into("<III", head, 0, 13, 1, 3)
    head[12:15] = b"md5"
    struct.pack_into("<IIB", head, 0x107, 9, 1 << 20, 3)

    def slot(version):
        body = bytearray(124 + 2 * 16)
        struct.pack_into("<QQI", body, 8, version, size + eof_extra, 1)
        struct.pack_into("<II", body, 116, 2, 1)
        crc = veeam.crc32c(bank) if bank_ok else 0xDEADBEEF
        struct.pack_into("<IQI", body, 124, crc, bank_off, bank_len)
        struct.pack_into("<II", body, 0, 0, 1)
        struct.pack_into("<I", body, 0, veeam.crc32c(bytes(body[4:])) if slot_ok else 1)
        return bytes(body) + bytes(page - len(body))

    data = bytes(head) + slot(7) + slot(6)
    data = data + bytes(bank_off - len(data)) + bank
    assert len(data) == size
    path.write_bytes(data)
    return size


def _stats(size, data):
    return escape(f"<CBackupStats><BackupSize>{size}</BackupSize><DataSize>{data}</DataSize>"
                  f"<DedupRatio>60</DedupRatio><CompressRatio>50</CompressRatio></CBackupStats>", {'"': "&quot;"})


def _aux():
    return escape('<COibAuxData><DesktopOibAuxData OsVersion="10.0.19045"><OsName>Microsoft Windows 10 Pro</OsName>'
                  '<Disk FriendlyName="NVMe TEST" Capacity="512110190592"><IndexedDiskInfo><VeeamDiskId>'
                  '<MountPoint path="C:\\" /></VeeamDiskId></IndexedDiskInfo></Disk></DesktopOibAuxData>'
                  '</COibAuxData>', {'"': "&quot;"})


def make_job(base, name=JOB, *, host="DESKTOP-TEST", host_uuid=HOST_UUID, point_prefix="p"):
    """A Veeam Agent job folder: a full and three increments in the .vbm.
    The 1st increment is a different size on disk, the 2nd is missing, the
    3rd (which needs the 2nd) is marked corrupt; one .vib on disk is not in
    the .vbm."""
    job = base / name
    job.mkdir(parents=True)
    files = [(f"{name}2024-04-01T003011.vbk", "0", "2024-04-01 06:30:11"),
             (f"{name}2024-04-02T003012.vib", "1", "2024-04-02 06:30:12"),
             (f"{name}2024-04-03T003011.vib", "1", "2024-04-03 06:30:11"),
             (f"{name}2024-04-04T003011.vib", "1", "2024-04-04 06:30:11")]
    sizes = {}
    for i, (fn, _, _) in enumerate(files):
        if i != 2:
            sizes[fn] = make_backup_file(job / fn)
    make_backup_file(job / f"{name}2024-03-30T003011.vib")
    storages, points, oibs = [], [], []
    for i, (fn, ptype, when) in enumerate(files):
        d, t = when.split()
        y, m, dd = d.split("-")
        stamp = f"{m}/{dd}/{y} {t}"
        recorded = 0 if i == 3 else sizes.get(fn, 28672) + (100 if i == 1 else 0)
        link = f' LinkId="s{i - 1}"' if i else ""
        point_link = f' LinkId="{point_prefix}{i - 1}"' if i else ""
        storages.append(f'<Storage Id="s{i}" FilePath="\\\\nas-legacy\\Backup\\{name}\\{fn}" CreationTimeUtc="{stamp}"'
                        f' Stats="{_stats(recorded, 3 * recorded)}" PartialIncrement="False"{link} />')
        points.append(f'<Point Id="{point_prefix}{i}" Num="{i + 1}" Type="{ptype}" CreationTimeUtc="{stamp}"'
                      f'{point_link} />')
        oibs.append(f'<OIB Id="o{i}" ObjectId="obj" PointId="{point_prefix}{i}" StorageId="s{i}"'
                    f' IsCorrupted="{"True" if i == 3 else "False"}" IsConsistent="{"False" if i == 3 else "True"}"'
                    f' VmName="{host}" ApproxSize="858093602816" AuxData="{_aux()}" />')
    (job / f"{name}.vbm").write_text(
        f'<BackupMeta Version="50" CreationTimeUtc="04/04/2024 06:44:53">'
        f'<Backup Id="b1" JobId="j1" JobName="{name}" JobType="4000" BackupPlatform="6"'
        f' DirPath="\\\\nas-legacy\\Backup\\{name}" CreationTime="11/07/2023 01:37:33" EncryptionState="0" />'
        f'<BackupMetaInfo><Storages>{"".join(storages)}</Storages>'
        f'<Points>{"".join(points)}</Points><Oibs>{"".join(oibs)}</Oibs>'
        f'<Objects><Object Id="obj" Name="{host}" Uuid="{host_uuid}" /></Objects>'
        f'</BackupMetaInfo></BackupMeta>', encoding="utf-8")
    return job


def test_veeam_job_is_detected_and_its_backup_files_are_listed_only():
    st = detect("x/Job A", "Job A", {"Job A.vbm", "Job A2024-04-01T003011.vbk"})
    assert st is not None and st.format is veeam.FORMAT
    assert st.opaque("x/Job A/Job A2024-04-01T003011.vbk")
    assert st.opaque("x/Job A/Job A2024-04-02T003011.VIB")
    assert not st.opaque("x/Job A/Job A.vbm")
    assert not st.opaque("x/Job A/sub/notes.vbk")
    # a .vbk without its .vbm still counts when it has Veeam's own name
    assert detect("c", "copy", {"Job A2024-04-01T003011.vbk"}).format is veeam.FORMAT
    assert detect("c", "copy", {"srv01D2024-04-01T003011_8C1A.vib"}).format is veeam.FORMAT
    # a VMware .vib bundle and a dictionary .vrb are not Veeam files
    assert detect("d", "Downloads", {"VMware_locker_tools-light_11.0.5.15389592-15999342.vib"}) is None
    assert detect("d", "dict", {"en.vrb", "de.vrb"}) is None
    assert detect("d", "notes", {"Job A.vbm"}) is None


def test_veeam_summary(fixture_dir):
    job = make_job(fixture_dir)
    names = set(os.listdir(job))
    b = summarize(detect(JOB, JOB, names), str(job), names)

    assert b["format"] == "veeam"
    assert (b["job"], b["job_id"], b["backup_id"], b["job_type"]) == (JOB, "j1", "b1", 4000)
    assert b["written_to"] == f"\\\\nas-legacy\\Backup\\{JOB}" and b["encrypted"] is False
    assert b["metadata_updated"] == "2024-04-04T06:44:53+00:00"
    assert b["machines"] == ["DESKTOP-TEST"] and b["os"] == "Microsoft Windows 10 Pro"
    assert b["versions"] == 4 and b["fulls"] == 1
    full, inc1, inc2, inc3 = b["points"]
    assert full == {"file": f"{JOB}2024-04-01T003011.vbk", "storage_id": "s0", "link": None, "point_id": "p0",
                    "num": "1", "type": "full", "created": "2024-04-01T06:30:11+00:00", "backup_bytes": 28672,
                    "data_bytes": 3 * 28672, "dedup": 60, "compress": 50, "partial": False, "corrupt": False,
                    "consistent": True, "source_bytes": 858093602816, "on_disk": True}
    assert inc1["size_on_disk"] == 28672 and inc1["backup_bytes"] == 28772
    assert inc2["on_disk"] is False and inc3["corrupt"] is True
    assert b["latest"] == inc3["created"] and b["latest_good"] == inc1["created"]
    assert b["files"] == {"listed": 4, "missing": 1, "size_mismatch": 1, "unlisted": 1}
    assert b["storage"]["on_disk_bytes"] == 4 * 28672
    assert b["problems"] == [
        f"{JOB}2024-04-03T003011.vib: missing (restore point of 2024-04-03 06:30); "
        "1 later restore points depend on it",
        f"{JOB}2024-04-04T003011.vib: marked corrupt by Veeam (restore point of 2024-04-04 06:30)",
        f"{JOB}2024-04-02T003012.vib: 28672 bytes on disk, metadata 28772",
        f"1 backup files are not in the .vbm (Veeam no longer tracks them), e.g. {JOB}2024-03-30T003011.vib"]
    assert b["copy_keys"] == ["veeam-point:p0", "veeam-point:p1"]
    assert b["machine_keys"] == ["host:desktop-test", f"veeam-object:{HOST_UUID.lower()}"]
    assert "verified" not in b


def test_verify_backups_checks_each_files_own_metadata(fixture_dir):
    job = make_job(fixture_dir)
    make_backup_file(job / f"{JOB}2024-04-02T003012.vib", bank_ok=False)
    make_backup_file(job / f"{JOB}2024-04-04T003011.vib", eof_extra=4096)
    make_backup_file(job / f"{JOB}2024-03-30T003011.vib", slot_ok=False)
    names = set(os.listdir(job))
    b = summarize(detect(JOB, JOB, names), str(job), names, verify=True)

    v = {x["file"]: x for x in b["verified"]}
    assert v[f"{JOB}2024-04-01T003011.vbk"] == {
        "file": f"{JOB}2024-04-01T003011.vbk", "format_version": 13, "block_size": 1 << 20, "digest": "md5",
        "slot_version": 7, "eof": 28672, "banks": 1, "metadata_bytes": 8192, "banks_bad": 0}
    assert f"{JOB}2024-04-02T003012.vib: 1 of 1 metadata banks fail their checksum in both slots" in b["problems"]
    assert (f"{JOB}2024-04-04T003011.vib: truncated: its metadata ends at 32768 bytes, the file has 28672"
            in b["problems"])
    assert (f"{JOB}2024-03-30T003011.vib: no snapshot slot with a valid checksum: the file's metadata is "
            "unusable" in b["problems"])


def test_crc32c_check_value():
    assert veeam.crc32c(b"123456789") == 0xE3069283


def test_walker_lists_the_backup_files_and_reads_the_vbm(fixture_dir, monkeypatch):
    make_job(fixture_dir / "Backup")
    measured = []

    def measure(root, rel_path, *a):
        measured.append(rel_path)
        return _measure_stub(root, rel_path, *a)

    def no_second_listing(path):
        raise AssertionError("the store was listed again")

    monkeypatch.setattr(veeam, "_os_listing", no_second_listing)
    backend = MemoryBackend()
    root = str(fixture_dir)
    walk_root(root, ScanOptions(), backend, None, _resume(), measure)
    docs = {d["rel_path"]: d for d in backend.list(root=root)}

    vbk = docs[f"Backup/{JOB}/{JOB}2024-04-01T003011.vbk"]
    assert vbk["kind"] == "data" and vbk["probe"] == {"backup_data": "veeam"}
    assert measured == [f"Backup/{JOB}/{JOB}.vbm"]
    b = docs[f"Backup/{JOB}"]["probe"]["backup"]
    assert b["files"] == {"listed": 4, "missing": 1, "size_mismatch": 1, "unlisted": 1}


def test_backups_command_prints_a_veeam_job(fixture_dir, capsys, monkeypatch):
    make_job(fixture_dir)
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
    assert "[veeam]  4 problems" in out
    assert f"job       {JOB} (Microsoft Windows 10 Pro), written to \\\\nas-legacy\\Backup\\{JOB}" in out
    assert "1 missing, 1 differ in size, 1 not in the .vbm" in out
    assert "increment" in out and "corrupt" in out and "  missing" in out


def test_a_copied_job_is_a_copy_and_a_second_job_of_the_machine_is_a_job(fixture_dir):
    make_job(fixture_dir / "a")
    make_job(fixture_dir / "b" / "old")
    make_job(fixture_dir / "c", "Job DESKTOP-TEST 2", point_prefix="q")
    backend = MemoryBackend()
    for sub in ("a", "b", "c"):
        walk_root(str(fixture_dir / sub), ScanOptions(), backend, None, _resume(), _measure_stub)
    copies, jobs = backups_cmd.groups(list(backups_cmd.stores(backend)))
    pa = os.path.join(str(fixture_dir / "a"), JOB)
    pb = os.path.join(str(fixture_dir / "b"), "old", JOB)
    pc = os.path.join(str(fixture_dir / "c"), "Job DESKTOP-TEST 2")
    assert copies == [sorted([pa, pb])]
    assert jobs["host:desktop-test"] == sorted([pa, pb, pc])
