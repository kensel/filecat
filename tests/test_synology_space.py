"""The Synology collector's use of DSM's space history (/etc/space/space_history_*.xml), the iSCSI
files under /usr/syno/etc, smartctl by version, sdX disk names, and the agent's read scope
(allowed roots and the deny list) as the fake agent enforces it.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from filecat.agent_client import AgentClient, AgentError
from filecat.topology_collect import AgentSource, RecordedSource, collect, parse
from filecat.topology_collect import synology
from _fake_agent import (DENY_SHA256, FakeAgent, cert_fingerprint, denied, denied_windows,
                         resolve_allow_roots, under)

DATA = Path(__file__).parent / "data"
RAW = DATA / "raw"
NAS3 = RAW / "nas3"
NOW = "2026-10-22T09:00:00Z"
DSM_ROOTS = ["/volume*", "/proc", "/sys", "/dev/disk", "/etc/samba", "/etc/space", "/etc/VERSION",
             "/etc/exports", "/etc/lvm/backup", "/usr/syno/etc/iscsi_*.conf"]


def copy_nas3(fixture_dir, space=True) -> Path:
    rec = fixture_dir / "nas3"
    shutil.copytree(NAS3, rec)
    if not space:
        shutil.rmtree(rec / "files" / "etc" / "space")
    return rec


def collect_dir(rec: Path):
    return collect(RecordedSource(rec), unc_server="\\\\nas3", now=NOW)


def put(rec: Path, rel: str, text: str) -> None:
    p = rec / "files" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


# --- the parser on the real files -----------------------------------------------------------
def test_parse_the_real_nas3_space_history():
    spaces = parse.parse_space_history((RAW / "dsm_space_history_nas3.xml").read_text(encoding="utf-8"))
    assert [s["path"] for s in spaces] == ["/dev/shared_cache_vg1", "/dev/vg1"]
    cache, pool = spaces
    assert cache["cache"] and not pool["cache"] and pool["lvm"]["total_size"] == 63959671504896
    raid, = pool["raids"]
    assert (raid["path"], raid["level"], len(raid["disks"])) == ("/dev/md2", "raid10", 8)
    assert [d["dev_path"] for d in raid["disks"]] == [f"/dev/sata{i}p3" for i in range(1, 9)]
    assert [d["slot"] for d in raid["disks"]] == list(range(8))
    assert raid["disks"][0]["serial"] == "7072EOX47G54OW6KT" and raid["disks"][7]["serial"] == "8674MXL71L8LJV3IX"
    assert raid["disks"][4]["physical_location"] == "0-5" and raid["disks"][0]["model"] == "HAT3310-16T"
    craid, = cache["raids"]
    assert craid["level"] == "raid1" and [d["dev_path"] for d in craid["disks"]] == [
        "/dev/nvme0n1p1", "/dev/nvme1n1p1"]
    assert pool["volumes"] == [{"path": "/volume1", "dev_path": "/dev/vg1/volume_1",
                                "uuid": "Ty8iSi-ZfZA-bpWU-xsBO-jGJE-9Iss-HAtnP7", "type": "btrfs"}]
    assert cache["caches"][0]["reference"] == pool["volumes"][0]["uuid"]      # the SSD cache serves /volume1


def test_parse_the_nas2_space_history_pool_cache_pool_with_sdx_names():
    spaces = parse.parse_space_history((RAW / "dsm_space_history_nas2.xml").read_text(encoding="utf-8"))
    assert [(s["path"], s["cache"]) for s in spaces] == [
        ("/dev/vg2", False), ("/dev/shared_cache_vg1", True), ("/dev/vg1", False)]     # order means nothing
    vg2, cache, vg1 = spaces
    assert [d["dev_path"] for d in vg2["raids"][0]["disks"]] == ["/dev/sde5", "/dev/sdf5", "/dev/sdg5"]
    assert vg2["raids"][0]["level"] == "raid5" and vg2["volumes"][0]["type"] == "ext4"
    assert [d["dev_path"] for d in vg1["raids"][0]["disks"]] == [f"/dev/sd{c}5" for c in "abcd"]
    assert vg1["raids"][0]["disks"][0]["model"] == "HUH721010ALN600"
    craid, = cache["raids"]
    assert craid["level"] == "raid1" and len(craid["disks"]) == 1 and craid["disks"][0]["dev_path"] == "/dev/sdh1"
    assert cache["caches"][0]["reference"] == vg1["volumes"][0]["uuid"]
    assert synology.base_disk("sde5") == "sde" and synology.base_disk("sata1p3") == "sata1"
    assert synology.base_disk("nvme0n1p1") == "nvme0n1" and synology.base_disk("sdh1") == "sdh"
    assert synology.base_disk("sda") == "sda"


def test_space_history_is_untrusted_input():
    good = (RAW / "dsm_space_history_nas3.xml").read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="DOCTYPE"):
        parse.parse_space_history('<?xml version="1.0"?><!DOCTYPE spaces [<!ENTITY a "b">]><spaces/>')
    with pytest.raises(ValueError, match="ENTITY"):
        parse.parse_space_history('<spaces><!ENTITY x "y"></spaces>')
    with pytest.raises(ValueError, match="longer"):
        parse.parse_space_history(good + " " * parse.MAX_SPACE_XML)
    with pytest.raises(ValueError, match="not XML"):
        parse.parse_space_history("<spaces><space>")
    assert parse.parse_space_history("<spaces/>") == []


def test_newest_space_history_is_chosen_by_the_stamp_in_the_name():
    names = ["space_history_20261021_183000.xml", "space_history_20261022_085500.xml", "space_table",
             "space_history_20260101_000000.xml", "space_history_20261022_085500.xml.bak"]
    assert parse.newest_space_history(names) == "space_history_20261022_085500.xml"
    assert parse.newest_space_history(["space_table"]) is None


def test_smartctl_version_parses():
    assert parse.parse_smartctl_version("smartctl 6.5 2016-05-07 r4318 [x86_64-linux-4.4.302+] (local build)\n") == (6, 5)
    assert parse.parse_smartctl_version("smartctl 7.2 2020-12-30 r5155\n") == (7, 2)
    assert parse.parse_smartctl_version("usage: smartctl") is None


# --- the collector prefers the space history, with md and LVM as the fallback -----------------
def test_the_newest_space_history_is_the_authority_and_smartctl_is_not_run(fixture_dir):
    src = RecordedSource(copy_nas3(fixture_dir))
    t = collect(src, unc_server="\\\\nas3", now=NOW)
    pool, = t.of_type("pool")
    assert pool.level == "raid5" and len(t.nodes["disk:ZR6N3A04"].platform) == 1       # the older file says raid6, 3 disks
    sata1 = t.nodes["disk:ZR6N3A01"]
    assert (sata1.model, sata1.slot, sata1.platform["synology"]["physical_location"]) == ("ST16000NM001G", "1", "0-1")
    assert not [r for r in src.runs if r[0].startswith("smartctl")]
    assert pool.allocated_bytes < pool.size_bytes


def test_without_a_space_history_md_and_lvm_decide_and_smartctl_is_asked_once(fixture_dir):
    rec = RecordedSource(copy_nas3(fixture_dir, space=False))
    t = collect(rec, unc_server="\\\\nas3", now=NOW)
    pool, = t.of_type("pool")
    group, = t.of_type("group")
    assert (pool.level, group.level, group.role) == ("raid5", "raid5", "data")
    assert [d.serial for d in t.of_type("disk") if d.media == "hdd"] == [f"ZR6N3A0{i}" for i in (1, 2, 3, 4)]
    assert t.nodes["disk:ZR6N3A01"].platform["synology"]["wwn"]              # smartctl's, not in the space history
    assert [r for r in rec.runs if r[0] == "smartctl_version"] == [("smartctl_version", None)]
    assert all("nvme" in n for n in t.extra["collector"]["notes"])           # only the NVMe disks, which nothing recorded


def test_smartctl_below_7_goes_straight_to_the_text_form(fixture_dir):
    rec = copy_nas3(fixture_dir, space=False)
    (rec / "run" / "smartctl_version.stdout").write_text("smartctl 6.5 2016-05-07 r4318 [x86_64-linux-4.4.302+]\n")
    for i in range(1, 5):
        (rec / "run" / f"smartctl_info@%2Fdev%2Fsata{i}.stdout").write_text(
            f"smartctl 6.5\nDevice Model:     ST16000NM001G\nSerial Number:    ZR6N3A0{i}\nRotation Rate:    7200 rpm\n")
    src = RecordedSource(rec)
    t = collect(src, unc_server="\\\\nas3", now=NOW)
    assert [d.serial for d in t.of_type("disk") if d.media == "hdd"] == [f"ZR6N3A0{i}" for i in (1, 2, 3, 4)]
    assert {r[0] for r in src.runs if r[0].startswith("smartctl")} == {"smartctl_version", "smartctl_info"}
    assert len([r for r in src.runs if r[0] == "smartctl_version"]) == 1


def test_serial_sources_in_order_syno_disk_serial_before_smartctl(fixture_dir):
    rec = copy_nas3(fixture_dir, space=False)
    put(rec, "sys/block/sata1/device/syno_disk_serial", "FROM-SYNO-FILE\n")
    src = RecordedSource(rec)
    t = collect(src, unc_server="\\\\nas3", now=NOW)
    assert t.nodes["disk:FROM-SYNO-FILE"].slot == "1" and "disk:ZR6N3A01" not in t.nodes
    assert ("smartctl_info_json", "/dev/sata1") not in src.runs
    assert ("smartctl_info_json", "/dev/sata2") in src.runs


def test_several_arrays_in_one_pool_are_shr_with_each_level_on_its_group(fixture_dir):
    rec = copy_nas3(fixture_dir)
    for f in (rec / "files" / "etc" / "space").glob("*.xml"):
        f.unlink()
    xml = (NAS3 / "files" / "etc" / "space" / "space_history_20261022_085500.xml").read_text(encoding="utf-8")
    raid2 = xml[xml.index('<raid path="/dev/md2"'):xml.index("</raid>") + len("</raid>")]
    raid4 = raid2.replace("/dev/md2", "/dev/md4").replace("raid5", "raid1").replace("c40e7b19:6d254f83:a1b093e8:d52f7a46",
                                                                                      "11111111:22222222:33333333:44444444")
    put(rec, "etc/space/space_history_20261022_085500.xml", xml.replace(raid2, raid2 + "\n" + raid4))
    t = collect_dir(rec)
    pool, = t.of_type("pool")
    assert pool.level == "shr"
    assert sorted(g.level for g in t.of_type("group") if g.role == "data") == ["raid1", "raid5"]


def test_a_cache_that_names_no_volume_goes_under_the_only_pool_with_a_note(fixture_dir):
    rec = copy_nas3(fixture_dir)
    f = rec / "files" / "etc" / "space" / "space_history_20261022_085500.xml"
    f.write_text(f.read_text(encoding="utf-8").replace('cache reference="kP7mQz-4tRw-LnB8-Vc2x-Ds5H-Gj3f-Ya9Uie"',
                                                       'cache reference="unknown"'), encoding="utf-8")
    t = collect_dir(rec)
    cache, = [g for g in t.of_type("group") if g.role == "cache"]
    assert cache.parent == t.of_type("pool")[0].id
    assert any("does not say which pool" in n for n in t.extra["collector"]["notes"])


def test_an_unusable_space_history_falls_back_with_a_note(fixture_dir):
    rec = copy_nas3(fixture_dir)
    put(rec, "etc/space/space_history_20261023_000000.xml", '<!DOCTYPE x [<!ENTITY a "b">]><spaces/>')
    t = collect_dir(rec)
    assert [g.role for g in t.of_type("group")] == ["data"]                   # md and LVM: no cache group
    assert any("DOCTYPE" in n and "md and LVM" in n for n in t.extra["collector"]["notes"])


# --- sdX disks (older models), and what is not a disk ----------------------------------------
def test_sdx_disks_from_the_space_history_and_no_mtdblock_or_loopback(fixture_dir):
    rec = fixture_dir / "nas2"
    stamp = "space_history_20261027_222023.xml"
    put(rec, f"etc/space/{stamp}", (RAW / "dsm_space_history_nas2.xml").read_text(encoding="utf-8"))
    put(rec, "etc/VERSION", 'productversion="7.1.1"\n')
    for dev in "abcdefgh":
        put(rec, f"sys/block/sd{dev}/size", "19532873728\n")
        put(rec, f"sys/block/sd{dev}/removable", "0\n")
    put(rec, "sys/block/sdi/size", "100\n")
    put(rec, "sys/block/sdi/removable", "0\n")
    put(rec, "sys/block/sdi/device/syno_disk_serial", "SPARE-1\n")
    put(rec, "sys/block/sdj/size", "100\n")                                   # a USB stick
    put(rec, "sys/block/sdj/removable", "1\n")
    put(rec, "sys/block/sdk/size", "2097152\n")                               # a LUN loopback that took an sdX name
    put(rec, "sys/block/mtdblock0/size", "256\n")
    put(rec, "sys/block/mtdblock5/size", "256\n")
    put(rec, "sys/block/zram0/size", "256\n")
    (rec / "links.json").write_text(json.dumps({"/sys/block/sdk": "../devices/tcm_loop_0/x/block/sdk"}))
    (rec / "meta.json").write_text('{"hostname": "nas2"}')
    t = collect_dir(rec)
    devs = sorted(d.platform["synology"]["device"] for d in t.of_type("disk"))
    assert devs == [f"/dev/sd{c}" for c in "abcdefghi"]
    assert t.nodes["disk:17924K212370"].model == "SSD PLUS 1000GB" and t.nodes["disk:SPARE-1"].serial == "SPARE-1"
    pools = {p.name: p for p in t.of_type("pool")}
    assert sorted(pools) == ["Storage Pool 1", "Storage Pool 2"]
    groups = {g.name: g for g in t.of_type("group")}
    assert groups["md2"].parent == pools["Storage Pool 1"].id and groups["md4"].parent == pools["Storage Pool 2"].id
    assert [m["disk"] for m in groups["md2"].members] == [f"disk:{s}" for s in
                                                          ("4YS6XXUL", "6BO48XIK", "6DN1AXKZ", "4WO0U08A")]
    cache = groups["md3"]
    assert cache.role == "cache" and cache.parent == pools["Storage Pool 1"].id       # via the volume uuid
    assert cache.level == "raid1" and cache.health == "ok" and len(cache.members) == 1  # one SSD: not degraded
    assert cache.platform["synology"]["cache_for"] == ["/volume1"]
    assert t.nodes["disk:CP-ZYF7M7U8XJN5"].slot == "7"


def test_iscsi_loopback_and_other_non_disks_are_never_disks():
    t = collect(RecordedSource(NAS3), unc_server="\\\\nas3", now=NOW)
    assert not [d for d in t.of_type("disk") if "iscsi" in d.platform["synology"]["device"]]
    assert all(not synology._DISK.match(n) for n in ("iscsi1", "iscsi2", "loop0", "ram0", "zram0", "md0",
                                                       "dm-0", "synoboot", "mtdblock0", "sata1p1", "sde5"))
    assert all(synology._DISK.match(n) for n in ("sata1", "sas2", "nvme0n1", "sda", "sdh"))
    assert "/sys/block/iscsi1/device/model" not in RecordedSource(NAS3).reads        # not even looked at


# --- iSCSI targets and files -----------------------------------------------------------------
def test_targets_come_from_usr_syno_etc_with_iqn_enabled_and_lun_number():
    t = collect(RecordedSource(NAS3), unc_server="\\\\nas3", now=NOW)
    lun3 = t.nodes["lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1"]
    assert lun3.target == "PVEC"
    assert lun3.platform["synology"]["targets"] == [{
        "tid": 2, "name": "PVEC", "iqn": "iqn.2000-01.com.synology:NAS3.PVEC.b822278c1ad", "enabled": True, "lun": 1}]
    lun4 = t.nodes["lun:2a93d1c8-71e4-4b60-8c25-5f0e9a6b7d14"]
    assert lun4.target == "lkensel-g5-5090" and lun4.platform["synology"]["targets"][0]["lun"] == 1


def test_a_lun_behind_two_targets_records_both(fixture_dir):
    rec = copy_nas3(fixture_dir)
    f = rec / "files" / "usr" / "syno" / "etc" / "iscsi_mapping.conf"
    f.write_text(f.read_text() + "[iSCSI_MAP_T3_Lf48f1514-6072-4193-989e-9e7bfbe6d0e1]\ntid=3\n"
                 "uuid=f48f1514-6072-4193-989e-9e7bfbe6d0e1\nlun=5\n"
                 "[iSCSI_MAP_T9_L79494475-cb0a-4937-886c-ceeb8f894547]\ntid=9\nuuid=79494475-cb0a-4937-886c-ceeb8f894547\nlun=1\n")
    t = collect_dir(rec)
    lun3 = t.nodes["lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1"]
    assert lun3.target == "PVEC, lkensel-g5-5090"
    assert [(x["tid"], x["lun"]) for x in lun3.platform["synology"]["targets"]] == [(2, 1), (3, 5)]


def test_no_target_credential_reaches_the_topology(fixture_dir):
    committed = (NAS3 / "files" / "usr" / "syno" / "etc" / "iscsi_target.conf").read_text()
    for key in ("username", "password", "mutual_username", "mutual_password"):
        assert f"\n{key}=<filecat-redacted>\n" in committed                # as the agent serves it: blanked
    rec = copy_nas3(fixture_dir)
    f = rec / "files" / "usr" / "syno" / "etc" / "iscsi_target.conf"
    secrets = {"password": "CANARY-PW-1", "mutual_password": "CANARY-PW-2", "username": "CANARY-USER-1",
               "mutual_username": "CANARY-USER-2"}
    text = f.read_text()
    for k, v in secrets.items():
        text = text.replace(f"\n{k}=<filecat-redacted>\n", f"\n{k}={v}\n")
    f.write_text(text)
    t = collect_dir(rec)
    dumped = json.dumps(t.to_dict())
    assert all(v not in dumped for v in secrets.values()) and "CANARY" not in dumped
    assert "password" not in dumped and "mutual" not in dumped


def test_luns_go_to_the_volume_of_their_rootpath_and_per_volume_files_may_be_subsets(fixture_dir):
    rec = fixture_dir / "nas2"
    stanza = ("[LUN_{u}]\nlid={lid}\nrootpath={root}\nname=LUN-{lid}\nuuid={u}\nvpd_unit_serial={u}\nbytes={b}\n"
              "devtype=1\npre_alloc=yes\ndescription={d}\n")
    u1, u2, u3 = ("7860d5d8-d97e-4f5a-b03a-c676b596c26f", "e11f98ed-9301-4f5f-b7f7-8141f2e8c98e",
                  "0a0a0a0a-0b0b-4c0c-8d0d-0e0e0e0e0e0e")
    system = (stanza.format(u=u1, lid=1, root="/volume2", b=107374182400, d="Windows0")
              + stanza.format(u=u2, lid=2, root="/volume2", b=108447924224, d="ESXI0")
              + stanza.format(u=u3, lid=3, root="/volume1", b=1073741824, d="Third"))
    put(rec, "usr/syno/etc/iscsi_lun.conf", system)
    put(rec, "volume2/@iSCSI/LUN/iscsi_lun.conf", stanza.format(u=u1, lid=1, root="/volume2", b=107374182400, d="Windows0")
        + stanza.format(u=u2, lid=2, root="/volume2", b=108447924224, d="ESXI0"))
    put(rec, "volume1/@iSCSI/LUN/iscsi_lun.conf", stanza.format(u=u3, lid=3, root="/volume1", b=1073741824, d="Third"))
    put(rec, "volume1/@iSCSI/LUN/FILE/x", "")
    put(rec, "proc/mounts", "/dev/md2 /volume1 ext4 rw 0 0\n/dev/md4 /volume2 ext4 rw 0 0\n")
    put(rec, "etc/VERSION", 'productversion="7.1.1"\n')
    (rec / "meta.json").write_text('{"hostname": "nas2"}')
    (rec / "subtree.json").write_text(json.dumps({
        f"/volume2/@iSCSI/LUN/FILE/{u1}": {"total_size": 107374182400, "total_allocated_size": 107374182400},
        f"/volume2/@iSCSI/LUN/THIN/{u2}": {"total_size": 108447924224, "total_allocated_size": 5120}}))
    t = collect_dir(rec)
    luns = {n.name: n for n in t.of_type("lun")}
    vols = {v.mount: v.id for v in t.of_type("volume")}
    assert luns["LUN-1"].parent == vols["/volume2"] and luns["LUN-3"].parent == vols["/volume1"]
    assert luns["LUN-1"].detail == "Windows0" and luns["LUN-2"].detail == "ESXI0"
    assert luns["LUN-1"].thin is False
    assert "naa:" + __import__("filecat").topology.naa_from_unit_serial(u1) in luns["LUN-1"].match
    notes = t.extra["collector"]["notes"]
    # ext4 LUN directories: FILE when pre_alloc=yes, THIN otherwise, the other tried second, else a note
    assert luns["LUN-1"].path == f"/volume2/@iSCSI/LUN/FILE/{u1}" and luns["LUN-1"].allocated_bytes == 107374182400
    assert luns["LUN-2"].path == f"/volume2/@iSCSI/LUN/THIN/{u2}" and luns["LUN-2"].allocated_bytes == 5120
    assert luns["LUN-3"].path is None and luns["LUN-3"].allocated_bytes is None
    assert any("LUN-3" in n and "no FILE/" in n for n in notes) and not any("FILE/THIN" in n for n in notes)
    assert not any("differ" in n or "lacks" in n for n in notes)               # a subset is normal
    # a stanza a volume's file has and the system file lacks, or with other values, is noted
    put(rec, "volume1/@iSCSI/LUN/iscsi_lun.conf", stanza.format(u=u3, lid=3, root="/volume1", b=5, d="Third")
        + stanza.format(u="ffffffff-0000-4000-8000-000000000000", lid=9, root="/volume1", b=1, d="Extra"))
    t = collect_dir(rec)
    notes = t.extra["collector"]["notes"]
    assert any("differ" in n for n in notes) and any("lacks" in n for n in notes)
    assert {n.name: n for n in t.of_type("lun")}["LUN-3"].size_bytes == 1073741824     # the system file wins


def test_without_the_system_file_each_volumes_file_places_its_luns(fixture_dir):
    rec = copy_nas3(fixture_dir)
    shutil.rmtree(rec / "files" / "usr" / "syno" / "etc")
    t = collect_dir(rec)
    assert len(t.of_type("lun")) == 7 and all(n.target is None for n in t.of_type("lun"))


# --- the agent's read scope ------------------------------------------------------------------
def client(agent) -> AgentClient:
    return AgentClient("127.0.0.1", agent.port, cert_fingerprint(), agent.token, timeout=5, io_timeout=20)


def refused(c, method, *args):
    with pytest.raises(AgentError) as err:
        getattr(c, method)(*args)
    assert err.value.code == "refused", (method, args, err.value)
    return err.value


@pytest.fixture
def scoped(fixture_dir):
    root = fixture_dir / "served"
    for rel, text in (("volume1/Share/a.txt", "a"), ("volume1/Share/.env", "SECRET=1"),
                      ("volume1/Share/.env.production", "SECRET=2"), ("volume1/Share/.env.example", "KEY="),
                      ("volume1/Share/.env.local.bak", "x"), ("volume1/Share/env", "plain"),
                      ("etc/shadow", "root:*"), ("etc/hosts", "h"), ("var/log/messages", "log"),
                      ("etc/ssh/ssh_host_ed25519_key", "k"), ("proc/mdstat", "md")):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    with FakeAgent(root, allow_roots=["/volume*", "/proc", "/etc", "/var"]) as agent:
        yield agent, root


def test_reads_outside_the_allowed_roots_are_refused_with_a_clear_error(fixture_dir):
    root = fixture_dir / "served"
    (root / "volume1").mkdir(parents=True)
    (root / "volume1" / "a.txt").write_text("a")
    (root / "home" / "u").mkdir(parents=True)
    (root / "home" / "u" / "f.txt").write_text("f")
    with FakeAgent(root, allow_roots=["/volume*"]) as agent, client(agent) as c:
        assert c.read_file("/volume1/a.txt").text() == "a"
        for call in (lambda: c.read_file("/home/u/f.txt"), lambda: c.read_range("/home/u/f.txt", 0, 1),
                     lambda: c.list_dir("/home"), lambda: c.statfs("/home"), lambda: c.read_file("/home/none")):
            with pytest.raises(AgentError) as err:
                call()
            assert err.value.code == "refused" and "allowed roots" in str(err.value)
            assert "FILECAT_AGENT_ALLOW_ROOTS" in str(err.value) and "/home" in str(err.value)
        assert c.capabilities().allow_roots == ("/volume*",)                # the server can explain a refusal
        assert c.capabilities().allow_roots_source == "env" and c.capabilities().deny_sha256 == DENY_SHA256


def test_the_deny_list_wins_over_the_allowed_roots(scoped):
    agent, root = scoped
    with client(agent) as c:
        for path in ("/etc/shadow", "/var/log/messages", "/volume1/Share/.env", "/volume1/Share/.env.production",
                     "/etc/ssh/ssh_host_ed25519_key"):
            err = refused(c, "read_file", path)
            assert str(err) == f"{path}: denied by agent policy"           # the request path and nothing more
        refused(c, "read_range", "/etc/shadow", 0, 4)
        refused(c, "measure", "/volume1/Share/.env")
        for ok in ("/volume1/Share/a.txt", "/volume1/Share/.env.example", "/volume1/Share/env", "/etc/hosts",
                   "/proc/mdstat"):
            assert c.read_file(ok).data
        names = {e.name for e in c.list_dir("/volume1/Share").entries}
        assert {".env", ".env.example"} <= names                            # names stay listable
        assert c.list_dir("/var/log").entries[0].name == "messages"
        assert c.statfs("/etc").total_bytes > 0


def test_a_link_into_a_denied_or_outside_file_is_refused(scoped):
    agent, root = scoped
    try:
        os.symlink("../../etc/shadow", root / "volume1" / "Share" / "innocent.txt")
        os.symlink("../../var/log/messages", root / "volume1" / "Share" / "log.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    with client(agent) as c:
        refused(c, "read_file", "/volume1/Share/innocent.txt")             # canonical path /etc/shadow
        refused(c, "read_file", "/volume1/Share/log.txt")
        refused(c, "read_range", "/volume1/Share/innocent.txt", 0, 4)
    agent.allow_roots = ["/volume*"]
    with client(agent) as c:
        err = refused(c, "read_file", "/volume1/Share/innocent.txt")       # outside the roots as well
        assert "allowed roots" in str(err)


def test_a_link_out_of_the_served_tree_is_refused(scoped, fixture_dir):
    agent, root = scoped
    outside = fixture_dir / "outside.txt"
    outside.write_text("x")
    try:
        os.symlink(outside, root / "volume1" / "Share" / "out.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    with client(agent) as c:
        refused(c, "read_file", "/volume1/Share/out.txt")


def test_the_collector_notes_a_refused_source_and_goes_on(fixture_dir):
    root = fixture_dir / "served"
    root.mkdir()
    with FakeAgent(root, allow_roots=[r for r in DSM_ROOTS if "syno" not in r]) as agent:
        agent.load_recording(NAS3)
        with client(agent) as c:
            t = collect(AgentSource(c), "synology", name="nas3", unc_server="\\\\nas3", now=NOW)
    assert any(n.startswith("/usr/syno/etc/iscsi_lun.conf: refused") for n in t.extra["collector"]["notes"])
    assert len(t.of_type("lun")) == 7 and all(n.target is None for n in t.of_type("lun"))    # the copies in the volume


def test_the_dsm_default_roots_cover_everything_the_collector_reads(fixture_dir):
    root = fixture_dir / "served"
    root.mkdir()
    with FakeAgent(root, allow_roots=DSM_ROOTS) as agent:
        agent.load_recording(NAS3)
        with client(agent) as c:
            t = collect(AgentSource(c), "synology", name="nas3", unc_server="\\\\nas3", now=NOW, measure_shares=True)
        assert "collector" not in t.to_dict()                                 # nothing was refused
        paths = [r["path"] for r in agent.requests if "path" in r]
        assert paths and not [p for p in paths if denied(p)]                  # and nothing it reads is on the deny list
    assert t.to_dict() == collect(RecordedSource(NAS3), unc_server="\\\\nas3", now=NOW, measure_shares=True).to_dict()


def test_allow_roots_come_from_the_environment_then_the_env_file_then_the_default():
    default = ["/volume*", "/proc"]
    sep = ";" if os.name == "nt" else ":"
    env = {"FILECAT_AGENT_ALLOW_ROOTS": sep.join(["/a", "/b*"])}
    dotenv = "# agent\nFILECAT_AGENT_ALLOW_ROOTS=\"/from/file\"\nOTHER=1\n"
    assert resolve_allow_roots(env, dotenv, default) == (["/a", "/b*"], "env")          # the environment wins
    assert resolve_allow_roots({}, dotenv, default) == (["/from/file"], "env_file")
    assert resolve_allow_roots({}, None, default) == (default, "default")
    assert resolve_allow_roots({}, "OTHER=1\n", default) == (default, "default")
    assert resolve_allow_roots({"FILECAT_AGENT_ALLOW_ROOTS": ""}, dotenv, default) == ([], "env")   # set but empty: nothing


def test_root_and_deny_matching_rules():
    assert under("/volume*", "/volume1/x") and under("/volume*", "/volumeUSB1") and not under("/volume*", "/vol")
    assert under("/etc/space", "/etc/space") and under("/etc/space", "/etc/space/a.xml")
    assert not under("/etc/space", "/etc/spacey/a") and not under("/etc/space", "/etc")
    assert under("/usr/syno/etc/iscsi_*.conf", "/usr/syno/etc/iscsi_target.conf")
    assert not under("/usr/syno/etc/iscsi_*.conf", "/usr/syno/etc/smb.conf")
    assert under("/", "/anything")
    for p in ("/etc/shadow", "/etc/gshadow-", "/etc/sudoers.d/x", "/var/log/a/b", "/var/logs/x", "/a/.env",
              "/a/.env.production", "/etc/ssh/ssh_host_rsa_key", "/etc/ssl/private/k.pem"):
        assert denied(p), p
    for p in ("/a/.env.example", "/a/.env.sample", "/a/.env.template", "/a/env", "/etc/ssh/ssh_host_rsa_key.pub",
              "/etc/passwd", "/var/lib/x", "/volume1/environment"):
        assert not denied(p), p
    for p in (r"C:\Windows\System32\config\SAM", r"c:\windows\SYSTEM32\CONFIG\RegBack\SYSTEM",
              r"C:\Windows\NTDS\ntds.dit", r"D:\x\copy.dit", r"C:\Users\u\NTUSER.DAT.LOG1",
              r"C:\Users\u\AppData\Local\Microsoft\Windows\UsrClass.dat", r"D:\Share\.env", r"D:\Share\.ENV.local"):
        assert denied_windows(p), p
    for p in (r"C:\Windows\SYSVOL\domain\Policies\x.xml", r"C:\Windows\System32\drivers\a.sys", r"D:\Share\.env.example"):
        assert not denied_windows(p), p
