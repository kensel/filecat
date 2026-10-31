"""The storage topology collectors (filecat.topology_collect) over recorded raw sources, the
agent primitives they use (read_file, statfs, run, capabilities) against the fake agent with the
allowlist enforced, the `storage_topology` catalog store, and `filecat storage collect|show|links`.
"""
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from filecat import cli, config, topology, topology_store
from filecat.agent_client import AgentClient, AgentError
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.jsonl_dir import JsonlDirBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.topology_collect import AgentSource, RecordedSource, collect, detect_platform, parse
from filecat.topology_collect import linux, synology
from _fake_agent import (DENY_SHA256, FakeAgent, cert_fingerprint, denied, denied_windows,
                          resolve_allow_roots, under)

DATA = Path(__file__).parent / "data"
NAS3 = DATA / "raw" / "nas3"
NOW = "2026-10-22T09:00:00Z"
LUN3 = "lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1"


def nas3(**kw) -> topology.Topology:
    return collect(RecordedSource(NAS3), unc_server="\\\\nas3", now=NOW, measure_shares=True, **kw)


# --- the Synology collector against the recorded nas3 ---------------------------------------
def test_nas3_collects_to_the_lab_fixture():
    got = nas3().to_dict()
    lab = json.loads((DATA / "lab_nas3.json").read_text(encoding="utf-8"))["topology"]
    assert got == lab                        # lab_nas3.json is this collector's output on tests/data/raw/nas3
    assert "collector" not in got            # nothing was unreadable


def test_a_recording_made_while_collecting_replays_to_the_same_topology(tmp_path):
    # storage collect --record: RecordingSource writes what the collector read; collecting again
    # from that recording alone gives the same topology
    from filecat.topology_collect import RecordingSource
    rec = RecordingSource(RecordedSource(NAS3), tmp_path / "nas3")
    first = collect(rec, unc_server="\\\\nas3", now=NOW, measure_shares=True).to_dict()
    rec.save()
    again = collect(RecordedSource(tmp_path / "nas3"), unc_server="\\\\nas3", now=NOW, measure_shares=True)
    assert again.to_dict() == first
    assert json.loads((tmp_path / "nas3" / "meta.json").read_text())["hostname"] == "nas3"


def test_nas3_layers():
    t = nas3()
    assert t.platform == "synology" and t.host["os"] == "DSM 7.2.2"
    assert [d.serial for d in t.of_type("disk")] == ["SYNTH-NVME-0001", "SYNTH-NVME-0002"] + [
        f"ZR6N3A0{i}" for i in (1, 2, 3, 4)]
    pool, = t.of_type("pool")
    group, cache = sorted(t.of_type("group"), key=lambda g: g.role != "data")
    vol, = t.of_type("volume")
    assert cache.role == "cache" and cache.parent == pool.id and cache.level == "raid1"
    assert [m["role"] for m in cache.members] == ["cache", "cache"]
    assert cache.platform["synology"]["cache_for"] == ["/volume1"]         # cache.reference == the volume's LV uuid
    assert vol.platform["synology"]["ssd_cache"] == cache.id
    assert pool.id == "pool:Xw3kLp-9aVt-QmR2-uYb7-Hn4d-Zc8e-Ft6Sgj"        # the VG id of /etc/lvm/backup
    assert group.id == "group:c40e7b19-6d25-4f83-a1b0-93e8d52f7a46"        # the md uuid of mdadm --detail --scan
    assert vol.id == "vol:5e2c8d41-90ab-4c17-a3f6-7b1d0e94c258"            # /sys/fs/btrfs uuid via cachedev_0 -> dm-0 -> md2
    assert (group.parent, vol.parent) == (pool.id, pool.id)
    assert group.level == "raid5" and len(group.members) == 4
    assert vol.device == "/dev/mapper/cachedev_0" and vol.fs_type == "btrfs" and vol.health == "ok"
    assert vol.used_bytes + vol.free_bytes == vol.size_bytes and vol.detail == "87.22% used"
    assert [s.unc for s in t.of_type("share")] == ["\\\\nas3\\Backup", "\\\\nas3\\homes", "\\\\nas3\\Apps"]
    assert topology.share_entries(t)["/volume1/Backup"] == "\\\\nas3\\Backup"


def test_naa_comes_through_the_collector():
    lun = nas3().nodes[LUN3]
    assert "naa:6001405f48f1514d6072d4193d989ed9" in lun.match            # topology.naa_from_unit_serial
    assert lun.platform["synology"]["vpd_unit_serial"] == "f48f1514-6072-4193-989e-9e7bfbe6d0e1"
    assert lun.target == "PVEC" and [i["iqn"] for i in lun.initiators][-1] == synology.DEFAULT_ACL_IQN
    assert lun.initiators[-1]["default"] is True and lun.initiators[0]["authority"] == 3
    # and it links to the Proxmox cluster's disk exactly as the hand-made fixture did
    pvec = topology.from_response(json.loads((DATA / "lab_pvec.json").read_text(encoding="utf-8")))
    links, _ = topology.resolve_links([nas3(), pvec])
    assert any(l.provider == ("nas3", LUN3) and l.via == "naa~naa" for l in links)


def test_allocated_bytes_are_st_blocks_never_the_rod_size():
    rec = RecordedSource(NAS3)
    recorded = rec.sum_subtree("/volume1/@iSCSI/LUN/BLUN/f48f1514-6072-4193-989e-9e7bfbe6d0e1")
    assert recorded.total_size == recorded.total_allocated_size + 512 * 2 ** 30      # the sparse ROD
    lun = collect(rec, now=NOW).nodes[LUN3]
    assert lun.allocated_bytes == recorded.total_allocated_size < lun.size_bytes
    thin_empty = collect(rec, now=NOW).nodes["lun:7949c2d0-3b1e-4f58-9a6d-0e5c8b1f2a33"]
    assert thin_empty.allocated_bytes == 0 and thin_empty.size_bytes == 10 * 2 ** 30


def copy_nas3(fixture_dir, name="nas3", space=True) -> Path:
    rec = fixture_dir / name
    shutil.copytree(NAS3, rec)
    if not space:
        shutil.rmtree(rec / "files" / "etc" / "space")
    return rec


def test_nonzero_smartctl_exit_status_is_not_a_failure(fixture_dir):
    rec = RecordedSource(NAS3)
    assert rec.run("smartctl_info_json", "/dev/sata2").exit_code == 64
    src = RecordedSource(copy_nas3(fixture_dir, space=False))
    assert collect(src, now=NOW).nodes["disk:ZR6N3A02"].serial == "ZR6N3A02"
    assert ("smartctl_info_json", "/dev/sata2") in src.runs


def test_unreadable_sources_leave_notes_not_failures(fixture_dir):
    rec = copy_nas3(fixture_dir, space=False)
    (rec / "statfs.json").write_text("{}")
    (rec / "files" / "etc" / "samba" / "smb.conf").unlink()
    (rec / "files" / "etc" / "samba" / "smb.share.conf").unlink()
    (rec / "files" / "etc" / "lvm" / "backup" / "vg1").unlink()
    (rec / "run" / "mdadm_detail_scan.stdout").unlink()
    t = collect(RecordedSource(rec), unc_server="\\\\nas3", now=NOW)
    notes = t.extra["collector"]["notes"]
    assert any("statfs /volume1" in n for n in notes) and any("no Samba configuration" in n for n in notes)
    assert any("mdadm --detail --scan is not available" in n for n in notes)
    vol, = t.of_type("volume")
    assert vol.size_bytes is None and vol.parent is not None        # the array is its own pool without the VG
    assert t.of_type("group")[0].id.startswith("group:") and t.of_type("group")[0].id != \
        "group:c40e7b19-6d25-4f83-a1b0-93e8d52f7a46"
    assert t.of_type("share") == []                 # the fallback skips @-folders and found no others


def test_image_template_orphan_vdisk_and_nfs_export(fixture_dir):
    rec = copy_nas3(fixture_dir)
    lun_conf = rec / "files" / "volume1" / "@iSCSI" / "LUN" / "iscsi_lun.conf"
    lun_conf.write_text(lun_conf.read_text() + (
        "[LUN_dc8c50db-f451-4367-966a-f6277ac5341b]\nuuid=dc8c50db-f451-4367-966a-f6277ac5341b\n"
        "name=image.b9c5e9e5-0000-4000-8000-000000000000.v.sata.0\nlid=10\nbytes=1000727379968\ndevtype=7\n\n"
        "[LUN_11111111-2222-4333-8444-555555555555]\nuuid=11111111-2222-4333-8444-555555555555\n"
        "name=vdisk.99999999-0000-4000-8000-000000000000.11111111-2222-4333-8444-555555555555.sata.0\n"
        "lid=11\nbytes=1000\ndevtype=7\n"))
    (rec / "files" / "etc" / "exports").write_text("/volume1/Apps *(rw)\n/volume1/Media *(ro)\n")
    t = collect(RecordedSource(rec), unc_server="\\\\nas3", now=NOW)
    image = t.nodes["vdisk:dc8c50db-f451-4367-966a-f6277ac5341b"]
    assert image.attached is False and image.vm is None and image.name == "[VMM_IMAGE: b9c5e9e5]"
    orphan = t.nodes["vdisk:11111111-2222-4333-8444-555555555555"]
    assert orphan.vm["name"] == "[ORPHANED_VDISK]" and t.nodes[orphan.vm["id"]].platform["synology"]["orphaned"]
    assert t.nodes["share:apps"].protocols == ["smb", "nfs"]
    assert t.nodes["share:media"].protocols == ["nfs"] and t.nodes["share:media"].unc is None


DSM_SHARES = (
    "[ActiveBackupforBusiness]\n\trecycle bin admin only=no\n\tbrowseable=yes\n\tguest ok=yes\n"
    "\tpath=/volume1/ActiveBackupforBusiness\n\tskip smb perm=yes\n\tcomment=\"\"\n"
    "[ActiveBackupforBusinessC]\n\tbrowseable=yes\n\tpath=/volume1/ActiveBackupforBusinessC\n"
    "\tcomment=\"Active Backup for Business destination\"\n\tvalid users=nobody,nobody\n")


def with_samba(fixture_dir, conf, **files):
    """nas3 with smb.conf replaced by `conf`, no smb.share.conf, and these other files
    (path relative to the fixture root, text) added."""
    rec = copy_nas3(fixture_dir)
    samba = rec / "files" / "etc" / "samba"
    (samba / "smb.share.conf").unlink()
    (samba / "smb.conf").write_text(conf, newline="\n")
    for rel, text in files.items():
        f = rec / "files" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, newline="\n")
    return collect(RecordedSource(rec), unc_server="\\\\nas3", now=NOW)


def test_dsm_share_file_is_read_without_an_include(fixture_dir):
    t = with_samba(fixture_dir, "[global]\n\tworkgroup=WORKGROUP\n\tinclude=/var/tmp/nginx/smb.netbios.aliases.conf\n",
                   **{"etc/samba/smb.share.conf": DSM_SHARES})
    abb = t.nodes["share:activebackupforbusiness"]
    assert abb.unc == "\\\\nas3\\ActiveBackupforBusiness" and abb.path == "/volume1/ActiveBackupforBusiness"
    assert t.nodes["share:activebackupforbusinessc"].protocols == ["smb"]
    assert not any("smb" in n.lower() for n in (t.extra.get("collector") or {}).get("notes", []))      # the include outside the roots is silent


def test_samba_includes_are_followed(fixture_dir):
    conf = "[global]\n\tinclude = /etc/samba/extra.conf\n\tinclude = /etc/samba/%U.conf\n"
    t = with_samba(fixture_dir, conf, **{"etc/samba/extra.conf": "[Media]\npath = /volume1/Media\n"
                                         "include = /etc/samba/nested.conf\n",
                                         "etc/samba/nested.conf": "[Deep]\npath = /volume1/Deep\n"})
    assert [s.name for s in t.of_type("share")] == ["Media", "Deep"]


def test_samba_include_loop_is_guarded(fixture_dir):
    t = with_samba(fixture_dir, "[global]\ninclude = /etc/samba/a.conf\n",
                   **{"etc/samba/a.conf": "[A]\npath = /volume1/A\ninclude = /etc/samba/b.conf\n",
                      "etc/samba/b.conf": "[B]\npath = /volume1/B\ninclude = /etc/samba/smb.conf\ninclude = /etc/samba/a.conf\n"})
    assert [s.name for s in t.of_type("share")] == ["A", "B"]


def test_samba_include_outside_the_roots_is_silent(fixture_dir):
    t = with_samba(fixture_dir, "[global]\ninclude = /usr/syno/etc/smb.conf.global\n[Only]\npath = /volume1/Only\n")
    assert [s.name for s in t.of_type("share")] == ["Only"]
    assert not any("smb.conf.global" in n for n in (t.extra.get("collector") or {}).get("notes", []))


def test_samba_shares_merge_with_nfs_exports(fixture_dir):
    rec = copy_nas3(fixture_dir)
    (rec / "files" / "etc" / "samba" / "smb.share.conf").write_text(DSM_SHARES, newline="\n")
    (rec / "files" / "etc" / "exports").write_text("/volume1/ActiveBackupforBusiness *(rw)\n/volume1/PVE *(rw)\n")
    t = collect(RecordedSource(rec), unc_server="\\\\nas3", now=NOW)
    assert t.nodes["share:activebackupforbusiness"].protocols == ["smb", "nfs"]
    assert t.nodes["share:pve"].protocols == ["nfs"]


def test_vmm_image_with_several_disks_is_numbered(fixture_dir):
    rec = copy_nas3(fixture_dir)
    lun_conf = rec / "files" / "volume1" / "@iSCSI" / "LUN" / "iscsi_lun.conf"
    lun_conf.write_text(lun_conf.read_text() + "".join(
        f"[LUN_{u}]\nuuid={u}\nname=image.8ad92580-0000-4000-8000-000000000000.v.sata.{i}\nlid={20 + i}\n"
        f"bytes={(i + 1) * 1000}\ndevtype=7\n\n"
        for i, u in enumerate(("aaaaaaaa-0000-4000-8000-000000000001", "aaaaaaaa-0000-4000-8000-000000000002"))))
    t = collect(RecordedSource(rec), unc_server="\\\\nas3", now=NOW)
    names = [t.nodes[f"vdisk:aaaaaaaa-0000-4000-8000-00000000000{i}"].name for i in (1, 2)]
    assert names == ["[VMM_IMAGE: 8ad92580] disk 1", "[VMM_IMAGE: 8ad92580] disk 2"]


def test_storage_show_labels_cache_group_volume_cache_and_disks():
    from filecat import storage_cmd
    t = nas3()
    cache, = [g for g in t.of_type("group") if g.role == "cache"]
    vol, = t.of_type("volume")
    line = storage_cmd._line(cache)
    assert line.startswith("group") and " cache " in line and "cache for /volume1" in line
    assert "ssd cache md3" in storage_cmd._line(vol, t)


def test_detect_platform_and_dispatch():
    assert detect_platform(RecordedSource(NAS3)) == "synology"
    with pytest.raises(ValueError, match="no collector"):
        collect(RecordedSource(NAS3), "proxmox")
    assert collect(RecordedSource(NAS3), "truenas", now=NOW).platform == "truenas"   # forced: notes, no ZFS


# --- parsers --------------------------------------------------------------------------------
def test_parse_mdstat_and_scan():
    arrays = parse.parse_mdstat((NAS3 / "files" / "proc" / "mdstat").read_text())
    assert sorted(arrays) == ["md0", "md1", "md2", "md3"]
    md2 = arrays["md2"]
    assert md2["level"] == "raid5" and md2["flags"] == "UUUU" and (md2["active"], md2["total"]) == (4, 4)
    assert [m["name"] for m in md2["members"]] == ["sata1p5", "sata2p5", "sata3p5", "sata4p5"]
    degraded = parse.parse_mdstat("md3 : active raid1 sdb1[1](F) sda1[0]\n      100 blocks [2/1] [U_]\n"
                                  "md4 : inactive sdc1[0](S)\n      5 blocks\n")
    assert degraded["md3"]["members"][1]["failed"] and degraded["md3"]["flags"] == "U_"
    assert degraded["md4"]["level"] is None and degraded["md4"]["members"][0]["spare"]
    assert parse.md_uuid("c40e7b19:6d254f83:a1b093e8:d52f7a46") == "c40e7b19-6d25-4f83-a1b0-93e8d52f7a46"


def test_parse_lvm_text_and_smartctl_text_and_lsblk():
    vg = parse.parse_lvm_text((NAS3 / "files" / "etc" / "lvm" / "backup" / "vg1").read_text())["vg1"]
    assert vg["extent_size"] == 8192 and vg["logical_volumes"]["volume_1"]["segment1"]["stripes"] == ["pv0", 0]
    with pytest.raises(ValueError):
        parse.parse_lvm_text('vg1 { id = "x"')
    info = parse.parse_smartctl_text("Device Model:     ST1\nSerial Number:    ZZ1\nRotation Rate:    7200 rpm\n"
                                     "User Capacity:    16,000,900,661,248 bytes [16.0 TB]\n")
    assert info == {"serial": "ZZ1", "model": "ST1", "rotation_rate": 7200, "size_bytes": 16000900661248}
    js = ('{"blockdevices":[{"name":"sda","kname":"sda","pkname":null,"type":"disk","size":"1000","rota":"1",'
          '"mountpoint":null,"children":[{"name":"sda1","kname":"sda1","type":"part","size":500,"rota":false,'
          '"mountpoints":["/data"]}]}]}')
    rows = parse.parse_lsblk(js)
    assert rows[0]["size"] == 1000 and rows[0]["rota"] is True and rows[1]["pkname"] == "sda"
    assert rows[1]["mountpoints"] == ["/data"]
    pairs = parse.parse_lsblk('NAME="sda" KNAME="sda" TYPE="disk" SIZE="1000" ROTA="0" MOUNTPOINT=""\n')
    assert pairs[0]["rota"] is False and pairs[0]["mountpoints"] == []
    assert parse.parse_blkid_export("DEVNAME=/dev/sda1\nUUID=a-b\nTYPE=ext4\n\nDEVNAME=/dev/sdb\nUUID=c\n")[1]["UUID"] == "c"


def test_generic_linux_collector(fixture_dir):
    rec = fixture_dir / "box"
    (rec / "files" / "proc").mkdir(parents=True)
    (rec / "files" / "proc" / "mounts").write_text("/dev/sda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n")
    (rec / "files" / "etc").mkdir()
    (rec / "files" / "etc" / "os-release").write_text('PRETTY_NAME="Debian GNU/Linux 12"\n')
    (rec / "run").mkdir()
    (rec / "run" / "lsblk_json.stdout").write_text(json.dumps({"blockdevices": [
        {"name": "sda", "kname": "sda", "type": "disk", "size": 1000204886016, "rota": False, "model": "SSD",
         "serial": "S1", "children": [{"name": "sda1", "kname": "sda1", "type": "part", "size": 1000000,
                                       "mountpoints": ["/"]}]},
        {"name": "loop0", "kname": "loop0", "type": "loop", "size": 5}]}))
    (rec / "statfs.json").write_text(json.dumps({"/": {"total_bytes": 1000, "free_bytes": 400}}))
    (rec / "meta.json").write_text('{"hostname": "box"}')
    t = collect(RecordedSource(rec), now=NOW)
    assert t.platform == "linux" and t.host["os"] == "Debian GNU/Linux 12" and t.name == "box"
    assert [d.serial for d in t.of_type("disk")] == ["S1"] and t.of_type("disk")[0].media == "ssd"
    vol, = t.of_type("volume")
    assert (vol.mount, vol.size_bytes, vol.used_bytes, vol.free_bytes) == ("/", 1000, 600, 400)
    assert vol.members == [{"disk": "disk:S1", "role": "data"}]
    assert linux.PLATFORM == "linux"


# --- the fake agent: read_file, statfs, run, capabilities, with the allowlist enforced -------
@pytest.fixture
def served(fixture_dir):
    root = fixture_dir / "served"
    root.mkdir()
    with FakeAgent(root) as agent:
        agent.load_recording(NAS3)
        yield agent


def client(agent) -> AgentClient:
    return AgentClient("127.0.0.1", agent.port, cert_fingerprint(), agent.token, timeout=5, io_timeout=20)


def test_read_file_caps_and_kinds(served):
    with client(served) as c:
        whole = c.read_file("/proc/mdstat")
        assert not whole.truncated and whole.text().startswith("Personalities")
        part = c.read_file("/proc/mdstat", 10)
        assert part.truncated and part.data == whole.data[:10]
        for path, code in (("/proc", "bad_request"), ("/nope", "not_found")):
            with pytest.raises(AgentError) as err:
                c.read_file(path)
            assert err.value.code == code
        with pytest.raises(ValueError):
            c.read_file("/proc/mdstat", 4 * 1024 * 1024 + 1)
        with pytest.raises(AgentError) as err:                       # the agent checks too
            c._call({"cmd": "read_file", "path": "/proc/mdstat", "max": 4 * 1024 * 1024 + 1})
        assert err.value.code == "bad_request"


def test_statfs(served):
    with client(served) as c:
        st = c.statfs("/volume1")
        assert st.fs_type_id == 0x9123683E and st.used_bytes == st.total_bytes - st.free_bytes
        assert parse.fs_type_name(st.fs_type_id) == "btrfs" and not st.read_only
        assert c.statfs("/etc").block_size == 4096


def test_run_allowlist_is_enforced(served):
    served.run_outputs["btrfs_usage@/volume1"] = {"stdout": "Overall:\n"}
    with client(served) as c:
        assert c.run("mdadm_detail_scan").stdout.startswith("ARRAY /dev/md0")
        assert c.run("smartctl_info_json", "/dev/sata1").exit_code == 0
        assert c.run("smartctl_info_json", "/dev/sata2").exit_code == 64
        assert c.run("btrfs_usage", "/volume1").stdout == "Overall:\n"
        bad = [("rm_rf", None, "bad_request"),                          # not in the allowlist
               ("mdadm_detail_scan", "/dev/md2", "bad_request"),         # an argument for an entry without a kind
               ("smartctl_info_json", None, "bad_request"),              # a kind with no argument
               ("smartctl_info_json", "/dev/sata9", "refused"),          # not a disk of /sys/block
               ("smartctl_info_json", "/dev/sata1p5", "refused"),        # a partition
               ("smartctl_info_json", "/dev/loop0", "refused"),
               ("smartctl_info_json", "--help", "refused"),
               ("smartctl_info_json", "/dev/sata1; id", "refused"),
               ("smartctl_info_json", "/dev/../etc/passwd", "refused"),
               ("btrfs_usage", "/proc", "refused"),                      # not a btrfs mount
               ("btrfs_usage", "/volume1/", "refused"),
               ("btrfs_usage", "/volume1/Backup", "refused"),
               ("mdadm_detail", "/dev/md9", "refused"),
               ("zpool_list", None, "not_found")]                        # in the allowlist, no binary here
        for entry, arg, code in bad:
            with pytest.raises(AgentError) as err:
                c.run(entry, arg)
            assert err.value.code == code, (entry, arg)
    assert ("smartctl_info_json", "/dev/sata9") not in served.ran and ("btrfs_usage", "/proc") not in served.ran


def test_capabilities(served):
    served.unavailable.add("smartctl_info")
    with client(served) as c:
        caps = c.capabilities()
        assert caps.has("mdadm_detail_scan") and caps.has("smartctl_info_json")
        assert not caps.has("lsblk_json") and not caps.has("smartctl_info") and not caps.has("nope")
        assert caps.entries["btrfs_usage"].arg_kind == "btrfs_mount" and len(caps.allowlist_sha256) == 64
        with pytest.raises(AgentError) as err:
            c.wmi("storage_physical_disk")                              # Windows agents only
        assert err.value.code == "bad_request"


def test_the_collector_runs_through_the_agent(served):
    with client(served) as c:
        t = collect(AgentSource(c), "synology", name="nas3", unc_server="\\\\nas3", now=NOW, measure_shares=True)
    assert t.to_dict() == nas3().to_dict()
    assert {e for e, _ in served.ran} == {"mdadm_detail_scan"}            # the space history named the disks: no smartctl


# --- the catalog store -----------------------------------------------------------------------
def _backends(fixture_dir):
    return {"memory": MemoryBackend(), "sqlite": SqliteBackend(str(fixture_dir / "s.sqlite")),
            "jsonl": JsonlBackend(str(fixture_dir / "s.jsonl")),
            "jsonl_dir": JsonlDirBackend(str(fixture_dir / "s-dir"))}


def test_store_history_only_on_structure_change(fixture_dir):
    for name, backend in _backends(fixture_dir).items():
        t = nas3()
        r = topology_store.save_snapshot(backend, t, agent={"name": "nas3"})
        assert r.first and r.changed and r.history_written, name
        doc = backend.get_topology("NAS3")
        assert doc["host"] == "nas3" and doc["agent"] == {"name": "nas3"} and doc["platform"] == "synology"
        assert doc["unc_roots"] == ["\\\\nas3\\Apps", "\\\\nas3\\Backup", "\\\\nas3\\homes"]
        assert topology.parse(doc["topology"]).to_dict() == t.to_dict()
        # usage moves: the snapshot is replaced, no history row
        d = t.to_dict()
        for n in d["nodes"]:
            if n["id"].startswith("vol:"):
                n["used_bytes"] += 4096
                n["free_bytes"] -= 4096
            if n["id"] == LUN3:
                n["allocated_bytes"] += 4096
        d["collected_at"] = "2026-10-23T09:00:00Z"
        r = topology_store.save_snapshot(backend, topology.parse(d))
        assert not r.changed and not r.history_written, name
        assert len(backend.topology_history("nas3")) == 1
        assert backend.get_topology("nas3")["topology"]["collected_at"] == "2026-10-23T09:00:00Z"
        # structure moves: a disk goes degraded and a LUN is added
        d2 = copy.deepcopy(d)
        d2["collected_at"] = "2026-10-24T09:00:00Z"
        next(n for n in d2["nodes"] if n["id"] == "disk:ZR6N3A03")["health"] = "failed"
        d2["nodes"].append({"id": "lun:new", "type": "lun", "parent": next(
            n["id"] for n in d2["nodes"] if n["type"] == "volume"), "name": "LUN-8", "size_bytes": 1})
        r = topology_store.save_snapshot(backend, topology.parse(d2))
        assert r.changed and r.history_written and not r.first, name
        assert r.diff == {"added": ["lun:new"], "removed": [], "changed": ["disk:ZR6N3A03"]}
        rows = backend.topology_history("nas3")
        assert [x["scanned_at"] for x in rows] == [NOW, "2026-10-24T09:00:00Z"]
        assert rows[1]["previous_hash"] == rows[0]["structure_hash"] and rows[1]["diff"] == r.diff
        # the hash ignores usage and the snapshot time, nothing else
        assert topology_store.structure_hash(t) == topology_store.structure_hash(topology.parse(d))
        assert topology_store.structure_hash(t) != topology_store.structure_hash(topology.parse(d2))
        backend.delete_topology("nas3")
        assert backend.get_topology("nas3") is None and len(backend.topology_history("nas3")) == 2
        backend.close()


def test_store_derives_guest_servers_and_attached_to(fixture_dir):
    backend = MemoryBackend()
    pvec = topology.from_response(json.loads((DATA / "lab_pvec.json").read_text(encoding="utf-8")))
    topology_store.save_snapshot(backend, nas3())
    topology_store.save_snapshot(backend, pvec)
    docs = {d["key"]: d for d in backend.topologies()}
    assert docs["pvec"]["attached_to"] == ["nas3"]
    assert docs["nas3"]["attached_to"] == []


# --- the commands ----------------------------------------------------------------------------
def _config(fixture_dir, agent, extra=""):
    path = fixture_dir / "filecat.toml"
    path.write_text(
        f'[[agents]]\nname = "nas3"\nhost = "127.0.0.1"\nport = {agent.port}\n'
        f'cert_sha256 = "{cert_fingerprint()}"\ntoken = "{agent.token}"\nalias = \'\\\\nas3\'\n' + extra,
        encoding="utf-8")
    return path


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr()


def test_storage_collect_show_and_links(served, fixture_dir, capsys):
    cfg = _config(fixture_dir, served, '[[storage.hosts]]\nname = "ghost"\nnodes = []\n')
    db = str(fixture_dir / "cat.sqlite")
    common = ["--config", str(cfg)]
    bk = ["--backend", "sqlite", "--out", db]
    go = lambda *a: run(capsys, *common, "storage", *a, *bk)
    code, out = go("collect", "--measure-shares", "--dry-run")
    assert code == 0 and "nas3  nas3  synology  23 nodes  not stored" in out.out
    assert not Path(db).exists()
    code, out = go("collect", "--measure-shares")
    assert code == 0 and "first snapshot stored" in out.out
    code, out = go("collect", "--measure-shares", "--json")
    row = json.loads(out.out)
    assert code == 0 and row["changed"] is False and row["first"] is False and row["nodes"] == 23
    code, out = go("show")
    assert code == 0 and "nas3" in out.out and "stored" in out.out and "ghost" in out.out and "manual" in out.out
    code, out = go("show", "NAS3")
    assert code == 0 and "pool  Storage Pool 1  raid5" in out.out and "volume  Volume 1" in out.out
    assert "\\\\nas3\\Backup" in out.out and "lun  LUN-3" in out.out and "vm  NAS01" in out.out
    code, out = go("show", "nas3", "--json")
    assert json.loads(out.out)["topology"]["host"]["name"] == "nas3"
    code, out = go("show", "nope")
    assert code == 1 and "no host 'nope'" in out.err
    code, out = go("links", "--json")          # stored snapshots, no --snapshot
    doc = json.loads(out.out)
    assert code == 0 and [s["name"] for s in doc["snapshots"]] == ["nas3"] and doc["snapshots"][0]["from"] == "catalog"
    code, out = go("collect", "--agent", "nope")
    assert code == 2 and "no such [[agents]]" in out.err


def test_storage_collect_record_writes_a_replayable_recording(served, fixture_dir, capsys):
    cfg = _config(fixture_dir, served)
    rec = fixture_dir / "rec"
    code, out = run(capsys, "--config", str(cfg), "storage", "collect", "--measure-shares", "--dry-run",
                    "--record", str(rec))
    assert code == 0 and f"nas3: raw outputs recorded in {rec / 'nas3'}" in out.out
    assert (rec / "nas3" / "run" / "mdadm_detail_scan.stdout").is_file()      # argument-free entries are run
    assert "mdadm_detail_scan" in json.loads((rec / "nas3" / "capabilities.json").read_text())
    replayed = collect(RecordedSource(rec / "nas3"), unc_server="\\\\nas3", now=NOW, measure_shares=True)
    assert len(replayed.nodes) == 23


def test_storage_links_reads_nothing_when_there_is_no_catalog(fixture_dir, capsys, monkeypatch):
    monkeypatch.chdir(fixture_dir)
    code, out = run(capsys, "storage", "links")
    assert code == 0 and not (fixture_dir / "catalog.sqlite").exists()


def test_storage_collect_of_an_empty_host_stores_notes_only(fixture_dir, capsys):
    root = fixture_dir / "empty"
    root.mkdir()
    with FakeAgent(root) as agent:
        cfg = _config(fixture_dir, agent)
        code, out = run(capsys, "--config", str(cfg), "storage", "collect", "--platform", "synology",
                        "--backend", "sqlite", "--out", str(fixture_dir / "c.sqlite"))
    assert code == 0                                  # an empty host still collects: nothing to read, notes only
    assert "nas3  nas3  synology  0 nodes" in out.out
