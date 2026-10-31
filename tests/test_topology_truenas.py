"""The TrueNAS collector against tests/data/raw/truenas2: a recording of a TrueNAS 26 host
(`filecat storage collect --record`), trimmed to what the collector reads, with every dataset,
zvol and share name that is not TrueNAS's own replaced by a generic one (ds0NN)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from filecat.topology_collect import RecordedSource, collect, detect_platform

TRUENAS2 = Path(__file__).parent / "data" / "raw" / "truenas2"
NOW = "2026-10-31T12:00:00Z"
BOOT, POOL0 = "pool:17928622918366983245", "pool:8667592160816057359"
POOL0_ROOT = "vol:9113223098416544285"


def topo(root=TRUENAS2):
    return collect(RecordedSource(root), name="truenas2", now=NOW)


def all_nodes(t) -> list[dict]:
    return t.to_dict()["nodes"]


def by_name(t, kind):
    return {n["name"]: n for n in all_nodes(t) if n["type"] == kind}


def copy(fixture_dir) -> Path:
    dst = fixture_dir / "truenas2"
    shutil.copytree(TRUENAS2, dst)
    return dst


def edit_json(path: Path, fn) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    out = fn(doc)
    path.write_text(json.dumps(doc if out is None else out), encoding="utf-8")


def test_detected_as_truenas_and_collected_whole():
    assert detect_platform(RecordedSource(TRUENAS2)) == "truenas"
    t = topo()
    assert t.platform == "truenas" and t.host["os"] == "TrueNAS 26.0.0-BETA.3"
    assert "collector" not in t.to_dict()                     # nothing unreadable
    counts = {k: len(by_name(t, k)) for k in ("disk", "pool", "group", "volume", "lun", "share")}
    assert counts == {"disk": 2, "pool": 2, "group": 2, "volume": 18, "lun": 3, "share": 7}


def test_pools_vdevs_and_disks():
    t = topo()
    pools = by_name(t, "pool")
    assert pools["pool0"]["id"] == POOL0 and pools["boot-pool"]["id"] == BOOT
    p0 = pools["pool0"]
    assert p0["size_bytes"] == 11802570129408 and p0["allocated_bytes"] == 10069235400704
    assert p0["health"] == "ok" and p0["platform"]["truenas"]["ashift"] == 12
    groups = by_name(t, "group")
    sdb1 = groups["sdb1"]                                     # by-partuuid -> sdb1 -> sdb's serial
    assert sdb1["parent"] == POOL0 and sdb1["level"] == "single" and sdb1["role"] == "data"
    assert sdb1["members"] == [{"disk": "disk:TRUENASDISK002", "role": "data"}]
    assert groups["sda3"]["members"] == [{"disk": "disk:TRUENASDISK001", "role": "data"}]
    assert by_name(t, "disk")["sdb"]["health"] == "ok"


def test_datasets_with_truenas_system_trees_collapsed():
    vols = by_name(topo(), "volume")
    assert vols["pool0"]["parent"] == POOL0 and vols["pool0"]["mount"] == "/mnt/pool0"
    assert vols["pool0"]["size_bytes"] == vols["pool0"]["used_bytes"] + vols["pool0"]["free_bytes"]
    assert vols["pool0/AppData/ds010"]["parent"] == vols["pool0/AppData"]["id"]
    inside = {n: v["platform"]["truenas"]["datasets_inside"] for n, v in vols.items()
              if "datasets_inside" in (v.get("platform") or {}).get("truenas", {})}
    assert inside == {"boot-pool": 47, "pool0/.system": 9, "pool0/iocage": 30,
                      "pool0/ix-applications": 116, "pool0/ix-apps": 60}
    # a shared dataset stays visible inside a system tree, under the tree's top
    assert vols["pool0/iocage/jails"]["parent"] == vols["pool0/iocage"]["id"]
    assert not any(n.startswith("boot-pool/") for n in vols)


def test_zvols_and_shares():
    t = topo()
    z = by_name(t, "lun")["pool0/ds045"]
    assert z["kind"] == "zvol" and z["thin"] is False and z["size_bytes"] == 214748397568
    assert z["path"] == "/dev/zvol/pool0/ds045" and z["parent"] == POOL0_ROOT
    shares = by_name(t, "share")
    vols = {v["id"]: v for v in by_name(t, "volume").values()}
    jails = shares["jails"]
    assert jails["unc"] == "\\\\truenas2\\jails" and jails["protocols"] == ["smb"]
    assert jails["path"] == "/mnt/pool0/iocage/jails" and vols[jails["parent"]]["name"] == "pool0/iocage/jails"
    assert shares["ds017"]["used_bytes"] == vols[shares["ds017"]["parent"]]["used_bytes"]


def test_guids_come_from_the_text_listing_when_the_json_clamps_them(fixture_dir):
    # zfs list -j --json-int prints a guid above 2**63 as 2**63-1; without the text listing those
    # datasets are keyed by name, so no two nodes share an id
    rec = copy(fixture_dir)
    datasets = json.loads((rec / "run" / "zfs_list_json.stdout").read_text())["datasets"].values()
    assert any(d["properties"]["guid"]["value"] == 2 ** 63 - 1 for d in datasets)   # the recording has it
    (rec / "run" / "zfs_list.stdout").unlink()
    edit_json(rec / "capabilities.json", lambda c: [x for x in c if x != "zfs_list"])
    ids = [n["id"] for n in all_nodes(topo(rec))]
    assert len(ids) == len(set(ids)) == 34
    assert any(i.startswith("vol:pool0/") for i in ids)       # a clamped one, keyed by name


def test_mirror_raidz_cache_spares_and_a_degraded_member(fixture_dir):
    rec = copy(fixture_dir)
    part = "/dev/disk/by-partuuid/ec264ca4-2130-4f48-9259-c5ff0206ba59"

    def leaf(name, state="ONLINE"):
        return {"name": name, "path": name, "vdev_type": "disk", "state": state}

    def layout(doc):
        pool = doc["pools"]["pool0"]
        pool["vdevs"]["pool0"]["vdevs"] = {
            "mirror-0": {"name": "mirror-0", "vdev_type": "mirror", "guid": 11, "class": "normal",
                         "state": "DEGRADED", "vdevs": {"/dev/sda3": leaf("/dev/sda3"), part: leaf(part, "FAULTED")}},
            "raidz2-1": {"name": "raidz2-1", "vdev_type": "raidz", "guid": 12, "class": "log",
                         "state": "ONLINE", "vdevs": {"/dev/sda3": leaf("/dev/sda3")}}}
        pool["l2cache"] = {"/dev/sda3": leaf("/dev/sda3")}
        pool["spares"] = {part: leaf(part, "AVAIL")}
    edit_json(rec / "run" / "zpool_status_json.stdout", layout)
    t = topo(rec)
    groups = {g["name"]: g for g in by_name(t, "group").values() if g["parent"] == POOL0}
    m = groups["mirror-0"]
    assert m["level"] == "mirror" and m["role"] == "data" and m["health"] == "degraded"
    assert [x["disk"] for x in m["members"]] == ["disk:TRUENASDISK001", "disk:TRUENASDISK002"]
    assert groups["raidz2-1"]["level"] == "raidz2" and groups["raidz2-1"]["role"] == "log"
    assert groups["cache"]["role"] == "cache" and groups["spares"]["members"][0]["role"] == "spare"


def test_nfs_merges_with_smb_by_path_and_an_iscsi_extent_names_its_zvol(fixture_dir):
    rec = copy(fixture_dir)
    (rec / "run" / "midclt_nfs_shares.stdout").write_text(json.dumps(
        [{"path": "/mnt/pool0/ds017", "enabled": True}, {"paths": ["/mnt/pool0/ds066"], "enabled": False}]))
    (rec / "run" / "midclt_iscsi_extents.stdout").write_text(json.dumps(
        [{"name": "lun1", "disk": "zvol/pool0/ds045", "naa": "0x6589CFC000000ABC"}]))
    t = topo(rec)
    shares = by_name(t, "share")
    assert shares["ds017"]["protocols"] == ["smb", "nfs"] and "unc" in shares["ds017"]
    nfs_only = shares["ds066"]
    assert nfs_only["protocols"] == ["nfs"] and "unc" not in nfs_only and nfs_only["health"] == "warning"
    lun = by_name(t, "lun")["pool0/ds045"]
    assert lun["platform"]["truenas"]["extent"] == "lun1" and lun["match"] == ["naa:6589cfc000000abc"]


def test_without_zfs_json_the_disks_remain_and_a_note_says_why(fixture_dir):
    rec = copy(fixture_dir)
    gone = ("zpool_status_json", "zfs_list_json")
    for f in gone:
        (rec / "run" / f"{f}.stdout").unlink()
    edit_json(rec / "capabilities.json", lambda c: [x for x in c if x not in gone])
    t = topo(rec)
    assert {n["type"] for n in all_nodes(t)} == {"disk"}   # the shares have no dataset to sit on
    notes = t.to_dict()["collector"]["notes"]
    assert any("OpenZFS 2.3" in n for n in notes) and any("no dataset holds" in n for n in notes)


def test_a_plain_debian_host_is_not_truenas(fixture_dir):
    rec = copy(fixture_dir)
    (rec / "files" / "etc" / "os-release").write_text('PRETTY_NAME="Debian 13"\nID=debian\n')
    assert detect_platform(RecordedSource(rec)) == "linux"
