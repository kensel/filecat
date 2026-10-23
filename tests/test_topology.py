"""The generic storage topology (topology.py, docs/storage-topology.md): Synology
fixtures modelled on notes 03 and 04, and a skeletal TrueNAS one to show the same
layout carries a ZFS pool with vdev roles.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from filecat import topology
from filecat.agent_client import ShareMap
from filecat.topology import TopologyError

DATA = Path(__file__).parent / "data"


def load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


@pytest.fixture
def main_doc():
    return load("synology_nas_main.json")["topology"]


@pytest.fixture
def main(main_doc):
    return topology.parse(main_doc)


@pytest.fixture
def truenas():
    return topology.from_response(load("truenas_tank.json"))


def problems(doc, edit):
    doc = copy.deepcopy(doc)
    edit(doc)
    return topology.validate(doc)


def node(doc, node_id):
    return next(n for n in doc["nodes"] if n["id"] == node_id)


# --- fixtures parse -----------------------------------------------------------------------

@pytest.mark.parametrize("name", ["synology_nas_main.json", "synology_nas_old.json", "truenas_tank.json"])
def test_fixtures_are_valid_and_round_trip(name):
    doc = load(name)["topology"]
    assert topology.validate(doc) == []
    again = topology.parse(doc).to_dict()
    assert again == doc


def test_unknown_fields_survive():
    doc = load("synology_nas_old.json")["topology"]
    doc["future"] = {"a": 1}
    doc["nodes"][0]["new_field"] = "kept"
    topo = topology.parse(doc)
    assert topo.to_dict()["future"] == {"a": 1}
    assert topo.nodes["disk:WD-WCC7K1AA"].extra == {"new_field": "kept"}
    assert topo.to_dict() == doc


# --- the hierarchy ------------------------------------------------------------------------

def test_nas_main_tree(main):
    shape = [(n.type, n.name, d) for n, d in main.walk()]
    assert shape[0] == ("pool", "Storage Pool 1", 0)
    assert ("group", "md2", 1) in shape
    assert ("volume", "volume1", 1) in shape
    assert ("share", "Backup", 2) in shape and ("share", "Scratch", 2) in shape
    assert ("lun", "LUN-3", 2) in shape and ("vdisk", "NAS-VM disk 1", 2) in shape
    assert not any(t == "disk" for t, _, _ in shape)


def test_walk_from_a_node_and_ancestors(main):
    vol = next(n for n in main.of_type("volume") if n.name == "volume2")
    assert [(n.name, d) for n, d in main.walk(vol.id)] == [("volume2", 0), ("Scratch", 1)]
    assert [a.type for a in main.ancestors("share:scratch")] == ["volume", "pool"]


def test_disks_of_pool_and_roles(main, truenas):
    assert [r for _, r in main.disks_of(main.of_type("pool")[0].id)] == ["data"] * 5
    pool = truenas.of_type("pool")[0]
    roles = {}
    for disk, role in truenas.disks_of(pool.id):
        roles.setdefault(role, []).append(disk.serial)
    assert sorted(roles) == ["cache", "data", "log", "spare"]
    assert len(roles["data"]) == 6 and roles["log"] == ["S5GXNX0N"] and roles["spare"] == ["3GJ7A07"]


def test_nas_old_one_raid_array():
    old = topology.from_response(load("synology_nas_old.json"))
    group = old.of_type("group")[0]
    assert group.level == "raid1" and len(group.members) == 2
    assert [d.health for d, _ in old.disks_of(group.id)] == ["ok", "warning"]
    assert old.unc_server == "\\\\nas-old"


def test_block_storage_logical_vs_physical(main):
    thick = main.nodes["lun:47f5d7a8-5444-4932-93e3-c712f6aa0130"]
    thin = main.nodes["lun:bd85bc23-c5d3-459e-8801-39d17f096c57"]
    assert thick.thin is False and thick.size_bytes == thick.allocated_bytes
    assert thin.thin is True and thin.allocated_bytes < thin.size_bytes
    image = main.nodes["vdisk:dc8c50db-f451-4367-966a-f6277ac5341b"]
    assert image.attached is False and image.vm is None
    # 512 GiB ROD is never counted: nothing is allocated beyond what was provisioned plus slack
    assert all(n.allocated_bytes < 2 ** 40 * 13 for n in main.of_type("lun", "vdisk"))


def test_truenas_carries_the_same_layout(truenas):
    zvol = truenas.nodes["lun:9000000000000010"]
    assert zvol.kind == "zvol" and zvol.thin and zvol.platform["truenas"]["extent"] == "esx-lun"
    datasets = truenas.of_type("volume")
    assert [n.name for n in datasets] == ["tank", "tank/media", "tank/backups"]
    assert truenas.nodes["vol:9000000000000002"].parent == "vol:9000000000000001"
    assert {g.role for g in truenas.of_type("group")} == {"data", "log", "cache", "spare"}


# --- capacity -----------------------------------------------------------------------------

def test_capacity_summary(main):
    cap = topology.capacity_summary(main)
    assert cap["disk_bytes"] == 5 * 16_000_900_661_248
    assert cap["pool_bytes"] == 4 * 16_000_900_661_248
    assert cap["volume_bytes"] == 61_352_978_841_600 + 2_199_023_255_552
    assert cap["volume_used_bytes"] + cap["volume_free_bytes"] == cap["volume_bytes"]
    assert cap["block_provisioned_bytes"] > cap["block_allocated_bytes"] - 1
    assert cap["share_used_bytes"] > 29 * 10 ** 12


def test_capacity_counts_nested_datasets_once(truenas):
    cap = topology.capacity_summary(truenas)
    assert cap["volume_bytes"] == 71_999_999_000_000
    assert topology.subtree_sum(truenas, "vol:9000000000000001", "used_bytes", "volume") == \
        40_100_000_000_000 + 22_000_000_000_000 + 9_000_000_000_000


def test_subtree_sum_of_block_storage(main):
    vol = "vol:5b0e9c77-1a2d-4f46-8e3b-7a1c9d204e55"
    assert topology.subtree_sum(main, vol, "allocated_bytes", "lun", "vdisk") == \
        12_094_627_905_536 + 1000 * 2 ** 30 + 1_000_727_379_968 + 2_528_876_743_884 + 1_000_727_379_968


# --- validation ---------------------------------------------------------------------------

def test_not_an_object_and_bad_header():
    assert topology.validate([]) == ["topology is not an object"]
    p = topology.validate({"version": 2, "platform": "", "host": {}, "nodes": {}})
    assert any("version" in x for x in p) and any("platform" in x for x in p)
    assert any("host.name" in x for x in p) and "nodes must be a list" in p


def test_from_response_wants_the_generic_shape():
    with pytest.raises(TopologyError, match="no topology"):
        topology.from_response({"ok": True, "volumes": []})


def test_duplicate_ids(main_doc):
    p = problems(main_doc, lambda d: d["nodes"].append(dict(d["nodes"][0])))
    assert any("duplicate id" in x for x in p)


def test_unknown_type_and_missing_id(main_doc):
    def edit(d):
        d["nodes"][0]["type"] = "array"
        d["nodes"].append({"type": "disk"})
    p = problems(main_doc, edit)
    assert any("unknown type" in x for x in p) and any("no usable id" in x for x in p)


def test_dangling_parent(main_doc):
    p = problems(main_doc, lambda d: node(d, "share:backup").update(parent="vol:gone"))
    assert any("not in this topology" in x for x in p)


def test_wrong_parent_type(main_doc):
    p = problems(main_doc, lambda d: node(d, "share:backup").update(parent="share:apps"))
    assert any("cannot sit under" in x for x in p)
    p = problems(main_doc, lambda d: node(d, "disk:ZR5A1B2C").update(parent="vol:5b0e9c77-1a2d-4f46-8e3b-7a1c9d204e55"))
    assert any("a disk has no parent" in x for x in p)


def test_required_parent(main_doc):
    p = problems(main_doc, lambda d: node(d, "share:backup").update(parent=None))
    assert any("needs a parent" in x for x in p)


def test_cycle():
    doc = {"version": 1, "platform": "x", "host": {"name": "h"}, "nodes": [
        {"id": "pool:a", "type": "pool", "parent": "pool:b"},
        {"id": "pool:b", "type": "pool", "parent": "pool:a"}]}
    assert any("cycle" in x for x in topology.validate(doc))
    doc["nodes"][1]["parent"] = "pool:b"
    assert any("cycle" in x for x in topology.validate(doc))


def test_bad_member(main_doc):
    gid = "group:8c1f6a40-2e77-4d3b-b9a5-0c4e1d6f7a22"
    p = problems(main_doc, lambda d: node(d, gid)["members"].append({"disk": "disk:nope", "role": "data"}))
    assert any("not a disk" in x for x in p)
    p = problems(main_doc, lambda d: node(d, gid)["members"].append({"disk": "disk:ZR5A1B2C", "role": "boss"}))
    assert any("member role" in x for x in p)
    p = problems(main_doc, lambda d: node(d, gid)["members"].append({"disk": gid}))
    assert any("not a disk" in x for x in p)


def test_field_types(main_doc):
    def edit(d):
        n = node(d, "vol:5b0e9c77-1a2d-4f46-8e3b-7a1c9d204e55")
        n["size_bytes"] = -1
        n["used_bytes"] = "lots"
        n["free_bytes"] = True
        n["health"] = "fine"
        n["thin"] = "no"
        n["platform"] = {"synology": "x"}
        node(d, "share:backup")["protocols"] = ["ftp"]
        node(d, "share:apps")["unc"] = "nas-main/Apps"
        node(d, "group:8c1f6a40-2e77-4d3b-b9a5-0c4e1d6f7a22")["role"] = "boss"
    p = " | ".join(problems(main_doc, edit))
    for needle in ("size_bytes must be", "used_bytes must be", "free_bytes must be", "health 'fine'",
                   "thin must be", "platform must map", "protocols must be", "unc 'nas-main/Apps'", "role 'boss'"):
        assert needle in p


def test_host_unc_server(main_doc):
    p = problems(main_doc, lambda d: d["host"].update(unc_server="nas-main"))
    assert any("unc_server" in x for x in p)
    p = problems(main_doc, lambda d: d["host"].update(unc_server="\\\\nas-main\\x"))
    assert any("unc_server" in x for x in p)


def test_parse_raises_with_all_problems(main_doc):
    node(main_doc, "share:backup")["parent"] = "vol:gone"
    node(main_doc, "share:apps")["parent"] = "vol:gone2"
    with pytest.raises(TopologyError) as e:
        topology.parse(main_doc)
    assert len(e.value.problems) == 2 and "invalid storage_topology" in str(e.value)


def test_members_only_on_groups_pools_volumes(main_doc):
    p = problems(main_doc, lambda d: node(d, "share:backup").update(members=[{"disk": "disk:ZR5A1B2C"}]))
    assert any("only groups, pools and volumes" in x for x in p)


# --- share_entries / ShareMap -------------------------------------------------------------

def test_share_entries_nas_main(main):
    assert topology.share_entries(main) == {
        "/volume1/Backup": "\\\\nas-main\\Backup",
        "/volume1/ActiveBackupforBusiness": "\\\\nas-main\\ActiveBackupforBusiness",
        "/volume1/Apps": "\\\\nas-main\\Apps",
        "/volume1/homes": "\\\\nas-main\\homes",
        "/volume2/Scratch": "\\\\nas-main\\Scratch",
    }


def test_share_entries_derive_unc_from_host_or_alias():
    old = topology.from_response(load("synology_nas_old.json"))
    assert topology.share_entries(old) == {"/volume1/photo": "\\\\nas-old\\photo",
                                           "/volume1/video": "\\\\nas-old\\video"}
    assert topology.share_entries(old, alias="\\\\Nas-Old.lan")["/volume1/photo"] == "\\\\Nas-Old.lan\\photo"


def test_share_entries_skip_what_cannot_map(truenas):
    # backups has no unc (derived from the host); NFS-only and non-POSIX paths are left out
    doc = load("truenas_tank.json")["topology"]
    doc["nodes"].append({"id": "share:nfsonly", "type": "share", "parent": "vol:9000000000000003",
                         "name": "nfsonly", "path": "/mnt/tank/backups/nfs", "protocols": ["nfs"]})
    doc["nodes"].append({"id": "share:win", "type": "share", "parent": "vol:9000000000000003",
                         "name": "win", "path": "D:\\Data", "protocols": ["smb"]})
    doc["nodes"].append({"id": "share:dup", "type": "share", "parent": "vol:9000000000000003",
                         "name": "Backups", "path": "/mnt/tank/other", "protocols": ["smb"]})
    assert topology.share_entries(topology.parse(doc)) == {
        "/mnt/tank/media": "\\\\truenas\\media", "/mnt/tank/backups": "\\\\truenas\\backups"}


def test_derived_entries_feed_sharemap(main):
    entries = topology.share_entries(main)
    sm = ShareMap("\\\\nas-main", entries, volume=1)
    assert sm.to_catalog_path("/volume2/Scratch/a/b.txt") == "\\\\nas-main\\Scratch\\a\\b.txt"
    assert sm.to_posix_path("\\\\NAS-MAIN\\Scratch\\a\\b.txt") == "/volume2/Scratch/a/b.txt"


def test_config_wins_over_derived(main):
    derived = topology.share_entries(main)
    cfg = {"/volume1/Backup": "\\\\nas-main\\Backups",       # same prefix: repoints the share
           "/mnt/other": "\\\\NAS-MAIN\\APPS"}               # same UNC root, other prefix
    merged = topology.merge_share_maps(derived, cfg)
    assert merged["/volume1/Backup"] == "\\\\nas-main\\Backups"
    assert merged["/mnt/other"] == "\\\\NAS-MAIN\\APPS"
    assert "/volume1/Apps" not in merged
    assert merged["/volume2/Scratch"] == "\\\\nas-main\\Scratch"
    ShareMap("\\\\nas-main", merged)  # no duplicate prefix or root, so the constructor accepts it
    assert topology.merge_share_maps(derived, None) == derived


# --- guests -------------------------------------------------------------------------------

def test_link_guests(main):
    vm = main.nodes["vdisk:ff8a106f-f063-439f-85e9-e21abb402ae1"]
    assert vm.guest_server is None
    n = topology.link_guests(main, {"nas-vm": "\\\\nas-vm", "lun-3": "\\\\other"})
    assert n == 1 and vm.guest_server == "\\\\nas-vm"
    # a guest the agent already knows is not overwritten
    assert main.nodes["lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1"].guest_server == "\\\\nas-zfs"
    assert topology.link_guests(main, {"vdisk:dc8c50db-f451-4367-966a-f6277ac5341b": "\\\\x"}) == 1
