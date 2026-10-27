"""The generic storage topology (topology.py, docs/storage-topology.md): Synology
fixtures modelled on notes 03 and 04, a skeletal TrueNAS one to show the same layout
carries a ZFS pool with vdev roles, and the lab_* set (nas3, the PVEC cluster, pve2,
truenas2, NAS01, a Windows workstation) for the links between hosts.
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

LAB = ["lab_nas3.json", "lab_pvec.json", "lab_pve2.json", "lab_truenas2.json", "lab_nas01.json",
       "lab_lkensel_g5_5090.json"]


@pytest.mark.parametrize("name", ["synology_nas_main.json", "synology_nas_old.json", "truenas_tank.json", *LAB])
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




# --- the lab: links between hosts ---------------------------------------------------------

LUN3 = ("nas3", "lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1")
PVEC_DISK = ("pvec", "disk:naa.6001405f48f1514d6072d4193d989ed9")
SCSI1 = ("pve2", "vdisk:155:scsi1")
SCSI0 = ("pve2", "vdisk:155:scsi0")
POOL_DISK = ("truenas2", "disk:TRUENASDISK002")
BOOT_DISK = ("truenas2", "disk:TRUENASDISK001")
NAS01_META = ("nas01", "disk:vmm-0b10c7a2-58de-4b3f-a641-9d02f7e8c5b1")
NAS01_DATA = ("nas01", "disk:vmm-ff8a106f-f063-439f-85e9-e21abb402ae1")


def lab_docs() -> dict[str, dict]:
    """Fresh topology documents of the lab, keyed by host."""
    docs = [load(n)["topology"] for n in LAB]
    return {d["host"]["name"]: d for d in docs}


def lab(drop=(), edit=None):
    docs = lab_docs()
    if edit:
        edit(docs)
    return [topology.parse(d) for h, d in docs.items() if h not in drop]


def resolved(snaps, overrides=None):
    links, unresolved = topology.resolve_links(snaps, overrides)
    return {link.consumer: link for link in links}, unresolved


def test_lab_nodes_are_what_the_lab_is():
    nas3 = topology.parse(lab_docs()["nas3"])
    luns = nas3.of_type("lun")
    assert [n.name for n in luns] == [f"LUN-{i}" for i in range(1, 8)]
    assert {n.parent for n in luns} == {n.parent for n in luns[:1]}     # LUN health is not collected (nothing readable says it)
    thin = {n.name: n.thin for n in luns}
    assert thin["LUN-1"] is True and thin["LUN-2"] is False and luns[1].size_bytes == luns[1].allocated_bytes
    assert luns[0].allocated_bytes == 0 and luns[0].size_bytes == 10 * 2 ** 30
    assert [n.target for n in luns] == ["Synology iSCSI Target"] * 2 + ["PVEC"] + ["lkensel-g5-5090"] * 4
    vol = nas3.of_type("volume")[0]
    assert round(vol.used_bytes / vol.size_bytes, 4) == 0.8722
    assert [n.name for n in nas3.of_type("vm")] == ["NAS01"]
    assert [d.name for d in nas3.vm_disks(nas3.of_type("vm")[0].id)] == ["NAS01 disk 1", "NAS01 disk 2"]
    # vm nodes are not part of the containment tree
    assert not any(n.type == "vm" for n, _ in nas3.walk())
    pve2 = topology.parse(lab_docs()["pve2"])
    assert sorted(d.platform["proxmox"]["slot"] for d in pve2.vm_disks("vm:155")) == \
        ["efidisk0", "scsi0", "scsi1", "tpmstate0"]
    assert pve2.cluster == "pvec" and topology.parse(lab_docs()["pvec"]).is_cluster


def test_truenas2_chain_resolves_hop_by_hop():
    links, unresolved = resolved(lab())
    assert unresolved == []
    assert topology.chain(links.values(), POOL_DISK) == [POOL_DISK, SCSI1, PVEC_DISK, LUN3]
    assert links[POOL_DISK].via == "serial~vmserial" and links[POOL_DISK].key == "serial:TRUENASDISK002"
    assert links[SCSI1].via == "volid~volid"
    assert links[PVEC_DISK].via == "naa~naa" and links[PVEC_DISK].initiator_ok is True
    # the boot disk goes to the local vdisk and stops there
    assert topology.chain(links.values(), BOOT_DISK) == [BOOT_DISK, SCSI0]


def test_luns_4_to_7_resolve_to_the_workstation_disks():
    links, _ = resolved(lab())
    ws = {c: p for c, p in ((c, l.provider) for c, l in links.items()) if c[0] == "lkensel-g5-5090"}
    assert sorted(p[1].split("lun:")[1][:4] for p in ws.values()) == ["2a93", "83a1", "a006", "bd85"]
    assert all(p[0] == "nas3" for p in ws.values()) and len(ws) == 4
    assert all(links[c].initiator_ok is True for c in ws)
    nas3 = lab()[0]
    assert {nas3.nodes[p[1]].name for p in ws.values()} == {"LUN-4", "LUN-5", "LUN-6", "LUN-7"}


def test_initiator_not_on_the_acl_is_flagged_not_dropped():
    def edit(docs):
        docs["lkensel-g5-5090"]["host"]["name"] = "other-pc"
        docs["lkensel-g5-5090"]["host"]["iqn"] = "iqn.1991-05.com.microsoft:other-pc"
    links, _ = resolved(lab(edit=edit))
    assert [l.initiator_ok for c, l in links.items() if c[0] == "other-pc"] == [False] * 4


def test_nas01_resolves_to_nas3():
    links, _ = resolved(lab())
    assert links[NAS01_META].provider == ("nas3", "vdisk:0b10c7a2-58de-4b3f-a641-9d02f7e8c5b1")
    assert links[NAS01_DATA].provider == ("nas3", "vdisk:ff8a106f-f063-439f-85e9-e21abb402ae1")
    assert links[NAS01_DATA].via == "vmmdisk~vmmdisk"
    servers = topology.guest_servers(lab(), links.values())
    assert servers[("nas3", "vdisk:ff8a106f-f063-439f-85e9-e21abb402ae1")] == ["\\\\nas01"]
    assert servers[LUN3] == ["\\\\truenas2"]            # through three hops; the cluster is not a guest
    assert servers[SCSI1] == ["\\\\truenas2"]


def test_virtual_dsm_disk_without_an_id_needs_a_config_link():
    def edit(docs):
        node(docs["nas01"], NAS01_META[1])["match"] = []
    links, unresolved = resolved(lab(edit=edit))
    assert NAS01_META not in links and NAS01_DATA in links
    assert [(u.node, u.reason) for u in unresolved] == [(NAS01_META, "no provider found")]
    meta_vdisk = "nas3/vdisk:0b10c7a2-58de-4b3f-a641-9d02f7e8c5b1"
    links, unresolved = resolved(lab(edit=edit), {f"NAS01/{NAS01_META[1]}": meta_vdisk})
    assert unresolved == [] and links[NAS01_META].via == "config"
    assert links[NAS01_META].provider == ("nas3", "vdisk:0b10c7a2-58de-4b3f-a641-9d02f7e8c5b1")


def test_naa_rule_on_the_real_lun():
    # nas3's LUN-3: iscsi_lun.conf says f48f1514-..., Proxmox sees scsi-36001405f48f1514d6072d4193d989ed9
    serial = "f48f1514-6072-4193-989e-9e7bfbe6d0e1"
    assert topology.naa_from_unit_serial(serial) == "6001405f48f1514d6072d4193d989ed9"
    assert topology.naa_from_unit_serial(serial.upper()) == "6001405f48f1514d6072d4193d989ed9"
    # only the first 25 characters count
    assert topology.naa_from_unit_serial(serial + "ffff") == topology.naa_from_unit_serial(serial)
    # a character that is not a hex digit becomes the hex digit of ord(c) & 0xF: '-' 0x2d -> d,
    # '_' 0x5f -> f, 'g' 0x67 -> 7, ' ' 0x20 -> 0
    assert topology.naa_from_unit_serial("ab_dg 12-" + "0" * 16) == "6001405abfd70" + "1" + "2" + "d" + "0" * 16
    with pytest.raises(ValueError, match="25 characters"):
        topology.naa_from_unit_serial("f48f1514-6072")


def test_lab_luns_carry_their_unit_serial_and_naa():
    nas3 = topology.parse(lab_docs()["nas3"])
    for lun in nas3.of_type("lun"):
        serial = lun.platform["synology"]["vpd_unit_serial"]
        assert lun.id == f"lun:{serial}"
        assert f"naa:{topology.naa_from_unit_serial(serial)}" in lun.match
    lun3 = nas3.nodes[LUN3[1]]
    assert "naa:6001405f48f1514d6072d4193d989ed9" in lun3.match
    # the Windows workstation's disks are LUN-4..7 under the same rule
    ws = topology.parse(lab_docs()["lkensel-g5-5090"])
    assert {m for d in ws.of_type("disk") for m in d.match} == \
        {m for n in nas3.of_type("lun") if n.target == "lkensel-g5-5090" for m in n.match if m.startswith("naa:")}


def test_lun_acl_shape():
    nas3 = topology.parse(lab_docs()["nas3"])
    lun3 = nas3.nodes[LUN3[1]]
    assert lun3.initiators == [
        {"iqn": "iqn.1993-08.org.debian:01:pve1", "authority": 3},
        {"iqn": "iqn.1993-08.org.debian:01:pve2", "authority": 3},
        {"iqn": "iqn.2000-01.com.synology:default.acl", "authority": 0, "default": True}]
    # every LUN has the default.acl entry; nothing but the raw authority is recorded
    assert all(any(i.get("default") for i in n.initiators) for n in nas3.of_type("lun"))
    # a bare IQN (an older agent) is read as an entry with no authority, and the round trip is stable
    doc = lab_docs()["nas3"]
    node(doc, LUN3[1])["initiators"] = ["iqn.1993-08.org.debian:01:pve2"]
    assert topology.parse(doc).nodes[LUN3[1]].initiators == [{"iqn": "iqn.1993-08.org.debian:01:pve2"}]


def test_naa_match_is_exact_and_ignores_spelling():
    for spelled in ("naa.6001405F48F1514D6072D4193D989ED9", "36001405f48f1514d6072d4193d989ed9"):
        def edit(docs, spelled=spelled):
            node(docs["pvec"], PVEC_DISK[1])["match"] = [f"naa:{spelled}"]
        links, _ = resolved(lab(edit=edit))
        assert links[PVEC_DISK].provider == LUN3, spelled
    # the old hyphen-stripped guess, a different LUN, or a prefix does not link
    for spelled in ("6001405f48f151460724193989e9e7bf", "6001405f48f1514d6072d4193d989ed8",
                    "6001405f48f1514d6072d419"):
        def edit(docs, spelled=spelled):
            node(docs["pvec"], PVEC_DISK[1])["match"] = [f"naa:{spelled}"]
        links, unresolved = resolved(lab(edit=edit))
        assert PVEC_DISK not in links and unresolved[0].node == PVEC_DISK, spelled


def test_a_lun_without_a_naa_key_is_matched_through_its_serial_or_uuid():
    def strip(docs):
        n = node(docs["nas3"], LUN3[1])
        n["match"] = [m for m in n["match"] if not m.startswith("naa:")]
    links, _ = resolved(lab(edit=strip))               # vpd_unit_serial is still there
    assert links[PVEC_DISK].provider == LUN3

    def strip_more(docs):
        strip(docs)
        del node(docs["nas3"], LUN3[1])["platform"]["synology"]["vpd_unit_serial"]
        node(docs["nas3"], LUN3[1])["match"].append("uuid:" + LUN3[1].split(":", 1)[1])
    links, _ = resolved(lab(edit=strip_more))          # only the uuid: the serial equals it
    assert links[PVEC_DISK].provider == LUN3


def test_config_link_overrides_a_match_and_backing():
    wrong = "nas3/lun:47f5d7a8-5444-4932-93e3-c712f6aa0130"
    links, _ = resolved(lab(), {f"pvec/{PVEC_DISK[1]}": wrong})
    assert links[PVEC_DISK].via == "config" and links[PVEC_DISK].provider[1].startswith("lun:47f5")
    with pytest.raises(ValueError, match="host/node-id"):
        topology.resolve_links(lab(), {"nohost": wrong})


def test_explicit_backing_links_and_chains():
    def edit(docs):
        n = node(docs["pvec"], PVEC_DISK[1])
        n["match"] = [m for m in n["match"] if not m.startswith("naa:")]   # the volume id stays: pve2 uses it
        n["backing"] = {"host": "NAS3", "id": LUN3[1]}
    links, unresolved = resolved(lab(edit=edit))
    assert unresolved == [] and links[PVEC_DISK].via == "backing"
    assert topology.chain(links.values(), POOL_DISK)[-1] == LUN3
    topo = topology.parse(lab_docs()["pvec"])
    assert topo.to_dict() == lab_docs()["pvec"]


def test_losing_a_snapshot_leaves_unresolved_links_not_a_crash():
    # LUN-3 goes away (the node is gone, the host is still there)
    def no_lun3(docs):
        docs["nas3"]["nodes"] = [n for n in docs["nas3"]["nodes"] if n["id"] != LUN3[1]]
    links, unresolved = resolved(lab(edit=no_lun3))
    assert [u.node for u in unresolved] == [PVEC_DISK]
    assert unresolved[0].wanted.startswith("naa:6001405f48f1")
    assert topology.chain(links.values(), POOL_DISK) == [POOL_DISK, SCSI1, PVEC_DISK]
    # nas3 is not scanned at all: every disk that was made of it is unresolved, nothing else changes
    links, unresolved = resolved(lab(drop=("nas3",)))
    assert {u.node for u in unresolved} == {PVEC_DISK, NAS01_META, NAS01_DATA} | \
        {(("lkensel-g5-5090"), n.id) for n in lab()[5].of_type("disk") if n.virtual}
    assert POOL_DISK in links and links[POOL_DISK].provider == SCSI1
    # pve2 is gone: truenas2's disks have no provider
    links, unresolved = resolved(lab(drop=("pve2",)))
    assert {u.node for u in unresolved if u.node[0] == "truenas2"} == {POOL_DISK, BOOT_DISK}
    assert PVEC_DISK in links
    # truenas2 is gone (the temporary setup is torn down): everything else still links
    links, unresolved = resolved(lab(drop=("truenas2",)))
    assert unresolved == [] and SCSI1 in links and POOL_DISK not in links


def test_explicit_backing_to_a_missing_host_or_node_is_unresolved():
    def edit(docs):
        node(docs["pvec"], PVEC_DISK[1]).update(match=[], backing={"host": "nas9", "id": "lun:x"})
        node(docs["truenas2"], POOL_DISK[1]).update(match=[], backing={"host": "pve2", "id": "vdisk:155:scsi9"})
        node(docs["nas01"], NAS01_DATA[1]).update(match=[], backing={"host": "nas3", "id": "share:backup"})
    links, unresolved = resolved(lab(edit=edit))
    reasons = {u.node: u.reason for u in unresolved}
    assert reasons[PVEC_DISK] == "no snapshot for host nas9"
    assert reasons[POOL_DISK] == "pve2 has no node vdisk:155:scsi9"
    assert "is a volume" in reasons[NAS01_DATA] or "is a share" in reasons[NAS01_DATA]


def test_ambiguous_match_is_unresolved():
    def edit(docs):
        twin = dict(node(docs["pve2"], SCSI1[1]), id="vdisk:155:scsi2")
        docs["pve2"]["nodes"].append(twin)
    links, unresolved = resolved(lab(edit=edit))
    assert POOL_DISK not in links
    assert [u.reason.split(":")[0] for u in unresolved if u.node == POOL_DISK] == ["ambiguous"]


def test_a_vm_moved_to_another_node_keeps_its_storage_links():
    def migrate(docs):
        pve2 = docs["pve2"]
        keep = {"vm:155", "vdisk:155:scsi1"}   # the cluster-scope disk moves; local-btrfs stays behind
        moved = [dict(n) for n in pve2["nodes"] if n["id"] in keep]
        pve2["nodes"] = [n for n in pve2["nodes"] if n["id"] not in keep and not n["id"].startswith("vdisk:155")]
        docs["pve3"] = {"version": 1, "platform": "proxmox", "collected_at": "2026-10-22T10:00:00Z",
                        "host": {"name": "pve3", "cluster": "pvec"}, "nodes": moved}
    snaps = lab(edit=migrate)
    links, unresolved = resolved(snaps)
    moved_disk = ("pve3", "vdisk:155:scsi1")
    assert links[POOL_DISK].provider == moved_disk            # re-resolved by serial, no edit to truenas2
    assert links[moved_disk].provider == PVEC_DISK            # the storage did not move
    assert topology.chain(links.values(), POOL_DISK) == [POOL_DISK, moved_disk, PVEC_DISK, LUN3]
    assert {u.node for u in unresolved} == {BOOT_DISK}         # its local disk was not carried along
    pve3 = next(t for t in snaps if t.key == "pve3")
    assert [d.id for d in pve3.vm_disks("vm:155")] == ["vdisk:155:scsi1"] and pve3.cluster == "pvec"


# --- physical totals ------------------------------------------------------------------------

def test_physical_total_counts_lun3_and_nas01_once():
    snaps = lab()
    links, unresolved = topology.resolve_links(snaps)
    phys = topology.physical_summary(snaps, links, unresolved)
    by = {t.key: t for t in snaps}
    nas3, pve2, ws = by["nas3"], by["pve2"], by["lkensel-g5-5090"]
    vol1 = nas3.of_type("volume")[0]
    local = pve2.nodes["vol:3b9f6a02-c1d7-4e58-b240-8a7e5d913c60"]
    c_drive = ws.nodes["vol:{c5a1b3d2-0e47-4f89-96a8-71d2e0b5c3f4}"]
    assert phys["volume_used_bytes"] == vol1.used_bytes + local.used_bytes + c_drive.used_bytes
    assert phys["by_host"] == {"nas3": vol1.used_bytes, "pve2": local.used_bytes,
                               "lkensel-g5-5090": c_drive.used_bytes}
    excluded = {(e["host"], e["name"]) for e in phys["excluded"]}
    assert {("truenas2", "tank"), ("truenas2", "boot-pool"), ("nas01", "volume1"), ("pvec", "PVEC"),
            ("lkensel-g5-5090", "E:"), ("lkensel-g5-5090", "H:")} <= excluded
    assert not {h for h, _ in excluded} & {"nas3", "pve2"}
    # the naive sum counts those bytes a second time; the difference is exactly what was excluded
    naive = sum(v.used_bytes or 0 for t in snaps for v in t.of_type("volume") if v.parent is None or
                t.nodes[v.parent].type == "pool")
    assert naive - phys["volume_used_bytes"] == sum(e["bytes"] for e in phys["excluded"] if e["type"] == "volume")
    lun3_alloc = by["nas3"].nodes[LUN3[1]].allocated_bytes
    assert lun3_alloc < vol1.used_bytes                         # inside Volume 1, not on top of it
    # physical disks: nas3's four, the NVMe of pve2 and of the workstation; every virtual disk is excluded
    assert phys["disk_bytes"] == 4 * 16_000_900_661_248 + 1_000_204_886_016 + 2_000_398_934_016
    assert phys["unresolved_disk_bytes"] == 0 and phys["excluded_disk_bytes"] > 11_000 * 2 ** 30 * 2
    # logical bytes are still reported: truenas2's migrated share and NAS01's shares
    assert phys["share_used_bytes"] == sum(s.used_bytes or 0 for t in snaps for s in t.of_type("share"))
    assert phys["share_used_bytes"] > 10_800_000_000_000 + 1_300_000_000_000


def test_truenas2_boot_disk_is_counted_under_pve2s_local_storage():
    snaps = lab()
    links, _ = topology.resolve_links(snaps)
    phys = topology.physical_summary(snaps, links)
    assert ("truenas2", "boot-pool") in {(e["host"], e["name"]) for e in phys["excluded"]}
    pve2 = next(t for t in snaps if t.key == "pve2")
    scsi0 = pve2.nodes[SCSI0[1]]
    assert pve2.nodes[scsi0.parent].name == "local-btrfs" and phys["by_host"]["pve2"] == 142_000_000_000


def test_without_links_everything_is_counted_and_the_rule_is_per_disk():
    snaps = lab()
    phys = topology.physical_summary(snaps, [])
    assert phys["excluded"] == [] and phys["volume_used_bytes"] > 50_000_000_000_000
    # one backed disk of two does not exclude a volume that also sits on a real disk
    def edit(docs):
        tank = node(docs["truenas2"], "pool:9100000000000001")
        tank["members"].append({"disk": "disk:TRUENASDISK001", "role": "data"})
        node(docs["truenas2"], "disk:TRUENASDISK001")["match"] = []
        node(docs["truenas2"], "disk:TRUENASDISK001")["virtual"] = False
    snaps = lab(edit=edit)
    links, unresolved = topology.resolve_links(snaps)
    phys = topology.physical_summary(snaps, links, unresolved)
    assert ("truenas2", "tank") not in {(e["host"], e["name"]) for e in phys["excluded"]}
    assert phys["by_host"]["truenas2"] == 10_900_000_000_000 + 3 * 2 ** 30   # tank, and boot-pool (now unbacked)


def test_unresolved_virtual_disks_are_counted_and_reported():
    snaps = lab(drop=("nas3",))
    links, unresolved = topology.resolve_links(snaps)
    phys = topology.physical_summary(snaps, links, unresolved)
    assert phys["unresolved_disk_bytes"] == 11000 * 2 ** 30 + 20 * 2 ** 30 + 2000 * 2 ** 30 + 100 * 2 ** 30 * 3 \
        + 1000 * 2 ** 30
    assert ("pvec", "PVEC") not in {(e["host"], e["name"]) for e in phys["excluded"]}


# --- link validation ------------------------------------------------------------------------

def test_link_fields_validate():
    docs = lab_docs()

    def check(host, node_id, edit, needle):
        doc = copy.deepcopy(docs[host])
        edit(node(doc, node_id))
        assert any(needle in p for p in topology.validate(doc)), needle

    check("pvec", PVEC_DISK[1], lambda n: n.update(backing="nas3/lun"), "backing must be an object")
    check("pvec", PVEC_DISK[1], lambda n: n.update(backing={"host": "nas3"}), "backing must be an object")
    check("pvec", PVEC_DISK[1], lambda n: n.update(backing={"host": "PVEC", "id": "x"}), "backing joins different hosts")
    check("pvec", "pool:PVEC", lambda n: n.update(backing={"host": "nas3", "id": "x"}), "can have a backing, not a pool")
    check("pvec", PVEC_DISK[1], lambda n: n.update(match=["naa6001"]), "must look like kind:value")
    check("pvec", PVEC_DISK[1], lambda n: n.update(match="naa:6001"), "match must be a list")
    check("pvec", PVEC_DISK[1], lambda n: n.update(virtual="yes"), "virtual must be true or false")
    check("pvec", "pool:PVEC", lambda n: n.update(virtual=True), "can be virtual")
    check("nas3", "vol:5e2c8d41-90ab-4c17-a3f6-7b1d0e94c258", lambda n: n.update(initiators=["x"]), "only a lun has initiators")
    check("nas3", LUN3[1], lambda n: n.update(initiators=[""]), "initiators must be a list")
    check("nas3", LUN3[1], lambda n: n.update(initiators=[{"iqn": "x", "authority": "3"}]),
          "initiators must be a list")
    check("nas3", "vdisk:ff8a106f-f063-439f-85e9-e21abb402ae1", lambda n: n.update(vm={"id": "vm:nope"}),
          "is not a vm node")
    check("nas3", "vm:dead21af-c947-4f6a-9b25-1535ccd2dd75", lambda n: n.update(parent=LUN3[1]), "cannot sit under")
    bad = copy.deepcopy(docs["pve2"])
    bad["host"].update(cluster="", kind="rack")
    p = " | ".join(topology.validate(bad))
    assert "host.cluster" in p and "host.kind" in p


def test_old_style_vm_ids_without_vm_nodes_still_validate(main_doc):
    # nas-main (note 03 shape) names its VMs by uuid and has no vm nodes
    assert topology.validate(main_doc) == []


def test_snapshots_from_response_carries_the_cluster():
    reply = load("lab_pve2.json")
    reply["cluster_topology"] = load("lab_pvec.json")["topology"]
    snaps = topology.snapshots_from_response(reply)
    assert [t.key for t in snaps] == ["pve2", "pvec"]
    assert len(topology.snapshots_from_response(load("lab_nas3.json"))) == 1
    reply["cluster_topology"]["host"]["name"] = ""
    with pytest.raises(TopologyError):
        topology.snapshots_from_response(reply)
