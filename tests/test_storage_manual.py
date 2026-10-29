"""Storage written by hand in filecat.toml: [[storage.hosts]], [[storage.links]], how they
resolve against snapshots (topology.resolve), and `filecat storage links`.
The case: truenas2, a host with no agent whose pool is one LUN of nas3 (tests/data/lab_nas3.json).
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from filecat import cli, config, topology

DATA = Path(__file__).parent / "data"
LUN3_ID = "lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1"
LUN3 = ("nas3", LUN3_ID)
TANK_DISK = ("truenas2", "disk:tank-disk")

TRUENAS2 = r"""
[[storage.hosts]]
name = "truenas2"
unc_server = '\\truenas2'
platform = "truenas"
nodes = [
  { type = "disk",   name = "tank-disk", virtual = true, size = "10.74 TiB" },
  { type = "pool",   name = "tank", disks = ["tank-disk"], size = "10 TiB" },
  { type = "volume", name = "tank", used = "2 TiB", size = "10 TiB" },
  { type = "share",  name = "Media", used = "1.5 TiB" },
  { type = "share",  name = "Archive" },
]

[[storage.links]]
from = "truenas2/disk:tank-disk"
to = "nas3/lun:LUN-3"
note = "tank is one iSCSI LUN on nas3"
"""


def storage(text: str = TRUENAS2) -> config.StorageConfig:
    return config.load_storage(tomllib.loads(text))


def nas3() -> topology.Topology:
    return topology.from_response(json.loads((DATA / "lab_nas3.json").read_text(encoding="utf-8")))


def lab_snaps() -> list[topology.Topology]:
    names = ["lab_nas3.json", "lab_pvec.json", "lab_pve2.json", "lab_truenas2.json", "lab_nas01.json",
             "lab_lkensel_g5_5090.json"]
    return [topology.from_response(json.loads((DATA / n).read_text(encoding="utf-8"))) for n in names]


# --- loading ------------------------------------------------------------------------------

def test_truenas2_loads_as_a_manual_snapshot_and_a_link():
    cfg = storage()
    (host,) = cfg.hosts
    assert (host.name, host.unc_server, host.platform) == ("truenas2", "\\\\truenas2", "truenas")
    assert (host.source, host.origin) == ("manual", "config")
    assert sorted(host.nodes) == ["disk:tank-disk", "pool:tank", "share:archive", "share:media", "volume:tank"]
    # the pool lists the disk, the volume went into the only pool, the shares into the only volume
    assert host.nodes["pool:tank"].members == [{"disk": "disk:tank-disk", "role": "data"}]
    assert host.nodes["volume:tank"].parent == "pool:tank"
    assert host.nodes["share:media"].parent == "volume:tank"
    assert host.nodes["share:media"].unc == "\\\\truenas2\\Media"
    assert host.nodes["share:media"].protocols == ["smb"]
    assert host.nodes["disk:tank-disk"].size_bytes == round(10.74 * 2 ** 40) and host.nodes["disk:tank-disk"].virtual
    assert topology.validate(host.to_dict()) == []
    assert topology.parse(host.to_dict()).source == "manual"          # survives a round trip
    (link,) = cfg.links
    assert (link.from_ref, link.to_ref, link.source) == ("truenas2/disk:tank-disk", "nas3/lun:LUN-3", "config")
    assert link.note == "tank is one iSCSI LUN on nas3"
    assert config.load_storage({}) == config.StorageConfig()


def test_share_entries_come_from_a_manual_host_with_paths():
    cfg = storage(TRUENAS2.replace('name = "Media"', 'name = "Media", path = "/mnt/tank/media"'))
    assert topology.share_entries(cfg.hosts[0]) == {"/mnt/tank/media": "\\\\truenas2\\Media"}


def test_parse_size():
    assert topology.parse_size(5) == 5 and topology.parse_size("1024") == 1024
    assert topology.parse_size("2 TiB") == 2 * 2 ** 40 and topology.parse_size("500GB") == 500 * 10 ** 9
    for bad in ("big", "-1", -1, 1.5, True, "10 XB"):
        with pytest.raises(ValueError):
            topology.parse_size(bad)


def error(text: str) -> str:
    with pytest.raises(config.ConfigError) as exc:
        storage(text)
    return str(exc.value)


HOST = '[[storage.hosts]]\nname = "h"\n'


@pytest.mark.parametrize("text, needle", [
    ("storage = 1\n", "storage: write"),
    ("[storage]\nvolumes = []\n", "unknown key 'volumes'"),
    ("[storage]\nlinks = {}\n", "double brackets"),
    ("[[storage.hosts]]\nplatform = 'x'\n", "#1: name is required"),
    ('[[storage.hosts]]\nname = "a b"\n', "must not contain spaces"),
    ('[[storage.hosts]]\nname = "h"\ncolour = 1\n', "(h): unknown key 'colour'"),
    ('[[storage.hosts]]\nname = "h"\nunc_server = "truenas2"\n', "unc_server"),
    ('[[storage.hosts]]\nname = "h"\nnodes = 3\n', "nodes wants a list"),
    (HOST + 'nodes = [{ name = "x" }]\n', "type = None"),
    (HOST + 'nodes = [{ type = "cloud", name = "x" }]\n', "type = 'cloud'"),
    (HOST + 'nodes = [{ type = "disk" }]\n', "name is required"),
    (HOST + 'nodes = [{ type = "disk", name = "d", colour = 1 }]\n', "unknown key 'colour'"),
    (HOST + 'nodes = [{ type = "disk", name = "d" }, { type = "disk", name = "d" }]\n', "used twice"),
    (HOST + 'nodes = [{ type = "disk", name = "d", size = "lots" }]\n', "size: 'lots' is not a size"),
    (HOST + 'nodes = [{ type = "pool", name = "p", disks = ["nope"] }]\n', "names no node of this host"),
    (HOST + 'nodes = [{ type = "share", name = "s" }]\n', "needs parent"),
    (HOST + 'nodes = [{ type = "disk", name = "x" }, { type = "pool", name = "x", disks = ["x"] }, '
            '{ type = "pool", name = "y", disks = ["x"], parent = "x" }]\n', "ambiguous"),
    (HOST + 'nodes = [{ type = "disk", name = "d", parent = "d" }]\n', "invalid storage_topology"),
    (TRUENAS2 + TRUENAS2.split("[[storage.links]]")[0], "name 'truenas2' is used twice"),
    ('[[storage.links]]\nto = "a/disk:x"\n', "#1: from is required"),
    ('[[storage.links]]\nfrom = "a/disk:x"\nto = "b"\n', "to: link 'b' must look like host/node-id"),
    ('[[storage.links]]\nfrom = "a/x"\nto = "b/disk:y"\n', "must be a node id or type:name"),
    ('[[storage.links]]\nfrom = "a/cloud:x"\nto = "b/disk:y"\n', "type being one of"),
    ('[[storage.links]]\nfrom = "a/disk:x"\nto = "A/disk:y"\n', "different hosts"),
    ('[[storage.links]]\nfrom = "a/disk:x"\nto = "b/disk:y"\nnote = 3\n', "note wants a string"),
    ('[[storage.links]]\nfrom = "a/disk:x"\nto = "b/disk:y"\nwhy = "?"\n', "unknown key 'why'"),
    ('[[storage.links]]\nfrom = "a/disk:x"\nto = "b/disk:y"\n[[storage.links]]\nfrom = "a/disk:x"\n'
     'to = "c/disk:z"\n', "linked twice"),
])
def test_config_errors(text, needle):
    assert needle in error(text)


def test_a_link_to_an_unknown_host_is_not_a_config_error():
    cfg = storage('[[storage.links]]\nfrom = "ghost/disk:x"\nto = "nowhere/lun:y"\n')
    res = topology.resolve([], manual=cfg.links)
    assert res.links == [] and res.manual[0].status == "unresolved"
    assert res.manual[0].reason == "no snapshot for host ghost"
    assert [(u.node, u.wanted) for u in res.unresolved] == [(("ghost", "disk:x"), "nowhere/lun:y")]


def test_config_init_writes_a_commented_example_that_loads_when_uncommented():
    text = config.render()
    assert "storage" not in tomllib.loads(text)
    lines = [ln[1:].strip() for ln in config.STORAGE_EXAMPLE]
    toml_lines = [ln for ln in lines if ln.startswith(("[[", "name =", "unc_server =", "platform =", "nodes =",
                                                      "{", "]", "from =", "to =", "note ="))]
    cfg = storage("\n".join(toml_lines))
    assert [h.name for h in cfg.hosts] == ["truenas2"]
    assert cfg.links[0].to_ref == "nas3/lun:LUN-3"
    assert cfg.hosts[0].nodes["share:share1"].unc == "\\\\truenas2\\Share1"
    assert "[[storage.links]]" in text and 'to = "nas3/lun:LUN-3"' in text


# --- resolving ----------------------------------------------------------------------------

def test_manual_truenas2_resolves_to_nas3_with_no_proxmox_snapshots():
    cfg = storage()
    snaps = [nas3(), *cfg.hosts]
    res = topology.resolve(snaps, manual=cfg.links)
    (link,) = res.links
    assert (link.consumer, link.provider, link.via) == (TANK_DISK, LUN3, "config")
    assert link.note == "tank is one iSCSI LUN on nas3"
    assert [(r.status, r.consumer, r.provider) for r in res.manual] == [("resolved", TANK_DISK, LUN3)]
    assert res.conflicts == []
    assert (TANK_DISK in {u.node for u in res.unresolved}) is False
    # the virtual disk is backed, so tank is excluded; its shares still count as logical bytes
    summary = topology.physical_summary(snaps, res.links, res.unresolved)
    assert {(x["id"], x["backed_by"]) for x in summary["excluded"] if x["host"] == "truenas2"} == \
        {("pool:tank", "nas3/" + LUN3_ID), ("volume:tank", "nas3/" + LUN3_ID)}
    unlinked = topology.physical_summary(snaps, [], [])
    assert summary["pool_bytes"] == unlinked["pool_bytes"] - 10 * 2 ** 40
    assert summary["volume_bytes"] == unlinked["volume_bytes"] - 10 * 2 ** 40
    assert summary["volume_used_bytes"] == unlinked["volume_used_bytes"] - 2 * 2 ** 40
    assert summary["disk_bytes"] == unlinked["disk_bytes"] - round(10.74 * 2 ** 40)
    assert summary["excluded_disk_bytes"] == round(10.74 * 2 ** 40)
    assert summary["share_used_bytes"] == unlinked["share_used_bytes"]       # logical bytes stay
    assert topology.guest_servers(snaps, res.links)[LUN3] == ["\\\\truenas2"]


def test_the_same_host_from_an_agent_replaces_the_manual_one():
    cfg = storage()
    real = topology.from_response(json.loads((DATA / "lab_truenas2.json").read_text(encoding="utf-8")))
    res = topology.resolve([*cfg.hosts, nas3(), real], manual=cfg.links)
    assert res.manual[0].status == "unresolved" and "no node disk:tank-disk" in res.manual[0].reason


@pytest.mark.parametrize("ref, status", [
    ("nas3/lun:LUN-3", "resolved"),                 # by name
    ("nas3/lun:lun-3", "resolved"),                 # case-insensitively
    ("nas3/" + LUN3_ID, "resolved"),                # by id
    ("NAS3/" + LUN3_ID, "resolved"),                # the host is case-insensitive
    ("nas3/lun:LUN-99", "unresolved"),
    ("nas3/vdisk:LUN-3", "unresolved"),             # the type counts
    ("nas3/lun:f48f1514-6072-4193-989e-9e7bfbe6d0e0", "unresolved"),
])
def test_name_based_refs(ref, status):
    link = topology.ManualLink("truenas2/disk:tank-disk", ref)
    res = topology.resolve([nas3(), *storage().hosts], manual=[link])
    assert res.manual[0].status == status
    if status == "resolved":
        assert res.manual[0].provider == LUN3
    else:
        assert "has no node" in res.manual[0].reason
        assert res.unresolved[-1].wanted == "nas3/" + ref.split("/", 1)[1]


def test_an_ambiguous_name_is_unresolved_and_names_the_candidates():
    snap = nas3()
    snap.nodes["lun:2a93d1c8-71e4-4b60-8c25-5f0e9a6b7d14"].name = "LUN-3"
    link = topology.ManualLink("truenas2/disk:tank-disk", "nas3/lun:LUN-3")
    res = topology.resolve([snap, *storage().hosts], manual=[link])
    (r,) = res.manual
    assert r.status == "unresolved" and r.reason.startswith("ambiguous: nas3 has 2 lun nodes named 'LUN-3'")
    assert LUN3_ID in r.reason and "2a93d1c8" in r.reason
    assert res.links == []
    link = topology.ManualLink("truenas2/disk:tank-disk", "nas3/" + LUN3_ID)   # the id is always exact
    assert topology.resolve([snap, *storage().hosts], manual=[link]).manual[0].status == "resolved"


def test_a_link_may_start_at_a_pool_or_a_share_when_one_disk_is_beneath_it():
    for start in ("pool:tank", "volume:tank", "share:media", "share:Media", "pool:TANK"):
        link = topology.ManualLink(f"truenas2/{start}", "nas3/lun:LUN-3")
        res = topology.resolve([nas3(), *storage().hosts], manual=[link])
        assert (res.manual[0].status, res.manual[0].consumer) == ("resolved", TANK_DISK), start
    # two disks under the pool: say which
    text = TRUENAS2.replace('{ type = "pool",   name = "tank", disks = ["tank-disk"]',
                            '{ type = "disk", name = "second" },\n  { type = "pool",   name = "tank", '
                            'disks = ["tank-disk", "second"]')
    cfg = storage(text)
    res = topology.resolve([nas3(), *cfg.hosts], manual=[topology.ManualLink("truenas2/pool:tank", "nas3/lun:LUN-3")])
    assert res.manual[0].status == "unresolved" and "sits on 2 disks" in res.manual[0].reason
    link = topology.ManualLink("truenas2/disk:second", "nas3/lun:LUN-3")
    assert topology.resolve([nas3(), *cfg.hosts], manual=[link]).manual[0].status == "resolved"


def test_a_link_must_join_two_hosts_and_a_missing_target_beats_an_automatic_match():
    res = topology.resolve(lab_snaps(), manual=[topology.ManualLink("pvec/disk:naa.6001405f48f1514d6072d4193d989ed9",
                                                                     "pvec/pool:PVEC")])
    assert res.manual[0].reason == "a link joins different hosts"
    # the manual link names a node nas3 does not have: the consumer is unresolved, the automatic match
    # is not used behind the config's back
    link = topology.ManualLink("pvec/disk:naa.6001405f48f1514d6072d4193d989ed9", "nas3/lun:LUN-77")
    res = topology.resolve(lab_snaps(), manual=[link])
    consumer = ("pvec", "disk:naa.6001405f48f1514d6072d4193d989ed9")
    assert consumer not in {l.consumer for l in res.links}
    assert any(u.node == consumer and "no node lun:LUN-77" in u.reason for u in res.unresolved)


def test_manual_link_wins_over_an_automatic_match_and_the_conflict_is_reported():
    wrong = topology.ManualLink("pvec/disk:naa.6001405f48f1514d6072d4193d989ed9", "nas3/lun:LUN-2", "oops")
    res = topology.resolve(lab_snaps(), manual=[wrong])
    consumer = ("pvec", "disk:naa.6001405f48f1514d6072d4193d989ed9")
    link = next(l for l in res.links if l.consumer == consumer)
    assert link.provider[1].startswith("lun:47f5d7a8") and link.via == "config" and link.note == "oops"
    (conflict,) = res.conflicts
    assert conflict.consumer == consumer and conflict.manual is link
    assert conflict.automatic.provider == LUN3 and conflict.automatic.via == "naa~naa"
    (r,) = res.manual
    assert r.status == "conflict" and r.automatic is conflict.automatic
    # agreeing with the automatic match is no conflict, and the link is still marked as manual
    same = topology.ManualLink("pvec/disk:naa.6001405f48f1514d6072d4193d989ed9", "nas3/lun:LUN-3")
    res = topology.resolve(lab_snaps(), manual=[same])
    assert res.conflicts == [] and res.manual[0].status == "resolved"
    assert next(l for l in res.links if l.consumer == consumer).via == "config"
    # no link at all for that consumer: the automatic ones are as before
    assert topology.resolve(lab_snaps()).conflicts == []


def test_a_manual_link_fills_in_for_a_node_the_rules_could_not_link():
    def snaps():
        s = lab_snaps()
        meta = next(t for t in s if t.key == "nas01").nodes["disk:vmm-0b10c7a2-58de-4b3f-a641-9d02f7e8c5b1"]
        meta.match = []
        return s
    assert [u.reason for u in topology.resolve(snaps()).unresolved] == ["no provider found"]
    link = topology.ManualLink("nas01/disk:vmm-0b10c7a2-58de-4b3f-a641-9d02f7e8c5b1",
                               "nas3/vdisk:0b10c7a2-58de-4b3f-a641-9d02f7e8c5b1")
    res = topology.resolve(snaps(), manual=[link])
    assert res.unresolved == [] and res.conflicts == [] and res.manual[0].status == "resolved"


def test_resolve_links_is_the_pair_form():
    cfg = storage()
    links, unresolved = topology.resolve_links([nas3(), *cfg.hosts], manual=cfg.links)
    assert [l.provider for l in links] == [LUN3] and unresolved == []


# --- the CLI ------------------------------------------------------------------------------

@pytest.fixture
def cfg_file(tmp_path):
    path = tmp_path / "filecat.toml"
    path.write_text(TRUENAS2, encoding="utf-8")
    return path


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr()


def test_storage_links_lists_without_snapshots(cfg_file, capsys):
    # the manual host is a snapshot of its own, so the link is checked against it, but nas3 is unknown
    code, out = run(capsys, "--config", str(cfg_file), "storage", "links")
    assert code == 1
    assert "host truenas2  \\\\truenas2  truenas, 5 nodes" in out.out
    assert "UNRESOLVED truenas2/disk:tank-disk -> nas3/lun:LUN-3" in out.out
    assert "no snapshot for host nas3" in out.out


def test_storage_links_resolves_against_snapshots(cfg_file, capsys):
    code, out = run(capsys, "--config", str(cfg_file), "storage", "links", "--snapshot", str(DATA / "lab_nas3.json"))
    assert code == 0, out
    assert "RESOLVED   truenas2/disk:tank-disk -> nas3/lun:LUN-3" in out.out
    assert f"ends at nas3/{LUN3_ID}" in out.out
    assert "not counted: truenas2/pool:tank" in out.out and "physical, over the snapshots" in out.out


def test_storage_links_json(cfg_file, capsys):
    code, out = run(capsys, "--config", str(cfg_file), "storage", "links", "--json",
                    "--snapshot", str(DATA / "lab_nas3.json"))
    doc = json.loads(out.out)
    assert code == 0 and [h["name"] for h in doc["hosts"]] == ["truenas2"]
    (row,) = doc["links"]
    assert row["status"] == "resolved" and row["provider"] == "nas3/" + LUN3_ID
    assert row["consumer"] == "truenas2/disk:tank-disk" and row["note"] == "tank is one iSCSI LUN on nas3"
    assert doc["physical_summary"]["excluded"][0]["id"] == "pool:tank"
    assert doc["unresolved"] == []


def test_storage_links_reports_a_conflict(tmp_path, capsys):
    cfg = tmp_path / "filecat.toml"
    cfg.write_text('[[storage.links]]\nfrom = "pvec/disk:naa.6001405f48f1514d6072d4193d989ed9"\n'
                   'to = "nas3/lun:LUN-2"\n', encoding="utf-8")
    snaps = [str(DATA / n) for n in ("lab_nas3.json", "lab_pvec.json")]
    code, out = run(capsys, "--config", str(cfg), "storage", "links",
                    "--snapshot", snaps[0], "--snapshot", snaps[1])
    assert code == 1
    assert "CONFLICT" in out.out and "the config wins" in out.out and "naa~naa" in out.out


def test_storage_links_without_config_or_with_bad_files(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("FILECAT_CONFIG", "none")
    code, out = run(capsys, "storage", "links")
    assert code == 0 and "no [[storage.hosts]]" in out.out
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, out = run(capsys, "storage", "links", "--snapshot", str(bad))
    assert code == 2 and "bad.json" in out.err
    bare = tmp_path / "bare.json"       # a bare topology, not a reply
    bare.write_text(json.dumps(json.loads((DATA / "lab_nas3.json").read_text(encoding="utf-8"))["topology"]),
                    encoding="utf-8")
    code, out = run(capsys, "storage", "links", "--snapshot", str(bare))
    assert code == 0


def test_config_show_lists_hosts_and_links(cfg_file, capsys):
    code, out = run(capsys, "--config", str(cfg_file), "config", "show")
    assert code == 0
    assert "storage:     1 manual hosts, 1 links" in out.out
    assert "host truenas2" in out.out and "link truenas2/disk:tank-disk -> nas3/lun:LUN-3" in out.out
    cfg_file.write_text('[[storage.links]]\nfrom = "x"\nto = "y"\n', encoding="utf-8")
    code, out = run(capsys, "--config", str(cfg_file), "config", "show")
    assert code == 1 and "storage:     invalid:" in out.out
