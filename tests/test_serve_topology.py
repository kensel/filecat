"""`GET /api/topology` (topology_view.py): the stored lab snapshots, a host written by hand in
filecat.toml, an [[agents]] host with no snapshot, shares joined to catalog roots (case
insensitively, with roots beneath a share), roots no share accounts for, the links between
hosts, and the empty state."""
from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from filecat import serve, topology, topology_store
from filecat.backends.sqlite import SqliteBackend
from filecat.record import new_document
from tests.test_storage_manual import TRUENAS2

DATA = Path(__file__).parent / "data"
LUN3 = "lun:f48f1514-6072-4193-989e-9e7bfbe6d0e1"
FP = "ab" * 32
AGENTS = (f'\n[[agents]]\nname = "ghost-agent"\nhost = "10.9.9.9"\ncert_sha256 = "{FP}"\ntoken = "x"\n'
          "alias = '\\\\ghost'\n")


def snapshot(name: str) -> topology.Topology:
    return topology.from_response(json.loads((DATA / f"lab_{name}.json").read_text(encoding="utf-8")))


def start(db: str, config: str | None = None):
    args = SimpleNamespace(backend="sqlite", out=db, dsn=None, quiet=True, no_save=False, config=config)
    catalog = serve.Catalog(args)
    server = ThreadingHTTPServer(("127.0.0.1", 0), serve.make_handler(catalog, b"<html></html>"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return catalog, server


def get(base, path, **params):
    with urllib.request.urlopen(f"{base}{path}?{urllib.parse.urlencode(params)}") as r:
        return json.load(r)


def fetch(db: str, config: str | None) -> dict:
    catalog, server = start(db, config)
    try:
        return get(f"http://127.0.0.1:{server.server_address[1]}", "/api/topology")
    finally:
        server.shutdown()
        server.server_close()
        catalog.close()


@pytest.fixture
def paths(tmp_path):
    db = str(tmp_path / "c.sqlite")
    with SqliteBackend(db) as b:
        for name in ("nas3", "pvec", "pve2", "nas01"):
            topology_store.save_snapshot(b, snapshot(name))
        for root, n in ((r"\\nas3\Backup", 3), (r"\\NAS3\homes", 2), (r"\\nas3\homes\jdoe", 4), (r"\\elsewhere\data", 1)):
            b.put(new_document(root, "", kind="dir"))
            for i in range(n):
                b.put(new_document(root, f"f{i}.bin", kind="data", size=100 * (i + 1)))
    cfg = tmp_path / "filecat.toml"
    cfg.write_text(TRUENAS2.replace("nas3/lun:LUN-3", f"nas3/{LUN3}") + AGENTS, encoding="utf-8")
    return db, str(cfg)


@pytest.fixture
def doc(paths):
    return fetch(*paths)


def walk(nodes):
    for n in nodes:
        yield n
        yield from walk(n["children"])


def host(doc, name):
    return next(h for h in doc["hosts"] if h["name"] == name)


def test_hosts_are_the_snapshots_and_the_manual_host_sorted_by_name(doc):
    assert [h["name"] for h in doc["hosts"]] == ["nas01", "nas3", "pve2", "pvec", "truenas2"]
    nas3 = host(doc, "nas3")
    assert (nas3["source"], nas3["platform"], nas3["os"]) == ("stored", "synology", "DSM 7.2.2")
    assert nas3["scanned_at"] and nas3["age_seconds"] is not None and nas3["age_seconds"] >= 0
    assert host(doc, "truenas2")["source"] == "manual" and host(doc, "truenas2")["scanned_at"] is None
    assert doc["waiting"] == [{"name": "ghost", "agent": "ghost-agent", "snapshot": False}]
    assert doc["problem"] is None


def test_the_tree_runs_from_pool_to_volume_to_shares_and_luns_with_capacity(doc):
    nas3 = host(doc, "nas3")
    kinds = {n["type"] for n in walk(nas3["tree"])}
    assert {"pool", "group", "volume", "share", "lun"} <= kinds
    vol = next(n for n in walk(nas3["tree"]) if n["type"] == "volume")
    assert vol["used_bytes"] + vol["free_bytes"] == vol["size_bytes"] and vol["label"].startswith("volume")
    group = next(n for n in walk(nas3["tree"]) if n["type"] == "group" and n["role"] == "data")
    assert len(group["disks"]) == 4
    assert [d["type"] for d in nas3["disks"]] == ["disk"] * 6
    assert nas3["capacity"]["disk_bytes"] > 0 and nas3["capacity"]["volume_bytes"] == vol["size_bytes"]


def test_shares_are_joined_to_their_roots_case_insensitively(doc):
    shares = {n["name"]: n for n in walk(host(doc, "nas3")["tree"]) if n["type"] == "share"}
    backup = shares["Backup"]["root"]
    assert (backup["root"], backup["files"], backup["bytes"]) == (r"\\nas3\Backup", 3, 600)
    assert backup["below"] == []
    homes = shares["homes"]["root"]
    assert homes["root"] == r"\\NAS3\homes" and homes["files"] == 2
    assert [b["root"] for b in homes["below"]] == [r"\\nas3\homes\jdoe"] and homes["below"][0]["files"] == 4
    assert shares["Apps"]["root"] is None                # a share with no root


def test_roots_no_share_accounts_for_are_listed_last(doc):
    assert [r["root"] for r in doc["roots_not_in_topology"]] == [r"\\elsewhere\data"]
    assert doc["roots_not_in_topology"][0]["files"] == 1 and doc["roots"] == 4


def test_a_lun_points_at_the_guest_server_and_a_disk_at_its_provider(doc):
    lun = next(n for n in walk(host(doc, "nas3")["tree"]) if n["id"] == LUN3)
    assert {"host": "truenas2", "server": "\\\\truenas2"} in lun["guests"]
    assert lun["consumers"]
    pool_disk = host(doc, "truenas2")["disks"][0]
    assert pool_disk["provider"]["host"] == "nas3" and pool_disk["provider"]["via"] == "config"
    assert "truenas2" in host(doc, "nas3")["provides_to"] and "nas3" in host(doc, "truenas2")["attached_to"]
    assert any(l["consumer"]["host"] == "truenas2" and l["provider"]["id"] == LUN3 for l in doc["links"])
    assert doc["physical_summary"]["disk_bytes"] > 0


def test_a_stored_snapshot_replaces_a_manual_host_of_the_same_name(paths):
    db, cfg = paths
    with SqliteBackend(db) as b:
        topology_store.save_snapshot(b, snapshot("truenas2"))
    assert host(fetch(db, cfg), "truenas2")["source"] == "stored"


def test_no_topology_collected_is_an_empty_document(tmp_path):
    db = str(tmp_path / "c.sqlite")
    with SqliteBackend(db) as b:
        b.put(new_document(r"\\nas3\Backup", "a.txt", kind="text", size=5))
    doc = fetch(db, None)
    assert doc["hosts"] == [] and doc["waiting"] == [] and doc["links"] == []
    assert [r["root"] for r in doc["roots_not_in_topology"]] == [r"\\nas3\Backup"]


def test_a_broken_config_still_shows_the_snapshots(tmp_path):
    db = str(tmp_path / "c.sqlite")
    with SqliteBackend(db) as b:
        topology_store.save_snapshot(b, snapshot("nas3"))
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[[storage.hosts]]\nplatform = 'x'\n", encoding="utf-8")
    doc = fetch(db, str(cfg))
    assert [h["name"] for h in doc["hosts"]] == ["nas3"] and "name is required" in doc["problem"]


def test_the_document_carries_nothing_from_below_a_share(doc):
    text = json.dumps(doc)
    for name in ("f0.bin", "f1.bin", "f2.bin", "jdoe/f"):
        assert name not in text
