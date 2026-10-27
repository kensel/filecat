"""The `storage_topology` catalog store (docs/storage-topology.md section 7).

One document per host snapshot, replaced whole on every collection, so a reader never sees a
half-written scan:

    {"host": "nas3", "platform": "synology", "scanned_at": "...", "agent": {...},
     "topology": {...the generic topology...},
     "unc_roots": ["\\\\nas3\\Backup", ...],          # the catalog roots its shares are
     "guest_servers": ["\\\\nas01"],                  # servers whose disks are made of this host's
     "attached_to": ["nas3"],                         # hosts whose nodes this host's disks are made of
     "structure_hash": "<sha256 of the nodes without usage fields>"}

plus a `storage_topology_history` row only when the structure hash changes (a disk swapped, a
group degraded, a LUN added or resized), with the added, removed and changed node ids and the
topology itself, so any two rows can be diffed. Usage moving (used, free, allocated bytes)
rewrites the snapshot but writes no row. `guest_servers` and `attached_to` are derived from the
links between the stored snapshots (`topology.resolve`) and recomputed for every stored host
whenever one is saved; the links themselves are not stored. Hosts written by hand in
filecat.toml are never stored: they take part in the links at read time.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from . import topology
from .backends.base import Backend, Document

# fields that move with use and are therefore not part of a snapshot's structure
USAGE_FIELDS = ("used_bytes", "free_bytes", "allocated_bytes", "detail")


def _structure(doc: dict[str, Any]) -> dict[str, Any]:
    nodes = {n["id"]: {k: v for k, v in n.items() if k not in USAGE_FIELDS} for n in doc["nodes"]}
    host = {k: v for k, v in doc["host"].items()}
    return {"platform": doc["platform"], "host": host, "nodes": dict(sorted(nodes.items()))}


def structure_hash(topo: topology.Topology | dict[str, Any]) -> str:
    """SHA-256 (hex) of the topology without its usage fields, the snapshot time and the
    collector's notes, in a canonical form: the same structure always has the same hash."""
    doc = topo.to_dict() if isinstance(topo, topology.Topology) else topo
    text = json.dumps(_structure(doc), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def diff_structure(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, list[str]]:
    """Node ids added, removed and changed (structure fields only) between two topology dicts."""
    a = _structure(old)["nodes"] if old else {}
    b = _structure(new)["nodes"]
    return {"added": sorted(b.keys() - a.keys()), "removed": sorted(a.keys() - b.keys()),
            "changed": sorted(k for k in a.keys() & b.keys() if a[k] != b[k])}


def snapshot_document(topo: topology.Topology, *, agent: dict[str, Any] | None = None,
                      scanned_at: str | None = None) -> Document:
    doc: Document = {
        "host": topo.name, "platform": topo.platform,
        "scanned_at": scanned_at or topo.collected_at or "",
        "agent": agent or {}, "topology": topo.to_dict(),
        "unc_roots": sorted({n.unc for n in topo.of_type("share") if n.unc}, key=str.lower),
        "guest_servers": [], "attached_to": [],
        "structure_hash": structure_hash(topo)}
    return doc


@dataclass(frozen=True)
class SaveResult:
    host: str
    changed: bool                   # the structure differs from the stored snapshot (or there was none)
    first: bool                     # there was no stored snapshot
    history_written: bool
    structure_hash: str
    diff: dict[str, list[str]]


def load_snapshots(backend: Backend) -> list[topology.Topology]:
    """The stored snapshots as Topology objects, by host. A stored document that no longer
    validates (an older or newer contract) is skipped."""
    out = []
    for doc in backend.topologies():
        try:
            out.append(topology.parse(doc["topology"]))
        except (topology.TopologyError, KeyError):
            continue
    return out


def save_snapshot(backend: Backend, topo: topology.Topology, *, agent: dict[str, Any] | None = None,
                  scanned_at: str | None = None, others: Iterable[topology.Topology] = (),
                  manual: Iterable[topology.ManualLink] = ()) -> SaveResult:
    """Store `topo` as its host's snapshot. A history row is added when the structure hash
    differs from the stored one (or there is none). `others` (hosts from filecat.toml) and
    `manual` (its links) take part in recomputing the derived `guest_servers`/`attached_to`."""
    new = snapshot_document(topo, agent=agent, scanned_at=scanned_at)
    old = backend.get_topology(topo.name)
    first = old is None
    changed = first or old.get("structure_hash") != new["structure_hash"]
    diff = diff_structure(old["topology"] if old else None, new["topology"])
    if old and not changed:         # keep what was derived; refresh_links recomputes it below
        new["guest_servers"], new["attached_to"] = old.get("guest_servers", []), old.get("attached_to", [])
    backend.put_topology(new)
    if changed:
        backend.add_topology_history({
            "host": topo.name, "scanned_at": new["scanned_at"], "structure_hash": new["structure_hash"],
            "previous_hash": old.get("structure_hash") if old else None, "diff": diff,
            "platform": topo.platform, "topology": new["topology"]})
    refresh_links(backend, others, manual)
    return SaveResult(topo.name, changed, first, changed, new["structure_hash"], diff)


def refresh_links(backend: Backend, others: Iterable[topology.Topology] = (),
                  manual: Iterable[topology.ManualLink] = ()) -> int:
    """Recompute `guest_servers` and `attached_to` of every stored snapshot from the links
    between all of them (and `others`, `manual`); returns how many documents changed."""
    docs = backend.topologies()
    stored = load_snapshots(backend)
    stored_keys = {t.key for t in stored}
    snaps = [*(t for t in others if t.key not in stored_keys), *stored]
    res = topology.resolve(snaps, manual=list(manual))
    guests = topology.guest_servers(snaps, res.links)
    changed = 0
    for doc in docs:
        host = doc["host"].lower()
        servers = sorted({s for (h, _), ss in guests.items() if h == host for s in ss}, key=str.lower)
        attached = sorted({key[0] for link in res.links if link.consumer[0] == host
                           for key in topology.chain(res.links, link.consumer)[1:] if key[0] != host})
        if doc.get("guest_servers") != servers or doc.get("attached_to") != attached:
            backend.put_topology({**doc, "guest_servers": servers, "attached_to": attached})
            changed += 1
    return changed
