"""The data behind `GET /api/topology` of `filecat serve` (the Topology page).

One document for the whole picture: every host with its hierarchy (disks, then
pool/group/volume, then shares, LUNs and VM disks), capacity, the links between
hosts that `topology.resolve` finds, the physical totals, and for every share
the catalog root it is (`share.unc` matched case-insensitively to the roots, with
the file and byte totals of the root and its last scan). Roots that no share
accounts for come last, as "not in topology".

The hosts are the stored snapshots (`storage_topology`, written by `filecat
storage collect`) plus the `[[storage.hosts]]` of filecat.toml that have no
snapshot; a stored snapshot replaces a manual host of the same name, exactly as
`filecat storage show` does. `[[agents]]` hosts with no snapshot yet are listed
as such. The rendering of a node as text is storage_cmd._line, so the page and
the command agree.

Topology holds no file names (docs/storage-topology.md): disk, pool and share
names, sizes, UNC roots and the catalog's own root names and totals, nothing
below a share.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import config, rootinfo, topology
from .backends.base import Backend

NODE_FIELDS = ("id", "type", "name", "health", "detail", "size_bytes", "used_bytes", "free_bytes",
               "allocated_bytes", "raw_bytes", "thin", "role", "level", "kind", "mount", "fs_type", "path",
               "unc", "protocols", "target", "attached", "virtual", "serial", "model", "slot", "media")


def _unc_key(unc: str | None) -> str:
    return (unc or "").rstrip("\\/").lower()


def _age(iso: str | None, now: datetime) -> float | None:
    if not iso:
        return None
    try:
        then = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0.0, (now - then).total_seconds())


def _ref(topos: dict[str, topology.Topology], key: topology.Key) -> dict[str, Any]:
    topo = topos.get(key[0])
    node = topo.nodes.get(key[1]) if topo else None
    return {"host": topo.name if topo else key[0], "id": key[1],
            "name": (node.name or node.id) if node else key[1], "type": node.type if node else None,
            "known": node is not None}


def _stored(backend: Backend) -> dict[str, dict[str, Any]]:
    try:
        return {d["key"]: d for d in backend.topologies()}
    except NotImplementedError:
        return {}


def _hosts(backend: Backend, storage: config.StorageConfig
           ) -> list[tuple[topology.Topology, str, dict[str, Any] | None]]:
    out: list[tuple[topology.Topology, str, dict[str, Any] | None]] = []
    seen: set[str] = set()
    for key, doc in _stored(backend).items():
        try:
            out.append((topology.parse(doc["topology"]), "stored", doc))
            seen.add(key)
        except (topology.TopologyError, KeyError):
            continue            # a snapshot of another contract: skipped, as `storage show` does
    out.extend((h, "manual", None) for h in storage.hosts if h.key not in seen)
    return sorted(out, key=lambda t: t[0].key)


def _node(topo: topology.Topology, n: topology.Node, ctx: dict[str, Any]) -> dict[str, Any]:
    from .storage_cmd import _line
    out: dict[str, Any] = {k: getattr(n, k) for k in NODE_FIELDS if getattr(n, k) not in (None, [], "")}
    out["name"] = n.name or n.id
    out["label"] = _line(n, topo)
    if n.vm:
        out["vm"] = {"id": n.vm.get("id"), "name": n.vm.get("name")}
    if n.members:
        out["disks"] = [{"id": m["disk"], "role": m.get("role") or "data",
                         "name": (topo.nodes[m["disk"]].name or m["disk"]) if m["disk"] in topo.nodes else m["disk"]}
                        for m in n.members]
    key = (topo.key, n.id)
    if n.type == "share":
        out["root"] = ctx["share_roots"].get(key)
    guests = ctx["guests"].get(key)
    if guests:
        out["guests"] = guests
    consumers = ctx["consumers"].get(key)
    if consumers:
        out["consumers"] = consumers
    provider = ctx["providers"].get(key)
    if provider:
        out["provider"] = provider
    out["children"] = [_node(topo, c, ctx) for c in topo.children(n.id)]
    return out


def build(backend: Backend, config_path: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    """The /api/topology document."""
    now = now or datetime.now(timezone.utc)
    try:
        cfg = config.load(config.find(config_path))
        storage = config.load_storage(cfg)
        agents = config.load_agents(cfg)
        problem = None
    except config.ConfigError as exc:       # a broken file after startup: show the snapshots, say why
        storage, agents, problem = config.StorageConfig(), [], str(exc)
    hosts = _hosts(backend, storage)
    topos = {t.key: t for t, _, _ in hosts}
    snaps = [t for t, _, _ in hosts]
    res = topology.resolve(snaps, manual=storage.links)
    guests = topology.guest_servers(snaps, res.links)
    by_unc = {_unc_key(t.unc_server): t for t in snaps}

    roots = rootinfo.index(backend)
    share_nodes = [(t, n) for t in snaps for n in t.of_type("share") if n.unc]
    matched: set[str] = set()
    share_roots: dict[topology.Key, dict[str, Any] | None] = {}
    for topo, n in share_nodes:
        want = _unc_key(n.unc)
        hits = [r for r in roots if _unc_key(r["root"]) == want]
        below = [r for r in roots if _unc_key(r["root"]).startswith(want + "\\")]
        matched.update(r["root"] for r in [*hits, *below])
        if hits or below:
            share_roots[(topo.key, n.id)] = {
                "root": hits[0]["root"] if hits else None,
                **(_root_row(backend, hits[0]) if hits else {}),
                "below": [{"root": r["root"], **_root_row(backend, r)} for r in below]}

    consumers: dict[topology.Key, list[dict[str, Any]]] = {}
    providers: dict[topology.Key, dict[str, Any]] = {}
    for link in res.links:
        consumers.setdefault(link.provider, []).append({**_ref(topos, link.consumer), "via": link.via})
        providers[link.consumer] = {**_ref(topos, link.provider), "via": link.via, "note": link.note,
                                    "initiator_ok": link.initiator_ok}
    guest_hosts: dict[topology.Key, list[dict[str, Any]]] = {}
    for key, servers in guests.items():
        for server in servers:
            host = by_unc.get(_unc_key(server))
            guest_hosts.setdefault(key, []).append({"host": host.name if host else None, "server": server})
    ctx = {"share_roots": share_roots, "guests": guest_hosts, "consumers": consumers, "providers": providers}

    out_hosts = []
    for topo, source, doc in hosts:
        scanned = (doc or {}).get("scanned_at") or topo.collected_at
        notes = (topo.extra.get("collector") or {}).get("notes", [])
        attached = sorted({k[0] for link in res.links if link.consumer[0] == topo.key
                           for k in topology.chain(res.links, link.consumer)[1:] if k[0] != topo.key})
        provides = sorted({g["host"] or g["server"] for key, gs in guest_hosts.items() if key[0] == topo.key
                           for g in gs}, key=str.lower)
        out_hosts.append({
            "name": topo.name, "key": topo.key, "platform": topo.platform, "os": topo.host.get("os"),
            "kind": topo.host.get("kind"), "unc_server": topo.unc_server, "source": source,
            "origin": topo.origin, "scanned_at": scanned or None, "age_seconds": _age(scanned, now),
            "notes": notes, "attached_to": attached, "provides_to": provides,
            "capacity": topology.capacity_summary(topo),
            "disks": [_node_flat(topo, d, ctx) for d in topo.of_type("disk")],
            "tree": [_node(topo, n, ctx) for n in topo.children(None)],
            "vms": [{"id": v.id, "name": v.name or v.id, "disks": [x.id for x in topo.vm_disks(v.id)]}
                    for v in topo.of_type("vm")]})

    have = {h["key"] for h in out_hosts}
    waiting = []
    for agent in agents:
        name = agent.alias.strip("\\/") or agent.name
        if name.lower() not in have:
            waiting.append({"name": name, "agent": agent.name, "snapshot": False})

    unmatched = [r for r in roots if r["root"] not in matched]
    return {
        "problem": problem,
        "hosts": out_hosts,
        "waiting": waiting,
        "links": [{**_pair(topos, link), "via": link.via, "note": link.note, "initiator_ok": link.initiator_ok}
                  for link in res.links],
        "unresolved": [{**_ref(topos, u.node), "reason": u.reason, "wanted": u.wanted} for u in res.unresolved],
        "conflicts": len(res.conflicts),
        "physical_summary": topology.physical_summary(snaps, res.links, res.unresolved) if snaps else None,
        "roots_not_in_topology": [{"root": r["root"], **_root_row(backend, r)} for r in unmatched],
        "roots": len(roots),
        "now": now.isoformat(timespec="seconds"),
    }


def _node_flat(topo: topology.Topology, n: topology.Node, ctx: dict[str, Any]) -> dict[str, Any]:
    out = _node(topo, n, ctx)
    out.pop("children", None)
    return out


def _pair(topos: dict[str, topology.Topology], link: topology.Link) -> dict[str, Any]:
    return {"consumer": _ref(topos, link.consumer), "provider": _ref(topos, link.provider)}


def _root_row(backend: Backend, r: dict[str, Any]) -> dict[str, Any]:
    """What a root contributes to the page: totals, state and last scan."""
    info = r.get("info") or {}
    last = info.get("last_scan") or {}
    summary = r.get("summary")
    files = bytes_ = None
    if summary and summary.get("total_files") is not None:
        files, bytes_ = summary["total_files"], summary.get("total_bytes")
    else:
        try:
            from . import browse
            q = backend.query(browse.normalize({"root": r["root"], "files_only": "1", "limit": "1"}))
            files, bytes_ = q["total"], q["bytes"]
        except Exception:     # a total is a convenience; the row still stands without it
            pass
    return {"files": files, "bytes": bytes_, "state": r.get("state"),
            "last_scan": last.get("finished_at") or last.get("started_at"),
            "last_scan_status": last.get("status")}
