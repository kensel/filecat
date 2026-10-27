"""`filecat storage`: the storage topology of the hosts.

    collect [--agent NAME] [--platform P] [--measure-shares]
        read each [[agents]] host's raw storage sources through its agent, build the generic
        topology in Python (filecat.topology_collect), validate it and store it in the
        catalog (one snapshot per host; a history row when the structure changed). Exit 1
        when an agent could not be collected, 2 for a bad config or catalog.
    show [HOST] [--json]
        the stored snapshots (and the hosts written by hand in filecat.toml); with a host, its
        hierarchy from the disks up to the shares, LUNs and VM disks.
    links [--snapshot FILE ...] [--json]
        list the [[storage.hosts]] and [[storage.links]]. Resolves them over the stored
        snapshots, or over snapshot files (agent-style replies or bare topologies saved to
        disk) when given, manual hosts included, and prints each manual link as resolved,
        unresolved or conflict (it won over a different automatic match), the other nodes that
        expect a provider and have none, and the physical totals. A snapshot of a host replaces
        a manual host of the same name. Exit 1 when a manual link is unresolved or in conflict,
        2 for a bad config or snapshot file.

See docs/storage-topology.md and docs/agent-allowlist.md.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import config, topology, topology_store
from .summary import _human_bytes


def _load_snapshots(paths: list[str]) -> list[topology.Topology]:
    out: list[topology.Topology] = []
    for path in paths:
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(doc, dict) and "nodes" in doc and "topology" not in doc:
                out.append(topology.parse(doc))
            else:
                out.extend(topology.snapshots_from_response(doc))
        except (OSError, ValueError) as exc:    # json errors and TopologyError are ValueErrors
            raise config.ConfigError(f"{path}: {exc}") from None
    return out


def _open_catalog(args: Any, create: bool = False) -> Any:
    """The catalog backend. Without `create`, a file catalog that does not exist yet is None
    (reading must not leave an empty catalog behind); a server that cannot be reached is
    reported on stderr and is None too."""
    from .backends import DEFAULT_OUT, open_backend
    backend = getattr(args, "backend", None) or "sqlite"
    if not create and backend in ("sqlite", "jsonl"):
        out = getattr(args, "out", None) or DEFAULT_OUT[backend]
        if not Path(out).exists():
            return None
    try:
        return open_backend(backend, getattr(args, "out", None), getattr(args, "dsn", None))
    except Exception as exc:
        if create:
            raise config.ConfigError(f"catalog: {exc}") from None
        print(f"filecat storage: catalog not read: {exc}", file=sys.stderr)
        return None


def _stored(args: Any) -> list[topology.Topology]:
    backend = _open_catalog(args)
    if backend is None:
        return []
    try:
        return topology_store.load_snapshots(backend)
    except NotImplementedError:
        return []
    finally:
        backend.close()


def _key(key: topology.Key | None) -> str | None:
    return f"{key[0]}/{key[1]}" if key else None


def _row(result: topology.ManualResult) -> dict[str, Any]:
    row: dict[str, Any] = {**result.link.to_dict(), "status": result.status}
    for name in ("consumer", "provider"):
        if getattr(result, name):
            row[name] = _key(getattr(result, name))
    if result.reason:
        row["reason"] = result.reason
    if result.automatic:
        row["automatic"] = {"provider": _key(result.automatic.provider), "via": result.automatic.via}
    return row


# --- links ---------------------------------------------------------------------------------
def _links(args: Any) -> int:
    storage = config.load_storage(config.load(config.find(getattr(args, "config", None))))
    files = _load_snapshots(args.snapshot or [])
    from_stored = False
    if not files:
        files = _stored(args)
        from_stored = bool(files)
    checked = bool(files) or bool(storage.hosts)
    res = None
    summary = None
    if checked:
        # agent snapshots come last, so they replace a manual host of the same name
        snaps = [*storage.hosts, *files]
        res = topology.resolve(snaps, manual=storage.links)
        summary = topology.physical_summary(snaps, res.links, res.unresolved)
    mine = {r.consumer or topology.parse_ref(r.link.from_ref) for r in res.manual} if res else set()
    others = [u for u in res.unresolved if u.node not in mine] if res else []
    rows = [_row(r) for r in res.manual] if res else [
        {**link.to_dict(), "status": "unchecked"} for link in storage.links]
    if args.json:
        print(json.dumps({
            "hosts": [{"name": h.name, "unc_server": h.unc_server, "platform": h.platform,
                       "source": h.source, "origin": h.origin, "nodes": len(h.nodes)}
                      for h in storage.hosts],
            "snapshots": [{"name": t.name, "platform": t.platform, "nodes": len(t.nodes),
                           "from": "catalog" if from_stored else "file"} for t in files],
            "links": rows,
            "unresolved": [{"node": _key(u.node), "reason": u.reason, "wanted": u.wanted} for u in others],
            "physical_summary": summary}, ensure_ascii=False))
    else:
        _print(storage, rows, others, summary, bool(files), from_stored)
    bad = [r for r in rows if r["status"] in ("unresolved", "conflict")]
    return 1 if bad else 0


def _print(storage: config.StorageConfig, rows: list[dict[str, Any]], others: list[topology.Unresolved],
           summary: dict[str, Any] | None, from_files: bool, from_stored: bool = False) -> None:
    if not storage.hosts and not storage.links:
        print("(no [[storage.hosts]] or [[storage.links]] in filecat.toml)")
    for h in storage.hosts:
        print(f"host {h.name}  {h.unc_server}  {h.platform}, {len(h.nodes)} nodes  (manual, {h.origin})")
    for row in rows:
        note = f"   ({row['note']})" if row.get("note") else ""
        print(f"{row['status'].upper():10} {row['from']} -> {row['to']}{note}")
        if row.get("consumer") and row["consumer"].lower() != row["from"].lower():
            print(f"{'':10} starts at {row['consumer']}")
        if row.get("provider") and row["provider"].lower() != row["to"].lower():
            print(f"{'':10} ends at {row['provider']}")
        if row.get("reason"):
            print(f"{'':10} {row['reason']}")
        if row.get("automatic"):
            auto = row["automatic"]
            print(f"{'':10} the automatic match ({auto['via']}) said {auto['provider']}; the config wins")
    if others:
        print("expecting a provider, none found:")
        for u in others:
            print(f"  {_key(u.node)}: {u.reason}" + (f" ({u.wanted})" if u.wanted else ""))
    if summary:
        where = ("the stored snapshots" if from_stored else "the snapshots") if from_files else "the manual hosts"
        print(f"physical, over {where}: disks {_human_bytes(summary['disk_bytes'])}, "
              f"pools {_human_bytes(summary['pool_bytes'])}, "
              f"volumes {_human_bytes(summary['volume_bytes'])} "
              f"({_human_bytes(summary['volume_used_bytes'])} used), "
              f"shares {_human_bytes(summary['share_used_bytes'])} used")
        for x in summary["excluded"]:
            print(f"  not counted: {x['host']}/{x['id']} ({_human_bytes(x['bytes'])}), "
                  f"already inside {x['backed_by']}")
    elif storage.links:
        print("(not checked: no stored snapshots yet; run `filecat storage collect` or pass "
              "--snapshot FILE for each host's saved topology)")


# --- collect -------------------------------------------------------------------------------
def _server_of(alias: str) -> str:
    return alias.strip("\\/")


def collect_agent(agent: config.AgentConfig, *, platform: str | None = None,
                  measure_shares: bool = False) -> tuple[topology.Topology, dict[str, Any]]:
    """Collect one [[agents]] host through its agent: (topology, agent info for the store)."""
    from .agent_client import AgentClient
    from .topology_collect import AgentSource, collect
    with AgentClient.from_config(agent) as client:
        source = AgentSource(client)
        info = client.info
        assert info is not None
        topo = collect(source, platform, name=_server_of(agent.alias), unc_server="\\\\" + _server_of(agent.alias),
                       measure_shares=measure_shares)
        caps = source.capabilities()
    return topo, {"name": agent.name, "version": info.agent_version, "protocol": info.protocol,
                  "hostname": info.hostname, "os": info.os, "arch": info.arch,
                  "allowlist_version": caps.allowlist_version, "allowlist_sha256": caps.allowlist_sha256}


def _collect(args: Any) -> int:
    cfg = config.load(config.find(getattr(args, "config", None)))
    agents = config.load_agents(cfg)
    storage = config.load_storage(cfg)
    if args.agent:
        agents = [a for a in agents if a.name == args.agent]
        if not agents:
            raise config.ConfigError(f"--agent {args.agent}: no such [[agents]] in filecat.toml")
    if not agents:
        raise config.ConfigError("no [[agents]] in filecat.toml: there is nothing to collect from")
    backend = None if args.dry_run else _open_catalog(args, create=True)
    failed = 0
    try:
        for agent in agents:
            try:
                topo, info = collect_agent(agent, platform=args.platform, measure_shares=args.measure_shares)
            except Exception as exc:    # report every agent, whatever fails (unreachable, invalid topology)
                failed += 1
                msg = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
                if args.json:
                    print(json.dumps({"agent": agent.name, "ok": False, "error": type(exc).__name__,
                                      "message": msg}))
                else:
                    print(f"FAIL {agent.name}: {type(exc).__name__}: {msg}", file=sys.stderr)
                continue
            notes = (topo.extra.get("collector") or {}).get("notes", [])
            result = None
            if backend is not None:
                try:
                    result = topology_store.save_snapshot(backend, topo, agent=info, others=storage.hosts,
                                                          manual=storage.links)
                except NotImplementedError as exc:
                    raise config.ConfigError(f"catalog: {exc}") from None
            _report(agent, topo, result, notes, args.json)
    finally:
        if backend is not None:
            backend.close()
    return 1 if failed else 0


def _report(agent: config.AgentConfig, topo: topology.Topology, result: Any, notes: list[str],
            as_json: bool) -> None:
    if as_json:
        print(json.dumps({"agent": agent.name, "ok": True, "host": topo.name, "platform": topo.platform,
                          "nodes": len(topo.nodes), "stored": result is not None,
                          "changed": result.changed if result else None, "first": result.first if result else None,
                          "diff": result.diff if result else None,
                          "structure_hash": result.structure_hash if result else topology_store.structure_hash(topo),
                          "notes": notes}, ensure_ascii=False))
        return
    if result is None:
        state = "not stored (--dry-run)"
    elif result.first:
        state = "first snapshot stored"
    elif result.changed:
        d = result.diff
        state = f"structure changed (+{len(d['added'])} -{len(d['removed'])} ~{len(d['changed'])}), history row added"
    else:
        state = "structure unchanged, usage refreshed"
    print(f"{agent.name}  {topo.name}  {topo.platform}  {len(topo.nodes)} nodes  {state}")
    for note in notes:
        print(f"  note: {note}")


# --- show ----------------------------------------------------------------------------------
def _merged(args: Any, storage: config.StorageConfig) -> list[tuple[topology.Topology, str, dict[str, Any] | None]]:
    """(topology, "stored" | "manual", stored document) for every host: a stored snapshot
    replaces a manual host of the same name."""
    stored: dict[str, dict[str, Any]] = {}
    backend = _open_catalog(args)
    if backend is not None:
        try:
            stored = {d["key"]: d for d in backend.topologies()}
        except NotImplementedError:
            stored = {}
        finally:
            backend.close()
    out = []
    seen: set[str] = set()
    for key, doc in stored.items():
        try:
            out.append((topology.parse(doc["topology"]), "stored", doc))
            seen.add(key)
        except topology.TopologyError as exc:
            print(f"filecat storage: stored snapshot of {doc['host']} skipped: {exc}", file=sys.stderr)
    out.extend((h, "manual", None) for h in storage.hosts if h.key not in seen)
    return sorted(out, key=lambda t: t[0].key)


def _show(args: Any) -> int:
    storage = config.load_storage(config.load(config.find(getattr(args, "config", None))))
    hosts = _merged(args, storage)
    if args.host:
        found = [h for h in hosts if h[0].key == args.host.lower()]
        if not found:
            known = ", ".join(h[0].name for h in hosts) or "none"
            print(f"filecat storage: no host {args.host!r} (known: {known})", file=sys.stderr)
            return 1
        topo, source, doc = found[0]
        if args.json:
            print(json.dumps(doc if doc else {"host": topo.name, "platform": topo.platform,
                                              "topology": topo.to_dict()}, ensure_ascii=False))
        else:
            _print_host(topo, source, doc)
        return 0
    if args.json:
        print(json.dumps([_summary_row(t, s, d) for t, s, d in hosts], ensure_ascii=False))
        return 0
    if not hosts:
        print("(no stored snapshots and no [[storage.hosts]]: run `filecat storage collect`)")
    for t, s, d in hosts:
        row = _summary_row(t, s, d)
        extra = ""
        if row["attached_to"]:
            extra += f"  on {', '.join(row['attached_to'])}"
        if row["guest_servers"]:
            extra += f"  hosts {', '.join(row['guest_servers'])}"
        print(f"{t.name:12} {t.platform:10} {row['source']:7} {row['nodes']:4} nodes  "
              f"{row['scanned_at'] or '-':20}{extra}")
    return 0


def _summary_row(t: topology.Topology, source: str, doc: dict[str, Any] | None) -> dict[str, Any]:
    return {"host": t.name, "platform": t.platform, "source": source, "nodes": len(t.nodes),
            "scanned_at": (doc or {}).get("scanned_at") or t.collected_at,
            "unc_roots": (doc or {}).get("unc_roots") or [n.unc for n in t.of_type("share") if n.unc],
            "guest_servers": (doc or {}).get("guest_servers", []), "attached_to": (doc or {}).get("attached_to", []),
            "structure_hash": (doc or {}).get("structure_hash")}


def _line(n: topology.Node) -> str:
    bits = [n.type, n.name or n.id]
    if n.level:
        bits.append(n.level)
    if n.kind:
        bits.append(n.kind)
    if n.mount:
        bits.append(f"{n.mount} {n.fs_type or ''}".strip())
    if n.type in ("lun", "vdisk"):
        bits.append("thin" if n.thin else "thick" if n.thin is False else "")
    size = n.size_bytes
    if size is not None:
        bits.append(_human_bytes(size))
    if n.used_bytes is not None and n.type in ("volume", "pool", "share"):
        bits.append(f"{_human_bytes(n.used_bytes)} used")
    if n.allocated_bytes is not None and n.type in ("lun", "vdisk"):
        bits.append(f"{_human_bytes(n.allocated_bytes)} allocated")
    if n.unc:
        bits.append(n.unc)
    if n.target:
        bits.append(f"target {n.target}")
    if n.vm:
        bits.append(f"vm {n.vm.get('name')}")
    if n.attached is False:
        bits.append("not attached")
    if n.health and n.health != "ok":
        bits.append(f"[{n.health}]")
    return "  ".join(b for b in bits if b)


def _print_host(topo: topology.Topology, source: str, doc: dict[str, Any] | None) -> None:
    os_name = topo.host.get("os")
    print(f"{topo.name}  {topo.unc_server}  {topo.platform}" + (f"  {os_name}" if os_name else "")
          + f"  ({source}" + (f", scanned {doc['scanned_at']}" if doc and doc.get("scanned_at") else "") + ")")
    for disk in topo.of_type("disk"):
        print("  " + _line(disk) + (f"  {disk.model}" if disk.model else "")
              + (f"  {disk.media}" if disk.media else ""))
    for n, depth in topo.walk():
        print("  " * (depth + 1) + _line(n))
    for vm in topo.of_type("vm"):
        print("  " + _line(vm))
    notes = (topo.extra.get("collector") or {}).get("notes", [])
    for note in notes:
        print(f"  note: {note}")
    if doc:
        if doc.get("attached_to"):
            print("  made of storage on: " + ", ".join(doc["attached_to"]))
        if doc.get("guest_servers"):
            print("  provides storage to: " + ", ".join(doc["guest_servers"]))


def run(args: Any) -> int:
    try:
        if args.action == "collect":
            return _collect(args)
        if args.action == "show":
            return _show(args)
        return _links(args)
    except config.ConfigError as exc:
        print(f"filecat storage: {exc}", file=sys.stderr)
        return 2
