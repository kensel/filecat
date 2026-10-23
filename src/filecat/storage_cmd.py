"""`filecat storage`: the storage written by hand in filecat.toml.

    links [--snapshot FILE ...] [--json]
        list the [[storage.hosts]] and [[storage.links]]. With snapshot files (agent
        `storage_topology` replies or bare topologies saved to disk) it also resolves them,
        manual hosts included, and prints each manual link as resolved, unresolved or
        conflict (it won over a different automatic match), the other nodes that expect a
        provider and have none, and the physical totals. A snapshot of a host replaces a
        manual host of the same name. Exit 1 when a manual link is unresolved or in conflict,
        2 for a bad config or snapshot file.

See docs/storage-topology.md.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import config, topology
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


def _links(args: Any) -> int:
    storage = config.load_storage(config.load(config.find(getattr(args, "config", None))))
    files = _load_snapshots(args.snapshot or [])
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
            "links": rows,
            "unresolved": [{"node": _key(u.node), "reason": u.reason, "wanted": u.wanted} for u in others],
            "physical_summary": summary}, ensure_ascii=False))
    else:
        _print(storage, rows, others, summary, bool(files))
    bad = [r for r in rows if r["status"] in ("unresolved", "conflict")]
    return 1 if bad else 0


def _print(storage: config.StorageConfig, rows: list[dict[str, Any]], others: list[topology.Unresolved],
           summary: dict[str, Any] | None, from_files: bool) -> None:
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
        where = "the snapshots" if from_files else "the manual hosts"
        print(f"physical, over {where}: disks {_human_bytes(summary['disk_bytes'])}, "
              f"pools {_human_bytes(summary['pool_bytes'])}, "
              f"volumes {_human_bytes(summary['volume_bytes'])} "
              f"({_human_bytes(summary['volume_used_bytes'])} used), "
              f"shares {_human_bytes(summary['share_used_bytes'])} used")
        for x in summary["excluded"]:
            print(f"  not counted: {x['host']}/{x['id']} ({_human_bytes(x['bytes'])}), "
                  f"already inside {x['backed_by']}")
    elif storage.links:
        print("(not checked: pass --snapshot FILE for each host's saved storage_topology reply)")


def run(args: Any) -> int:
    try:
        return _links(args)
    except config.ConfigError as exc:
        print(f"filecat storage: {exc}", file=sys.stderr)
        return 2
