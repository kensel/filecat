"""The generic storage topology a filecat-agent reports (docs/storage-topology.md).

One response, whichever platform the host runs:

    {"version": 1, "platform": "synology",
     "host": {"name": "nas-main", "unc_server": "\\\\\\\\nas-main"},
     "collected_at": "2026-10-21T18:00:00Z",
     "nodes": [{"id": "pool:...", "type": "pool", "parent": null, ...}, ...]}

Seven node types make the hierarchy server > disks > group > pool > volume >
share / lun / vdisk. `parent` is the containment link (group in pool, volume in
pool or volume, share in volume, lun and vdisk in a volume or a pool). Disks
are an inventory with no parent: a disk can serve several groups (SHR slices
one disk into several arrays), so groups, pools and volumes list `members`
with a role per disk instead. Ids are strings built from platform-native ids
(pool GUID, disk serial), never array indices; (host, id) is global.

`validate` checks a response and returns every problem; `parse` raises
TopologyError(problems) instead. Unknown fields are kept in `Node.extra` so a
newer agent's output survives a round trip. `share_entries` derives what
`ShareMap` needs (POSIX prefix -> UNC root) and `merge_share_maps` lets the
`[[agents]] shares` table of filecat.toml win over it.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

VERSION = 1
TYPES = ("disk", "group", "pool", "volume", "share", "lun", "vdisk")
# type -> types its `parent` may have; None (no parent) is always allowed unless REQUIRES_PARENT.
PARENT_TYPES: dict[str, tuple[str, ...]] = {
    "disk": (),
    "group": ("pool",),
    "pool": ("pool",),            # an LVM thin pool inside its volume group
    "volume": ("pool", "volume"),  # a ZFS child dataset inside its parent dataset
    "share": ("volume",),
    "lun": ("pool", "volume"),
    "vdisk": ("pool", "volume"),
}
REQUIRES_PARENT = ("group", "share")
ROLES = ("data", "parity", "spare", "log", "cache", "special", "dedup", "boot")
HEALTH = ("ok", "warning", "degraded", "failed", "unknown")
PROTOCOLS = ("smb", "nfs")

_INT_FIELDS = ("size_bytes", "used_bytes", "free_bytes", "allocated_bytes", "raw_bytes")
_STR_FIELDS = ("name", "detail", "role", "level", "kind", "mount", "fs_type", "device", "path",
               "unc", "guest_server", "serial", "model", "slot", "media")


class TopologyError(ValueError):
    """A storage_topology response that does not follow the contract."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        shown = "; ".join(problems[:5]) + (f"; and {len(problems) - 5} more" if len(problems) > 5 else "")
        super().__init__(f"invalid storage_topology: {shown}")


@dataclass
class Node:
    """One element of the hierarchy. Which fields apply depends on `type`
    (docs/storage-topology.md); the rest stay None or empty.

    size_bytes       disk: raw; pool/volume: usable; lun/vdisk: logical (provisioned)
    used_bytes       volume/pool/share: bytes in use (file systems; ZFS `used`)
    free_bytes       volume/pool: bytes available
    allocated_bytes  lun/vdisk: physical bytes behind it (st_blocks * 512), pool: given out to children
    raw_bytes        pool/group: before redundancy
    thin             lun/vdisk/pool: sparse or thin provisioned (False thick, None unknown)
    """
    id: str
    type: str
    name: str = ""
    parent: str | None = None
    health: str | None = None
    detail: str | None = None
    size_bytes: int | None = None
    used_bytes: int | None = None
    free_bytes: int | None = None
    allocated_bytes: int | None = None
    raw_bytes: int | None = None
    thin: bool | None = None
    role: str | None = None             # group: data, log, cache, spare, special, dedup
    level: str | None = None            # group/pool: raid5, mirror, raidz2, shr, single ...
    members: list[dict[str, Any]] = field(default_factory=list)  # [{"disk": id, "role": "data"}]
    kind: str | None = None             # lun: iscsi, zvol, lv, file; pool: lvm_thin ...
    mount: str | None = None            # volume
    fs_type: str | None = None          # volume
    device: str | None = None           # volume
    path: str | None = None             # share: the folder on the host; lun/vdisk: backing file or dir
    unc: str | None = None              # share: the catalog root, \\server\Share
    protocols: list[str] = field(default_factory=list)   # share: smb, nfs
    vm: dict[str, Any] | None = None    # vdisk: {"id", "name"} of the VM it is attached to
    attached: bool | None = None        # vdisk: False for an image-library template
    guest_server: str | None = None     # lun/vdisk: UNC server whose own shares live inside it
    serial: str | None = None           # disk
    model: str | None = None
    slot: str | None = None
    media: str | None = None            # hdd, ssd, nvme
    platform: dict[str, dict[str, Any]] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)  # unknown fields, kept as received

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Node":
        known = {f.name for f in dataclasses.fields(cls)} - {"extra"}
        kwargs = {k: v for k, v in d.items() if k in known}
        for k in ("members", "protocols"):
            if kwargs.get(k) is None:
                kwargs.pop(k, None)
        if kwargs.get("platform") is None:
            kwargs.pop("platform", None)
        return cls(extra={k: v for k, v in d.items() if k not in known}, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "type": self.type, "parent": self.parent}
        for f in dataclasses.fields(self):
            if f.name in ("id", "type", "parent", "extra"):
                continue
            v = getattr(self, f.name)
            if v is None or v == [] or v == {} or (f.name == "name" and not v):
                continue
            out[f.name] = v
        out.update(self.extra)
        return out


@dataclass
class Topology:
    platform: str
    host: dict[str, Any]
    nodes: dict[str, Node]
    collected_at: str | None = None
    version: int = VERSION
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.host["name"]

    @property
    def unc_server(self) -> str:
        """`\\\\nas-main`: the host's `unc_server`, else its name."""
        return self.host.get("unc_server") or "\\\\" + self.host["name"]

    def get(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def of_type(self, *types: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.type in types]

    def children(self, node_id: str | None) -> list[Node]:
        """Nodes whose parent is `node_id`; with None the top of the tree (disks excluded)."""
        return [n for n in self.nodes.values() if n.parent == node_id and n.type != "disk"]

    def ancestors(self, node_id: str) -> list[Node]:
        """Parent first, the top-most last."""
        out: list[Node] = []
        node = self.nodes[node_id]
        while node.parent is not None:
            node = self.nodes[node.parent]
            out.append(node)
        return out

    def walk(self, start: str | None = None) -> Iterator[tuple[Node, int]]:
        """Depth-first (node, depth) over the containment tree, in response order.
        With `start` that node comes first at depth 0; without it the walk covers
        every top-level pool and volume. Disks are not part of the tree (see `disks_of`)."""
        stack = [(self.nodes[start], 0)] if start else [(n, 0) for n in reversed(self.children(None))]
        while stack:
            node, depth = stack.pop()
            yield node, depth
            stack.extend((c, depth + 1) for c in reversed(self.children(node.id)))

    def subtree(self, node_id: str) -> list[Node]:
        return [n for n, _ in self.walk(node_id)]

    def disks_of(self, node_id: str) -> list[tuple[Node, str]]:
        """(disk, role) for every disk behind a node: its own members and those of the
        groups, pools and volumes beneath it. A disk with several roles appears once per role."""
        seen: set[tuple[str, str]] = set()
        out: list[tuple[Node, str]] = []
        for node in self.subtree(node_id):
            for m in node.members:
                key = (m["disk"], m.get("role") or "data")
                if key not in seen:
                    seen.add(key)
                    out.append((self.nodes[m["disk"]], key[1]))
        return out

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"version": self.version, "platform": self.platform, "host": self.host}
        if self.collected_at:
            out["collected_at"] = self.collected_at
        out["nodes"] = [n.to_dict() for n in self.nodes.values()]
        out.update(self.extra)
        return out


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def validate(doc: Any) -> list[str]:
    """Every way `doc` breaks the contract; an empty list means it is sound."""
    if not isinstance(doc, dict):
        return ["topology is not an object"]
    problems: list[str] = []
    if doc.get("version") != VERSION:
        problems.append(f"version is {doc.get('version')!r}, expected {VERSION}")
    if not isinstance(doc.get("platform"), str) or not doc["platform"]:
        problems.append("platform must be a non-empty string")
    host = doc.get("host")
    if not isinstance(host, dict) or not isinstance(host.get("name"), str) or not host["name"]:
        problems.append("host.name must be a non-empty string")
    elif "unc_server" in host and host["unc_server"] is not None:
        unc = host["unc_server"]
        if not isinstance(unc, str) or not unc.startswith("\\\\") or "\\" in unc[2:] or len(unc) < 3:
            problems.append(f"host.unc_server {unc!r} must look like \\\\server")
    nodes = doc.get("nodes")
    if not isinstance(nodes, list):
        return problems + ["nodes must be a list"]

    by_id: dict[str, dict[str, Any]] = {}
    for i, n in enumerate(nodes):
        if not isinstance(n, dict):
            problems.append(f"nodes[{i}] is not an object")
            continue
        nid = n.get("id")
        if not isinstance(nid, str) or not nid or nid != nid.strip():
            problems.append(f"nodes[{i}] has no usable id")
            continue
        if nid in by_id:
            problems.append(f"duplicate id {nid!r}")
            continue
        by_id[nid] = n

    for nid, n in by_id.items():
        t = n.get("type")
        if t not in TYPES:
            problems.append(f"{nid}: unknown type {t!r}")
            continue
        for k in _INT_FIELDS:
            v = n.get(k)
            if v is not None and (not _is_int(v) or v < 0):
                problems.append(f"{nid}: {k} must be a non-negative integer, got {v!r}")
        for k in _STR_FIELDS:
            v = n.get(k)
            if v is not None and not isinstance(v, str):
                problems.append(f"{nid}: {k} must be a string, got {v!r}")
        for k in ("thin", "attached"):
            v = n.get(k)
            if v is not None and not isinstance(v, bool):
                problems.append(f"{nid}: {k} must be true or false, got {v!r}")
        if n.get("health") is not None and n["health"] not in HEALTH:
            problems.append(f"{nid}: health {n['health']!r} is not one of {', '.join(HEALTH)}")
        if n.get("role") is not None and n["role"] not in ROLES:
            problems.append(f"{nid}: role {n['role']!r} is not one of {', '.join(ROLES)}")
        plat = n.get("platform")
        if plat is not None and (not isinstance(plat, dict)
                                 or not all(isinstance(v, dict) for v in plat.values())):
            problems.append(f"{nid}: platform must map a platform name to an object")
        prot = n.get("protocols")
        if prot is not None:
            if not isinstance(prot, list) or any(p not in PROTOCOLS for p in prot):
                problems.append(f"{nid}: protocols must be a list of {', '.join(PROTOCOLS)}")
        if n.get("vm") is not None and not isinstance(n["vm"], dict):
            problems.append(f"{nid}: vm must be an object")
        if n.get("unc") is not None and isinstance(n["unc"], str):
            if not n["unc"].startswith("\\\\") or n["unc"].count("\\") < 3:
                problems.append(f"{nid}: unc {n['unc']!r} must look like \\\\server\\Share")
        if t == "share" and not (n.get("name") or n.get("unc")):
            problems.append(f"{nid}: a share needs a name")
        if t == "disk" and n.get("parent") is not None:
            problems.append(f"{nid}: a disk has no parent (pools list it in members)")
        members = n.get("members")
        if members is not None:
            if not isinstance(members, list):
                problems.append(f"{nid}: members must be a list")
            else:
                if t not in ("group", "pool", "volume"):
                    problems.append(f"{nid}: only groups, pools and volumes have members")
                for m in members:
                    if not isinstance(m, dict) or not isinstance(m.get("disk"), str):
                        problems.append(f"{nid}: a member needs a disk id")
                    elif m["disk"] not in by_id or by_id[m["disk"]].get("type") != "disk":
                        problems.append(f"{nid}: member {m['disk']!r} is not a disk in this topology")
                    elif m.get("role") is not None and m["role"] not in ROLES:
                        problems.append(f"{nid}: member role {m['role']!r} is not one of {', '.join(ROLES)}")
        parent = n.get("parent")
        if parent is None:
            if t in REQUIRES_PARENT:
                problems.append(f"{nid}: a {t} needs a parent")
        elif not isinstance(parent, str) or parent not in by_id:
            problems.append(f"{nid}: parent {parent!r} is not in this topology")
        elif by_id[parent].get("type") not in PARENT_TYPES[t]:
            problems.append(f"{nid}: a {t} cannot sit under a {by_id[parent].get('type')} ({parent})")

    # cycles: only pool-in-pool and volume-in-volume can loop, but check every chain
    for nid in by_id:
        seen = {nid}
        cur = by_id[nid].get("parent")
        while isinstance(cur, str) and cur in by_id:
            if cur in seen:
                problems.append(f"{nid}: parent links form a cycle through {cur!r}")
                break
            seen.add(cur)
            cur = by_id[cur].get("parent")
    return problems


def parse(doc: Any) -> Topology:
    """Validate `doc` (the `topology` object of a response) and build a Topology."""
    problems = validate(doc)
    if problems:
        raise TopologyError(problems)
    nodes = {n["id"]: Node.from_dict(n) for n in doc["nodes"]}
    extra = {k: v for k, v in doc.items() if k not in ("version", "platform", "host", "collected_at", "nodes")}
    return Topology(platform=doc["platform"], host=dict(doc["host"]), nodes=nodes,
                    collected_at=doc.get("collected_at"), version=doc["version"], extra=extra)


def from_response(resp: dict[str, Any]) -> Topology:
    """Parse a whole `storage_topology` reply, `{"ok": true, "topology": {...}}`."""
    if not isinstance(resp, dict) or "topology" not in resp:
        raise TopologyError(["reply has no topology (an agent older than the generic layout "
                             "answers with `volumes`)"])
    return parse(resp["topology"])


def subtree_sum(topo: Topology, node_id: str, field_name: str, *types: str) -> int:
    """Sum `field_name` over the nodes beneath (and including) `node_id`, of the given
    types when any are named. Nodes without the field add nothing."""
    total = 0
    for n in topo.subtree(node_id):
        v = getattr(n, field_name)
        if v is not None and (not types or n.type in types):
            total += v
    return total


def capacity_summary(topo: Topology) -> dict[str, int]:
    """Host-wide totals, each counted once. Nested pools (a thin pool in its volume group)
    and nested datasets are not added twice: only top-level pools and volumes count.

        disk_bytes       raw size of every disk
        pool_bytes       usable size of the top-level pools
        volume_bytes / volume_used_bytes / volume_free_bytes   top-level volumes
        share_used_bytes   shares that report a size
        block_provisioned_bytes / block_allocated_bytes   luns and vdisks, logical vs physical
    """
    def total(nodes: Iterable[Node], attr: str) -> int:
        return sum(getattr(n, attr) or 0 for n in nodes)

    pools = [n for n in topo.of_type("pool") if n.parent is None]
    volumes = [n for n in topo.of_type("volume") if n.parent is None or topo.nodes[n.parent].type == "pool"]
    block = topo.of_type("lun", "vdisk")
    return {
        "disk_bytes": total(topo.of_type("disk"), "size_bytes"),
        "pool_bytes": total(pools, "size_bytes"),
        "volume_bytes": total(volumes, "size_bytes"),
        "volume_used_bytes": total(volumes, "used_bytes"),
        "volume_free_bytes": total(volumes, "free_bytes"),
        "share_used_bytes": total(topo.of_type("share"), "used_bytes"),
        "block_provisioned_bytes": total(block, "size_bytes"),
        "block_allocated_bytes": total(block, "allocated_bytes"),
    }


def _norm_posix(path: str) -> str:
    return "/" + "/".join(p for p in path.split("/") if p)


def share_entries(topo: Topology, alias: str | None = None) -> dict[str, str]:
    """POSIX prefix -> UNC root for every SMB share on a POSIX path, the table `ShareMap`
    takes as `shares`.

    The UNC root is the share's own `unc` when the agent gave one, otherwise
    `<server>\\<name>` with `alias` (the `[[agents]]` alias) or else the host's
    `unc_server`. Shares with no `smb` protocol and no `unc`, and paths that are not
    POSIX (a Windows `D:\\Data`), are left out. Two shares on one folder, or with one
    name, keep the first in response order: ShareMap refuses duplicates.
    """
    server = alias or topo.unc_server
    out: dict[str, str] = {}
    taken: set[str] = set()
    for n in topo.of_type("share"):
        if not n.path or not n.path.startswith("/"):
            continue
        if not n.unc and "smb" not in n.protocols:
            continue
        prefix = _norm_posix(n.path)
        if prefix == "/":
            continue
        unc = n.unc or f"{server}\\{n.name}"
        if prefix in out or unc.lower() in taken:
            continue
        out[prefix] = unc
        taken.add(unc.lower())
    return out


def merge_share_maps(derived: dict[str, str], configured: dict[str, str] | None) -> dict[str, str]:
    """`derived` (from `share_entries`) with the configured `[agents.shares]` on top.

    A configured entry wins over a derived one with the same POSIX prefix or the same UNC
    root (case-insensitively), so a hand-written map can rename or repoint a share."""
    configured = configured or {}
    cfg_prefix = {_norm_posix(p) for p in configured}
    cfg_unc = {u.lower() for u in configured.values()}
    out = {p: u for p, u in derived.items() if p not in cfg_prefix and u.lower() not in cfg_unc}
    out.update(configured)
    return out


def link_guests(topo: Topology, guests: dict[str, str]) -> int:
    """Fill `guest_server` on luns and vdisks that have none. `guests` maps a node id, a
    VM name or a LUN name (the last two matched case-insensitively) to a UNC server like
    `\\\\nas-vm`. Returns how many nodes were linked."""
    by_name = {k.lower(): v for k, v in guests.items()}
    linked = 0
    for n in topo.of_type("lun", "vdisk"):
        if n.guest_server:
            continue
        keys = [n.id, (n.vm or {}).get("name"), n.name]
        server = guests.get(n.id) or next((by_name[k.lower()] for k in keys[1:] if k and k.lower() in by_name), None)
        if server:
            n.guest_server = server
            linked += 1
    return linked
