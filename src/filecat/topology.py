"""The generic storage topology a filecat-agent reports (docs/storage-topology.md).

One response, whichever platform the host runs:

    {"version": 1, "platform": "synology",
     "host": {"name": "nas-main", "unc_server": "\\\\\\\\nas-main"},
     "collected_at": "2026-10-21T18:00:00Z",
     "nodes": [{"id": "pool:...", "type": "pool", "parent": null, ...}, ...]}

Eight node types make the hierarchy server > disks > group > pool > volume >
share / lun / vdisk, plus `vm` on the host that runs it. `parent` is the containment link (group in pool, volume in
pool or volume, share in volume, lun and vdisk in a volume or a pool). Disks
are an inventory with no parent: a disk can serve several groups (SHR slices
one disk into several arrays), so groups, pools and volumes list `members`
with a role per disk instead. Ids are strings built from platform-native ids
(pool GUID, disk serial), never array indices; (host, id) is global.

Hosts join through links between individual disks: a `disk`, `lun` or `vdisk`
may carry `backing: {host, id}` naming the node on another host that provides it,
or `match` identifiers (`naa:`, `uuid:`, `serial:`, `volid:`, ...) from which
`resolve_links` pairs consumers with providers across many hosts' snapshots,
chaining through any number of hops. `physical_summary` counts the bytes behind a
backed disk once, on the host that owns the real disk.

A host with no agent, and a link no automatic rule can find, are written by hand in
filecat.toml (`[[storage.hosts]]`, `[[storage.links]]`): `manual_topology` builds the
host's snapshot (`source: "manual"`), `ManualLink` is a link, and `resolve` puts both
over the automatic matches, reporting where they disagree.

`validate` checks a response and returns every problem; `parse` raises
TopologyError(problems) instead. Unknown fields are kept in `Node.extra` so a
newer agent's output survives a round trip. `share_entries` derives what
`ShareMap` needs (POSIX prefix -> UNC root) and `merge_share_maps` lets the
`[[agents]] shares` table of filecat.toml win over it.
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

VERSION = 1
TYPES = ("disk", "group", "pool", "volume", "share", "lun", "vdisk", "vm")
LINK_TYPES = ("disk", "lun", "vdisk")   # nodes that can consume or provide a block device
# type -> types its `parent` may have; None (no parent) is always allowed unless REQUIRES_PARENT.
PARENT_TYPES: dict[str, tuple[str, ...]] = {
    "disk": (),
    "group": ("pool",),
    "pool": ("pool",),            # an LVM thin pool inside its volume group
    "volume": ("pool", "volume"),  # a ZFS child dataset inside its parent dataset
    "share": ("volume",),
    "lun": ("pool", "volume"),
    "vdisk": ("pool", "volume"),
    "vm": (),
}
REQUIRES_PARENT = ("group", "share")
ROLES = ("data", "parity", "spare", "log", "cache", "special", "dedup", "boot")
HEALTH = ("ok", "warning", "degraded", "failed", "unknown")
PROTOCOLS = ("smb", "nfs")
HOST_KINDS = ("host", "cluster")
SOURCES = ("agent", "manual")
ORIGINS = ("config", "catalog")
_MATCH_RE = re.compile(r"^[a-z][a-z0-9_]*:\S")

_INT_FIELDS = ("size_bytes", "used_bytes", "free_bytes", "allocated_bytes", "raw_bytes")
_STR_FIELDS = ("name", "detail", "role", "level", "kind", "mount", "fs_type", "device", "path",
               "unc", "target", "serial", "model", "slot", "media")


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

    match            "kind:value": naa (SCSI WWN), uuid (a Synology LUN or vdisk), serial (a guest disk),
                     vmserial (the serial= a hypervisor gave a vdisk), volid (a Proxmox storage volume),
                     vmmdisk (a Synology VMM vdisk uuid). Lowercase kind; the value keeps its case.
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
    vm: dict[str, Any] | None = None    # vdisk: {"id", "name"} of the VM it is attached to (a vm node's id)
    attached: bool | None = None        # vdisk: False for an image-library template
    target: str | None = None           # lun: the iSCSI target it is exported through
    initiators: list[dict[str, Any]] = field(default_factory=list)  # lun ACL: {"iqn", "authority"?, "default"?}
    backing: dict[str, str] | None = None  # disk/lun/vdisk: {"host", "id"} of the node elsewhere that provides it
    match: list[str] = field(default_factory=list)  # "kind:value" identifiers that link nodes of different hosts
    virtual: bool | None = None         # disk/lun/vdisk: provided by something else, so a provider is expected
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
        for k in ("members", "protocols", "initiators", "match"):
            if kwargs.get(k) is None:
                kwargs.pop(k, None)
        if "initiators" in kwargs:   # a bare IQN is an entry with no authority
            kwargs["initiators"] = [{"iqn": i} if isinstance(i, str) else i for i in kwargs["initiators"]]
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
    source: str = "agent"             # "agent" (reported by filecat-agent) or "manual" (written by hand)
    origin: str | None = None         # a manual host: "config" (filecat.toml) or "catalog" (the web viewer)
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

    @property
    def key(self) -> str:
        """The host part of the global node key `(host, id)`: the lowercased name."""
        return self.host["name"].lower()

    @property
    def is_cluster(self) -> bool:
        return self.host.get("kind") == "cluster"

    @property
    def cluster(self) -> str | None:
        """The cluster this host belongs to (`host.cluster`), or its own name if it is one."""
        return self.host["name"] if self.is_cluster else self.host.get("cluster")

    def vm_disks(self, vm_id: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.type == "vdisk" and (n.vm or {}).get("id") == vm_id]

    def children(self, node_id: str | None) -> list[Node]:
        """Nodes whose parent is `node_id`; with None the top of the tree (disks and vms excluded)."""
        return [n for n in self.nodes.values() if n.parent == node_id and n.type not in ("disk", "vm")]

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
        if self.source != "agent":
            out["source"] = self.source
        if self.origin:
            out["origin"] = self.origin
        out["nodes"] = [n.to_dict() for n in self.nodes.values()]
        out.update(self.extra)
        return out


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_initiator(x: Any) -> bool:
    if isinstance(x, str):
        return bool(x)
    return (isinstance(x, dict) and isinstance(x.get("iqn"), str) and bool(x["iqn"])
            and (x.get("authority") is None or _is_int(x["authority"]))
            and (x.get("default") is None or isinstance(x["default"], bool)))


def validate(doc: Any) -> list[str]:
    """Every way `doc` breaks the contract; an empty list means it is sound."""
    if not isinstance(doc, dict):
        return ["topology is not an object"]
    problems: list[str] = []
    if doc.get("version") != VERSION:
        problems.append(f"version is {doc.get('version')!r}, expected {VERSION}")
    if not isinstance(doc.get("platform"), str) or not doc["platform"]:
        problems.append("platform must be a non-empty string")
    if doc.get("source", "agent") not in SOURCES:
        problems.append(f"source {doc['source']!r} is not one of {', '.join(SOURCES)}")
    if doc.get("origin") is not None and doc["origin"] not in ORIGINS:
        problems.append(f"origin {doc['origin']!r} is not one of {', '.join(ORIGINS)}")
    host = doc.get("host")
    if not isinstance(host, dict) or not isinstance(host.get("name"), str) or not host["name"]:
        problems.append("host.name must be a non-empty string")
    else:
        if "unc_server" in host and host["unc_server"] is not None:
            unc = host["unc_server"]
            if not isinstance(unc, str) or not unc.startswith("\\\\") or "\\" in unc[2:] or len(unc) < 3:
                problems.append(f"host.unc_server {unc!r} must look like \\\\server")
        if host.get("cluster") is not None and (not isinstance(host["cluster"], str) or not host["cluster"]):
            problems.append(f"host.cluster {host['cluster']!r} must be a cluster name")
        if host.get("kind") is not None and host["kind"] not in HOST_KINDS:
            problems.append(f"host.kind {host['kind']!r} is not one of {', '.join(HOST_KINDS)}")
    nodes = doc.get("nodes")
    if not isinstance(nodes, list):
        return problems + ["nodes must be a list"]

    own_host = host["name"].lower() if isinstance(host, dict) and isinstance(host.get("name"), str) else None
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
        for k in ("thin", "attached", "virtual"):
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
        v = n.get("match")
        if v is not None and (not isinstance(v, list) or not all(isinstance(x, str) and x for x in v)):
            problems.append(f"{nid}: match must be a list of non-empty strings")
        v = n.get("initiators")
        if v is not None and (not isinstance(v, list) or not all(_is_initiator(x) for x in v)):
            problems.append(f"{nid}: initiators must be a list of {{iqn, authority}} objects")
        if isinstance(n.get("match"), list):
            for m in n["match"]:
                if isinstance(m, str) and m and not _MATCH_RE.match(m):
                    problems.append(f"{nid}: match {m!r} must look like kind:value")
        if n.get("initiators") and t != "lun":
            problems.append(f"{nid}: only a lun has initiators")
        if n.get("virtual") and t not in LINK_TYPES:
            problems.append(f"{nid}: only a disk, lun or vdisk can be virtual")
        b = n.get("backing")
        if b is not None:
            if t not in LINK_TYPES:
                problems.append(f"{nid}: only a disk, lun or vdisk can have a backing, not a {t}")
            if not isinstance(b, dict) or not all(isinstance(b.get(k), str) and b[k] for k in ("host", "id")):
                problems.append(f"{nid}: backing must be an object with a host and an id")
            elif own_host is not None and b["host"].lower() == own_host:
                problems.append(f"{nid}: backing {b['id']!r} is on this host (backing joins different hosts)")
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

    vm_ids = {nid for nid, n in by_id.items() if n.get("type") == "vm"}
    if vm_ids:
        for nid, n in by_id.items():
            vm = n.get("vm")
            if n.get("type") == "vdisk" and isinstance(vm, dict) and vm.get("id") not in vm_ids:
                problems.append(f"{nid}: vm {vm.get('id')!r} is not a vm node in this topology")

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
    extra = {k: v for k, v in doc.items()
             if k not in ("version", "platform", "host", "collected_at", "nodes", "source", "origin")}
    return Topology(platform=doc["platform"], host=dict(doc["host"]), nodes=nodes,
                    collected_at=doc.get("collected_at"), version=doc["version"],
                    source=doc.get("source", "agent"), origin=doc.get("origin"), extra=extra)


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


def snapshots_from_response(resp: dict[str, Any]) -> list[Topology]:
    """A `storage_topology` reply as the snapshots it carries: the host's own and, from a
    Proxmox node, the cluster's (`cluster_topology`, host.kind "cluster")."""
    out = [from_response(resp)]
    if isinstance(resp.get("cluster_topology"), dict):
        out.append(parse(resp["cluster_topology"]))
    return out


# --- links between hosts ------------------------------------------------------------------

Key = tuple[str, str]   # (lowercased host name, node id): the global key of a node


@dataclass(frozen=True)
class Link:
    """`consumer` is a disk, lun or vdisk that is made of `provider`, a node on another host.
    via: "backing" (the node says so), "config" or "catalog" (a manual link, which wins) or
    "<consumer kind>~<provider kind>" (an automatic match); key is the matched identifier.
    initiator_ok: when the provider is a lun with an ACL naming initiators, whether the
    consumer's host (name or IQN) is on it. note: the manual link's note."""
    consumer: Key
    provider: Key
    via: str
    key: str | None = None
    initiator_ok: bool | None = None
    note: str | None = None


@dataclass(frozen=True)
class Unresolved:
    """A node that should have a provider and has none. Reported, not an error."""
    node: Key
    reason: str
    wanted: str | None = None


def _hex(s: str) -> str:
    return re.sub(r"[^0-9a-f]", "", s.lower())


NAA_PREFIX = "6001405"   # NAA type 6 and the LIO OUI 001405, which Synology's iSCSI target uses


def naa_from_unit_serial(serial: str) -> str:
    """The NAA id an initiator sees for a LIO LUN (a Synology iSCSI LUN), from its
    `vpd_unit_serial` in `iscsi_lun.conf` (equal to the LUN's uuid).

    `6001405` plus the first 25 characters of the serial, where a character that is not
    a hex digit becomes the hex digit of its low four bits (`ord(c) & 0xF`), so the hyphen
    of a uuid, 0x2d, becomes `d`. Hex digits are kept, lowercase. Confirmed on nas3:
    f48f1514-6072-4193-989e-9e7bfbe6d0e1 is seen as scsi-36001405f48f1514d6072d4193d989ed9
    (the leading 3 of `scsi-3` is the id's type, not part of this result).
    """
    if len(serial) < 25:
        raise ValueError(f"vpd_unit_serial {serial!r} is shorter than 25 characters")
    digits = "0123456789abcdef"
    return NAA_PREFIX + "".join(c if c in digits else format(ord(c) & 0xF, "x")
                                for c in serial[:25].lower())


def _naa(s: str) -> str:
    """Hex of an NAA id as written in `naa.6001...`, `scsi-36001...` or bare."""
    h = _hex(s.lower().removeprefix("naa.").removeprefix("scsi-"))
    return h[1:] if len(h) == 33 and h.startswith("3") else h


def _same_naa(a: str, b: str) -> bool:
    return _naa(a) == _naa(b)


def _same(a: str, b: str) -> bool:
    return a == b


def _same_ci(a: str, b: str) -> bool:
    return a.strip().lower() == b.strip().lower()


# (consumer kind, provider kind, equal?, consumer types, provider types)
_RULES = (
    ("naa", "naa", _same_naa, LINK_TYPES, ("lun",)),          # initiator or cluster disk -> Synology LUN
    ("serial", "vmserial", _same_ci, ("disk",), ("vdisk",)),  # guest disk -> hypervisor vdisk
    ("volid", "volid", _same, ("vdisk",), ("disk", "lun")),   # VM disk -> cluster storage volume
    ("vmmdisk", "vmmdisk", _same, ("disk",), ("vdisk",)),     # Virtual DSM disk -> VMM vdisk
)
_CONSUMER_KINDS = {r[0] for r in _RULES}


def _keys(node: Node) -> list[tuple[str, str]]:
    return [tuple(m.split(":", 1)) for m in node.match if ":" in m]  # type: ignore[misc]


def _provider_keys(node: Node) -> list[tuple[str, str]]:
    """The node's `match` keys, plus for a LUN without a `naa:` key the one derived from its
    `vpd_unit_serial` (platform.synology) or else its `uuid:` key, which is the same string."""
    keys = _keys(node)
    if node.type == "lun" and not any(k == "naa" for k, _ in keys):
        serial = (node.platform.get("synology") or {}).get("vpd_unit_serial") \
            or next((v for k, v in keys if k == "uuid"), None)
        if isinstance(serial, str):
            try:
                keys.append(("naa", naa_from_unit_serial(serial)))
            except ValueError:
                pass
    return keys


def _expects_provider(node: Node) -> bool:
    if node.virtual:
        return True
    return (node.parent is None and node.type in ("lun", "vdisk")
            and any(k in _CONSUMER_KINDS for k, _ in _keys(node)))


@dataclass(frozen=True)
class ManualLink:
    """A link written by hand: `from_ref` (a disk, lun or vdisk; see `resolve`) is made of
    `to_ref`. Each is `host/ref`, ref being a node id (`lun:f48f1514-...`) or `type:name`
    (`lun:LUN-3`, matched on the node's name, case-insensitively, when exactly one node of
    that type has it). source: "config" (filecat.toml, read-only in the viewer) or
    "catalog" (stored in the catalog, edited in the viewer)."""
    from_ref: str
    to_ref: str
    note: str | None = None
    source: str = "config"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"from": self.from_ref, "to": self.to_ref, "source": self.source}
        if self.note:
            out["note"] = self.note
        return out


def parse_ref(ref: str) -> Key:
    """`host/ref` as (lowercased host, ref). The ref is `type:...` with a node type: either a
    node id (`lun:f48f...`, `disk:naa.6001...`) or `type:name`. Raises ValueError."""
    host, sep, rest = ref.strip().partition("/")
    if not sep or not host or not rest:
        raise ValueError(f"link {ref!r} must look like host/node-id (or host/type:name)")
    kind = rest.split(":", 1)[0]
    if ":" not in rest or kind not in TYPES or not rest.split(":", 1)[1]:
        raise ValueError(f"link {ref!r}: {rest!r} must be a node id or type:name, "
                         f"type being one of {', '.join(TYPES)}")
    return host.lower(), rest


def _find(topos: dict[str, Topology], key: Key) -> tuple[Node | None, str | None]:
    """The node a ref names: an exact id first, then `type:name` by name. (node, problem)."""
    topo = topos.get(key[0])
    if topo is None:
        return None, f"no snapshot for host {key[0]}"
    node = topo.nodes.get(key[1])
    if node is not None:
        return node, None
    kind, _, name = key[1].partition(":")
    named = [n for n in topo.nodes.values() if n.type == kind and n.name.casefold() == name.casefold()]
    if len(named) == 1:
        return named[0], None
    if named:
        return None, f"ambiguous: {key[0]} has {len(named)} {kind} nodes named {name!r} ({', '.join(n.id for n in named)})"
    return None, f"{key[0]} has no node {key[1]}"


@dataclass(frozen=True)
class Conflict:
    """A manual link that names a different provider than the automatic match (or backing)
    found for the same consumer. The manual link wins and is in `Resolution.links`."""
    consumer: Key
    manual: Link
    automatic: Link


@dataclass(frozen=True)
class ManualResult:
    """What became of one `ManualLink`. status: "resolved", "unresolved" (reason says why) or
    "conflict" (it won against `automatic`). consumer is the disk the link starts from, which
    differs from the named node when a pool or a share was named."""
    link: ManualLink
    status: str
    consumer: Key | None = None
    provider: Key | None = None
    reason: str | None = None
    automatic: Link | None = None


@dataclass
class Resolution:
    links: list[Link]
    unresolved: list[Unresolved]
    conflicts: list[Conflict] = field(default_factory=list)
    manual: list[ManualResult] = field(default_factory=list)


def resolve_links(snapshots: Iterable[Topology], overrides: dict[str, str] | None = None,
                  manual: Iterable[ManualLink] = ()) -> tuple[list[Link], list[Unresolved]]:
    """`resolve(...)` without the conflicts and the per-link results."""
    res = resolve(snapshots, overrides, manual)
    return res.links, res.unresolved


def resolve(snapshots: Iterable[Topology], overrides: dict[str, str] | None = None,
            manual: Iterable[ManualLink] = ()) -> Resolution:
    """Link the disks, luns and vdisks of many hosts' snapshots (a later snapshot replaces an
    earlier one of the same host). For each consumer:

    1. a manual link (`manual`; `overrides` is the same as a `{"host/ref": "host/ref"}` dict
       of config links), which wins over everything below;
    2. its own `backing`;
    3. an automatic match on its `match` identifiers: NAA id to the NAA id of a Synology LUN
       (its `naa:` key, else derived from `vpd_unit_serial` or the uuid), disk serial to a
       hypervisor vdisk's `vmserial`, Proxmox volume id to the cluster storage's disk, VMM
       vdisk uuid to a Virtual DSM disk.

    A manual link starts at a disk, lun or vdisk. Naming a pool, group, volume or share
    starts it at the one disk beneath it (several disks: unresolved, name one). Its target
    may be any node of another host. A link is always to a different host. When the automatic
    result for that consumer is a different provider the link is also reported in
    `conflicts`; an unknown host, node or an ambiguous name is `Unresolved`, never an error.
    A named backing that is missing, or an automatic match that is ambiguous, is `Unresolved`
    too; so is a node that expects a provider (virtual, or a cluster-scope vdisk with a
    volume id) and finds none.
    """
    topos = {t.key: t for t in snapshots}
    wanted = [ManualLink(k, v) for k, v in (overrides or {}).items()] + list(manual)
    refs = [(parse_ref(m.from_ref), parse_ref(m.to_ref)) for m in wanted]
    providers: dict[str, list[tuple[Key, Node, str]]] = {}
    for host, topo in topos.items():
        for node in topo.nodes.values():
            for kind, value in _provider_keys(node):
                providers.setdefault(kind, []).append(((host, node.id), node, value))

    links: dict[Key, Link] = {}
    unresolved: dict[Key, Unresolved] = {}
    for host, topo in topos.items():
        for node in topo.nodes.values():
            if node.type not in LINK_TYPES:
                continue
            me = (host, node.id)
            if node.backing:
                target = (node.backing["host"].lower(), node.backing["id"])
                problem = _target_problem(topos, me, target)
                if problem:
                    unresolved[me] = Unresolved(me, problem, f"{target[0]}/{target[1]}")
                else:
                    links[me] = Link(me, target, "backing")
                continue
            found: dict[Key, tuple[str, str]] = {}
            for ckind, pkind, same, ctypes, ptypes in _RULES:
                if node.type not in ctypes:
                    continue
                for kind, value in _keys(node):
                    if kind != ckind:
                        continue
                    for pkey, pnode, pvalue in providers.get(pkind, ()):
                        if pkey[0] != host and pnode.type in ptypes and same(value, pvalue):
                            found.setdefault(pkey, (f"{ckind}~{pkind}", f"{kind}:{value}"))
            if len(found) == 1:
                (pkey, (how, key)), = found.items()
                links[me] = Link(me, pkey, how, key, _initiator_ok(topo, topos[pkey[0]].nodes[pkey[1]]))
            elif found:
                names = ", ".join(f"{h}/{i}" for h, i in found)
                unresolved[me] = Unresolved(me, f"ambiguous: matches {names}")
            elif _expects_provider(node):
                want = next((f"{k}:{v}" for k, v in _keys(node) if k in _CONSUMER_KINDS), None)
                unresolved[me] = Unresolved(me, "no provider found", want)

    conflicts: list[Conflict] = []
    results: list[ManualResult] = []
    for ml, (fref, tref) in zip(wanted, refs):
        target = f"{tref[0]}/{tref[1]}"

        fnode, problem = _find(topos, fref)
        if problem is None:
            consumer, problem = _consumer_of(topos[fref[0]], fnode)
        if problem:
            unresolved[fref] = Unresolved(fref, problem, target)
            results.append(ManualResult(ml, "unresolved", None, None, problem))
            continue
        me = (fref[0], consumer.id)
        unresolved.pop(me, None)
        tnode, problem = _find(topos, tref)
        if problem is None and tref[0] == fref[0]:
            problem = "a link joins different hosts"
        if problem:
            links.pop(me, None)
            unresolved[me] = Unresolved(me, problem, target)
            results.append(ManualResult(ml, "unresolved", me, None, problem))
            continue
        provider = (tref[0], tnode.id)
        link = Link(me, provider, ml.source, None, _initiator_ok(topos[fref[0]], tnode), ml.note)
        auto = links.get(me)
        links[me] = link
        if auto is not None and auto.provider != provider:
            conflicts.append(Conflict(me, link, auto))
            results.append(ManualResult(ml, "conflict", me, provider, None, auto))
        else:
            results.append(ManualResult(ml, "resolved", me, provider))
    return Resolution(list(links.values()), list(unresolved.values()), conflicts, results)


def _consumer_of(topo: Topology, node: Node) -> tuple[Node | None, str | None]:
    """The disk, lun or vdisk a manual link starts from: the node itself, or for a group,
    pool, volume or share the one disk under it. (node, problem)"""
    if node.type in LINK_TYPES:
        return node, None
    if node.type == "vm":
        return None, f"{node.id} is a vm; link one of its disks"
    disks = sorted(_disks_behind(topo, node))
    if len(disks) == 1:
        return topo.nodes[disks[0]], None
    if not disks:
        return None, f"{node.id} has no disk beneath it; link a disk, lun or vdisk"
    return None, f"{node.id} sits on {len(disks)} disks ({', '.join(disks)}); link one of them"


def _target_problem(topos: dict[str, Topology], me: Key, target: Key) -> str | None:
    if target[0] == me[0]:
        return "a link joins different hosts"
    topo = topos.get(target[0])
    if topo is None:
        return f"no snapshot for host {target[0]}"
    node = topo.nodes.get(target[1])
    if node is None:
        return f"{target[0]} has no node {target[1]}"
    if node.type not in LINK_TYPES:
        return f"{target[1]} is a {node.type}, not a disk, lun or vdisk"
    return None


def _initiator_ok(consumer: Topology, provider: Node) -> bool | None:
    """Is the consumer's host (name or IQN) on the provider LUN's ACL? None: not a LUN, or the
    ACL lists no initiator by name (only the default entry). The `authority` is not used:
    what its values mean is not verified."""
    named = [str(i.get("iqn")).lower() for i in provider.initiators if not i.get("default")]
    if provider.type != "lun" or not named:
        return None
    mine = {consumer.key, str(consumer.host.get("iqn") or "").lower(),
            *(str(q).lower() for q in consumer.host.get("iqns") or ())}
    return any(i in mine for i in named)


def chain(links: Iterable[Link], start: Key) -> list[Key]:
    """`start` and every provider below it, hop by hop, as far as links go."""
    nxt = {link.consumer: link.provider for link in links}
    out = [start]
    while out[-1] in nxt and nxt[out[-1]] not in out:
        out.append(nxt[out[-1]])
    return out


def guest_servers(snapshots: Iterable[Topology], links: Iterable[Link]) -> dict[Key, list[str]]:
    """Derived convenience (what `guest_server` used to store): for every provider node, the
    UNC servers of the hosts whose disks are made of it, through any number of hops. A
    cluster is not a guest."""
    topos = {t.key: t for t in snapshots}
    links = list(links)
    out: dict[Key, list[str]] = {}
    for link in links:
        topo = topos.get(link.consumer[0])
        node = topo.nodes.get(link.consumer[1]) if topo else None
        if topo is None or node is None or node.type != "disk" or topo.is_cluster:
            continue
        for key in chain(links, link.consumer)[1:]:
            servers = out.setdefault(key, [])
            if topo.unc_server not in servers:
                servers.append(topo.unc_server)
    return out


def _disks_behind(topo: Topology, node: Node) -> set[str]:
    """Ids of the disks under a node: its members, those beneath it and those of its ancestors."""
    ids = {m["disk"] for n in topo.subtree(node.id) for m in n.members}
    ids |= {m["disk"] for a in topo.ancestors(node.id) for m in a.members}
    return ids


def physical_summary(snapshots: Iterable[Topology], links: Iterable[Link],
                     unresolved: Iterable[Unresolved] = ()) -> dict[str, Any]:
    """Physical totals over many hosts, each byte counted once.

    The rule is per disk. A disk with a resolved link is not physical on its own host: its
    bytes are already inside the provider's volume (a LUN's allocation lives in the NAS
    volume; a VM disk in the hypervisor's local storage). A top-level pool or volume whose
    disks are all backed is `excluded` from the totals, but its shares still count in
    `share_used_bytes`, which is logical and counts every share of every host. A volume
    that sits on at least one unbacked disk is counted whole.

        disk_bytes         raw size of the unbacked disks
        pool_bytes / volume_bytes / volume_used_bytes / volume_free_bytes   unbacked top-level ones
        excluded           [{host, id, name, type, bytes, backed_by}] pools and volumes left out
        excluded_disk_bytes / unresolved_disk_bytes   backed disks, and virtual disks with no provider
                           (those are counted, since nothing else holds their bytes)
        share_used_bytes   every share that reports a size
        by_host            {host: volume_used_bytes of what was counted}
    """
    topos = {t.key: t for t in snapshots}
    backed = {link.consumer: link.provider for link in links}
    unres = {u.node for u in unresolved}
    out: dict[str, Any] = {k: 0 for k in ("disk_bytes", "pool_bytes", "volume_bytes", "volume_used_bytes",
                                          "volume_free_bytes", "excluded_disk_bytes",
                                          "unresolved_disk_bytes", "share_used_bytes")}
    out["excluded"] = []
    out["by_host"] = {}
    for host, topo in topos.items():
        for n in topo.nodes.values():
            if n.type == "share":
                out["share_used_bytes"] += n.used_bytes or 0
            elif n.type == "disk":
                if (host, n.id) in backed:
                    out["excluded_disk_bytes"] += n.size_bytes or 0
                else:
                    out["disk_bytes"] += n.size_bytes or 0
                    if (host, n.id) in unres:
                        out["unresolved_disk_bytes"] += n.size_bytes or 0
        top = [n for n in topo.nodes.values()
               if (n.type == "pool" and n.parent is None)
               or (n.type == "volume" and (n.parent is None or topo.nodes[n.parent].type == "pool"))]
        for n in top:
            disks = _disks_behind(topo, n)
            if disks and all((host, d) in backed for d in disks):
                first = backed[(host, sorted(disks)[0])]
                out["excluded"].append({"host": host, "id": n.id, "name": n.name, "type": n.type,
                                        "bytes": (n.used_bytes if n.type == "volume" else n.size_bytes) or 0,
                                        "backed_by": f"{first[0]}/{first[1]}"})
            elif n.type == "pool":
                out["pool_bytes"] += n.size_bytes or 0
            else:
                out["volume_bytes"] += n.size_bytes or 0
                out["volume_used_bytes"] += n.used_bytes or 0
                out["volume_free_bytes"] += n.free_bytes or 0
                out["by_host"][host] = out["by_host"].get(host, 0) + (n.used_bytes or 0)
    return out


# --- hosts written by hand -----------------------------------------------------------------

MANUAL_TYPES = ("disk", "group", "pool", "volume", "share", "lun", "vdisk")
MANUAL_KEYS = ("type", "name", "id", "parent", "disks", "size", "used", "free", "unc", "path",
               "virtual", "serial", "model", "media", "kind", "health", "detail", "protocols", "match")
_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(?:([KMGTP])(i?)B)?\s*$", re.IGNORECASE)


def parse_size(value: Any) -> int:
    """Bytes from an integer or a string such as `"10.74 TiB"`, `"500GB"` or `"1024"`.
    KB, MB, ... are powers of 1000, KiB, MiB, ... of 1024. Raises ValueError."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{value!r} is not a size")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{value!r} is not a size")
        return value
    m = _SIZE_RE.match(value)
    if not m:
        raise ValueError(f"{value!r} is not a size (want bytes, or a number with KB, MiB, TB, TiB ...)")
    unit = m.group(2)
    base = 1024 if m.group(3) else 1000
    return int(float(m.group(1)) * (base ** ("KMGTP".index(unit.upper()) + 1) if unit else 1))


def manual_topology(name: str, nodes: list[dict[str, Any]], *, unc_server: str | None = None,
                    platform: str = "manual", origin: str = "config") -> Topology:
    """The snapshot of a host with no agent, from a terse node list (`[[storage.hosts]]`).

    Each node is a dict with `type` (disk group pool volume share lun vdisk) and `name`; the
    rest is optional. `id` defaults to `type:name` (shares: lowercased). `parent` and `disks`
    name nodes of this host by id, by `type:name` or by a name only one node has. A volume
    with no parent goes in the host's only pool, a share with none in its only volume.
    `disks` (pool, group, volume) become `members`. `size`, `used`, `free` take bytes or
    "10.74 TiB". A share's `unc` defaults to `<unc_server>\\<name>` and its `protocols` to smb.
    The other keys are node fields of the same name. Raises ValueError (a TopologyError when
    the result breaks the contract); the snapshot has `source: "manual"`.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("a host needs a name")
    specs: list[dict[str, Any]] = []
    ids: set[str] = set()
    for i, spec in enumerate(nodes, 1):
        label = f"nodes[{i}]"
        if not isinstance(spec, dict):
            raise ValueError(f"{label} wants a table with type and name")
        unknown = [k for k in spec if k not in MANUAL_KEYS]
        if unknown:
            raise ValueError(f"{label}: unknown key {unknown[0]!r}; the keys are {', '.join(MANUAL_KEYS)}")
        kind, nname = spec.get("type"), spec.get("name")
        if kind not in MANUAL_TYPES:
            raise ValueError(f"{label}: type = {kind!r}; choose from {', '.join(MANUAL_TYPES)}")
        if not isinstance(nname, str) or not nname.strip():
            raise ValueError(f"{label} ({kind}): name is required")
        nid = spec.get("id") or f"{kind}:{nname.lower() if kind == 'share' else nname}"
        if not isinstance(nid, str):
            raise ValueError(f"{label}: id wants a string")
        if nid in ids:
            raise ValueError(f"{label}: id {nid!r} is used twice (give one of the nodes an id)")
        ids.add(nid)
        specs.append({**spec, "id": nid, "_label": f"{label} ({nid})"})

    def local(ref: Any, what: str, label: str) -> str:
        if not isinstance(ref, str) or not ref:
            raise ValueError(f"{label}: {what} wants a node id, type:name or name")
        if ref in ids:
            return ref
        kind, _, nm = ref.partition(":")
        named = [s["id"] for s in specs if s["type"] == kind and s["name"].casefold() == nm.casefold()]
        if not named:
            named = [s["id"] for s in specs if s["name"].casefold() == ref.casefold()]
        if len(named) == 1:
            return named[0]
        raise ValueError(f"{label}: {what} {ref!r} " + (
            f"is ambiguous ({', '.join(named)}); write type:name or the id" if named
            else "names no node of this host"))

    def only(kind: str) -> str | None:
        found = [s["id"] for s in specs if s["type"] == kind]
        return found[0] if len(found) == 1 else None

    out: list[dict[str, Any]] = []
    for spec in specs:
        label, kind = spec["_label"], spec["type"]
        n: dict[str, Any] = {"id": spec["id"], "type": kind, "name": spec["name"], "parent": None}
        if spec.get("parent") is not None:
            n["parent"] = local(spec["parent"], "parent", label)
        elif kind == "volume":
            n["parent"] = only("pool")
        elif kind == "share":
            n["parent"] = only("volume")
            if n["parent"] is None:
                raise ValueError(f"{label}: a share needs parent = \"<volume>\" "
                                 "(the host has no volume, or more than one)")
        if "disks" in spec:
            if not isinstance(spec["disks"], list):
                raise ValueError(f"{label}: disks wants a list of disk names")
            n["members"] = [{"disk": local(d, "disks", label), "role": "data"} for d in spec["disks"]]
        for key, field_name in (("size", "size_bytes"), ("used", "used_bytes"), ("free", "free_bytes")):
            if key in spec:
                try:
                    n[field_name] = parse_size(spec[key])
                except ValueError as exc:
                    raise ValueError(f"{label}: {key}: {exc}") from None
        for key in ("unc", "path", "virtual", "serial", "model", "media", "kind", "health", "detail",
                    "protocols", "match"):
            if key in spec:
                n[key] = spec[key]
        if kind == "share":
            n.setdefault("protocols", ["smb"])
            if not n.get("unc") and unc_server:
                n["unc"] = f"{unc_server}\\{spec['name']}"
        out.append(n)
    host: dict[str, Any] = {"name": name.strip()}
    if unc_server:
        host["unc_server"] = unc_server
    return parse({"version": VERSION, "platform": platform or "manual", "host": host,
                  "source": "manual", "origin": origin, "nodes": out})
