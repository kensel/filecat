"""The TrueNAS (SCALE) collector: ZFS pools, their vdevs, every dataset and zvol, the SMB and
NFS shares and the iSCSI extents (docs/storage-topology.md, "TrueNAS").

Sources, all read-only: `zpool status -P -p` (the vdev layout and roles), `zpool list -H -p -v`
(sizes), `zpool get -H -p all` (guid, ashift), `zfs list -H -p` (datasets and zvols with used,
avail, referenced, volsize and refreservation), lsblk and /dev/disk/by-partuuid for the disks
the vdevs are made of (shared with the Linux collector), and the middleware's own queries
(`midclt call sharing.smb.query`, `sharing.nfs.query`, `iscsi.extent.query`) for what TrueNAS
keeps in its database. /etc/exports stands in for the NFS query when midclt cannot be run.

Zvols are measured from ZFS's own accounting, never by reading them: `size_bytes` is `volsize`
(what the initiator sees), `allocated_bytes` is `referenced` (what its data takes in the pool,
after compression), `thin` is a refreservation of 0. Datasets carry `used` and `avail`; a share
is measured from the dataset it is the mount point of, or with sum_subtree under
--measure-shares when it is a folder inside one.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .. import topology
from . import linux
from .common import Reader, finish
from .parse import (parse_exports, parse_zfs_list, parse_zpool_get, parse_zpool_list,
                    parse_zpool_status)
from .source import Source

PLATFORM = "truenas"
# datasets TrueNAS keeps for itself: not storage anyone shares
_SYSTEM_DATASET = re.compile(r"(^|/)(\.system|\.ix-virt|ix-applications|ix-apps)(/|$)")
_STATE_HEALTH = {"ONLINE": "ok", "AVAIL": "ok", "INUSE": "ok", "DEGRADED": "degraded", "OFFLINE": "warning",
                 "FAULTED": "failed", "UNAVAIL": "failed", "REMOVED": "failed"}
_LEVEL = re.compile(r"^(mirror|raidz[123]?|draid[123]?)")
MIDCLT = ("midclt_pool_query", "midclt_smb_shares", "midclt_nfs_shares", "midclt_iscsi_extents")


def is_truenas(source: Source) -> bool:
    """A host whose agent can run the TrueNAS middleware client."""
    return any(source.has(e) for e in MIDCLT)


def _health(state: str | None) -> str | None:
    return _STATE_HEALTH.get((state or "").upper(), "unknown") if state else None


def _midclt(r: Reader, entry: str) -> list[dict[str, Any]] | None:
    out = r.run(entry)
    if out is None:
        return None
    try:
        data = json.loads(out)
    except ValueError as exc:
        r.note(f"{entry}: not JSON: {exc}")
        return None
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else None


class _Collector:
    def __init__(self, source: Source, host_name: str, unc_server: str, measure_shares: bool) -> None:
        self.src = source
        self.r = Reader(source)
        self.host_name = host_name
        self.unc_server = unc_server
        self.measure_shares = measure_shares
        self.nodes: list[dict[str, Any]] = []
        self.disks: dict[str, dict[str, Any]] = {}
        self.zvols: dict[str, dict[str, Any]] = {}

    # --- disks, and which disk a zpool status path is on ---
    def leaf_resolver(self) -> Any:
        disks, disk_of = linux.block_disks(self.r, PLATFORM)
        self.disks = {d["id"]: d for d in disks}
        links: dict[str, str] = {}              # /dev/disk/by-*/<name> -> kernel name
        for folder in ("/dev/disk/by-partuuid", "/dev/disk/by-id", "/dev/disk/by-uuid"):
            for e in self.r.entries(folder):
                if e.link_target:
                    links[f"{folder}/{e.name}"] = e.link_target.rsplit("/", 1)[-1]

        def resolve(path: str) -> str | None:
            kname = links.get(path) or (path[len("/dev/"):] if path.startswith("/dev/") and path.count("/") == 2
                                        else None)
            return disk_of(kname) if kname else None
        return resolve

    # --- pools and their vdevs ---
    def pools(self) -> dict[str, str]:
        """Pool and group nodes; returns {pool name: pool node id}."""
        resolve = self.leaf_resolver()
        status = parse_zpool_status(self.r.run("zpool_status") or "")
        sizes = parse_zpool_list(self.r.run("zpool_list") or "")
        props = parse_zpool_get(self.r.run("zpool_get") or "")
        if not status and not sizes:
            self.r.note("no ZFS pool found (zpool status and zpool list gave nothing)")
        pool_ids: dict[str, str] = {}
        for name in sorted(set(status) | set(sizes)):
            p, s, g = status.get(name) or {"state": None, "vdevs": []}, sizes.get(name) or {}, props.get(name) or {}
            guid = g.get("guid") or name
            pid = f"pool:{guid}"
            pool_ids[name] = pid
            node: dict[str, Any] = {"id": pid, "type": "pool", "parent": None, "name": name}
            health = _health(p["state"] or s.get("health"))
            if health:
                node["health"] = health
            for key, field in (("size", "size_bytes"), ("alloc", "allocated_bytes"), ("free", "free_bytes")):
                if s.get(key) is not None:
                    node[field] = s[key]
            plat: dict[str, Any] = {"guid": guid}
            if g.get("ashift", "").isdigit():
                plat["ashift"] = int(g["ashift"])
            if s.get("frag") is not None:
                plat["fragmentation"] = s["frag"]
            if s.get("dedup"):
                plat["dedup_ratio"] = s["dedup"]
            node["platform"] = {PLATFORM: plat}
            groups, direct, levels = [], [], []
            for v in p["vdevs"]:
                members = []
                for leaf in v["leaves"]:
                    disk = resolve(leaf["path"])
                    if disk is None:
                        self.r.note(f"{name}: {leaf['path']} is not on a disk lsblk listed")
                        continue
                    if leaf["state"] and leaf["state"] != "ONLINE" and leaf["state"] not in ("AVAIL", "INUSE"):
                        self.disks[disk]["health"] = _health(leaf["state"])
                    else:
                        self.disks[disk].setdefault("health", "ok")
                    members.append({"disk": disk, "role": v["role"]})
                level = _LEVEL.match(v["name"])
                if level:                        # mirror-0, raidz2-1, draid...: a group of its own
                    gnode = {"id": f"group:{guid}/{v['name']}", "type": "group", "parent": pid, "name": v["name"],
                             "role": v["role"], "level": level.group(1), "members": members}
                    if _health(v["state"]):
                        gnode["health"] = _health(v["state"])
                    groups.append(gnode)
                    if v["role"] == "data":
                        levels.append(level.group(1))
                elif v["role"] == "data":        # a single device of the data section
                    direct.extend(members)
                    levels.append("single")
                else:                            # log, cache, spare devices on their own: one group per section
                    section = next((x for x in groups if x["id"] == f"group:{guid}/{v['role']}"), None)
                    if section is None:
                        section = {"id": f"group:{guid}/{v['role']}", "type": "group", "parent": pid,
                                   "name": {"log": "logs", "spare": "spares"}.get(v["role"], v["role"]),
                                   "role": v["role"], "level": "single", "members": []}
                        groups.append(section)
                    section["members"].extend(members)
            if levels:
                node["level"] = levels[0] if len(set(levels)) == 1 else "mixed"
                if node["level"] == "single" and len(direct) > 1:
                    node["level"] = "stripe"
            if direct:
                node["members"] = direct
            self.nodes.append(node)
            self.nodes.extend(groups)
        return pool_ids

    # --- datasets and zvols ---
    def datasets(self, pool_ids: dict[str, str]) -> dict[str, dict[str, Any]]:
        """Volume nodes (datasets) and lun nodes (zvols); returns {mountpoint: volume node}."""
        rows = parse_zfs_list(self.r.run("zfs_list") or "")
        if not rows and pool_ids:
            self.r.note("zfs list gave no datasets")
        vol_ids: dict[str, str] = {}
        mounts: dict[str, dict[str, Any]] = {}
        for d in sorted(rows, key=lambda x: x["name"].count("/")):   # parents first
            name = d["name"]
            pool, _, rest = name.partition("/")
            if _SYSTEM_DATASET.search(name) or (pool == "boot-pool" and rest):
                continue
            parent = vol_ids.get(name.rsplit("/", 1)[0]) if rest else pool_ids.get(pool)
            if parent is None:
                continue                          # under a skipped dataset, or a pool zpool did not list
            ident = d["guid"] or name
            if d["type"] == "volume":
                node: dict[str, Any] = {"id": f"lun:{ident}", "type": "lun", "parent": parent, "name": name,
                                        "kind": "zvol", "path": f"/dev/zvol/{name}",
                                        "thin": not d["refreservation"]}
                if d["volsize"] is not None:
                    node["size_bytes"] = d["volsize"]
                if d["refer"] is not None:
                    node["allocated_bytes"] = d["refer"]
                node["platform"] = {PLATFORM: {k: d[k] for k in ("used", "refreservation") if d[k] is not None}}
                self.nodes.append(node)
                self.zvols[name] = node
                continue
            if d["type"] != "filesystem":
                continue
            node = {"id": f"vol:{ident}", "type": "volume", "parent": parent, "name": name,
                    "fs_type": "zfs", "device": name}
            if d["used"] is not None:
                node["used_bytes"] = d["used"]
            if d["avail"] is not None:
                node["free_bytes"] = d["avail"]
            if not rest and d["used"] is not None and d["avail"] is not None:
                node["size_bytes"] = d["used"] + d["avail"]     # the pool's root dataset: its usable size
            if d["mountpoint"]:
                node["mount"] = d["mountpoint"]
                mounts[d["mountpoint"]] = node
            if d["refer"] is not None:
                node["platform"] = {PLATFORM: {"referenced": d["refer"]}}
            vol_ids[name] = node["id"]
            self.nodes.append(node)
        return mounts

    # --- iSCSI extents: on the zvol they export ---
    def extents(self) -> None:
        for ext in _midclt(self.r, "midclt_iscsi_extents") or []:
            disk = str(ext.get("disk") or "")
            zvol = self.zvols.get(disk[len("zvol/"):]) if disk.startswith("zvol/") else None
            if zvol is None:
                continue
            plat = zvol["platform"][PLATFORM]
            plat["extent"] = ext.get("name")
            if ext.get("enabled") is False:
                plat["extent_enabled"] = False
            naa = re.sub(r"[^0-9a-f]", "", str(ext.get("naa") or "").lower().removeprefix("0x"))
            if naa:                                  # what an initiator sees: links its disk to this zvol
                zvol["match"] = [f"naa:{naa}"]
            if ext.get("serial"):
                plat["serial"] = ext["serial"]

    # --- shares ---
    def shares(self, mounts: dict[str, dict[str, Any]]) -> None:
        by_len = sorted(mounts, key=len, reverse=True)

        def dataset_of(path: str) -> dict[str, Any] | None:
            m = next((m for m in by_len if path == m or path.startswith(m.rstrip("/") + "/")), None)
            return mounts[m] if m else None

        found: dict[str, dict[str, Any]] = {}     # path -> {"name", "protocols"}
        smb = _midclt(self.r, "midclt_smb_shares")
        for sh in smb or []:
            path = str(sh.get("path") or "").rstrip("/")
            if path.startswith("/") and sh.get("name") and sh.get("enabled", True) is not False:
                found.setdefault(path, {"name": str(sh["name"]), "protocols": []})["protocols"].append("smb")
        nfs = _midclt(self.r, "midclt_nfs_shares")
        if nfs is None:
            text = self.r.text("/etc/exports")
            nfs = [{"path": p} for p in parse_exports(text or "")]
        for sh in nfs:
            if sh.get("enabled", True) is False:
                continue
            for path in [sh.get("path")] + list(sh.get("paths") or []):
                path = str(path or "").rstrip("/")
                if not path.startswith("/"):
                    continue
                entry = found.setdefault(path, {"name": path.rsplit("/", 1)[-1], "protocols": []})
                if "nfs" not in entry["protocols"]:
                    entry["protocols"].append("nfs")
        if smb is None and not found:
            self.r.note("the TrueNAS middleware could not be asked for its shares (midclt): none listed")
        taken: set[str] = set()
        for path, sh in sorted(found.items()):
            dataset = dataset_of(path)
            sid = "share:" + sh["name"].lower()
            if dataset is None or sid in taken:
                continue
            taken.add(sid)
            node: dict[str, Any] = {"id": sid, "type": "share", "parent": dataset["id"], "name": sh["name"],
                                    "path": path, "protocols": sh["protocols"],
                                    "unc": f"{self.unc_server}\\{sh['name']}"}
            if self.measure_shares:
                try:
                    node["used_bytes"] = self.src.sum_subtree(path).total_size
                except Exception as exc:
                    self.r.note(f"sum_subtree {path}: {exc}")
            elif dataset.get("mount") == path and dataset.get("used_bytes") is not None:
                node["used_bytes"] = dataset["used_bytes"]
            self.nodes.append(node)

    def host(self) -> dict[str, Any]:
        host: dict[str, Any] = {"name": self.host_name, "unc_server": self.unc_server}
        version = (self.r.text("/etc/version", max=4096, silent=True) or "").strip()
        if version:
            host["os"] = version if version.lower().startswith("truenas") else f"TrueNAS {version}"
        return host


def collect(source: Source, *, name: str | None = None, unc_server: str | None = None,
            now: str | None = None, measure_shares: bool = False) -> topology.Topology:
    host_name = name or source.hostname
    c = _Collector(source, host_name, unc_server or "\\\\" + host_name, measure_shares)
    pool_ids = c.pools()
    mounts = c.datasets(pool_ids)
    c.extents()
    c.shares(mounts)
    disks = list(c.disks.values())
    return finish(PLATFORM, c.host(), [*disks, *c.nodes], c.r, name="truenas", collected_at=now)
