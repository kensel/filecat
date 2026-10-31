"""The TrueNAS (SCALE / Community Edition) collector: disks, ZFS pools and their vdevs, datasets,
zvols and the SMB/NFS shares, after docs/storage-topology.md ("TrueNAS").

    disk     lsblk (as the Linux collector), health from the pool member's state
    group    each top-level vdev of `zpool status -j` (mirror, raidz1..3, draid, or one disk:
             `single`), role from its class; the cache and spare devices are one group each
    pool     `zpool get -j all`: size, allocated, free, ashift, fragmentation, dedup ratio
    volume   each dataset of `zfs list -j` (parent: its parent dataset, the root dataset's is the
             pool); TrueNAS's own trees (boot environments, .system, ix-applications, ix-apps,
             iocage) are one node each, their children counted in `platform.truenas`
    lun      each zvol, with its iSCSI extent when `iscsi.extent.query` names it
    share    `midclt call sharing.smb.query` and `sharing.nfs.query`, merged by path, under the
             dataset that holds the path

The JSON forms of zpool and zfs need OpenZFS 2.3 (TrueNAS 24.10 and later); without them the
pools, datasets and zvols are left out with a note. A vdev names its device by path
(`/dev/disk/by-partuuid/...` or `/dev/sda3`): the links under /dev/disk say which partition,
lsblk which disk it is on.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .. import topology
from .common import Reader, finish
from .linux import disks
from .source import Source

PLATFORM = "truenas"
SYSTEM_TREES = {".system", "ix-applications", "ix-apps", "iocage", ".ix-virt"}
BOOT_POOL = "boot-pool"
LINK_DIRS = ("/dev/disk/by-partuuid", "/dev/disk/by-id", "/dev/disk/by-uuid", "/dev/disk/by-path")
_HEALTH = {"ONLINE": "ok", "DEGRADED": "degraded", "FAULTED": "failed", "UNAVAIL": "failed",
           "REMOVED": "failed", "OFFLINE": "warning"}
_ROLE = {"normal": "data", "log": "log", "special": "special", "dedup": "dedup"}


def is_truenas(source: Source) -> bool:
    """TrueNAS SCALE / CE: os-release says ID=truenas, or the middleware client is there."""
    r = Reader(source)
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        text = r.text(path, silent=True)
        if text is not None:
            return bool(re.search(r'^ID="?truenas"?\s*$', text, re.M))
    return source.has("midclt_pool_query")


def _value(props: dict[str, Any], key: str) -> Any:
    """A property's value from the -j output (`{"value": ..., "source": ...}`); None for "-"."""
    v = (props.get(key) or {}).get("value")
    return None if v in ("-", "none", None) else v


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _json_run(r: Reader, entry: str) -> Any | None:
    out = r.run(entry)
    if not out or not out.strip():
        return None
    try:
        return json.loads(out)
    except ValueError as exc:
        r.note(f"{entry}: not JSON: {exc}")
        return None


INT64_MAX = 2 ** 63 - 1


def _text_guids(r: Reader) -> dict[str, str]:
    """dataset -> guid from `zfs list -H -p` (its last column). `zfs list -j --json-int` clamps
    a guid above 2**63 to 2**63-1 (seen with OpenZFS 2.3/2.4), so half the datasets would
    share one id; the text form prints the full unsigned value."""
    out: dict[str, str] = {}
    for line in (r.run("zfs_list") or "").splitlines():
        cols = line.split("\t")
        if len(cols) >= 9 and cols[-1].isdigit():
            out[cols[0]] = cols[-1]
    return out


def _health(state: str | None) -> str:
    return _HEALTH.get((state or "").upper(), "unknown")


def collect(source: Source, *, name: str | None = None, unc_server: str | None = None,
            now: str | None = None, measure_shares: bool = False) -> topology.Topology:
    r = Reader(source)
    host_name = name or source.hostname
    unc = unc_server or "\\\\" + host_name
    disk_nodes, disk_of = disks(r, PLATFORM)
    disk_by_id = {d["id"]: d for d in disk_nodes}

    links: dict[str, str] = {}                      # /dev/disk/by-*/<name> -> kernel name
    for folder in LINK_DIRS:
        for e in r.entries(folder):
            if e.link_target:
                links[f"{folder}/{e.name}"] = e.link_target.rsplit("/", 1)[-1]

    def kname_of(path: str | None) -> str | None:
        if not path:
            return None
        return links.get(path) or (path.rsplit("/", 1)[-1] if path.startswith("/dev/") else None)

    def member(path: str | None) -> str | None:
        kname = kname_of(path)
        return disk_of(kname) if kname else None

    nodes: list[dict[str, Any]] = []
    status = _json_run(r, "zpool_status_json")
    props = _json_run(r, "zpool_get_json")
    datasets = _json_run(r, "zfs_list_json")
    if status is None or datasets is None:
        r.note("zpool/zfs JSON output is not available (OpenZFS 2.3+, TrueNAS 24.10+): pools, "
               "datasets and zvols are not collected")
    pool_id: dict[str, str] = {}
    for pname, pool in sorted(((status or {}).get("pools") or {}).items()):
        pp = (((props or {}).get("pools") or {}).get(pname) or {}).get("properties") or {}
        guid = str(pool.get("pool_guid") or _value(pp, "guid") or pname)
        pid = f"pool:{guid}"
        pool_id[pname] = pid
        pnode: dict[str, Any] = {"id": pid, "type": "pool", "parent": None, "name": pname, "level": "zfs",
                                 "health": _health(pool.get("state") or _value(pp, "health"))}
        for key, field in (("size", "size_bytes"), ("allocated", "allocated_bytes"), ("free", "free_bytes")):
            if _int(_value(pp, key)) is not None:
                pnode[field] = _int(_value(pp, key))
        plat: dict[str, Any] = {"guid": guid}
        if _int(_value(pp, "ashift")) is not None:
            plat["ashift"] = _int(_value(pp, "ashift"))
        if _int(_value(pp, "fragmentation")) is not None:
            plat["fragmentation"] = _int(_value(pp, "fragmentation"))
        if _value(pp, "dedupratio") is not None:
            plat["dedup_ratio"] = f"{_value(pp, 'dedupratio')}x"
        pnode["platform"] = {PLATFORM: plat}
        nodes.append(pnode)
        nodes.extend(_groups(pool, pid, member, kname_of, disk_by_id))

    vol_id: dict[str, str] = {}                     # dataset name -> node id (shown ones)
    mounts: list[tuple[str, str, int | None]] = []  # (mountpoint, node id, used) for the shares
    all_ds = (datasets or {}).get("datasets") or {}
    shown, hidden_under = _visible(all_ds, _share_paths(r))
    text_guids = _text_guids(r) if all_ds else {}
    for dname in sorted(all_ds, key=lambda n: (n.count("/"), n)):
        ds = all_ds[dname]
        if dname not in shown:
            continue
        dp = ds.get("properties") or {}
        guid = text_guids.get(dname) or str(_value(dp, "guid") or "")
        if not guid or guid == str(INT64_MAX):          # clamped and no text form: key by name
            guid = dname
        parent_name = dname.rsplit("/", 1)[0] if "/" in dname else None
        parent = vol_id.get(parent_name) if parent_name else pool_id.get(ds.get("pool") or dname)
        if parent is None and parent_name:
            parent = pool_id.get(dname.split("/", 1)[0])
        used, avail = _int(_value(dp, "used")), _int(_value(dp, "available"))
        if (ds.get("type") or "").upper() == "VOLUME":
            nodes.append(_zvol(dname, guid, parent, dp, used))
            continue
        node: dict[str, Any] = {"id": f"vol:{guid}", "type": "volume", "parent": parent, "name": dname,
                                "fs_type": "zfs", "device": dname}
        mount = _value(dp, "mountpoint")
        if isinstance(mount, str) and mount.startswith("/"):
            node["mount"] = mount
            mounts.append((mount, node["id"], used))
        if used is not None:
            node["used_bytes"] = used
        if avail is not None:
            node["free_bytes"] = avail
        if parent_name is None and used is not None and avail is not None:
            node["size_bytes"] = used + avail
        if hidden_under.get(dname):
            node["platform"] = {PLATFORM: {"datasets_inside": hidden_under[dname]}}
        vol_id[dname] = node["id"]
        nodes.append(node)

    _attach_extents(r, nodes)
    nodes.extend(_shares(r, mounts, unc))

    host: dict[str, Any] = {"name": host_name, "unc_server": unc}
    release = r.text("/etc/os-release", max=8192, silent=True) or r.text("/usr/lib/os-release", max=8192, silent=True)
    if release:
        mm = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', release, re.M)
        if mm:
            host["os"] = mm.group(1)
    return finish(PLATFORM, host, [*disk_nodes, *nodes], r, name="truenas", collected_at=now)


def _leaves(vdev: dict[str, Any]) -> list[dict[str, Any]]:
    children = vdev.get("vdevs") or {}
    if not children:
        return [vdev]
    return [leaf for child in children.values() for leaf in _leaves(child)]


def _groups(pool: dict[str, Any], pid: str, member: Any, kname_of: Any,
            disk_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """A group per top-level vdev; the cache devices and the spares one group each."""
    out: list[dict[str, Any]] = []
    root = next(iter((pool.get("vdevs") or {}).values()), {})
    top = list((root.get("vdevs") or {}).values())
    for section in ("logs", "special", "dedup"):        # some versions list these classes apart
        top += list((pool.get(section) or {}).values())

    def members(vdevs: list[dict[str, Any]], role: str) -> list[dict[str, Any]]:
        got = []
        for leaf in vdevs:
            did = member(leaf.get("path") or leaf.get("name"))
            if did is None:
                continue
            got.append({"disk": did, "role": role})
            disk = disk_by_id.get(did)
            if disk is not None:
                disk["health"] = _health(leaf.get("state"))
        return got

    for vdev in top:
        role = _ROLE.get(vdev.get("class") or "normal", "data")
        vtype = vdev.get("vdev_type") or "disk"
        vname = str(vdev.get("name") or "")
        if vtype in ("disk", "file"):                 # one device: named by its partition (sdb1)
            level, name = "single", kname_of(vdev.get("path") or vname) or vname.rsplit("/", 1)[-1]
        else:
            level = vname.split("-", 1)[0] if vtype in ("raidz", "draid") else vtype
            name = vname
        group: dict[str, Any] = {"id": f"group:{vdev.get('guid') or pid + ':' + name}", "type": "group",
                                 "parent": pid, "name": name, "role": role, "level": level,
                                 "health": _health(vdev.get("state")),
                                 "members": members(_leaves(vdev), role)}
        if vdev.get("guid") is not None:
            group["platform"] = {PLATFORM: {"guid": str(vdev["guid"])}}
        out.append(group)
    for section, role, name in (("l2cache", "cache", "cache"), ("spares", "spare", "spares")):
        devs = list((pool.get(section) or {}).values())
        if devs:
            out.append({"id": f"group:{pid}:{name}", "type": "group", "parent": pid, "name": name,
                        "role": role, "level": "single", "health": "ok",
                        "members": members([leaf for d in devs for leaf in _leaves(d)], role)})
    return out


def _share_paths(r: Reader) -> list[str]:
    paths = []
    for entry in ("midclt_smb_shares", "midclt_nfs_shares"):
        for s in _json_run(r, entry) or []:
            paths += [p for p in ([s.get("path")] + list(s.get("paths") or [])) if p]
    return paths


def _visible(all_ds: dict[str, Any], share_paths: list[str]) -> tuple[set[str], dict[str, int]]:
    """The datasets shown, and per shown dataset how many it hides. Inside a TrueNAS system tree
    (and in the boot pool) only the tree's top is shown, unless a dataset under it is a share's
    mountpoint or holds a zvol."""
    def system_top(dname: str) -> str | None:
        parts = dname.split("/")
        if parts[0] == BOOT_POOL:
            return BOOT_POOL if len(parts) > 1 else None
        for i in range(1, len(parts) - 1):
            if parts[i] in SYSTEM_TREES:
                return "/".join(parts[: i + 1])
        return None

    keep: set[str] = set()
    for dname, ds in all_ds.items():
        mount = _value(ds.get("properties") or {}, "mountpoint")
        if mount in share_paths:
            keep.add(dname)
    shown = {d for d in all_ds if system_top(d) is None}
    for d in list(keep):                                # a shared dataset and its ancestors
        parts = d.split("/")
        shown.update("/".join(parts[: i + 1]) for i in range(len(parts)))
    hidden: dict[str, int] = {}
    for d in all_ds:
        if d not in shown:
            top = system_top(d)
            if top is not None:
                hidden[top] = hidden.get(top, 0) + 1
    return shown & set(all_ds), hidden


def _zvol(dname: str, guid: str, parent: str | None, dp: dict[str, Any], used: int | None) -> dict[str, Any]:
    volsize, refres = _int(_value(dp, "volsize")), _int(_value(dp, "refreservation"))
    node: dict[str, Any] = {"id": f"lun:{guid}", "type": "lun", "parent": parent, "name": dname,
                            "kind": "zvol", "thin": not refres, "path": f"/dev/zvol/{dname}"}
    if volsize is not None:
        node["size_bytes"] = volsize
    referenced = _int(_value(dp, "referenced"))
    if referenced is not None:
        node["allocated_bytes"] = referenced
    plat: dict[str, Any] = {}
    if used is not None:
        plat["used_bytes"] = used                     # with the refreservation and metadata
    if refres:
        plat["refreservation"] = refres
    if plat:
        node["platform"] = {PLATFORM: plat}
    return node


def _attach_extents(r: Reader, nodes: list[dict[str, Any]]) -> None:
    """The iSCSI extent that serves a zvol (`disk: zvol/<dataset>`), in the lun's platform."""
    extents = _json_run(r, "midclt_iscsi_extents") or []
    by_zvol = {}
    for e in extents:
        disk = str(e.get("disk") or e.get("path") or "")
        if disk.startswith("zvol/"):
            by_zvol[disk[len("zvol/"):]] = e
    for n in nodes:
        e = by_zvol.get(n["name"]) if n["type"] == "lun" else None
        if e is not None:
            plat = n.setdefault("platform", {}).setdefault(PLATFORM, {})
            plat["extent"] = e.get("name")
            if e.get("naa"):
                n.setdefault("match", []).append(f"naa:{str(e['naa']).lower().removeprefix('0x')}")


def _shares(r: Reader, mounts: list[tuple[str, str, int | None]], unc: str) -> list[dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for s in _json_run(r, "midclt_smb_shares") or []:
        path = s.get("path")
        if not path:
            continue
        sh = by_path.setdefault(path, {"name": s.get("name") or path.rsplit("/", 1)[-1], "protocols": [],
                                       "enabled": True})
        sh["protocols"].append("smb")
        sh["smb_name"] = s.get("name")
        sh["enabled"] = sh["enabled"] and s.get("enabled", True) is not False
    for s in _json_run(r, "midclt_nfs_shares") or []:
        for path in [p for p in ([s.get("path")] + list(s.get("paths") or [])) if p]:
            sh = by_path.setdefault(path, {"name": path.rstrip("/").rsplit("/", 1)[-1], "protocols": [],
                                           "enabled": True})
            if "nfs" not in sh["protocols"]:
                sh["protocols"].append("nfs")
            sh["enabled"] = sh["enabled"] and s.get("enabled", True) is not False
    out = []
    for path, sh in sorted(by_path.items()):
        holder = max((m for m in mounts if path == m[0] or path.startswith(m[0].rstrip("/") + "/")),
                     key=lambda m: len(m[0]), default=None)
        if holder is None:                          # a share must sit on something
            r.note(f"share {sh['name']} ({path}): no dataset holds it, left out")
            continue
        node: dict[str, Any] = {"id": f"share:{sh['name'].lower()}", "type": "share",
                                "parent": holder[1], "name": sh["name"],
                                "path": path, "protocols": sh["protocols"]}
        if sh.get("smb_name"):
            node["unc"] = f"{unc}\\{sh['smb_name']}"
        if holder[0] == path and holder[2] is not None:
            node["used_bytes"] = holder[2]
        if not sh["enabled"]:
            node["health"] = "warning"
            node["platform"] = {PLATFORM: {"enabled": False}}
        out.append(node)
    return out
