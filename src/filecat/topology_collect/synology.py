"""The Synology DSM 7 collector: raw sources -> the generic storage topology.

Everything the old Rust `synology_storage.rs` did, and the layers it lacked, in Python over a
`Source` (a live agent or a recording). The agent reads files and runs allowlisted commands; the
interpretation is here (docs/storage-topology.md section 3, docs/agent-allowlist.md):

    /etc/VERSION                             DSM version
    /proc/mounts, statfs <mount>             volumes and their totals, ro/rw as health
    /sys/block/*, /sys/block/dm-*, /sys/fs/btrfs
                                             disks, the device-mapper chain, the btrfs UUID
    /proc/mdstat, mdadm --detail --scan      md arrays (groups) and their UUIDs
    /etc/lvm/backup/vgN                      the volume group (pool), its LVs
    smartctl --json -i /dev/sataN            a disk's serial, model, WWN (allowlisted `run`)
    /etc/samba/smb.conf, /etc/exports        shares
    <volume>/@iSCSI/LUN/iscsi_lun.conf       LUNs and VMM vdisks; the NAA id by topology.naa_from_unit_serial
    <volume>/@iSCSI/LUN/iscsi_lun_acl.conf   each LUN's initiators
    <volume>/@iSCSI/LUN/iscsi_target.conf, iscsi_mapping.conf   targets (format assumed: *verify on DSM*)
    <volume>/@Repository/<vm>/vguest.conf, vdisk.conf             VMM guests
    sum_subtree of each LUN directory        allocated bytes: st_blocks, never st_size (the 512 GiB ROD)

Items marked "verify on DSM" are the facts not yet seen on a device; each has a fallback and a
note in the snapshot when the fallback is used.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .. import topology
from .common import Reader, finish, now_iso
from .parse import (ST_RDONLY, fs_type_name, md_uuid, parse_blkid_export, parse_exports,
                    parse_lvm_text, parse_mdadm_scan, parse_mdstat, parse_mounts, parse_shell_vars,
                    parse_smartctl_json, parse_smartctl_text, parse_smb_conf, parse_stanzas)
from .source import Source

PLATFORM = "synology"
SMB_CONF_PATHS = ("/etc/samba/smb.conf", "/usr/syno/etc/smb.conf")      # verify on DSM: which one lists the shares
DEFAULT_ACL_IQN = "iqn.2000-01.com.synology:default.acl"
SECTOR = 512
DEVTYPE_DIRS = {5: "BLUN", 11: "BLUN_THICK", 7: "VDISK_BLUN"}
_VOLUME = re.compile(r"^/volume(\d+)$")
_DISK = re.compile(r"^(sata\d+|sas\d+|nvme\d+n\d+)$")
_PART = re.compile(r"^((?:sata|sas)\d+p\d+|nvme\d+n\d+p\d+|sd[a-z]+\d+)$")


def base_disk(partition: str) -> str:
    """sata1p5 -> sata1, nvme0n1p3 -> nvme0n1, sdb5 -> sdb; anything else unchanged."""
    if _PART.match(partition):
        return re.sub(r"p?\d+$", "", partition) if not partition.startswith("sd") else partition.rstrip("0123456789")
    return partition


def _int(text: str | None) -> int | None:
    try:
        return int((text or "").strip())
    except ValueError:
        return None


def _dm_escape(name: str) -> str:
    return name.replace("-", "--")


class _Collector:
    def __init__(self, source: Source, *, name: str | None, unc_server: str | None,
                 measure_shares: bool) -> None:
        self.src = source
        self.r = Reader(source)
        self.name = name or source.hostname
        self.unc_server = unc_server or "\\\\" + self.name
        self.measure_shares = measure_shares
        self.nodes: dict[str, list[dict[str, Any]]] = {k: [] for k in
                                                      ("disk", "pool", "group", "volume", "share", "lun", "vm", "vdisk")}

    # --- small readers ---
    def num(self, path: str) -> int | None:
        return _int(self.r.text(path, max=4096))

    def line(self, path: str) -> str | None:
        t = self.r.text(path, max=4096)
        return t.strip() if t else None

    # --- host ---
    def os_name(self) -> str | None:
        text = self.r.text("/etc/VERSION")
        if text is None:
            return None
        v = parse_shell_vars(text)
        return f"DSM {v['productversion']}" if v.get("productversion") else None

    # --- LVM, md ---
    def volume_groups(self) -> dict[str, dict[str, Any]]:
        """{vg name: {id, extent, pvs: {pv: {device, size}}, lvs: {lv: {id, size}}}} from /etc/lvm/backup."""
        out: dict[str, dict[str, Any]] = {}
        for fname in self.r.names("/etc/lvm/backup") or []:
            text = self.r.text(f"/etc/lvm/backup/{fname}")
            if text is None:
                continue
            try:
                doc = parse_lvm_text(text)
            except ValueError as exc:
                self.r.note(f"/etc/lvm/backup/{fname}: {exc}")
                continue
            for vg_name, vg in doc.items():
                if not isinstance(vg, dict) or "physical_volumes" not in vg:
                    continue
                extent = int(vg.get("extent_size", 8192)) * SECTOR
                pvs = {n: {"device": p.get("device"), "size": int(p.get("pe_count", 0)) * extent}
                       for n, p in (vg.get("physical_volumes") or {}).items()}
                lvs = {}
                for n, lv in (vg.get("logical_volumes") or {}).items():
                    segs = [s for k, s in lv.items() if k.startswith("segment") and isinstance(s, dict)]
                    lvs[n] = {"id": lv.get("id"), "size": sum(int(s.get("extent_count", 0)) for s in segs) * extent}
                out[vg_name] = {"id": vg.get("id"), "extent": extent, "pvs": pvs, "lvs": lvs}
        return out

    def md_arrays(self) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        """(/proc/mdstat arrays, {md name: uuid} from `mdadm --detail --scan`)."""
        text = self.r.text("/proc/mdstat")
        arrays = parse_mdstat(text) if text else {}
        uuids: dict[str, str] = {}
        scan = self.r.run("mdadm_detail_scan")
        if scan is None:
            if arrays:
                self.r.note("mdadm --detail --scan is not available: md arrays are keyed by their members, "
                            "not their UUID")
        else:
            for dev, props in parse_mdadm_scan(scan).items():
                try:
                    uuids[dev.rsplit("/", 1)[-1]] = md_uuid(props["UUID"])
                except (KeyError, ValueError):
                    pass
        return arrays, uuids

    # --- the device-mapper chain behind a mount device ---
    def kernel_name(self, device: str) -> str | None:
        """dm-1 for /dev/mapper/cachedev_0 (or /dev/vg1/volume_1), md2 for /dev/md2."""
        base = device.rsplit("/", 1)[-1]
        if device.startswith("/dev/mapper/"):
            want = base
        elif device.count("/") == 3 and device.startswith("/dev/vg"):
            want = _dm_escape(device.split("/")[2]) + "-" + _dm_escape(base)
        else:
            return base if re.match(r"^(dm-\d+|md\d+|sd[a-z]+\d*|sata\d+p?\d*|nvme\S+)$", base) else None
        for kname in self.r.names("/sys/block") or []:
            if kname.startswith("dm-") and self.line(f"/sys/block/{kname}/dm/name") == want:
                return kname
        return None

    def chain(self, kname: str) -> list[str]:
        """kname, then what it sits on, depth first: dm-1, dm-0, md2."""
        out, stack = [], [kname]
        while stack:
            k = stack.pop()
            if k in out:
                continue
            out.append(k)
            below = self.r.names(f"/sys/block/{k}/slaves") or []
            stack.extend(reversed(below))
        return out

    def fs_uuid(self, fstype: str, knames: list[str]) -> str | None:
        if fstype == "btrfs":
            for uuid in self.r.names("/sys/fs/btrfs") or []:
                if uuid == "features":
                    continue
                if set(self.r.names(f"/sys/fs/btrfs/{uuid}/devices") or []) & set(knames):
                    return uuid
        for entry in self.r.entries("/dev/disk/by-uuid"):
            if entry.link_target and entry.link_target.rsplit("/", 1)[-1] in knames:
                return entry.name
        blkid = self.r.run("blkid_export")
        if blkid:
            for dev in parse_blkid_export(blkid):
                if dev.get("DEVNAME", "").rsplit("/", 1)[-1] in knames and dev.get("UUID"):
                    return dev["UUID"]
        return None

    # --- disks ---
    def disk_info(self, dev: str) -> dict[str, Any]:
        """serial, model, wwn, rotation_rate from smartctl (JSON, then JSON with -d sat, then text)."""
        for entry, parser in (("smartctl_info_json", parse_smartctl_json),
                              ("smartctl_info_json_sat", parse_smartctl_json),
                              ("smartctl_info", parse_smartctl_text)):
            out = self.r.run(entry, f"/dev/{dev}")
            if out is None:
                continue
            try:
                info = parser(out)
            except ValueError:
                continue
            if info.get("serial"):
                return info
        return {}

    def disk_node(self, dev: str, health: str | None) -> dict[str, Any]:
        sectors = self.num(f"/sys/block/{dev}/size")
        info = self.disk_info(dev)
        model = info.get("model") or self.line(f"/sys/block/{dev}/device/model")
        serial = info.get("serial") or self.line(f"/sys/block/{dev}/device/serial")
        rota = self.num(f"/sys/block/{dev}/queue/rotational")
        if dev.startswith("nvme"):
            slot = str(int(re.match(r"nvme(\d+)", dev).group(1)) + 1)
        else:
            digits = re.search(r"(\d+)$", dev)
            slot = digits.group(1) if digits else None
        plat: dict[str, Any] = {"device": f"/dev/{dev}"}
        if info.get("wwn"):
            plat["wwn"] = info["wwn"]
        if serial:
            did = f"disk:{serial}"
        elif info.get("wwn") or self.line(f"/sys/block/{dev}/device/wwid"):
            did = f"disk:wwn.{info.get('wwn') or self.line(f'/sys/block/{dev}/device/wwid')}"
            plat["id_unstable"] = True
            self.r.note(f"{dev}: no serial number readable, the disk is keyed by its WWN")
        else:
            did = f"disk:{dev}"
            plat["id_unstable"] = True
            self.r.note(f"{dev}: no serial number or WWN readable, the disk is keyed by its device name")
        node: dict[str, Any] = {"id": did, "type": "disk", "parent": None}
        if slot:
            node["name"] = f"M.2 Drive {slot}" if dev.startswith("nvme") else f"Drive {slot}"
            node["slot"] = slot
        if health:
            node["health"] = health
        if sectors is not None:
            node["size_bytes"] = sectors * SECTOR
        if serial:
            node["serial"] = serial
        if model:
            node["model"] = model
        if dev.startswith("nvme"):
            node["media"] = "nvme"
        elif rota is not None or "rotation_rate" in info:
            node["media"] = "hdd" if (rota == 1 or info.get("rotation_rate", 0) > 0) else "ssd"
        node["platform"] = {PLATFORM: plat}
        return node

    # --- the build ---
    def run(self, now: str | None) -> topology.Topology:
        mounts = parse_mounts(self.r.text("/proc/mounts") or "")
        volume_mounts = [m for m in mounts if _VOLUME.match(m["mount"])]
        vgs = self.volume_groups()
        arrays, md_uuids = self.md_arrays()

        # volumes -> chain -> pool (VG) or array
        vol_info: list[dict[str, Any]] = []
        used_md: dict[str, str | None] = {}         # md name -> vg name using it (None: used directly)
        for m in sorted(volume_mounts, key=lambda m: int(_VOLUME.match(m["mount"]).group(1))):
            kname = self.kernel_name(m["device"])
            chain = self.chain(kname) if kname else []
            vg_name = lv_name = None
            dm_names = {self.line(f"/sys/block/{k}/dm/name") for k in chain if k.startswith("dm-")}
            for vg, vgd in vgs.items():
                for lv in vgd["lvs"]:
                    if _dm_escape(vg) + "-" + _dm_escape(lv) in dm_names:
                        vg_name, lv_name = vg, lv
            for k in chain:
                if k.startswith("md") and k in arrays:
                    used_md[k] = vg_name
            vol_info.append({"mount": m, "kname": kname, "chain": chain, "vg": vg_name, "lv": lv_name})
        for vg_name, vgd in vgs.items():             # arrays under a VG even when no volume was found on them
            for pv in vgd["pvs"].values():
                md = (pv.get("device") or "").rsplit("/", 1)[-1]
                if md in arrays:
                    used_md.setdefault(md, vg_name)

        # arrays -> groups, and which disks are in them
        group_by_md: dict[str, dict[str, Any]] = {}
        disk_health: dict[str, str] = {}
        disk_names: set[str] = set()
        for dev in self.r.names("/sys/block") or []:
            if _DISK.match(dev) and self.num(f"/sys/block/{dev}/removable") in (0, None):
                disk_names.add(dev)
        for md in sorted(used_md):
            arr = arrays[md]
            members, raw = [], 0
            for mem in arr["members"]:
                disk = base_disk(mem["name"])
                disk_names.add(disk)
                part = self.num(f"/sys/block/{disk}/{mem['name']}/size")
                if mem["failed"]:
                    disk_health[disk] = "failed"
                else:
                    disk_health.setdefault(disk, "ok")
                if not mem["spare"] and part:
                    raw += part * SECTOR
                members.append((disk, "spare" if mem["spare"] else "data"))
            group_by_md[md] = {"arr": arr, "members": members, "raw": raw}
        disks = sorted(disk_names, key=lambda d: (int(m.group(1)) if (m := re.search(r"(\d+)", d)) else 0, d))
        disk_id: dict[str, str] = {}
        for dev in disks:
            node = self.disk_node(dev, disk_health.get(dev))
            disk_id[dev] = node["id"]
            self.nodes["disk"].append(node)

        # pools: a VG, or an array used directly
        pool_of_md: dict[str, str] = {}
        pool_of_vg: dict[str, str] = {}
        for vg_name in sorted(vgs):
            vgd = vgs[vg_name]
            mds = [md for md, v in used_md.items() if v == vg_name]
            if not vgd["id"]:
                self.r.note(f"{vg_name}: no volume group id in /etc/lvm/backup")
                continue
            pid = f"pool:{vgd['id']}"
            pool_of_vg[vg_name] = pid
            for md in mds:
                pool_of_md[md] = pid
            n = re.fullmatch(r"vg(\d+)", vg_name)
            node: dict[str, Any] = {"id": pid, "type": "pool", "parent": None,
                                    "name": f"Storage Pool {n.group(1)}" if n else vg_name,
                                    "size_bytes": sum(p["size"] for p in vgd["pvs"].values()),
                                    "allocated_bytes": sum(lv["size"] for lv in vgd["lvs"].values())}
            raws = [group_by_md[md]["raw"] for md in mds if group_by_md[md]["raw"]]
            if raws:
                node["raw_bytes"] = sum(raws)
            levels = {group_by_md[md]["arr"]["level"] for md in mds}
            if len(mds) > 1:
                node["level"] = "shr"           # several arrays in one VG: the layout SHR makes of unequal disks
            elif len(levels) == 1 and None not in levels:
                node["level"] = levels.pop()
            health = self._health([group_by_md[md]["arr"] for md in mds])
            if health:
                node["health"] = health
            node["platform"] = {PLATFORM: {"vg": vg_name}}
            self.nodes["pool"].append(node)
        for md in sorted(used_md):                  # an array with no VG is its own pool
            if md in pool_of_md:
                continue
            g = group_by_md[md]
            pool_of_md[md] = f"pool:{md_uuids.get(md) or md}"
            node = {"id": pool_of_md[md], "type": "pool", "parent": None, "name": md}
            if g["arr"]["blocks"]:
                node["size_bytes"] = g["arr"]["blocks"] * 1024
            if g["raw"]:
                node["raw_bytes"] = g["raw"]
            if g["arr"]["level"]:
                node["level"] = g["arr"]["level"]
            health = self._health([g["arr"]])
            if health:
                node["health"] = health
            self.nodes["pool"].append(node)

        for md in sorted(used_md):
            g = group_by_md[md]
            arr = g["arr"]
            uid = md_uuids.get(md)
            if uid:
                gid = f"group:{uid}"
            else:
                key = "|".join(sorted(disk_id.get(d, d) for d, _ in g["members"]))
                gid = "group:" + hashlib.sha256(f"{pool_of_md.get(md, md)}|{key}".encode()).hexdigest()[:32]
                self.r.note(f"{md}: no array UUID, keyed by pool and member disks (unstable if a disk is replaced)")
            sectors = self.num(f"/sys/block/{md}/size")
            node = {"id": gid, "type": "group", "parent": pool_of_md.get(md), "name": md}
            size = sectors * SECTOR if sectors else (arr["blocks"] * 1024 if arr["blocks"] else None)
            if size:
                node["size_bytes"] = size
            if g["raw"]:
                node["raw_bytes"] = g["raw"]
            node["role"] = "data"
            if arr["level"]:
                node["level"] = arr["level"]
            health = self._health([arr])
            if health:
                node["health"] = health
            if arr["flags"] and "_" in arr["flags"]:
                node["detail"] = f"[{arr['active']}/{arr['total']}] [{arr['flags']}]"
            node["members"] = [{"disk": disk_id[d], "role": role} for d, role in g["members"] if d in disk_id]
            node["platform"] = {PLATFORM: {"md": md}}
            self.nodes["group"].append(node)

        # volumes
        volume_id: dict[str, str] = {}              # mount -> node id
        for v in vol_info:
            m = v["mount"]
            knames = v["chain"] or ([v["kname"]] if v["kname"] else [])
            uuid = self.fs_uuid(m["type"], knames)
            num = _VOLUME.match(m["mount"]).group(1)
            vid = f"vol:{uuid}" if uuid else f"vol:{m['mount']}"
            if not uuid:
                self.r.note(f"{m['mount']}: no file system UUID found, keyed by its mount point")
            volume_id[m["mount"]] = vid
            node = {"id": vid, "type": "volume", "parent": pool_of_vg.get(v["vg"]) if v["vg"] else None,
                    "name": f"Volume {num}"}
            if node["parent"] is None:
                mds = [k for k in v["chain"] if k in pool_of_md]
                node["parent"] = pool_of_md[mds[0]] if mds else None
            try:
                st = self.src.statfs(m["mount"])
            except Exception as exc:                # AgentError; a recording without a statfs
                self.r.note(f"statfs {m['mount']}: {exc}")
                st = None
            readonly = "ro" in m["options"] or (st is not None and st.flags & ST_RDONLY)
            node["health"] = "warning" if readonly else "ok"
            if st is not None and st.total_bytes:
                used = st.total_bytes - st.free_bytes
                node.update(detail=f"{used / st.total_bytes * 100:.2f}% used", size_bytes=st.total_bytes,
                            used_bytes=used, free_bytes=st.avail_bytes)
            node.update(mount=m["mount"], fs_type=m["type"], device=m["device"])
            if st is not None and fs_type_name(st.fs_type_id) not in (None, m["type"]):
                self.r.note(f"{m['mount']}: mounted as {m['type']} but statfs says {fs_type_name(st.fs_type_id)}")
            if node["parent"] is None and v["chain"]:       # no pool: the disks are the volume's members
                node["members"] = [{"disk": disk_id[base_disk(k)], "role": "data"} for k in v["chain"]
                                   if base_disk(k) in disk_id]
            self.nodes["volume"].append(node)

        self.shares(volume_id)
        for v in vol_info:
            self.block_storage(v["mount"]["mount"], volume_id[v["mount"]["mount"]])
        host: dict[str, Any] = {"name": self.name, "unc_server": self.unc_server}
        os_name = self.os_name()
        if os_name:
            host["os"] = os_name
        nodes = [n for kind in ("disk", "pool", "group", "volume", "share", "lun", "vm", "vdisk")
                 for n in self.nodes[kind]]
        return finish(PLATFORM, host, nodes, self.r, name="synology", collected_at=now)

    @staticmethod
    def _health(arrays: list[dict[str, Any]]) -> str | None:
        if not arrays:
            return None
        if any(a["flags"] and "_" in a["flags"] for a in arrays) or any(
                m["failed"] for a in arrays for m in a["members"]):
            return "degraded"
        if any(a["state"] != "active" for a in arrays):
            return "warning"
        return "ok"

    # --- shares ---
    def shares(self, volume_id: dict[str, str]) -> None:
        mounts = sorted(volume_id, key=len, reverse=True)

        def volume_of(path: str) -> str | None:
            return next((m for m in mounts if path == m or path.startswith(m + "/")), None)

        exports = []
        text = self.r.text("/etc/exports")
        if text:
            exports = parse_exports(text)
        found: list[dict[str, str]] = []
        for conf in SMB_CONF_PATHS:
            text = self.r.text(conf)
            if text is not None:
                found = parse_smb_conf(text)
                break
        else:
            self.r.note("no Samba configuration found (tried " + ", ".join(SMB_CONF_PATHS)
                        + "): shares are the top-level folders of each volume")
            for m in volume_id:
                for e in self.r.entries(m):
                    if e.kind == "dir" and not e.name.startswith(("@", "#", "$", ".")) and e.name != "lost+found":
                        found.append({"name": e.name, "path": f"{m}/{e.name}", "_guessed": "1"})
        seen: set[str] = set()
        for sh in found:
            path = sh["path"].rstrip("/")
            mount = volume_of(path)
            sid = "share:" + sh["name"].lower()
            if mount is None or sid in seen:
                continue
            seen.add(sid)
            prot = ["smb"] + (["nfs"] if path in exports else [])
            node = {"id": sid, "type": "share", "parent": volume_id[mount], "name": sh["name"]}
            if self.measure_shares:
                try:
                    node["used_bytes"] = self.src.sum_subtree(path).total_size
                except Exception as exc:
                    self.r.note(f"sum_subtree {path}: {exc}")
            node.update(path=path, unc=f"{self.unc_server}\\{sh['name']}", protocols=prot)
            if sh.get("_guessed"):
                node["platform"] = {PLATFORM: {"source": "folder"}}
            self.nodes["share"].append(node)
        for path in exports:                             # NFS-only exports
            mount = volume_of(path)
            if mount is None or path == mount or any(n["path"] == path for n in self.nodes["share"]):
                continue
            sid = "share:" + path.rsplit("/", 1)[-1].lower()
            if sid not in seen:
                seen.add(sid)
                self.nodes["share"].append({"id": sid, "type": "share", "parent": volume_id[mount],
                                            "name": path.rsplit("/", 1)[-1], "path": path, "protocols": ["nfs"]})

    # --- LUNs, VMM ---
    def block_storage(self, mount: str, vol_id: str) -> None:
        lun_dir = f"{mount}/@iSCSI/LUN"
        text = self.r.text(f"{lun_dir}/iscsi_lun.conf")
        if text is None:
            return
        stanzas = [p for _, p in parse_stanzas(text) if p.get("uuid")]
        acl: dict[str, list[dict[str, Any]]] = {}
        acl_text = self.r.text(f"{lun_dir}/iscsi_lun_acl.conf")
        for _, p in parse_stanzas(acl_text or ""):
            if p.get("lun_uuid") and p.get("initiator"):
                entry: dict[str, Any] = {"iqn": p["initiator"]}
                if (a := _int(p.get("authority"))) is not None:
                    entry["authority"] = a
                if p["initiator"] == DEFAULT_ACL_IQN:
                    entry["default"] = True
                acl.setdefault(p["lun_uuid"], []).append(entry)
        targets = self.targets(lun_dir)
        repo = self.vmm_guests(mount)

        luns, vdisks = [], []
        for p in stanzas:
            devtype = _int(p.get("devtype"))
            if devtype not in DEVTYPE_DIRS:
                self.r.note(f"{p.get('name', p['uuid'])}: devtype {p.get('devtype')} is not one this collector knows")
                continue
            (vdisks if devtype == 7 else luns).append((p, devtype))
        luns.sort(key=lambda t: (_int(t[0].get("lid")) or 0, t[0]["uuid"]))

        for p, devtype in luns:
            uuid = p["uuid"]
            sub = DEVTYPE_DIRS[devtype]
            node: dict[str, Any] = {"id": f"lun:{uuid}", "type": "lun", "parent": vol_id, "name": p.get("name", uuid)}
            if (size := _int(p.get("bytes"))) is not None:
                node["size_bytes"] = size
            alloc = self.allocated(f"{lun_dir}/{sub}/{uuid}")
            if alloc is not None:
                node["allocated_bytes"] = alloc
            node.update(thin=devtype == 5, kind="iscsi", path=f"{lun_dir}/{sub}/{uuid}")
            if targets.get(uuid):
                node["target"] = targets[uuid]
            serial = p.get("vpd_unit_serial") or uuid
            match = []
            try:
                match.append("naa:" + topology.naa_from_unit_serial(serial))
            except ValueError:
                self.r.note(f"{node['name']}: vpd_unit_serial {serial!r} is too short for an NAA id")
            match.append(f"uuid:{uuid}")
            node["match"] = match
            plat: dict[str, Any] = {"devtype": devtype}
            if (lid := _int(p.get("lid"))) is not None:
                plat["lid"] = lid
            if p.get("vpd_unit_serial"):
                plat["vpd_unit_serial"] = p["vpd_unit_serial"]
            node["platform"] = {PLATFORM: plat}
            inits = sorted(acl.get(uuid, []), key=lambda e: (bool(e.get("default")), e["iqn"]))
            if inits:
                node["initiators"] = inits
            self.nodes["lun"].append(node)

        named_vms = set()                            # VMs that vdisk stanzas name, found or not
        for p, _ in vdisks:
            parts = p.get("name", "").split(".")
            if parts[0] == "vdisk" and len(parts) > 2:
                named_vms.add(parts[1])
        for vm_uuid in sorted(set(repo) | named_vms):
            guest = repo.get(vm_uuid)
            vm: dict[str, Any] = {"id": f"vm:{vm_uuid}", "type": "vm", "parent": None,
                                  "name": guest["conf"].get("name") if guest else "[ORPHANED_VDISK]"}
            plat = {}
            if guest:
                c = guest["conf"]
                plat = {"is_general_vm": bool(c.get("is_general_vm")), "vcpu_num": c.get("vcpu_num"),
                        "vram_size_mib": c.get("vram_size"), "version": c.get("version")}
                plat = {k: v for k, v in plat.items() if v is not None}
            else:
                plat = {"orphaned": True}
            vm["platform"] = {PLATFORM: plat}
            self.nodes["vm"].append(vm)

        def vm_name(u: str) -> str:
            return next(n["name"] for n in self.nodes["vm"] if n["id"] == f"vm:{u}")

        counts: dict[str, int] = {}
        for p, parts in sorted(((p, p.get("name", "").split(".")) for p, _ in vdisks),
                               key=lambda t: (t[1][1] if len(t[1]) > 1 else "", t[1][3] if len(t[1]) > 3 else "",
                                              _int(t[1][4]) if len(t[1]) > 4 else 0, t[0]["uuid"])):
            uuid = p["uuid"]
            node = {"id": f"vdisk:{uuid}", "type": "vdisk", "parent": vol_id}
            attached = parts[0] == "vdisk" and len(parts) > 2
            plat = {"devtype": 7, "kind": "VDISK_BLUN"}
            if attached:
                vm_uuid = parts[1]
                counts[vm_uuid] = counts.get(vm_uuid, 0) + 1
                node["name"] = f"{vm_name(vm_uuid)} disk {counts[vm_uuid]}"
            else:
                node["name"] = f"[VMM_IMAGE: {parts[1][:8] if len(parts) > 1 else uuid[:8]}]"
            if (size := _int(p.get("bytes"))) is not None:
                node["size_bytes"] = size
            alloc = self.allocated(f"{lun_dir}/VDISK_BLUN/{uuid}")
            if alloc is not None:
                node["allocated_bytes"] = alloc
            node.update(thin=True, path=f"{lun_dir}/VDISK_BLUN/{uuid}")
            if attached:
                node["vm"] = {"id": f"vm:{parts[1]}", "name": vm_name(parts[1])}
                node["attached"] = True
                node["match"] = [f"uuid:{uuid}", f"vmmdisk:{uuid}"]
                disk_conf = (repo.get(parts[1]) or {}).get("disks", {}).get(parts[2], {})
                if "is_meta_disk" in disk_conf:
                    plat["is_meta_disk"] = bool(disk_conf["is_meta_disk"])
                if len(parts) > 3:
                    plat["bus"] = parts[3]
                if len(parts) > 4 and (u := _int(parts[4])) is not None:
                    plat["unit"] = u
            else:
                node["attached"] = False
                node["match"] = [f"uuid:{uuid}"]
            node["platform"] = {PLATFORM: plat}
            self.nodes["vdisk"].append(node)

    def allocated(self, path: str) -> int | None:
        """Physical bytes behind a LUN directory: st_blocks * 512 summed (sum_subtree's
        total_allocated_size). Never total_size: the sparse `ROD` file there is 512 GiB."""
        try:
            return self.src.sum_subtree(path).total_allocated_size
        except Exception as exc:
            self.r.note(f"sum_subtree {path}: {exc}")
            return None

    def targets(self, lun_dir: str) -> dict[str, str]:
        """{lun uuid: target name}. *Verify on DSM*: the file names and keys are assumed
        (iscsi_target.conf stanzas with `tid` and `name`; iscsi_mapping.conf stanzas with `tid`
        and `lun_uuid`); a host that has neither gets no `target` on its LUNs."""
        tt = self.r.text(f"{lun_dir}/iscsi_target.conf")
        mt = self.r.text(f"{lun_dir}/iscsi_mapping.conf")
        if tt is None or mt is None:
            return {}
        names = {p["tid"]: p.get("name") for _, p in parse_stanzas(tt) if p.get("tid")}
        out: dict[str, str] = {}
        for _, p in parse_stanzas(mt):
            if p.get("lun_uuid") and names.get(p.get("tid")) and p["lun_uuid"] not in out:
                out[p["lun_uuid"]] = names[p["tid"]]
        return out

    def vmm_guests(self, mount: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for vm_uuid in self.r.names(f"{mount}/@Repository") or []:
            conf = self.r.json(f"{mount}/@Repository/{vm_uuid}/vguest.conf")
            if not isinstance(conf, dict):
                continue
            disks = self.r.json(f"{mount}/@Repository/{vm_uuid}/vdisk.conf")
            out[vm_uuid] = {"conf": conf, "disks": disks if isinstance(disks, dict) else {}}
        return out


def collect(source: Source, *, name: str | None = None, unc_server: str | None = None,
            now: str | None = None, measure_shares: bool = False) -> topology.Topology:
    """The topology of a Synology DSM 7 host from its raw sources. `name` and `unc_server`
    default to the source's hostname and `\\\\<hostname>`; pass the `[[agents]]` alias for the
    server name the catalog's roots use. `measure_shares` sums each share with `sum_subtree`
    (minutes on a big share) for its `used_bytes`."""
    return _Collector(source, name=name, unc_server=unc_server, measure_shares=measure_shares).run(now)


def is_synology(source: Source) -> bool:
    """A DSM host: /etc/VERSION with a `productversion` and /etc/synoinfo.conf or /etc.defaults."""
    r = Reader(source)
    text = r.text("/etc/VERSION")
    return bool(text and "productversion" in parse_shell_vars(text))
