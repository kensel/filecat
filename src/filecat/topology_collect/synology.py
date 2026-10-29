"""The Synology DSM 7 collector: raw sources -> the generic storage topology.

Everything the old Rust `synology_storage.rs` did, and the layers it lacked, in Python over a
`Source` (a live agent or a recording). The agent reads files and runs allowlisted commands; the
interpretation is here (docs/storage-topology.md section 3, docs/agent-allowlist.md):

    /etc/VERSION                             DSM version
    /etc/space/space_history_<stamp>.xml     DSM's own view of its pools: the newest file by the
                                             stamp in its name gives each pool's md arrays with
                                             their RAID level, the member disks with model, serial,
                                             slot and bay, the volumes, and the SSD cache spaces
    /proc/mounts, statfs <mount>             volumes and their totals, ro/rw as health
    /sys/block/*, /sys/block/dm-*, /sys/fs/btrfs
                                             disks, the device-mapper chain, the btrfs UUID
    /proc/mdstat, mdadm --detail --scan      md arrays and their UUIDs; the pools too when there
                                             is no space history (then md/LVM alone decide)
    /etc/lvm/backup/vgN                      the volume group (pool), its LVs
    smartctl -i /dev/sataN                   a disk's serial, model, WWN, only when the space
                                             history does not name it; the version is asked once
                                             (`smartctl_version`): below 7.0 there is no --json
    /etc/samba/smb.share.conf, smb.conf, /etc/exports  shares
    /usr/syno/etc/iscsi_lun.conf, iscsi_lun_acl.conf
                                             LUNs and VMM vdisks (the NAA id by
                                             topology.naa_from_unit_serial) and each LUN's
                                             initiators; <volume>/@iSCSI/LUN/ holds copies
    /usr/syno/etc/iscsi_target.conf, iscsi_mapping.conf
                                             targets (tid, name, iqn, enabled) and the LUN each
                                             maps, with its LUN number on that target. The
                                             credentials in the target file are never read out
    <volume>/@Repository/<vm>/vguest.conf, vdisk.conf             VMM guests
    sum_subtree of each LUN directory        allocated bytes: st_blocks, never st_size (the 512 GiB ROD)

None of this needs `lsblk` or `findmnt`, which DSM does not have. `iscsiN` block devices
(tcm_loop, DSM's loopback of its own LUNs) are not disks and are left out.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .. import topology
from .common import Reader, finish, now_iso
from .parse import (MAX_SPACE_XML, ST_RDONLY, fs_type_name, md_uuid, newest_space_history,
                    parse_blkid_export, parse_exports, parse_lvm_text, parse_mdadm_scan, parse_mdstat,
                    parse_mounts, parse_shell_vars, parse_smartctl_json, parse_smartctl_text,
                    parse_smartctl_version, parse_smb_conf, parse_smb_includes, parse_space_history,
                    parse_stanzas)
from .source import Source

PLATFORM = "synology"
SMB_CONF = "/etc/samba/smb.conf"
SMB_SHARES = "/etc/samba/smb.share.conf"      # DSM 7: the share stanzas, loaded implicitly by Samba
MAX_SMB_INCLUDES = 16
SYNO_ETC = "/usr/syno/etc"
SPACE_DIR = "/etc/space"
SMARTCTL_JSON = (7, 0)          # smartmontools before this has no --json
DEFAULT_ACL_IQN = "iqn.2000-01.com.synology:default.acl"
SECTOR = 512
EXT4_DEVTYPE = 1                                # ext4 volumes: a directory per LUN in FILE (thick) or THIN
DEVTYPE_DIRS = {5: "BLUN", 11: "BLUN_THICK", 7: "VDISK_BLUN"}
_VOLUME = re.compile(r"^/volume(\d+)$")
_DISK = re.compile(r"^(sata\d+|sas\d+|nvme\d+n\d+|sd[a-z]+)$")      # DSM names disks sataN, or sdX on older models
_UNASKED = object()
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
        self._smart_ver: Any = _UNASKED
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
    def smartctl_version(self) -> tuple[int, int] | None:
        """(major, minor) of smartctl, asked once per host; None when it cannot be told."""
        if self._smart_ver is _UNASKED:
            out = self.r.run("smartctl_version")
            self._smart_ver = parse_smartctl_version(out) if out else None
        return self._smart_ver

    def disk_info(self, dev: str) -> dict[str, Any]:
        """serial, model, wwn, rotation_rate from smartctl: JSON, then JSON with -d sat, then
        text; below smartmontools 7.0 (no --json) the text form straight away."""
        ver = self.smartctl_version()
        forms = [("smartctl_info", parse_smartctl_text)]
        if ver is None or ver >= SMARTCTL_JSON:
            forms = [("smartctl_info_json", parse_smartctl_json),
                     ("smartctl_info_json_sat", parse_smartctl_json)] + forms
        for entry, parser in forms:
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

    def disk_node(self, dev: str, health: str | None, known: dict[str, Any] | None = None) -> dict[str, Any]:
        """`known` is what the space history says of the disk (serial, model, physical_location):
        with a serial there, smartctl is not run."""
        known = known or {}
        sectors = self.num(f"/sys/block/{dev}/size")
        # serial: the space history, DSM's own sysfs file, smartctl, the generic sysfs file
        serial = known.get("serial") or self.line(f"/sys/block/{dev}/device/syno_disk_serial")
        info = {} if serial else self.disk_info(dev)
        model = known.get("model") or info.get("model") or self.line(f"/sys/block/{dev}/device/model")
        serial = serial or info.get("serial") or self.line(f"/sys/block/{dev}/device/serial")
        rota = self.num(f"/sys/block/{dev}/queue/rotational")
        bay = (known.get("physical_location") or "").rsplit("-", 1)[-1]
        if bay.isdigit():
            slot = bay
        elif dev.startswith("nvme"):
            slot = str(int(re.match(r"nvme(\d+)", dev).group(1)) + 1)
        else:
            digits = re.search(r"(\d+)$", dev)
            slot = digits.group(1) if digits else None
        plat: dict[str, Any] = {"device": f"/dev/{dev}"}
        if known.get("physical_location"):
            plat["physical_location"] = known["physical_location"]
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
        spaces = self.space_history()

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

        if spaces is not None:
            pool_of_vg, pool_of_md, pool_of_mount, disk_id, cache_of_mount = self.layout_from_spaces(
                spaces, vgs, arrays, md_uuids)
        else:
            pool_of_vg, pool_of_md, disk_id = self.layout_from_md(vgs, arrays, md_uuids, used_md)
            pool_of_mount, cache_of_mount = {}, {}

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
            node = {"id": vid, "type": "volume", "parent": pool_of_mount.get(m["mount"]) or (
                pool_of_vg.get(v["vg"]) if v["vg"] else None), "name": f"Volume {num}"}
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
            if m["mount"] in cache_of_mount:
                node["platform"] = {PLATFORM: {"ssd_cache": cache_of_mount[m["mount"]]}}
            self.nodes["volume"].append(node)

        self.shares(volume_id)
        self.block_storage_all(volume_id)
        host: dict[str, Any] = {"name": self.name, "unc_server": self.unc_server}
        os_name = self.os_name()
        if os_name:
            host["os"] = os_name
        nodes = [n for kind in ("disk", "pool", "group", "volume", "share", "lun", "vm", "vdisk")
                 for n in self.nodes[kind]]
        return finish(PLATFORM, host, nodes, self.r, name="synology", collected_at=now)

    def sysfs_disks(self) -> set[str]:
        """Whole disks in /sys/block: sataN, sasN, nvmeNnM, sdX; not removable, and never a
        tcm_loop device (DSM's local loopback of one of its own LUNs, `iscsiN` on nas3, which
        would show as sdX on a kernel that names it so)."""
        out = set()
        for e in self.r.entries("/sys/block"):
            if not _DISK.match(e.name) or "tcm_loop" in (e.link_target or ""):
                continue
            if self.num(f"/sys/block/{e.name}/removable") in (0, None):
                out.add(e.name)
        return out

    def space_history(self) -> list[dict[str, Any]] | None:
        """The spaces of the newest /etc/space/space_history_<stamp>.xml (by the stamp in the
        name), or None when there is none or it cannot be used."""
        newest = newest_space_history(self.r.names(SPACE_DIR) or [])
        if newest is None:
            return None
        text = self.r.text(f"{SPACE_DIR}/{newest}", max=MAX_SPACE_XML)
        if text is None:
            return None
        try:
            spaces = parse_space_history(text)
        except ValueError as exc:
            self.r.note(f"{SPACE_DIR}/{newest}: {exc}: pools come from md and LVM")
            return None
        if not any(s["raids"] for s in spaces):
            self.r.note(f"{SPACE_DIR}/{newest}: no md arrays in it: pools come from md and LVM")
            return None
        return spaces

    @staticmethod
    def _space_health(status: str | None) -> str | None:
        if status is None:
            return None
        return "ok" if status == "normal" else "failed" if status in ("crashed", "failed", "faulty") else "warning"

    def layout_from_spaces(self, spaces: list[dict[str, Any]], vgs: dict[str, dict[str, Any]],
                           arrays: dict[str, dict[str, Any]], md_uuids: dict[str, str]
                           ) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
        """Disk, pool and group nodes from DSM's space history, which names each pool's md arrays
        with their RAID level and their member disks with model, serial, slot and bay. The order
        of the spaces means nothing (a pool may come before or after its cache). One array in a
        pool: the pool has its level; several arrays in one LVM: `shr`, each group keeps its own
        level. A `@shared_cache` space is a group with role `cache` under the pool of the volume
        it caches. md and LVM only fill in sizes and health the XML does not carry.

        Returns ({vg: pool id}, {md: pool id}, {mount: pool id}, {device: disk id},
        {mount: cache group id}); only data arrays are in the md map."""
        pools = [s for s in spaces if not s["cache"] and s["raids"]]
        caches = [s for s in spaces if s["cache"] and s["raids"]]
        rank = {"ok": 0, "warning": 1, "failed": 2}

        # disks: everything the XML names, plus whole disks in sysfs that it does not
        known: dict[str, dict[str, Any]] = {}
        health: dict[str, str] = {}
        for s in pools + caches:
            for raid in s["raids"]:
                for d in raid["disks"]:
                    dev = base_disk((d.get("dev_path") or "").rsplit("/", 1)[-1])
                    if not dev:
                        continue
                    known.setdefault(dev, {k: d[k] for k in ("serial", "model", "physical_location") if d.get(k)})
                    h = self._space_health(d.get("status"))
                    if h and rank[h] >= rank.get(health.get(dev, "ok"), 0):
                        health[dev] = h
        for md, arr in arrays.items():
            for mem in arr["members"]:
                if mem["failed"] and base_disk(mem["name"]) in known:
                    health[base_disk(mem["name"])] = "failed"
        names = self.sysfs_disks() | set(known)
        disk_id: dict[str, str] = {}
        for dev in sorted(names, key=lambda d: (int(m.group(1)) if (m := re.search(r"(\d+)", d)) else 0, d)):
            node = self.disk_node(dev, health.get(dev), known.get(dev))
            disk_id[dev] = node["id"]
            self.nodes["disk"].append(node)

        def raid_md(raid: dict[str, Any]) -> str:
            return (raid.get("path") or "").rsplit("/", 1)[-1]

        def raid_uuid(raid: dict[str, Any]) -> str | None:
            try:
                return md_uuid(raid["uuid"])
            except (KeyError, ValueError):
                return md_uuids.get(raid_md(raid))

        def raid_raw(raid: dict[str, Any]) -> int:
            return sum(d["partition_size"] * SECTOR for d in raid["disks"]
                       if isinstance(d.get("partition_size"), int))

        def group_node(raid: dict[str, Any], parent: str, role: str, pool_key: str) -> dict[str, Any]:
            md = raid_md(raid)
            arr = arrays.get(md)
            uid = raid_uuid(raid)
            members = [(base_disk(d["dev_path"].rsplit("/", 1)[-1]), role) for d in raid["disks"] if d.get("dev_path")]
            if uid:
                gid = f"group:{uid}"
            else:
                key = "|".join(sorted(disk_id.get(d, d) for d, _ in members))
                gid = "group:" + hashlib.sha256(f"{pool_key}|{key}".encode()).hexdigest()[:32]
                self.r.note(f"{md}: no array UUID, keyed by pool and member disks (unstable if a disk is replaced)")
            node: dict[str, Any] = {"id": gid, "type": "group", "parent": parent, "name": md}
            sectors = self.num(f"/sys/block/{md}/size")
            size = sectors * SECTOR if sectors else (arr["blocks"] * 1024 if arr and arr["blocks"] else None)
            if size:
                node["size_bytes"] = size
            if raw := raid_raw(raid):
                node["raw_bytes"] = raw
            node["role"] = role
            if raid.get("level"):
                node["level"] = raid["level"].lower()
            h = self._health([arr]) if arr else None
            if h is None and raid["disks"]:
                h = max((self._space_health(d.get("status")) or "ok" for d in raid["disks"]), key=rank.get)
            if h:
                node["health"] = h
            if arr and arr["flags"] and "_" in arr["flags"]:
                node["detail"] = f"[{arr['active']}/{arr['total']}] [{arr['flags']}]"
            node["members"] = [{"disk": disk_id[d], "role": r} for d, r in members if d in disk_id]
            node["platform"] = {PLATFORM: {"md": md}}
            return node

        pool_of_vg: dict[str, str] = {}
        pool_of_md: dict[str, str] = {}
        pool_of_mount: dict[str, str] = {}
        pool_of_space: dict[int, str] = {}
        for s in sorted(pools, key=lambda s: s.get("path", "")):
            lvm = s["lvm"] or {}
            vg = (lvm.get("path") or s.get("path") or "").rsplit("/", 1)[-1]
            raids = sorted(s["raids"], key=raid_md)
            first = raid_uuid(raids[0])
            key = lvm.get("uuid") or s.get("uuid") or first or raid_md(raids[0])
            pid = f"pool:{key}"
            pool_of_space[id(s)] = pid
            if lvm:
                pool_of_vg[vg] = pid
            for raid in raids:
                pool_of_md[raid_md(raid)] = pid
            for vol in s["volumes"]:
                if vol.get("path"):
                    pool_of_mount[vol["path"]] = pid
            vgd = vgs.get(vg)
            n = re.fullmatch(r"vg(\d+)", vg)
            node: dict[str, Any] = {"id": pid, "type": "pool", "parent": None,
                                    "name": f"Storage Pool {n.group(1)}" if n and lvm else vg or raid_md(raids[0])}
            total, free = lvm.get("total_size"), lvm.get("free_size")
            if isinstance(total, int):
                node["size_bytes"] = total
                if isinstance(free, int):
                    node["allocated_bytes"] = total - free
            elif vgd:
                node["size_bytes"] = sum(p["size"] for p in vgd["pvs"].values())
                node["allocated_bytes"] = sum(lv["size"] for lv in vgd["lvs"].values())
            elif len(raids) == 1 and arrays.get(raid_md(raids[0]), {}).get("blocks"):
                node["size_bytes"] = arrays[raid_md(raids[0])]["blocks"] * 1024
            if raw := sum(raid_raw(r) for r in raids):
                node["raw_bytes"] = raw
            levels = {(r.get("level") or "").lower() for r in raids}
            if len(raids) > 1:
                node["level"] = "shr"
            elif levels != {""}:
                node["level"] = levels.pop()
            present = [arrays[raid_md(r)] for r in raids if raid_md(r) in arrays]
            h = self._health(present) if len(present) == len(raids) else self._space_health(lvm.get("status"))
            if h:
                node["health"] = h
            node["platform"] = {PLATFORM: {k: v for k, v in (("vg", vg or None), ("space_id", s.get("space_id"))) if v}}
            self.nodes["pool"].append(node)
            for raid in raids:
                self.nodes["group"].append(group_node(raid, pid, "data", pid))

        cache_of_mount: dict[str, str] = {}
        by_vol_uuid = {v["uuid"]: (s, v) for s in pools for v in s["volumes"] if v.get("uuid")}
        for s in sorted(caches, key=lambda s: s.get("path", "")):
            refs = {c["reference"] for c in s["caches"] if c.get("reference")}
            served = [by_vol_uuid[r] for r in sorted(refs) if r in by_vol_uuid]
            pid = pool_of_space[id(served[0][0])] if served else None
            if pid is None:                            # not named by a volume: the pool that mentions it, or owns the LV
                pid = next((pool_of_space[id(p)] for p in pools if refs & set(p["refs"])), None)
            if pid is None:
                pid = next((pool_of_vg[vg] for vg, vgd in vgs.items() if vg in pool_of_vg
                            and refs & {lv["id"] for lv in vgd["lvs"].values()}), None)
            if pid is None and pool_of_space:
                pid = next(iter(pool_of_space.values()))
                self.r.note(f"{s.get('path', 'SSD cache')}: the space history does not say which pool it "
                            f"serves, put under {'the only pool' if len(pool_of_space) == 1 else 'the first pool'}")
            for raid in sorted(s["raids"], key=raid_md):
                if pid is None:
                    self.r.note(f"{raid_md(raid)}: SSD cache with no pool to attach to, left out")
                    continue
                g = group_node(raid, pid, "cache", pid)
                g["platform"][PLATFORM].update(
                    {k: v for k, v in (("space", (s.get("path") or "").rsplit("/", 1)[-1] or None),
                                       ("cache_for", sorted(v["path"] for _, v in served if v.get("path")) or None))
                     if v})
                self.nodes["group"].append(g)
                for _, v in served:
                    if v.get("path"):
                        cache_of_mount[v["path"]] = g["id"]
        return pool_of_vg, pool_of_md, pool_of_mount, disk_id, cache_of_mount

    def layout_from_md(self,vgs: dict[str, dict[str, Any]], arrays: dict[str, dict[str, Any]],
                       md_uuids: dict[str, str], used_md: dict[str, str | None]
                       ) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        """Disk, pool and group nodes from /proc/mdstat, /etc/lvm/backup and sysfs, when DSM has
        no space history. Returns ({vg: pool id}, {md: pool id}, {device: disk id})."""
        # arrays -> groups, and which disks are in them
        group_by_md: dict[str, dict[str, Any]] = {}
        disk_health: dict[str, str] = {}
        disk_names = self.sysfs_disks()
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

        return pool_of_vg, pool_of_md, disk_id

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
    def smb_files(self) -> list[str] | None:
        """The texts of the Samba files that hold shares, None when none could be read.
        smb.conf (the DSM 7 one has only [global]) and /etc/samba/smb.share.conf, which DSM's
        Samba loads without any `include` naming it, so it is always tried; then the files
        smb.conf and those include (`include = <path>`, in any section), to a depth of
        MAX_SMB_INCLUDES files and each file once. An include with a macro in it is skipped; one
        outside the agent's allowed roots (DSM's /var/tmp/nginx/smb.netbios.aliases.conf) or
        missing is skipped without a note."""
        texts: list[str] = []
        seen: set[str] = set()
        queue = [SMB_CONF, SMB_SHARES]
        while queue and len(seen) < MAX_SMB_INCLUDES:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            text = self.r.text(path, silent=path != SMB_CONF)
            if text is None:
                continue
            texts.append(text)
            queue.extend(parse_smb_includes(text))
        return texts or None

    def shares(self, volume_id: dict[str, str]) -> None:
        mounts = sorted(volume_id, key=len, reverse=True)

        def volume_of(path: str) -> str | None:
            return next((m for m in mounts if path == m or path.startswith(m + "/")), None)

        exports = []
        text = self.r.text("/etc/exports")
        if text:
            exports = parse_exports(text)
        found: list[dict[str, str]] = []
        smb = self.smb_files()
        if smb is not None:
            found = [sh for text in smb for sh in parse_smb_conf(text)]
        else:
            self.r.note(f"no Samba configuration found ({SMB_CONF}, {SMB_SHARES}): shares are the "
                        "top-level folders of each volume")
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
    def lun_files(self, name: str, mounts: list[str], key: tuple[str, ...]
                  ) -> tuple[dict[tuple[str, ...], dict[str, str]], dict[tuple[str, ...], str]]:
        """Stanzas of an iSCSI file (iscsi_lun.conf, iscsi_lun_acl.conf), keyed by the stanza
        keys in `key` that identify one. /usr/syno/etc/<name> is the host-wide union of every
        volume's LUNs (each LUN stanza carries `rootpath=/volumeN`); /volumeN/@iSCSI/LUN/<name>
        holds only that volume's, so a copy being a subset is normal. When the system file cannot
        be read the copies are used and each stanza's home is the volume it was found on. A
        stanza a copy has and the system file lacks, or has with other values, is noted (the
        system file wins). Returns ({identity: stanza}, {identity: home volume, copies only})."""
        def read(path: str) -> dict[tuple[str, ...], dict[str, str]]:
            out = {}
            for _, p in parse_stanzas(self.r.text(path) or ""):
                if all(p.get(k) for k in key):
                    out[tuple(p[k] for k in key)] = p
            return out
        merged = read(f"{SYNO_ETC}/{name}")
        system = bool(merged)
        home: dict[tuple[str, ...], str] = {}
        for mount in mounts:
            for ident, p in read(f"{mount}/@iSCSI/LUN/{name}").items():
                where = f"{mount}/@iSCSI/LUN/{name}"
                if not system:
                    merged.setdefault(ident, p)
                elif ident not in merged:
                    self.r.note(f"{where} has {'/'.join(ident)}, which {SYNO_ETC}/{name} lacks")
                    merged[ident] = p
                elif any(merged[ident].get(k, v) != v for k, v in p.items()):
                    self.r.note(f"{where} and {SYNO_ETC}/{name} differ for {'/'.join(ident)}: "
                                "the system file wins")
                home.setdefault(ident, mount)
        return merged, home

    def block_storage_all(self, volume_id: dict[str, str]) -> None:
        """LUNs, VMM vdisks and guests of every volume. A LUN belongs to the volume of its
        `rootpath`; without one (or when it is no volume we know) to the volume whose copy of
        the file holds it, else the first volume with an @iSCSI/LUN directory."""
        mounts = sorted(volume_id, key=lambda m: int(_VOLUME.match(m).group(1)) if _VOLUME.match(m) else 0)
        luns, home = self.lun_files("iscsi_lun.conf", mounts, ("uuid",))
        if not luns:
            return
        acl_stanzas, _ = self.lun_files("iscsi_lun_acl.conf", mounts, ("lun_uuid", "initiator"))
        acl: dict[str, list[dict[str, Any]]] = {}
        for (lun_uuid, initiator), p in sorted(acl_stanzas.items()):
            entry: dict[str, Any] = {"iqn": initiator}
            if (a := _int(p.get("authority"))) is not None:
                entry["authority"] = a
            if initiator == DEFAULT_ACL_IQN:
                entry["default"] = True
            acl.setdefault(lun_uuid, []).append(entry)
        has_dir = [m for m in mounts if self.r.names(f"{m}/@iSCSI/LUN") is not None]
        by_mount: dict[str, list[dict[str, str]]] = {m: [] for m in mounts}
        for ident, p in luns.items():
            root = (p.get("rootpath") or "").rstrip("/")
            owner = root if root in by_mount else home.get(ident) or next(iter(has_dir), None)
            if owner is None:
                owner = mounts[0]
                self.r.note(f"LUN {p.get('name', ident[0])}: no volume found for it, put on {owner}")
            elif root and root not in by_mount:
                self.r.note(f"LUN {p.get('name', ident[0])}: rootpath {root} is not a volume of this host, "
                            f"put on {owner}")
            by_mount[owner].append(p)
        targets = self.targets()
        for mount in mounts:
            if by_mount[mount]:
                self.block_storage(mount, volume_id[mount], by_mount[mount], acl, targets)


    def block_storage(self, mount: str, vol_id: str, stanzas: list[dict[str, str]],
                      acl: dict[str, list[dict[str, Any]]], targets: dict[str, list[dict[str, Any]]]) -> None:
        lun_dir = f"{mount}/@iSCSI/LUN"
        repo = self.vmm_guests(mount)

        luns, vdisks = [], []
        for p in stanzas:
            devtype = _int(p.get("devtype"))
            if devtype not in DEVTYPE_DIRS and devtype != EXT4_DEVTYPE:
                self.r.note(f"{mount}: LUN {p.get('name', p['uuid'])} has devtype {p.get('devtype')}: "
                            "backing path and allocated bytes are not collected")
            (vdisks if devtype == 7 else luns).append((p, devtype))
        luns.sort(key=lambda t: (_int(t[0].get("lid")) or 0, t[0]["uuid"]))

        for p, devtype in luns:
            uuid = p["uuid"]
            sub = DEVTYPE_DIRS.get(devtype)
            node: dict[str, Any] = {"id": f"lun:{uuid}", "type": "lun", "parent": vol_id, "name": p.get("name", uuid)}
            if (size := _int(p.get("bytes"))) is not None:
                node["size_bytes"] = size
            if sub:
                alloc = self.allocated(f"{lun_dir}/{sub}/{uuid}")
                if alloc is not None:
                    node["allocated_bytes"] = alloc
                node.update(thin=devtype == 5, kind="iscsi", path=f"{lun_dir}/{sub}/{uuid}")
            elif devtype == EXT4_DEVTYPE:
                node.update(kind="iscsi", **({"thin": p["pre_alloc"] == "no"} if p.get("pre_alloc") in ("yes", "no") else {}))
                found = self.ext4_lun(lun_dir, uuid, p.get("pre_alloc") == "yes", node["name"])
                if found:
                    node["path"], node["allocated_bytes"] = found
            else:                                # thin only where the stanza says it is not pre-allocated
                node.update(kind="iscsi", **({"thin": p["pre_alloc"] == "no"} if p.get("pre_alloc") in ("yes", "no") else {}))
            if p.get("description"):
                node["detail"] = p["description"]       # the admin's label ("Windows0")
            if targets.get(uuid):
                node["target"] = ", ".join(t["name"] for t in targets[uuid] if t.get("name"))
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
            if p.get("rootpath"):
                plat["rootpath"] = p["rootpath"]
            if p.get("description"):
                plat["description"] = p["description"]
            if targets.get(uuid):
                plat["targets"] = targets[uuid]
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
            if any(n["id"] == f"vm:{vm_uuid}" for n in self.nodes["vm"]):
                continue                             # a guest with disks on two volumes
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
        images: dict[str, int] = {}                  # image id -> disks numbered so far
        image_disks: dict[str, int] = {}             # image id -> disks it has
        for p, _ in vdisks:
            pp = p.get("name", "").split(".")
            if not (pp[0] == "vdisk" and len(pp) > 2):
                image = pp[1] if len(pp) > 1 else p["uuid"]
                image_disks[image] = image_disks.get(image, 0) + 1
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
                image = parts[1] if len(parts) > 1 else uuid
                images[image] = images.get(image, 0) + 1
                node["name"] = f"[VMM_IMAGE: {image[:8]}]" + (f" disk {images[image]}" if image_disks[image] > 1 else "")
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

    def ext4_lun(self, lun_dir: str, uuid: str, thick: bool, name: str) -> tuple[str, int] | None:
        """(path, allocated bytes) of an ext4 file-backed LUN: its own directory named by the
        uuid, in FILE when pre_alloc=yes (thick), else THIN; the other one is tried when the
        first is not there. What the directory holds is not read, only summed
        (total_allocated_size: the files can be sparse)."""
        order = ("FILE", "THIN") if thick else ("THIN", "FILE")
        for sub in order:
            path = f"{lun_dir}/{sub}/{uuid}"
            try:
                return path, self.src.sum_subtree(path).total_allocated_size
            except Exception:
                continue
        self.r.note(f"{name}: no {order[0]}/{uuid} or {order[1]}/{uuid} directory under {lun_dir}: "
                    "backing path and allocated bytes not collected")
        return None

    def allocated(self, path: str) -> int | None:
        """Physical bytes behind a LUN directory: st_blocks * 512 summed (sum_subtree's
        total_allocated_size). Never total_size: the sparse `ROD` file there is 512 GiB."""
        try:
            return self.src.sum_subtree(path).total_allocated_size
        except Exception as exc:
            self.r.note(f"sum_subtree {path}: {exc}")
            return None

    def targets(self) -> dict[str, list[dict[str, Any]]]:
        """{lun uuid: [{tid, name, iqn, enabled, lun}, ...]} in tid order, from
        /usr/syno/etc/iscsi_target.conf (`[iSCSI_T1]`: tid, name, iqn, enabled=yes|no, ...) and
        iscsi_mapping.conf (`[iSCSI_MAP_T1_L<uuid>]`: tid, uuid, lun = the LUN number on that
        target). A LUN can sit behind several targets. The target file also holds CHAP
        credentials (username, password, mutual_*): only tid, name, iqn and enabled are ever
        taken out of a stanza, so no secret reaches the topology."""
        tt = self.r.text(f"{SYNO_ETC}/iscsi_target.conf")
        mt = self.r.text(f"{SYNO_ETC}/iscsi_mapping.conf")
        if tt is None or mt is None:
            return {}
        targets: dict[int, dict[str, Any]] = {}
        for _, p in parse_stanzas(tt):
            tid = _int(p.get("tid"))
            if tid is None:
                continue
            t: dict[str, Any] = {"tid": tid}
            for key in ("name", "iqn"):
                if p.get(key):
                    t[key] = p[key]
            if p.get("enabled") in ("yes", "no"):
                t["enabled"] = p["enabled"] == "yes"
            targets[tid] = t
        out: dict[str, list[dict[str, Any]]] = {}
        for _, p in parse_stanzas(mt):
            tid = _int(p.get("tid"))
            if p.get("uuid") and tid in targets:
                entry = dict(targets[tid])
                if (n := _int(p.get("lun"))) is not None:
                    entry["lun"] = n
                out.setdefault(p["uuid"], []).append(entry)
        for rows in out.values():
            rows.sort(key=lambda t: t["tid"])
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
