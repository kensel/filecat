"""The generic Linux collector: only what is cheap and the same everywhere.

Disks (lsblk when the agent has it, else /sys/block), mounted file systems with their totals
(/proc/mounts and statfs) and the disk each sits on. No md, LVM or ZFS layers yet: those come
with the Proxmox and TrueNAS collectors (docs/agent-allowlist.md), and a host that has them
gets a note in the snapshot saying the layers are not collected.
"""
from __future__ import annotations

import re
from typing import Any

from .. import topology
from .common import Reader, finish
from .parse import ST_RDONLY, parse_blkid_export, parse_lsblk, parse_mounts
from .source import Source

PLATFORM = "linux"
SECTOR = 512
_REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "ntfs", "ntfs3", "vfat", "exfat", "f2fs", "zfs", "jfs"}
_SKIP_DISK = re.compile(r"^(loop|ram|zram|sr|fd|nbd|dm-|md|zd)\d*")
_COLUMNS = ("lsblk_json", "lsblk_json_legacy", "lsblk_pairs")


def _lsblk(r: Reader) -> list[dict[str, Any]] | None:
    for entry in _COLUMNS:
        out = r.run(entry)
        if out:
            try:
                return parse_lsblk(out)
            except ValueError:
                continue
    return None


def _sysfs_disks(r: Reader) -> list[dict[str, Any]]:
    out = []
    for name in r.names("/sys/block") or []:
        if _SKIP_DISK.match(name) or r.text(f"/sys/block/{name}/removable", max=16) == "1\n":
            continue
        sectors = (r.text(f"/sys/block/{name}/size", max=64) or "").strip()
        rota = (r.text(f"/sys/block/{name}/queue/rotational", max=16) or "").strip()
        out.append({"name": name, "kname": name, "pkname": None, "type": "disk",
                    "size": int(sectors) * SECTOR if sectors.isdigit() else None, "rota": rota == "1",
                    "model": (r.text(f"/sys/block/{name}/device/model", max=256) or "").strip() or None,
                    "serial": (r.text(f"/sys/block/{name}/device/serial", max=256) or "").strip() or None,
                    "wwn": (r.text(f"/sys/block/{name}/device/wwid", max=256) or "").strip() or None,
                    "mountpoints": []})
    return out


def collect(source: Source, *, name: str | None = None, unc_server: str | None = None,
            now: str | None = None, measure_shares: bool = False) -> topology.Topology:
    r = Reader(source)
    host_name = name or source.hostname
    devices = _lsblk(r)
    if devices is None:
        r.note("lsblk is not available: disks come from /sys/block")
        devices = _sysfs_disks(r)
    by_kname = {d.get("kname") or d["name"]: d for d in devices}

    disks: list[dict[str, Any]] = []
    disk_id: dict[str, str] = {}
    for d in devices:
        if d.get("type") != "disk" or _SKIP_DISK.match(d["name"]):
            continue
        serial, wwn = d.get("serial"), d.get("wwn")
        plat: dict[str, Any] = {"device": f"/dev/{d['name']}"}
        if serial:
            did = f"disk:{serial}"
        elif wwn:
            did = f"disk:wwn.{wwn}"
            plat["id_unstable"] = True
        else:
            did = f"disk:{d['name']}"
            plat["id_unstable"] = True
            r.note(f"{d['name']}: no serial number or WWN, keyed by its device name")
        node: dict[str, Any] = {"id": did, "type": "disk", "parent": None, "name": d["name"]}
        if d.get("size") is not None:
            node["size_bytes"] = d["size"]
        if serial:
            node["serial"] = serial
        if d.get("model"):
            node["model"] = d["model"]
        node["media"] = "nvme" if d["name"].startswith("nvme") else "hdd" if d.get("rota") else "ssd"
        node["platform"] = {PLATFORM: plat}
        disk_id[d.get("kname") or d["name"]] = did
        disks.append(node)

    def disk_of(kname: str) -> str | None:
        seen = set()
        while kname and kname not in seen:
            seen.add(kname)
            if kname in disk_id:
                return disk_id[kname]
            kname = (by_kname.get(kname) or {}).get("pkname")
        return None

    uuids: dict[str, str] = {}                      # kernel name -> file system uuid
    for entry in r.entries("/dev/disk/by-uuid"):
        if entry.link_target:
            uuids[entry.link_target.rsplit("/", 1)[-1]] = entry.name
    if not uuids:
        for dev in parse_blkid_export(r.run("blkid_export") or ""):
            if dev.get("UUID") and dev.get("DEVNAME"):
                uuids[dev["DEVNAME"].rsplit("/", 1)[-1]] = dev["UUID"]

    volumes: list[dict[str, Any]] = []
    layered = False
    for m in parse_mounts(r.text("/proc/mounts") or ""):
        if m["type"] not in _REAL_FS or not m["device"].startswith("/dev/"):
            continue
        kname = m["device"].rsplit("/", 1)[-1]
        if re.match(r"^(dm-\d+|md\d+|zd\d+)", kname) or m["device"].startswith("/dev/mapper/"):
            layered = True
        uuid = uuids.get(kname)
        node = {"id": f"vol:{uuid}" if uuid else f"vol:{m['mount']}", "type": "volume", "parent": None,
                "name": m["mount"]}
        try:
            st = source.statfs(m["mount"])
        except Exception as exc:
            r.note(f"statfs {m['mount']}: {exc}")
            st = None
        node["health"] = "warning" if "ro" in m["options"] or (st and st.flags & ST_RDONLY) else "ok"
        if st and st.total_bytes:
            node.update(size_bytes=st.total_bytes, used_bytes=st.total_bytes - st.free_bytes,
                        free_bytes=st.avail_bytes)
        node.update(mount=m["mount"], fs_type=m["type"], device=m["device"])
        disk = disk_of(kname)
        if disk:
            node["members"] = [{"disk": disk, "role": "data"}]
        volumes.append(node)
    if layered:
        r.note("md, LVM or device-mapper layers exist and are not collected by the generic Linux collector")
    host: dict[str, Any] = {"name": host_name, "unc_server": unc_server or "\\\\" + host_name}
    release = r.text("/etc/os-release", max=8192)
    if release:
        mm = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', release, re.M)
        if mm:
            host["os"] = mm.group(1)
    return finish(PLATFORM, host, [*disks, *volumes], r, name="linux", collected_at=now)
