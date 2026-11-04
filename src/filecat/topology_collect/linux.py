"""The generic Linux collector: only what is cheap and the same everywhere.

Disks (lsblk when the agent has it, else /sys/block), mounted file systems with their totals
(/proc/mounts and statfs) and the disk each sits on. No md, LVM or ZFS layers yet: those come
with the Proxmox and TrueNAS collectors (docs/agent-allowlist.md), and a host that has them
gets a note in the snapshot saying the layers are not collected.
"""
from __future__ import annotations

import re
from typing import Any, Callable

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


def _naa6(wwn: str | None) -> str | None:
    """The 32 hex digits of an NAA type 6 (registered extended) WWN, as lsblk shows it
    (`0x6001405...`), else None: local disks' type 5 WWNs are not LUNs of another host."""
    h = re.sub(r"[^0-9a-f]", "", (wwn or "").lower().removeprefix("0x").removeprefix("naa."))
    return h if len(h) == 32 and h.startswith("6") else None


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


# Models a hypervisor gives its guests' disks: their serial is the one the VM's config sets
# (Proxmox `serial=`), so such a disk is virtual and links to the vdisk by `serial:`.
VIRTUAL_MODELS = ("QEMU HARDDISK", "QEMU_HARDDISK", "VBOX HARDDISK", "Virtual disk", "Virtual Disk")


def block_disks(r: Reader, platform: str = "linux"
                ) -> tuple[list[dict[str, Any]], Callable[[str], str | None]]:
    """The disk nodes of a Linux host (lsblk, else /sys/block) and `disk_of(kname)`, the disk id a
    block device (a partition, a disk) sits on, or None. Paths to one LUN (one serial or WWN) are
    one disk with `platform.<platform>.paths`; an NAA type 6 WWN is a `naa:` match (a SAN LUN), a
    hypervisor's disk model makes the disk virtual with a `serial:` match. Shared by the Linux and
    TrueNAS collectors."""
    devices = _lsblk(r)
    if devices is None:
        r.note("lsblk is not available: disks come from /sys/block")
        devices = _sysfs_disks(r)
    by_kname = {d.get("kname") or d["name"]: d for d in devices}
    PLATFORM = platform                 # noqa: N806 - the key under node["platform"]

    disks: list[dict[str, Any]] = []
    disk_id: dict[str, str] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for d in devices:
        if d.get("type") != "disk" or _SKIP_DISK.match(d["name"]):
            continue
        serial, wwn = d.get("serial"), d.get("wwn")
        if serial or wwn:
            did = f"disk:{serial}" if serial else f"disk:wwn.{wwn}"
            same = by_id.get(did)
            if same is not None:          # another path to the same LUN (multipath, or two iSCSI portals)
                plat = same["platform"][PLATFORM]
                plat.setdefault("paths", [plat["device"]]).append(f"/dev/{d['name']}")
                disk_id[d.get("kname") or d["name"]] = did
                continue
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
        naa = _naa6(wwn)
        if naa:                           # a SAN LUN (e.g. a Synology iSCSI LUN): link to it by NAA id
            node["match"] = [f"naa:{naa}"]
        elif serial and (d.get("model") or "").strip() in VIRTUAL_MODELS:
            node["virtual"] = True        # a VM's disk: its bytes are the hypervisor's
            node["match"] = [f"serial:{serial}"]
        node["platform"] = {PLATFORM: plat}
        disk_id[d.get("kname") or d["name"]] = did
        by_id[did] = node
        disks.append(node)
    for node in disks:
        paths = node["platform"][PLATFORM].get("paths")
        if paths:
            r.note(f"{node['id']}: one disk seen on {len(paths)} paths ({', '.join(paths)})")

    def disk_of(kname: str) -> str | None:
        seen = set()
        while kname and kname not in seen:
            seen.add(kname)
            if kname in disk_id:
                return disk_id[kname]
            kname = (by_kname.get(kname) or {}).get("pkname")
        return None
    return disks, disk_of


def collect(source: Source, *, name: str | None = None, unc_server: str | None = None,
            now: str | None = None, measure_shares: bool = False) -> topology.Topology:
    r = Reader(source)
    host_name = name or source.hostname
    disks, disk_of = block_disks(r)

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
