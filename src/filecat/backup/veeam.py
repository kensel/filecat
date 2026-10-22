"""Veeam backup files (Veeam Agent for Windows / Linux, Backup & Replication).

Veeam does not document the format; this is read from Veeam Agent for
Windows 6.x jobs written to an SMB share. Layout of a job folder::

    Job <HOST>/                              <- the store root
        Job <HOST>.vbm                       XML: the job and every restore point
                                             it still tracks (read normally)
        Job <HOST>2024-04-01T003011.vbk      full backup          } opaque: one
        Job <HOST>2024-04-02T003012.vib      forward increment    } file per
        ...                .vrb              reverse increment    } restore point

The .vbm is the manifest: <Backup> names the job, <Storages> lists each
backup file (its path as written, creation time, and Stats with BackupSize =
the file's size and DataSize = the data read), <Points> the restore points
(Type 0 full, 1 increment; LinkId the point before it), <OIB> joins a point
to its file and the machine, with IsCorrupted / IsConsistent and the disks
and OS in AuxData.

Checks (from the .vbm and the walk's listing, no backup file is opened):
- every file the .vbm lists is in the folder with its BackupSize;
- restore points Veeam marked corrupt, partial increments, increments whose
  parent the .vbm does not list; what depends on a missing or corrupt file;
- backup files in the folder the .vbm does not list (Veeam no longer tracks
  them, so its restore wizard will not offer them).
With `scan --verify-backups` each backup file's own metadata is read too
(~0.02% of the file: header, both snapshot slots, the metadata banks) and
its CRC32C checksums and end-of-file mark checked. Data blocks are not read.

The on-disk format, as far as it is known, is in docs/formats/veeam-vbk.md.
"""
from __future__ import annotations

import os
import re
import struct
import xml.etree.ElementTree as ET
import zlib
from datetime import datetime, timezone
from typing import Any, Callable

from .util import listdir

DATA_EXT = (".vbk", ".vib", ".vrb", ".vlb", ".vsb")
_STAMPED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{6}(_[0-9a-f]{4})?\.(vbk|vib|vrb)$", re.I)
_POINT_TYPE = {"0": "full", "1": "increment", "2": "reverse"}
_MAX_EXAMPLES = 5
_PAGE = 4096


def _when(text: str | None) -> str | None:
    """'04/17/2024 06:30:11' (the .vbm's UTC fields) -> ISO."""
    try:
        return datetime.strptime(text or "", "%m/%d/%Y %H:%M:%S").replace(tzinfo=timezone.utc) \
            .isoformat(timespec="seconds")
    except ValueError:
        return None


def _basename(path: str | None) -> str:
    return re.split(r"[\\/]", path or "")[-1]


def _int(text: str | None) -> int | None:
    try:
        return int(text) if text is not None else None
    except ValueError:
        return None


def _xml(text: str | None) -> ET.Element | None:
    """The XML documents the .vbm keeps escaped inside attributes."""
    try:
        return ET.fromstring(text) if text else None
    except ET.ParseError:
        return None


def _os_listing(path: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for name, e in listdir(path).items():
        try:
            if e.is_file(follow_symlinks=False):
                out[name] = e.stat(follow_symlinks=False).st_size
        except OSError:
            pass
    return out


class _Veeam:
    name = "veeam"
    uses_listing = True     # summarize() takes the walk's listing of the store
    verifies = True         # and verify=True: check each backup file's own metadata

    def matches(self, dir_name: str, names: set[str]) -> bool:
        lower = [n.lower() for n in names]
        data = [n for n in lower if n.endswith(DATA_EXT)]
        if any(n.endswith(".vbm") for n in lower):
            return bool(data)
        # no .vbm (lost, or a copied file): only Veeam's own timestamped names,
        # so a VMware .vib bundle or a dictionary .vrb is not taken for one
        return any(_STAMPED.search(n) for n in data)

    def opaque(self, inner: str) -> bool:
        return "/" not in inner and inner.lower().endswith(DATA_EXT)

    def summarize(self, path: str, names: set[str],
                  listing: Callable[[], dict[str, int]] | None = None,
                  verify: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {"format": self.name}
        problems: list[str] = []
        on_disk = {k: v for k, v in (listing() if listing else _os_listing(path)).items() if "/" not in k}
        data_files = sorted(n for n in on_disk if n.lower().endswith(DATA_EXT))

        metas = sorted(n for n in on_disk if n.lower().endswith(".vbm"))
        if not metas:
            problems.append("no .vbm in the folder: the restore points are not listed")
        points: list[dict[str, Any]] = []
        machines: dict[str, dict[str, Any]] = {}
        for meta in metas:
            try:
                root = ET.parse(os.path.join(path, meta)).getroot()
            except (OSError, ET.ParseError) as e:
                problems.append(f"{meta} unreadable: {type(e).__name__}: {e}")
                continue
            self._read_meta(root, meta, out, points, machines)

        points.sort(key=lambda p: (p.get("created") or "", p["file"]))
        listed = {p["file"] for p in points}
        missing, differ = [], []
        for p in points:
            size = on_disk.get(p["file"])
            p["on_disk"] = size is not None
            if size is None:
                missing.append(p["file"])
            elif p.get("backup_bytes") and size != p["backup_bytes"]:
                differ.append(p["file"])
                p["size_on_disk"] = size
        self._chain_problems(points, problems)
        for p in points:
            if p["file"] in differ:
                problems.append(f"{p['file']}: {p['size_on_disk']} bytes on disk, metadata {p['backup_bytes']}")
        unlisted = [n for n in data_files if n not in listed]
        if metas and unlisted:
            problems.append(f"{len(unlisted)} backup files are not in the .vbm (Veeam no longer tracks them), "
                            f"e.g. {', '.join(unlisted[:_MAX_EXAMPLES])}")

        good = [p for p in points if p["on_disk"] and not p.get("corrupt")]
        out.update({
            "machines": sorted(machines),
            "os": next((m["os"] for m in machines.values() if m.get("os")), None),
            "points": points,
            "versions": len(points),
            "fulls": sum(1 for p in points if p["type"] == "full"),
            "latest": max((p["created"] for p in points if p.get("created")), default=None),
            "latest_good": max((p["created"] for p in good if p.get("created")), default=None),
            "storage": {"backup_bytes": sum(p.get("backup_bytes") or 0 for p in points),
                        "data_bytes": sum(p.get("data_bytes") or 0 for p in points),
                        "on_disk_bytes": sum(on_disk[n] for n in data_files)},
            "files": {"listed": len(points), "missing": len(missing), "size_mismatch": len(differ),
                      "unlisted": len(unlisted)},
            "unlisted": unlisted,
        })
        if verify:
            checked = []
            for n in data_files:
                info = check_file(os.path.join(path, n), on_disk[n])
                checked.append({"file": n, **{k: v for k, v in info.items() if k != "problems"}})
                problems += [f"{n}: {q}" for q in info["problems"]]
            out["verified"] = checked
        out["problems"] = problems
        out["copy_keys"] = sorted(f"veeam-point:{p['point_id']}" for p in good if p.get("point_id"))
        out["machine_keys"] = sorted({f"host:{m.lower()}" for m in machines}
                                     | {f"veeam-object:{m['uuid'].lower()}" for m in machines.values()
                                        if m.get("uuid")})
        return out

    def _read_meta(self, root: ET.Element, meta: str, out: dict[str, Any],
                   points: list[dict[str, Any]], machines: dict[str, dict[str, Any]]) -> None:
        b = root.find("Backup")
        if b is not None and "job" not in out:
            out.update({
                "job": b.get("JobName"), "job_id": b.get("JobId"), "backup_id": b.get("Id"),
                "job_type": _int(b.get("JobType")), "platform": _int(b.get("BackupPlatform")),
                "created": b.get("CreationTime"),       # local time of the writer
                "written_to": b.get("DirPath"),         # where Veeam wrote it, before any move
                "encrypted": b.get("EncryptionState") not in (None, "0"),
                "metadata_updated": _when(root.get("CreationTimeUtc")),
            })
        objects = {o.get("Id"): o for o in root.iter("Object")}
        for o in objects.values():
            name = o.get("Name") or o.get("DisplayName")
            if name:
                machines.setdefault(name, {"uuid": o.get("Uuid") or o.get("ObjectId")})
        storages = {s.get("Id"): s for s in root.iter("Storage")}
        pts = {p.get("Id"): p for p in root.iter("Point")}
        by_storage = {o.get("StorageId"): o for o in root.iter("OIB")}
        for sid, s in storages.items():
            stats = _xml(s.get("Stats"))
            oib = by_storage.get(sid)
            pt = pts.get(oib.get("PointId")) if oib is not None else None
            fname = _basename(s.get("FilePath"))
            kind = _POINT_TYPE.get(pt.get("Type") if pt is not None else "", None) or \
                {".vbk": "full", ".vrb": "reverse"}.get(os.path.splitext(fname)[1].lower(), "increment")
            p: dict[str, Any] = {
                "file": fname, "storage_id": sid, "link": s.get("LinkId"),
                "point_id": pt.get("Id") if pt is not None else None,
                "num": pt.get("Num") if pt is not None else None,
                "type": kind, "created": _when(s.get("CreationTimeUtc")),
                "backup_bytes": _int(stats.findtext("BackupSize")) if stats is not None else None,
                "data_bytes": _int(stats.findtext("DataSize")) if stats is not None else None,
                "dedup": _int(stats.findtext("DedupRatio")) if stats is not None else None,
                "compress": _int(stats.findtext("CompressRatio")) if stats is not None else None,
                "partial": s.get("PartialIncrement") == "True",
            }
            if oib is not None:
                p["corrupt"] = oib.get("IsCorrupted") == "True"
                p["consistent"] = oib.get("IsConsistent") == "True"
                p["source_bytes"] = _int(oib.get("ApproxSize"))
                name = oib.get("VmName")
                if name:
                    m = machines.setdefault(name, {})
                    aux = _xml(oib.get("AuxData"))
                    if aux is not None:
                        m["os"] = aux.findtext("DesktopOibAuxData/OsName") or m.get("os")
                        m["disks"] = [{"name": d.get("FriendlyName"), "capacity": _int(d.get("Capacity")),
                                       "mounts": [mp.get("path") for mp in d.iter("MountPoint")]}
                                      for d in aux.iter("Disk")]
            points.append(p)

    def _chain_problems(self, points: list[dict[str, Any]], problems: list[str]) -> None:
        by_id = {p["storage_id"]: p for p in points}
        children: dict[str, list[dict[str, Any]]] = {}
        for p in points:
            if p.get("link"):
                children.setdefault(p["link"], []).append(p)

        def dependents(p: dict[str, Any]) -> int:
            n, stack = 0, list(children.get(p["storage_id"], []))
            while stack:
                c = stack.pop()
                n += 1
                stack += children.get(c["storage_id"], [])
            return n

        for p in points:
            when = (p.get("created") or "?")[:16].replace("T", " ")
            tail = ""
            if not p["on_disk"] or p.get("corrupt"):
                n = dependents(p)
                tail = f"; {n} later restore points depend on it" if n else ""
            if not p["on_disk"]:
                problems.append(f"{p['file']}: missing (restore point of {when}){tail}")
            if p.get("corrupt"):
                problems.append(f"{p['file']}: marked corrupt by Veeam (restore point of {when}){tail}")
            if p.get("partial"):
                problems.append(f"{p['file']}: partial increment")
            if p["type"] != "full" and p.get("link") and p["link"] not in by_id:
                problems.append(f"{p['file']}: its parent backup file is not in the .vbm")


# --- the backup file's own metadata (scan --verify-backups) -----------------

def _crc32c_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0x82F63B78 if c & 1 else 0)
        table.append(c)
    return table


_CRC32C = _crc32c_table()


def crc32c(data: bytes, crc: int = 0) -> int:
    """CRC-32C (Castagnoli). Pure Python, ~7 MB/s: used on metadata only."""
    crc ^= 0xFFFFFFFF
    t = _CRC32C
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def check_file(path: str, size: int | None = None) -> dict[str, Any]:
    """Header, snapshot slots and metadata banks of one .vbk/.vib/.vrb."""
    info: dict[str, Any] = {"problems": []}
    problems = info["problems"]
    try:
        with open(path, "rb") as f:
            size = os.fstat(f.fileno()).st_size if size is None else size
            head = f.read(_PAGE)
            if len(head) < 0x110:
                problems.append("too short for a Veeam header")
                return info
            fmt, initialized, digest_len = struct.unpack_from("<III", head, 0)
            slot_fmt, block_size = struct.unpack_from("<II", head, 0x107)
            info.update({"format_version": fmt, "block_size": block_size,
                         "digest": head[12:12 + min(digest_len, 251)].decode("ascii", "replace")})
            if not initialized:
                problems.append("header says the file was never initialised")
            slot_crc = crc32c if slot_fmt > 5 else zlib.crc32
            bank_crc = crc32c if fmt >= 12 and fmt != 0x10008 else zlib.crc32
            default_banks = 0xF8 if slot_fmt == 0 else 0x7F00

            slots, offset = [], _PAGE
            for _ in range(2):
                slot, length = _read_slot(f, offset, default_banks, slot_crc)
                slots.append(slot)
                offset += length
            valid = [s for s in slots if s and s["crc_ok"]]
            if not valid:
                problems.append("no snapshot slot with a valid checksum: the file's metadata is unusable"
                                if any(slots) else "no snapshot slot holds metadata")
                return info
            if len(valid) < sum(1 for s in slots if s):
                info["slot_crc_failures"] = sum(1 for s in slots if s) - len(valid)
            active = max(valid, key=lambda s: s["version"])
            info.update({"slot_version": active["version"], "eof": active["eof"],
                         "banks": len(active["banks"]),
                         "metadata_bytes": sum(b[2] for b in active["banks"])})
            if active["eof"] > size:
                problems.append(f"truncated: its metadata ends at {active['eof']} bytes, the file has {size}")
                return info
            def bank_ok(bank: tuple[int, int, int]) -> bool:
                want, off, length = bank
                f.seek(off)
                data = f.read(length)
                return len(data) == length and bank_crc(data) == want

            bad = [i for i, bank in enumerate(active["banks"]) if not bank_ok(bank)]
            info["banks_bad"] = len(bad)
            if bad:
                # each slot keeps its own copy of every bank
                spare = [s for s in valid if s is not active and len(s["banks"]) == len(active["banks"])]
                rescued = [i for i in bad if spare and bank_ok(spare[0]["banks"][i])]
                problems.append(f"{len(bad)} of {len(active['banks'])} metadata banks fail their checksum"
                                + (f" ({len(rescued)} have a good copy in the other slot)" if rescued
                                   else " in both slots" if spare else ""))
    except OSError as e:
        problems.append(f"unreadable: {type(e).__name__}: {e}")
    return info


def _read_slot(f: Any, offset: int, default_banks: int,
               crc: Callable[[bytes], int]) -> tuple[dict[str, Any] | None, int]:
    """(slot, its length in the file). A slot: 8-byte header (CRC, has
    snapshot), 108-byte snapshot descriptor, 8-byte banks grain (max,
    stored), then max x 16-byte bank descriptors (CRC, offset, size)."""
    f.seek(offset)
    raw = f.read(8 + 108 + 8)
    if len(raw) < 124:
        return None, _PAGE
    want, contains = struct.unpack_from("<II", raw, 0)
    max_banks, stored = struct.unpack_from("<II", raw, 116)
    if not contains or max_banks > 0x7F00 or stored > max_banks:
        length = 116 + default_banks * 16
        return None, (length + _PAGE - 1) // _PAGE * _PAGE
    length = 124 + max_banks * 16
    f.seek(offset)
    body = f.read(length)
    version, eof = struct.unpack_from("<QQ", body, 8)
    banks = [struct.unpack_from("<IQI", body, 124 + 16 * i) for i in range(stored)]
    return ({"version": version, "eof": eof, "banks": banks, "crc_ok": crc(body[4:]) == want},
            (length + _PAGE - 1) // _PAGE * _PAGE)


FORMAT = _Veeam()
