"""Parsers for the raw storage sources the collectors read: text files from /proc, /sys and
/etc, and the output of allowlisted commands. Pure functions over text, so they are tested
on recorded outputs and the agent needs none of them (docs/agent-allowlist.md).
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any


# --- INI-like stanzas: iscsi_lun.conf, iscsi_lun_acl.conf, smb.conf ----------------------
def parse_stanzas(text: str) -> list[tuple[str, dict[str, str]]]:
    """`[name]` stanzas of `key=value` lines, in file order. Lines before the first stanza are
    kept under the name ""; `#` and `;` lines are comments; a repeated key keeps the last."""
    out: list[tuple[str, dict[str, str]]] = []
    name, props = "", {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            if props or name:
                out.append((name, props))
            name, props = line[1:-1].strip(), {}
        elif "=" in line:
            key, _, value = line.partition("=")
            props[key.strip()] = value.strip()
    if props or name:
        out.append((name, props))
    return out


def parse_shell_vars(text: str) -> dict[str, str]:
    """`key="value"` lines (Synology's /etc/VERSION)."""
    out = {}
    for raw in text.splitlines():
        key, sep, value = raw.strip().partition("=")
        if sep and key and not key.startswith("#"):
            out[key.strip()] = value.strip().strip('"')
    return out


# --- /proc ---------------------------------------------------------------------------------
def parse_mounts(text: str) -> list[dict[str, Any]]:
    """/proc/mounts: device, mount, type, options (octal escapes such as \\040 decoded)."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            out.append({"device": _unescape(parts[0]), "mount": _unescape(parts[1]), "type": parts[2],
                        "options": parts[3].split(",")})
    return out


def _unescape(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


_MD_HEAD = re.compile(r"^(md\d+)\s*:\s*(.*)$")
_MD_DEV = re.compile(r"^([A-Za-z0-9_.-]+)\[(\d+)\]((?:\([A-Z]\))*)$")
_MD_STATE = re.compile(r"\[(\d+)/(\d+)\]\s+\[([U_]+)\]")


def parse_mdstat(text: str) -> dict[str, dict[str, Any]]:
    """/proc/mdstat: {md name: {state, level, blocks, members, total, active, flags}}. A member
    is {name, slot, failed, spare, write_mostly}; `members` is in slot order; `flags` is the
    `[UUU_]` string. `blocks` is in KiB. An `inactive` array has level None."""
    arrays: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        m = _MD_HEAD.match(line)
        if m:
            tokens = m.group(2).split()
            state = tokens[0] if tokens else ""
            rest = tokens[1:]
            level = None
            if state != "inactive":
                while rest and rest[0].startswith("("):     # (read-only), (auto-read-only)
                    rest.pop(0)
                level = rest.pop(0) if rest else None
            members = []
            for tok in rest:
                dm = _MD_DEV.match(tok)
                if dm:
                    flags = dm.group(3)
                    members.append({"name": dm.group(1), "slot": int(dm.group(2)),
                                    "failed": "(F)" in flags, "spare": "(S)" in flags,
                                    "write_mostly": "(W)" in flags})
            current = {"state": state, "level": level, "blocks": None,
                       "members": sorted(members, key=lambda d: d["slot"]),
                       "total": None, "active": None, "flags": None}
            arrays[m.group(1)] = current
            continue
        if current is not None and line.startswith((" ", "\t")):
            b = re.match(r"\s*(\d+)\s+blocks", line)
            if b:
                current["blocks"] = int(b.group(1))
            st = _MD_STATE.search(line)
            if st:
                current["total"], current["active"], current["flags"] = int(st.group(1)), int(st.group(2)), st.group(3)
            if re.search(r"(resync|recovery|reshape|check)\s*=", line):
                current["sync"] = line.strip()
    return arrays


_MDADM_ARRAY = re.compile(r"^ARRAY\s+(\S+)\s*(.*)$")


def parse_mdadm_scan(text: str) -> dict[str, dict[str, str]]:
    """`mdadm --detail --scan`: {"/dev/md2": {"UUID": "c40e7b19:6d254f83:...", "metadata": "1.2", ...}}."""
    out = {}
    for line in text.splitlines():
        m = _MDADM_ARRAY.match(line.strip())
        if m:
            out[m.group(1)] = dict(kv.split("=", 1) for kv in m.group(2).split() if "=" in kv)
    return out


def md_uuid(raw: str) -> str:
    """mdadm's `c40e7b19:6d254f83:a1b093e8:d52f7a46` as the usual 8-4-4-4-12 uuid."""
    h = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(h) != 32:
        raise ValueError(f"not an md uuid: {raw!r}")
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


# --- LVM text metadata (/etc/lvm/backup/vgN) -----------------------------------------------
_LVM_TOKEN = re.compile(r'\s*(?:(#[^\n]*)|("(?:[^"\\]|\\.)*")|(\[)|(\])|(\{)|(\})|(=)|(,)|([^\s=\[\]{},"#]+))')


def parse_lvm_text(text: str) -> dict[str, Any]:
    """The text format of LVM2 metadata: `name { key = value ... }`, strings in quotes, integers,
    lists in brackets. Returns nested dicts; a section is a dict, a list a list. Raises
    ValueError on anything it cannot read."""
    tokens: list[str] = []
    pos = 0
    text = text.replace("\r\n", "\n")
    while pos < len(text):
        m = _LVM_TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise ValueError(f"unreadable LVM metadata near {text[pos:pos + 30]!r}")
        pos = m.end()
        if m.group(1) is not None:
            continue
        tokens.append(next(g for g in m.groups()[1:] if g is not None))
    i = 0

    def value() -> Any:
        nonlocal i
        tok = tokens[i]
        i += 1
        if tok == "[":
            items = []
            while tokens[i] != "]":
                if tokens[i] == ",":
                    i += 1
                    continue
                items.append(value())
            i += 1
            return items
        if tok.startswith('"'):
            return json.loads(tok)
        try:
            return int(tok)
        except ValueError:
            return tok

    def section(nested: bool = False) -> dict[str, Any]:
        nonlocal i
        out: dict[str, Any] = {}
        while i < len(tokens) and tokens[i] != "}":
            key = tokens[i]
            i += 1
            if i >= len(tokens):
                raise ValueError("LVM metadata ends inside a statement")
            if tokens[i] == "=":
                i += 1
                out[key] = value()
            elif tokens[i] == "{":
                i += 1
                out[key] = section(True)
                i += 1          # the closing brace
            else:
                raise ValueError(f"LVM metadata: unexpected {tokens[i]!r} after {key!r}")
        if nested and i >= len(tokens):
            raise ValueError("LVM metadata ends inside a section")
        return out

    return section()


# --- smartctl and lsblk --------------------------------------------------------------------
def parse_smartctl_json(text: str) -> dict[str, Any]:
    """`smartctl --json -i`: {serial, model, wwn (naa hex), rotation_rate, size_bytes}; keys that
    smartctl did not print are left out."""
    doc = json.loads(text)
    out: dict[str, Any] = {}
    if doc.get("serial_number"):
        out["serial"] = str(doc["serial_number"]).strip()
    if doc.get("model_name"):
        out["model"] = str(doc["model_name"]).strip()
    wwn = doc.get("wwn")
    if isinstance(wwn, dict) and all(k in wwn for k in ("naa", "oui", "id")):
        out["wwn"] = f"{wwn['naa']:x}{wwn['oui']:06x}{wwn['id']:09x}"
    if isinstance(doc.get("rotation_rate"), int):
        out["rotation_rate"] = doc["rotation_rate"]
    cap = (doc.get("user_capacity") or {}).get("bytes")
    if isinstance(cap, int):
        out["size_bytes"] = cap
    return out


_SMARTCTL_VERSION = re.compile(r"^smartctl\s+(\d+)\.(\d+)", re.M)


def parse_smartctl_version(text: str) -> tuple[int, int] | None:
    """`smartctl --version` ("smartctl 6.5 2016-05-07 r4318 [x86_64-linux-4.4.302+] (local
    build)") -> (6, 5); None when the output is not smartctl's."""
    m = _SMARTCTL_VERSION.search(text)
    return (int(m.group(1)), int(m.group(2))) if m else None


def parse_smartctl_text(text: str) -> dict[str, Any]:
    """`smartctl -i` (smartmontools before 7.0): the same keys as parse_smartctl_json."""
    out: dict[str, Any] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "serial number":
            out["serial"] = value
        elif key in ("device model", "model number", "product"):
            out["model"] = value
        elif key == "rotation rate":
            out["rotation_rate"] = 0 if "solid state" in value.lower() else int(re.match(r"\d+", value).group()) \
                if re.match(r"\d+", value) else None
            if out["rotation_rate"] is None:
                del out["rotation_rate"]
        elif key == "lu wwn device id":
            out["wwn"] = re.sub(r"\s", "", value).lower()
        elif key == "user capacity":
            m = re.match(r"([\d,.]+)\s+bytes", value)
            if m:
                out["size_bytes"] = int(re.sub(r"[,.]", "", m.group(1)))
    return out


def _lsblk_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_lsblk(text: str) -> list[dict[str, Any]]:
    """lsblk output as a flat list of devices, `-J` or `-P`. Keys are lowercase column names
    (`name`, `kname`, `pkname`, `maj:min`, `type`, `fstype`, `size` int, `rota` bool, `model`,
    `serial`, `wwn`, `mountpoints` list). JSON children are flattened, `pkname` filled from
    the parent when lsblk left it out."""
    text = text.strip()
    devices: list[dict[str, Any]] = []
    if text.startswith("{"):
        def walk(items: list[dict[str, Any]], parent: str | None) -> None:
            for d in items:
                row = {k.lower(): v for k, v in d.items() if k != "children"}
                row.setdefault("pkname", parent)
                devices.append(row)
                walk(d.get("children") or [], d.get("name"))
        walk(json.loads(text).get("blockdevices", []), None)
    else:
        for line in text.splitlines():
            pairs = re.findall(r'([A-Z:_]+)="((?:[^"\\]|\\.)*)"', line)
            if pairs:
                devices.append({k.lower(): v.encode().decode("unicode_escape") if "\\x" in v else v
                                for k, v in pairs})
    for row in devices:
        row["size"] = _lsblk_int(row.get("size"))
        rota = row.get("rota")
        row["rota"] = rota in (True, 1, "1", "true")
        mps = row.pop("mountpoints", None)
        if mps is None:
            mps = [row["mountpoint"]] if row.get("mountpoint") else []
        row["mountpoints"] = [m for m in mps if m]
        for key in ("pkname", "fstype", "model", "serial", "wwn"):
            if row.get(key) in ("", None):
                row[key] = None
            elif isinstance(row[key], str):
                row[key] = row[key].strip()
    return devices


def parse_blkid_export(text: str) -> list[dict[str, str]]:
    """`blkid -o export`: one dict per device, blocks separated by an empty line."""
    out, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                out.append(cur)
            cur = {}
            continue
        key, sep, value = line.partition("=")
        if sep:
            cur[key] = value
    if cur:
        out.append(cur)
    return out


# --- shares ---------------------------------------------------------------------------------
_SMB_SKIP = {"global", "printers", "print$", "ipc$"}


def parse_smb_conf(text: str) -> list[dict[str, str]]:
    """The shares of a Samba configuration: [{"name", "path", ...}] for every section that has a
    `path`, except [global] and the printer sections. Keys are lowercase."""
    out = []
    for name, props in parse_stanzas(text):
        low = {k.lower(): v for k, v in props.items()}
        if not name or name.lower() in _SMB_SKIP or "path" not in low:
            continue
        out.append({"name": name, **low})
    return out


def parse_exports(text: str) -> list[str]:
    """The exported paths of /etc/exports."""
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        path = line.split()[0].strip('"')
        if path.startswith("/"):
            out.append(path.rstrip("/") or "/")
    return out


# --- file systems ---------------------------------------------------------------------------
# f_type of statfs(2): the magic numbers that matter for storage
FS_MAGIC = {
    0x9123683E: "btrfs", 0xEF53: "ext4", 0x58465342: "xfs", 0x2FC12FC1: "zfs", 0x6969: "nfs",
    0xFE534D42: "smb2", 0xFF534D42: "cifs", 0x01021994: "tmpfs", 0x858458F6: "ramfs",
    0x65735546: "fuse", 0x4D44: "vfat", 0x5346544E: "ntfs", 0xF2F52010: "f2fs", 0x73717368: "squashfs",
}
ST_RDONLY = 1


def fs_type_name(type_id: int | None) -> str | None:
    return FS_MAGIC.get(type_id) if type_id is not None else None


# --- DSM's own view of its storage: /etc/space/space_history_<YYYYMMDD_HHMMSS>.xml -----------
MAX_SPACE_XML = 4 * 1024 * 1024
_SPACE_FILE = re.compile(r"^space_history_(\d{8}_\d{6})\.xml$")


def newest_space_history(names: list[str]) -> str | None:
    """The file name with the latest timestamp in it (the current layout), or None."""
    stamped = [(m.group(1), n) for n in names if (m := _SPACE_FILE.match(n))]
    return max(stamped)[1] if stamped else None


def _attrs(el: ET.Element, *keys: str) -> dict[str, str]:
    return {k: el.attrib[k] for k in keys if k in el.attrib}


def _int_attr(v: str) -> int | str:
    try:
        return int(v)
    except ValueError:
        return v


def parse_space_history(text: str) -> list[dict[str, Any]]:
    """A space_history XML: one dict per `<space>`:

        {path, reference, uuid, space_id, device_type, drive_type,
         cache: True for a `@shared_cache` space (SSD cache),
         lvm: {path, uuid, status, total_size, free_size, pe_size} | None,
         raids: [{path, uuid, level, disks: [{dev_path, status, physical_location, model, serial,
                  slot, partition_size}]}],
         volumes: [{path, dev_path, uuid, type}]   (the volumes DSM made on the space),
         caches: [{reference, dev_path, uuid}]     (`reference` is the uuid of the volume cached),
         refs: every uuid / reference attribute value below the space except its caches'}

    Numbers are ints; a missing attribute is left out. A document from a device is untrusted:
    a DOCTYPE or ENTITY declaration is refused (so nothing is expanded) and so is more than
    MAX_SPACE_XML characters. Raises ValueError."""
    if len(text) > MAX_SPACE_XML:
        raise ValueError(f"space history is longer than {MAX_SPACE_XML} characters")
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("space history has a DOCTYPE or ENTITY declaration")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"space history is not XML: {exc}") from exc
    spaces = []
    for sp in root.iter("space"):
        out: dict[str, Any] = _attrs(sp, "path", "reference", "uuid", "space_id", "device_type", "drive_type")
        out["cache"] = sp.attrib.get("reference") == "@shared_cache"
        lvm = sp.find("./device/lvm")
        out["lvm"] = None
        if lvm is not None:
            out["lvm"] = {k: (_int_attr(v) if k in ("total_size", "free_size", "pe_size") else v)
                          for k, v in _attrs(lvm, "path", "uuid", "status", "total_size", "free_size",
                                             "pe_size").items()}
        raids = []
        for raid in sp.findall("./device//raid"):
            disks = []
            for d in raid.iter("disk"):
                row: dict[str, Any] = _attrs(d, "dev_path", "status", "physical_location", "model",
                                             "serial", "slot", "partition_size")
                for k in ("slot", "partition_size"):
                    if k in row:
                        row[k] = _int_attr(row[k])
                disks.append(row)
            raids.append({**_attrs(raid, "path", "uuid", "level"), "disks": disks})
        out["raids"] = raids
        out["volumes"] = [_attrs(v, "path", "dev_path", "uuid", "type") for v in sp.iter("volume")]
        caches = list(sp.iter("cache"))
        out["caches"] = [_attrs(c, "reference", "dev_path", "uuid") for c in caches]
        skip = {id(sp), *(id(c) for c in caches)}
        out["refs"] = sorted({v for el in sp.iter() if id(el) not in skip
                              for k, v in el.attrib.items() if "uuid" in k or "reference" in k})
        spaces.append(out)
    return spaces
