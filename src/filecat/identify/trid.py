"""TrID definitions, used as a suffix -> description table (--trid-defs PATH).

Supports:
* a directory of ``*.trid.xml`` definition files (the TrIDDefs XML package),
* a ``.zip`` of the same,
* a single ``.trid.xml`` file, and
* a plain ``ext<TAB>description`` text file.

TrID's native ``.trd`` format is a private binary format and is not read here.
An unrecognised path raises ValueError, which the caller turns into one
scan-level error (see Identifier._init_trid).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_trid_xml_bytes(data: bytes, fallback_name: str = "") -> dict[str, str]:
    root = ET.fromstring(data)
    out: dict[str, str] = {}
    nodes = [root] if _local(root.tag) == "FileType" else root.findall(".//{*}FileType")
    if not nodes:
        nodes = [root]
    for node in nodes:
        exts = [e.text.strip().lstrip(".").lower()
                for e in node.iter() if _local(e.tag) == "Ext" and e.text and e.text.strip()]
        if not exts:
            continue
        desc = None
        for want in ("FileTypeName", "Rem", "Type"):
            el = node.find(f".//{{*}}{want}")
            if el is not None and el.text and el.text.strip():
                desc = el.text.strip()
                break
        if desc is None:
            desc = fallback_name
        for ext in exts:
            out.setdefault(ext, desc)
    return out


def _parse_tab_file(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.rstrip()
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if "\t" not in line:
            continue
        ext, _, desc = line.partition("\t")
        ext = ext.strip().lstrip(".").lower()
        desc = desc.strip()
        if ext and desc:
            out.setdefault(ext, desc)
    return out


def load_defs(path: str) -> dict[str, str]:
    """Parse a TrID defs source into {suffix: description}. Raises ValueError
    (or an OS/parse error) for a path that is not one of the supported forms."""
    p = Path(path)
    if not p.exists():
        raise ValueError(f"TrID defs path not found: {p}")

    if p.is_dir():
        mapping: dict[str, str] = {}
        for f in sorted(p.rglob("*.trid.xml")):
            try:
                mapping.update(_parse_trid_xml_bytes(f.read_bytes(), fallback_name=f.stem))
            except ET.ParseError:
                continue
        if not mapping:
            raise ValueError(f"no usable .trid.xml definitions found under {p}")
        return mapping

    if p.suffix.lower() == ".zip":
        mapping = {}
        with zipfile.ZipFile(p) as zf:
            members = [n for n in zf.namelist() if n.lower().endswith(".trid.xml")]
            if not members:
                raise ValueError(f"no .trid.xml members found in {p}")
            for member in members:
                with zf.open(member) as fh:
                    try:
                        mapping.update(_parse_trid_xml_bytes(fh.read(), fallback_name=Path(member).stem))
                    except ET.ParseError:
                        continue
        if not mapping:
            raise ValueError(f"no usable .trid.xml definitions found in {p}")
        return mapping

    text = p.read_text(encoding="utf-8", errors="replace")
    if text.lstrip().startswith("<"):
        mapping = _parse_trid_xml_bytes(text.encode("utf-8"), fallback_name=p.stem)
        if not mapping:
            raise ValueError(f"no <FileType>/<Ext> definitions found in {p}")
        return mapping

    mapping = _parse_tab_file(text)
    if not mapping:
        raise ValueError(f"unrecognised TrID defs format: {p}")
    return mapping
