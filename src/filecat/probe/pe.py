"""PE executable measurements via pefile: header fields, sections, imports,
VERSIONINFO, the Rich header / toolchain, and a simple packed-image heuristic.

See file-catalog-requirements.md, "Executables" and "Rich header and toolchain".
"""
from __future__ import annotations

import datetime as dt
import importlib.resources
from functools import lru_cache
from typing import Any

import pefile

from ..options import ScanOptions

PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", ".upx0", ".upx1", ".upx2",
    ".aspack", ".adata", ".mpress1", ".mpress2", ".packed",
    "pec1", "pec2", ".perplex", ".petite", ".nsp0", ".nsp1", ".nsp2",
    ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2",
}
HIGH_ENTROPY_THRESHOLD = 7.2
_DIRECTORIES = [pefile.DIRECTORY_ENTRY[name] for name in (
    "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_RESOURCE", "IMAGE_DIRECTORY_ENTRY_DEBUG")]
ENTROPY_SAMPLE = 8 * 1024 * 1024  # bytes of a huge section read for its entropy
SPARSE_IMPORT_THRESHOLD = 2  # distinct DLLs at or below this + high entropy -> packed

# Bracket mark (from comp_id.txt) -> short role name.
_ROLE_MAP = {
    "---": "unmarked", "C": "c", "C++": "cpp", "CPP": "cpp", "RES": "res",
    "C S": "c_std", "C+S": "cpp_std", "C B": "c_book", "C+B": "cpp_book",
    "BSC": "basic", "OMF": "cvtomf", "PGD": "cvtpgd", "IMP": "import",
    "EXP": "export", "ASM": "asm", "ILA": "ilasm", "AOb": "aliasobj",
    "CIL": "cvtcil_c", "CI+": "cvtcil_cpp", "LTC": "ltcg_c", "LT+": "ltcg_cpp",
    "LTM": "ltcg_msil", "PGO": "pogo_i_c", "PG+": "pogo_i_cpp",
    "POC": "pogo_o_c", "PO+": "pogo_o_cpp", "LNK": "linker",
}

_HEX_DIGITS = set("0123456789abcdef")


@lru_cache(maxsize=1)
def _comp_id_tables() -> tuple[dict[str, tuple[str, str | None]], dict[str, tuple[str, str | None]]]:
    """Parse the vendored comp_id.txt into (8-hex comp.id, 4-hex prod-id) lookup maps.

    Each maps to (role, name). `name` is the trailing `# prodidXxx` identifier
    when the line has one, else the free-text description before any comment
    (never invented).
    """
    full: dict[str, tuple[str, str | None]] = {}
    by_prod: dict[str, tuple[str, str | None]] = {}
    raw = importlib.resources.files("filecat.data").joinpath("comp_id.txt").read_text("utf-8")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, rest = line.partition(" ")
        key = key.lower()
        if len(key) not in (4, 8) or any(c not in _HEX_DIGITS for c in key):
            continue
        rest = rest.strip()
        if not rest.startswith("[") or "]" not in rest:
            continue
        mark, _, desc = rest[1:].partition("]")
        desc_text, _, comment = desc.partition("#")
        desc_text = desc_text.strip()
        comment = comment.strip()
        name = desc_text or None
        if comment.startswith("prodid"):
            ident = comment[len("prodid"):].strip()
            if ident:
                name = ident
        role = _ROLE_MAP.get(mark.strip(), mark.strip().lower() or "unmapped")
        entry = (role, name)
        if len(key) == 8:
            full[key] = entry
        else:
            by_prod[key] = entry
    return full, by_prod


def lookup_comp_id(prod_id: int, build: int) -> tuple[str, str | None]:
    """(role, name) for a Rich-header comp.id. Unknown ids come back ('unmapped', None)."""
    full, by_prod = _comp_id_tables()
    key8 = f"{prod_id:04x}{build:04x}"
    if key8 in full:
        return full[key8]
    key4 = f"{prod_id:04x}"
    if key4 in by_prod:
        return by_prod[key4]
    return "unmapped", None


def probe_pe(path: str, options: ScanOptions, result: Any) -> None:
    result.kind = "exe"
    result.container = "pe"
    probe: dict[str, Any] = {}
    result.probe["pe"] = probe

    # fast_load skips pefile's whole-file byte census (it reads every byte,
    # minutes for a large installer on SMB). Then only the directories read
    # below: a game binary's exception and relocation tables run to hundreds
    # of thousands of entries (45 s and 1.3 GB for one 77 MB exe).
    pe = pefile.PE(path, fast_load=True)
    try:
        pe.parse_data_directories(directories=_DIRECTORIES)
        _fill_header(pe, probe, result)
        section_names = _fill_sections(pe, probe)
        import_count, dll_count = _fill_imports(pe, probe)
        packed = _is_packed(section_names, probe.get("sections", []), dll_count)
        # packed and toolchain sit directly on the record's probe (spec:
        # probe.packed, probe.toolchain.linker); the rest of the PE detail is
        # under probe.pe.
        result.probe["packed"] = packed
        result.probe["toolchain"] = {"linker": probe.get("linker")}
        if packed:
            probe.pop("imports", None)
        else:
            _fill_rich(pe, result.probe["toolchain"])
        _fill_version_info(pe, result)
        _fill_pdb(pe, probe)
    finally:
        pe.close()


def _fill_header(pe: "pefile.PE", probe: dict[str, Any], result: Any) -> None:
    probe["machine"] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, pe.FILE_HEADER.Machine)
    magic = pe.OPTIONAL_HEADER.Magic
    probe["magic"] = "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else hex(magic)
    probe["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.Subsystem)
    probe["linker"] = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
    probe["entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    probe["image_size"] = pe.OPTIONAL_HEADER.SizeOfImage

    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        probe["timestamp"] = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError) as exc:
        probe["timestamp_raw"] = ts
        result.errors.append({"stage": "pe", "message": f"timestamp: {exc}"})

    chars = pe.FILE_HEADER.Characteristics
    char_flags = [name for name, bit in pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, "IMAGE_FILE_")
                  if chars & bit]
    probe["characteristics"] = {"value": chars, "flags": char_flags}

    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    dll_flags = [name for name, bit in pefile.retrieve_flags(pefile.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_")
                 if dll_chars & bit]
    probe["dll_characteristics"] = {"value": dll_chars, "flags": dll_flags}


def _fill_sections(pe: "pefile.PE", probe: dict[str, Any]) -> list[str]:
    sections = []
    names = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
        names.append(name)
        section: dict[str, Any] = {
            "name": name,
            "virtual_address": s.VirtualAddress,
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
        }
        try:
            if s.SizeOfRawData > ENTROPY_SAMPLE:
                section["entropy"] = s.entropy_H(s.get_data(length=ENTROPY_SAMPLE))
                section["entropy_sampled"] = ENTROPY_SAMPLE
            else:
                section["entropy"] = s.get_entropy()
        except Exception:
            pass
        sections.append(section)
    probe["sections"] = sections
    return names


def _fill_imports(pe: "pefile.PE", probe: dict[str, Any]) -> tuple[int, int]:
    imports: dict[str, list[str]] = {}
    total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("latin-1", errors="replace") if entry.dll else "?"
        symbols = []
        for imp in entry.imports:
            if imp.name is not None:
                symbols.append(imp.name.decode("latin-1", errors="replace"))
            else:
                symbols.append(f"ord:{imp.ordinal}")
        imports[dll] = symbols
        total += len(symbols)
    if imports:
        probe["imports"] = imports
    return total, len(imports)


def _is_packed(section_names: list[str], sections: list[dict[str, Any]], dll_count: int) -> bool:
    lowered = {n.lower() for n in section_names}
    if lowered & PACKER_SECTION_NAMES:
        return True
    max_entropy = max((s["entropy"] for s in sections if "entropy" in s), default=0.0)
    return max_entropy >= HIGH_ENTROPY_THRESHOLD and dll_count <= SPARSE_IMPORT_THRESHOLD


def _fill_rich(pe: "pefile.PE", toolchain: dict[str, Any]) -> None:
    """Rich rows go in toolchain["objects"]; absent when there is no Rich header."""
    rich = pe.parse_rich_header()
    if not rich or "values" not in rich:
        return
    values = rich["values"]
    objects = []
    linker_prod = None
    for comp_id, count in zip(values[0::2], values[1::2]):
        prod_id = comp_id >> 16
        build = comp_id & 0xFFFF
        role, name = lookup_comp_id(prod_id, build)
        obj: dict[str, Any] = {"prod_id": prod_id, "build": build, "count": count, "role": role}
        if name is not None:
            obj["name"] = name
        objects.append(obj)
    toolchain["objects"] = objects


def _fill_version_info(pe: "pefile.PE", result: Any) -> None:
    file_info_groups = getattr(pe, "FileInfo", None)
    strings: dict[str, str] = {}
    if file_info_groups:
        for group in file_info_groups:
            for entry in group:
                if getattr(entry, "name", None) != "StringFileInfo":
                    continue
                for st in getattr(entry, "StringTable", []):
                    for k, v in st.entries.items():
                        key = k.decode("latin-1", errors="replace") if isinstance(k, bytes) else k
                        val = v.decode("latin-1", errors="replace") if isinstance(v, bytes) else v
                        strings[key] = val
    result.probe["has_version_info"] = bool(strings)
    if strings:
        version_info = {}
        if "ProductName" in strings:
            version_info["product_name"] = strings["ProductName"]
        if "FileVersion" in strings:
            version_info["file_version"] = strings["FileVersion"]
        if version_info:
            result.probe["version_info"] = version_info


def _fill_pdb(pe: "pefile.PE", probe: dict[str, Any]) -> None:
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        entry = getattr(d, "entry", None)
        pdb_name = getattr(entry, "PdbFileName", None) if entry is not None else None
        if pdb_name:
            if isinstance(pdb_name, bytes):
                pdb_name = pdb_name.rstrip(b"\x00").decode("latin-1", errors="replace")
            probe["pdb_path"] = pdb_name
            return
