"""Synthetic PE32+ images hand-assembled byte by byte, plus the Rich-header
comp_id.txt mapping. See file-catalog-requirements.md 'Executables' and
'Rich header and toolchain'.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

import pefile
import pytest

from filecat.options import ScanOptions
from filecat.probe import probe_file
from filecat.probe.pe import lookup_comp_id

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
NUM_DATA_DIRS = 16


def _build_pe(*, linker_major: int, linker_minor: int, section_name: bytes = b".text",
              section_characteristics: int = 0x60000020, section_data: bytes | None = None,
              timestamp: int = 1_700_000_000, dos_stub_padding: int = 0) -> bytes:
    """A minimal, valid PE32+ (x64) image pefile can parse: DOS stub, COFF
    header, optional header (no data directories populated), one section.

    `dos_stub_padding` grows the DOS stub beyond the usual 64 bytes, pushing
    e_lfanew (and the 'PE\\0\\0' signature) further into the file -- used to
    reproduce the oversized-stub case seen on tcblaunch.exe.
    """
    if section_data is None:
        section_data = b"\x00" * FILE_ALIGN

    e_lfanew = 64 + dos_stub_padding
    dos_header = bytearray(e_lfanew)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    opt_header_size = 0x70 + NUM_DATA_DIRS * 8
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,          # Machine: AMD64
        1,               # NumberOfSections
        timestamp,
        0,               # PointerToSymbolTable
        0,               # NumberOfSymbols
        opt_header_size, # SizeOfOptionalHeader
        0x22,            # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    section_rva = SECTION_ALIGN
    section_vsize = len(section_data)
    image_size = SECTION_ALIGN + ((section_vsize + SECTION_ALIGN - 1) // SECTION_ALIGN) * SECTION_ALIGN

    headers_len = len(dos_header) + 4 + 20 + opt_header_size + 40  # dos + sig + coff + opt + 1 section
    size_of_headers = ((headers_len + FILE_ALIGN - 1) // FILE_ALIGN) * FILE_ALIGN

    opt = bytearray(opt_header_size)
    struct.pack_into("<H", opt, 0x00, 0x20B)          # Magic: PE32+
    opt[0x02] = linker_major
    opt[0x03] = linker_minor
    struct.pack_into("<I", opt, 0x04, section_vsize)  # SizeOfCode
    struct.pack_into("<I", opt, 0x08, 0)               # SizeOfInitializedData
    struct.pack_into("<I", opt, 0x0C, 0)               # SizeOfUninitializedData
    struct.pack_into("<I", opt, 0x10, section_rva)    # AddressOfEntryPoint
    struct.pack_into("<I", opt, 0x14, section_rva)    # BaseOfCode
    struct.pack_into("<Q", opt, 0x18, 0x140000000)    # ImageBase
    struct.pack_into("<I", opt, 0x20, SECTION_ALIGN)
    struct.pack_into("<I", opt, 0x24, FILE_ALIGN)
    struct.pack_into("<H", opt, 0x28, 6)               # MajorOSVersion
    struct.pack_into("<H", opt, 0x2A, 0)
    struct.pack_into("<H", opt, 0x2C, 0)               # MajorImageVersion
    struct.pack_into("<H", opt, 0x2E, 0)
    struct.pack_into("<H", opt, 0x30, 6)               # MajorSubsystemVersion
    struct.pack_into("<H", opt, 0x32, 0)
    struct.pack_into("<I", opt, 0x34, 0)               # Reserved1
    struct.pack_into("<I", opt, 0x38, image_size)
    struct.pack_into("<I", opt, 0x3C, size_of_headers)
    struct.pack_into("<I", opt, 0x40, 0)               # CheckSum
    struct.pack_into("<H", opt, 0x44, 3)               # Subsystem: WINDOWS_CUI
    struct.pack_into("<H", opt, 0x46, 0)               # DllCharacteristics
    struct.pack_into("<Q", opt, 0x48, 0x100000)        # SizeOfStackReserve
    struct.pack_into("<Q", opt, 0x50, 0x1000)          # SizeOfStackCommit
    struct.pack_into("<Q", opt, 0x58, 0x100000)        # SizeOfHeapReserve
    struct.pack_into("<Q", opt, 0x60, 0x1000)          # SizeOfHeapCommit
    struct.pack_into("<I", opt, 0x68, 0)               # LoaderFlags
    struct.pack_into("<I", opt, 0x6C, NUM_DATA_DIRS)
    # data directories (0x70 onward) left zeroed: no imports, no resources, no debug.

    section_header = bytearray(40)
    name = section_name[:8].ljust(8, b"\x00")
    section_header[0:8] = name
    struct.pack_into("<I", section_header, 8, section_vsize)    # VirtualSize
    struct.pack_into("<I", section_header, 12, section_rva)     # VirtualAddress
    struct.pack_into("<I", section_header, 16, len(section_data))  # SizeOfRawData
    struct.pack_into("<I", section_header, 20, size_of_headers)  # PointerToRawData
    struct.pack_into("<I", section_header, 24, 0)
    struct.pack_into("<I", section_header, 28, 0)
    struct.pack_into("<H", section_header, 32, 0)
    struct.pack_into("<H", section_header, 34, 0)
    struct.pack_into("<I", section_header, 36, section_characteristics)

    headers = bytes(dos_header) + b"PE\x00\x00" + coff + bytes(opt) + bytes(section_header)
    headers = headers.ljust(size_of_headers, b"\x00")
    return headers + section_data


def test_synthetic_pe_linker_version(fixture_dir: Path):
    data = _build_pe(linker_major=14, linker_minor=29)
    p = fixture_dir / "tiny.exe"
    p.write_bytes(data)
    r = probe_file(str(p), "tiny.exe", len(data), data[:8192], ScanOptions())
    assert r.kind == "exe"
    assert r.container == "pe"
    assert r.probe["pe"]["linker"] == "14.29"
    assert r.probe["toolchain"]["linker"] == "14.29"
    assert r.probe["pe"]["magic"] == "PE32+"
    assert r.probe["pe"]["machine"] == "IMAGE_FILE_MACHINE_AMD64"
    assert r.errors == []


def test_synthetic_pe_oversized_dos_stub(fixture_dir: Path):
    """e_lfanew past the 8 KiB head window (as on the real tcblaunch.exe) must
    still be recognized as a PE -- the probe seeks on disk to verify it."""
    data = _build_pe(linker_major=14, linker_minor=38, dos_stub_padding=9000)
    p = fixture_dir / "bigstub.exe"
    p.write_bytes(data)
    head = data[:8192]
    assert len(data) > len(head)
    r = probe_file(str(p), "bigstub.exe", len(data), head, ScanOptions())
    assert r.kind == "exe"
    assert r.container == "pe"
    assert r.probe["pe"]["linker"] == "14.38"
    assert r.errors == []


def test_synthetic_pe_timestamp(fixture_dir: Path):
    data = _build_pe(linker_major=12, linker_minor=0, timestamp=1_700_000_000)
    p = fixture_dir / "tiny2.exe"
    p.write_bytes(data)
    r = probe_file(str(p), "tiny2.exe", len(data), data[:8192], ScanOptions())
    assert r.probe["pe"]["timestamp"].startswith("2023-")


def test_synthetic_pe_packed_section_name(fixture_dir: Path):
    data = _build_pe(linker_major=9, linker_minor=0, section_name=b".aspack")
    p = fixture_dir / "packed.exe"
    p.write_bytes(data)
    r = probe_file(str(p), "packed.exe", len(data), data[:8192], ScanOptions())
    assert r.kind == "exe"
    assert r.probe["packed"] is True
    assert "objects" not in r.probe["toolchain"]
    assert "imports" not in r.probe["pe"]


def test_rich_lookup_12_10_family():
    """Build 40116 on product ids 241/242/243 stays the 12.10 family and is
    never relabeled as a newer Visual Studio."""
    role, name = lookup_comp_id(241, 40116)
    assert (role, name) == ("asm", "Masm1210")
    role, name = lookup_comp_id(242, 40116)
    assert (role, name) == ("c", "Utc1810_C")
    role, name = lookup_comp_id(243, 40116)
    assert (role, name) == ("cpp", "Utc1810_CPP")


def test_rich_lookup_unmapped_id_never_invents_a_name():
    role, name = lookup_comp_id(0xFFFF, 0xFFFF)
    assert role == "unmapped"
    assert name is None


@pytest.mark.parametrize("exe_path", [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\kernel32.dll",
])
def test_sanity_real_binaries_do_not_crash(exe_path):
    if not os.path.isfile(exe_path):
        pytest.skip(f"{exe_path} not present on this machine")
    size = os.path.getsize(exe_path)
    with open(exe_path, "rb") as f:
        head = f.read(min(size, 8192))
    r = probe_file(exe_path, os.path.basename(exe_path), size, head, ScanOptions())
    assert r.kind == "exe"
    assert r.probe["pe"]["linker"]


def test_filecat_exe_rich_row_count_matches_pefile_directly():
    """Optional: FILECAT_EXE points at a real PE. Confirm one prod id's row
    count matches pefile's own parse_rich_header() exactly."""
    exe_path = os.environ.get("FILECAT_EXE")
    if not exe_path:
        pytest.skip("FILECAT_EXE not set")
    size = os.path.getsize(exe_path)
    with open(exe_path, "rb") as f:
        head = f.read(min(size, 8192))
    r = probe_file(exe_path, os.path.basename(exe_path), size, head, ScanOptions())
    objects = r.probe.get("toolchain", {}).get("objects")
    assert objects, "expected a Rich header on FILECAT_EXE"

    pe = pefile.PE(exe_path)
    try:
        rich = pe.parse_rich_header()
    finally:
        pe.close()
    values = rich["values"]
    expected_counts: dict[int, int] = {}
    for comp_id, count in zip(values[0::2], values[1::2]):
        prod_id = comp_id >> 16
        expected_counts[prod_id] = expected_counts.get(prod_id, 0) + count

    first_prod_id = objects[0]["prod_id"]
    probed_count = sum(o["count"] for o in objects if o["prod_id"] == first_prod_id)
    assert probed_count == expected_counts[first_prod_id]
