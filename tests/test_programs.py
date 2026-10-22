"""Tests for filecat.programs: .reg parsing, .lnk parsing, PATH scan shape,
and the exe <-> installed-program join. All fixtures are built under
tests/_fixtures by the tests themselves; nothing here touches the real
registry, PATH, or Start Menu."""
from __future__ import annotations

import struct
from pathlib import Path

from filecat import lnk as lnkmod
from filecat import programs
from filecat.backends.memory import MemoryBackend
from filecat.record import new_document

REG_HEADER = "Windows Registry Editor Version 5.00\r\n\r\n"

REG_BODY = r"""[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppOne]
"DisplayName"="App One"
"Publisher"="Vendor One"
"DisplayVersion"="1.2.3"
"InstallLocation"="C:\\Program Files\\AppOne"
"EstimatedSize"=dword:00001388

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AppTwo]
"DisplayName"="App Two (32-bit)"
"DisplayVersion"="2.0"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppThree]
"DisplayName"="App Three"
"DisplayVersion"="3.5.1"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NoNameKey]
"Publisher"="Ghost Vendor"

"""


def _write_reg_utf16(path: Path, text: str) -> None:
    path.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))


def test_reg_file_records_display_name_version_hive(fixture_dir):
    reg_path = fixture_dir / "uninstall.reg"
    _write_reg_utf16(reg_path, REG_HEADER + REG_BODY)

    before = sorted(p.name for p in fixture_dir.iterdir())

    records = programs.scan_reg_files([str(reg_path)])

    after = sorted(p.name for p in fixture_dir.iterdir())
    assert before == after, "scanning a .reg file must not write anything under the fixture dir"

    by_name = {r["display_name"]: r for r in records if "display_name" in r}
    assert set(by_name) == {"App One", "App Two (32-bit)", "App Three"}

    one = by_name["App One"]
    assert one["type"] == "uninstall"
    assert one["hive"] == "HKLM"
    assert one["key"] == "AppOne"
    assert one["publisher"] == "Vendor One"
    assert one["display_version"] == "1.2.3"
    assert one["install_location"] == "C:\\Program Files\\AppOne"
    assert one["estimated_size"] == 0x1388

    two = by_name["App Two (32-bit)"]
    assert two["hive"] == "HKLM\\WOW6432Node"
    assert two["key"] == "AppTwo"
    assert two["display_version"] == "2.0"

    three = by_name["App Three"]
    assert three["hive"] == "HKCU"
    assert three["key"] == "AppThree"

    # The key with no DisplayName is skipped entirely.
    assert all(r.get("key") != "NoNameKey" for r in records)
    assert len(records) == 3


def test_reg_file_regedit4_ansi_variant(fixture_dir):
    reg_path = fixture_dir / "legacy.reg"
    text = (
        "REGEDIT4\r\n\r\n"
        "[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Legacy]\r\n"
        '"DisplayName"="Legacy App"\r\n'
        '"DisplayVersion"="0.9"\r\n'
    )
    reg_path.write_text(text, encoding="utf-8")

    records = programs.scan_reg_files([str(reg_path)])
    assert len(records) == 1
    assert records[0]["display_name"] == "Legacy App"
    assert records[0]["hive"] == "HKCU"


def test_classify_key_only_direct_subkeys():
    assert programs.classify_key(
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    ) is None
    assert programs.classify_key(
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foo\Bar"
    ) is None
    assert programs.classify_key(
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foo"
    ) == ("uninstall", "HKLM", "Foo")


# --- .lnk parsing ------------------------------------------------------

_STANDARD_CLSID = bytes.fromhex("01140200") + bytes.fromhex("0000") + bytes.fromhex("0000") + bytes(
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
)


def _build_lnk_with_link_info(local_base_path: str, common_path_suffix: str) -> bytes:
    label = b"\x00"
    volume_id = struct.pack("<IIII", 16 + len(label), 3, 0x12345678, 16) + label

    local_base_bytes = local_base_path.encode("cp1252") + b"\x00"
    suffix_bytes = common_path_suffix.encode("cp1252") + b"\x00"

    link_info_header_size = 0x1C
    volume_id_offset = link_info_header_size
    local_base_path_offset = volume_id_offset + len(volume_id)
    common_network_relative_link_offset = 0
    common_path_suffix_offset = local_base_path_offset + len(local_base_bytes)
    link_info_size = common_path_suffix_offset + len(suffix_bytes)

    link_info_header = struct.pack(
        "<IIIIIII",
        link_info_size,
        link_info_header_size,
        1,  # VolumeIDAndLocalBasePath
        volume_id_offset,
        local_base_path_offset,
        common_network_relative_link_offset,
        common_path_suffix_offset,
    )
    link_info = link_info_header + volume_id + local_base_bytes + suffix_bytes
    assert len(link_info) == link_info_size

    link_flags = lnkmod.HAS_LINK_INFO
    header_rest = struct.pack(
        "<IIQQQIIIHHII",
        link_flags, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    )
    header = struct.pack("<I", lnkmod.HEADER_SIZE) + _STANDARD_CLSID + header_rest
    assert len(header) == lnkmod.HEADER_SIZE
    return header + link_info


def test_lnk_parses_local_base_path_and_suffix():
    data = _build_lnk_with_link_info("C:\\Target\\", "App.exe")
    parsed = lnkmod.parse(data)
    assert parsed["target"] == "C:\\Target\\App.exe"


def test_scan_start_menu_parses_good_lnk_and_errors_on_garbage(fixture_dir):
    start_menu = fixture_dir / "Start Menu"
    start_menu.mkdir()
    (start_menu / "Good App.lnk").write_bytes(_build_lnk_with_link_info("C:\\Target\\", "App.exe"))
    (start_menu / "Garbage.lnk").write_bytes(b"not a shortcut" * 10)

    records = programs.scan_start_menu(roots=[str(start_menu)])
    assert len(records) == 2
    by_name = {Path(r["path"]).name: r for r in records}

    good = by_name["Good App.lnk"]
    assert good["type"] == "shortcut"
    assert good["target"] == "C:\\Target\\App.exe"
    assert "errors" not in good

    bad = by_name["Garbage.lnk"]
    assert bad["type"] == "shortcut"
    assert "errors" in bad
    assert "target" not in bad


# --- PATH scan shape -----------------------------------------------------

def test_scan_path_records_dirs_and_exes(fixture_dir, monkeypatch):
    bin_dir = fixture_dir / "bin"
    bin_dir.mkdir()
    (bin_dir / "tool.exe").write_bytes(b"MZ")
    (bin_dir / "readme.txt").write_text("not an exe")
    missing_dir = fixture_dir / "does-not-exist"

    monkeypatch.setenv("PATH", f"{bin_dir}{__import__('os').pathsep}{missing_dir}")

    records = programs.scan_path()
    by_type = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r)

    dirs = {r["path"]: r for r in by_type.get("path_dir", [])}
    assert dirs[str(bin_dir)]["exists"] is True
    assert dirs[str(missing_dir)]["exists"] is False

    exes = by_type.get("path_exe", [])
    assert len(exes) == 1
    assert exes[0]["name"] == "tool.exe"
    assert exes[0]["dir"] == str(bin_dir)


# --- join: exe file record <-> installed program ---------------------------

def test_join_sets_installed_program_on_matching_exe():
    backend = MemoryBackend()
    backend.put_program({
        "program_id": "p1",
        "type": "uninstall",
        "hive": "HKLM",
        "key": "AppOne",
        "display_name": "My App",
    })

    root = "C:\\apps"
    doc = new_document(root, "my-app/app.exe", kind="exe", size=123)
    doc["probe"] = {"version_info": {"product_name": "My App"}}
    backend.put(doc)

    # A second exe whose product name only matches after whitespace/case
    # normalization (documented fallback match).
    doc2 = new_document(root, "other/other.exe", kind="exe", size=456)
    doc2["probe"] = {"version_info": {"product_name": "  my   app  "}}
    backend.put(doc2)

    # A third exe with no match at all.
    doc3 = new_document(root, "none/none.exe", kind="exe", size=789)
    doc3["probe"] = {"version_info": {"product_name": "Unrelated Tool"}}
    backend.put(doc3)

    updated = programs.join_installed_programs(backend)
    assert updated == 2

    got1 = backend.get(root, "my-app/app.exe")
    assert got1["probe"]["installed_program"] == "My App"

    got2 = backend.get(root, "other/other.exe")
    assert got2["probe"]["installed_program"] == "My App"

    got3 = backend.get(root, "none/none.exe")
    assert "installed_program" not in got3.get("probe", {})


def test_programs_run_with_reg_file_against_memory_backend(fixture_dir, monkeypatch):
    reg_path = fixture_dir / "uninstall.reg"
    _write_reg_utf16(reg_path, REG_HEADER + REG_BODY)

    import argparse
    args = argparse.Namespace(
        backend="memory", out=None, dsn=None,
        reg=[str(reg_path)], no_path=True, no_start_menu=True,
    )

    backend = MemoryBackend()
    monkeypatch.setattr(programs, "open_backend", lambda *a, **k: backend)

    rc = programs.run(args)
    assert rc == 0

    names = {p["display_name"] for p in backend.list_programs() if "display_name" in p}
    assert names == {"App One", "App Two (32-bit)", "App Three"}
