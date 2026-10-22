"""BOB1 mesh chunk walk, the .cat/.dat catalogue pair, mesh ext_only fallback.

See file-catalog-requirements.md 'Archives, images, models, data'.
"""
from __future__ import annotations

import struct
from pathlib import Path

from filecat.options import ScanOptions
from filecat.probe import probe_file, x3


def _probe(fixture_dir: Path, filename: str, data: bytes, opts: ScanOptions | None = None):
    p = fixture_dir / filename
    p.write_bytes(data)
    return probe_file(str(p), filename, len(data), data[:8192], opts or ScanOptions())


def _build_bob1() -> bytes:
    data = b"BOB1"
    data += struct.pack("<H", 0x001B) + b"\x00" * 36  # 38 bytes
    data += struct.pack("<H", 0x001B) + b"\x00" * 36
    data += struct.pack("<H", 0x001F) + b"\x00" * 44  # 46 bytes
    data += struct.pack("<H", 0x0099) + b"\x00" * 10  # unknown tag stops the walk
    return data


def test_bob1_mesh(fixture_dir):
    r = _probe(fixture_dir, "model.bob", _build_bob1())
    assert r.kind == "mesh"
    assert r.probe["format"] == "bob1"
    assert r.probe["vertex_tag_0x001b"] == 2
    assert r.probe["vertex_tag_0x001f"] == 1
    assert r.probe["unknown_vertex_tag"] == "0x0099"
    assert "0x001b" in r.probe["chunk_tags"]
    assert "0x001f" in r.probe["chunk_tags"]
    assert "0x0099" in r.probe["chunk_tags"]


def test_mesh_ext_only(fixture_dir):
    for name in ("model.obj", "model.stl", "model.glb"):
        data = b"just some ascii content, not a real mesh header\n"
        r = _probe(fixture_dir, name, data)
        assert r.kind == "mesh", name
        assert r.probe["ext_only"] is True


def _xor_cat(raw: bytes) -> bytes:
    return bytes(b ^ ((0xDB + i) & 0xFF) for i, b in enumerate(raw))


def _build_cat_text(entries: list[tuple[str, int]]) -> bytes:
    lines = ["header line, skipped"]
    lines += [f"{path} {size}" for path, size in entries]
    return ("\n".join(lines) + "\n").encode("utf-8")


def test_cat_dat_pair(fixture_dir):
    entries = [("textures/a.dds", 100), ("textures/b.dds", 200)]
    cat_plain = _build_cat_text(entries)
    cat_bytes = _xor_cat(cat_plain)
    cat_path = fixture_dir / "pack.cat"
    cat_path.write_bytes(cat_bytes)

    dat_path = fixture_dir / "pack.dat"
    dat_path.write_bytes(b"\x00" * 300)

    r_cat = probe_file(str(cat_path), "pack.cat", len(cat_bytes), cat_bytes[:8192], ScanOptions())
    assert r_cat.kind == "data"
    assert r_cat.probe["format"] == "x3-cat"
    cat_entries = r_cat.probe["entries"]
    assert cat_entries[0]["path"] == "textures/a.dds"
    assert cat_entries[0]["size"] == 100
    assert cat_entries[0]["offset"] == 0
    assert cat_entries[1]["path"] == "textures/b.dds"
    assert cat_entries[1]["offset"] == 100

    dat_bytes = dat_path.read_bytes()
    r_dat = probe_file(str(dat_path), "pack.dat", len(dat_bytes), dat_bytes[:8192], ScanOptions())
    assert r_dat.kind == "data"
    assert r_dat.probe["format"] == "x3-dat"
    assert r_dat.probe["transform"] == "byte ^= 0x33"


def test_dat_without_cat_sibling_is_not_x3(fixture_dir):
    dat_path = fixture_dir / "lonely.dat"
    data = b"\x00\x01\x02\x03binary junk\x00\x00"
    dat_path.write_bytes(data)
    r = probe_file(str(dat_path), "lonely.dat", len(data), data[:8192], ScanOptions())
    assert r.probe.get("format") != "x3-dat"


def test_expand_dat_members(fixture_dir):
    # One member whose transformed bytes are a PNG signature.
    png_sig_plain = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
    member_bytes = bytes(b ^ 0x33 for b in png_sig_plain)
    entries = [("sprite.png", len(member_bytes))]
    cat_plain = _build_cat_text(entries)
    cat_bytes = _xor_cat(cat_plain)
    (fixture_dir / "assets.cat").write_bytes(cat_bytes)
    dat_path = fixture_dir / "assets.dat"
    dat_path.write_bytes(member_bytes)

    dat_bytes = dat_path.read_bytes()
    opts = ScanOptions(expand_dat=True, member_cap=10)
    r = probe_file(str(dat_path), "assets.dat", len(dat_bytes), dat_bytes[:8192], opts)
    assert r.probe["format"] == "x3-dat"
    members = r.probe["members"]
    assert members[0]["path"] == "sprite.png"
    assert members[0]["kind"] == "image"
    assert members[0]["format"] == "png"


# --- real-layout BOB1 (named chunks), cat member rows ---------------------

def _chunked_bob1(parts: int = 1, vtag: int = 0x001B, points: int = 3, close: bool = True) -> bytes:
    size = {0x001B: 38, 0x001F: 46}[vtag]
    info = (b"INFO$PATH: F:\\src\\ship.bob SRC: F:\\src\\ship.max VERS: 3.37 "
            b"TIME: Jul 19 2005 15:57:35 Copyright 1 2003 by EGOSOFT$\x00/INF")
    mat = (b"MAT6" + struct.pack(">I", 2) + b"\x00\x00\x02asteroid.fx\x00\x00g_Wrap\x00"
           b"environments\\asteroids\\a_diff.tga\x00\x00envmap.dds\x00\x00standard.fx\x00/MAT")
    out = b"BOB1" + info + mat + b"BODY" + struct.pack(">HII", parts, 12345, 0)
    for i in range(parts):
        if i:
            out += b"\x00\x00\x00\x1e"                      # gap between parts
        rec = struct.pack(">H", vtag) + b"\x00" * (size - 2)
        out += b"POIN" + struct.pack(">I", points) + rec * points + b"/POI"
        out += b"PART" + b"\x00\x00\x00\x01\x10" + b"\x00" * 8 + b"/PAR"
    out += b"/BOD"
    if close:
        out += b"/BOB"
    return out


def test_bob1_chunked_layout():
    r = x3.sniff_bob1(_chunked_bob1(parts=2, points=5))
    assert r["kind"] == "mesh" and r["format"] == "bob1" and r["bob1_layout"] == "chunked"
    assert r["chunk_tags"] == ["INFO", "MAT6", "BODY", "POIN", "PART"]
    assert r["bodies"] == 1 and r["parts"] == 2 and r["points"] == 10
    assert r["vertex_tag_0x001b"] == 10 and r["vertex_tag_0x001f"] == 0
    assert r["material_count"] == 2
    assert r["shaders"] == ["asteroid.fx", "standard.fx"]
    assert r["textures"] == ["environments\\asteroids\\a_diff.tga", "envmap.dds"]
    assert r["export_info"]["vers"] == "3.37"
    assert r["export_info"]["path"] == "F:\\src\\ship.bob"
    assert "chunks_truncated" not in r and "unknown_vertex_tag" not in r


def test_bob1_chunked_46_byte_vertices_and_truncation():
    r = x3.sniff_bob1(_chunked_bob1(vtag=0x001F, points=4))
    assert r["vertex_tag_0x001f"] == 4 and r["vertex_tag_0x001b"] == 0
    r = x3.sniff_bob1(_chunked_bob1(points=50)[:400])
    assert r["chunks_truncated"] is True            # header counts survive a cut-off body


def test_bob1_chunked_unknown_vertex_tag():
    data = bytearray(_chunked_bob1(points=2))
    i = data.index(b"POIN") + 8
    data[i:i + 2] = struct.pack(">H", 0x0042)
    r = x3.sniff_bob1(bytes(data))
    assert r["unknown_vertex_tag"] == "0x0042"


def test_bob1_chunked_file_probe(fixture_dir):
    r = _probe(fixture_dir, "ship.bob", _chunked_bob1(parts=1, points=3))
    assert r.kind == "mesh" and r.probe["parts"] == 1 and r.probe["format"] == "bob1"


def test_cat_member_rows_and_dat_pointer(fixture_dir):
    entries = [("dds/a.dds", 100), ("scripts/x.xml", 5), ("s/001.wav", 7)]
    cat_bytes = _xor_cat(_build_cat_text(entries))
    (fixture_dir / "pk.cat").write_bytes(cat_bytes)
    (fixture_dir / "pk.dat").write_bytes(b"\x00" * 112)
    r = probe_file(str(fixture_dir / "pk.cat"), "pk.cat", len(cat_bytes), cat_bytes[:8192], ScanOptions())
    assert r.probe["format"] == "x3-cat"
    assert r.probe["entries"][1] == {"path": "scripts/x.xml", "size": 5, "offset": 100}   # original key kept
    assert [m["path"] for m in r.members] == ["dds/a.dds", "scripts/x.xml", "s/001.wav"]
    assert [m["offset"] for m in r.members] == [0, 100, 105]
    assert [m["role"] for m in r.members] == ["texture", "config", "audio"]
    assert r.probe["members_count"] == 3 and r.probe["x3_dat"] == "pk.dat"
    d = probe_file(str(fixture_dir / "pk.dat"), "pk.dat", 112, b"\x00" * 112, ScanOptions())
    assert d.probe["x3_cat"] == "pk.cat"
    assert d.members is None                        # no duplicated member rows


def test_cat_member_cap(fixture_dir):
    entries = [(f"f/{i}.txt", 1) for i in range(10)]
    cat_bytes = _xor_cat(_build_cat_text(entries))
    (fixture_dir / "cap.cat").write_bytes(cat_bytes)
    # probe_file calls probe_cat(path, result) without options today, so
    # pass them directly (the optional third argument is for the merge).
    from filecat.probe import ProbeResult
    r = ProbeResult()
    assert x3.probe_cat(str(fixture_dir / "cap.cat"), r, ScanOptions(max_members=4))
    assert len(r.members) == 4 and r.probe["members_truncated"] is True
    assert r.probe["entries_total"] == 10


def test_header_only_cat_is_an_empty_pack(fixture_dir):
    cat_bytes = _xor_cat(b"x03.dat\n")
    (fixture_dir / "x03.cat").write_bytes(cat_bytes)
    r = probe_file(str(fixture_dir / "x03.cat"), "x03.cat", len(cat_bytes), cat_bytes, ScanOptions())
    assert r.probe["format"] == "x3-cat" and r.members == [] and r.probe["entries"] == []
    junk = _xor_cat(b"hello world\n")
    (fixture_dir / "junk.cat").write_bytes(junk)
    r = probe_file(str(fixture_dir / "junk.cat"), "junk.cat", len(junk), junk, ScanOptions())
    assert r.probe.get("format") != "x3-cat"
