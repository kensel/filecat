"""Godot GDPC packs, X3 XOR-gzip .pck payloads, pickles and unknown .pck."""
from __future__ import annotations

import gzip
import pickle
import struct
from pathlib import Path

from filecat.options import ScanOptions
from filecat.probe import pck, probe_file


def _probe(tmp: Path, name: str, data: bytes, opts: ScanOptions | None = None):
    p = tmp / name
    p.write_bytes(data)
    return probe_file(str(p), name, len(data), data[:8192], opts or ScanOptions())


def _xor_gzip(payload: bytes, key: int = 0x5D) -> bytes:
    gz = gzip.compress(payload, mtime=0)
    return bytes([key ^ 0xC8]) + bytes(b ^ key for b in gz)


def _godot(version: int, files: list[tuple[str, bytes]], *, flags: int = 0) -> bytes:
    hdr = b"GDPC" + struct.pack("<IIII", version, 4, 2, 1)
    files_base = 0
    if version >= 2:
        hdr += struct.pack("<I", flags) + struct.pack("<Q", files_base)
    hdr += b"\0" * 64
    hdr_len = len(hdr) + 4
    entries = b""
    for name, _ in files:
        raw = name.encode() + b"\0" * (-len(name.encode()) % 4)
        hdr_len += 4 + len(raw) + 8 + 8 + 16 + (4 if version >= 2 else 0)
    pos = hdr_len
    body = b""
    for name, data in files:
        raw = name.encode() + b"\0" * (-len(name.encode()) % 4)
        entries += struct.pack("<I", len(raw)) + raw + struct.pack("<QQ", pos + len(body), len(data))
        entries += bytes(16)
        if version >= 2:
            entries += struct.pack("<I", 0)
        body += data
    return hdr + struct.pack("<I", len(files)) + entries + body


FILES = [
    ("res://scripts/player.gd", b"extends Node\n"),
    ("res://scenes/main.tscn", b"[gd_scene]\n"),
    ("res://art/hero.ctex", b"\0" * 20),
    ("res://models/ship.mesh", b"\0" * 8),
    ("res://sfx/hit.ogg", b"OggS" * 3),
]


def test_godot_v1(fixture_dir):
    r = _probe(fixture_dir, "game.pck", _godot(1, FILES))
    assert r.kind == "archive"
    assert r.probe["pck_format"] == "godot"
    assert r.probe["godot"]["engine_version"] == "4.2.1"
    assert r.probe["godot"]["file_count"] == 5
    assert [m["path"] for m in r.members][0] == "res://scripts/player.gd"
    assert [m["role"] for m in r.members] == ["script", "config", "texture", "model", "audio"]
    assert r.members[0]["size"] == len(FILES[0][1])
    assert len(r.members[0]["md5"]) == 32
    assert r.probe["members_count"] == 5


def test_godot_v2_offsets_point_at_data(fixture_dir):
    data = _godot(2, FILES)
    r = _probe(fixture_dir, "v2.pck", data)
    assert r.probe["pck_format"] == "godot"
    m = r.members[0]
    assert data[m["offset"]:m["offset"] + m["size"]] == FILES[0][1]


def test_godot_encrypted_directory_stops(fixture_dir):
    r = _probe(fixture_dir, "enc.pck", _godot(2, FILES, flags=1))
    assert r.probe["godot"]["encrypted_dir"] is True
    assert r.probe["pck_format"] == "godot"
    assert not r.members


def test_godot_truncated_is_error_not_crash(fixture_dir):
    r = _probe(fixture_dir, "cut.pck", _godot(1, FILES)[:120])
    assert r.kind == "archive"
    assert r.errors


SCRIPT = (b'<?xml version="1.0" standalone="yes" ?>\r\n<script>\r\n<name>!bbs.news</name>\r\n'
          b'<version>3</version>\r\n<engineversion>17</engineversion>\r\n'
          b'<description>Checks news</description>\r\n<arguments>\r\n'
          b'<argument index="1" name="a" type="Number" />\r\n</arguments>\r\n'
          b'<sourcetext><line linenr="001"><var>$x</var></line></sourcetext>\r\n'
          b'<codearray><sval type="array" size="1"/></codearray>\r\n</script>\r\n')
TFILE = (b'<?xml version="1.0" ?>\r\n<language id="44">\r\n<page id="115" stream="1">\r\n'
         b'  <t id="300051" s="0" l="35540"/>\r\n  <t id="352302" s="36040" l="22910"/>\r\n</page>\r\n'
         b'<page id="119" stream="1">\r\n  <t id="310208" s="1" l="2"/>\r\n</page>\r\n</language>\r\n')


def test_x3_script_pck(fixture_dir):
    r = _probe(fixture_dir, "!bbs.news.pck", _xor_gzip(SCRIPT))
    assert r.container == "gzip_xored"
    assert r.probe["pck_format"] == "x3"
    pl = r.probe["x3_payload"]
    assert pl["role"] == "script" and pl["format"] == "x3-script"
    assert pl["inflated_size"] == len(SCRIPT) and pl["truncated"] is False
    assert pl["name"] == "!bbs.news" and pl["codearray"] is True and pl["arguments"] == 1
    assert [m["path"] for m in r.members] == ["!bbs.news.xml"]
    assert r.members[0]["role"] == "script"
    assert r.probe["member_roles"] == {"script": 1}


def test_x3_tfile_pck_plain_gzip(fixture_dir):
    r = _probe(fixture_dir, "00044.pck", gzip.compress(TFILE))
    assert r.container == "gzip"
    pl = r.probe["x3_payload"]
    assert pl["role"] == "table" and pl["format"] == "x3-tfile"
    assert pl["language_id"] == 44 and pl["pages"] == 2 and pl["entries"] == 3
    assert pl["stream"] is True
    assert r.members[0]["role"] == "table"


def test_x3_bob_pck(fixture_dir):
    bob = b"BOB1" + struct.pack("<H", 0x001B) + b"\0" * 36
    r = _probe(fixture_dir, "ship.pck", _xor_gzip(bob))
    assert r.kind == "mesh"                      # existing classification kept
    assert r.probe["pck_format"] == "x3"
    assert r.probe["x3_payload"]["role"] == "model"
    assert r.members[0]["path"] == "ship.bob"


def test_x3_texture_and_scene_text(fixture_dir):
    r = _probe(fixture_dir, "tex.pck", _xor_gzip(b"DDS " + b"\0" * 120))
    assert r.probe["x3_payload"]["role"] == "texture"
    scene = b"VER: 3\r\n// body\r\n1 2 3\r\n"
    r = _probe(fixture_dir, "body.pck", _xor_gzip(scene))
    assert r.probe["x3_payload"]["format"] == "scene-text"
    assert r.probe["x3_payload"]["scene_version"] == 3


def test_x3_bodyfile_and_cut1_payloads(fixture_dir):
    body = (b"/======\n/ Bodyfile F:\\SRC\\cut\\00128.BOD\n/ EGOSOFT Bodyfile exporter version Jul  8 2003\n"
            b"MATERIAL5:  0; 27; 144\nMATERIAL5:  1; 113; 144\n")
    r = _probe(fixture_dir, "00128.pck", _xor_gzip(body))
    pl = r.probe["x3_payload"]
    assert pl["format"] == "scene-text" and pl["role"] == "model"
    assert pl["row_kinds"] == {"MATERIAL5": 2}
    assert r.members[0]["path"] == "00128.pbd"
    cut = b"CUT1INFO$PATH: X:\\cut\\948.bob SRC: D:\\a.max TIME: x$\x00/INF"
    r = _probe(fixture_dir, "948.pck", _xor_gzip(cut))
    assert r.probe["x3_payload"]["format"] == "cut1"
    assert r.probe["x3_payload"]["source_path"] == "X:\\cut\\948.bob"


def test_x3_truncated_flag():
    class R:
        kind = "text"
        probe: dict = {}
        members = None
    r = R()
    r.probe = {}
    pck.refine_x3_pck("big.pck", SCRIPT, True, r)
    assert r.probe["x3_payload"]["truncated"] is True
    assert "size" not in r.members[0]


def test_pickle_protocols():
    class R:
        probe: dict = {}
    for proto in (0, 2, 4):
        r = R()
        r.probe = {}
        blob = pickle.dumps({"a": [1, 2, 3], "b": "text" * 3}, protocol=proto)
        assert pck.identify_other("x.pck", blob[:8192], r) == "pickle", proto
        assert r.probe["pickle_protocol"] == proto


def test_python27_text_pickle_head():
    head = b"crandom\nRandom\np0\n(tRp1\n(I2\n(I-2147483648\nI-845974985\nI-1294090086\nI1193659239\ntp2\nb."
    class R:
        probe: dict = {}
    r = R()
    r.probe = {}
    assert pck.identify_other("randv2_32.pck", head, r) == "pickle"


def test_unknown_pck_and_noop_rules():
    class R:
        probe: dict = {}
    r = R()
    r.probe = {}
    assert pck.identify_other("blob.pck", bytes(range(256)) * 4, r) == "unknown"
    assert r.probe["pck_format"] == "unknown"
    r2 = R()
    r2.probe = {"pck_format": "x3"}
    assert pck.identify_other("a.pck", b"\x80\x02N.", r2) is None
    assert r2.probe["pck_format"] == "x3"
    r3 = R()
    r3.probe = {}
    assert pck.identify_other("a.txt", b"\x80\x02N.", r3) is None
    assert r3.probe == {}
    r4 = R()
    r4.probe = {}
    assert pck.identify_other("notes.pck", b"hello world, plain text.\n", r4) == "unknown"
