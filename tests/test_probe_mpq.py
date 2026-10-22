"""MPQ header, encrypted hash/block tables, (listfile) in several encodings.

The builder here reimplements the MPQ crypto independently of
filecat.probe.mpq so the test is a cross-check, not a round trip of one
implementation.
"""
from __future__ import annotations

import bz2
import struct
import zlib
from pathlib import Path

from filecat.options import ScanOptions
from filecat.probe import mpq, probe_file

EXISTS = 0x80000000
SINGLE = 0x01000000
COMPRESS = 0x00000200
ENCRYPTED = 0x00010000

_TABLE = [0] * 0x500
_seed = 0x00100001
for _i in range(0x100):
    _j = _i
    for _ in range(5):
        _seed = (_seed * 125 + 3) % 0x2AAAAB
        _t1 = (_seed & 0xFFFF) << 16
        _seed = (_seed * 125 + 3) % 0x2AAAAB
        _TABLE[_j] = _t1 | (_seed & 0xFFFF)
        _j += 0x100


def _hash(name: str, kind: int) -> int:
    s1, s2 = 0x7FED7FED, 0xEEEEEEEE
    for ch in name.upper():
        c = ord(ch)
        s1 = (_TABLE[(kind << 8) + c] ^ (s1 + s2)) & 0xFFFFFFFF
        s2 = (c + s1 + s2 + (s2 << 5) + 3) & 0xFFFFFFFF
    return s1


def _encrypt(data: bytes, key: int) -> bytes:
    padded = data + b"\0" * (-len(data) % 4)
    n = len(padded) // 4
    s2 = 0xEEEEEEEE
    out = []
    for v in struct.unpack(f"<{n}I", padded):
        s2 = (s2 + _TABLE[0x400 + (key & 0xFF)]) & 0xFFFFFFFF
        out.append((v ^ (key + s2)) & 0xFFFFFFFF)
        key = (((~key << 21) + 0x11111111) | (key >> 11)) & 0xFFFFFFFF
        s2 = (v + s2 + (s2 << 5) + 3) & 0xFFFFFFFF
    return struct.pack(f"<{n}I", *out)[: len(data)]


def build_mpq(members: list[tuple[str, int, int, int]], listfile: str | None, *,
              compress: str = "none", encrypt: bool = False, prefix: bytes = b"",
              user_data: bool = False, sectored: bool = False) -> bytes:
    """members: (name, size, csize, flags) decoys whose bytes are never read."""
    body = b""
    lf_flags = EXISTS
    lf_size = 0
    if listfile is not None:
        plain = listfile.encode()
        lf_size = len(plain)
        stored = plain
        if compress == "zlib":
            stored, lf_flags = b"\x02" + zlib.compress(plain), lf_flags | COMPRESS
        elif compress == "bzip2":
            stored, lf_flags = b"\x10" + bz2.compress(plain), lf_flags | COMPRESS
        if sectored:
            ss = 512 << 3
            sectors = [stored[i:i + ss] for i in range(0, len(stored), ss)] or [b""]
            # one sector per stored chunk only valid when each sector is a
            # whole uncompressed sector; callers pass an uncompressed listfile
            assert compress == "none"
            offs, pos = [], 4 * (len(sectors) + 1)
            for s in sectors:
                offs.append(pos)
                pos += len(s)
            offs.append(pos)
            table = struct.pack(f"<{len(offs)}I", *offs)
            stored = table + b"".join(sectors)
        else:
            lf_flags |= SINGLE
        if encrypt:
            lf_flags |= ENCRYPTED
            key = _hash("(listfile)", 3)
            if sectored:
                nsec = len(offs) - 1
                t = _encrypt(stored[: 4 * len(offs)], (key - 1) & 0xFFFFFFFF)
                rest = stored[4 * len(offs):]
                parts = [t]
                for i in range(nsec):
                    parts.append(_encrypt(rest[offs[i] - offs[0]: offs[i + 1] - offs[0]], (key + i) & 0xFFFFFFFF))
                stored = b"".join(parts)
            else:
                stored = _encrypt(stored, key)
        body = stored

    base = len(prefix)
    blocks, names = [], []
    pos = 32
    lf_block = None
    if listfile is not None:
        lf_block = (pos, len(body), lf_size, lf_flags)
        pos += len(body)
    for name, size, csize, flags in members:
        blocks.append((pos, csize, size, flags))
        names.append(name)
        pos += csize
    all_blocks = list(blocks)
    all_names = list(names)
    if lf_block is not None:
        all_blocks.append(lf_block)
        all_names.append("(listfile)")

    n = 4
    while n < len(all_names) * 2:
        n *= 2
    slots = [(0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF)] * n
    for bi, name in enumerate(all_names):
        i = _hash(name, 0) & (n - 1)
        while slots[i][4] != 0xFFFFFFFF:
            i = (i + 1) % n
        slots[i] = (_hash(name, 1), _hash(name, 2), 0, 0, bi)
    hash_raw = b"".join(struct.pack("<IIHHI", *s) for s in slots)
    block_raw = b"".join(struct.pack("<IIII", *b) for b in all_blocks)
    hash_off = pos
    block_off = hash_off + len(hash_raw)
    total = block_off + len(block_raw)
    header = struct.pack("<4sIIHHIIII", b"MPQ\x1a", 32, total, 0, 3, hash_off, block_off, n, len(all_blocks))
    arch = bytearray(total)
    arch[0:32] = header
    if listfile is not None:
        arch[32:32 + len(body)] = body
    arch[hash_off:hash_off + len(hash_raw)] = _encrypt(hash_raw, _hash("(hash table)", 3))
    arch[block_off:block_off + len(block_raw)] = _encrypt(block_raw, _hash("(block table)", 3))
    out = bytes(arch)
    if user_data:
        udh = b"MPQ\x1b" + struct.pack("<III", 0, 16 + len(prefix), 16)
        return udh + prefix + out
    return prefix + out


MEMBERS = [
    ("Units\\Footman.mdx", 5000, 2000, EXISTS | COMPRESS),
    ("Scripts\\common.j", 900, 900, EXISTS),
    ("ReplaceableTextures\\icon.blp", 1200, 700, EXISTS | COMPRESS),
    ("Sound\\hit.wav", 300, 300, EXISTS),
]
_P = "Game\\Data\\Shared\\Assets\\Repeated\\Directory\\Prefix\\"
MEMBERS = [(_P + n, s, c, f) for n, s, c, f in MEMBERS]   # long shared prefix so zlib/bzip2 shrink it
LISTFILE = "\r\n".join(n for n, *_ in MEMBERS) + "\r\n"


def _probe(tmp: Path, name: str, data: bytes, opts: ScanOptions | None = None):
    p = tmp / name
    p.write_bytes(data)
    return probe_file(str(p), name, len(data), data[:8192], opts or ScanOptions())


def _check(r, count=4):
    assert r.kind == "archive", r.errors
    assert r.probe["format"] == "mpq"
    info = r.probe["mpq"]
    assert info["format_version"] == 1
    assert info["sector_size"] == 4096
    assert info["block_table_entries"] == count + 1
    assert info["header_offset"] == 0
    assert info["listfile"] is True
    assert info["unnamed_blocks"] == 1          # the (listfile) block itself
    rows = r.members
    assert [m["path"] for m in rows] == [n.replace("\\", "/") for n, *_ in MEMBERS]
    assert [m["role"] for m in rows] == ["model", "script", "texture", "audio"]
    assert rows[0]["size"] == 5000 and rows[0]["csize"] == 2000
    assert rows[0]["method"] == "compress" and rows[1]["method"] == "stored"
    assert r.probe["members_count"] == 4
    assert r.probe["member_roles"]["model"] == 1
    assert not r.errors


def test_detect():
    assert mpq.detect(b"MPQ\x1a....")
    assert mpq.detect(b"MPQ\x1b....")
    assert not mpq.detect(b"MZ\x90\x00")


def test_uncompressed_listfile(fixture_dir):
    _check(_probe(fixture_dir, "plain.mpq", build_mpq(MEMBERS, LISTFILE)))


def test_zlib_listfile(fixture_dir):
    _check(_probe(fixture_dir, "z.mpq", build_mpq(MEMBERS, LISTFILE, compress="zlib")))


def test_bzip2_listfile(fixture_dir):
    _check(_probe(fixture_dir, "b.mpq", build_mpq(MEMBERS, LISTFILE, compress="bzip2")))


def test_encrypted_zlib_listfile(fixture_dir):
    _check(_probe(fixture_dir, "ez.mpq", build_mpq(MEMBERS, LISTFILE, compress="zlib", encrypt=True)))


def test_sectored_encrypted_listfile(fixture_dir):
    big = "".join(f"Dir\\file{i:05d}.txt\r\n" for i in range(600))  # > 1 sector of 4096
    members = [(f"Dir\\file{i:05d}.txt", 10, 10, EXISTS) for i in range(600)]
    r = _probe(fixture_dir, "sec.mpq", build_mpq(members, big, encrypt=True, sectored=True))
    assert r.probe["mpq"]["listfile"] is True, r.errors
    assert r.probe["members_count"] == 600
    assert r.members[599]["path"] == "Dir/file00599.txt"


def test_user_data_header_and_prefix(fixture_dir):
    data = build_mpq(MEMBERS, LISTFILE, prefix=b"\0" * 100, user_data=True)
    # offsets inside the archive are relative to the MPQ header, which sits
    # after the 16-byte user-data header plus the 100 bytes of user data
    r = _probe(fixture_dir, "ud.mpq", data)
    assert r.probe["mpq"]["header_offset"] == 116
    assert r.probe["mpq"]["listfile"] is True, r.errors
    assert r.probe["members_count"] == 4


def test_no_listfile_gives_block_rows(fixture_dir):
    r = _probe(fixture_dir, "nolf.mpq", build_mpq(MEMBERS, None))
    assert r.kind == "archive"
    assert r.probe["mpq"]["listfile"] is False
    assert [m["path"] for m in r.members] == ["<block 0>", "<block 1>", "<block 2>", "<block 3>"]
    assert r.probe["mpq"]["unnamed_blocks"] == 4


def test_unknown_name_and_unnamed_blocks(fixture_dir):
    members = MEMBERS + [("Extra\\hidden.bin", 10, 10, EXISTS)]
    lf = LISTFILE + "Missing\\ghost.txt\r\n"
    r = _probe(fixture_dir, "extra.mpq", build_mpq(members, lf))
    assert r.probe["mpq"]["unnamed_blocks"] == 2           # hidden.bin + (listfile)
    ghost = [m for m in r.members if m["path"] == "Missing/ghost.txt"][0]
    assert "error" in ghost


def test_max_members_truncates(fixture_dir):
    r = _probe(fixture_dir, "cap.mpq", build_mpq(MEMBERS, LISTFILE), ScanOptions(max_members=2))
    assert len(r.members) == 2
    assert r.probe["members_truncated"] is True
    assert r.probe["members_count"] == 2


def test_truncated_file_is_an_error_not_a_crash(fixture_dir):
    data = build_mpq(MEMBERS, LISTFILE)
    r = _probe(fixture_dir, "cut.mpq", data[:60])
    assert r.kind == "archive"
    assert r.errors


def test_explode_known_vector():
    # worked example from blast.c: "AIAIAIAIAIAIA"
    assert mpq.explode(bytes.fromhex("0004822425" "8f807f"), 1000) == b"AIAIAIAIAIAIA"
