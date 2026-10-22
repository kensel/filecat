"""7z signature header, plain and LZMA2-encoded header databases, members.

The builder writes the 7z structures straight from 7zFormat.txt, independently
of filecat.probe.sevenzip, so the test is a cross-check and not a round trip.
"""
from __future__ import annotations

import lzma
import struct
import zlib
from pathlib import Path

from filecat.probe import probe_file

SIG = b"7z\xbc\xaf\x27\x1c"

A_TXT = b"hello 7z\n" * 20
B_BIN = bytes(range(256)) * 4


def num(v: int) -> bytes:
    if v < 0x80:
        return bytes([v])
    for n in range(1, 9):
        if v < 1 << (7 * (n + 1)):
            first = ((0xFF << (8 - n)) & 0xFF) | (v >> (8 * n))
            return bytes([first]) + (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
    raise ValueError(v)


def names_blob(names: list[str]) -> bytes:
    return b"\x00" + b"".join(n.encode("utf-16-le") + b"\x00\x00" for n in names)


def prop(pid: int, body: bytes) -> bytes:
    return bytes([pid]) + num(len(body)) + body


def lzma1(data: bytes) -> tuple[bytes, bytes]:
    filt = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 16}]
    packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filt)
    return packed, bytes([0x5D]) + struct.pack("<I", 1 << 16)


def main_header(packed_len: int, props: bytes, unpack_total: int) -> bytes:
    pack_info = b"\x06" + num(0) + num(1) + b"\x09" + num(packed_len) + b"\x00"
    folder = num(1) + b"\x23" + b"\x03\x01\x01" + num(len(props)) + props
    unpack_info = (b"\x07\x0b" + num(1) + b"\x00" + folder +
                   b"\x0c" + num(unpack_total) + b"\x00")
    sub = (b"\x08\x0d" + num(2) + b"\x09" + num(len(A_TXT)) +
           b"\x0a\x01" + struct.pack("<II", zlib.crc32(A_TXT), zlib.crc32(B_BIN)) + b"\x00")
    streams = b"\x04" + pack_info + unpack_info + sub + b"\x00"
    # a.txt, b.bin, dir, empty.txt: files 2 and 3 have no stream, 3 is a file.
    files = (b"\x05" + num(4) +
             prop(0x0E, bytes([0b00110000])) +
             prop(0x0F, bytes([0b01000000])) +
             prop(0x11, names_blob(["a.txt", "sub\\b.bin", "emptydir", "empty.txt"])) +
             prop(0x14, b"\x01\x00" + struct.pack("<Q", 132_000_000_000_000_000) * 4) +
             b"\x00")
    return b"\x01" + streams + files + b"\x00"


def start_header(next_off: int, next_header: bytes) -> bytes:
    tail = struct.pack("<QQI", next_off, len(next_header), zlib.crc32(next_header))
    return SIG + b"\x00\x04" + struct.pack("<I", zlib.crc32(tail)) + tail


def build_7z(*, encode_header: bool = False, encrypt_header: bool = False) -> bytes:
    packed, props = lzma1(A_TXT + B_BIN)
    header = main_header(len(packed), props, len(A_TXT) + len(B_BIN))
    body = packed
    if encode_header:
        coder = b"\x21" + num(1) + b"\x12"
        filt = [{"id": lzma.FILTER_LZMA2, "dict_size": 2 << 20}]
        hpacked = lzma.compress(header, format=lzma.FORMAT_RAW, filters=filt)
        if encrypt_header:
            coder = b"\x06\xf1\x07\x01" + num(1) + b"\x00"
            coder_flag = 0x24
        else:
            coder_flag = 0x21
        if encrypt_header:
            hpacked = bytes(len(hpacked))
        pack_pos = len(body)
        body += hpacked
        header = (b"\x17" +
                  b"\x06" + num(pack_pos) + num(1) + b"\x09" + num(len(hpacked)) + b"\x00" +
                  b"\x07\x0b" + num(1) + b"\x00" + num(1) + bytes([coder_flag]) + coder +
                  b"\x0c" + num(len(header)) + b"\x0a\x01" + struct.pack("<I", zlib.crc32(header)) +
                  b"\x00" + b"\x00")
    return start_header(len(body), header) + body + header


def probe(tmp_path: Path, blob: bytes):
    p = tmp_path / "x.7z"
    p.write_bytes(blob)
    return probe_file(str(p), p.name, len(blob), blob[:8192])


def check_members(res) -> None:
    rows = {m["path"]: m for m in res.members}
    assert list(rows) == ["a.txt", "sub/b.bin", "emptydir", "empty.txt"]
    assert rows["a.txt"]["size"] == len(A_TXT)
    assert rows["a.txt"]["crc32"] == zlib.crc32(A_TXT)
    assert rows["a.txt"]["method"] == "lzma"
    assert rows["a.txt"]["role"] == "text"
    assert rows["sub/b.bin"]["size"] == len(B_BIN)
    assert rows["sub/b.bin"]["crc32"] == zlib.crc32(B_BIN)
    assert rows["emptydir"]["is_dir"] is True
    assert "is_dir" not in rows["empty.txt"] and rows["empty.txt"]["size"] == 0
    assert rows["a.txt"]["mtime_ns"] == (13_200_000_000 - 11_644_473_600) * 1_000_000_000


def test_plain_header(tmp_path):
    res = probe(tmp_path, build_7z())
    assert res.errors == []
    assert (res.kind, res.container) == ("archive", "7z")
    check_members(res)
    assert res.probe["entry_count"] == 4
    assert res.probe["uncompressed_size"] == len(A_TXT) + len(B_BIN)
    info = res.probe["7z"]
    assert info["version"] == "0.4" and info["solid"] is True
    assert info["methods"] == ["lzma"] and info["folders"] == 1
    assert "header_encoded" not in info and "header_crc_ok" not in info


def test_lzma2_encoded_header(tmp_path):
    res = probe(tmp_path, build_7z(encode_header=True))
    assert res.errors == []
    assert res.probe["7z"]["header_encoded"] is True
    check_members(res)


def test_encrypted_header_is_reported_not_listed(tmp_path):
    res = probe(tmp_path, build_7z(encode_header=True, encrypt_header=True))
    assert (res.kind, res.container) == ("archive", "7z")
    assert res.probe["7z"]["header_encrypted"] is True
    assert res.members is None and res.errors == []


def test_incomplete_download_is_flagged(tmp_path):
    blob = build_7z(encode_header=True)
    res = probe(tmp_path, blob[:-10])
    assert res.kind == "archive" and res.probe["truncated"] is True
    assert "incomplete" in res.errors[0]["message"]
    assert res.members is None


def test_corrupt_header_does_not_raise(tmp_path):
    blob = bytearray(build_7z())
    blob[-6] ^= 0xFF
    res = probe(tmp_path, bytes(blob))
    assert res.kind == "archive" and res.container == "7z"
    assert res.probe["7z"]["header_crc_ok"] is False


def test_empty_archive(tmp_path):
    blob = start_header(0, b"")
    res = probe(tmp_path, blob)
    assert res.members == [] and res.probe["entry_count"] == 0 and res.errors == []
