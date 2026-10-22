"""JPEG/PNG/GIF dims, DDS, TGA. See file-catalog-requirements.md fixture table
and 'Archives, images, models, data'.
"""
from __future__ import annotations

import struct
from pathlib import Path

from filecat.options import ScanOptions
from filecat.probe import probe_file


def _probe(fixture_dir: Path, filename: str, data: bytes):
    p = fixture_dir / filename
    p.write_bytes(data)
    return probe_file(str(p), filename, len(data), data[:8192], ScanOptions())


def _build_jpeg(width: int, height: int) -> bytes:
    sof = b"\xff\xc0" + struct.pack(">H", 11) + bytes([8]) + struct.pack(">HH", height, width) + bytes([1, 1, 0x11, 0])
    return b"\xff\xd8" + sof + b"\xff\xd9"


def _build_png(width: int, height: int) -> bytes:
    ihdr = struct.pack(">II", width, height) + bytes([8, 2, 0, 0, 0])
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\x00\x00\x00\x00"


def _build_gif(width: int, height: int) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00\x00\x00"


def _build_dds(width: int, height: int, fourcc: bytes = b"DXT1", mip_count: int = 1) -> bytes:
    header = bytearray(128)
    header[0:4] = b"DDS "
    struct.pack_into("<I", header, 4, 124)
    struct.pack_into("<I", header, 8, 0x1007)
    struct.pack_into("<I", header, 12, height)
    struct.pack_into("<I", header, 16, width)
    struct.pack_into("<I", header, 28, mip_count)
    struct.pack_into("<I", header, 76, 32)
    struct.pack_into("<I", header, 80, 0x4)
    header[84:88] = fourcc
    struct.pack_into("<I", header, 108, 0x1000)
    return bytes(header)


def _build_tga(width: int, height: int, image_type: int = 2, depth: int = 24) -> bytes:
    header = bytearray(18)
    header[2] = image_type
    struct.pack_into("<H", header, 12, width)
    struct.pack_into("<H", header, 14, height)
    header[16] = depth
    return bytes(header)


def test_jpeg_dims(fixture_dir):
    r = _probe(fixture_dir, "photo.jpg", _build_jpeg(640, 480))
    assert r.kind == "image"
    assert r.probe["width"] == 640
    assert r.probe["height"] == 480


def test_png_dims(fixture_dir):
    r = _probe(fixture_dir, "photo.png", _build_png(100, 50))
    assert r.kind == "image"
    assert r.probe["width"] == 100
    assert r.probe["height"] == 50


def test_gif_dims(fixture_dir):
    r = _probe(fixture_dir, "photo.gif", _build_gif(16, 16))
    assert r.kind == "image"
    assert r.probe["width"] == 16
    assert r.probe["height"] == 16


def test_dds_4x4_dxt1(fixture_dir):
    r = _probe(fixture_dir, "tex.dds", _build_dds(4, 4, b"DXT1"))
    assert r.kind == "texture"
    assert r.probe["fourcc"] == "DXT1"
    assert r.probe["width"] == 4
    assert r.probe["height"] == 4


def test_tga(fixture_dir):
    r = _probe(fixture_dir, "tex.tga", _build_tga(32, 32, image_type=2, depth=24))
    assert r.kind == "texture"
    assert r.probe["format"] == "tga"
    assert r.probe["width"] == 32
    assert r.probe["height"] == 32
    assert r.probe["pixel_depth"] == 24


def test_tga_invalid_image_type_falls_through(fixture_dir):
    # image type 99 is outside {1,2,3,9,10,11} -> leave the file to the next probe.
    header = bytearray(18)
    header[2] = 99
    struct.pack_into("<H", header, 12, 32)
    struct.pack_into("<H", header, 14, 32)
    header[16] = 24
    data = bytes(header) + b"some text after it that is still plain ascii\n"
    r = _probe(fixture_dir, "notatga.bin", data)
    assert r.kind != "texture"


def test_note_pdf_with_png_bytes_is_image(fixture_dir):
    """A file named note.pdf whose bytes are a PNG signature -> kind=image.

    probe.kind is set purely from magic; the name-vs-magic disagreement is
    the identify layer's job, not this probe's.
    """
    r = _probe(fixture_dir, "note.pdf", _build_png(10, 10))
    assert r.kind == "image"
