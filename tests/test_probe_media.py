"""RIFF/WAVE, ID3, MP3 frame sync, ISO BMFF, EBML. Not in the required fixture
table but covers 'Probe order' step 9.
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


def test_riff_wave(fixture_dir):
    fmt_chunk = b"fmt " + struct.pack("<IHHIIHH", 16, 1, 2, 44100, 44100 * 4, 4, 16)
    data_chunk = b"data" + struct.pack("<I", 0)
    body = fmt_chunk + data_chunk
    riff = b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WAVE" + body
    r = _probe(fixture_dir, "tone.wav", riff)
    assert r.kind == "audio"
    assert r.probe["format"] == "wav"
    assert r.probe["channels"] == 2
    assert r.probe["sample_rate"] == 44100


def test_id3_mp3(fixture_dir):
    data = b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\x00" * 50
    r = _probe(fixture_dir, "song.mp3", data)
    assert r.kind == "audio"
    assert r.probe["format"] == "mp3"
    assert r.probe["id3_version"] == "2.4.0"


def test_mp3_frame_sync(fixture_dir):
    # MPEG1 Layer3, 128 kbps, 44100 Hz frame header.
    data = bytes([0xFF, 0xFB, 0x90, 0x00]) + b"\x00" * 100
    r = _probe(fixture_dir, "raw.mp3", data)
    assert r.kind == "audio"
    assert r.probe["format"] == "mp3"


def test_isobmff_video(fixture_dir):
    data = struct.pack(">I", 24) + b"ftyp" + b"isom" + b"\x00" * 16
    r = _probe(fixture_dir, "clip.mp4", data)
    assert r.kind == "video"
    assert r.probe["major_brand"] == "isom"


def test_ebml_video(fixture_dir):
    data = b"\x1a\x45\xdf\xa3" + b"\x00" * 20
    r = _probe(fixture_dir, "clip.mkv", data)
    assert r.kind == "video"
    assert r.probe["format"] == "ebml"
