"""Audio/video container sniffing: RIFF/WAVE, ID3, MP3 frame sync, ISO BMFF, EBML.

Duration is omitted -- it is not available from the header bytes this probe reads.
See file-catalog-requirements.md, "Probe order" step 9.
"""
from __future__ import annotations

import struct
from typing import Any

_MPEG_VERSION = {0b00: "2.5", 0b10: "2", 0b11: "1"}
_LAYER = {0b01: "3", 0b10: "2", 0b11: "1"}
_BITRATES_V1L3 = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, None)
_SAMPLE_RATES_V1 = (44100, 48000, 32000, None)


def sniff(data: bytes) -> dict[str, Any] | None:
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return _wave(data)
    if data[:3] == b"ID3":
        return _id3(data)
    if len(data) >= 4 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
        hdr = _mp3_frame(data)
        if hdr is not None:
            return hdr
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return _isobmff(data)
    if data[:4] == b"\x1a\x45\xdf\xa3":
        return {"kind": "video", "format": "ebml"}
    return None


def _wave(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": "audio", "format": "wav"}
    idx = data.find(b"fmt ", 12)
    if idx != -1 and idx + 24 <= len(data):
        audio_format, channels, sample_rate = struct.unpack_from("<HHI", data, idx + 8)
        out["audio_format"] = audio_format
        out["channels"] = channels
        out["sample_rate"] = sample_rate
    return out


def _id3(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": "audio", "format": "mp3"}
    if len(data) >= 5:
        out["id3_version"] = f"2.{data[3]}.{data[4]}"
    return out


def _mp3_frame(data: bytes) -> dict[str, Any] | None:
    b2, b3 = data[1], data[2]
    version = _MPEG_VERSION.get((b2 >> 3) & 0x03)
    layer = _LAYER.get((b2 >> 1) & 0x03)
    if version is None or layer is None:
        return None
    bitrate_idx = (b3 >> 4) & 0x0F
    samplerate_idx = (b3 >> 2) & 0x03
    if bitrate_idx in (0, 15) or samplerate_idx == 3:
        return None
    out: dict[str, Any] = {"kind": "audio", "format": "mp3", "mpeg_version": version, "layer": layer}
    if version == "1" and layer == "3":
        br = _BITRATES_V1L3[bitrate_idx]
        sr = _SAMPLE_RATES_V1[samplerate_idx]
        if br:
            out["bitrate_kbps"] = br
        if sr:
            out["sample_rate"] = sr
    return out


def _isobmff(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": "video", "format": "isobmff"}
    brand = data[8:12]
    try:
        out["major_brand"] = brand.decode("ascii").strip("\x00").strip()
    except UnicodeDecodeError:
        pass
    return out
