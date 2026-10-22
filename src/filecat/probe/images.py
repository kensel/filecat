"""Image and GPU-texture header sniffing: JPEG, PNG, GIF, DDS, TGA.

No pixel decode -- dimensions and container-level fields only.
See file-catalog-requirements.md, "Archives, images, models, data".
"""
from __future__ import annotations

import struct
from typing import Any

_TGA_IMAGE_TYPES = (1, 2, 3, 9, 10, 11)
_TGA_DEPTHS = (1, 8, 15, 16, 24, 32)

_SOF_MARKERS = (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)
_STANDALONE_MARKERS = (0xD8, 0x01) + tuple(range(0xD0, 0xD8))


def sniff(data: bytes) -> dict[str, Any] | None:
    """Try DDS, TGA, JPEG, PNG, GIF in spec order. None if nothing matches."""
    if data[:4] == b"DDS ":
        return _dds(data)
    tga = _tga(data)
    if tga is not None:
        return tga
    if data[:3] == b"\xff\xd8\xff":
        return _jpeg(data)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return _png(data)
    if data[:4] == b"GIF8":
        return _gif(data)
    return None


def _dds(data: bytes) -> dict[str, Any] | None:
    if len(data) < 128:
        return None
    height = struct.unpack_from("<I", data, 12)[0]
    width = struct.unpack_from("<I", data, 16)[0]
    mip_count = struct.unpack_from("<I", data, 28)[0]
    fourcc = data[84:88].decode("ascii", errors="replace").rstrip("\x00")
    return {
        "kind": "texture",
        "format": "dds",
        "width": width,
        "height": height,
        "mip_count": mip_count,
        "fourcc": fourcc,
    }


def _tga(data: bytes) -> dict[str, Any] | None:
    if len(data) < 18:
        return None
    colormap_type = data[1]
    image_type = data[2]
    if colormap_type not in (0, 1):
        return None
    if image_type not in _TGA_IMAGE_TYPES:
        return None
    width = struct.unpack_from("<H", data, 12)[0]
    height = struct.unpack_from("<H", data, 14)[0]
    depth = data[16]
    if width == 0 or height == 0:
        return None
    if depth not in _TGA_DEPTHS:
        return None
    # TGA has no magic, so the header fields must agree with each other.
    # Colour-mapped image types (1, 9) need a colour map with a real entry
    # size; the others must not declare one. Descriptor bits 6-7 (interleave)
    # are unused in practice, and the alpha-bit count cannot exceed the depth.
    cmap_length = struct.unpack_from("<H", data, 5)[0]
    cmap_entry_size = data[7]
    if image_type in (1, 9):
        if colormap_type != 1 or cmap_length == 0 or cmap_entry_size not in (15, 16, 24, 32):
            return None
    elif colormap_type != 0 or any(data[3:8]):
        return None
    descriptor = data[17]
    if descriptor & 0xC0 or (descriptor & 0x0F) > depth:
        return None
    return {
        "kind": "texture",
        "format": "tga",
        "width": width,
        "height": height,
        "pixel_depth": depth,
        "image_type": image_type,
    }


def _jpeg(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": "image", "format": "jpeg"}
    i = 2
    n = len(data)
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xFF:
            i += 1
            continue
        if marker in _STANDALONE_MARKERS:
            i += 2
            continue
        if marker == 0xD9:
            break
        if i + 4 > n:
            break
        seg_len = struct.unpack_from(">H", data, i + 2)[0]
        if marker in _SOF_MARKERS:
            if i + 9 <= n:
                height = struct.unpack_from(">H", data, i + 5)[0]
                width = struct.unpack_from(">H", data, i + 7)[0]
                out["width"] = width
                out["height"] = height
            break
        if seg_len < 2:
            break
        i += 2 + seg_len
    return out


def _png(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": "image", "format": "png"}
    if len(data) >= 24 and data[12:16] == b"IHDR":
        out["width"] = struct.unpack_from(">I", data, 16)[0]
        out["height"] = struct.unpack_from(">I", data, 20)[0]
    return out


def _gif(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": "image", "format": "gif"}
    if len(data) >= 10:
        out["width"] = struct.unpack_from("<H", data, 6)[0]
        out["height"] = struct.unpack_from("<H", data, 8)[0]
    return out
