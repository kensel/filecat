"""Minimal MS-SHLLINK (.lnk) parser.

Only what `filecat programs` needs: whether the header is the standard
76-byte ShellLinkHeader, the LinkInfo local target path (when present), and
the easy StringData fields (relative path, working directory, arguments).
LinkTargetIDList is skipped, not decoded. A file that is not a well-formed
shortcut raises ValueError; callers turn that into an `errors` entry.
"""
from __future__ import annotations

import struct
from typing import Any

HEADER_SIZE = 0x4C
LINK_CLSID = bytes.fromhex("01140200") + bytes.fromhex("0000") + bytes.fromhex("0000") + bytes([
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
])
# {00021401-0000-0000-C000-000000000046} in on-disk (mixed-endian GUID) byte order.

HAS_LINK_TARGET_ID_LIST = 1 << 0
HAS_LINK_INFO = 1 << 1
HAS_NAME = 1 << 2
HAS_RELATIVE_PATH = 1 << 3
HAS_WORKING_DIR = 1 << 4
HAS_ARGUMENTS = 1 << 5
HAS_ICON_LOCATION = 1 << 6
IS_UNICODE = 1 << 7

VOLUME_ID_AND_LOCAL_BASE_PATH = 1 << 0


def _read_string_data(buf: bytes, offset: int, unicode: bool) -> tuple[str, int]:
    count = struct.unpack_from("<H", buf, offset)[0]
    offset += 2
    if unicode:
        nbytes = count * 2
        text = buf[offset:offset + nbytes].decode("utf-16-le", errors="replace")
    else:
        nbytes = count
        text = buf[offset:offset + nbytes].decode("cp1252", errors="replace")
    return text, offset + nbytes


def _cstr(buf: bytes, offset: int, unicode: bool) -> str:
    if unicode:
        end = offset
        while end + 1 < len(buf) and not (buf[end] == 0 and buf[end + 1] == 0):
            end += 2
        return buf[offset:end].decode("utf-16-le", errors="replace")
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("cp1252", errors="replace")


def parse(data: bytes) -> dict[str, Any]:
    """Parse a .lnk file's bytes. Raises ValueError if the header is not
    the standard ShellLinkHeader."""
    if len(data) < HEADER_SIZE:
        raise ValueError("file shorter than a ShellLinkHeader")
    header_size = struct.unpack_from("<I", data, 0)[0]
    clsid = data[4:20]
    if header_size != HEADER_SIZE or clsid != LINK_CLSID:
        raise ValueError("not a standard ShellLinkHeader")
    link_flags = struct.unpack_from("<I", data, 20)[0]
    unicode = bool(link_flags & IS_UNICODE)

    result: dict[str, Any] = {}
    offset = HEADER_SIZE

    if link_flags & HAS_LINK_TARGET_ID_LIST:
        id_list_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + id_list_size

    local_base_path = None
    common_path_suffix = None
    if link_flags & HAS_LINK_INFO:
        link_info_start = offset
        link_info_size = struct.unpack_from("<I", data, link_info_start)[0]
        link_info_header_size = struct.unpack_from("<I", data, link_info_start + 4)[0]
        link_info_flags = struct.unpack_from("<I", data, link_info_start + 8)[0]
        local_base_path_offset = struct.unpack_from("<I", data, link_info_start + 16)[0]
        common_path_suffix_offset = struct.unpack_from("<I", data, link_info_start + 24)[0]
        local_base_path_offset_unicode = None
        common_path_suffix_offset_unicode = None
        if link_info_header_size >= 0x24:
            local_base_path_offset_unicode = struct.unpack_from("<I", data, link_info_start + 28)[0]
            common_path_suffix_offset_unicode = struct.unpack_from("<I", data, link_info_start + 32)[0]

        if link_info_flags & VOLUME_ID_AND_LOCAL_BASE_PATH:
            if local_base_path_offset_unicode:
                local_base_path = _cstr(data, link_info_start + local_base_path_offset_unicode, True)
            elif local_base_path_offset:
                local_base_path = _cstr(data, link_info_start + local_base_path_offset, False)
            if common_path_suffix_offset_unicode:
                common_path_suffix = _cstr(data, link_info_start + common_path_suffix_offset_unicode, True)
            elif common_path_suffix_offset:
                common_path_suffix = _cstr(data, link_info_start + common_path_suffix_offset, False)
        offset = link_info_start + link_info_size

    if local_base_path is not None:
        result["target"] = local_base_path + (common_path_suffix or "")

    for flag, key in (
        (HAS_NAME, "name"),
        (HAS_RELATIVE_PATH, "relative_path"),
        (HAS_WORKING_DIR, "working_dir"),
        (HAS_ARGUMENTS, "arguments"),
        (HAS_ICON_LOCATION, "icon_location"),
    ):
        if link_flags & flag:
            text, offset = _read_string_data(data, offset, unicode)
            if key != "icon_location":
                result[key] = text

    return result


def parse_file(path: str) -> dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    return parse(data)
