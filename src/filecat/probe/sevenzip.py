"""7z archives: signature header, (encoded) header, member names and sizes.

Reads the 32-byte signature header and the header database at the end of the
file -- never a member's packed bytes. A header that is itself compressed (the
7-Zip default) is inflated when its coder is Copy, LZMA or LZMA2; an
encrypted header is reported and not listed. Layout: 7zFormat.txt from the
7-Zip source distribution.
"""
from __future__ import annotations

import lzma
import os
import struct
import zlib
from typing import Any

from ..options import ScanOptions
from ..fsource import fopen, fsize
from . import members as members_mod

_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
_START_HEADER_SIZE = 32

# A header database is a few bytes per file; this many means a mis-parsed
# offset rather than a real archive.
_HEADER_CAP = 128 * 1024 * 1024
_MAX_ENCODED_DEPTH = 4

(_END, _HEADER, _ARCHIVE_PROPS, _ADDITIONAL_STREAMS, _MAIN_STREAMS, _FILES_INFO,
 _PACK_INFO, _UNPACK_INFO, _SUBSTREAMS_INFO, _SIZE, _CRC, _FOLDER, _CODERS_UNPACK_SIZE,
 _NUM_UNPACK_STREAM, _EMPTY_STREAM, _EMPTY_FILE, _ANTI, _NAMES, _CTIME, _ATIME,
 _MTIME, _WIN_ATTRIBUTES, _COMMENT, _ENCODED_HEADER) = range(24)

_METHODS = {
    b"\x00": "copy",
    b"\x03": "delta",
    b"\x04": "bcj",
    b"\x05": "ppc",
    b"\x06": "ia64",
    b"\x07": "arm",
    b"\x08": "armt",
    b"\x09": "sparc",
    b"\x0a": "arm64",
    b"\x21": "lzma2",
    b"\x03\x01\x01": "lzma",
    b"\x03\x03\x01\x03": "bcj",
    b"\x03\x03\x01\x1b": "bcj2",
    b"\x03\x03\x02\x05": "ppc",
    b"\x03\x03\x04\x01": "ia64",
    b"\x03\x03\x05\x01": "arm",
    b"\x03\x03\x07\x01": "armt",
    b"\x03\x03\x08\x05": "sparc",
    b"\x03\x04\x01": "ppmd",
    b"\x04\x01\x08": "deflate",
    b"\x04\x01\x09": "deflate64",
    b"\x04\x02\x02": "bzip2",
    b"\x04\xf7\x11\x01": "zstd",
    b"\x04\xf7\x11\x04": "brotli",
    b"\x06\xf1\x07\x01": "aes",
}
_AES = b"\x06\xf1\x07\x01"
_FILTERS = {"delta", "bcj", "bcj2", "ppc", "ia64", "arm", "armt", "sparc", "arm64"}

_FILETIME_EPOCH_DELTA = 11644473600   # seconds from 1601-01-01 to 1970-01-01


def detect(head: bytes) -> bool:
    return head[:6] == _SIGNATURE


class _Truncated(Exception):
    pass


class _Reader:
    """Cursor over a header database; every short read raises _Truncated."""
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise _Truncated()
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def number(self) -> int:
        """7z variable-length integer: leading 1-bits of the first byte say
        how many more little-endian bytes follow."""
        first = self.byte()
        mask = 0x80
        value = 0
        for i in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * i))
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def bits(self, n: int) -> list[bool]:
        raw = self.take((n + 7) // 8)
        return [bool(raw[i >> 3] & (0x80 >> (i & 7))) for i in range(n)]

    def defined(self, n: int) -> list[bool]:
        """allDefined byte, then a bit vector when it is zero."""
        return [True] * n if self.byte() else self.bits(n)


class _Folder:
    __slots__ = ("coders", "bind_outs", "packed_ins", "unpack_sizes", "crc",
                 "num_streams", "first_pack")

    def __init__(self) -> None:
        self.coders: list[tuple[bytes, int, int, bytes]] = []   # id, n_in, n_out, props
        self.bind_outs: set[int] = set()
        self.packed_ins: list[int] = []
        self.unpack_sizes: list[int] = []
        self.crc: int | None = None
        self.num_streams = 1
        self.first_pack = 0

    @property
    def unpack_size(self) -> int:
        for i, size in enumerate(self.unpack_sizes):
            if i not in self.bind_outs:
                return size
        return self.unpack_sizes[-1] if self.unpack_sizes else 0

    @property
    def methods(self) -> list[str]:
        return [_METHODS.get(c[0], c[0].hex()) for c in self.coders]

    @property
    def encrypted(self) -> bool:
        return any(c[0] == _AES for c in self.coders)

    def method_label(self) -> str:
        return "+".join(self.methods)


def _read_digests(r: _Reader, n: int) -> list[int | None]:
    defined = r.defined(n)
    return [struct.unpack("<I", r.take(4))[0] if d else None for d in defined]


def _read_pack_info(r: _Reader) -> tuple[int, list[int]]:
    pack_pos = r.number()
    count = r.number()
    sizes: list[int] = []
    while True:
        prop = r.byte()
        if prop == _END:
            break
        if prop == _SIZE:
            sizes = [r.number() for _ in range(count)]
        elif prop == _CRC:
            _read_digests(r, count)
        else:
            raise ValueError(f"unexpected PackInfo property {prop}")
    return pack_pos, sizes


def _read_folder(r: _Reader) -> _Folder:
    folder = _Folder()
    n_coders = r.number()
    if n_coders < 1 or n_coders > 32:
        raise ValueError(f"folder with {n_coders} coders")
    total_in = total_out = 0
    for _ in range(n_coders):
        flag = r.byte()
        coder_id = r.take(flag & 0x0F)
        n_in, n_out = (r.number(), r.number()) if flag & 0x10 else (1, 1)
        props = r.take(r.number()) if flag & 0x20 else b""
        if flag & 0x80:
            raise ValueError("alternative coder methods are not defined")
        folder.coders.append((coder_id, n_in, n_out, props))
        total_in += n_in
        total_out += n_out
    bound_ins: set[int] = set()
    for _ in range(total_out - 1):
        bound_ins.add(r.number())
        folder.bind_outs.add(r.number())
    n_packed = total_in - len(bound_ins)
    if n_packed == 1:
        folder.packed_ins = [i for i in range(total_in) if i not in bound_ins][:1]
    else:
        folder.packed_ins = [r.number() for _ in range(n_packed)]
    return folder


def _read_unpack_info(r: _Reader) -> list[_Folder]:
    if r.byte() != _FOLDER:
        raise ValueError("UnpackInfo without Folder")
    n_folders = r.number()
    if r.byte():
        raise ValueError("external folder data is not supported")
    folders = [_read_folder(r) for _ in range(n_folders)]
    if r.byte() != _CODERS_UNPACK_SIZE:
        raise ValueError("UnpackInfo without CodersUnpackSize")
    for folder in folders:
        n_out = sum(c[2] for c in folder.coders)
        folder.unpack_sizes = [r.number() for _ in range(n_out)]
    while True:
        prop = r.byte()
        if prop == _END:
            break
        if prop == _CRC:
            for folder, crc in zip(folders, _read_digests(r, n_folders)):
                folder.crc = crc
        else:
            raise ValueError(f"unexpected UnpackInfo property {prop}")
    return folders


def _read_substreams(r: _Reader, folders: list[_Folder]) -> tuple[list[int], list[int | None]]:
    """Per-file unpack sizes and CRCs, in folder order."""
    prop = r.byte()
    if prop == _NUM_UNPACK_STREAM:
        for folder in folders:
            folder.num_streams = r.number()
        prop = r.byte()
    sizes: list[int] = []
    for folder in folders:
        n = folder.num_streams
        if n == 0:
            continue
        listed = [r.number() for _ in range(n - 1)] if prop == _SIZE else []
        if prop != _SIZE and n > 1:
            raise ValueError("substreams without sizes")
        sizes.extend(listed + [folder.unpack_size - sum(listed)])
    if prop == _SIZE:
        prop = r.byte()

    crcs: list[int | None] = []
    while prop != _END:
        if prop == _CRC:
            unknown = sum(f.num_streams for f in folders
                          if not (f.num_streams == 1 and f.crc is not None))
            listed_crcs = iter(_read_digests(r, unknown))
            crcs = []
            for folder in folders:
                if folder.num_streams == 1 and folder.crc is not None:
                    crcs.append(folder.crc)
                else:
                    crcs.extend(next(listed_crcs) for _ in range(folder.num_streams))
        else:
            raise ValueError(f"unexpected SubStreamsInfo property {prop}")
        prop = r.byte()
    if not crcs:
        crcs = [folder.crc if folder.num_streams == 1 else None
                for folder in folders for _ in range(folder.num_streams)]
    return sizes, crcs


def _read_streams_info(r: _Reader) -> dict[str, Any]:
    info: dict[str, Any] = {"pack_pos": 0, "pack_sizes": [], "folders": [],
                            "sizes": None, "crcs": []}
    while True:
        prop = r.byte()
        if prop == _END:
            break
        if prop == _PACK_INFO:
            info["pack_pos"], info["pack_sizes"] = _read_pack_info(r)
        elif prop == _UNPACK_INFO:
            info["folders"] = _read_unpack_info(r)
        elif prop == _SUBSTREAMS_INFO:
            info["sizes"], info["crcs"] = _read_substreams(r, info["folders"])
        else:
            raise ValueError(f"unexpected StreamsInfo property {prop}")
    if info["sizes"] is None:
        info["sizes"] = [f.unpack_size for f in info["folders"]]
        info["crcs"] = [f.crc for f in info["folders"]]
    pack = 0
    for folder in info["folders"]:
        folder.first_pack = pack
        pack += len(folder.packed_ins)
    return info


def _filetime_ns(value: int) -> int | None:
    secs, rem = divmod(value, 10_000_000)
    secs -= _FILETIME_EPOCH_DELTA
    return secs * 1_000_000_000 + rem * 100 if secs >= 0 else None


def _read_files_info(r: _Reader) -> list[dict[str, Any]]:
    n_files = r.number()
    if n_files > 50_000_000:
        raise ValueError(f"implausible file count {n_files}")
    empty_stream = [False] * n_files
    empty_file: list[bool] = []
    names: list[str] = []
    mtimes: list[int | None] = [None] * n_files
    attrs: list[int | None] = [None] * n_files
    while True:
        prop = r.byte()
        if prop == _END:
            break
        size = r.number()
        body = _Reader(r.take(size))
        if prop == _EMPTY_STREAM:
            empty_stream = body.bits(n_files)
        elif prop == _EMPTY_FILE:
            empty_file = body.bits(sum(empty_stream))
        elif prop == _NAMES:
            if body.byte():
                raise ValueError("external file names are not supported")
            text = body.data[1:].decode("utf-16-le", errors="replace")
            names = text.split("\x00")[:n_files]
        elif prop == _MTIME:
            defined = body.defined(n_files)
            if body.byte():
                continue
            for i, d in enumerate(defined):
                if d:
                    mtimes[i] = _filetime_ns(struct.unpack("<Q", body.take(8))[0])
        elif prop == _WIN_ATTRIBUTES:
            defined = body.defined(n_files)
            if body.byte():
                continue
            for i, d in enumerate(defined):
                if d:
                    attrs[i] = struct.unpack("<I", body.take(4))[0]
        # CTime, ATime, StartPos, Anti, Dummy and unknown properties are skipped.

    files: list[dict[str, Any]] = []
    empty_idx = 0
    for i in range(n_files):
        entry: dict[str, Any] = {
            "path": (names[i] if i < len(names) else "").replace("\\", "/"),
            "stream": not empty_stream[i],
            "mtime_ns": mtimes[i],
            "attrs": attrs[i],
        }
        if empty_stream[i]:
            is_empty_file = empty_idx < len(empty_file) and empty_file[empty_idx]
            entry["dir"] = not is_empty_file
            empty_idx += 1
        else:
            entry["dir"] = False
        a = attrs[i]
        if a is not None and not entry["stream"]:
            if a & 0x10 or (a & 0x8000 and (a >> 16) & 0o170000 == 0o040000):
                entry["dir"] = True
        files.append(entry)
    return files


def _decode_header(f: Any, info: dict[str, Any]) -> bytes:
    """Inflate the one folder of an encoded header."""
    folders = info["folders"]
    if len(folders) != 1 or len(folders[0].coders) != 1:
        raise ValueError("encoded header uses a coder chain")
    folder = folders[0]
    coder_id, _n_in, _n_out, props = folder.coders[0]
    if coder_id == _AES:
        raise PermissionError("header is encrypted")
    if not info["pack_sizes"]:
        raise ValueError("encoded header without a packed stream")
    size = folder.unpack_size
    if size > _HEADER_CAP or info["pack_sizes"][0] > _HEADER_CAP:
        raise ValueError(f"encoded header too large to probe ({size} bytes)")
    f.seek(_START_HEADER_SIZE + info["pack_pos"])
    packed = f.read(info["pack_sizes"][0])
    if len(packed) < info["pack_sizes"][0]:
        raise _Truncated()
    if coder_id == b"\x00":
        raw = packed
    elif coder_id == b"\x03\x01\x01" and len(props) == 5:
        d = props[0]
        lc, rest = d % 9, d // 9
        flt = {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": rest % 5, "pb": rest // 5,
               "dict_size": max(struct.unpack("<I", props[1:])[0], 4096)}
        raw = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[flt]).decompress(packed, size)
    elif coder_id == b"\x21" and len(props) == 1:
        p = props[0]
        dict_size = 0xFFFFFFFF if p >= 40 else (2 | (p & 1)) << (p // 2 + 11)
        flt = {"id": lzma.FILTER_LZMA2, "dict_size": dict_size}
        raw = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[flt]).decompress(packed, size)
    else:
        raise ValueError(f"encoded header uses unsupported coder {_METHODS.get(coder_id, coder_id.hex())}")
    if len(raw) != size:
        raise ValueError(f"encoded header inflated to {len(raw)} of {size} bytes")
    if folder.crc is not None and zlib.crc32(raw) != folder.crc:
        raise ValueError("encoded header CRC mismatch")
    return raw


def _rows(files: list[dict[str, Any]], info: dict[str, Any]) -> list[dict[str, Any]]:
    folders: list[_Folder] = info["folders"]
    sizes: list[int] = info["sizes"]
    crcs: list[int | None] = info["crcs"]
    # Folder index and packed size per stream, in stream order.
    stream_folder: list[int] = []
    for fi, folder in enumerate(folders):
        stream_folder.extend([fi] * folder.num_streams)
    pack_sizes: list[int] = info["pack_sizes"]

    rows: list[dict[str, Any]] = []
    stream = 0
    for idx, entry in enumerate(files):
        path = entry["path"]
        row: dict[str, Any] = {"index": idx, "path": path}
        if entry["dir"]:
            row["is_dir"] = True
            row["size"] = 0
            row["role"] = "dir"
        elif entry["stream"]:
            if stream < len(sizes):
                row["size"] = sizes[stream]
                if stream < len(crcs) and crcs[stream] is not None:
                    row["crc32"] = crcs[stream]
            if stream < len(stream_folder):
                folder = folders[stream_folder[stream]]
                row["method"] = folder.method_label()
                row["folder"] = stream_folder[stream]
                if folder.encrypted:
                    row["encrypted"] = True
            stream += 1
            row["role"] = members_mod.member_role(path)
        else:
            row["size"] = 0
            row["role"] = members_mod.member_role(path)
        if entry["mtime_ns"] is not None:
            row["mtime_ns"] = entry["mtime_ns"]
        rows.append(row)
    return rows


def probe_7z(path: str, head: bytes, options: ScanOptions, result: Any) -> None:
    result.kind = "archive"
    result.container = "7z"

    with fopen(path, "rb") as f:
        start = f.read(_START_HEADER_SIZE)
        if len(start) < _START_HEADER_SIZE:
            result.errors.append({"stage": "7z", "message": "signature header truncated"})
            return
        major, minor = start[6], start[7]
        start_crc, next_off, next_size, next_crc = struct.unpack("<IQQI", start[8:])
        info7z: dict[str, Any] = {"version": f"{major}.{minor}"}
        result.probe["7z"] = info7z
        if zlib.crc32(start[12:32]) != start_crc:
            info7z["start_header_crc_ok"] = False

        file_size = fsize(path)
        header_end = _START_HEADER_SIZE + next_off + next_size
        info7z["expected_size"] = header_end
        if header_end > file_size:
            result.probe["truncated"] = True
            result.errors.append({
                "stage": "7z",
                "message": f"archive incomplete: header ends at {header_end}, file is {file_size} bytes"})
            return
        if next_size == 0:
            result.members = []
            result.probe.update(members_mod.summarize([], truncated=False, list_cap=options.list_zip_cap))
            result.probe["entry_count"] = 0
            return
        if next_size > _HEADER_CAP:
            result.errors.append({"stage": "7z", "message": f"header too large to probe ({next_size} bytes)"})
            return

        f.seek(_START_HEADER_SIZE + next_off)
        data = f.read(next_size)
        if zlib.crc32(data) != next_crc:
            info7z["header_crc_ok"] = False

        try:
            files, info = _read_database(f, data, info7z)
        except PermissionError:
            info7z["header_encrypted"] = True
            return
        except (_Truncated, ValueError, lzma.LZMAError, struct.error) as exc:
            msg = "header truncated" if isinstance(exc, _Truncated) else f"{type(exc).__name__}: {exc}"
            result.errors.append({"stage": "7z", "message": msg})
            return

    folders: list[_Folder] = info["folders"]
    info7z["folders"] = len(folders)
    info7z["packed_size"] = sum(info["pack_sizes"])
    methods = sorted({m for fo in folders for m in fo.methods if m not in _FILTERS} or
                     {m for fo in folders for m in fo.methods})
    if methods:
        info7z["methods"] = methods
    if any(fo.encrypted for fo in folders):
        info7z["encrypted"] = True
    solid = any(fo.num_streams > 1 for fo in folders)
    info7z["solid"] = solid

    rows = _rows(files, info)
    result.probe["entry_count"] = len(rows)
    result.probe["uncompressed_size"] = sum(r.get("size", 0) for r in rows)
    truncated = len(rows) > options.max_members
    result.members = rows[: options.max_members]
    result.probe.update(members_mod.summarize(result.members, truncated=truncated,
                                               list_cap=options.list_zip_cap))


def _read_database(f: Any, data: bytes, info7z: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Header -> (file entries, main streams info); inflates encoded headers."""
    for _ in range(_MAX_ENCODED_DEPTH):
        r = _Reader(data)
        kind = r.byte()
        if kind == _ENCODED_HEADER:
            info7z["header_encoded"] = True
            data = _decode_header(f, _read_streams_info(r))
            continue
        if kind != _HEADER:
            raise ValueError(f"unexpected header type {kind}")
        break
    else:
        raise ValueError("encoded header nests too deeply")

    info: dict[str, Any] = {"pack_pos": 0, "pack_sizes": [], "folders": [], "sizes": [], "crcs": []}
    files: list[dict[str, Any]] = []
    while True:
        prop = r.byte()
        if prop == _END:
            break
        if prop == _ARCHIVE_PROPS:
            while r.byte() != _END:
                r.take(r.number())
        elif prop == _ADDITIONAL_STREAMS:
            _read_streams_info(r)
        elif prop == _MAIN_STREAMS:
            info = _read_streams_info(r)
        elif prop == _FILES_INFO:
            files = _read_files_info(r)
        else:
            raise ValueError(f"unexpected Header property {prop}")
    return files, info
