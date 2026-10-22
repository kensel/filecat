"""ZIP listing (central directory only, no member data), and gzip /
gzip_xored / bzip2 / xz: unwrap + classify, plus a streamed tar listing when
the decompressed body turns out to be a tar.

See file-catalog-requirements.md, "Probe order" steps 5-6 and
"Archives, images, models, data".
"""
from __future__ import annotations

import bz2
import calendar
import functools
import lzma
import os
import struct
import zipfile
import zlib
from typing import Any, Callable, Iterator

from ..record import suffix_of
from ..options import GZIP_PROBE_CAP, ScanOptions
from . import images, media, members, tarball, text, x3

_CHUNK = 64 * 1024

# Per-call output cap for every incremental decompress() call, so a highly
# compressible chunk never blows up memory in one step (a small rolling
# buffer, not the whole decompressed body).
_STEP = 64 * 1024


# --- ZIP -----------------------------------------------------------------

_ZIP_METHOD_NAMES = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflated",
    zipfile.ZIP_BZIP2: "bzip2",
    zipfile.ZIP_LZMA: "lzma",
}


def _zip_method_name(method: int) -> str:
    return _ZIP_METHOD_NAMES.get(method, str(method))


def _zip_extra_mtime(extra: bytes) -> int | None:
    """Unix mtime (seconds) from the 0x5455 extended-timestamp extra field,
    when present and flagged as carrying mtime."""
    i, n = 0, len(extra)
    while i + 4 <= n:
        header_id, size = struct.unpack_from("<HH", extra, i)
        i += 4
        if i + size > n:
            break
        data = extra[i:i + size]
        i += size
        if header_id == 0x5455 and len(data) >= 5 and (data[0] & 0x1):
            return struct.unpack_from("<i", data, 1)[0]
    return None


def _dos_mtime_ns(date_time: tuple) -> int | None:
    """DOS (year, month, day, hour, min, sec) has no timezone. Recorded as
    naive UTC nanoseconds (i.e. the six fields are treated as a UTC wall
    clock reading, which they may not be)."""
    try:
        return calendar.timegm(tuple(date_time) + (0, 0, 0)) * 1_000_000_000
    except (ValueError, OverflowError):
        return None


def probe_zip(path: str, options: ScanOptions, result: Any) -> None:
    """List every entry from the central directory only (zipfile.ZipFile on
    a path reads the EOCD/zip64-EOCD and the central directory -- it never
    touches a local file header or member data on open)."""
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()

    names = [i.filename for i in infos]
    is_ooxml = bool(names) and names[0] == "[Content_Types].xml"
    result.kind = "document" if is_ooxml else "archive"
    result.container = "zip"
    result.probe["entry_count"] = len(infos)
    result.probe["uncompressed_size"] = sum(i.file_size for i in infos)

    rows: list[dict[str, Any]] = []
    for idx, zi in enumerate(infos):
        zpath = zi.filename.replace("\\", "/")
        row: dict[str, Any] = {
            "index": idx,
            "path": zpath,
            "size": zi.file_size,
            "csize": zi.compress_size,
            "crc32": zi.CRC,
            "method": _zip_method_name(zi.compress_type),
            "offset": zi.header_offset,
            "flags": zi.flag_bits,
            "role": members.member_role(zpath),
        }
        if zi.is_dir():
            row["is_dir"] = True
        if zi.flag_bits & 0x1:
            row["encrypted"] = True
        mtime_ns = _zip_extra_mtime(zi.extra)
        if mtime_ns is not None:
            row["mtime_ns"] = mtime_ns * 1_000_000_000
        else:
            dos_ns = _dos_mtime_ns(zi.date_time)
            if dos_ns is not None:
                row["mtime_ns"] = dos_ns
        rows.append(row)

    truncated = len(rows) > options.max_members
    result.members = rows[: options.max_members]
    result.probe.update(members.summarize(result.members, truncated=truncated,
                                           list_cap=options.list_zip_cap))


# --- gzip / gzip_xored -----------------------------------------------------

def detect_gzip(head: bytes) -> str | None:
    """'gzip' for a plain gzip header, 'gzip_xored' for the XOR wrapper, else None."""
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if len(head) >= 3:
        key = head[0] ^ 0xC8
        if (head[1] ^ key) == 0x1F and (head[2] ^ key) == 0x8B:
            return "gzip_xored"
    return None


def _parse_gzip_header(data: bytes) -> dict[str, Any]:
    if len(data) < 10 or data[:2] != b"\x1f\x8b":
        return {}
    method, flags = data[2], data[3]
    mtime = struct.unpack_from("<I", data, 4)[0]
    os_byte = data[9]
    return {"method": method, "flags": flags, "mtime": mtime, "os": os_byte}


@functools.lru_cache(maxsize=256)
def _xor_table(key: int) -> bytes:
    """translate() table for a single-byte XOR; far faster than a generator."""
    return bytes(b ^ key for b in range(256))


def _make_unwrap(container: str, key: int) -> Callable[[bytes, bool], bytes]:
    def unwrap(chunk: bytes, first: bool) -> bytes:
        if container != "gzip_xored":
            return chunk
        if first:
            chunk = chunk[1:]
        if not key:
            return chunk
        return chunk.translate(_xor_table(key))
    return unwrap


_FEXTRA, _FNAME, _FCOMMENT, _FHCRC = 0x04, 0x08, 0x10, 0x02


def _gzip_original_name(path: str, container: str, key: int) -> str | None:
    """FNAME from the gzip header, when the FNAME flag is set."""
    try:
        with open(path, "rb") as f:
            raw = f.read(1024)
    except OSError:
        return None
    if container == "gzip_xored":
        if not raw:
            return None
        raw = raw[1:]
        if key:
            raw = raw.translate(_xor_table(key))
    if len(raw) < 10 or raw[:2] != b"\x1f\x8b":
        return None
    flags = raw[3]
    pos = 10
    if flags & _FEXTRA:
        if pos + 2 > len(raw):
            return None
        xlen = struct.unpack_from("<H", raw, pos)[0]
        pos += 2 + xlen
    if flags & _FNAME:
        end = raw.find(b"\x00", pos)
        if end == -1:
            return None  # name longer than our read window; not worth a bigger read
        try:
            return raw[pos:end].decode("latin-1")
        except UnicodeDecodeError:
            return None
    return None


def _gzip_trailer_isize(path: str, container: str, key: int) -> int | None:
    """ISIZE, the last 4 bytes of a (single-member) gzip stream: the
    uncompressed size modulo 2**32 -- ambiguous above 4 GiB, by design of
    the format."""
    try:
        size = os.path.getsize(path)
        if size < 8:
            return None
        with open(path, "rb") as f:
            f.seek(-4, os.SEEK_END)
            tail = f.read(4)
    except OSError:
        return None
    if len(tail) < 4:
        return None
    if container == "gzip_xored" and key:
        tail = tail.translate(_xor_table(key))
    return struct.unpack("<I", tail)[0]


def _gzip_chunks(path: str, container: str, key: int, step: int = _STEP) -> Iterator[bytes]:
    """Decompressed chunks, bounded to at most `step` bytes per call so a
    pathological ratio can't produce an unbounded chunk. Restarts on a
    concatenated gzip member."""
    unwrap = _make_unwrap(container, key)
    with open(path, "rb") as f:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        first = True
        while True:
            if decompressor.unconsumed_tail:
                chunk = decompressor.unconsumed_tail
            else:
                raw = f.read(_CHUNK)
                if raw:
                    chunk = unwrap(raw, first)
                    first = False
                else:
                    chunk = b""
            if not chunk:
                if decompressor.unused_data:
                    chunk = decompressor.unused_data
                    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                else:
                    break
            try:
                data = decompressor.decompress(chunk, step)
            except zlib.error:
                return
            if data:
                yield data
        tail = decompressor.flush()
        if tail:
            yield tail


def probe_gzip(path: str, container: str, options: ScanOptions, result: Any) -> None:
    result.container = container
    result.kind = "unknown"

    try:
        with open(path, "rb") as f:
            prefix = f.read(16)
    except OSError as exc:
        result.errors.append({"stage": "archive", "message": str(exc)})
        return

    key = (prefix[0] ^ 0xC8) if (container == "gzip_xored" and prefix) else 0

    def unwrap(chunk: bytes, first: bool) -> bytes:
        if container != "gzip_xored":
            return chunk
        if first:
            chunk = chunk[1:]
        if not key:
            return chunk
        return chunk.translate(_xor_table(key))

    header_src = unwrap(prefix, True)
    gz_header = _parse_gzip_header(header_src)
    if gz_header:
        result.probe["gzip"] = gz_header

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    inflated = bytearray()
    cap = GZIP_PROBE_CAP
    reached_cap = False
    try:
        with open(path, "rb") as f:
            first = True
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                chunk = unwrap(chunk, first)
                first = False
                remaining = cap - len(inflated)
                if remaining <= 0:
                    reached_cap = True
                    break
                try:
                    data = decompressor.decompress(chunk, remaining)
                except zlib.error as exc:
                    result.errors.append({"stage": "archive", "message": f"inflate: {exc}"})
                    break
                inflated += data
                if decompressor.unconsumed_tail:
                    reached_cap = True
                    break
                if decompressor.eof:
                    # Classification needs only the first gzip member. A file
                    # that merely starts with one (an X3 .dat whose first entry
                    # is packed) must not be read to its end.
                    break
    except OSError as exc:
        result.errors.append({"stage": "archive", "message": str(exc)})

    truncated = reached_cap or len(inflated) >= cap
    if truncated:
        result.probe["inflate_truncated"] = True
    if inflated:
        inflated_bytes = bytes(inflated)
        _classify_inflated(inflated_bytes, result)
        name = os.path.basename(path)
        if suffix_of(name) == "pck":
            from . import pck
            pck.refine_x3_pck(name, inflated_bytes, truncated, result)
        if tarball.detect(inflated_bytes):
            make_chunks = functools.partial(_gzip_chunks, container=container, key=key)
            _list_embedded_tar(path, container, make_chunks, options, result)

    original_name = _gzip_original_name(path, container, key)
    if original_name:
        result.probe.setdefault("gzip", {})["original_name"] = original_name
    isize = _gzip_trailer_isize(path, container, key)
    if isize is not None:
        result.probe.setdefault("gzip", {})["original_size"] = isize


def _classify_inflated(data: bytes, result: Any) -> None:
    save = x3.sniff_save(data)
    if save:
        result.kind = save.pop("kind")
        result.probe.update(save)
        return
    hit = images.sniff(data) or x3.sniff_bob1(data) or media.sniff(data)
    if hit:
        result.kind = hit.pop("kind")
        result.probe.update(hit)
        return
    window = data[: min(len(data), 8192)]
    if b"\x00" not in window:
        enc, decoded = text.detect_encoding(data)
        result.encoding = enc
        result.newlines = text.classify_newlines(decoded)
        sample, truncated = text.make_sample(decoded)
        result.sample = sample
        result.sample_truncated = truncated
        result.kind = "text"


# --- shared: tar embedded in a decompressed stream ------------------------

def _list_embedded_tar(path: str, container: str,
                        make_chunks: Callable[..., Iterator[bytes]],
                        options: ScanOptions, result: Any) -> None:
    """Walk a tar found inside a compressed stream (gzip/bzip2/xz), up to
    options.archive_scan_cap decompressed bytes, or to the end with
    --deep-archives. Never keeps member data; only a rolling decompression
    buffer."""
    cap = None if options.deep_archives else options.archive_scan_cap
    src = tarball.StreamSource(make_chunks(path, step=_STEP), cap)
    rows, truncated = tarball.walk(src, max_members=options.max_members)

    result.kind = "archive"
    result.container = container
    result.probe["format"] = "tar"
    capped_rows = rows[: options.max_members]
    result.members = capped_rows
    if src.hit_cap:
        truncated = True
        result.probe["scan_stopped_at"] = src.consumed
    result.probe.update(members.summarize(capped_rows, truncated=truncated,
                                           list_cap=options.list_zip_cap))


def _classify_and_maybe_tar(path: str, container: str,
                             make_chunks: Callable[..., Iterator[bytes]],
                             options: ScanOptions, result: Any) -> None:
    """Shared bzip2/xz path: decompress up to GZIP_PROBE_CAP to classify the
    content (same rule as gzip), then, if it's a tar, list it up to
    archive_scan_cap / to the end."""
    cap = GZIP_PROBE_CAP
    inflated = bytearray()
    reached_cap = False
    try:
        for chunk in make_chunks(path, step=min(_STEP, cap)):
            remaining = cap - len(inflated)
            if remaining <= 0:
                reached_cap = True
                break
            inflated += chunk[:remaining]
            if len(chunk) > remaining:
                reached_cap = True
                break
    except OSError as exc:
        result.errors.append({"stage": "archive", "message": str(exc)})

    if reached_cap:
        result.probe["inflate_truncated"] = True

    inflated_bytes = bytes(inflated)
    if inflated_bytes:
        _classify_inflated(inflated_bytes, result)
        if tarball.detect(inflated_bytes):
            _list_embedded_tar(path, container, make_chunks, options, result)


# --- bzip2 -----------------------------------------------------------------

def detect_bzip2(head: bytes) -> bool:
    """'BZh' + block size digit (1-9) + the block magic pi digits."""
    if len(head) < 10 or head[:3] != b"BZh":
        return False
    if not (0x31 <= head[3] <= 0x39):
        return False
    return head[4:10] == b"\x31\x41\x59\x26\x53\x59"


def _bz2_chunks(path: str, step: int = _STEP) -> Iterator[bytes]:
    """Decompressed chunks, bounded to `step` bytes per call. Restarts on a
    concatenated bzip2 stream. bzip2 carries no uncompressed-size field, so
    there is nothing to report without decompressing."""
    with open(path, "rb") as f:
        decomp = bz2.BZ2Decompressor()
        pending = b""
        while True:
            if decomp.eof:
                if not decomp.unused_data:
                    break
                pending, decomp = decomp.unused_data, bz2.BZ2Decompressor()
            if pending:
                chunk, pending = pending, b""
            elif decomp.needs_input:
                chunk = f.read(_CHUNK)
                if not chunk:
                    if decomp.eof:
                        continue
                    break
            else:
                chunk = b""
            try:
                data = decomp.decompress(chunk, step)
            except OSError as exc:
                return
            if data:
                yield data
            while not decomp.needs_input and not decomp.eof:
                try:
                    data = decomp.decompress(b"", step)
                except OSError:
                    return
                if data:
                    yield data


def probe_bzip2(path: str, head: bytes, options: ScanOptions, result: Any) -> None:
    result.container = "bzip2"
    result.kind = "unknown"
    _classify_and_maybe_tar(path, "bzip2", _bz2_chunks, options, result)


# --- xz ---------------------------------------------------------------

_XZ_MAGIC = b"\xfd7zXZ\x00"
_XZ_FOOTER_MAGIC = b"YZ"


def detect_xz(head: bytes) -> bool:
    """FD 37 7A 58 5A 00."""
    return head[:6] == _XZ_MAGIC


def _read_vint(data: bytes, pos: int) -> tuple[int, int]:
    """xz multibyte integer: little-endian base-128, high bit = more bytes."""
    result = 0
    for i in range(9):
        if pos + i >= len(data):
            raise ValueError("truncated vint")
        b = data[pos + i]
        result |= (b & 0x7F) << (7 * i)
        if not (b & 0x80):
            return result, pos + i + 1
    raise ValueError("vint too long")


def _parse_xz_index(path: str) -> dict[str, Any] | None:
    """Uncompressed size and block count from the xz stream footer + index,
    without decompressing anything. None on anything unexpected."""
    try:
        size = os.path.getsize(path)
        if size < 32:
            return None
        with open(path, "rb") as f:
            f.seek(-12, os.SEEK_END)
            footer = f.read(12)
            if len(footer) != 12 or footer[10:12] != _XZ_FOOTER_MAGIC:
                return None
            backward_size_field = struct.unpack_from("<I", footer, 4)[0]
            index_size = (backward_size_field + 1) * 4
            index_start = size - 12 - index_size
            if index_start < len(_XZ_MAGIC):
                return None
            f.seek(index_start)
            index_data = f.read(index_size)
    except OSError:
        return None
    if len(index_data) != index_size or not index_data or index_data[0] != 0x00:
        return None
    try:
        num_records, pos = _read_vint(index_data, 1)
        total_uncompressed = 0
        for _ in range(num_records):
            _unpadded, pos = _read_vint(index_data, pos)
            uncompressed, pos = _read_vint(index_data, pos)
            total_uncompressed += uncompressed
    except (ValueError, IndexError):
        return None
    return {"uncompressed_size": total_uncompressed, "block_count": num_records}


def _xz_chunks(path: str, step: int = _STEP) -> Iterator[bytes]:
    """Decompressed chunks, bounded to `step` bytes per call. Restarts on a
    concatenated xz stream."""
    with open(path, "rb") as f:
        decomp = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        pending = b""
        while True:
            if decomp.eof:
                if not decomp.unused_data:
                    break
                pending = decomp.unused_data
                decomp = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            if pending:
                chunk, pending = pending, b""
            elif not decomp.needs_input:
                chunk = b""
            else:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
            try:
                data = decomp.decompress(chunk, step)
            except lzma.LZMAError:
                return
            if data:
                yield data
            while not decomp.needs_input and not decomp.eof:
                try:
                    data = decomp.decompress(b"", step)
                except lzma.LZMAError:
                    return
                if data:
                    yield data


def probe_xz(path: str, head: bytes, options: ScanOptions, result: Any) -> None:
    result.container = "xz"
    result.kind = "unknown"
    try:
        index = _parse_xz_index(path)
    except Exception:
        index = None
    if index:
        result.probe["xz"] = index
    _classify_and_maybe_tar(path, "xz", _xz_chunks, options, result)
