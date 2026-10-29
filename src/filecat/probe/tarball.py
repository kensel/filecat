"""Plain tar: walk 512-byte headers, seeking past member data. Also used by
archive.probe_gzip / probe_bzip2 / probe_xz to list a tar found inside a
decompressed stream, without ever buffering a whole member's payload.

ustar (POSIX) and GNU tar headers are supported, including GNU long name
('L') / long linkname ('K') extensions and PAX extended headers ('x' for the
next entry, 'g' for a block of following entries). GNU base-256 size/mtime
encoding is handled. Old V7 tar (no "ustar" magic) is accepted when the
header checksum validates.

See file-catalog-requirements.md, "Probe order" step 5b (tar) and
"Archives, images, models, data".
"""
from __future__ import annotations

from typing import Any, Iterator

from ..options import ScanOptions
from ..fsource import fopen
from . import members

_BLOCK = 512

_USTAR_MAGIC6 = b"ustar\x00"
_INT64 = 2 ** 63
_GNU_MAGIC8 = b"ustar  \x00"

# file/dir/symlink/hardlink are the four the catalog record cares about;
# chardev/blockdev/fifo are real tar types we still report rather than drop.
_TYPE_MAP = {
    b"0": "file", b"\x00": "file", b"7": "file",
    b"1": "hardlink",
    b"2": "symlink",
    b"3": "chardev",
    b"4": "blockdev",
    b"5": "dir",
    b"6": "fifo",
}


# V7 numeric fields: mode, uid, gid, size, mtime, chksum.
_V7_NUMERIC = ((100, 108), (108, 116), (116, 124), (124, 136), (136, 148), (148, 156))
_OCTAL_BYTES = frozenset(b"01234567 \x00")


def _v7_fields_valid(block: bytes) -> bool:
    """Every numeric field is ASCII octal (spaces/NULs as padding), the
    checksum is present and the name is non-empty. A checksum alone matches random bytes about once in
    a few thousand files -- on a NAS that is a real false positive (a
    damaged PNG was once "listed" as a tar of garbage)."""
    if block[0] == 0:
        return False
    for a, b in _V7_NUMERIC:
        field = block[a:b]
        if not set(field) <= _OCTAL_BYTES:
            return False
    return bool(block[148:156].strip(b" \x00"))


def detect(head: bytes) -> bool:
    """'ustar' magic at offset 257 (POSIX or GNU), or a V7 header whose
    numeric fields are octal and whose checksum validates."""
    if len(head) < 265:
        return False
    if head[257:263] == _USTAR_MAGIC6 or head[257:265] == _GNU_MAGIC8:
        return True
    if len(head) >= _BLOCK:
        return _v7_fields_valid(head[:_BLOCK]) and _checksum_valid(head[:_BLOCK])
    return False


def probe_tar(path: str, head: bytes, options: ScanOptions, result: Any) -> None:
    """Plain (uncompressed) tar on disk: list members by seeking past each
    member's data instead of reading it."""
    result.kind = "archive"
    result.container = "plain"
    result.probe["format"] = "tar"
    try:
        with fopen(path, "rb") as f:
            src = FileSource(f)
            rows, truncated = walk(src, max_members=options.max_members)
    except OSError as exc:
        result.errors.append({"stage": "tar", "message": str(exc)})
        return
    result.members = rows[: options.max_members]
    result.probe.update(members.summarize(result.members, truncated=truncated,
                                           list_cap=options.list_zip_cap))


# --- sources ----------------------------------------------------------
# `walk()` is shared between a seekable on-disk tar (FileSource -- skipping
# member data costs nothing) and a non-seekable decompressed stream
# (StreamSource -- skipping member data means reading and discarding it,
# which counts against a byte budget so a hostile archive can't force an
# unbounded decompression).

class FileSource:
    """Wraps an open binary file. No cap: seeking is free."""

    def __init__(self, f: Any) -> None:
        self.f = f
        self.consumed = 0

    def read(self, n: int) -> bytes:
        data = self.f.read(n)
        self.consumed += len(data)
        return data

    def skip(self, n: int) -> None:
        if n <= 0:
            return
        self.f.seek(n, 1)
        self.consumed += n

    @property
    def hit_cap(self) -> bool:
        return False


class StreamSource:
    """Pulls from a lazy iterator of decompressed chunks, bounded by `cap`
    bytes of decompressed output (None = unbounded, i.e. --deep-archives).

    Keeps only a small rolling buffer -- member data is read in order to
    skip past it (the stream can't seek) but is never retained.
    """

    def __init__(self, chunks: Iterator[bytes], cap: int | None) -> None:
        self._it = iter(chunks)
        self._buf = b""
        self.consumed = 0
        self.cap = cap
        self.hit_cap = False

    def _fill(self, n: int) -> None:
        while len(self._buf) < n and not self.hit_cap:
            try:
                chunk = next(self._it)
            except StopIteration:
                return
            if chunk:
                self._buf += chunk

    def read(self, n: int) -> bytes:
        if self.cap is not None and self.consumed >= self.cap:
            self.hit_cap = True
            return b""
        self._fill(n)
        data, self._buf = self._buf[:n], self._buf[n:]
        self.consumed += len(data)
        if self.cap is not None and self.consumed >= self.cap:
            self.hit_cap = True
        return data

    def skip(self, n: int) -> None:
        remaining = n
        while remaining > 0:
            if self.cap is not None and self.consumed >= self.cap:
                self.hit_cap = True
                return
            chunk = self.read(min(remaining, 1 << 16))
            if not chunk:
                return
            remaining -= len(chunk)


# --- header parsing -----------------------------------------------------

def _octal(field: bytes) -> int:
    s = field.rstrip(b"\x00 ").lstrip(b" ")
    if not s:
        return 0
    try:
        return int(s, 8)
    except ValueError:
        return 0


def _numeric_field(field: bytes) -> int:
    """Octal, or GNU base-256 when the first byte's high bit is set."""
    if field and field[0] & 0x80:
        n = field[0] & 0x7F
        for b in field[1:]:
            n = (n << 8) | b
        return n
    return _octal(field)


def _checksum_valid(block: bytes) -> bool:
    if len(block) < _BLOCK or block == b"\x00" * _BLOCK:
        return False
    recorded = _octal(block[148:156])
    data = bytearray(block[:_BLOCK])
    data[148:156] = b" " * 8
    unsigned_sum = sum(data)
    signed_sum = sum((b if b < 128 else b - 256) for b in data)
    return recorded in (unsigned_sum, signed_sum)


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _parse_block(block: bytes) -> dict[str, Any]:
    name = _cstr(block[0:100])
    prefix = _cstr(block[345:500])
    full_name = f"{prefix}/{name}" if prefix else name
    return {
        "name": full_name,
        "mode": _octal(block[100:108]),
        "size": _numeric_field(block[124:136]),
        "mtime": _numeric_field(block[136:148]),
        "typeflag": block[156:157],
        "linkname": _cstr(block[157:257]),
    }


def _parse_pax(data: bytes) -> dict[str, str]:
    """PAX extended header records: '<len> key=value\\n', length-prefixed."""
    out: dict[str, str] = {}
    pos = 0
    n = len(data)
    while pos < n:
        sp = data.find(b" ", pos)
        if sp == -1:
            break
        try:
            length = int(data[pos:sp])
        except ValueError:
            break
        if length <= 0 or pos + length > n:
            break
        record = data[pos:pos + length]
        eq = record.find(b"=")
        if eq != -1:
            key = record[sp - pos + 1:eq].decode("utf-8", errors="replace")
            value = record[eq + 1:-1].decode("utf-8", errors="replace")
            out[key] = value
        pos += length
    return out


def _padded(size: int) -> int:
    return (size + _BLOCK - 1) // _BLOCK * _BLOCK


def walk(src: Any, *, max_members: int) -> tuple[list[dict[str, Any]], bool]:
    """Walk tar headers from `src` (FileSource or StreamSource).

    Returns (rows, truncated). `truncated` means rows were cut by
    max_members with more remaining, or (StreamSource only) the decompressed
    byte cap stopped the walk before a clean end-of-archive.
    """
    rows: list[dict[str, Any]] = []
    index = 0
    pending_name: str | None = None
    pending_linkname: str | None = None
    pending_pax: dict[str, str] = {}
    pax_global: dict[str, str] = {}
    zero_blocks = 0
    truncated = False

    while True:
        if src.hit_cap:
            truncated = True
            break
        offset = src.consumed
        block = src.read(_BLOCK)
        if len(block) < _BLOCK:
            break
        if block == b"\x00" * _BLOCK:
            zero_blocks += 1
            if zero_blocks >= 2:
                break
            continue
        zero_blocks = 0
        if not _checksum_valid(block):
            break
        hdr = _parse_block(block)
        typeflag = hdr["typeflag"]
        data_size = hdr["size"]
        padded = _padded(data_size)

        if typeflag == b"L":
            data = src.read(padded)
            pending_name = data[:data_size].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            if src.hit_cap:
                truncated = True
                break
            continue
        if typeflag == b"K":
            data = src.read(padded)
            pending_linkname = data[:data_size].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            if src.hit_cap:
                truncated = True
                break
            continue
        if typeflag in (b"x", b"g"):
            data = src.read(padded)
            kv = _parse_pax(data[:data_size])
            if typeflag == b"g":
                pax_global.update(kv)
            else:
                pending_pax = kv
            if src.hit_cap:
                truncated = True
                break
            continue

        name = pending_name or hdr["name"]
        linkname = pending_linkname or hdr["linkname"]
        size = data_size
        merged_pax = {**pax_global, **pending_pax}
        if "path" in merged_pax:
            name = merged_pax["path"]
        if "linkpath" in merged_pax:
            linkname = merged_pax["linkpath"]
        if "size" in merged_pax:
            try:
                size = int(float(merged_pax["size"]))
            except ValueError:
                pass
        mtime_ns: int | None = None
        if "mtime" in merged_pax:
            try:
                mtime_ns = int(float(merged_pax["mtime"]) * 1_000_000_000)
            except ValueError:
                mtime_ns = None
        if mtime_ns is None:
            mtime_ns = hdr["mtime"] * 1_000_000_000
        if not -_INT64 <= mtime_ns < _INT64:
            mtime_ns = None  # a corrupt base-256 field; no real file has it

        pending_name = None
        pending_linkname = None
        pending_pax = {}

        norm_name = name.replace("\\", "/")
        row: dict[str, Any] = {
            "index": index,
            "path": norm_name,
            "size": size,
            "mtime_ns": mtime_ns,
            "mode": hdr["mode"],
            "type": _TYPE_MAP.get(typeflag, "file"),
            "offset": offset,
            "role": members.member_role(norm_name),
        }
        if linkname:
            row["link_target"] = linkname
        rows.append(row)
        index += 1

        src.skip(_padded(size))
        if src.hit_cap:
            truncated = True
            break

        if len(rows) >= max_members:
            nxt = src.read(_BLOCK)
            if len(nxt) < _BLOCK or nxt == b"\x00" * _BLOCK:
                truncated = False
            else:
                truncated = True
            break

    return rows, truncated
