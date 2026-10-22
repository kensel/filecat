"""MPQ (Blizzard) archives: header, hash/block tables, (listfile) names.

Reads the header, both tables, and the (listfile) member only -- never the
other members' bytes. See file-catalog-requirements.md and the MoPaQ format
description (Justin Olbrantz / Ladislav Zezula) for the on-disk layout this
module parses.
"""
from __future__ import annotations

import bz2
import struct
import zlib
from typing import Any

from ..options import ScanOptions
from . import members as members_mod

_MPQ_MAGIC = b"MPQ\x1a"
_MPQ_USERDATA_MAGIC = b"MPQ\x1b"

# -- MPQ file-block flags ---------------------------------------------------
_MPQ_FILE_IMPLODE = 0x00000100
_MPQ_FILE_COMPRESS = 0x00000200
_MPQ_FILE_ENCRYPTED = 0x00010000
_MPQ_FILE_FIX_KEY = 0x00020000
_MPQ_FILE_SINGLE_UNIT = 0x01000000
_MPQ_FILE_SECTOR_CRC = 0x04000000
_MPQ_FILE_EXISTS = 0x80000000

_HASH_ENTRY_EMPTY = 0xFFFFFFFF
_HASH_ENTRY_DELETED = 0xFFFFFFFE

# Hash types, used both to pick a crypt-table quadrant and to key tables/files.
_HASH_TABLE_OFFSET = 0
_HASH_NAME_A = 1
_HASH_NAME_B = 2
_HASH_FILE_KEY = 3

_HEADER_V1_SIZE = 32
_HEADER_V4_SIZE = 208

# A single-call PKWARE DCL explode is pure Python; cap the input so a
# pathological or misread compressed size can't spin forever.
_IMPLODE_CSIZE_CAP = 4 * 1024 * 1024
# Refuse to even attempt reading a (listfile) this large; it is always a
# small text file in every known MPQ, so a huge csize means we mis-parsed
# the tables rather than found a genuinely huge listfile.
_LISTFILE_CSIZE_CAP = 32 * 1024 * 1024


def detect(head: bytes) -> bool:
    """'MPQ\x1a' archive header or 'MPQ\x1b' user-data header."""
    return head[:4] in (_MPQ_MAGIC, _MPQ_USERDATA_MAGIC)


# ---------------------------------------------------------------------------
# MPQ crypto: one shared 0x500-entry table, seeded with 0x00100001. Every
# name hash and every table/file decryption key is derived from it.
# ---------------------------------------------------------------------------

def _build_crypt_table() -> list[int]:
    seed = 0x00100001
    table = [0] * 0x500
    for index1 in range(0x100):
        index2 = index1
        for _ in range(5):
            seed = (seed * 125 + 3) % 0x2AAAAB
            temp1 = (seed & 0xFFFF) << 0x10
            seed = (seed * 125 + 3) % 0x2AAAAB
            temp2 = seed & 0xFFFF
            table[index2] = temp1 | temp2
            index2 += 0x100
    return table


_CRYPT_TABLE = _build_crypt_table()


def _hash_string(s: str, hash_type: int) -> int:
    seed1 = 0x7FED7FED
    seed2 = 0xEEEEEEEE
    for ch in s.upper():
        code = ord(ch) & 0xFF
        value = _CRYPT_TABLE[(hash_type << 8) + code]
        seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
        seed2 = (code + seed1 + seed2 + (seed2 << 5) + 3) & 0xFFFFFFFF
    return seed1


def _decrypt(data: bytes, key: int) -> bytes:
    """Decrypt a byte string that is a whole number of dwords (padded if not)."""
    pad = (-len(data)) % 4
    padded = data + b"\x00" * pad
    count = len(padded) // 4
    if count == 0:
        return data
    values = struct.unpack(f"<{count}I", padded)
    seed1 = key & 0xFFFFFFFF
    seed2 = 0xEEEEEEEE
    out = []
    for value in values:
        seed2 = (seed2 + _CRYPT_TABLE[0x400 + (seed1 & 0xFF)]) & 0xFFFFFFFF
        decrypted = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
        seed1 = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B)
        seed1 &= 0xFFFFFFFF
        seed2 = (decrypted + seed2 + (seed2 << 5) + 3) & 0xFFFFFFFF
        out.append(decrypted)
    result = struct.pack(f"<{count}I", *out)
    return result[: len(data)]


def _file_key(name: str, flags: int, file_pos: int, size: int) -> int:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    key = _hash_string(base, _HASH_FILE_KEY)
    if flags & _MPQ_FILE_FIX_KEY:
        key = ((key + file_pos) ^ size) & 0xFFFFFFFF
    return key


# ---------------------------------------------------------------------------
# PKWARE Data Compression Library "explode" (the "implode" method, mask bit
# 0x08). Ported from Mark Adler's public-domain blast.c (zlib contrib,
# "blast", v1.3), which decompresses the same format used by the MPQ,
# ancient PKZIP, and PKWare DCL. Verified against blast.c's own worked
# example: bytes `00 04 82 24 25 8f 80 7f` explode to "AIAIAIAIAIAIA".
# ---------------------------------------------------------------------------

_MAXBITS = 13


class ImplodeError(Exception):
    pass


class _BitReader:
    __slots__ = ("data", "pos", "bitbuf", "bitcnt")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.bitbuf = 0
        self.bitcnt = 0

    def bits(self, need: int) -> int:
        val = self.bitbuf
        cnt = self.bitcnt
        while cnt < need:
            if self.pos >= len(self.data):
                raise ImplodeError("ran out of input")
            val |= self.data[self.pos] << cnt
            self.pos += 1
            cnt += 8
        self.bitbuf = val >> need
        self.bitcnt = cnt - need
        return val & ((1 << need) - 1)


def _construct(rep: bytes) -> tuple[list[int], list[int]]:
    """Expand a compacted (count<<4 | length) byte list into canonical
    Huffman count/symbol tables (see blast.c's `construct`)."""
    length: list[int] = []
    for byte in rep:
        repeat = (byte >> 4) + 1
        ln = byte & 0x0F
        length.extend([ln] * repeat)
    n = len(length)
    count = [0] * (_MAXBITS + 1)
    for ln in length:
        count[ln] += 1
    if count[0] == n:
        return count, []
    left = 1
    for ln in range(1, _MAXBITS + 1):
        left <<= 1
        left -= count[ln]
        if left < 0:
            raise ImplodeError("over-subscribed Huffman table")
    offs = [0] * (_MAXBITS + 2)
    for ln in range(1, _MAXBITS):
        offs[ln + 1] = offs[ln] + count[ln]
    symbol = [0] * n
    for sym, ln in enumerate(length):
        if ln != 0:
            symbol[offs[ln]] = sym
            offs[ln] += 1
    return count, symbol


def _decode(br: _BitReader, count: list[int], symbol: list[int]) -> int:
    code = first = index = 0
    for length in range(1, _MAXBITS + 1):
        code |= br.bits(1) ^ 1
        cnt = count[length]
        if code < first + cnt:
            return symbol[index + (code - first)]
        index += cnt
        first += cnt
        first <<= 1
        code <<= 1
    raise ImplodeError("ran out of codes")


# Fixed tables from blast.c: compacted bit lengths for the literal, length
# and distance Huffman codes used by the PKWare Compression Library format.
_LITLEN = bytes([
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8,
    9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5,
    7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12,
    8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27,
    44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45,
    44, 173,
])
_LENLEN = bytes([2, 35, 36, 53, 38, 23])
_DISTLEN = bytes([2, 20, 53, 230, 247, 151, 248])
_LEN_BASE = (3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264)
_LEN_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8)

_LITCOUNT, _LITSYMBOL = _construct(_LITLEN)
_LENCOUNT, _LENSYMBOL = _construct(_LENLEN)
_DISTCOUNT, _DISTSYMBOL = _construct(_DISTLEN)


def explode(data: bytes, max_output: int) -> bytes:
    """PKWARE DCL "implode" decompression (StormLib/MPQ compression type 0x08)."""
    br = _BitReader(data)
    lit = br.bits(8)
    if lit > 1:
        raise ImplodeError("bad literal-coded flag")
    dict_bits = br.bits(8)
    if dict_bits < 4 or dict_bits > 6:
        raise ImplodeError("bad dictionary size byte")
    out = bytearray()
    # MPQ sector streams usually carry no end code: the reader stops once the
    # expected output size is reached. max_output is that size.
    while len(out) < max_output:
        if br.bits(1):
            symbol = _decode(br, _LENCOUNT, _LENSYMBOL)
            length = _LEN_BASE[symbol] + br.bits(_LEN_EXTRA[symbol])
            if length == 519:
                break
            dist_bits = 2 if length == 2 else dict_bits
            dsym = _decode(br, _DISTCOUNT, _DISTSYMBOL)
            dist = (dsym << dist_bits) + br.bits(dist_bits) + 1
            if dist > len(out):
                raise ImplodeError("copy distance precedes start of output")
            start = len(out) - dist
            for i in range(length):
                out.append(out[start + i])
        else:
            symbol = _decode(br, _LITCOUNT, _LITSYMBOL) if lit else br.bits(8)
            out.append(symbol)
    return bytes(out[:max_output])


def _safe_explode(body: bytes, cap: int) -> bytes:
    if len(body) > _IMPLODE_CSIZE_CAP:
        raise ImplodeError(f"PKWARE implode input too large to probe ({len(body)} bytes)")
    return explode(body, cap)


def _decompress_sector(data: bytes, uncompressed_cap: int) -> bytes:
    """One MPQ_FILE_COMPRESS sector/block: the first byte selects the method."""
    if not data:
        return data
    method = data[0]
    body = data[1:]
    if method == 0x00:
        return body
    if method == 0x02:
        return zlib.decompress(body, 15)
    if method == 0x10:
        return bz2.decompress(body)
    if method == 0x08:
        return _safe_explode(body, uncompressed_cap)
    raise ValueError(f"unsupported MPQ sector compression 0x{method:02x}")


# ---------------------------------------------------------------------------
# Header, hash table, block table
# ---------------------------------------------------------------------------

def _resolve_header_offset(f: Any) -> int | None:
    f.seek(0)
    magic = f.read(4)
    if magic == _MPQ_MAGIC:
        return 0
    if magic == _MPQ_USERDATA_MAGIC:
        rest = f.read(12)
        if len(rest) < 12:
            return None
        _user_data_size, header_offset, _user_header_size = struct.unpack("<III", rest)
        f.seek(header_offset)
        if f.read(4) != _MPQ_MAGIC:
            return None
        return header_offset
    return None


def _read_header(f: Any, header_offset: int) -> dict[str, Any]:
    f.seek(header_offset)
    base = f.read(_HEADER_V1_SIZE)
    if len(base) < _HEADER_V1_SIZE or base[:4] != _MPQ_MAGIC:
        raise ValueError("bad MPQ header")
    (_magic, header_size, archive_size, fmt_version, sector_shift,
     hash_pos, block_pos, hash_entries, block_entries) = struct.unpack("<4sIIHHIIII", base)

    header: dict[str, Any] = {
        "header_size": header_size,
        "format_version": fmt_version,
        "sector_size": 512 << sector_shift,
        "archive_size": archive_size,
        "hash_table_pos": hash_pos,
        "block_table_pos": block_pos,
        "hash_table_entries": hash_entries,
        "block_table_entries": block_entries,
        "hi_block_table_pos": 0,
    }
    if fmt_version >= 1 and header_size >= 44:
        f.seek(header_offset + 32)
        extra = f.read(12)
        if len(extra) == 12:
            hi_block_pos, hash_pos_hi, block_pos_hi = struct.unpack("<QHH", extra)
            header["hi_block_table_pos"] = hi_block_pos
            header["hash_table_pos"] = hash_pos | (hash_pos_hi << 32)
            header["block_table_pos"] = block_pos | (block_pos_hi << 32)
    if fmt_version >= 2 and header_size >= 68:
        f.seek(header_offset + 44)
        extra = f.read(24)
        if len(extra) == 24:
            archive_size64, bet_pos, het_pos = struct.unpack("<QQQ", extra)
            if archive_size64:
                header["archive_size"] = archive_size64
            header["bet_table_pos"] = bet_pos
            header["het_table_pos"] = het_pos
    if fmt_version >= 3 and header_size >= _HEADER_V4_SIZE:
        f.seek(header_offset + 68)
        extra = f.read(_HEADER_V4_SIZE - 68)
        if len(extra) >= 44:
            (hash_size64, block_size64, hi_block_size64, het_size64,
             bet_size64, raw_chunk_size) = struct.unpack("<QQQQQI", extra[:44])
            header["v4"] = {
                "hash_table_compressed_size": hash_size64,
                "block_table_compressed_size": block_size64,
                "hi_block_table_size": hi_block_size64,
                "het_table_size": het_size64,
                "bet_table_size": bet_size64,
                "raw_chunk_size": raw_chunk_size,
            }
    return header


def _read_table(f: Any, header_offset: int, table_pos: int, entries: int, name: str) -> bytes:
    if entries <= 0:
        return b""
    length = entries * 16
    f.seek(header_offset + table_pos)
    raw = f.read(length)
    if len(raw) < length:
        raise ValueError(f"{name} table truncated ({len(raw)} of {length} bytes)")
    key = _hash_string(f"({name})", _HASH_FILE_KEY)
    return _decrypt(raw, key)


def _parse_hash_table(raw: bytes, entries: int) -> list[dict[str, int]]:
    out = []
    for i in range(entries):
        chunk = raw[i * 16:(i + 1) * 16]
        if len(chunk) < 16:
            break
        name1, name2, locale, platform, block_index = struct.unpack("<IIHHI", chunk)
        out.append({"name1": name1, "name2": name2, "locale": locale,
                    "platform": platform, "block_index": block_index})
    return out


def _parse_block_table(raw: bytes, entries: int) -> list[dict[str, int]]:
    out = []
    for i in range(entries):
        chunk = raw[i * 16:(i + 1) * 16]
        if len(chunk) < 16:
            break
        file_pos, csize, size, flags = struct.unpack("<IIII", chunk)
        out.append({"file_pos": file_pos, "csize": csize, "size": size, "flags": flags})
    return out


def _apply_hi_block_table(f: Any, header_offset: int, header: dict[str, Any],
                           blocks: list[dict[str, int]]) -> None:
    pos = header.get("hi_block_table_pos") or 0
    if not pos or not blocks:
        return
    n = len(blocks)
    f.seek(header_offset + pos)
    raw = f.read(n * 2)
    if len(raw) < n * 2:
        return
    his = struct.unpack(f"<{n}H", raw)
    for block, hi in zip(blocks, his):
        if hi:
            block["file_pos"] |= hi << 32


def _find_hash_entry(hash_entries: list[dict[str, int]], name: str, table_entries: int) -> int | None:
    if not hash_entries or table_entries <= 0:
        return None
    mask = table_entries - 1
    start = _hash_string(name, _HASH_TABLE_OFFSET) & mask
    name1 = _hash_string(name, _HASH_NAME_A)
    name2 = _hash_string(name, _HASH_NAME_B)
    for step in range(table_entries):
        idx = (start + step) % table_entries
        entry = hash_entries[idx]
        if entry["block_index"] == _HASH_ENTRY_EMPTY:
            return None
        if entry["block_index"] == _HASH_ENTRY_DELETED:
            continue
        if entry["name1"] == name1 and entry["name2"] == name2:
            return idx
    return None


def _read_member_bytes(f: Any, header_offset: int, name: str, block: dict[str, int],
                        sector_size: int) -> tuple[bytes | None, str | None]:
    """Read and fully decompress one member's bytes (used only for (listfile))."""
    flags = block["flags"]
    if not (flags & _MPQ_FILE_EXISTS):
        return None, "block does not exist"
    size = block["size"]
    csize = block["csize"]
    if size == 0 or csize == 0:
        return b"", None
    if csize > _LISTFILE_CSIZE_CAP:
        return None, f"(listfile) too large to probe ({csize} bytes)"

    abs_offset = header_offset + block["file_pos"]
    try:
        f.seek(abs_offset)
        raw = f.read(csize)
    except OSError as exc:
        return None, str(exc)
    if len(raw) < csize:
        return None, f"truncated read at {abs_offset} ({len(raw)} of {csize} bytes)"

    key = None
    if flags & _MPQ_FILE_ENCRYPTED:
        key = _file_key(name, flags, block["file_pos"], size)

    has_compress = bool(flags & _MPQ_FILE_COMPRESS)
    has_implode_only = bool(flags & _MPQ_FILE_IMPLODE) and not has_compress
    should_decompress = (has_compress and size > csize) or has_implode_only

    def decompress_one(chunk: bytes, cap: int) -> bytes:
        if has_compress:
            return _decompress_sector(chunk, cap)
        return _safe_explode(chunk, cap)

    try:
        if flags & _MPQ_FILE_SINGLE_UNIT:
            data = raw
            if key is not None:
                data = _decrypt(data, key)
            if should_decompress:
                data = decompress_one(data, size)
            return bytes(data[:size]), None

        sector_count = -(-size // sector_size) if size else 0
        has_crc = bool(flags & _MPQ_FILE_SECTOR_CRC)
        table_entries = sector_count + 1 + (1 if has_crc else 0)
        table_raw = raw[: 4 * table_entries]
        if key is not None and len(table_raw) == 4 * table_entries:
            table_raw = _decrypt(table_raw, (key - 1) & 0xFFFFFFFF)
        if len(table_raw) < 4 * (sector_count + 1):
            return None, "truncated sector offset table"
        offsets = struct.unpack(f"<{table_entries}I", table_raw)

        out = bytearray()
        for i in range(sector_count):
            start, end = offsets[i], offsets[i + 1]
            if end < start or end > len(raw):
                return None, f"bad sector {i} offsets ({start}, {end})"
            chunk = raw[start:end]
            if key is not None:
                chunk = _decrypt(chunk, (key + i) & 0xFFFFFFFF)
            if should_decompress:
                remaining = size - len(out)
                cap = min(sector_size, remaining) if remaining > 0 else sector_size
                chunk = decompress_one(chunk, cap)
            out += chunk
        return bytes(out[:size]), None
    except ImplodeError as exc:
        return None, f"(listfile) uses PKWARE implode compression: {exc}"
    except (zlib.error, OSError, ValueError) as exc:
        return None, f"(listfile) decompress failed: {exc}"


def probe_mpq(path: str, head: bytes, options: ScanOptions, result: Any) -> None:
    result.kind = "archive"
    result.container = "unknown"
    result.probe["format"] = "mpq"

    with open(path, "rb") as f:
        header_offset = _resolve_header_offset(f)
        if header_offset is None:
            result.errors.append({"stage": "mpq", "message": "no MPQ header found"})
            return

        header = _read_header(f, header_offset)
        hash_table_entries = header["hash_table_entries"]
        block_table_entries = header["block_table_entries"]

        hash_raw = _read_table(f, header_offset, header["hash_table_pos"], hash_table_entries, "hash table")
        block_raw = _read_table(f, header_offset, header["block_table_pos"], block_table_entries, "block table")
        hash_entries = _parse_hash_table(hash_raw, hash_table_entries)
        blocks = _parse_block_table(block_raw, block_table_entries)
        _apply_hi_block_table(f, header_offset, header, blocks)

        result.probe["mpq"] = {
            "format_version": header["format_version"] + 1,
            "sector_size": header["sector_size"],
            "archive_size": header["archive_size"],
            "hash_table_entries": hash_table_entries,
            "block_table_entries": len(blocks),
            "header_offset": header_offset,
        }

        listfile_idx = _find_hash_entry(hash_entries, "(listfile)", hash_table_entries)
        listfile_bytes: bytes | None = None
        listfile_found = False
        lf_err: str | None = None
        if listfile_idx is not None:
            block_index = hash_entries[listfile_idx]["block_index"]
            if 0 <= block_index < len(blocks):
                listfile_bytes, lf_err = _read_member_bytes(
                    f, header_offset, "(listfile)", blocks[block_index], header["sector_size"])
                listfile_found = lf_err is None
            else:
                lf_err = "(listfile) hash entry points at an out-of-range block"
        else:
            lf_err = "no (listfile) in the hash table"

        rows: list[dict[str, Any]] = []
        if listfile_found and listfile_bytes is not None:
            text = listfile_bytes.decode("utf-8", errors="replace")
            names = [ln.strip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
            names = [n for n in names if n]
            named_block_indices: set[int] = set()
            for i, name in enumerate(names):
                idx = _find_hash_entry(hash_entries, name, hash_table_entries)
                display_path = name.replace("\\", "/")
                if idx is not None:
                    block_index = hash_entries[idx]["block_index"]
                    if 0 <= block_index < len(blocks):
                        named_block_indices.add(block_index)
                        blk = blocks[block_index]
                        row: dict[str, Any] = {
                            "index": i,
                            "path": display_path,
                            "offset": header_offset + blk["file_pos"],
                            "flags": blk["flags"],
                            "method": _method_name(blk["flags"]),
                            "role": members_mod.member_role(display_path),
                        }
                        if blk["flags"] & _MPQ_FILE_EXISTS:
                            row["size"] = blk["size"]
                            row["csize"] = blk["csize"]
                        rows.append(row)
                        continue
                rows.append({
                    "index": i,
                    "path": display_path,
                    "role": members_mod.member_role(display_path),
                    "error": "name not found in hash table",
                })
            unnamed_blocks = sum(
                1 for bi, blk in enumerate(blocks)
                if (blk["flags"] & _MPQ_FILE_EXISTS) and bi not in named_block_indices
            )
        else:
            if lf_err:
                result.errors.append({"stage": "mpq", "message": lf_err})
            for bi, blk in enumerate(blocks):
                if blk["flags"] & _MPQ_FILE_EXISTS:
                    rows.append({
                        "index": bi,
                        "path": f"<block {bi}>",
                        "size": blk["size"],
                        "csize": blk["csize"],
                        "offset": header_offset + blk["file_pos"],
                        "flags": blk["flags"],
                        "method": _method_name(blk["flags"]),
                    })
            unnamed_blocks = len(rows)

        result.probe["mpq"]["unnamed_blocks"] = unnamed_blocks
        result.probe["mpq"]["listfile"] = listfile_found

        truncated = len(rows) > options.max_members
        result.members = rows[: options.max_members]
        result.probe.update(members_mod.summarize(result.members, truncated=truncated,
                                                    list_cap=options.list_zip_cap))


def _method_name(flags: int) -> str:
    if flags & _MPQ_FILE_IMPLODE and not flags & _MPQ_FILE_COMPRESS:
        return "implode"
    if flags & _MPQ_FILE_COMPRESS:
        return "compress"
    return "stored"
