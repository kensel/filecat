from __future__ import annotations

import hashlib
import struct

from filecat.hashing import hash_file
from filecat.options import PARTIAL_HASH_CUTOFF, PARTIAL_HASH_EDGE


def _make_sparse(path: str, size: int) -> None:
    with open(path, "wb") as f:
        if size > 0:
            f.seek(size - 1)
            f.write(b"\0")


def test_hash_auto_empty_file_omits_digest(fixture_dir):
    p = fixture_dir / "empty.bin"
    p.write_bytes(b"")
    assert hash_file(str(p), 0, 0, "auto") == {}


def test_hash_auto_small_file_full_sha256(fixture_dir):
    p = fixture_dir / "small.bin"
    content = b"hello world" * 10
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert hash_file(str(p), len(content), 0, "auto") == {"sha256": expected}


def test_hash_auto_large_file_sets_partial_not_full(fixture_dir):
    size = PARTIAL_HASH_CUTOFF + 1  # 64 MiB + 1 byte
    p = fixture_dir / "big.bin"
    _make_sparse(str(p), size)
    try:
        mtime_ns = 1234567890123456789
        result = hash_file(str(p), size, mtime_ns, "auto")
        assert "sha256" not in result
        assert "sha256_partial" in result

        with open(p, "rb") as f:
            first = f.read(PARTIAL_HASH_EDGE)
            f.seek(size - PARTIAL_HASH_EDGE)
            last = f.read(PARTIAL_HASH_EDGE)
        h = hashlib.sha256()
        h.update(first)
        h.update(last)
        h.update(struct.pack(">Q", size))
        h.update(struct.pack(">q", mtime_ns))
        assert result["sha256_partial"] == h.hexdigest()
    finally:
        p.unlink(missing_ok=True)


def test_hash_full_policy_hashes_every_byte_even_above_cutoff(fixture_dir):
    size = PARTIAL_HASH_CUTOFF + 1
    p = fixture_dir / "big-full.bin"
    _make_sparse(str(p), size)
    try:
        result = hash_file(str(p), size, 0, "full")
        assert "sha256_partial" not in result
        assert "sha256" in result
        assert result["sha256"] == hashlib.sha256(b"\0" * size).hexdigest()
    finally:
        p.unlink(missing_ok=True)


def test_hash_none_policy_stores_nothing(fixture_dir):
    p = fixture_dir / "x.bin"
    p.write_bytes(b"abc")
    assert hash_file(str(p), 3, 0, "none") == {}


def test_hash_full_policy_on_empty_file(fixture_dir):
    p = fixture_dir / "empty-full.bin"
    p.write_bytes(b"")
    assert hash_file(str(p), 0, 0, "full") == {"sha256": hashlib.sha256(b"").hexdigest()}
