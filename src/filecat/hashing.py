"""Hash policy. See file-catalog-requirements.md, "How a large or remote
tree is walked" (the hash-policy table).

| size              | policy auto          | --hash full | --hash none |
|-------------------|-----------------------|-------------|-------------|
| 0                 | no hash               | sha256(b"") | no hash     |
| 1 B .. 64 MiB     | sha256 (whole file)   | sha256      | no hash     |
| > 64 MiB          | sha256_partial        | sha256      | no hash     |

A partial digest never lands in the `sha256` field.

`sha256_partial` byte encoding (exact order, all fed into one hashlib.sha256()):
  1. the first PARTIAL_HASH_EDGE (1 MiB) bytes of the file
  2. the last PARTIAL_HASH_EDGE (1 MiB) bytes of the file
  3. the file size, 8 bytes big-endian unsigned (``struct.pack(">Q", size)``)
  4. mtime_ns, 8 bytes big-endian signed (``struct.pack(">q", mtime_ns)``;
     signed so a pre-1970 mtime does not raise)
This path is only reached above the partial cutoff (larger than 64 MiB by
default), so the first/last 1 MiB windows never overlap.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any

from .options import MiB, PARTIAL_HASH_CUTOFF, PARTIAL_HASH_EDGE

CHUNK = 1 * MiB


def _sha256_full(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha256_partial(path: str, size: int, mtime_ns: int) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(PARTIAL_HASH_EDGE))
        f.seek(max(size - PARTIAL_HASH_EDGE, 0))
        h.update(f.read(PARTIAL_HASH_EDGE))
    h.update(struct.pack(">Q", size))
    h.update(struct.pack(">q", mtime_ns))
    return h.hexdigest()


def hash_file(path: str, size: int, mtime_ns: int, policy: str = "auto") -> dict[str, Any]:
    """Hash one file per `policy` (auto | full | none).

    Returns {} , {"sha256": hex} or {"sha256_partial": hex} -- never both.
    Raises OSError if the file cannot be opened/read; callers record that as
    a `hash`-stage error rather than letting it crash the scan.
    """
    if policy not in ("auto", "full", "none"):
        raise ValueError(f"unknown hash policy {policy!r}")
    if policy == "none":
        return {}
    if policy == "full":
        return {"sha256": _sha256_full(path)}
    # auto
    if size == 0:
        return {}
    if size <= PARTIAL_HASH_CUTOFF:
        return {"sha256": _sha256_full(path)}
    return {"sha256_partial": _sha256_partial(path, size, mtime_ns)}
