"""The catalog document: one per file or directory, shared by every backend.

See file-catalog-requirements.md, section "Record".
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

KINDS = (
    "dir", "link", "empty", "exe", "archive", "image", "texture", "mesh",
    "audio", "video", "document", "text", "data", "save", "disk", "unknown",
)
CONTAINERS = ("plain", "gzip", "gzip_xored", "zip", "pe", "bzip2", "xz", "7z", "unknown")

# Fields stored as indexed columns by the SQL backends and the Mongo index.
INDEXED_FIELDS = ("root_id", "rel_path", "sha256", "kind", "suffix", "mime")

# rel_path of the root directory itself.
ROOT_REL = ""

# Transient key carrying an archive's member list from the probe to
# Backend.store(); never written into a stored document.
MEMBERS_KEY = "_members"


def root_id(root: str) -> str:
    """Hash of the root path string exactly as the user passed it."""
    return hashlib.sha256(root.encode("utf-8")).hexdigest()[:16]


def suffix_of(name: str) -> str:
    """Extension in lower case without the dot; empty when the name has none.

    A leading dot alone (".bashrc") is not an extension.
    """
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem.strip(".") and name.startswith("."):
        return ""
    return ext.lower()


def to_rel_path(root: str, path: str) -> str:
    """Path relative to root, '/'-separated. The root itself is ROOT_REL."""
    rel = os.path.relpath(path, root)
    if rel == ".":
        return ROOT_REL
    return rel.replace("\\", "/")


def join_root(root: str, rel_path: str) -> str:
    """Absolute OS path for a record."""
    if rel_path == ROOT_REL:
        return root
    return os.path.join(root, *rel_path.split("/"))


def new_document(root: str, rel_path: str, *, kind: str, size: int = 0,
                 mtime_ns: int | None = None, ctime_ns: int | None = None,
                 name: str | None = None) -> dict[str, Any]:
    """Skeleton document with identity fields filled. Optional fields omitted."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    if name is None:
        name = rel_path.rsplit("/", 1)[-1] if rel_path else os.path.basename(root.rstrip("\\/")) or root
    doc: dict[str, Any] = {
        "root_id": root_id(root),
        "root": root,
        "rel_path": rel_path,
        "name": name,
        "size": size,
        "kind": kind,
        "suffix": "" if kind == "dir" else suffix_of(name),
    }
    if mtime_ns is not None:
        doc["mtime_ns"] = mtime_ns
    if ctime_ns is not None:
        doc["ctime_ns"] = ctime_ns
    return doc


def add_fs_info(doc: dict[str, Any], *, allocated_size: int | None = None, ino: int | None = None,
                dev: int | None = None, nlink: int | None = None) -> None:
    """The optional file-system fields only a scan through filecat-agent knows
    (an SMB scan leaves them out): `allocated_size`, the space the file really
    takes (st_blocks * 512; a sparse file's is smaller than `size`), and
    `ino` / `dev` / `nlink`, the identity of the file on its volume. Names
    sharing (dev, ino) are hard links to one file; HardLinks counts it once."""
    if allocated_size is not None:
        doc["allocated_size"] = allocated_size
    if ino:
        doc["ino"], doc["dev"], doc["nlink"] = ino, dev or 0, nlink or 1


class HardLinks:
    """Counts the size of a hard-linked file once per (dev, ino), where a
    scan totals sizes. Only files with nlink above 1 are remembered."""

    def __init__(self) -> None:
        self._seen: set[tuple[int, int]] = set()

    def counted(self, size: int, ino: int | None, dev: int | None, nlink: int | None) -> int:
        if not ino or not nlink or nlink <= 1:
            return size
        key = (dev or 0, ino)
        if key in self._seen:
            return 0
        self._seen.add(key)
        return size

    def counted_doc(self, doc: dict[str, Any]) -> int:
        return self.counted(doc.get("size") or 0, doc.get("ino"), doc.get("dev"), doc.get("nlink"))


def add_error(doc: dict[str, Any], stage: str, message: str | BaseException) -> None:
    """Append {stage, message} to doc['errors']."""
    if isinstance(message, BaseException):
        message = f"{type(message).__name__}: {message}"
    doc.setdefault("errors", []).append({"stage": stage, "message": str(message)})


def prune(doc: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None so omitted means not measured."""
    out = {}
    for k, v in doc.items():
        if v is None:
            continue
        if isinstance(v, dict):
            v = prune(v)
        out[k] = v
    return out
