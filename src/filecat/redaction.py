"""Sticky [REDACTED]: forget the name, remember the folder (docs/rollups.md
section 3.7).

Once a folder has been redacted, by marker or by config, the catalog keeps a
keyed hash of its path (and, from an agent scan, its (dev, ino)) in the
`redactions` store, so a removed marker, an edited config, a restore or a
rename on the NAS does not reveal it at the next scan. The entry holds no
name. The key is 32 random bytes in `redact.key` next to filecat.toml (or
$FILECAT_REDACT_KEY_FILE), never in the catalog and never in an output.

    key_path / load_key / create_key / key_id
    path_hash(key, root_id, rel_path)          the 32-digit HMAC of section 3.7
    StickySet                                   one root's entries during a scan
    locate / release / approve                  the two-step release

Releasing is deliberately two commands: `release` marks the entry pending
(still redacted), `approve` removes it.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import fsource, rollup, rootinfo
from .backends.base import Backend, Document
from .record import root_id as make_root_id

KEY_ENV = "FILECAT_REDACT_KEY_FILE"
KEY_BYTES = 32
HASH_DIGITS = 32
MAX_PER_ROOT = 10_000                   # hashes and inodes the agent takes per root


class RedactionKeyError(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- the key ---------------------------------------------------------------
def key_path() -> Path:
    env = os.environ.get(KEY_ENV)
    if env:
        return Path(env)
    from .config import user_path
    return user_path().with_name("redact.key")


def load_key() -> bytes | None:
    try:
        key = key_path().read_bytes()
    except OSError:
        return None
    return key if len(key) == KEY_BYTES else None


def create_key() -> bytes:
    """A new key, owner-only where the platform has such a thing. An existing
    key file is never overwritten."""
    path = key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_BYTES)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        existing = load_key()
        if existing is not None:
            return existing
        raise RedactionKeyError(f"{path} exists but is not a redaction key (32 bytes)") from None
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


def path_hash(key: bytes, root_id: str, rel_path: str) -> str:
    """HMAC-SHA256(key, "filecat-redact-v1\\0" + root_id + "\\0" + rel_path),
    hex of the first 16 bytes. `rel_path` is the folder's catalog rel_path
    (a byte that is not UTF-8 is U+F700 + byte, fsource.to_storage); no case
    folding, no Unicode normalisation."""
    data = (b"filecat-redact-v1\0" + root_id.encode("utf-8") + b"\0"
            + fsource.to_storage(rel_path).encode("utf-8", "surrogatepass"))
    return hmac.new(key, data, hashlib.sha256).hexdigest()[:HASH_DIGITS]


# --- one root's entries during a scan ----------------------------------------
class StickySet:
    """The sticky entries of one root, as the walk uses them. Thread-safe:
    the read-ahead threads ask `matches` for the folders they are about to
    list. Entries that matched are touched (`last_seen`) by `finish`."""

    def __init__(self, backend: Backend, root: str, key: bytes | None, entries: list[Document],
                 agent: bool = False) -> None:
        self.backend, self.root, self.agent = backend, root, agent
        self.rid = make_root_id(root)
        self.key = key
        self._lock = threading.Lock()
        self.entries: dict[str, Document] = {e["id"]: e for e in entries}
        self.hashes: set[str] = set()
        self._by_hash: dict[str, Document] = {}
        self._by_inode: dict[tuple[int, int], Document] = {}
        self._seen: set[str] = set()
        self.new: int = 0
        self.truncated = False
        self._index()

    def _index(self) -> None:
        kid = key_id(self.key) if self.key else None
        self.hashes.clear()
        self._by_hash.clear()
        self._by_inode.clear()
        for e in self.entries.values():
            if e.get("status") not in ("active", "pending"):
                continue
            if kid is not None and e.get("key_id") == kid:
                self.hashes.add(e["path_hash"])
                self._by_hash[e["path_hash"]] = e
            if e.get("ino"):
                self._by_inode[(e.get("dev") or 0, e["ino"])] = e

    def __bool__(self) -> bool:
        return bool(self.entries)

    def matches(self, rel_path: str) -> bool:
        """Is this folder (by path hash) a sticky entry?"""
        if not self.hashes or self.key is None:
            return False
        h = path_hash(self.key, self.rid, rel_path)
        if h not in self.hashes:
            return False
        with self._lock:
            self._seen.add(self._by_hash[h]["id"])
        return True

    def _ensure_key(self) -> bytes:
        if self.key is None:
            self.key = load_key() or create_key()
        return self.key

    def register(self, parent: str, rel_path: str, source: str, dev: int = 0, ino: int = 0) -> None:
        """A folder was rolled into [REDACTED] by `source` (marker, config):
        remember it. Known folders are only touched."""
        key = self._ensure_key()
        h = path_hash(key, self.rid, rel_path)
        with self._lock:
            known = self._by_hash.get(h)
            if known is not None:
                self._seen.add(known["id"])
                if ino and not known.get("ino"):
                    known.update(dev=dev, ino=ino)
                    self.backend.put_redaction(known)
                    self._by_inode[(dev, ino)] = known
                return
            entry = self._new_entry(parent, h, source, dev, ino)
            self.backend.put_redaction(entry)
            self._add(entry)

    def _new_entry(self, parent: str, h: str, source: str, dev: int, ino: int) -> Document:
        stamp = now()
        entry: Document = {"id": secrets.token_hex(4), "root_id": self.rid, "root": self.root,
                           "parent": parent, "path_hash": h, "status": "active", "source": source,
                           "created": stamp, "last_seen": stamp, "key_id": key_id(self._ensure_key())}
        if ino:
            entry["dev"], entry["ino"] = dev, ino
        return entry

    def _add(self, entry: Document) -> None:
        self.entries[entry["id"]] = entry
        self._by_hash[entry["path_hash"]] = entry
        self.hashes.add(entry["path_hash"])
        if entry.get("ino"):
            self._by_inode[(entry.get("dev") or 0, entry["ino"])] = entry
        self._seen.add(entry["id"])
        self.new += 1

    def fold_agent(self, parent: str, folded: list[dict[str, Any]], source: str) -> None:
        """The `folded` list of an agent's [REDACTED] rollup: {h, dev, ino}
        for each folder folded in. A folder whose hash we know is touched; one
        known only by (dev, ino) was renamed and gets its new hash; the rest
        are new. The agent never sends a name."""
        with self._lock:
            for item in folded:
                h, dev, ino = item.get("h"), item.get("dev") or 0, item.get("ino") or 0
                if not h:
                    continue
                known = self._by_hash.get(h)
                if known is not None:
                    self._seen.add(known["id"])
                    continue
                renamed = self._by_inode.get((dev, ino)) if ino else None
                if renamed is not None:
                    self._by_hash.pop(renamed["path_hash"], None)
                    self.hashes.discard(renamed["path_hash"])
                    self.backend.update_redaction_identity(renamed["id"], h, dev, ino, parent)
                    renamed.update(path_hash=h, parent=parent, key_id=key_id(self._ensure_key()))
                    self.backend.put_redaction(renamed)
                    self._by_hash[h] = renamed
                    self.hashes.add(h)
                    self._seen.add(renamed["id"])
                    continue
                entry = self._new_entry(parent, h, source, dev, ino)
                self.backend.put_redaction(entry)
                self._add(entry)

    def finish(self) -> None:
        """Touch the entries that matched this scan."""
        stamp = now()
        with self._lock:
            seen, self._seen = self._seen, set()
        for entry_id in seen:
            try:
                self.backend.touch_redaction(entry_id, stamp)
            except KeyError:
                pass

    # --- what an agent is sent -------------------------------------------------
    def wire(self) -> dict[str, Any]:
        """The `redaction` object of configure_policy for this root."""
        key = self._ensure_key()
        hashes = sorted(self.hashes)[:MAX_PER_ROOT]
        inodes = [[e.get("dev") or 0, e["ino"]] for e in self.entries.values()
                  if e.get("ino") and e.get("status") in ("active", "pending")][:MAX_PER_ROOT]
        return {"key": key.hex(), "roots": [{"root": self.rid, "base": "", "hashes": hashes,
                                              "inodes": inodes}]}


def open_set(backend: Backend, root: str, *, create_key_now: bool = False,
             new_key: bool = False, agent: bool = False) -> StickySet | None:
    """The sticky set of `root` for a scan; None when the backend keeps none.
    Stops (RedactionKeyError) when the root has entries and the key that made
    them is gone, unless `new_key` (then they match by (dev, ino) only). A
    fresh install with no entries creates its key silently, and only when an
    agent scan needs one (it computes the hashes) or the first folder is
    redacted."""
    try:
        entries = backend.redactions(root)
    except NotImplementedError:
        return None
    key = load_key()
    if entries:
        ids = sorted({e.get("key_id") for e in entries if e.get("key_id")})
        if key is None or key_id(key) not in ids:
            if not new_key:
                raise RedactionKeyError(
                    f"redaction key not found (key_id {ids[0] if ids else '?'}); restore "
                    f"{key_path().name} or scan with --new-redaction-key, which leaves the "
                    "old entries to be matched by inode only")
            key = key or create_key()
    elif create_key_now and key is None:
        key = create_key()
    return StickySet(backend, root, key, entries, agent=agent)


# --- release and approve ---------------------------------------------------------
def locate(backend: Backend, text: str, agents: list[Any] | None = None) -> tuple[str, str]:
    """(root, rel_path) of a path the user typed, in any pattern form:
    a UNC path, a local path, or an agent path (placed through the
    configured agents' share maps). The longest scanned root that contains
    it wins, ignoring case in the server, share or drive."""
    form = rollup.pattern_form(text.rstrip("/\\") or text)
    comps = rollup.path_comps(text)
    candidates: list[tuple[str, tuple[str, ...]]] = []
    if form == "agent":
        for agent in agents or []:
            try:
                unc = agent.share_map().to_catalog_path("/" + "/".join(comps))
            except ValueError:
                continue
            candidates.append((unc, rollup.path_comps(unc)))
    # also as typed: on Linux a local root is a POSIX path, which reads as the agent form
    candidates.append((text, comps))
    best: tuple[int, str, str] | None = None
    for root in backend.roots():
        rcomps = rollup.path_comps(root)
        for _, pcomps in candidates:
            n = len(rcomps)
            head = [rollup.fold(c) for c in pcomps[:n]]
            if len(pcomps) > n and head == [rollup.fold(c) for c in rcomps]:
                if best is None or n > best[0]:
                    best = (n, root, "/".join(pcomps[n:]))
    if best is None:
        raise ValueError("no scanned root contains that path")
    return best[1], best[2]


def find_entry(backend: Backend, root: str, rel_path: str) -> Document | None:
    key = load_key()
    if key is None:
        return None
    h = path_hash(key, make_root_id(root), rel_path)
    return next((e for e in backend.redactions(root)
                 if e["path_hash"] == h and e.get("key_id") == key_id(key)), None)


def release(backend: Backend, root: str, rel_path: str) -> Document:
    """Step one: mark the entry pending. Nothing visible changes."""
    entry = find_entry(backend, root, rel_path)
    if entry is None:
        raise ValueError("that folder is not in the sticky redaction store")
    if entry.get("status") != "pending":
        backend.set_redaction_status(entry["id"], "pending", released=now())
        entry = {**entry, "status": "pending"}
    return entry


def pending_entry(backend: Backend, ref: str, agents: list[Any] | None = None) -> Document:
    """The entry an `approve` argument names: an id, or a path; it must be
    pending."""
    rows = backend.redactions()
    entry = next((e for e in rows if e["id"] == ref), None)
    if entry is None:
        root, rel = locate(backend, ref, agents)
        entry = find_entry(backend, root, rel)
    if entry is None:
        raise ValueError("no such redaction")
    if entry.get("status") != "pending":
        raise ValueError(f"redaction {entry['id']} is {entry.get('status')}; run "
                         "`filecat rollups redacted release` first")
    return entry


def approve(backend: Backend, entry: Document) -> None:
    """Step two: forget the entry. The next scan lists the folder unless a
    marker or a rule still matches it."""
    backend.delete_redaction(entry["id"])


# --- what a purge leaves behind elsewhere ------------------------------------------
def _under(rel: str | None, paths: list[str]) -> bool:
    return rel is not None and any(rel == p or rel.startswith(p + "/") for p in paths)


def cleanup(backend: Backend, root: str, purged: list[str]) -> dict[str, int]:
    """After records at or beneath `purged` (rel_paths of `root`) were replaced
    by a rollup: remove their names from the places a plain delete misses
    (docs/rollups.md section 3.5). The dropped store; samples and member sets
    no record names any more; the root's unpinned treemap snapshots, and the
    folders of the pinned ones merged into one [REDACTED] folder; the root
    index's last_error and newest_file when they pointed there. Returns counts
    for the report."""
    paths = sorted(set(purged))
    done = {"dropped": 0, "treemaps": 0}
    backend.flush()
    try:
        done["dropped"] = backend.purge_dropped_paths(root, paths)
    except NotImplementedError:
        pass
    for prune in (backend.prune_samples, backend.prune_member_sets):
        try:
            prune()
        except NotImplementedError:
            pass
    done["treemaps"] = _clean_treemaps(backend, root, paths)
    try:
        info = backend.get_root_info(root)
    except NotImplementedError:
        info = None
    if info:
        changed = False
        for key in ("last_error", "newest_file"):
            if _under((info.get(key) or {}).get("rel_path"), paths):
                del info[key]
                changed = True
        if changed:
            backend.put_root_info(info)
    rootinfo.touch(backend, root)       # the purged records are gone from the root's summaries too
    return done


def _clean_treemaps(backend: Backend, root: str, paths: list[str]) -> int:
    try:
        metas = backend.list_treemaps(root)
    except NotImplementedError:
        return 0
    touched = 0
    for meta in metas:
        prefix = meta.get("prefix") or ""
        # paths relative to the snapshot's prefix; a path above it puts the whole snapshot inside
        inside = [p[len(prefix) + 1:] if prefix else p for p in paths
                  if not prefix or p.startswith(prefix + "/")]
        whole = any(prefix == p or prefix.startswith(p + "/") for p in paths)
        if not inside and not whole:
            continue
        touched += 1
        if whole or not meta.get("pin"):
            backend.delete_treemap(meta["id"])
            continue
        found = backend.get_treemap(meta["id"])
        if found is None:
            continue
        backend.put_treemap(meta, _merge_redacted(found[1], inside))
    return touched


def _merge_redacted(data: Document, inside: list[str]) -> Document:
    """A pinned treemap with every folder at or beneath a purged path replaced
    by one `[REDACTED]` folder per parent, of the summed size; extension and
    type keys only those folders used are removed."""
    keep, merged = [], {}
    for f in data.get("folders", []):
        hit = next((r for r in inside if f["path"] == r or f["path"].startswith(r + "/")), None)
        if hit is None:
            keep.append(dict(f))
            continue
        parent = hit.rsplit("/", 1)[0] + "/" if "/" in hit else ""
        m = merged.setdefault(parent + rollup.REDACTED,
                              {"path": parent + rollup.REDACTED, "files": 0, "bytes": 0,
                               "suffix": [], "mime": []})
        m["files"] += f["files"]
        m["bytes"] += f["bytes"]
    keys = {k: [dict(r) for r in rows] for k, rows in (data.get("keys") or {}).items()}
    for table in ("suffix", "mime"):
        used = {i for f in keep for i, _ in f.get(table, [])}
        remap, kept_rows = {}, []
        for i, row in enumerate(keys.get(table, [])):
            if i in used:
                remap[i] = len(kept_rows)
                kept_rows.append(row)
        keys[table] = kept_rows
        for f in keep:
            f[table] = [[remap[i], b] for i, b in f.get(table, []) if i in remap]
    return {**data, "keys": keys, "folders": keep + sorted(merged.values(), key=lambda f: -f["bytes"])}
