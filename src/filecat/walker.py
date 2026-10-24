"""Iterative directory walk. See file-catalog-requirements.md, "How a large
or remote tree is walked" and "Resume/rerun" (the rerun rule lives in
scan.py's docstring and here, since the walk is where it is enforced).

Design notes:
* os.scandir, not os.walk -- os.walk can't give us a directory's own record
  until its children are known, and we need that for post-order writes.
* "Stay on the volume the root is on" / "a junction is not followed" is the
  same rule as "a reparse point is recorded as `link` and not descended
  into" below: nothing in this module ever opens a directory through a
  reparse point, so a junction onto another volume or another share is
  never crossed.
* Per-entry timeout runs the measurement in a thread pool and waits with a
  timeout; a thread that is still blocked on a stuck handle keeps running
  (Python cannot kill a thread), it is simply abandoned and its result
  ignored. This can leak a thread for the life of the process on a truly
  wedged UNC path -- acceptable for a scanner, called out here and in the
  task report.
* Rerun vs resume. A directory whose stored record (mtime, child_count)
  matches disk is "unchanged"; its files are still stat()ed, but a file
  whose size and mtime match its record is not remeasured. A changed
  directory also drops the records of children that vanished. Separately,
  while a root's previous scan is unfinished, a directory resume.py marks
  done is skipped outright -- not even listed -- when its mtime matches
  (see resume.py for which directories are marked).
* Backup stores (backup/__init__.py). A folder whose entries look like a
  backup program's store is detected when it is listed; files in the
  store's data area (chunk pools, zip or tar volumes, disk images) are
  recorded from the listing only -- never opened -- unless
  --measure-backups, and the store folder's record gets probe.backup from
  the store's manifest once the folder is finished. A virtual store (a view
  of data kept elsewhere) is recorded with child_count 0 and not walked; a
  rescan drops what an older scan recorded inside it.
* Database data folders (dbfiles/) go through the same path: their data
  files are listed only, and the folder gets probe.database. With
  --measure-databases a data file that is quiet and big enough (dbfiles'
  table) is measured instead and keeps its probe.db_data tag. A file
  listed earlier that has since gone quiet is unchanged to a rescan;
  `filecat enrich` measures those.
* Store rollups (docs/rollups.md section 4). With `backup` / `database` set
  to `automatic`, or the store's folder listed in `[[rollups.backup_store]]` /
  `[[rollups.database_store]]`, a detected store's bulk folders
  (store_formats.json `rollup_children`: Hyper Backup's Pool, ABB's @data, a
  database's data folders) leave the listing for one `<store>/[BACKUP]` or
  `<store>/[DATABASE]` rollup; the store's own record keeps probe.backup /
  probe.database, and its top-level data files stay listed-only. A backup
  store's sum is carried forward while its fingerprint (manifests, listing,
  the rolled folders' mtimes) is unchanged and younger than `store_resum`.
  --measure-backups / --measure-databases scan a store per file instead.
* Cloud placeholders (cloudfiles.py). A file whose attributes say its data
  is not on the device (OneDrive/iCloud online-only, offline/tiered) is
  never opened -- reading it would download it -- and is recorded from its
  directory entry with probe.cloud; --force does not change that. Files in
  a sync root that are on the device are measured and get probe.cloud too.
  A rescan measures a file recorded while cloud-only once it is local.
* Agent scans (fsource.py). With a `source`, the tree is read through a
  filecat-agent: its listing entries and stats stand in for os.DirEntry and
  os.stat_result, and the same walk follows. Backup and database stores are
  detected from the listing as usual, but their manifests are not read
  through the agent yet (probe.store_note says so).
* Rollups (rollup.py, docs/rollups.md). A child that a rule, the sticky
  redaction store or a marker file rolls up is never recorded, never queued
  and never put in resume state: its files and folders are summed into one
  `kind: "rollup"` record per (folder, tag), written after the folder's
  files and before its own record. Rules and the sticky store decide from the
  name alone, before the child is listed. A marker is found in the child's
  own listing, which the walk reads anyway (including read-ahead): _list_dir
  checks the names for a marker before it returns anything, and answers
  rollup.Marked instead of a listing, so no name of a marked folder is ever
  recorded, logged, queued or kept. On an agent scan the agent does all of
  this and lists the rollups.
* Rescans of unchanged trees. A directory's stored records are read in one
  Backend.get_stats() call when it is entered (its subdirectories' own
  records included), not one get() per entry; and the listings of the next
  LIST_AHEAD subdirectories are read in background threads (_Lister), since
  over SMB a listing is mostly waiting on the network. The walk itself still
  takes one entry at a time, in name order.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from . import backup, browse, cloudfiles, dbfiles, fsource, record, rollup
from .backends.base import Backend
from .options import ScanOptions, is_unc
from .resume import ResumeState

FILE_ATTRIBUTE_REPARSE_POINT = 0x400

DEFAULT_SKIP_ROOT_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys"}
DEFAULT_SKIP_DIRS = {"$Recycle.Bin", "System Volume Information"}

# Subdirectory listings read ahead of the walk, per directory, and the
# threads that read them.
LIST_AHEAD = 16
LIST_THREADS = 8
# How many levels below a directory the read-ahead follows, and how many
# listings it holds at most.
LIST_DEPTH = 3
LIST_HELD = 1024

MeasureFunc = Callable[[str, str, str, os.stat_result, ScanOptions, Any], dict[str, Any]]
# progress(path, size, how): how is "measured" (new or changed file, read
# and written), "unchanged" (matched its record, skipped), "listed" (backup
# data recorded from its directory entry, not read), "cloud" (a cloud
# placeholder whose data is not on the device, recorded the same way) or "resumed" (a
# directory a previous unfinished scan already finished, skipped whole) or
# "dropped" (size is then how many records under `path` vanished from disk
# and were moved to the dropped store).
ProgressFunc = Callable[[str, int, str], None]


# --- small filesystem helpers -------------------------------------------

def is_reparse_point(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def read_link_target(path: str) -> str | None:
    try:
        target = os.readlink(path)
    except (OSError, ValueError):
        # ValueError: a Windows reparse point that is neither a symlink nor
        # a junction (an app execution alias, a dedup or cloud placeholder).
        return None
    # Windows may hand back the target in its \\?\ form; record the path a
    # person would type.
    if target.startswith("\\\\?\\UNC\\"):
        return "\\\\" + target[8:]
    if target.startswith("\\\\?\\") and target[5:6] == ":":
        return target[4:]
    return target


def stat_times(st: os.stat_result) -> tuple[int, int]:
    """(mtime_ns, ctime_ns), using the birth time when the platform has one."""
    mtime_ns = st.st_mtime_ns
    ctime_ns = getattr(st, "st_birthtime_ns", None)
    if ctime_ns is None:
        ctime_ns = st.st_ctime_ns
    return mtime_ns, ctime_ns


def is_drive_root(abs_path: str) -> bool:
    drive, tail = os.path.splitdrive(abs_path)
    if not (len(drive) == 2 and drive[1] == ":"):
        return False
    return tail in ("", "\\", "/")


def should_skip_dir(name: str, default_skips: bool) -> bool:
    return default_skips and name in DEFAULT_SKIP_DIRS


def _norm_path(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").lower()


def excluded(patterns: set[str], read_path: str, recorded_path: str) -> bool:
    """Is this entry one of --exclude's paths? Each is a whole path,
    matched case-insensitively either as read (\\\\192.0.2.13\\x) or as
    recorded under an alias (\\\\nas-main\\x). `patterns` are _norm_path()ed."""
    return _norm_path(read_path) in patterns or _norm_path(recorded_path) in patterns


def should_skip_root_file(name: str, at_drive_root: bool, default_skips: bool) -> bool:
    return default_skips and at_drive_root and name.lower() in DEFAULT_SKIP_ROOT_FILES


def resolve_unc(root: str) -> str | None:
    """If `root` is a mapped drive letter, resolve it to a UNC path with
    WNetGetConnectionW. Returns None for a UNC root, a bare local path, or
    when Windows has no mapping for the letter (or on resolution failure)."""
    if is_unc(root):
        return None
    drive, _ = os.path.splitdrive(root)
    if len(drive) != 2 or drive[1] != ":":
        return None
    try:
        import ctypes.wintypes as wintypes
        mpr = ctypes.WinDLL("mpr")
        length = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(length.value)
        rc = mpr.WNetGetConnectionW(ctypes.c_wchar_p(drive), buf, ctypes.byref(length))
        if rc == 0:
            return buf.value
        return None
    except Exception:
        return None


# --- the walk -------------------------------------------------------------

@dataclass
class _Frame:
    rel_path: str
    abs_path: str
    mtime_ns: int
    ctime_ns: int
    entries: list[os.DirEntry]
    idx: int = 0
    unchanged: bool = False     # set when the folder is finished: see `fresh`
    had_previous: bool = False
    is_drive_root: bool = False
    # A subdirectory could not be listed: this directory (and every one above
    # it) is not marked done, so a rerun comes back for it.
    incomplete: bool = False
    # Files submitted to the pool and not yet written: (future, rel, abs, st).
    pending: list = field(default_factory=list)
    # Backup stores this folder is in (outermost first), and the one rooted here.
    stores: tuple = ()
    store: backup.Store | None = None
    # Stored records of the entries, from one Backend.get_stats() call.
    stored: dict = field(default_factory=dict)
    # _Lister: the next entry to consider, and the listings read ahead.
    ahead_idx: int = 0
    ahead: set = field(default_factory=set)
    # Rollups: the groups of children folded into one record per tag, the
    # names rolled up here (memory only: they decide what is deleted, not
    # dropped, and are never written), those of `entries` that are not
    # recorded (a marker found in their listing), and whether every child
    # was (a marker in the root itself).
    rolled: dict = field(default_factory=dict)
    rolled_names: set = field(default_factory=set)
    not_recorded: set = field(default_factory=set)
    rolled_all: bool = False
    rollup_errors: list = field(default_factory=list)
    # What the stored record of this folder said: the folder is unchanged when its mtime
    # matches and, once every child is known (a marker is found only when a child is
    # listed), it holds as many entries and the same tags as before.
    fresh: bool = False
    stored_count: int | None = None
    stored_tags: list = field(default_factory=list)
    # Store rollups: every name in the store's folder (summarize() wants them
    # although the bulk folders left `entries`), the group of its bulk folders
    # and what summing it came to.
    store_names: set = field(default_factory=set)
    store_group: Any = None
    store_kids: set = field(default_factory=set)
    store_totals: Any = None


def _list_dir(path: str, markers: dict[str, rollup.Marker] | None = None
              ) -> "list[os.DirEntry] | rollup.Marked":
    """A directory's entries in name order, each stat()ed while the listing
    is fresh (free on Windows, where the listing carries the stat). This is
    the only way a local or SMB listing reaches the walk. With `markers`, the
    names are checked for a marker file first and, if one is there, the
    listing is dropped unread and rollup.Marked comes back instead: the
    folder is rolled up and none of its names is used for anything."""
    with os.scandir(path) as it:
        entries = list(it)
    if markers:
        hit = rollup.find_marker((e.name for e in entries), markers)
        if hit is not None:
            return rollup.Marked(hit)
    entries.sort(key=lambda e: e.name)
    for e in entries:
        try:
            e.stat(follow_symlinks=False)
        except OSError:
            pass        # the walk stats it again and records the error
    return entries


class _Lister:
    """Reads the listings of the subdirectories the walk will enter next, in
    LIST_THREADS background threads: LIST_AHEAD per directory, and from each
    listing read ahead its own subdirectories too, LIST_DEPTH levels down
    (a deep, narrow tree such as Plex's <hash>.bundle/Contents/Thumbnails
    would otherwise wait on every level). At most LIST_HELD listings are
    held. A listing that fails is raised again by take(), where the walk
    handles it as before; one read ahead and never taken costs only the time.

    `list_dir` is the walk's one way to read a listing (see _list_dir): it
    answers a list or rollup.Marked. A marked folder's read stops there:
    nothing of it is queued, and take() hands the walk the Marked."""

    def __init__(self, wanted: Callable[[os.DirEntry, str], str | None],
                 threads: int = LIST_THREADS,
                 list_dir: Callable[[str], Any] | None = None,
                 prune: Callable[[str, list], set] | None = None) -> None:
        self._wanted = wanted
        self._prune = prune         # (folder, its entries) -> child names not to read ahead
        self._list_dir = list_dir or (lambda path: _list_dir(path))
        self._pool = ThreadPoolExecutor(max_workers=threads) if threads > 0 else None
        self._pending: dict[str, Any] = {}
        self._lock = threading.Lock()

    def _submit(self, child_abs: str, child_rel: str, depth: int) -> bool:
        with self._lock:
            if child_abs in self._pending or len(self._pending) >= LIST_HELD:
                return False
            try:
                self._pending[child_abs] = self._pool.submit(self._read, child_abs, child_rel, depth)
            except RuntimeError:        # closed while a worker was still reading
                return False
        return True

    def _read(self, abs_path: str, rel_path: str, depth: int) -> list[os.DirEntry]:
        entries = self._list_dir(abs_path)
        if depth > 0 and not isinstance(entries, rollup.Marked):
            queued = 0
            skip = self._prune(rel_path, entries) if self._prune is not None else ()
            for e in entries:
                if queued >= LIST_AHEAD:
                    break
                if skip and e.name in skip:
                    continue        # a store's bulk folder: rolled up, never listed
                child_abs = self._wanted(e, rel_path)
                if child_abs is not None:
                    child_rel = f"{rel_path}/{e.name}" if rel_path else e.name
                    queued += self._submit(child_abs, child_rel, depth - 1)
        return entries

    def fill(self, frame: _Frame) -> None:
        if self._pool is None:
            return
        while frame.ahead_idx < len(frame.entries) and len(frame.ahead) < LIST_AHEAD:
            entry = frame.entries[frame.ahead_idx]
            frame.ahead_idx += 1
            child_abs = self._wanted(entry, frame.rel_path)
            if child_abs is not None:
                child_rel = f"{frame.rel_path}/{entry.name}" if frame.rel_path else entry.name
                frame.ahead.add(child_abs)
                self._submit(child_abs, child_rel, LIST_DEPTH)

    def take(self, frame: _Frame, child_abs: str) -> "list[os.DirEntry] | rollup.Marked":
        frame.ahead.discard(child_abs)
        with self._lock:
            fut = self._pending.pop(child_abs, None)
        return fut.result() if fut is not None else self._list_dir(child_abs)

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            with self._lock:
                self._pending.clear()


class _Self:
    """The whole folder being scanned as a member of a rollup group: a marker
    file in the root itself rolls up what is in it."""
    name = ""


def _is_dir_entry(entry: Any) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _partition(entries: list, rel_path: str, plan: rollup.RollupPlan, skipped: Callable[[Any, str], bool]
               ) -> tuple[list, dict, set]:
    """(entries to record, rolled groups by tag, names rolled up). On an SMB or
    local scan the plan's rules and the sticky store decide from the name; on
    an agent scan the agent has done it and its rollup entries are the groups.
    The rolled names are held in memory for the walk and nowhere else."""
    if not plan.python_side:
        recorded, groups = [], {}
        for e in entries:
            info = getattr(e, "rollup", None)
            if getattr(e, "kind", None) != "rollup":
                recorded.append(e)
                continue
            tag = (info or {}).get("tag") or e.name
            groups[tag] = rollup.Group(tag, plan.agent_rule((info or {}).get("rule"), tag),
                                       tag == rollup.REDACTED)
            groups[tag].agent, groups[tag].matched = info or {}, (info or {}).get("matched", 0)
            if tag == rollup.REDACTED and plan.sticky is not None:
                plan.sticky.fold_agent(rel_path, (info or {}).get("folded") or [], "agent")
        plan.note_suggest(rel_path, getattr(entries, "suggest", ()))
        return recorded, groups, set()
    recorded, groups = plan.partition(entries, rel_path, skipped)
    return recorded, groups, _names(groups)


def _store_kids(frame: "_Frame") -> set:
    """Names of a store's bulk folders rolled up in this folder (no secret)."""
    return frame.store_kids if frame.store_group is not None else set()


def _names(groups: dict) -> set:
    return {m.name for g in groups.values() for m in g.members}


def _register_redacted(plan: rollup.RollupPlan, rel_path: str, groups: dict) -> None:
    """Remember the folders a rule rolled into [REDACTED] (sticky.register keeps
    a known one as it is)."""
    g = groups.get(rollup.REDACTED)
    if g is None or plan.sticky is None or g.agent is not None:
        return
    for m in g.members:
        if _is_dir_entry(m):
            plan.sticky.register(rel_path, f"{rel_path}/{m.name}" if rel_path else m.name,
                                 "config" if g.rule.startswith("user") else "sticky")


def _make_frame(root: str, rel_path: str, abs_path: str, mtime_ns: int, ctime_ns: int,
                entries: list[os.DirEntry], options: ScanOptions, backend: Backend,
                parent_stores: tuple = (), stored: dict[str, Any] | None = None,
                plan: rollup.RollupPlan | None = None,
                skipped: Callable[[Any, str], bool] | None = None,
                store_rolls: Callable[[backup.Store, str], bool] | None = None) -> _Frame:
    """`stored` is this directory's own record, read with its parent's
    entries; the root's is read here. With a `plan`, the listing is first
    partitioned: the children a rule or the sticky store rolls up (or, on an
    agent scan, the agent's rollup entries) leave `entries` for `rolled`
    before anything else looks at them."""
    dir_name = rel_path.rsplit("/", 1)[-1] if rel_path else os.path.basename(abs_path.rstrip("\\/"))
    rolled: dict = {}
    rolled_names: set = set()
    if plan is not None:
        entries, rolled, rolled_names = _partition(entries, rel_path, plan, skipped)
        if rolled:
            _register_redacted(plan, rel_path, rolled)
    names = {e.name for e in entries}
    store = backup.detect(rel_path, dir_name, names) or dbfiles.detect(rel_path, dir_name, names)
    if store is not None and store.virtual and not options.measure_backups:
        entries = []    # recorded with its summary, not walked (see backup/__init__.py)
    store_names: set = set()
    store_kids: set = set()
    store_group = None
    if store is not None and store_rolls is not None and store_rolls(store, rel_path):
        kids = store.rollup_children(entries)
        existing = rolled.get(store.tag)
        if kids and (existing is None or existing.agent is None):
            store_names = set(names)
            store_group = existing or rollup.Group(store.tag, f"store:{store.format.name}", False)
            if existing is None:
                store_group.store = store
                rolled[store.tag] = store_group
            kid_names = {k.name for k in kids}
            store_kids = set(kid_names)
            for k in kids:
                store_group.add(k)
            for e in entries:   # a real child named like the tag is folded in too
                if (e.name not in kid_names and e.name[:1] == "[" and rollup.fold(e.name) == rollup.fold(store.tag)):
                    store_group.add(e)
                    kid_names.add(e.name)
            entries = [e for e in entries if e.name not in kid_names]
            rolled_names = rolled_names | kid_names
    children: dict[str, Any] = {}
    if not options.force:
        if not rel_path:
            stored = backend.get_stats(root, [rel_path]).get(rel_path)
            if plan is not None and stored is not None and stored.get("kind") == "dir":
                # a changed rule set relists every folder, so what the new rules roll up
                # is replaced and what they no longer roll up is recorded
                was = (stored.get("probe") or {}).get("rollup_policy") or rollup.default_policy_id()
                plan.policy_changed = was != plan.policy_id
        if entries:
            prefix = f"{rel_path}/" if rel_path else ""
            children = backend.get_stats(root, [prefix + e.name for e in entries])
    else:
        stored = None
    if stored is not None and stored.get("kind") != "dir":
        stored = None
    probe = (stored or {}).get("probe") or {}
    fresh = (stored is not None and not (plan is not None and plan.policy_changed)
             and stored.get("mtime_ns") == mtime_ns)
    return _Frame(rel_path=rel_path, abs_path=abs_path, mtime_ns=mtime_ns, ctime_ns=ctime_ns,
                  entries=entries, fresh=fresh, stored_count=probe.get("child_count"),
                  stored_tags=sorted(probe.get("rollup_tags") or ()), had_previous=stored is not None,
                  is_drive_root=is_drive_root(abs_path),
                  stores=parent_stores + ((store,) if store else ()), store=store,
                  stored=children, rolled=rolled, rolled_names=rolled_names,
                  store_names=store_names, store_group=store_group,
                  store_kids=store_kids)


def _listed_only(root: str, rel_path: str, name: str, st: os.stat_result,
                 store: backup.Store) -> dict[str, Any]:
    """The record of a backup or database data file, from its directory entry alone."""
    mtime_ns, ctime_ns = stat_times(st)
    doc = record.new_document(root, rel_path, kind="data", size=st.st_size,
                              mtime_ns=mtime_ns, ctime_ns=ctime_ns, name=name)
    doc["probe"] = {store.data_key: store.format.name}
    return doc


def _measure_tagged(measure_file: MeasureFunc, store: backup.Store | None,
                    cloud: dict[str, Any] | None, *args: Any) -> dict[str, Any]:
    """measure_file plus the tags the walk knows: a store data file that is
    read after all (database files) keeps its tag, and a file the server
    holds open says so; a file in a cloud sync root gets probe.cloud."""
    doc = measure_file(*args)
    if cloud is not None:
        doc.setdefault("probe", {})["cloud"] = cloud
    if store is None:
        return doc
    doc.setdefault("probe", {})[store.data_key] = store.format.name
    return dbfiles.settle_in_use(doc)


def _was_cloud_only(doc: dict[str, Any]) -> bool:
    return ((doc.get("probe") or {}).get("cloud") or {}).get("state") in ("online-only", "offline")


def _cloud_listed(root: str, rel_path: str, name: str, st: os.stat_result,
                  cloud: dict[str, Any], identifier: Any) -> dict[str, Any]:
    """The record of a file whose data is not on the device, from its
    directory entry and name alone (see cloudfiles.py)."""
    mtime_ns, ctime_ns = stat_times(st)
    doc = record.new_document(root, rel_path, kind="unknown", size=st.st_size,
                              mtime_ns=mtime_ns, ctime_ns=ctime_ns, name=name)
    doc["probe"] = {"cloud": cloud}
    by_name = getattr(identifier, "by_name", None)
    if by_name is not None:
        try:
            result = by_name(name, st.st_size, None)
        except Exception as e:  # a broken glob table must not stop the walk
            record.add_error(doc, "identify", e)
        else:
            if result:
                doc["probe"].update(result)
                if result.get("mime_glob"):
                    doc["mime"] = result["mime_glob"]
                doc["probe"].setdefault("identify_basis", "name")
    return doc


def _stored_rel_paths(backend: Backend, root: str, **filters: Any) -> list[str]:
    """rel_paths of the stored records matching a browse filter, paged."""
    out: list[str] = []
    offset = 0
    while True:
        q = browse.normalize({"root": root, "sort": "rel_path", "desc": "0",
                              "offset": offset, "limit": browse.MAX_LIMIT, **filters})
        page = backend.query(q)
        out += [d["rel_path"] for d in page["rows"]]
        offset += len(page["rows"])
        if not page["rows"] or offset >= page["total"]:
            return out


def _delete_stale_children(backend: Backend, root: str, rel_path: str, current: set[str],
                           rolled: set[str], rolled_all: bool = False,
                           purged: list[str] | None = None, produced: Iterable[str] = (),
                           quiet: Iterable[str] = ()) -> int:
    """A changed directory may have lost entries since the last scan; move
    their stored documents -- and everything stored beneath a vanished
    subdirectory -- to the dropped store (Backend.drop_many) so the catalog
    does not keep ghosts around. Reads only this directory's children
    (Backend.query), not the whole root. `current` is the names of the
    recorded entries and of the rollups written here. A stored entry whose
    name is in `rolled` (or any, with `rolled_all`) is not gone from disk but
    replaced by a rollup: it and everything beneath it are deleted for good
    (Backend.delete_many), never dropped, and its path is added to `purged`
    for the cleanup that follows (not for a name in `quiet`: a store's bulk
    folder, whose names are no secret). A stored rollup that was not produced this
    time is deleted, and so is anything stored beneath a path a rollup now
    occupies (a real folder that was called [CACHE]). Returns how many were
    dropped."""
    dropped = 0
    produced = set(produced)
    quiet = set(quiet)
    for rp in _stored_rel_paths(backend, root, parent=rel_path):
        name = rp.rsplit("/", 1)[-1]
        if name in current:
            if name in produced:
                beneath = _stored_rel_paths(backend, root, dir=rp, depth=len(rp.split("/")))
                if beneath:
                    backend.delete_many(root, beneath)
                    if purged is not None and name not in quiet:
                        purged.append(rp)
            continue
        if rolled_all or name in rolled:
            beneath = _stored_rel_paths(backend, root, dir=rp, depth=len(rp.split("/")))
            backend.delete_many(root, beneath + [rp])
            if purged is not None and name not in quiet:
                purged.append(rp)
            continue
        if name[:1] == "[" and (backend.get_stats(root, [rp]).get(rp) or {}).get("kind") == "rollup":
            backend.delete(root, rp)
            continue
        beneath = _stored_rel_paths(backend, root, dir=rp, depth=len(rp.split("/")))
        dropped += backend.drop_many(root, beneath + [rp])
    return dropped


def _identity(st: Any) -> tuple[int | None, int | None, int | None]:
    """(ino, dev, nlink) of an agent stat, else Nones (HardLinks.counted)."""
    if isinstance(st, fsource.AgentStat):
        return st.st_ino, st.st_dev, st.st_nlink
    return None, None, None


def _apply_unc(doc: dict[str, Any], unc: str | None) -> None:
    if unc is not None:
        doc.setdefault("probe", {})["unc"] = unc


def walk_root(root: str, options: ScanOptions, backend: Backend, identifier: Any,
              resume: ResumeState, measure_file: MeasureFunc, *,
              unc: str | None = None, progress: ProgressFunc | None = None,
              extra_root_errors: list[dict[str, str]] | None = None,
              path: str | None = None, source: Any = None,
              rollups: rollup.RollupPlan | None = None) -> bool:
    """Walk one root, writing file/dir documents to `backend` as they are
    finished (post-order for directories). Returns True if any document
    recorded for this root carries an `errors` entry. `path` is where the
    tree is read from when that differs from the recorded `root` (an alias).
    `source` is an fsource.AgentSource when the tree is read through a
    filecat-agent; None reads the local file system (or an SMB share).
    `rollups` is the root's rollup.RollupPlan (scan.py makes it, and sends an
    agent its half before anything is listed); without one it is made here."""
    had_errors = False
    path = path or root
    join = record.join_root if source is None else source.join
    links = record.HardLinks()      # a hard-linked file's size is totalled once
    own_plan = rollups is None
    plan = rollups or rollup.make_plan(options, root, path, backend, source=source)
    markers = plan.markers if source is None else None     # an agent looks for them itself
    skips = options.default_skips and not plan.windows_rule     # the [WINDOWS] rule replaces the skip
    cancel = threading.Event()
    cleanup_failed = False
    rollup_pool: list[ThreadPoolExecutor] = []

    try:
        if source is not None and (own_plan or not source.configured):
            source.configure_rollups([(plan, path)])    # never list before the agent has its rules
        root_st = os.stat(path) if source is None else source.stat_root(path)
    except OSError as e:
        doc = record.new_document(root, record.ROOT_REL, kind="dir")
        record.add_error(doc, "stat", e)
        if extra_root_errors:
            doc.setdefault("errors", []).extend(extra_root_errors)
        _apply_unc(doc, unc)
        backend.put(doc)
        return True

    root_mtime_ns, root_ctime_ns = stat_times(root_st)

    try:
        if source is None:
            root_entries = _list_dir(path, markers)
        else:
            root_entries = source.list_dir(path)
    except OSError as e:
        doc = record.new_document(root, record.ROOT_REL, kind="dir",
                                   mtime_ns=root_mtime_ns, ctime_ns=root_ctime_ns)
        record.add_error(doc, "listdir", e)
        if extra_root_errors:
            doc.setdefault("errors", []).extend(extra_root_errors)
        _apply_unc(doc, unc)
        backend.put(doc)
        return True

    root_marker = None
    if isinstance(root_entries, rollup.Marked):
        root_marker, root_entries = root_entries.marker, []     # the root's own listing is dropped

    timeout = options.timeout_for(path)
    exclude = {_norm_path(p) for p in options.exclude}
    max_in_flight = max(1, options.workers) * 4

    def _skipped(entry: Any, parent_rel: str) -> bool:
        """Excluded or skipped by default: neither walked, counted nor rolled up."""
        if skips and entry.name in DEFAULT_SKIP_DIRS:
            return True
        if not exclude:
            return False
        child_rel = f"{parent_rel}/{entry.name}" if parent_rel else entry.name
        return excluded(exclude, join(path, child_rel), record.join_root(root, child_rel))

    cfg = plan.cfg
    stores_on = (cfg.mode_of("backup") == "automatic" or cfg.mode_of("database") == "automatic"
                 or bool(cfg.backup_stores or cfg.database_stores))

    def _store_rolls(store: backup.Store, rel_path: str) -> bool:
        """Do this detected store's bulk folders roll up in this scan? Not a
        virtual store, not one that --measure-backups / --measure-databases
        reads per file, and only when its type is `automatic` or the store's
        folder is listed in [[rollups.backup_store]] / [[rollups.database_store]]."""
        if not stores_on or store.virtual or not store.rollup_patterns:
            return False
        db = store.probe_key == "database"
        mode = cfg.mode_of("database" if db else "backup")
        if mode == "disabled" or (options.measure_databases if db else options.measure_backups):
            return False
        if mode == "automatic":
            return True
        listed = cfg.database_stores if db else cfg.backup_stores
        if not listed:
            return False
        here = {_norm_path(join(path, rel_path)), _norm_path(record.join_root(root, rel_path))}
        if source is not None:
            here.add(_norm_path(source.posix(join(path, rel_path))))
        return any(_norm_path(p) in here for p in listed)

    def _prune(rel_path: str, entries: list) -> set:
        """Names in a read-ahead listing that are a store's bulk folders."""
        if not stores_on or isinstance(entries, rollup.Marked):
            return set()
        names = {e.name for e in entries}
        store = backup.detect(rel_path, rel_path.rsplit("/", 1)[-1], names) or dbfiles.detect(
            rel_path, rel_path.rsplit("/", 1)[-1], names)
        if store is not None and _store_rolls(store, rel_path):
            return {k.name for k in store.rollup_children(entries)}
        return set()

    if options.force:
        resume.forget_root(root)
    root_frame = _make_frame(root, record.ROOT_REL, path, root_mtime_ns, root_ctime_ns,
                              root_entries, options, backend, plan=plan, skipped=_skipped,
                              store_rolls=_store_rolls)
    if plan.policy_changed:
        resume.forget_root(root)
    if root_marker is not None:
        group = rollup.Group(root_marker.tag, f"marker:{root_marker.tag}", root_marker.private)
        group.add(_Self())
        root_frame.rolled[group.tag] = group
        root_frame.rolled_all = True
        root_frame.fresh = False
    for name in root_frame.rolled_names:
        resume.forget_beneath(root, name)
    stack: list[_Frame] = [root_frame]

    def _will_enter(entry: os.DirEntry, parent_rel: str) -> str | None:
        """The path of a subdirectory the walk is going to list, else None:
        the same tests as the walk below, minus the listing."""
        try:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                return None
            st = entry.stat(follow_symlinks=False)
        except OSError:
            return None
        if is_reparse_point(st) or should_skip_dir(entry.name, skips):
            return None
        child_rel = f"{parent_rel}/{entry.name}" if parent_rel else entry.name
        child_abs = join(path, child_rel)
        if exclude and excluded(exclude, child_abs, record.join_root(root, child_rel)):
            return None
        if plan.python_side and plan.classify(
                entry, entry.name, parent_rel,
                plan.comps_of(parent_rel) if plan.ruleset.needs_path else None, count=False):
            return None     # a rule or the sticky store rolls it up: never listed ahead
        done = None if options.force else resume.get_dir(root, child_rel)
        if done is not None and done.get("mtime_ns") == stat_times(st)[0]:
            return None
        return child_abs

    lister = _Lister(_will_enter, list_dir=(lambda p: _list_dir(p, markers)) if source is None
                     else source.list_dir, prune=_prune)

    def _drain(pending: list, count: int) -> bool:
        """Write the first `count` pending files in submission order."""
        errors = False
        for fut, child_rel, child_abs, st in pending[:count]:
            try:
                doc = fut.result(timeout=timeout)
            except FutureTimeoutError:
                mtime_ns, ctime_ns = stat_times(st)
                doc = record.new_document(root, child_rel, kind="unknown", size=st.st_size,
                                           mtime_ns=mtime_ns, ctime_ns=ctime_ns)
                record.add_error(
                    doc, "timeout",
                    f"measurement exceeded {timeout:.0f}s (the worker thread could not "
                    "be cancelled and may still be running)")
            except Exception as e:  # pragma: no cover - measure_file should not raise
                mtime_ns, ctime_ns = stat_times(st)
                doc = record.new_document(root, child_rel, kind="unknown", size=st.st_size,
                                           mtime_ns=mtime_ns, ctime_ns=ctime_ns)
                record.add_error(doc, "measure", e)
            _apply_unc(doc, unc)
            if doc.get("errors"):
                errors = True
            backend.store(doc)
            if progress:
                progress(child_abs, links.counted(doc.get("size", st.st_size), *_identity(st)), "measured")
        del pending[:count]
        return errors

    def _store_listing(frame: _Frame) -> dict[str, int]:
        """{path within the store: size} of the files recorded beneath it,
        every one of which is written by now (post-order)."""
        backend.flush()
        cut = len(frame.rel_path) + 1 if frame.rel_path else 0
        return {rel[cut:]: size for rel, size, _, _ in backend.sizes(root, frame.rel_path)}

    def _recorded_names(frame: _Frame) -> set[str]:
        return {e.name for e in frame.entries if e.name not in frame.not_recorded}

    def _rollup_info(frame: _Frame) -> dict[str, Any] | None:
        """What summarize() is told when this store's bulk folders are a
        rollup: their names and, once summed, the totals."""
        if frame.store_group is None:
            return None
        t = frame.store_totals
        info: dict[str, Any] = {"children": sorted(frame.store_kids)}
        if t is None:
            info.update(files=None, bytes=None, partial=True)
        else:
            info.update(files=t.total_files, bytes=t.size, partial=t.errors > 0)
        return info

    def _backup_summary(frame: _Frame, doc: dict[str, Any]) -> None:
        names = (frame.store_names - frame.not_recorded) if frame.store_names else _recorded_names(frame)
        fs = backup.storefs.for_store(source, frame.abs_path, plan.cfg.manifest_cap)
        try:
            summary = backup.summarize(
                frame.store, frame.abs_path, names,
                listing=lambda: _store_listing(frame), verify=options.verify_backups >= getattr(frame.store.format, "verify_level", 1),
                rollup=_rollup_info(frame), level=options.verify_backups, fs=fs)
        except Exception as e:  # a bad manifest must not stop the walk
            summary = None
            if not getattr(fs, "oversize", None):
                record.add_error(doc, frame.store.probe_key, e)
        oversize = getattr(fs, "oversize", None)
        if oversize:
            # a manifest over rollups.manifest_cap: the summary would be missing
            # what it holds, so the store gets a note instead of probe.backup
            doc.setdefault("probe", {})["store_note"] = (
                f"{frame.store.format.name}: manifest not read through filecat-agent, "
                f"over the manifest_cap limit: {', '.join(oversize)}")
        elif summary is not None:
            doc.setdefault("probe", {})[frame.store.probe_key] = summary

    def _manifest_stat(frame: _Frame, inner: str) -> list[int | None]:
        """[size, mtime_ns] of a file inside the store, [None, None] when it is not there."""
        where = join(frame.abs_path, inner)
        try:
            if source is None:
                st = os.stat(where)
                return [st.st_size, st.st_mtime_ns]
            m = source.client().measure(source.posix(where), hash="none", head_bytes=0)
            return [m.size, m.mtime_ns]
        except (OSError, ValueError):
            return [None, None]

    def _fingerprint(frame: _Frame, group: rollup.Group) -> str | None:
        """SHA-256 of what would change when a backup program ran: the store
        folder's mtime, the name, size and mtime of everything in it (the rolled
        folders included, so their mtimes) and of the manifest files the format
        reads. None for a format with no manifest list: it is always summed."""
        manifests = getattr(frame.store.format, "manifests", None)
        if manifests is None:
            return None
        listing = []
        for e in list(frame.entries) + list(group.members):
            try:
                # a folder's own stat: on NTFS the listing shows its mtime late
                st = (os.lstat(join(frame.abs_path, e.name)) if source is None
                      else e.stat(follow_symlinks=False))
                listing.append([e.name, st.st_size, st.st_mtime_ns])
            except OSError:
                listing.append([e.name, None, None])
        listing.sort(key=lambda x: x[0])
        inner = [[m, *_manifest_stat(frame, m)] for m in sorted(manifests)]
        try:
            own = os.lstat(frame.abs_path).st_mtime_ns if source is None else frame.mtime_ns
        except OSError:
            own = None
        blob = json.dumps([frame.store.format.name, frame.store.rel_path, own, listing, inner],
                          separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8", "surrogatepass")).hexdigest()

    def _carried(group: rollup.Group, fp: str | None, rel_path: str) -> dict[str, Any] | None:
        """The stored rollup of a backup store when it still stands: same
        fingerprint, same rules, no read errors, summed less than
        `store_resum` days ago. --force never carries."""
        if fp is None or options.force:
            return None
        prev = backend.get_stats(root, [rel_path]).get(rel_path)
        info = ((prev or {}).get("probe") or {}).get("rollup") or {}
        if (prev is None or prev.get("kind") != "rollup" or info.get("fp") != fp
                or info.get("partial") or info.get("errors") or info.get("policy") != plan.policy_id
                or info.get("matched") != group.matched):
            return None
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(info["summed_at"])
        except (KeyError, ValueError, TypeError):
            return None
        return prev if age < timedelta(days=cfg.store_resum_days) else None

    def _roll_marked(frame: _Frame, entry: Any, child_rel: str, marker: rollup.Marker) -> None:
        """The listing of this child held a marker: it is rolled up under the
        marker's tag, and the folder's stored records are replaced."""
        name = entry.name
        group = frame.rolled.get(marker.tag)
        if group is None:
            group = frame.rolled[marker.tag] = rollup.Group(marker.tag, f"marker:{marker.tag}",
                                                           marker.private)
            for later in frame.entries[frame.idx + 1:]:     # a real child named like the tag
                if (later.name[:1] == "[" and rollup.fold(later.name) == rollup.fold(marker.tag)
                        and later.name not in frame.rolled_names):
                    group.add(later)
                    frame.not_recorded.add(later.name)
                    frame.rolled_names.add(later.name)
        group.add(entry)
        frame.not_recorded.add(name)
        frame.rolled_names.add(name)
        resume.forget_beneath(root, child_rel)
        if marker.tag == rollup.REDACTED and plan.sticky is not None:
            plan.sticky.register(frame.rel_path, child_rel, "marker")

    def _sum_member(member_path: str, is_dir: bool, whole: bool, deadline: float | None
                    ) -> rollup.Totals:
        return rollup.sum_tree(member_path, is_dir=is_dir, count_self=not whole, cancel=cancel,
                               deadline=deadline)

    def _agent_totals(info: dict[str, Any]) -> rollup.Totals:
        t = rollup.Totals(
            matched=info.get("matched", 0), total_files=info.get("total_files", 0),
            total_dirs=info.get("total_dirs", 0), size=info.get("total_size", 0),
            allocated=info.get("total_allocated_size"), newest=info.get("newest_mtime_ns", 0),
            oldest=info.get("oldest_mtime_ns"), errors=info.get("errors", 0),
            error_codes=dict(info.get("error_codes") or {}), vanished=info.get("vanished", 0),
            skipped_mounts=info.get("skipped_mounts", 0), hardlink_names=info.get("hardlink_names") or None,
            complete=info.get("complete", True))
        return t

    def _sum_agent(member_path: str, deadline: float | None) -> rollup.Totals:
        """A store's bulk folder summed by the agent (`sum_subtree`, with
        progress lines and the deadline)."""
        left = max(deadline - time.monotonic(), 1.0) if deadline is not None else None
        try:
            return rollup.Totals.from_summary(source.sum_subtree(member_path, deadline_s=left))
        except OSError:
            raise rollup.RollupError("rollup failed") from None

    def _roll(frame: _Frame) -> bool:
        """Sum each group of the folder and write its rollup record. Returns
        whether a record carries an error. A backup store's rollup whose
        fingerprint is unchanged is carried forward as it is."""
        errors = False
        if not frame.rolled:
            return False
        deadline = time.monotonic() + options.rollup_timeout if options.rollup_timeout else None
        started: list[tuple[rollup.Group, list, dict | None, str | None]] = []
        for tag in sorted(frame.rolled):
            group = frame.rolled[tag]
            futures = []
            fp = carried = None
            if (group is frame.store_group and group.store is not None
                    and group.store.probe_key != "database"):
                fp = _fingerprint(frame, group)
                carried = _carried(group, fp, rollup.rollup_path(frame.rel_path, tag))
            if group.agent is None and carried is None:
                if not rollup_pool:
                    rollup_pool.append(ThreadPoolExecutor(max_workers=max(1, options.rollup_workers)))
                for m in group.members:
                    if isinstance(m, _Self):
                        futures.append(rollup_pool[0].submit(_sum_member, path, True, True, deadline))
                        continue
                    child_rel = f"{frame.rel_path}/{m.name}" if frame.rel_path else m.name
                    if source is not None:
                        futures.append(rollup_pool[0].submit(_sum_agent, join(path, child_rel), deadline))
                    else:
                        futures.append(rollup_pool[0].submit(
                            _sum_member, join(path, child_rel), _is_dir_entry(m), False, deadline))
            started.append((group, futures, carried, fp))
        for group, futures, carried, fp in started:
            shown = join(path, rollup.rollup_path(frame.rel_path, group.tag))   # the rollup's own path
            if carried is not None:
                totals = rollup.Totals.from_document(carried)
                if group is frame.store_group:
                    frame.store_totals = totals
                if progress:
                    progress(shown, totals.size, "carried")
                continue
            if group.agent is not None:
                totals = _agent_totals(group.agent)
            else:
                totals = rollup.Totals(matched=group.matched)
                pending_f = list(futures)
                while pending_f:
                    _, still = wait(pending_f, timeout=1.0)
                    pending_f = list(still)
                    if pending_f and progress:
                        progress(shown, 0, "summing")
                for fut in futures:
                    try:
                        totals.merge(fut.result())
                    except rollup.RollupError:
                        frame.rollup_errors.append("a rollup could not be summed")
                        errors = True
            if not totals.complete:
                frame.rollup_errors.append("a rollup was not finished in time; the earlier record is kept")
                errors = True
                continue
            totals.matched = group.matched
            store_ref = ({"format": group.store.format.name, "path": group.store.rel_path}
                         if group is frame.store_group and group.store is not None else None)
            doc = rollup.rollup_document(root, frame.rel_path, group.tag, totals, rule=group.rule,
                                         via="agent" if (group.agent is not None or source is not None)
                                         else "python", policy=plan.policy_id, store=store_ref, fp=fp)
            _apply_unc(doc, unc)
            if doc.get("errors"):
                errors = True
            backend.put(doc)
            if group is frame.store_group:
                frame.store_totals = totals
            if progress:
                progress(shown, totals.size, "rollup")
        return errors

    try:
        with ThreadPoolExecutor(max_workers=max(1, options.workers)) as executor, closing(lister):
            while stack:
                frame = stack[-1]
                lister.fill(frame)

                if frame.idx >= len(frame.entries):
                    # Every file of this directory is written before the
                    # directory record and its resume marker (post-order).
                    had_errors = _drain(frame.pending, len(frame.pending)) or had_errors
                    had_errors = _roll(frame) or had_errors
                    count = len(frame.entries) - len(frame.not_recorded) + len(frame.rolled)
                    frame.unchanged = (frame.fresh and frame.stored_count == count
                                       and frame.stored_tags == sorted(frame.rolled))
                    if (frame.had_previous or frame.rolled) and not frame.unchanged:
                        current = _recorded_names(frame) | set(frame.rolled)
                        gone = _delete_stale_children(
                            backend, root, frame.rel_path, current, frame.rolled_names,
                            frame.rolled_all, plan.purged, frame.rolled,
                            quiet=_store_kids(frame))
                        if gone and progress:
                            progress(frame.abs_path, gone, "dropped")
                    doc = record.new_document(root, frame.rel_path, kind="dir",
                                               mtime_ns=frame.mtime_ns, ctime_ns=frame.ctime_ns)
                    doc.setdefault("probe", {})["child_count"] = count
                    if frame.rolled:
                        doc["probe"]["rollup_tags"] = sorted(frame.rolled)
                    if frame is root_frame and plan.policy_id != rollup.default_policy_id():
                        doc["probe"]["rollup_policy"] = plan.policy_id
                    if frame.store is not None:
                        _backup_summary(frame, doc)
                    for message in frame.rollup_errors:
                        record.add_error(doc, "rollup", message)
                    if frame is root_frame and extra_root_errors:
                        doc.setdefault("errors", []).extend(extra_root_errors)
                    _apply_unc(doc, unc)
                    if doc.get("errors"):
                        had_errors = True
                    backend.put(doc)
                    stack.pop()
                    if frame.incomplete:
                        if stack:
                            stack[-1].incomplete = True
                    elif frame is root_frame:
                        resume.finish_root(root)
                    else:
                        resume.mark_dir_complete(
                            root, frame.rel_path, frame.mtime_ns, len(frame.entries) - len(frame.not_recorded),
                            child_dirs=[e.name for e in frame.entries
                                        if e.name not in frame.not_recorded])  # unmarked names: no-op
                    if stack:
                        stack[-1].idx += 1
                    continue

                entry = frame.entries[frame.idx]
                name = entry.name
                if frame.not_recorded and name in frame.not_recorded:
                    frame.idx += 1      # rolled up (a real child named like a tag)
                    continue
                child_rel = f"{frame.rel_path}/{name}" if frame.rel_path else name
                child_abs = join(path, child_rel)

                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError as e:
                    doc = record.new_document(root, child_rel, kind="unknown", name=name)
                    record.add_error(doc, "stat", e)
                    had_errors = True
                    backend.put(doc)
                    frame.idx += 1
                    continue

                if is_reparse_point(st) or entry.is_symlink():
                    mtime_ns, ctime_ns = stat_times(st)
                    doc = record.new_document(root, child_rel, kind="link", size=st.st_size,
                                               mtime_ns=mtime_ns, ctime_ns=ctime_ns, name=name)
                    target = read_link_target(child_abs) if source is None else entry.link_target
                    if target is not None:
                        doc.setdefault("probe", {})["link_target"] = target
                    fsource.apply_stat_extras(doc, st)
                    _apply_unc(doc, unc)
                    if doc.get("errors"):
                        had_errors = True
                    backend.put(doc)
                    frame.idx += 1
                    continue

                if entry.is_dir(follow_symlinks=False):
                    if should_skip_dir(name, skips) or (
                            exclude and excluded(exclude, child_abs, record.join_root(root, child_rel))):
                        frame.idx += 1
                        continue
                    done = None if options.force else resume.get_dir(root, child_rel)
                    if done is not None and done.get("mtime_ns") == stat_times(st)[0]:
                        # finished by the unfinished scan this one resumes
                        if progress:
                            progress(child_abs, 0, "resumed")
                        frame.idx += 1
                        continue
                    try:
                        child_entries = lister.take(frame, child_abs)
                    except OSError as e:
                        mtime_ns, ctime_ns = stat_times(st)
                        doc = record.new_document(root, child_rel, kind="dir",
                                                   mtime_ns=mtime_ns, ctime_ns=ctime_ns, name=name)
                        record.add_error(doc, "listdir", e)
                        _apply_unc(doc, unc)
                        had_errors = True
                        backend.put(doc)
                        frame.incomplete = True
                        frame.idx += 1
                        continue
                    if isinstance(child_entries, rollup.Marked):
                        _roll_marked(frame, entry, child_rel, child_entries.marker)
                        frame.idx += 1
                        continue
                    mtime_ns, ctime_ns = stat_times(st)
                    child_frame = _make_frame(root, child_rel, child_abs, mtime_ns, ctime_ns,
                                              child_entries, options, backend, frame.stores,
                                              stored=frame.stored.get(child_rel), plan=plan,
                                              skipped=_skipped, store_rolls=_store_rolls)
                    for rolled_name in child_frame.rolled_names:
                        resume.forget_beneath(root, f"{child_rel}/{rolled_name}")
                    stack.append(child_frame)
                    continue  # parent.idx advances only once child_frame is popped

                if entry.is_file(follow_symlinks=False):
                    if should_skip_root_file(name, frame.is_drive_root, skips) or (
                            exclude and excluded(exclude, child_abs, record.join_root(root, child_rel))):
                        frame.idx += 1
                        continue

                    size = st.st_size
                    attrs = cloudfiles.attributes_of(st)
                    cloud_only = cloudfiles.not_local(attrs)
                    # A file whose size and mtime match its stored record is not
                    # remeasured, even inside a directory whose mtime moved: NTFS
                    # can bump a directory's mtime lazily after a child is written,
                    # and a changed directory only needs its own record rewritten
                    # and its vanished children deleted. The exception is a file
                    # recorded while cloud-only that is on the device now.
                    if not options.force:
                        stored = frame.stored.get(child_rel)
                        if (stored is not None and stored.get("size") == size
                                and stored.get("mtime_ns") == st.st_mtime_ns
                                and (cloud_only or not _was_cloud_only(stored))):
                            if progress:
                                progress(child_abs, links.counted(size, *_identity(st)), "unchanged")
                            frame.idx += 1
                            continue

                    cloud = cloudfiles.describe(child_abs, attrs)
                    if cloud_only:
                        # opening it would make the provider download it
                        doc = _cloud_listed(root, child_rel, name, st, cloud, identifier)
                        _apply_unc(doc, unc)
                        backend.put(doc)
                        if progress:
                            progress(child_abs, links.counted(size, *_identity(st)), "cloud")
                        frame.idx += 1
                        continue

                    store = next((s for s in frame.stores if s.opaque(child_rel)), None)
                    if store is not None and not store.measured(st, options):
                        doc = _listed_only(root, child_rel, name, st, store)
                        _apply_unc(doc, unc)
                        backend.put(doc)
                        if progress:
                            progress(child_abs, links.counted(size, *_identity(st)), "listed")
                        frame.idx += 1
                        continue

                    if store is not None and not getattr(store.format, "tag_measured", False):
                        store = None
                    if source is not None:
                        child_abs = source.file_path(child_abs, size)   # opens through the agent
                    if store is not None or cloud is not None:
                        fut = executor.submit(_measure_tagged, measure_file, store, cloud, root,
                                              child_rel, child_abs, st, options, identifier)
                    else:
                        fut = executor.submit(measure_file, root, child_rel, child_abs, st,
                                              options, identifier)
                    frame.pending.append((fut, child_rel, child_abs, st))
                    in_flight = sum(len(f.pending) for f in stack)
                    if in_flight > max_in_flight:
                        # Keep memory and open handles bounded: finish the oldest
                        # outstanding files of the current directory first.
                        had_errors = _drain(frame.pending, len(frame.pending) // 2 or 1) or had_errors
                    frame.idx += 1
                    continue

                if getattr(entry, "special", False):
                    # a FIFO, socket or device on the agent's host: recorded from
                    # its listing, never opened (opening a FIFO blocks)
                    mtime_ns, ctime_ns = stat_times(st)
                    doc = record.new_document(root, child_rel, kind="unknown", size=st.st_size,
                                               mtime_ns=mtime_ns, ctime_ns=ctime_ns, name=name)
                    doc["probe"] = {"special_file": True}
                    fsource.apply_stat_extras(doc, st)
                    _apply_unc(doc, unc)
                    backend.put(doc)
                    if progress:
                        progress(child_abs, 0, "listed")

                # anything else that is neither dir, link nor regular file (device,
                # pipe, ...) -- vanishingly unlikely on Windows; ignore it.
                frame.idx += 1
        plan.complete = not root_frame.incomplete
    finally:
        cancel.set()                # a sum still running (Ctrl+C, an error) stops
        for pool in rollup_pool:
            pool.shutdown(wait=False, cancel_futures=True)
        if plan.sticky is not None:
            plan.sticky.finish()
        if plan.purged:
            # what the walk replaced by rollups must leave no trace anywhere else
            from . import redaction
            try:
                redaction.cleanup(backend, root, plan.purged)
            except Exception as exc:     # never a name: only the kind of failure
                print(f"filecat: {root}: cleaning up after rollups failed ({type(exc).__name__}); "
                      "scan again", file=sys.stderr)
                cleanup_failed = True

    return had_errors or cleanup_failed
