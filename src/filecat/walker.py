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
* Cloud placeholders (cloudfiles.py). A file whose attributes say its data
  is not on the device (OneDrive/iCloud online-only, offline/tiered) is
  never opened -- reading it would download it -- and is recorded from its
  directory entry with probe.cloud; --force does not change that. Files in
  a sync root that are on the device are measured and get probe.cloud too.
  A rescan measures a file recorded while cloud-only once it is local.
"""
from __future__ import annotations

import ctypes
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from . import backup, browse, cloudfiles, dbfiles, record
from .backends.base import Backend
from .options import ScanOptions, is_unc
from .resume import ResumeState

FILE_ATTRIBUTE_REPARSE_POINT = 0x400

DEFAULT_SKIP_ROOT_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys"}
DEFAULT_SKIP_DIRS = {"$Recycle.Bin", "System Volume Information"}

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
    unchanged: bool = False
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


def _make_frame(root: str, rel_path: str, abs_path: str, mtime_ns: int, ctime_ns: int,
                entries: list[os.DirEntry], options: ScanOptions, backend: Backend,
                parent_stores: tuple = ()) -> _Frame:
    dir_name = rel_path.rsplit("/", 1)[-1] if rel_path else os.path.basename(abs_path.rstrip("\\/"))
    names = {e.name for e in entries}
    store = backup.detect(rel_path, dir_name, names) or dbfiles.detect(rel_path, dir_name, names)
    if store is not None and store.virtual and not options.measure_backups:
        entries = []    # recorded with its summary, not walked (see backup/__init__.py)
    stored = None if options.force else backend.get(root, rel_path)
    if stored is not None and stored.get("kind") != "dir":
        stored = None
    unchanged = (stored is not None
                 and stored.get("mtime_ns") == mtime_ns
                 and (stored.get("probe") or {}).get("child_count") == len(entries))
    return _Frame(rel_path=rel_path, abs_path=abs_path, mtime_ns=mtime_ns, ctime_ns=ctime_ns,
                  entries=entries, unchanged=unchanged, had_previous=stored is not None,
                  is_drive_root=is_drive_root(abs_path),
                  stores=parent_stores + ((store,) if store else ()), store=store)


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


def _delete_stale_children(backend: Backend, root: str, rel_path: str,
                           entries: list[os.DirEntry]) -> int:
    """A changed directory may have lost entries since the last scan; move
    their stored documents -- and everything stored beneath a vanished
    subdirectory -- to the dropped store (Backend.drop_many) so the catalog
    does not keep ghosts around. Reads only this directory's children
    (Backend.query), not the whole root. Returns how many were dropped."""
    current = {e.name for e in entries}
    dropped = 0
    for rp in _stored_rel_paths(backend, root, parent=rel_path):
        if rp.rsplit("/", 1)[-1] in current:
            continue
        beneath = _stored_rel_paths(backend, root, dir=rp, depth=len(rp.split("/")))
        dropped += backend.drop_many(root, beneath + [rp])
    return dropped


def _apply_unc(doc: dict[str, Any], unc: str | None) -> None:
    if unc is not None:
        doc.setdefault("probe", {})["unc"] = unc


def walk_root(root: str, options: ScanOptions, backend: Backend, identifier: Any,
              resume: ResumeState, measure_file: MeasureFunc, *,
              unc: str | None = None, progress: ProgressFunc | None = None,
              extra_root_errors: list[dict[str, str]] | None = None,
              path: str | None = None) -> bool:
    """Walk one root, writing file/dir documents to `backend` as they are
    finished (post-order for directories). Returns True if any document
    recorded for this root carries an `errors` entry. `path` is where the
    tree is read from when that differs from the recorded `root` (an alias)."""
    had_errors = False
    path = path or root

    try:
        root_st = os.stat(path)
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
        with os.scandir(path) as it:
            root_entries = sorted(it, key=lambda e: e.name)
    except OSError as e:
        doc = record.new_document(root, record.ROOT_REL, kind="dir",
                                   mtime_ns=root_mtime_ns, ctime_ns=root_ctime_ns)
        record.add_error(doc, "listdir", e)
        if extra_root_errors:
            doc.setdefault("errors", []).extend(extra_root_errors)
        _apply_unc(doc, unc)
        backend.put(doc)
        return True

    if options.force:
        resume.forget_root(root)
    root_frame = _make_frame(root, record.ROOT_REL, path, root_mtime_ns, root_ctime_ns,
                              root_entries, options, backend)
    stack: list[_Frame] = [root_frame]

    timeout = options.timeout_for(path)
    exclude = {_norm_path(p) for p in options.exclude}
    max_in_flight = max(1, options.workers) * 4

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
                progress(child_abs, doc.get("size", st.st_size), "measured")
        del pending[:count]
        return errors

    def _store_listing(frame: _Frame) -> dict[str, int]:
        """{path within the store: size} of the files recorded beneath it,
        every one of which is written by now (post-order)."""
        backend.flush()
        cut = len(frame.rel_path) + 1 if frame.rel_path else 0
        return {rel[cut:]: size for rel, size, _, _ in backend.sizes(root, frame.rel_path)}

    def _backup_summary(frame: _Frame, doc: dict[str, Any]) -> None:
        try:
            doc.setdefault("probe", {})[frame.store.probe_key] = backup.summarize(
                frame.store, frame.abs_path, {e.name for e in frame.entries},
                listing=lambda: _store_listing(frame), verify=options.verify_backups)
        except Exception as e:  # a bad manifest must not stop the walk
            record.add_error(doc, frame.store.probe_key, e)

    with ThreadPoolExecutor(max_workers=max(1, options.workers)) as executor:
        while stack:
            frame = stack[-1]

            if frame.idx >= len(frame.entries):
                # Every file of this directory is written before the
                # directory record and its resume marker (post-order).
                had_errors = _drain(frame.pending, len(frame.pending)) or had_errors
                if frame.had_previous and not frame.unchanged:
                    gone = _delete_stale_children(backend, root, frame.rel_path, frame.entries)
                    if gone and progress:
                        progress(frame.abs_path, gone, "dropped")
                doc = record.new_document(root, frame.rel_path, kind="dir",
                                           mtime_ns=frame.mtime_ns, ctime_ns=frame.ctime_ns)
                doc.setdefault("probe", {})["child_count"] = len(frame.entries)
                if frame.store is not None:
                    _backup_summary(frame, doc)
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
                        root, frame.rel_path, frame.mtime_ns, len(frame.entries),
                        child_dirs=[e.name for e in frame.entries])  # unmarked names: no-op
                if stack:
                    stack[-1].idx += 1
                continue

            entry = frame.entries[frame.idx]
            name = entry.name
            child_rel = f"{frame.rel_path}/{name}" if frame.rel_path else name
            child_abs = record.join_root(path, child_rel)

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
                target = read_link_target(child_abs)
                if target is not None:
                    doc.setdefault("probe", {})["link_target"] = target
                _apply_unc(doc, unc)
                if doc.get("errors"):
                    had_errors = True
                backend.put(doc)
                frame.idx += 1
                continue

            if entry.is_dir(follow_symlinks=False):
                if should_skip_dir(name, options.default_skips) or (
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
                    with os.scandir(child_abs) as it:
                        child_entries = sorted(it, key=lambda e: e.name)
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
                mtime_ns, ctime_ns = stat_times(st)
                child_frame = _make_frame(root, child_rel, child_abs, mtime_ns, ctime_ns,
                                          child_entries, options, backend, frame.stores)
                stack.append(child_frame)
                continue  # parent.idx advances only once child_frame is popped

            if entry.is_file(follow_symlinks=False):
                if should_skip_root_file(name, frame.is_drive_root, options.default_skips) or (
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
                    stored = backend.get(root, child_rel)
                    if (stored is not None and stored.get("size") == size
                            and stored.get("mtime_ns") == st.st_mtime_ns
                            and (cloud_only or not _was_cloud_only(stored))):
                        if progress:
                            progress(child_abs, size, "unchanged")
                        frame.idx += 1
                        continue

                cloud = cloudfiles.describe(child_abs, attrs)
                if cloud_only:
                    # opening it would make the provider download it
                    doc = _cloud_listed(root, child_rel, name, st, cloud, identifier)
                    _apply_unc(doc, unc)
                    backend.put(doc)
                    if progress:
                        progress(child_abs, size, "cloud")
                    frame.idx += 1
                    continue

                store = next((s for s in frame.stores if s.opaque(child_rel)), None)
                if store is not None and not store.measured(st, options):
                    doc = _listed_only(root, child_rel, name, st, store)
                    _apply_unc(doc, unc)
                    backend.put(doc)
                    if progress:
                        progress(child_abs, size, "listed")
                    frame.idx += 1
                    continue

                if store is not None and not getattr(store.format, "tag_measured", False):
                    store = None
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

            # anything that is neither dir, link nor regular file (device,
            # pipe, ...) -- vanishingly unlikely on Windows; ignore it.
            frame.idx += 1

    return had_errors
