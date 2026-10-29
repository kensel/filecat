"""The root index: one document per root recording its scans.

    {"root_id", "root", "updated_at",
     "last_attempt": {"started_at", "finished_at", "status", "host", "pid", "path", "error",
                      "account": {"user", "source"}, "agent", "heartbeat_at",
                      "progress": {"files", "dirs", "bytes", "errors", "last_path"}},
     "last_scan":    {"started_at", "finished_at", "seconds", "status", "host", "account",
                      "agent", "files", "dirs", "bytes", "errors", "rollups", "rollup_bytes"},
     "last_error":   {"at", "rel_path", "stage", "message"},
     "changed_at":   when the root's records last changed (microseconds, UTC; see touch())
     "newest_file":  {"rel_path", "mtime_ns"},
     "suggestions":  {"items": [{"tag", "parent", "matched"}], "more", "at"},
     "rollup_unresolved": ["[[rollups.rule]] #3 ([CACHE])"]}

`last_attempt` is written as status "running" before a root is walked and
updated when the walk ends. While it runs, the scan rewrites it every
HEARTBEAT_SECONDS with `heartbeat_at` and its progress so far. A scan that
was killed leaves "running" behind with a heartbeat that stops; state()
tells the two apart (in_progress vs stalled). Statuses:

    ok           walked, no record written by this scan has errors
    errors       walked, some records carry errors (see last_error)
    unreachable  the root itself could not be stat()ed or listed
    interrupted  Ctrl+C / KeyboardInterrupt
    failed       any other exception escaped the walk (message in "error")

`path` is present when the root was read through an alias (aliases.py).
`agent` is the name of the filecat-agent the root was read through, absent
for an SMB or local scan; rootcase.py takes the spelling of a root scanned
through an agent to be the NAS's. `account` is the account the root was read
with (netaccount.py) when it could be told; preflight.py warns when it differs from the last scan's.
`last_scan` is the last attempt that finished walking (ok / errors /
unreachable). Its counts are of the records this scan wrote; files a
rescan skipped as unchanged are not counted. `last_error` is the last
error any scan recorded and is kept by later clean scans, with its time.
`newest_file` is the most recently modified file in the catalog for the
root, looked up after the walk, so unchanged files count too.

`changed_at` is the root's change stamp: every writer of a root's records sets
it (a scan that wrote or removed a file, rollup migrate, case-merge, redaction
release / approve, enrich; touch()), and the stored summaries (summaries.py)
are fresh while they are built after it. A scan that found nothing to write
leaves it alone, so an unchanged root keeps its summary however old.
"""
from __future__ import annotations

import os
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import browse
from .backends.base import Backend, Document
from .record import ROOT_REL, HardLinks, root_id


HEARTBEAT_SECONDS = 30.0
# A "running" attempt whose heartbeat is older than this is reported stalled.
STALE_AFTER = timedelta(seconds=HEARTBEAT_SECONDS * 4)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def now_precise() -> str:
    """For change stamps: a summary built in the same second as a change must not look newer."""
    return datetime.now(timezone.utc).isoformat()


def parse(text: Any) -> datetime | None:
    try:
        at = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def changed_stamp(info: Document | None) -> datetime | None:
    """When the root's records last changed, as far as its index entry says: `changed_at`; for an
    entry written before that existed, the end of its last scan. A "running" attempt (a scan in
    progress, or one that was killed) counts from its last heartbeat, since it writes as it goes."""
    info = info or {}
    stamps = [parse(info.get("changed_at"))]
    if info.get("changed_at") is None:
        stamps.append(parse((info.get("last_scan") or {}).get("finished_at")))
    attempt = info.get("last_attempt") or {}
    if attempt.get("status") == "running":
        stamps.append(parse(attempt.get("heartbeat_at") or attempt.get("started_at")))
    return max((s for s in stamps if s is not None), default=None)


def touch(backend: Backend, root: str, at: str | None = None) -> None:
    """Record that `root`'s records changed (the change stamp the stored summaries are judged by).
    For writers other than a scan, which stamps it in finish(). A catalog with no root index
    keeps no stamp; summaries then go by their age alone, so this never fails the caller."""
    try:
        info = _load(backend, root)
        info["changed_at"] = at or now_precise()
        backend.put_root_info(info)
    except NotImplementedError:
        pass


def state(info: Document | None, at: datetime | None = None) -> str:
    """What the root's last attempt amounts to right now: "in_progress",
    "stalled" (says running, but its heartbeat stopped: killed or hung),
    the finished attempt's status, or "never" when there is no attempt."""
    attempt = (info or {}).get("last_attempt")
    if not attempt:
        return "never"
    if attempt.get("status") != "running":
        return attempt.get("status") or "unknown"
    beat = attempt.get("heartbeat_at") or attempt.get("started_at")
    try:
        age = (at or datetime.now(timezone.utc)) - datetime.fromisoformat(beat)
    except (TypeError, ValueError):
        return "stalled"
    return "in_progress" if age <= STALE_AFTER else "stalled"


def in_progress(backend: Backend) -> list[str]:
    """Roots a scan is walking right now (a stalled one is not counted)."""
    try:
        infos = list(backend.list_root_info())
    except NotImplementedError:
        return []
    return sorted(i["root"] for i in infos if state(i) == "in_progress")


class ScanTracker:
    """Wraps the backend handed to walk_root and watches what it writes."""

    def __init__(self, backend: Backend, root: str, heartbeat: float | None = None) -> None:
        self._backend = backend
        self.root = root
        self.files = self.dirs = self.bytes = self.errors = 0
        self.rollups = self.rollup_bytes = 0    # rollup records are not files (record.NON_FILE_KINDS)
        self.removed = 0    # records deleted or dropped (a vanished file changes the summary too)
        self.last_error: dict[str, Any] | None = None
        self._links = HardLinks()   # a hard-linked file's bytes are counted once
        self.last_path = ""
        self.unreachable = False
        self.attempt: dict[str, Any] | None = None  # set by begin(); enables heartbeats
        self._heartbeat = HEARTBEAT_SECONDS if heartbeat is None else heartbeat
        self._last_beat = time.monotonic()

    def progress(self) -> dict[str, Any]:
        out = {"files": self.files, "dirs": self.dirs, "bytes": self.bytes,
               "errors": self.errors, "last_path": self.last_path}
        if self.rollups:
            out.update(rollups=self.rollups, rollup_bytes=self.rollup_bytes)
        return out

    def beat(self) -> None:
        """Rewrite the running attempt with the progress so far."""
        self._last_beat = time.monotonic()
        if self.attempt is None:
            return
        self.attempt.update(heartbeat_at=now(), progress=self.progress())
        try:
            info = _load(self._backend, self.root)
            info["last_attempt"] = dict(self.attempt)
            info["updated_at"] = self.attempt["heartbeat_at"]
            self._backend.put_root_info(info)
        except Exception:  # bookkeeping must never stop a scan
            pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._backend, name)

    @property
    def changed(self) -> bool:
        """The scan wrote or removed something a summary counts. Directory records do not count:
        every scan rewrites them, and no summary reads them."""
        return bool(self.files or self.rollups or self.removed)

    def delete(self, root: str, rel_path: str) -> None:
        self._backend.delete(root, rel_path)
        self.removed += 1

    def delete_many(self, root: str, rel_paths: Any) -> int:
        n = self._backend.delete_many(root, rel_paths)
        self.removed += n
        return n

    def drop_many(self, root: str, rel_paths: Any, reason: str = "vanished") -> int:
        n = self._backend.drop_many(root, rel_paths, reason)
        self.removed += n
        return n

    def _observe(self, doc: Document) -> None:
        self.last_path = doc.get("rel_path", "")
        kind = doc.get("kind")
        if kind == "dir":
            self.dirs += 1
        elif kind == "rollup":
            self.rollups += 1
            self.rollup_bytes += doc.get("size") or 0
        else:
            self.files += 1
            self.bytes += self._links.counted_doc(doc)
        errors = doc.get("errors")
        if errors:
            self.errors += 1
            last = errors[-1]
            self.last_error = {"at": now(), "rel_path": doc.get("rel_path", ""),
                               "stage": last.get("stage"), "message": last.get("message")}
            if doc.get("rel_path") == ROOT_REL and any(
                    e.get("stage") in ("stat", "listdir") for e in errors):
                self.unreachable = True
        if time.monotonic() - self._last_beat >= self._heartbeat:
            self.beat()

    def put(self, document: Document) -> None:
        self._observe(document)
        self._backend.put(document)

    def store(self, document: Document) -> None:
        self._observe(document)
        self._backend.store(document)


def _load(backend: Backend, root: str) -> Document:
    info = backend.get_root_info(root)
    return info or {"root_id": root_id(root), "root": root}


def begin(backend: Backend, root: str, tracker: ScanTracker | None = None,
          path: str | None = None, account: dict[str, str] | None = None,
          agent: str | None = None) -> dict[str, Any]:
    """Record that a scan of `root` is starting; returns the attempt. With a
    tracker, the tracker heartbeats this attempt while the walk runs. `path`
    is where it is read from, when an alias makes that differ from `root`."""
    started = now()
    attempt = {"started_at": started, "finished_at": None, "status": "running",
               "host": socket.gethostname(), "pid": os.getpid(), "heartbeat_at": started}
    if path and path != root:
        attempt["path"] = path
    if account:
        attempt["account"] = account
    if agent:
        attempt["agent"] = agent
    if tracker is not None:
        tracker.attempt = attempt
    info = _load(backend, root)
    info["last_attempt"] = attempt
    info["updated_at"] = attempt["started_at"]
    backend.put_root_info(info)
    return attempt


def newest_file(backend: Backend, root: str) -> dict[str, Any] | None:
    q = browse.normalize({"root": root, "files_only": "1", "sort": "mtime_ns", "desc": "1", "limit": "1"})
    rows = backend.query(q)["rows"]
    if not rows or rows[0].get("mtime_ns") is None:
        return None
    return {"rel_path": rows[0]["rel_path"], "mtime_ns": rows[0]["mtime_ns"]}


def finish(backend: Backend, root: str, attempt: dict[str, Any], tracker: ScanTracker,
           exc: BaseException | None = None, extra: dict[str, Any] | None = None) -> Document:
    """Record how the attempt ended. Never raises: the scan's own outcome
    matters more than its bookkeeping. `extra` is merged into the entry
    (the rollup suggestions of a complete scan)."""
    finished = now()
    if exc is not None:
        status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
    elif tracker.unreachable:
        status = "unreachable"
    else:
        status = "errors" if tracker.errors else "ok"
    attempt = {**attempt, "finished_at": finished, "status": status, "heartbeat_at": finished,
               "progress": tracker.progress()}
    tracker.attempt = None
    if exc is not None:
        attempt["error"] = f"{type(exc).__name__}: {exc}".strip()
    info = _load(backend, root)
    if tracker.changed:
        info["changed_at"] = now_precise()
    elif info.get("changed_at") is None:    # an entry from before the stamp: its last scan is the stamp
        info["changed_at"] = (info.get("last_scan") or {}).get("finished_at") or attempt["started_at"]
    info["last_attempt"] = attempt
    info["updated_at"] = finished
    if exc is None:
        started = datetime.fromisoformat(attempt["started_at"])
        info["last_scan"] = {
            "started_at": attempt["started_at"], "finished_at": finished, "status": status,
            "seconds": round((datetime.fromisoformat(finished) - started).total_seconds(), 1),
            "host": attempt["host"], "files": tracker.files, "dirs": tracker.dirs,
            "bytes": tracker.bytes, "errors": tracker.errors,
        }
        if tracker.rollups:
            info["last_scan"].update(rollups=tracker.rollups, rollup_bytes=tracker.rollup_bytes)
        if attempt.get("account"):
            info["last_scan"]["account"] = attempt["account"]
        if attempt.get("agent"):
            info["last_scan"]["agent"] = attempt["agent"]
    if tracker.last_error is not None:
        info["last_error"] = tracker.last_error
    elif exc is not None:
        info["last_error"] = {"at": finished, "rel_path": None, "stage": "scan",
                              "message": attempt["error"]}
    try:
        newest = newest_file(backend, root)
    except Exception:  # bookkeeping only
        newest = None
    if newest is not None:
        info["newest_file"] = newest
    if extra:
        info.update(extra)
    try:
        backend.put_root_info(info)
    except Exception:
        pass
    return info


def index(backend: Backend, extra_roots: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Every root that has a root-index entry or stored summary totals, and those in `extra_roots`;
    with its entry (None when it was never scanned since the index existed, e.g. imported) and the
    stored summary totals when there are some. `extra_roots` defaults to the distinct roots of the
    records (Backend.roots(), a pass over every record on a big catalog): a caller that knows the
    roots another way, as the viewer does, hands them in instead. No query is made per root."""
    try:
        infos = {i["root"]: i for i in backend.list_root_info()}
    except NotImplementedError:
        infos = {}
    try:
        stored = backend.stored_totals()
    except NotImplementedError:
        stored = {}
    known = backend.roots() if extra_roots is None else extra_roots
    out = []
    for root in sorted(set(known) | set(infos) | set(stored)):
        totals = stored.get(root)
        info = infos.get(root)
        out.append({"root": root, "info": info, "state": state(info), "summary": totals})
    return out


def names(backend: Backend, extra_roots: Iterable[str] | None = None) -> list[str]:
    """The roots index() lists, by name only (the viewer's root selector)."""
    try:
        found = {i["root"] for i in backend.list_root_info()}
    except NotImplementedError:
        found = set()
    found |= set(backend.stored_totals())
    found |= set(backend.roots() if extra_roots is None else extra_roots)
    return sorted(found)
