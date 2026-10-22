"""The root index: one document per root recording its scans.

    {"root_id", "root", "updated_at",
     "last_attempt": {"started_at", "finished_at", "status", "host", "pid", "path", "error",
                      "account": {"user", "source"}, "heartbeat_at",
                      "progress": {"files", "dirs", "bytes", "errors", "last_path"}},
     "last_scan":    {"started_at", "finished_at", "seconds", "status", "host", "account",
                      "files", "dirs", "bytes", "errors"},
     "last_error":   {"at", "rel_path", "stage", "message"},
     "newest_file":  {"rel_path", "mtime_ns"}}

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
`account` is the account the root was read with (netaccount.py) when it
could be told; preflight.py warns when it differs from the last scan's.
`last_scan` is the last attempt that finished walking (ok / errors /
unreachable). Its counts are of the records this scan wrote; files a
rescan skipped as unchanged are not counted. `last_error` is the last
error any scan recorded and is kept by later clean scans, with its time.
`newest_file` is the most recently modified file in the catalog for the
root, looked up after the walk, so unchanged files count too.
"""
from __future__ import annotations

import os
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from . import browse
from .backends.base import Backend, Document
from .record import ROOT_REL, root_id


HEARTBEAT_SECONDS = 30.0
# A "running" attempt whose heartbeat is older than this is reported stalled.
STALE_AFTER = timedelta(seconds=HEARTBEAT_SECONDS * 4)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
        self.last_error: dict[str, Any] | None = None
        self.last_path = ""
        self.unreachable = False
        self.attempt: dict[str, Any] | None = None  # set by begin(); enables heartbeats
        self._heartbeat = HEARTBEAT_SECONDS if heartbeat is None else heartbeat
        self._last_beat = time.monotonic()

    def progress(self) -> dict[str, Any]:
        return {"files": self.files, "dirs": self.dirs, "bytes": self.bytes,
                "errors": self.errors, "last_path": self.last_path}

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

    def _observe(self, doc: Document) -> None:
        self.last_path = doc.get("rel_path", "")
        if doc.get("kind") == "dir":
            self.dirs += 1
        else:
            self.files += 1
            self.bytes += doc.get("size") or 0
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
          path: str | None = None, account: dict[str, str] | None = None) -> dict[str, Any]:
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
           exc: BaseException | None = None) -> Document:
    """Record how the attempt ended. Never raises: the scan's own outcome
    matters more than its bookkeeping."""
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
        if attempt.get("account"):
            info["last_scan"]["account"] = attempt["account"]
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
    try:
        backend.put_root_info(info)
    except Exception:
        pass
    return info


def index(backend: Backend) -> list[dict[str, Any]]:
    """Every root that has records or a root-index entry, with its entry
    (None when it was never scanned since the index existed, e.g. imported)
    and the stored summary totals when there are some."""
    try:
        infos = {i["root"]: i for i in backend.list_root_info()}
    except NotImplementedError:
        infos = {}
    try:
        stored = backend.stored_aggregates()
    except NotImplementedError:
        stored = {}
    out = []
    for root in sorted(set(backend.roots()) | set(infos)):
        agg = stored.get(root)
        totals = None if agg is None else {k: agg.get(k) for k in
                                           ("total_files", "total_bytes", "unreadable", "built_at")}
        info = infos.get(root)
        out.append({"root": root, "info": info, "state": state(info), "summary": totals})
    return out
