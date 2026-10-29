"""`filecat serve`: a local web viewer for a catalog in any backend.

Read-only. Serves one page (filecat/web/index.html) and a JSON API:

    GET /api/info                      backend, location, roots
    GET /api/roots                     the root index (rootinfo.index): scans, state, stored totals and how
                                       current each root's summary is; no query per root
    GET /api/summary?root=&depth=&rebuild=   stored aggregates for one root; at depth 2 the stored summary
                                       (summaries.py), stale or "building" while one is rebuilt
    GET /api/records?<browse query>    Backend.query(), rows trimmed for a table
    GET /api/subtree?root=&parent=     Backend.subtree(): child folders with totals
    GET /api/treemap?root=&prefix=&depth=&refresh=   folders beneath prefix split by extension/type; the
                                       root's top at depth 2 is the stored summary, any other view is built
                                       on demand and reused for --graph-max-age
    GET /api/treemap?id=               one stored snapshot (a pinned one, say)
    GET /api/pins?root=&prefix=&depth= the pinned snapshots of that view, grouped by pin
    GET /api/search?q=&root=&host=&ext=&min_size=&max_size=&after=&before=&kind=&sort=&limit=&offset=
                                       file-name search, Everything-style (filecat/search.py); a page of
                                       rows and `more`, never anything inside a rollup
    GET /api/record?root=&rel_path=    the full stored document
    GET /api/members?root=&rel_path=&offset=&limit=   archive members
    GET /api/backends                  the backends in filecat.toml (plus the one served), which is active
    POST /api/backend  {"key": ...}    switch the viewer to one of them; returns /api/info
    GET /api/agents                    filecat server: agent health (live when `filecat server --serve`
                                       runs this viewer, else the last state saved in the catalog)
    GET /api/jobs?limit=&job=&agent=   filecat server: the configured jobs and the recent run history
    GET /api/topology                  storage topology: every host's disks, pools, volumes, shares, LUNs and
                                       VM disks with capacity, the links between hosts, the physical totals,
                                       and each share joined to its catalog root (topology_view.py)
    GET /api/rollups?root=&tag=        `filecat rollups list` as rows by root, tag and parent folder; a
                                       [REDACTED] row is counts only (rollups_view.py)
    POST /api/pin    {"ids": [...], "label": ...}   pin treemap snapshots together
    POST /api/unpin  {"ids": [...]} or {"at": ...}  unpin snapshots, or a whole pin
    POST /api/login {"password": ...}  filecat server --serve only: a session cookie (docs/agent-server.md)
    POST /api/logout                   end the session
    POST /api/jobs/<name>/run          start a job now (needs the session, custom header, same origin)
    POST /api/roots/scan {"root": ...} queue an ad-hoc scan of exactly that root (same guards as run now)
    POST /api/roots/remove {"root": ..., "confirm": <root>}
                                       remove a root that has no records (same guards; 409 otherwise)
    POST /api/summaries/refresh {"root": ...}
                                       queue a rebuild of that root's stored summary (same guards)

The HTTP side is threaded, but every backend call runs on one worker
thread that owns the connection: sqlite3 connections (and some drivers)
must stay on the thread that opened them, and a catalog viewer gains
little from parallel queries. Switching backends is one more job on that
thread, under a lock that also guards the settings it changes. Summaries
are read from the backend's stored aggregates; see Catalog.summary for
when they are computed and saved. Treemaps (treemap.py) read every file
beneath the folder, so each is saved in the catalog as a snapshot; see
treemap.py for pins. Apart from saving aggregates and snapshots, and
pinning (all off with --no-save, which keeps treemaps in memory instead),
the server never writes.

The default views, a root's summary and its treemap at depth 2 from the top, are the stored
summary of summaries.py: served at once while the root has not changed since it was built (however
old), served marked stale while one background thread, on a backend connection of its own,
rebuilds it, and answered `building` when nothing is stored yet. Only the narrower or deeper
treemaps, built on demand, are reused until --graph-max-age old. Responses carry Server-Timing,
JSON over 8 KiB is gzipped when the client accepts it, and a stored summary has an ETag.

Plain HTTP unless TLS is asked for: `--tls self-signed|acme`, `--tls-cert/--tls-key`, or a
[server.tls] table in filecat.toml make the viewer serve HTTPS itself (tls.py; docs/agent-server.md
"TLS"), and the session cookie is then Secure. Encryption is not authentication: without
`filecat server --serve` and its login there is none, the default bind is 127.0.0.1, and binding
anything else prints a warning.
"""
from __future__ import annotations

import copy
import gzip
import itertools
import json
import logging
import os
import queue
import re
import ssl
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path, PureWindowsPath
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from . import browse, config, control_auth, rootinfo, summaries, tls, treemap
from .backends import open_backend

_EMPTY = {"suffix": [], "mime": [], "dir": [], "total_files": 0, "total_bytes": 0, "unreadable": 0}
ROW_FIELDS = ("rel_path", "name", "kind", "size", "mtime_ns", "suffix", "mime", "sha256")
ROLLUP_FIELDS = ("tag", "total_files", "total_dirs", "matched", "partial", "errors", "newest_mtime_ns")
MEMBER_LIMIT = 500
TREEMAP_CACHE = 256
MAX_DEPTH = 6
GZIP_MIN = 8 * 1024         # JSON bodies smaller than this go out as they are
ROOTS_TTL = timedelta(minutes=10)   # how long the distinct roots of the records are trusted
COLD_WAIT = 2.0             # seconds the first look waits for them; a big catalog answers without
log = logging.getLogger("filecat.serve")


def _row(doc: dict[str, Any]) -> dict[str, Any]:
    """A record as one table row: the identity fields plus a few flags."""
    row = {k: doc[k] for k in ROW_FIELDS if doc.get(k) is not None}
    if doc.get("errors"):
        row["errors"] = len(doc["errors"])
    if browse.is_unreadable(doc):
        row["unreadable"] = True
    probe = doc.get("probe") or {}
    if probe.get("child_count") is not None:
        row["child_count"] = probe["child_count"]
    if doc.get("kind") == "rollup":
        row["rollup"] = {k: v for k, v in (probe.get("rollup") or {}).items() if k in ROLLUP_FIELDS}
    return row


def _location(args: Any) -> str:
    if args.backend in ("jsonl", "sqlite"):
        from .backends import DEFAULT_OUT
        return args.out or DEFAULT_OUT[args.backend]
    from .config import mask
    return mask(args.dsn) or "$FILECAT_DSN"


def _short(backend: str, location: str) -> str:
    """A location for a drop-down: the file name, or host/database of a DSN
    (already masked, so no password can appear)."""
    if backend in ("jsonl", "sqlite"):
        return PureWindowsPath(location).name or location
    m = re.search(r"(?i)\bserver=([^;]+)", location)
    if m:  # ODBC style
        db = re.search(r"(?i)\bdatabase=([^;]+)", location)
        return m.group(1) + (f"/{db.group(1)}" if db else "")
    if "://" in location:
        rest = location.split("://", 1)[1]
        host, _, path = rest.partition("/")
        return host.rpartition("@")[2] + ("/" + path.split("?")[0] if path else "")
    return location


class Refresher:
    """One daemon thread that runs the background jobs the viewer asks for (rebuilding a root's stored
    summary, listing the distinct roots), one at a time, so several stale roots queue behind each
    other instead of all reading the catalog at once. A job is named by a key and is queued once
    while it is waiting or running. The jobs open their own backend connection; this class does not."""

    def __init__(self, say: Callable[[str], None]) -> None:
        self._say = say
        self._queue: queue.Queue[Any] = queue.Queue()
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        self._pending: dict[Any, str] = {}      # key -> "queued" | "running"
        self.errors: dict[Any, str] = {}        # key -> why its last run failed
        self._thread: threading.Thread | None = None

    def request(self, key: Any, work: Callable[[], None]) -> bool:
        """Queue `work` unless `key` is already queued or running; True when it was queued."""
        with self._lock:
            if key in self._pending:
                return False
            self._pending[key] = "queued"
            if self._thread is None:
                self._thread = threading.Thread(target=self._loop, name="filecat-refresh", daemon=True)
                self._thread.start()
        self._queue.put((key, work))
        return True

    def state(self, key: Any) -> str | None:
        with self._lock:
            return self._pending.get(key)

    def wait_idle(self, timeout: float = 30.0) -> bool:
        """Block until nothing is queued or running (for tests and shutdown)."""
        with self._changed:
            return self._changed.wait_for(lambda: not self._pending, timeout)

    def wait_key(self, key: Any, timeout: float) -> bool:
        """Block until `key` is neither queued nor running, for at most `timeout` seconds."""
        with self._changed:
            return self._changed.wait_for(lambda: key not in self._pending, timeout)

    def stop(self) -> None:
        self._queue.put(None)

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            key, work = item
            with self._lock:
                self._pending[key] = "running"
            try:
                work()
                self.errors.pop(key, None)
            except Exception as exc:        # keep serving; the page shows why the rebuild failed
                self.errors[key] = f"{type(exc).__name__}: {exc}"
                self._say(f"background {key[-2:]} failed: {self.errors[key]}")
            finally:
                with self._changed:
                    self._pending.pop(key, None)
                    self._changed.notify_all()


class Catalog:
    """The backend plus the single thread allowed to touch it."""

    def __init__(self, args: Any) -> None:
        self.args = copy.copy(args)  # switching changes backend/out/dsn; leave the caller's alone
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="filecat-backend")
        self._lock = threading.Lock()  # guards a switch and the settings it changes
        self._backend = None
        self._summaries: dict[tuple[str, int], dict[str, Any]] = {}
        self._treemaps: dict[tuple[str, str, int], dict[str, Any]] = {}
        self._stores: bool | None = None            # whether the backend stores snapshots (_stores_treemaps)
        self._distinct: set[str] | None = None      # the distinct roots of the records, refreshed in the background
        self._distinct_at: datetime | None = None
        self.refresher = Refresher(lambda m: None if self.args.quiet else sys.stderr.write(f"filecat serve: {m}\n"))
        self._started = (self.args.backend, self.args.out, self.args.dsn)
        self.coordinator: Any = None    # set by `filecat server --serve`: the live agents and jobs
        self.auth: Any = getattr(self.args, "control_auth", None)   # control_auth.ControlAuth or None
        self.args.control_auth = None
        minutes = getattr(self.args, "graph_max_age", None)
        self.max_age = timedelta(minutes=minutes) if minutes is not None else treemap.MAX_AGE
        self.call(lambda b: None)  # open now, so a bad DSN fails at startup
        self._request_roots()

    def call(self, fn: Callable[[Any], Any]) -> Any:
        def run() -> Any:
            if self._backend is None:
                self._backend = open_backend(self.args.backend, self.args.out, self.args.dsn)
            return fn(self._backend)
        return self._pool.submit(run).result()

    def close(self) -> None:
        self.refresher.stop()
        if self._backend is not None:
            self._pool.submit(self._backend.close).result()
        self._pool.shutdown()

    # --- background work: the stored summaries and the distinct roots --------------------------
    def _where(self) -> tuple[Any, ...]:
        """Which catalog this is (backend, out, dsn): a job names the one it was asked for."""
        with self._lock:
            return (self.args.backend, self.args.out, self.args.dsn)

    def _on_own_connection(self, where: tuple[Any, ...], work: Callable[[Any], None]) -> None:
        """Run work(backend) on a backend opened for it, closed after. A jsonl catalog is one file
        a second instance must not write while this one may, so it runs on the worker thread."""
        if where[0] == "jsonl":
            if self._where() == where:
                self.call(work)
            return
        b = open_backend(*where)
        try:
            work(b)
        finally:
            b.close()

    def _queue_refresh(self, root: str) -> bool:
        """Rebuild the stored summary of `root` in the background; False when one is already queued."""
        where = self._where()
        return self.refresher.request((where, "summary", root),
                                      lambda: self._on_own_connection(where, lambda b: summaries.refresh(b, root)))

    def _refreshing(self, root: str) -> str | None:
        return self.refresher.state((self._where(), "summary", root))

    def _request_roots(self) -> None:
        """List the distinct roots of the records in the background: a query over every record, so
        never on a page load. Until it answers the roots are those of the index and stored summaries."""
        where = self._where()
        if where[0] == "jsonl":     # in memory: _known_roots lists it itself, on the backend thread
            return

        def got(b: Any) -> None:
            roots = set(b.roots())
            if self._where() == where:
                self._distinct, self._distinct_at = roots, datetime.now(timezone.utc)
        self.refresher.request((where, "roots"), lambda: self._on_own_connection(where, got))

    def _known_roots(self, b: Any) -> set[str]:
        """The distinct roots seen so far (on the backend thread). A jsonl catalog is in memory:
        listed at once, and again after ROOTS_TTL."""
        now = datetime.now(timezone.utc)
        stale = self._distinct_at is None or now - self._distinct_at > ROOTS_TTL
        if self.args.backend == "jsonl":
            if stale:
                self._distinct, self._distinct_at = set(b.roots()), now
            return set(self._distinct or ())
        if stale:
            self._request_roots()
        if self._distinct is None:      # the first look since start-up or a switch: give a small catalog its moment
            self.refresher.wait_key((self._where(), "roots"), COLD_WAIT)
        return set(self._distinct or ())

    # --- API ------------------------------------------------------------
    def info(self, p: dict[str, str]) -> dict[str, Any]:
        with self._lock:
            backend, location = self.args.backend, _location(self.args)
        return {"backend": backend, "location": location,
                "roots": self.call(lambda b: rootinfo.names(b, self._known_roots(b)))}

    def _options(self) -> list[dict[str, Any]]:
        """Every backend the viewer can switch to: the sections of filecat.toml
        that name a location, then the one served at startup when it is not
        one of them (it may come from the command line). Each entry has the
        settings to open it (out, dsn) and what the page shows (key, backend,
        location, title, available, error); the page never gets the settings,
        which hold unmasked DSNs."""
        from . import config
        from .backends import BACKENDS, DEFAULT_OUT
        options: list[dict[str, Any]] = []

        def add(key: str, backend: str, out: str | None, dsn: str | None, error: str | None = None,
                shown: str | None = None) -> None:
            if backend in config.FILE_BACKENDS:
                out = out or (None if shown else DEFAULT_OUT[backend])
                location = shown or out
            else:
                location = config.mask(dsn) if shown is None else shown
            options.append({"key": key, "backend": backend, "out": out, "dsn": dsn, "error": error,
                            "location": _short(backend, location), "title": location,
                            "available": error is None})

        cfg: dict[str, Any] = {}
        try:
            cfg = config.load(config.find(getattr(self.args, "config", None)))
        except config.ConfigError:
            pass  # the file broke after startup: offer only what is being served
        for name in BACKENDS:
            section = cfg.get(name)
            section = section if isinstance(section, dict) else {}
            if name in config.FILE_BACKENDS and section.get("out"):
                try:
                    out = config.expand(section["out"])
                except config.ConfigError:
                    add(name, name, None, None, "unset: " + ", ".join(config.missing_vars(section["out"])),
                        shown=section["out"])
                    continue
                # opening a missing file would create an empty catalog
                missing = None if Path(out).exists() else "no such file"
                add(name, name, out, None, missing)
            elif name in config.SERVER_BACKENDS and section.get("dsn"):
                raw = section["dsn"]
                try:
                    add(name, name, None, config.expand(raw))
                except config.ConfigError:
                    add(name, name, None, None, "unset: " + ", ".join(config.missing_vars(raw)),
                        shown=config.mask(raw))
        started = self._started
        if not any(self._same(o, *started) for o in options):
            backend, out, dsn = started
            add("startup", backend, out, dsn)
        return options

    @staticmethod
    def _same(option: dict[str, Any], backend: str, out: str | None, dsn: str | None) -> bool:
        if option["backend"] != backend:
            return False
        if backend in ("jsonl", "sqlite"):
            from .backends import DEFAULT_OUT
            same = os.path.normcase(os.path.abspath(option["out"] or ""))
            return same == os.path.normcase(os.path.abspath(out or DEFAULT_OUT[backend]))
        return option["dsn"] == dsn

    def backends(self, p: dict[str, str]) -> dict[str, Any]:
        with self._lock:
            active = (self.args.backend, self.args.out, self.args.dsn)
        shown = ("key", "backend", "location", "title", "available", "error")
        return {"backends": [{**{k: o[k] for k in shown}, "active": self._same(o, *active)}
                             for o in self._options()]}

    def select(self, p: dict[str, str]) -> dict[str, Any]:
        """Switch to the backend with this key. It is opened on the worker
        thread before the old one is closed, so a failure (a server that is
        down, a bad DSN) raises and leaves the current backend serving."""
        option = next((o for o in self._options() if o["key"] == p.get("key")), None)
        if option is None:
            raise ValueError(f"no such backend {p.get('key')!r}")
        if not option["available"]:
            raise ValueError(f"{option['backend']} is unavailable: {option['error']}")

        def swap() -> None:
            new = open_backend(option["backend"], option["out"], option["dsn"])
            old, self._backend = self._backend, new
            if old is not None:
                try:
                    old.close()
                except Exception:  # the new backend is already serving; a bad close is not worth failing for
                    pass

        with self._lock:
            self._pool.submit(swap).result()
            self.args.backend, self.args.out, self.args.dsn = option["backend"], option["out"], option["dsn"]
            self._summaries = {}  # computed summaries belong to the old catalog
            self._treemaps = {}
            self._stores, self._distinct, self._distinct_at = None, None, None
        self._request_roots()
        return self.info({})

    def _server_state(self, read: Callable[[Any], Any]) -> Any:
        """Something the filecat server saved in the catalog; None when the backend keeps none."""
        try:
            return self.call(read)
        except NotImplementedError:
            return None

    def agents(self, p: dict[str, str]) -> dict[str, Any]:
        from . import server_store
        lease = self._server_state(server_store.read_lease)
        if self.coordinator is not None:
            return {"source": "live", "server": lease, "agents": self.coordinator.agents_snapshot(),
                    "updated_at": server_store.iso(datetime.now(timezone.utc))}
        saved = self._server_state(server_store.read_agents) or {}
        return {"source": "catalog", "server": lease, "agents": saved.get("agents", []),
                "updated_at": saved.get("updated_at")}

    def jobs(self, p: dict[str, str]) -> dict[str, Any]:
        from . import server_store
        limit = min(max(int(p.get("limit") or 50), 1), 500)
        recent = self._server_state(lambda b: server_store.recent_runs(b, limit, p.get("job") or None,
                                                                       p.get("agent") or None)) or []
        live = self.coordinator is not None
        return {"source": "live" if live else "catalog", "server": self._server_state(server_store.read_lease),
                "jobs": self.coordinator.jobs_snapshot() if live else [], "recent": recent,
                "control": self.control()}

    def control(self) -> dict[str, Any]:
        """Whether "run now" works here, and if not why (the page shows the reason)."""
        if self.coordinator is None:
            return {"available": False, "reason": "read-only: run `filecat server --serve` to control jobs "
                                                  "(a plain `filecat serve` only shows them)"}
        if self.auth is None or not self.auth.enabled:
            return {"available": False, "reason": "disabled: run `filecat server set-password` and put "
                                                  "control_password_hash in [server] to enable \"run now\""}
        return {"available": True, "reason": None}

    def roots(self, p: dict[str, str]) -> dict[str, Any]:
        """The root index, from the root-index documents and the stored summary totals alone: no
        query per root, no pass over the records. Each row also says how current its stored summary
        is (`summary_state`: fresh, stale, scanning or missing; `refreshing` while one is being
        rebuilt), whether the viewer may remove it (`removable`, judged from the counts the row
        already has; remove_root checks the records itself) and, with a coordinator, why a scan of it
        is already running or queued here (`busy`); `control` is what jobs() reports."""
        rows = self.call(lambda b: rootinfo.index(b, extra_roots=self._known_roots(b)))
        for r in rows:
            r["busy"] = self.coordinator.scanning(r["root"]) if self.coordinator is not None else None
            r["removable"] = self._removable(r) and not r["busy"]
            totals = r["summary"]
            built = totals.get("built_at") if totals and totals.get("depth") == summaries.DEPTH else None
            r["summary_state"] = summaries.state_of(r["info"], built)
            r["refreshing"] = self._refreshing(r["root"])
        return {"now": rootinfo.now(), "roots": rows, "control": self.control(), "stores": self.call(self._stores_treemaps)}

    @staticmethod
    def _removable(row: dict[str, Any]) -> bool:
        """Offered for a root with nothing in it, judged from the row's stored totals and last scan
        (no query); `remove_root` looks at the records again when it is asked."""
        if row["state"] == "in_progress":
            return False
        if row["summary"] is None and row["info"] is None:
            return False        # records and no history: imported, not a typo
        if (row["summary"] or {}).get("total_files"):
            return False
        last = (row["info"] or {}).get("last_scan") or {}
        return not any(last.get(k) for k in ("files", "dirs", "rollups"))

    # --- the Roots page actions (docs/agent-server.md section 7): behind the same guards as run now ---
    def _root_row(self, root: Any) -> dict[str, Any] | None:
        from . import rootinfo
        if not isinstance(root, str) or not root:
            raise ValueError("root must be a root path")
        return next((r for r in self.call(lambda b: rootinfo.index(b, extra_roots=self._known_roots(b)))
                     if r["root"] == root), None)

    def scan_root(self, root: Any, remote: str) -> tuple[int, dict[str, Any]]:
        """POST /api/roots/scan: queue an ad-hoc scan of exactly this root (Coordinator.request_scan)."""
        if self._root_row(root) is None:
            return 404, {"error": f"no such root {root!r}"}
        return self.coordinator.request_scan(root, remote)

    def remove_root(self, root: Any, confirm: Any, remote: str) -> tuple[int, dict[str, Any]]:
        """POST /api/roots/remove: remove a root that has no records (root_remove.remove_root);
        `confirm` must repeat the root string."""
        from . import root_remove
        if self._root_row(root) is None:
            return 404, {"error": f"no such root {root!r}"}
        if confirm != root:
            return 400, {"error": "confirm must repeat the root exactly"}
        busy = self.coordinator.scanning(root)
        if busy:
            return 409, {"error": f"{root} is being scanned here: {busy}"}
        try:
            removed = self.call(lambda b: root_remove.remove_root(b, root))
        except root_remove.RootError as exc:
            return exc.status, {"error": str(exc)}
        self._summaries = {k: v for k, v in self._summaries.items() if k[0] != root}
        self._treemaps = {k: v for k, v in self._treemaps.items() if k[0] != root}
        self._distinct = (self._distinct or set()) - {root}
        self.coordinator.log(f"root {root} removed from the catalog (requested from {remote})")
        return 200, {"removed": removed}

    def refresh_summary(self, root: Any, remote: str) -> tuple[int, dict[str, Any]]:
        """POST /api/summaries/refresh: queue a rebuild of the stored summary of this root."""
        if self._root_row(root) is None:
            return 404, {"error": f"no such root {root!r}"}
        if not self.call(self._stores_treemaps):
            return 409, {"error": "summaries are not stored (--no-save, or the backend cannot store them)"}
        queued = self._queue_refresh(root)
        if self.coordinator is not None:
            self.coordinator.log(f"summary of {root}: refresh requested from {remote}" if queued
                                 else f"summary of {root}: refresh requested from {remote}, one is already queued")
        return 202, {"root": root, "queued": queued, "message": f"the summary of {root} is being rebuilt in "
                     "the background" if queued else f"the summary of {root} is already being rebuilt"}

    def _stored_summary(self, root: str, force: bool) -> dict[str, Any]:
        """The Summary page at the default depth: what is stored, served at once (summaries.py)."""
        def read(b: Any) -> tuple[Any, Any]:
            try:
                info = b.get_root_info(root)
            except NotImplementedError:
                info = None
            return info, b.stored_aggregates(root).get(root)
        info, entry = self.call(read)
        built_at = entry.get("built_at") if entry and entry.get("depth") == summaries.DEPTH else None
        state = summaries.state_of(info, built_at)
        if force or summaries.needs_refresh(state):
            self._queue_refresh(root)
        refreshing = self._refreshing(root) is not None
        flags = {"root": root, "depth": summaries.DEPTH, "can_save": True, "state": state, "refreshing": refreshing,
                 "refresh_error": self.refresher.errors.get((self._where(), "summary", root))}
        if built_at is None:
            return {**_EMPTY, **flags, "source": "building", "building": True, "stale": True}
        return {**entry, **flags, "source": "stored", "building": False, "stale": state != "fresh",
                "_etag": f"{built_at}|{state}|{int(refreshing)}"}

    def summary(self, p: dict[str, str]) -> dict[str, Any]:
        """The stored aggregates for (root, depth) when there are some.

        The default depth (summaries.DEPTH) is the stored summary of summaries.py: served at once,
        `stale` while the root has changed since, `building` when nothing is stored yet, a rebuild
        queued in the background (?rebuild=1 queues one too). Any other depth, and every depth
        with --no-save, is as follows.

        A root with nothing stored is computed and saved, so the next viewer
        (and `filecat summary`) gets it instantly; ?rebuild=1 recomputes and
        saves at the asked-for depth. A root stored at another depth is
        computed without saving, so browsing depths does not replace what
        scans and `summary --rebuild` wrote. With --no-save nothing is
        written and computed results are kept in memory only.
        """
        root, depth = p.get("root") or "", int(p.get("depth") or 2)
        rebuild = bool(p.get("rebuild"))
        save = not self.args.no_save
        if depth == summaries.DEPTH and self.call(self._stores_treemaps):
            return self._stored_summary(root, rebuild)

        def build(b: Any) -> dict[str, Any]:
            stored = b.stored_aggregates(root).get(root)
            if save and (rebuild or stored is None):
                b.rebuild_aggregates(depth=depth, root=root)
                saved = b.stored_aggregates(root).get(root)
                return {**(saved or _EMPTY), "source": "saved"}
            if stored is not None and stored.get("depth") == depth and not rebuild:
                return {**stored, "source": "stored"}
            from .aggregate import build_aggregates
            data = build_aggregates(b.list(root=root), depth=depth)["roots"].get(root)
            return {**(data or _EMPTY), "source": "computed",
                    "stored_depth": stored.get("depth") if stored else None}

        key = (root, depth)
        memo = self._summaries  # a switch replaces the dict; do not write into the new one
        cached = memo.get(key)
        if cached is None or rebuild:
            result = {"root": root, "depth": depth, "can_save": save, **self.call(build)}
            if result["source"] != "computed":
                return result  # reading it back from storage next time is cheap
            memo[key] = cached = result
        return cached

    def records(self, p: dict[str, str]) -> dict[str, Any]:
        q = browse.normalize(p)
        result = self.call(lambda b: b.query(q))
        return {"query": q, "total": result["total"], "bytes": result["bytes"],
                "rows": [_row(d) for d in result["rows"]]}

    def subtree(self, p: dict[str, str]) -> dict[str, Any]:
        root, parent = p["root"], p.get("parent", "").strip("/")

        def run(b: Any) -> list[dict[str, Any]]:
            return browse.with_rollups(b.subtree(root, parent), b.rollups(root, parent), parent)
        return {"root": root, "parent": parent, "folders": self.call(run)}

    def _stores_treemaps(self, b: Any) -> bool:
        """Snapshots (and with them the stored summaries) go in the catalog unless --no-save or the
        backend has no store for them."""
        if self.args.no_save:
            return False
        if self._stores is None:
            try:
                b.list_treemaps("")
                self._stores = True
            except NotImplementedError:
                self._stores = False
        return self._stores

    def _stored_treemap(self, root: str, refresh: bool) -> dict[str, Any]:
        """The Graph page at a root's top at the default depth: the stored summary's treemap, served
        at once whatever its age; stale or missing queues one rebuild (summaries.py)."""
        def read(b: Any) -> tuple[Any, Any]:
            try:
                info = b.get_root_info(root)
            except NotImplementedError:
                info = None
            meta = treemap.newest(b.list_treemaps(root), "", summaries.DEPTH)
            return info, (b.get_treemap(meta["id"]) if meta else None)
        info, found = self.call(read)
        built_at = found[0]["built_at"] if found else None
        state = summaries.state_of(info, built_at)
        if refresh or summaries.needs_refresh(state):
            self._queue_refresh(root)
        refreshing = self._refreshing(root) is not None
        flags = {"state": state, "refreshing": refreshing, "max_age": self.max_age.total_seconds(),
                 "refresh_error": self.refresher.errors.get((self._where(), "summary", root))}
        if found is None:
            return {"root": root, "prefix": "", "depth": summaries.DEPTH, "files": 0, "bytes": 0,
                    "keys": {"suffix": [], "mime": []}, "folders": [], "id": None, "pin": None, "built_at": None,
                    "source": "building", "building": True, "stale": True, "can_pin": False, **flags}
        meta, data = found
        return {**data, **meta, "source": "stored", "building": False, "stale": state != "fresh", "can_pin": True,
                **flags, "_etag": f"{meta['id']}|{state}|{int(refreshing)}"}

    def treemap(self, p: dict[str, str]) -> dict[str, Any]:
        """treemap.build() for the files beneath `prefix` of `root`, or the
        stored snapshot with ?id=. A root's top at depth 2 is the stored
        summary (_stored_treemap), whatever its age. For any other view the
        newest stored snapshot is
        served while it is younger than --graph-max-age ("source": "stored");
        otherwise, or with ?refresh=1, it is built and saved ("saved"). With
        nothing to save it in, results are kept in memory for the same time
        ("computed", then "memory")."""
        max_age = self.max_age

        if p.get("id"):
            def stored(b: Any) -> dict[str, Any] | None:
                found = b.get_treemap(p["id"]) if self._stores_treemaps(b) else None
                if found is None:
                    return None
                meta, data = found
                return {**data, **meta, "source": "pinned" if meta.get("pin") else "stored"}
            result = self.call(stored)
            return result and {**result, "can_pin": True, "max_age": max_age.total_seconds()}

        root, prefix = p["root"], (p.get("prefix") or "").strip("/")
        depth = min(MAX_DEPTH, max(1, int(p.get("depth") or 2)))
        refresh = bool(p.get("refresh"))
        now = datetime.now(timezone.utc)
        if not prefix and depth == summaries.DEPTH and self.call(self._stores_treemaps):
            return self._stored_treemap(root, refresh)

        def build(b: Any) -> dict[str, Any]:
            if not self._stores_treemaps(b):
                return {"store": False}
            current = None if refresh else treemap.newest(b.list_treemaps(root), prefix, depth)
            if current is not None and treemap.age(current, now) < max_age:
                found = b.get_treemap(current["id"])
                if found is not None:
                    return {**found[1], **found[0], "source": "stored"}
            data = treemap.build(b.sizes(root, prefix), prefix, depth, rollups=b.rollups(root, prefix))
            meta = treemap.save(b, root, data, datetime.now(timezone.utc).isoformat())
            return {**data, **meta, "source": "saved"}

        result = self.call(build)
        if result.pop("store", True):
            return {**result, "can_pin": True, "max_age": max_age.total_seconds()}

        key = (root, prefix, depth)
        treemaps = self._treemaps  # a switch replaces the dict; do not write into the new one
        cached = treemaps.get(key)
        if cached is not None and not refresh and treemap.age(cached, now) < max_age:
            return {**cached, "source": "memory"}
        cached = {"root": root, **self.call(lambda b: treemap.build(b.sizes(root, prefix), prefix, depth, rollups=b.rollups(root, prefix))),
                  "built_at": datetime.now(timezone.utc).isoformat(), "id": None, "pin": None, "can_pin": False,
                  "max_age": max_age.total_seconds()}
        treemaps.pop(key, None)
        treemaps[key] = cached
        while len(treemaps) > TREEMAP_CACHE:
            treemaps.pop(next(iter(treemaps)))
        return {**cached, "source": "computed"}

    def pins(self, p: dict[str, str]) -> dict[str, Any]:
        """The pins with a snapshot of (prefix, depth), of `root` or of every root."""
        prefix = (p.get("prefix") or "").strip("/")
        depth = min(MAX_DEPTH, max(1, int(p.get("depth") or 2)))
        root = p.get("root") or None

        def run(b: Any) -> list[dict[str, Any]]:
            return treemap.pins(b, prefix, depth, root) if self._stores_treemaps(b) else []
        return {"pins": self.call(run)}

    def pin(self, p: dict[str, Any]) -> dict[str, Any]:
        """POST {"ids": [snapshot ids], "label": text}: pin them together."""
        ids = p.get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise ValueError("ids must be a list of snapshot ids")
        label = p.get("label")
        if label is not None and not isinstance(label, str):
            raise ValueError("label must be text")

        def run(b: Any) -> dict[str, Any]:
            if not self._stores_treemaps(b):
                raise ValueError("snapshots are not stored (--no-save, or the backend cannot store them)")
            at = datetime.now(timezone.utc).isoformat()
            return {"pin": {"at": at, "label": (label or "").strip() or None},
                    "snapshots": treemap.pin(b, ids, label, at)}
        return self.call(run)

    def unpin(self, p: dict[str, Any]) -> dict[str, Any]:
        """POST {"ids": [...]} or {"at": pin time}: unpin snapshots."""
        ids, at = p.get("ids") or [], p.get("at")
        bad_ids = not isinstance(ids, list) or not all(isinstance(i, str) for i in ids)
        if bad_ids or (at is not None and not isinstance(at, str)) or not (ids or at):
            raise ValueError("send ids (a list of snapshot ids) or at (a pin time)")

        def run(b: Any) -> dict[str, Any]:
            if not self._stores_treemaps(b):
                raise ValueError("snapshots are not stored (--no-save, or the backend cannot store them)")
            return {"unpinned": treemap.unpin(b, ids, at)}
        return self.call(run)

    def record(self, p: dict[str, str]) -> dict[str, Any] | None:
        from . import samples

        def run(b: Any) -> dict[str, Any] | None:
            doc = samples.attach_one(b, b.get(p["root"], p["rel_path"]))
            if doc is not None and doc.get("kind") == "rollup":
                # the inspector card of a [BACKUP] / [DATABASE] shows the store it belongs to
                ref = ((doc.get("probe") or {}).get("rollup") or {}).get("store") or {}
                store = b.get(p["root"], ref["path"]) if ref.get("path") is not None else None
                if store is not None:
                    keep = {k: v for k, v in (store.get("probe") or {}).items()
                            if k in ("backup", "database", "store_note")}
                    doc = {**doc, "store_record": {"rel_path": store["rel_path"], "name": store.get("name"),
                                                   "probe": keep}}
            return doc
        return self.call(run)

    def members(self, p: dict[str, str]) -> dict[str, Any]:
        offset = max(0, int(p.get("offset") or 0))
        limit = min(MEMBER_LIMIT, max(1, int(p.get("limit") or 100)))

        def page(b: Any) -> dict[str, Any]:
            try:
                it = b.members_of(p["root"], p["rel_path"])
                rows = list(itertools.islice(it, offset, offset + limit + 1))
            except NotImplementedError:
                return {"supported": False, "rows": [], "more": False}
            return {"supported": True, "rows": rows[:limit], "more": len(rows) > limit}
        return {"offset": offset, "limit": limit, **self.call(page)}

    def topology(self, p: dict[str, str]) -> dict[str, Any]:
        """The storage topology of every host with the shares joined to their catalog roots
        (topology_view.py); empty `hosts` when `filecat storage collect` has not run."""
        from . import topology_view
        path = getattr(self.args, "config", None)
        return self.call(lambda b: topology_view.build(b, path))

    def rollups(self, p: dict[str, str]) -> dict[str, Any]:
        """The audit of `filecat rollups list` by root, tag and parent folder (rollups_view.py);
        a [REDACTED] row is counts only."""
        from . import rollups_view
        return self.call(lambda b: rollups_view.build(b, p.get("root") or None, p.get("tag") or None))

    # --- search (filecat/search.py) ------------------------------------------
    def search(self, p: dict[str, str]) -> dict[str, Any]:
        """GET /api/search?q=&root=&host=&ext=&min_size=&max_size=&after=&before=&kind=&sort=&desc=&limit=&offset=

        File-name search (Everything-style, see filecat.search): `q` holds name patterns and
        `key:value` filters, the other parameters add to them. Returns one page of
        {name, folder, root, host, size, mtime_ns, kind, rel_path, ...} rows, `more` when another
        page follows (no total: see Backend.search_names), the parsed criteria and the time taken.
        Rows are the stored records matched by their own name; nothing inside a rollup exists to
        match, so a [REDACTED] or [CACHE] folder is found as itself."""
        from . import search as srch
        started = time.perf_counter()
        spec = srch.with_params(srch.parse_query(p.get("q")), p)
        if not srch.has_criteria(spec):
            raise ValueError("type a name pattern or a filter (ext:, size:, root:, host:, ...)")
        query_roots = srch.resolve_roots(spec, self.call(lambda b: b.roots()))
        q = srch.to_query(spec, query_roots, sort=p.get("sort"), desc=p.get("desc"),
                          offset=p.get("offset"), limit=p.get("limit"))
        found = {"rows": [], "more": False} if query_roots == [] else self.call(lambda b: b.search_names(q))
        rows = []
        for doc in found["rows"]:
            row = _row(doc)
            rel = doc.get("rel_path") or ""
            root = doc.get("root") or ""
            rows.append({**row, "root": root, "host": srch.host_of(root), "folder": browse.parent_of(rel)})
        return {"query": srch.describe(spec), "rows": rows, "more": found["more"], "offset": q["offset"],
                "limit": q["limit"], "sort": q["sort"], "desc": q["desc"],
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)}


ROUTES = {"/api/info": "info", "/api/roots": "roots", "/api/summary": "summary", "/api/records": "records",
          "/api/subtree": "subtree", "/api/treemap": "treemap", "/api/record": "record", "/api/members": "members",
          "/api/backends": "backends", "/api/pins": "pins", "/api/agents": "agents", "/api/jobs": "jobs",
          "/api/search": "search"}
ROUTES.update({"/api/topology": "topology", "/api/rollups": "rollups"})
POST_ROUTES = {"/api/backend": "select", "/api/pin": "pin", "/api/unpin": "unpin"}
ROOT_ACTIONS = {"/api/roots/scan": "scan_root", "/api/roots/remove": "remove_root",
                "/api/summaries/refresh": "refresh_summary"}   # POST only, like run now
RUN_PATH = re.compile(r"^/api/jobs/([A-Za-z0-9._@-]{1,128})/run$")      # POST only: "run now"
CONTROL_HEADER = "X-Filecat-Control"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")
MAX_BODY = 64 * 1024


def make_handler(catalog: Catalog, page: bytes) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "filecat"

        _elapsed: float | None = None       # ms the API call took, for the access log

        def log_message(self, fmt: str, *a: Any) -> None:
            if not catalog.args.quiet:
                took = f" {self._elapsed:.1f}ms" if self._elapsed is not None else ""
                sys.stderr.write(f"{self.address_string()} {fmt % a}{took}\n")

        def _send(self, status: int, body: bytes, ctype: str, headers: dict[str, str] | None = None,
                  compress: bool = False) -> None:
            if compress and len(body) > GZIP_MIN and "gzip" in (self.headers.get("Accept-Encoding") or ""):
                body = gzip.compress(body, 5)
                headers = {**(headers or {}), "Content-Encoding": "gzip"}
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if compress:
                self.send_header("Vary", "Accept-Encoding")
            if not (headers or {}).get("ETag"):
                self.send_header("Cache-Control", "no-store")
            else:
                self.send_header("Cache-Control", "no-cache")      # keep it, but ask whether it is still current
            self.end_headers()
            if status != HTTPStatus.NOT_MODIFIED:
                self.wfile.write(body)

        def _json(self, status: int, data: Any, headers: dict[str, str] | None = None) -> None:
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8", headers, compress=True)

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if url.path in ("/", "/index.html"):
                return self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
            if RUN_PATH.match(url.path) or url.path in ("/api/login", "/api/logout") or url.path in ROOT_ACTIONS:
                return self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "POST only"}, {"Allow": "POST"})
            method = ROUTES.get(url.path)
            if method is None:
                return self._json(HTTPStatus.NOT_FOUND, {"error": f"no such path {url.path}"})
            if catalog.auth is not None and catalog.auth.login_required_for_view and not self._logged_in():
                return self._json(HTTPStatus.UNAUTHORIZED, {"error": "log in first", "login": True})
            params = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
            self._respond(method, params)

        # --- control: login, logout, run now (docs/agent-server.md "Run now") ---------------------
        def _session(self) -> str | None:
            try:
                jar = SimpleCookie(self.headers.get("Cookie") or "")
            except Exception:
                return None
            return jar[control_auth.COOKIE].value if control_auth.COOKIE in jar else None

        def _logged_in(self) -> bool:
            return bool(catalog.auth is not None and catalog.auth.sessions.valid(self._session()))

        def _tls(self) -> bool:
            """This connection is TLS served by filecat itself (not a proxy's)."""
            return isinstance(self.connection, ssl.SSLSocket)

        def _csrf_ok(self) -> bool:
            """Same-origin, custom header, JSON: a browser cannot send this cross-site without a CORS
            preflight, which this server never answers. Sends the refusal and returns False."""
            if self.headers.get(CONTROL_HEADER) != "run":
                self._json(HTTPStatus.FORBIDDEN, {"error": f"missing header {CONTROL_HEADER}: run"})
                return False
            if self.headers.get_content_type() != "application/json":
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "send application/json"})
                return False
            host = self.headers.get("Host") or ""
            origin = self.headers.get("Origin")
            if origin is not None:
                parts = urlsplit(origin)
                if parts.scheme not in (("https",) if self._tls() else ("http", "https")) or parts.netloc != host:
                    self._json(HTTPStatus.FORBIDDEN, {"error": "cross-origin request refused"})
                    return False
            # DNS rebinding: bound to loopback, the Host must be a loopback name
            if catalog.args.host in LOOPBACK_HOSTS and host.rpartition(":")[0].lower() not in LOOPBACK_HOSTS \
                    and host.lower() not in LOOPBACK_HOSTS:
                self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
                return False
            return True

        def _body(self) -> dict[str, Any] | None:
            """The JSON object body (empty = {}); sends the 400 and returns None when it is not one."""
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if not 0 <= length <= MAX_BODY:
                    raise ValueError("body too large")
                body = json.loads(self.rfile.read(length)) if length else {}
                if not isinstance(body, dict):
                    raise ValueError("body must be a JSON object")
                return body
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": f"{type(exc).__name__}: {exc}"})
                return None

        def _control_ready(self) -> bool:
            control = catalog.control()
            if not control["available"]:
                code = HTTPStatus.NOT_FOUND if catalog.coordinator is None else HTTPStatus.FORBIDDEN
                self._json(code, {"error": control["reason"]})
                return False
            return self._csrf_ok()

        def _login(self) -> None:
            auth = catalog.auth
            if not self._control_ready():
                return
            body = self._body()
            if body is None:
                return
            ip = self.client_address[0]
            wait = auth.guard.retry_after(ip)
            if wait:
                auth.guard.fail(ip)                 # trying while blocked lengthens the block
                wait = auth.guard.retry_after(ip) or wait
                return self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "too many failed logins; try later",
                                                                 "retry_after": wait}, {"Retry-After": str(wait)})
            # always one scrypt, whatever the request looks like, so timing says nothing
            if control_auth.verify_password(body.get("password"), auth.password_hash):
                auth.guard.success(ip)
                sid = auth.sessions.create()
                secure = "; Secure" if self._tls() or (self.headers.get("Origin") or "").startswith("https:") else ""
                cookie = f"{control_auth.COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/{secure}"
                return self._json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": cookie})
            auth.guard.fail(ip)
            time.sleep(auth.fail_delay)
            wait = auth.guard.retry_after(ip)
            extra = {"Retry-After": str(wait)} if wait else None
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "wrong password"}, extra)

        def _logout(self) -> None:
            if not self._control_ready():
                return
            catalog.auth.sessions.drop(self._session())
            cookie = f"{control_auth.COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            self._json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": cookie})

        def _run_job(self, name: str) -> None:
            """POST /api/jobs/<name>/run: a valid session AND the CSRF checks; nothing is started
            otherwise."""
            if not self._control_ready():
                return
            if not self._logged_in():
                return self._json(HTTPStatus.UNAUTHORIZED, {"error": "log in first", "login": True})
            if self._body() is None:
                return
            status, data = catalog.coordinator.request_run(name, self.client_address[0])
            self._json(status, data)

        def _root_action(self, action: str) -> None:
            """POST /api/roots/scan {"root"} and /api/roots/remove {"root", "confirm"}: exactly the
            guards of _run_job (coordinator and password configured, session, CSRF header, JSON,
            same origin); nothing happens otherwise."""
            if not self._control_ready():
                return
            if not self._logged_in():
                return self._json(HTTPStatus.UNAUTHORIZED, {"error": "log in first", "login": True})
            body = self._body()
            if body is None:
                return
            try:
                if action == "scan_root":
                    status, data = catalog.scan_root(body.get("root"), self.client_address[0])
                elif action == "refresh_summary":
                    status, data = catalog.refresh_summary(body.get("root"), self.client_address[0])
                else:
                    status, data = catalog.remove_root(body.get("root"), body.get("confirm"),
                                                       self.client_address[0])
            except ValueError as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:     # backend failure: report it, keep serving
                return self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            self._json(status, data)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            run = RUN_PATH.match(path)
            if run:
                return self._run_job(run.group(1))
            if path in ROOT_ACTIONS:
                return self._root_action(ROOT_ACTIONS[path])
            if path == "/api/login":
                return self._login()
            if path == "/api/logout":
                return self._logout()
            if catalog.auth is not None and catalog.auth.login_required_for_view and not self._logged_in():
                return self._json(HTTPStatus.UNAUTHORIZED, {"error": "log in first", "login": True})
            method = POST_ROUTES.get(path)
            if method is None:
                return self._json(HTTPStatus.NOT_FOUND, {"error": f"no such path {path}"})
            # JSON only: a cross-site form post cannot send it without a CORS preflight
            if self.headers.get_content_type() != "application/json":
                return self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "send application/json"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if not 0 < length <= MAX_BODY:
                    raise ValueError("body missing or too large")
                params = json.loads(self.rfile.read(length))
                if not isinstance(params, dict):
                    raise ValueError("body must be a JSON object")
            except ValueError as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": f"{type(exc).__name__}: {exc}"})
            self._respond(method, params)

        def _respond(self, method: str, params: dict[str, Any]) -> None:
            started = time.perf_counter()

            def timed() -> dict[str, str]:
                self._elapsed = (time.perf_counter() - started) * 1000
                log.debug("%s %s %.1fms", self.command, self.path, self._elapsed)
                return {"Server-Timing": f"app;dur={self._elapsed:.1f}", "X-Filecat-Time": f"{self._elapsed:.1f}ms"}
            try:
                data = getattr(catalog, method)(params)
            except (KeyError, ValueError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": f"{type(exc).__name__}: {exc}"}, timed())
            except Exception as exc:  # backend failure: report it, keep serving
                return self._json(HTTPStatus.INTERNAL_SERVER_ERROR,
                                  {"error": f"{type(exc).__name__}: {exc}"}, timed())
            if data is None:
                return self._json(HTTPStatus.NOT_FOUND, {"error": "no such record"}, timed())
            etag = data.pop("_etag", None) if isinstance(data, dict) else None
            headers = timed()
            if etag is not None:        # a stored summary: its built_at and state say whether it changed
                headers["ETag"] = tag = f'W/"{etag}"'
                wanted = [t.strip() for t in (self.headers.get("If-None-Match") or "").split(",")]
                if tag in wanted or "*" in wanted:
                    return self._send(HTTPStatus.NOT_MODIFIED, b"", "application/json; charset=utf-8", headers)
            self._json(HTTPStatus.OK, data, headers)

    return Handler


class Viewer:
    """A viewer running in a thread of this process (`filecat server --serve`)."""

    def __init__(self, httpd: ThreadingHTTPServer, catalog: Catalog) -> None:
        self.httpd, self.catalog = httpd, catalog
        self._stop = threading.Event()
        scheme = "https" if isinstance(httpd, tls.TlsHTTPServer) else "http"
        if isinstance(httpd, tls.TlsHTTPServer):
            tls.start_renewal(httpd.tls, self._stop)      # once a day: renew, reload into the live context
        self.url = f"{scheme}://{'127.0.0.1' if httpd.server_address[0] in ('', '0.0.0.0') else httpd.server_address[0]}:" \
                   f"{httpd.server_address[1]}/"
        self._thread = threading.Thread(target=httpd.serve_forever, name="filecat-viewer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.catalog.close()


def _listen(args: Any, catalog: Catalog, page: bytes, tls_cfg: tls.TlsConfig | None) -> ThreadingHTTPServer:
    """Bind args.host:args.port; with tls_cfg over HTTPS (certificate made or loaded now, its fingerprint
    printed). Raises OSError (the bind) or tls.TlsError (no certificate)."""
    handler = make_handler(catalog, page)
    if tls_cfg is None:
        return ThreadingHTTPServer((args.host, args.port), handler)
    manager = tls.TlsManager(tls_cfg, args.host, tls.default_dir(getattr(args, "out", None)))
    manager.start()
    httpd = tls.TlsHTTPServer((args.host, args.port), handler, manager)
    for line in manager.banner():
        print(f"filecat serve: {line}", file=sys.stderr)
    return httpd


def start_viewer(args: Any, coordinator: Any = None) -> Viewer | None:
    """Open the catalog and serve the page on args.host:args.port in a thread; None (after saying
    why) when either fails. With a coordinator the agent and job endpoints are live. args.tls (a
    tls.TlsConfig, from [server.tls] and the flags) makes it HTTPS, renewed daily while it runs."""
    page = resources.files("filecat").joinpath("web/index.html").read_bytes()
    try:
        catalog = Catalog(args)
    except Exception as exc:
        print(f"filecat serve: cannot open {args.backend} backend: {exc}", file=sys.stderr)
        return None
    catalog.coordinator = coordinator
    try:
        httpd = _listen(args, catalog, page, getattr(args, "tls", None))
    except tls.TlsError as exc:
        catalog.close()
        print(f"filecat serve: {exc}", file=sys.stderr)
        return None
    except OSError as exc:
        catalog.close()
        print(f"filecat serve: cannot listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        return None
    viewer = Viewer(httpd, catalog)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"filecat serve: warning: listening on {args.host or 'all interfaces'} with no "
              "authentication; anyone who can reach it can read the catalog", file=sys.stderr)
    print(f"filecat serve: {args.backend} ({_location(args)}) at {viewer.url}", file=sys.stderr)
    return viewer


def run(args: Any) -> int:
    page = resources.files("filecat").joinpath("web/index.html").read_bytes()
    try:
        cfg = config.load(config.find(getattr(args, "config", None)))
        tls_cfg = tls.effective(tls.parse_table((cfg.get("server") or {}).get("tls")), args,
                                (cfg.get("server") or {}).get("tls"))
    except config.ConfigError as exc:
        print(f"filecat serve: {exc}", file=sys.stderr)
        return 2
    try:
        catalog = Catalog(args)
    except Exception as exc:
        print(f"filecat serve: cannot open {args.backend} backend: {exc}", file=sys.stderr)
        return 1
    try:
        server = _listen(args, catalog, page, tls_cfg)
    except tls.TlsError as exc:
        catalog.close()
        print(f"filecat serve: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        catalog.close()
        print(f"filecat serve: cannot listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1
    host = "127.0.0.1" if args.host in ("", "0.0.0.0") else args.host
    url = f"{'https' if isinstance(server, tls.TlsHTTPServer) else 'http'}://{host}:{server.server_address[1]}/"
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"filecat serve: warning: listening on {args.host or 'all interfaces'} with no "
              "authentication; anyone who can reach it can read the catalog", file=sys.stderr)
    print(f"filecat serve: {args.backend} ({_location(args)}) at {url}  (Ctrl+C stops)")
    if args.open:
        threading.Timer(0.5, webbrowser.open, (url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        catalog.close()
    return 0
