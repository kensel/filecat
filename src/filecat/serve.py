"""`filecat serve`: a local web viewer for a catalog in any backend.

Read-only. Serves one page (filecat/web/index.html) and a JSON API:

    GET /api/info                      backend, location, roots
    GET /api/roots                     the root index (rootinfo.index): scans, state, totals
    GET /api/summary?root=&depth=&rebuild=   stored aggregates for one root
    GET /api/records?<browse query>    Backend.query(), rows trimmed for a table
    GET /api/subtree?root=&parent=     Backend.subtree(): child folders with totals
    GET /api/treemap?root=&prefix=&depth=&refresh=   folders beneath prefix split by extension/type
    GET /api/treemap?id=               one stored snapshot (a pinned one, say)
    GET /api/pins?root=&prefix=&depth= the pinned snapshots of that view, grouped by pin
    GET /api/record?root=&rel_path=    the full stored document
    GET /api/members?root=&rel_path=&offset=&limit=   archive members
    GET /api/backends                  the backends in filecat.toml (plus the one served), which is active
    POST /api/backend  {"key": ...}    switch the viewer to one of them; returns /api/info
    POST /api/pin    {"ids": [...], "label": ...}   pin treemap snapshots together
    POST /api/unpin  {"ids": [...]} or {"at": ...}  unpin snapshots, or a whole pin

The HTTP side is threaded, but every backend call runs on one worker
thread that owns the connection: sqlite3 connections (and some drivers)
must stay on the thread that opened them, and a catalog viewer gains
little from parallel queries. Switching backends is one more job on that
thread, under a lock that also guards the settings it changes. Summaries
are read from the backend's stored aggregates; see Catalog.summary for
when they are computed and saved. Treemaps (treemap.py) read every file
beneath the folder, so each is saved in the catalog as a snapshot and
reused until it is --graph-max-age old; see treemap.py for pins. Apart
from saving aggregates and snapshots, and pinning (all off with
--no-save, which keeps treemaps in memory instead), the server never writes.

There is no authentication: the default bind is 127.0.0.1, and binding
anything else prints a warning.
"""
from __future__ import annotations

import copy
import itertools
import json
import os
import re
import sys
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path, PureWindowsPath
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from . import browse, treemap
from .backends import open_backend

_EMPTY = {"suffix": [], "mime": [], "dir": [], "total_files": 0, "total_bytes": 0, "unreadable": 0}
ROW_FIELDS = ("rel_path", "name", "kind", "size", "mtime_ns", "suffix", "mime", "sha256")
ROLLUP_FIELDS = ("tag", "total_files", "total_dirs", "matched", "partial", "errors", "newest_mtime_ns")
MEMBER_LIMIT = 500
TREEMAP_CACHE = 256
MAX_DEPTH = 6


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


class Catalog:
    """The backend plus the single thread allowed to touch it."""

    def __init__(self, args: Any) -> None:
        self.args = copy.copy(args)  # switching changes backend/out/dsn; leave the caller's alone
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="filecat-backend")
        self._lock = threading.Lock()  # guards a switch and the settings it changes
        self._backend = None
        self._summaries: dict[tuple[str, int], dict[str, Any]] = {}
        self._treemaps: dict[tuple[str, str, int], dict[str, Any]] = {}
        self._started = (self.args.backend, self.args.out, self.args.dsn)
        minutes = getattr(self.args, "graph_max_age", None)
        self.max_age = timedelta(minutes=minutes) if minutes is not None else treemap.MAX_AGE
        self.call(lambda b: None)  # open now, so a bad DSN fails at startup

    def call(self, fn: Callable[[Any], Any]) -> Any:
        def run() -> Any:
            if self._backend is None:
                self._backend = open_backend(self.args.backend, self.args.out, self.args.dsn)
            return fn(self._backend)
        return self._pool.submit(run).result()

    def close(self) -> None:
        if self._backend is not None:
            self._pool.submit(self._backend.close).result()
        self._pool.shutdown()

    # --- API ------------------------------------------------------------
    def info(self, p: dict[str, str]) -> dict[str, Any]:
        with self._lock:
            backend, location = self.args.backend, _location(self.args)
        return {"backend": backend, "location": location, "roots": self.call(lambda b: b.roots())}

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
        return self.info({})

    def roots(self, p: dict[str, str]) -> dict[str, Any]:
        from . import rootinfo
        return {"now": rootinfo.now(), "roots": self.call(rootinfo.index)}

    def summary(self, p: dict[str, str]) -> dict[str, Any]:
        """The stored aggregates for (root, depth) when there are some.

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
        summaries = self._summaries  # a switch replaces the dict; do not write into the new one
        cached = summaries.get(key)
        if cached is None or rebuild:
            result = {"root": root, "depth": depth, "can_save": save, **self.call(build)}
            if result["source"] != "computed":
                return result  # reading it back from storage next time is cheap
            summaries[key] = cached = result
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
        """Snapshots go in the catalog unless --no-save or the backend has no store for them."""
        if self.args.no_save:
            return False
        try:
            b.list_treemaps("")
        except NotImplementedError:
            return False
        return True

    def treemap(self, p: dict[str, str]) -> dict[str, Any]:
        """treemap.build() for the files beneath `prefix` of `root`, or the
        stored snapshot with ?id=. The newest stored snapshot of the view is
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


ROUTES = {"/api/info": "info", "/api/roots": "roots", "/api/summary": "summary", "/api/records": "records",
          "/api/subtree": "subtree", "/api/treemap": "treemap", "/api/record": "record", "/api/members": "members",
          "/api/backends": "backends", "/api/pins": "pins"}
POST_ROUTES = {"/api/backend": "select", "/api/pin": "pin", "/api/unpin": "unpin"}
MAX_BODY = 64 * 1024


def make_handler(catalog: Catalog, page: bytes) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "filecat"

        def log_message(self, fmt: str, *a: Any) -> None:
            if not catalog.args.quiet:
                sys.stderr.write(f"{self.address_string()} {fmt % a}\n")

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data: Any) -> None:
            body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if url.path in ("/", "/index.html"):
                return self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
            method = ROUTES.get(url.path)
            if method is None:
                return self._json(HTTPStatus.NOT_FOUND, {"error": f"no such path {url.path}"})
            params = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
            self._respond(method, params)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
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
            try:
                data = getattr(catalog, method)(params)
            except (KeyError, ValueError) as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": f"{type(exc).__name__}: {exc}"})
            except Exception as exc:  # backend failure: report it, keep serving
                return self._json(HTTPStatus.INTERNAL_SERVER_ERROR,
                                  {"error": f"{type(exc).__name__}: {exc}"})
            if data is None:
                return self._json(HTTPStatus.NOT_FOUND, {"error": "no such record"})
            self._json(HTTPStatus.OK, data)

    return Handler


def run(args: Any) -> int:
    page = resources.files("filecat").joinpath("web/index.html").read_bytes()
    try:
        catalog = Catalog(args)
    except Exception as exc:
        print(f"filecat serve: cannot open {args.backend} backend: {exc}", file=sys.stderr)
        return 1
    try:
        server = ThreadingHTTPServer((args.host, args.port), make_handler(catalog, page))
    except OSError as exc:
        catalog.close()
        print(f"filecat serve: cannot listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1
    host = "127.0.0.1" if args.host in ("", "0.0.0.0") else args.host
    url = f"http://{host}:{server.server_address[1]}/"
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
