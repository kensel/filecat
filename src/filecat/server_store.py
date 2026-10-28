"""The filecat server's catalog state: job history and the single-instance lease
(docs/agent-server.md section 6).

Two stores of whole documents, in every backend (`Backend.put_server_doc`, `server_docs`,
`delete_server_doc`, on the storage topology's row primitives):

    server_jobs   one document per run, key "<started_at>#<job>"
    server_state  key "lease": {holder, host, pid, started_at, renewed_at, expires_at}
                  key "agents": {agents: [...], updated_at}

The module-level functions take a backend and are what `filecat serve` reads with; `ServerStore`
runs them on one thread that owns the connection (a SQLite connection may not change threads).
"""
from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

JOBS = "server_jobs"
STATE = "server_state"
LEASE_KEY = "lease"
AGENTS_KEY = "agents"
FINAL = ("ok", "errors", "failed", "cancelled", "skipped", "lost")


def iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_iso(text: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(text) if text else None
    except ValueError:
        return None


def _state(backend: Any, key: str) -> dict[str, Any] | None:
    return next((d for d in backend.server_docs(STATE) if d.get("key") == key), None)


# --- reading (a viewer needs nothing more) --------------------------------------------------------
def read_lease(backend: Any, now: datetime | None = None) -> dict[str, Any] | None:
    doc = _state(backend, LEASE_KEY)
    if doc is None:
        return None
    now = now or datetime.now(timezone.utc)
    expires = parse_iso(doc.get("expires_at"))
    return {k: v for k, v in doc.items() if k not in ("key", "host_key")} | {
        "alive": bool(expires and expires > now)}


def read_agents(backend: Any) -> dict[str, Any] | None:
    return _state(backend, AGENTS_KEY)


def recent_runs(backend: Any, limit: int = 50, job: str | None = None,
                agent: str | None = None) -> list[dict[str, Any]]:
    """Run documents, newest first."""
    rows = [d for d in backend.server_docs(JOBS)
            if (job is None or d.get("job") == job) and (agent is None or d.get("agent") == agent)]
    rows.sort(key=lambda d: (d.get("started_at") or "", d.get("key") or ""), reverse=True)
    return [{k: v for k, v in d.items() if k != "key"} for d in rows[:max(1, limit)]]


def last_starts(backend: Any) -> dict[str, datetime]:
    """When each job last really started (a skipped run is not a start)."""
    out: dict[str, datetime] = {}
    for d in backend.server_docs(JOBS):
        if d.get("outcome") == "skipped":
            continue
        when = parse_iso(d.get("started_at"))
        if when and (d["job"] not in out or when > out[d["job"]]):
            out[d["job"]] = when
    return out


# --- the thread that owns the connection ----------------------------------------------------------
class Handle:
    """One worker thread that opens the backend lazily and runs every call on it."""

    def __init__(self, opener: Callable[[], Any]) -> None:
        self._opener = opener
        self._queue: queue.Queue = queue.Queue()
        self._backend: Any = None
        self._thread = threading.Thread(target=self._loop, name="filecat-server-catalog", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                break
            fn, box, done = item
            try:
                if self._backend is None:
                    self._backend = self._opener()
                box.append((True, fn(self._backend)))
            except BaseException as exc:        # handed back to the caller
                box.append((False, exc))
            done.set()
        if self._backend is not None:
            try:
                self._backend.close()
            except Exception:
                pass

    def call(self, fn: Callable[[Any], Any]) -> Any:
        box: list[tuple[bool, Any]] = []
        done = threading.Event()
        self._queue.put((fn, box, done))
        done.wait()
        ok, value = box[0]
        if not ok:
            raise value
        return value

    def close(self) -> None:
        self._queue.put(None)
        self._thread.join(timeout=10)


@dataclass
class LeaseResult:
    ok: bool
    holder: dict[str, Any] | None       # the lease row as it stands (ours when ok)


class ServerStore:
    def __init__(self, handle: Handle, clock: Callable[[], datetime]) -> None:
        self.handle = handle
        self.clock = clock

    # --- lease ---
    def acquire(self, holder: str, host: str, pid: int, ttl: timedelta) -> LeaseResult:
        """Take the lease when it is free, expired or already ours: check, write, read back."""
        def fn(b: Any) -> LeaseResult:
            now = self.clock()
            doc = _state(b, LEASE_KEY)
            if doc and doc.get("holder") != holder:
                expires = parse_iso(doc.get("expires_at"))
                if expires and expires > now:
                    return LeaseResult(False, doc)
            mine = {"key": LEASE_KEY, "host": host, "holder": holder, "pid": pid,
                    "started_at": (doc or {}).get("started_at") if doc and doc.get("holder") == holder else iso(now),
                    "renewed_at": iso(now), "scanned_at": iso(now), "expires_at": iso(now + ttl)}
            b.put_server_doc(STATE, mine)
            back = _state(b, LEASE_KEY)
            return LeaseResult(bool(back and back.get("holder") == holder), back)
        return self.handle.call(fn)

    def renew(self, holder: str, ttl: timedelta) -> bool:
        """Extend our lease; False when another server holds it now (we were replaced)."""
        def fn(b: Any) -> bool:
            doc = _state(b, LEASE_KEY)
            if not doc or doc.get("holder") != holder:
                return False
            now = self.clock()
            b.put_server_doc(STATE, {**doc, "renewed_at": iso(now), "scanned_at": iso(now),
                                     "expires_at": iso(now + ttl)})
            return True
        return self.handle.call(fn)

    def release(self, holder: str) -> None:
        def fn(b: Any) -> None:
            doc = _state(b, LEASE_KEY)
            if doc and doc.get("holder") == holder:
                b.delete_server_doc(STATE, LEASE_KEY)
        self.handle.call(fn)

    def lease(self) -> dict[str, Any] | None:
        return self.handle.call(lambda b: read_lease(b, self.clock()))

    # --- runs ---
    def put_run(self, row: dict[str, Any]) -> None:
        doc = {**row, "key": f"{row['started_at']}#{row['job']}#{row.get('run', '')}", "host": row.get("agent") or "-",
               "scanned_at": row["started_at"]}
        self.handle.call(lambda b: b.put_server_doc(JOBS, doc))

    def recent(self, limit: int = 50, job: str | None = None, agent: str | None = None) -> list[dict[str, Any]]:
        return self.handle.call(lambda b: recent_runs(b, limit, job, agent))

    def last_starts(self) -> dict[str, datetime]:
        return self.handle.call(last_starts)

    def mark_lost(self, holder: str) -> int:
        """Runs a dead server left `running` are `lost` (called with the lease in hand)."""
        def fn(b: Any) -> int:
            n = 0
            for d in b.server_docs(JOBS):
                if d.get("outcome") == "running":
                    b.put_server_doc(JOBS, {**d, "outcome": "lost", "ended_at": iso(self.clock()),
                                            "error": "the server that started this run stopped without ending it"})
                    n += 1
            return n
        return self.handle.call(fn)

    def prune(self, keep: int, days: int) -> int:
        def fn(b: Any) -> int:
            cutoff = iso(self.clock() - timedelta(days=days))
            rows = sorted(b.server_docs(JOBS), key=lambda d: (d.get("started_at") or "", d["key"]), reverse=True)
            n = 0
            for i, d in enumerate(rows):
                if d.get("outcome") != "running" and (i >= keep or (d.get("started_at") or "") < cutoff):
                    b.delete_server_doc(JOBS, d["key"])
                    n += 1
            return n
        return self.handle.call(fn)

    # --- agent states ---
    def save_agents(self, agents: list[dict[str, Any]]) -> None:
        now = iso(self.clock())
        doc = {"key": AGENTS_KEY, "host": "server", "scanned_at": now, "updated_at": now, "agents": agents}
        self.handle.call(lambda b: b.put_server_doc(STATE, doc))

    def agents(self) -> dict[str, Any] | None:
        return self.handle.call(read_agents)
