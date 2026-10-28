"""`filecat server`: the coordinator (docs/agent-server.md).

Holds the [[agents]], probes their health, runs the [[server.jobs]] on their schedules as threads of
this process (calling the functions the commands call), records every run in the catalog, keeps a
lease there so two servers do not both run jobs, and can serve the web viewer from the same process.

    filecat server [--serve [HOST:PORT]] [--once] [--dry-run] [--job NAME ...]

Exit codes: 0 clean (every run ok), 1 a run ended errors/failed/cancelled, 2 bad config or catalog,
3 the lease was lost to another server, 4 another server holds the lease.
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from . import agent_status, config, control_auth, scheduler, server_cfg, server_store
from .server_cfg import JobSpec, ServerConfig
from .server_store import ServerStore, iso

FILE_BACKENDS = ("sqlite", "jsonl")
TICK = 1.0
SCAN_PROGRESS_SECONDS = 60.0


def log(message: str) -> None:
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} filecat server: {message}", file=sys.stderr, flush=True)


def local_now() -> datetime:
    return datetime.now().astimezone()


# --- job results and the runners ------------------------------------------------------------------
@dataclass
class JobResult:
    outcome: str                                # ok | errors | failed | cancelled | skipped
    exit_code: int | None = None
    counts: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class JobContext:
    spec: JobSpec
    agent: config.AgentConfig
    agents: list[config.AgentConfig]
    cfg: dict[str, Any]                         # the parsed filecat.toml
    catalog: argparse.Namespace                 # backend / out / dsn the server was started with
    cancel: threading.Event
    log: Callable[[str], None] = log


def _argv_args(ctx: JobContext, argv: list[str]) -> argparse.Namespace:
    """The namespace `filecat <argv>` would run with, with the file applied and the catalog the
    server's own."""
    args = server_cfg.parse_cli(argv)
    config.apply(args, ctx.cfg)
    for name in ("backend", "out", "dsn"):
        if hasattr(args, name):
            setattr(args, name, getattr(ctx.catalog, name, None))
    return args


def _open(ctx: JobContext) -> Any:
    from .backends import open_backend
    return open_backend(ctx.catalog.backend, ctx.catalog.out, ctx.catalog.dsn)


def agent_roots(ctx: JobContext, backend: Any) -> list[str]:
    """The job's roots: its `roots`, or every catalog root this agent covers plus the shares of the
    agent's stored topology snapshot."""
    if ctx.spec.roots:
        return list(ctx.spec.roots)
    agent = ctx.agent
    roots: dict[str, str] = {}
    for root in backend.roots():
        covering = config.agent_for(ctx.agents, root)
        if covering is not None and covering.name == agent.name:
            roots.setdefault(root.lower(), root)
    try:
        snap = backend.get_topology(agent.alias.strip("\\/"))
    except NotImplementedError:
        snap = None
    for root in (snap or {}).get("unc_roots", []):
        roots.setdefault(root.lower(), root)
    return sorted(roots.values(), key=str.lower)


def _scan_counts(backend: Any, roots: list[str]) -> dict[str, Any]:
    from . import rootinfo
    wanted = {r.lower() for r in roots}
    counts = {"roots": len(roots), "files": 0, "dirs": 0, "bytes": 0, "errors": 0}
    try:
        for entry in rootinfo.index(backend):
            last = (entry.get("info") or {}).get("last_scan")
            if last and entry["root"].lower() in wanted:
                for key in ("files", "dirs", "bytes", "errors"):
                    counts[key] += int(last.get(key) or 0)
    except NotImplementedError:
        pass
    return counts


def _run_scan(ctx: JobContext, roots: list[str], backend: Any) -> JobResult:
    from . import resume, scan
    from .options import ScanOptions
    args = _argv_args(ctx, ["scan", *roots, *ctx.spec.options, "--agent", ctx.agent.name])
    options = ScanOptions.from_args(args)
    options.cancel = ctx.cancel
    options.progress_interval = SCAN_PROGRESS_SECONDS
    base = resume.resume_path_for(getattr(backend, "name", "backend"), getattr(backend, "path", None))
    slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in ctx.spec.name)
    path = base.replace(".resume.json", f".{slug}.resume.json")      # jobs run side by side: own file
    code = scan.scan_roots(roots, backend, options, resume_path=path)
    counts = _scan_counts(backend, roots)
    outcome = {0: "ok", 1: "errors"}.get(code, "failed")
    return JobResult(outcome, code, counts, None if code < 2 else f"scan exited {code}")


def run_scan_job(ctx: JobContext) -> JobResult:
    backend = _open(ctx)
    try:
        roots = agent_roots(ctx, backend)
        if not roots:
            return JobResult("skipped", counts={"roots": 0}, error="no roots: name them in roots = [...] "
                             "or run a storage-collect so the agent's shares are known")
        return _run_scan(ctx, roots, backend)
    finally:
        backend.close()


def run_storage_collect_job(ctx: JobContext) -> JobResult:
    from . import storage_cmd, topology_store
    args = _argv_args(ctx, ["storage", "collect", *ctx.spec.options, "--agent", ctx.agent.name])
    storage = config.load_storage(ctx.cfg)
    topo, info = storage_cmd.collect_agent(ctx.agent, platform=args.platform,
                                           measure_shares=args.measure_shares)
    if ctx.cancel.is_set():
        raise scan_cancelled()
    backend = _open(ctx)
    try:
        result = topology_store.save_snapshot(backend, topo, agent=info, others=storage.hosts,
                                              manual=storage.links)
    finally:
        backend.close()
    return JobResult("ok", 0, {"nodes": len(topo.nodes), "changed": bool(result.changed),
                               "first": bool(result.first)})


def run_store_resum_job(ctx: JobContext, now: Callable[[], datetime] = local_now) -> JobResult:
    from . import rootinfo
    days = config.load_rollups(ctx.cfg).store_resum_days
    min_age = ctx.spec.min_age or timedelta(days=max(days - 1, 0))
    backend = _open(ctx)
    try:
        roots = agent_roots(ctx, backend)
        known = {e["root"].lower(): e for e in rootinfo.index(backend)}
        stale = []
        for root in roots:
            last = ((known.get(root.lower()) or {}).get("info") or {}).get("last_scan") or {}
            finished = server_store.parse_iso(last.get("finished_at"))
            if finished is None or now() - finished > min_age:
                stale.append(root)
        if not stale:
            return JobResult("ok", 0, {"roots": len(roots), "stale_roots": 0})
        result = _run_scan(ctx, stale, backend)
        result.counts["stale_roots"] = len(stale)
        return result
    finally:
        backend.close()


def scan_cancelled() -> BaseException:
    from .scan import ScanCancelled
    return ScanCancelled()


RUNNERS: dict[str, Callable[[JobContext], JobResult]] = {
    "scan": run_scan_job, "storage-collect": run_storage_collect_job, "store-resum": run_store_resum_job,
}


# --- state ----------------------------------------------------------------------------------------
@dataclass
class AgentState:
    name: str
    endpoint: str
    state: str = "unknown"                  # unknown | up | down
    since: str | None = None
    last_check: str | None = None
    last_error: str | None = None
    version: str | None = None
    platform: str | None = None
    allowlist_match: bool | None = None
    deny_match: bool | None = None
    warnings: list[str] = field(default_factory=list)
    failures: int = 0
    next_check: datetime | None = None
    checking: bool = False

    def to_dict(self, running: str | None = None) -> dict[str, Any]:
        return {"name": self.name, "endpoint": self.endpoint, "state": self.state, "since": self.since,
                "last_check": self.last_check, "last_error": self.last_error, "version": self.version,
                "platform": self.platform, "allowlist_match": self.allowlist_match,
                "deny_match": self.deny_match, "warnings": list(self.warnings), "failures": self.failures,
                "next_check": iso(self.next_check) if self.next_check else None, "running": running}


@dataclass
class Run:
    spec: JobSpec
    row: dict[str, Any]
    cancel: threading.Event
    started: float                          # time.monotonic()
    thread: threading.Thread | None = None
    result: JobResult | None = None
    timed_out: bool = False


class Coordinator:
    def __init__(self, cfg: ServerConfig, agents: list[config.AgentConfig], store: ServerStore, *,
                 file_cfg: dict[str, Any], catalog: argparse.Namespace,
                 clock: Callable[[], datetime] = local_now,
                 probe: Callable[..., agent_status.AgentStatus] = agent_status.probe,
                 runners: dict[str, Callable[[JobContext], JobResult]] | None = None,
                 logger: Callable[[str], None] = log, holder: str | None = None) -> None:
        self.cfg = cfg
        self.agents = {a.name: a for a in agents}
        self.store = store
        self.file_cfg = file_cfg
        self.catalog = catalog
        self.clock = clock
        self.probe = probe
        self.runners = runners or RUNNERS
        self.log = logger
        self.holder = holder or uuid.uuid4().hex[:16]
        self.max_concurrent = cfg.max_concurrent or (1 if (catalog.backend or "sqlite") in FILE_BACKENDS else 2)
        last = store.last_starts()
        self.sched = scheduler.Scheduler(cfg.jobs, last, self._first_seen(last))
        self.manual: dict[str, str] = {}        # job -> remote address: "run now" requests not started yet
        self.health: dict[str, AgentState] = {n: AgentState(n, a.endpoint) for n, a in self.agents.items()}
        self.runs: dict[str, Run] = {}
        self.last_outcome: dict[str, str] = {}
        self.outcomes: list[str] = []           # every run finished in this session
        self.lost = False
        self.stopping = False
        self.health_enabled = True
        self._lock = threading.RLock()
        self._dirty = True
        self._lease_renewed: datetime | None = None
        self._last_prune: datetime | None = None
        for row in reversed(store.recent(500)):
            self.last_outcome[row["job"]] = row["outcome"]

    def _first_seen(self, last: dict[str, datetime]) -> dict[str, datetime]:
        """When each job that never ran was first seen: saved in the catalog the first time, so a
        restart does not keep postponing its first run (jobs with run_on_start need none)."""
        try:
            seen = self.store.first_seen()
            new = {j.name: self.clock() for j in self.cfg.jobs
                   if j.enabled and not j.run_on_start and j.name not in last and j.name not in seen}
            if new:
                seen = {**seen, **new}
                self.store.save_first_seen(seen)
        except NotImplementedError:
            return {}
        return seen

    # --- "run now" (the viewer's POST /api/jobs/<name>/run) ---
    def request_run(self, name: str, remote: str) -> tuple[int, dict[str, Any]]:
        """Queue a manual run of `name`: (http status, body). The next tick starts it through the
        scheduler, so the per-agent exclusivity and the concurrency limit still apply."""
        spec = next((j for j in self.cfg.jobs if j.name == name), None)
        if spec is None:
            return 404, {"error": f"no such job {name!r}"}
        if not spec.enabled:
            return 409, {"error": f"job {name} is disabled in filecat.toml"}
        if self.lost or self.stopping:
            return 409, {"error": "this server is stopping or has lost the catalog lease"}
        with self._lock:
            if name in self.runs or name in self.manual:
                return 409, {"error": f"job {name} is already running" if name in self.runs
                             else f"job {name} is already queued to run"}
            if self.health[spec.agent].state == "down":
                return 409, {"error": f"agent {spec.agent} is down"}
            self.manual[name] = remote
        self.log(f"job {name}: run requested from {remote}")
        return 202, {"job": name, "queued": True,
                     "message": f"{name} will start now, or as soon as agent {spec.agent} and the "
                                "concurrency limit allow"}

    # --- lease ---
    def acquire(self) -> server_store.LeaseResult:
        res = self.store.acquire(self.holder, socket.gethostname(), os.getpid(), self.cfg.lease_ttl)
        if res.ok:
            self._lease_renewed = self.clock()
            lost = self.store.mark_lost(self.holder)
            if lost:
                self.log(f"{lost} run(s) left running by a stopped server marked lost")
            self._prune(self.clock())
        return res

    def _renew(self, now: datetime) -> None:
        if self._lease_renewed is not None and now - self._lease_renewed < self.cfg.lease_ttl / 3:
            return
        if self.store.renew(self.holder, self.cfg.lease_ttl):
            self._lease_renewed = now
        else:
            self.lost = True
            self.log("the lease is held by another server now: stopping")

    def _prune(self, now: datetime) -> None:
        if self._last_prune is None or now - self._last_prune > timedelta(hours=24):
            n = self.store.prune(self.cfg.history_keep, self.cfg.history_days)
            self._last_prune = now
            if n:
                self.log(f"history: {n} old run(s) removed")

    # --- health ---
    def probe_due(self, now: datetime, wait: bool = False) -> None:
        threads = []
        for state in self.health.values():
            with self._lock:
                if state.checking or (state.next_check and state.next_check > now):
                    continue
                state.checking = True
            t = threading.Thread(target=self._probe_one, args=(state.name,), daemon=True)
            t.start()
            threads.append(t)
        if wait:
            for t in threads:
                t.join()

    def _probe_one(self, name: str) -> None:
        try:
            status = self.probe(self.agents[name], self.cfg.health_timeout.total_seconds())
        except Exception as exc:
            status = agent_status.AgentStatus(name, self.agents[name].endpoint, error=agent_status.error_text(exc))
        self.record_health(name, status, self.clock())

    def record_health(self, name: str, status: agent_status.AgentStatus, now: datetime) -> None:
        with self._lock:
            st = self.health[name]
            st.checking = False
            st.last_check = iso(now)
            if status.ok:
                if st.state != "up":
                    self.log(f"agent {name} is up" + (f" (filecat-agent {status.version})" if status.version else ""))
                    st.state, st.since = "up", iso(now)
                st.failures, st.last_error = 0, None
                st.version, st.platform = status.version, status.platform
                st.allowlist_match, st.deny_match = status.allowlist_match, status.deny_match
                if status.warnings and status.warnings != st.warnings:
                    self.log(f"agent {name}: {'; '.join(status.warnings)}")
                st.warnings = list(status.warnings)
                st.next_check = now + self.cfg.health_interval
            else:
                st.failures += 1
                if st.state != "down":
                    self.log(f"agent {name} is down: {status.error}")
                    st.state, st.since = "down", iso(now)
                st.last_error = status.error
                delay = min(self.cfg.health_interval * 2 ** (st.failures - 1), self.cfg.health_backoff_max)
                st.next_check = now + delay
            self._dirty = True

    # --- running jobs ---
    def _row(self, spec: JobSpec, now: datetime, trigger: str, outcome: str, error: str | None = None,
             remote: str | None = None) -> dict[str, Any]:
        row = {"run": uuid.uuid4().hex[:8], "job": spec.name, "kind": spec.kind, "agent": spec.agent,
               "roots": list(spec.roots) if spec.roots else None, "started_at": iso(now), "ended_at": None,
               "outcome": outcome, "exit_code": None, "trigger": trigger, "counts": {}, "error": error,
               "server": self.holder}
        if remote:
            row["requested_from"] = remote        # the web viewer's "run now": the caller's address only
        if outcome == "skipped":
            row["ended_at"] = row["started_at"]
        return row

    def _start(self, spec: JobSpec, now: datetime, trigger: str, remote: str | None = None) -> None:
        run = Run(spec, self._row(spec, now, trigger, "running", remote=remote), threading.Event(), time.monotonic())
        self.store.put_run(run.row)
        self.runs[spec.name] = run
        self.last_outcome[spec.name] = "running"
        self.log(f"job {spec.name} ({spec.kind}, agent {spec.agent}) started")
        run.thread = threading.Thread(target=self._work, args=(run,), name=f"filecat-job-{spec.name}", daemon=True)
        run.thread.start()
        self._dirty = True

    def _work(self, run: Run) -> None:
        spec = run.spec
        ctx = JobContext(spec, self.agents[spec.agent], list(self.agents.values()), self.file_cfg,
                         self.catalog, run.cancel, self.log)
        try:
            run.result = self.runners[spec.kind](ctx)
        except KeyboardInterrupt:           # ScanCancelled
            run.result = JobResult("cancelled", error="cancelled")
        except Exception as exc:
            run.result = JobResult("failed", error=agent_status.error_text(exc))

    def _finish(self, run: Run, now: datetime) -> None:
        res = run.result or JobResult("cancelled", error="still stopping when the server exited")
        outcome = res.outcome
        if run.timed_out and outcome == "cancelled":
            res.error = "stopped: over max_runtime"
        run.row.update(ended_at=iso(now), outcome=outcome, exit_code=res.exit_code, counts=res.counts,
                       error=agent_status.scrub(res.error) if res.error else None)
        self.store.put_run(run.row)
        self.last_outcome[run.spec.name] = outcome
        self.outcomes.append(outcome)
        self.runs.pop(run.spec.name, None)
        self.sched.finished(run.spec.name)
        extra = ""
        if run.row["counts"]:
            extra = " " + " ".join(f"{k}={v}" for k, v in run.row["counts"].items())
        if run.row["error"]:
            extra += f" ({run.row['error']})"
        self.log(f"job {run.spec.name} {outcome} after {int(time.monotonic() - run.started)}s{extra}")
        self._dirty = True

    def _reap(self, now: datetime) -> None:
        for run in list(self.runs.values()):
            if run.thread is not None and not run.thread.is_alive():
                self._finish(run, now)
            elif (run.spec.max_runtime and not run.cancel.is_set()
                  and time.monotonic() - run.started > run.spec.max_runtime.total_seconds()):
                run.timed_out = True
                run.cancel.set()
                self.log(f"job {run.spec.name} is over max_runtime: cancelling")

    # --- one scheduling round ---
    def tick(self, now: datetime | None = None, forced: set[str] | None = None, trigger: str = "schedule") -> scheduler.Plan:
        now = now or self.clock()
        self._renew(now)
        plan = scheduler.Plan()
        if self.lost:
            return plan
        self._reap(now)
        if self.health_enabled:
            self.probe_due(now)
        if not self.stopping:
            with self._lock:
                down = {n for n, s in self.health.items() if s.state == "down"}
                unknown = {n for n, s in self.health.items() if s.state == "unknown"}
            with self._lock:
                manual = dict(self.manual)
            plan = self.sched.plan(now, max_concurrent=self.max_concurrent, down=down, unknown=unknown,
                                   forced=set(forced or ()) | set(manual))
            for spec, reason in plan.skipped:
                self.log(f"job {spec.name} skipped: {reason}")
                self.store.put_run(self._row(spec, now, self._trigger(spec, trigger, manual), "skipped", reason,
                                             manual.get(spec.name)))
                self.last_outcome[spec.name] = "skipped"
                self.outcomes.append("skipped")
                self._consumed(spec, forced)
            for spec in plan.start:
                self._start(spec, now, self._trigger(spec, trigger, manual), manual.get(spec.name))
                self._consumed(spec, forced)
        if self._dirty:
            self._save_agents()
        self._prune(now)
        return plan

    @staticmethod
    def _trigger(spec: JobSpec, trigger: str, manual: dict[str, str]) -> str:
        return "manual" if spec.name in manual else trigger

    def _consumed(self, spec: JobSpec, forced: set[str] | None) -> None:
        with self._lock:
            self.manual.pop(spec.name, None)
        if forced:
            forced.discard(spec.name)

    def _save_agents(self) -> None:
        self._dirty = False
        try:
            self.store.save_agents(self.agents_snapshot())
        except Exception as exc:
            self.log(f"agent states not saved: {agent_status.error_text(exc)}")

    # --- loops ---
    def run_forever(self, stop: threading.Event) -> int:
        self.log(f"running: {len(self.agents)} agent(s), {len(self.sched.jobs)} job(s), up to "
                 f"{self.max_concurrent} at a time")
        while not stop.is_set() and not self.lost:
            self.tick()
            stop.wait(TICK)
        return 3 if self.lost else 0

    def run_once(self, forced: set[str] | None = None) -> int:
        """Probe every agent, then run what is due (or `forced`) until nothing is running or waiting."""
        self.health_enabled = False
        self.probe_due(self.clock(), wait=True)
        forced = set(forced or ())
        trigger = "once" if not forced else "manual"
        if forced:      # --job NAME: exactly these, whatever their schedule says
            self.sched.jobs = [j for j in self.sched.jobs if j.name in forced]
        while not self.lost:
            plan = self.tick(forced=forced, trigger=trigger)
            if not self.runs and not plan.waiting and not plan.start:
                break
            time.sleep(0.05)
        if self.lost:
            return 3
        return 1 if any(o in ("errors", "failed", "cancelled") for o in self.outcomes) else 0

    def shutdown(self) -> None:
        """Stop scheduling, cancel what runs (a scan stops at its next entry and the agent's own
        request is cancelled with the protocol's `cancel`), wait `shutdown_grace`, record the rest
        as cancelled, save the agent states and release the lease."""
        self.stopping = True
        for run in list(self.runs.values()):
            run.cancel.set()
        if self.runs:
            self.log(f"stopping: cancelling {len(self.runs)} running job(s)")
        deadline = time.monotonic() + self.cfg.shutdown_grace.total_seconds()
        for run in list(self.runs.values()):
            if run.thread is not None:
                run.thread.join(max(0.0, deadline - time.monotonic()))
        now = self.clock()
        for run in list(self.runs.values()):
            if run.thread is not None and run.thread.is_alive():
                run.result = JobResult("cancelled", error="still stopping when the server exited")
            self._finish(run, now)
        self._save_agents()
        try:
            self.store.release(self.holder)
        except Exception as exc:
            self.log(f"lease not released: {agent_status.error_text(exc)}")
        self.log("stopped")

    # --- snapshots (the viewer's API) ---
    def agents_snapshot(self) -> list[dict[str, Any]]:
        running = {r.spec.agent: r.spec.name for r in self.runs.values()}
        with self._lock:
            return [s.to_dict(running.get(n)) for n, s in self.health.items()]

    def jobs_snapshot(self) -> list[dict[str, Any]]:
        now = self.clock()
        out = []
        for spec in self.sched.jobs:
            out.append({**spec.to_dict(), "next_due": iso(self.sched.next_due(spec, now)),
                        "running": spec.name in self.runs, "queued": spec.name in self.manual,
                        "last_outcome": self.last_outcome.get(spec.name)})
        return out

    def lease_snapshot(self) -> dict[str, Any] | None:
        return self.store.lease()


# --- the command ----------------------------------------------------------------------------------
def print_plan(cfg: ServerConfig, agents: list[config.AgentConfig], anchors: dict[str, datetime],
               max_concurrent: int, now: datetime, first_seen: dict[str, datetime] | None = None) -> None:
    print(f"filecat server plan: {len(agents)} agent(s), {len(cfg.jobs)} job(s), up to {max_concurrent} at a time")
    print(f"  health: every {int(cfg.health_interval.total_seconds())}s per agent, backoff up to "
          f"{int(cfg.health_backoff_max.total_seconds())}s when down")
    for a in agents:
        print(f"  agent {a.name}  {a.endpoint}")
    first_seen = first_seen or {}
    # a job never seen before is first seen when the server starts: now
    sched = scheduler.Scheduler(cfg.jobs, anchors, {j.name: first_seen.get(j.name, now) for j in cfg.jobs})
    for spec in sched.jobs:
        due = sched.next_due(spec, now)
        if anchors.get(spec.name) is not None:
            when = "due now" if due <= now else f"next {due:%Y-%m-%d %H:%M}"
        elif spec.run_on_start:
            when = "at server start (never ran; run_on_start)"
        elif spec.name in first_seen:
            when = f"first run {due:%Y-%m-%d %H:%M} (never ran; waits for its slot)"
        elif spec.every is not None:
            when = f"first run {spec.schedule_text[6:]} after the server first starts (never ran)"
        else:
            when = f"first run {due:%Y-%m-%d %H:%M} (never ran; waits for its slot)"
        what = {"storage-collect": "collect the storage topology",
                "scan": "scan " + (", ".join(spec.roots) if spec.roots else "every root the agent covers"),
                "store-resum": "re-sum backup/database store rollups older than "
                               + (f"{int(spec.min_age.total_seconds() // 86400)}d" if spec.min_age else
                                  "store_resum minus one day") + " in " + (", ".join(spec.roots) if spec.roots
                                                                           else "every root the agent covers")}[spec.kind]
        opts = f"  options {' '.join(spec.options)}" if spec.options else ""
        print(f"  job {spec.name}: {spec.schedule_text}, {when}; agent {spec.agent}: {what}{opts}")
    for spec in cfg.jobs:
        if not spec.enabled:
            print(f"  job {spec.name}: disabled")
    if not cfg.jobs:
        print("  (no [[server.jobs]]: the server only checks agent health)")


def run(args: Any) -> int:
    if getattr(args, "action", None) == "set-password":
        return control_auth.set_password(args)
    try:
        cfg_dict = config.load(config.find(getattr(args, "config", None)))
        agents = config.load_agents(cfg_dict)
        cfg = server_cfg.load_server(cfg_dict, agents)
        if args.job:
            known = {j.name for j in cfg.jobs}
            unknown = [j for j in args.job if j not in known]
            if unknown:
                raise config.ConfigError(f"--job {unknown[0]}: no such job (jobs: {', '.join(sorted(known)) or 'none'})")
            if not args.once:
                raise config.ConfigError("--job needs --once")
        listen = args.serve if args.serve is not None else cfg.serve
        if args.serve is not None and args.serve == "":
            listen = cfg.serve or "127.0.0.1:8765"
        if listen is not None and not server_cfg.parse_listen(listen):
            raise config.ConfigError(f"--serve {listen!r}: want HOST:PORT")
        pw_hash = cfg.resolve_password_hash()
        if pw_hash is not None and not control_auth.valid_hash(pw_hash):
            raise config.ConfigError("[server] control_password_hash is not a scrypt$n$r$p$salt$hash string "
                                     "(make one with `filecat server set-password`)")
        if cfg.login_required_for_view and pw_hash is None:
            raise config.ConfigError("[server] login_required_for_view needs control_password_hash "
                                     "(`filecat server set-password`)")
        auth = control_auth.ControlAuth(
            pw_hash, control_auth.LoginGuard(
                max_failures=cfg.login_max_failures, window=cfg.login_window.total_seconds(),
                block=cfg.login_block.total_seconds(), global_max_failures=cfg.login_global_max_failures, log=log),
            control_auth.Sessions(), cfg.login_required_for_view)
    except config.ConfigError as exc:
        print(f"filecat server: {exc}", file=sys.stderr)
        return 2
    catalog = argparse.Namespace(backend=args.backend, out=getattr(args, "out", None), dsn=getattr(args, "dsn", None))
    clock = local_now
    max_concurrent = cfg.max_concurrent or (1 if (catalog.backend or "sqlite") in FILE_BACKENDS else 2)
    if args.dry_run:
        anchors: dict[str, datetime] = {}
        seen: dict[str, datetime] = {}
        from . import storage_cmd
        backend = storage_cmd._open_catalog(args)
        if backend is not None:
            try:
                anchors = server_store.last_starts(backend)
                seen = server_store.read_first_seen(backend)
            except NotImplementedError:
                pass
            finally:
                backend.close()
        print_plan(cfg, agents, anchors, max_concurrent, clock(), seen)
        return 0
    from .backends import open_backend
    handle = server_store.Handle(lambda: open_backend(catalog.backend, catalog.out, catalog.dsn))
    store = ServerStore(handle, clock)
    try:
        try:
            coord = Coordinator(cfg, agents, store, file_cfg=cfg_dict, catalog=catalog, clock=clock)
        except Exception as exc:
            print(f"filecat server: catalog not usable: {agent_status.error_text(exc)}", file=sys.stderr)
            return 2
        lease = coord.acquire()
        if not lease.ok:
            held = lease.holder or {}
            print(f"filecat server: another server holds the catalog ({held.get('host', '?')}, pid "
                  f"{held.get('pid', '?')}) until {held.get('expires_at', '?')}", file=sys.stderr)
            return 4
        viewer = None
        if listen is not None:
            from . import serve
            host, port = server_cfg.parse_listen(listen)             # type: ignore[misc]
            viewer = serve.start_viewer(argparse.Namespace(
                backend=catalog.backend, out=catalog.out, dsn=catalog.dsn, host=host, port=port, quiet=True,
                no_save=False, graph_max_age=120, open=False, control_auth=auth), coord)
            if viewer is None:
                coord.shutdown()
                return 2
        stop = threading.Event()
        if args.once:
            try:
                code = coord.run_once(set(args.job or []))
            except KeyboardInterrupt:
                code = 130
            finally:
                coord.shutdown()
            return code
        previous = signal.signal(signal.SIGTERM, lambda *_: stop.set())
        code = 0
        try:
            code = coord.run_forever(stop)
        except KeyboardInterrupt:
            log("Ctrl+C: shutting down")
        finally:
            signal.signal(signal.SIGTERM, previous)
            coord.shutdown()
            if viewer is not None:
                viewer.stop()
        return code
    finally:
        handle.close()
