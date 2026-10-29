"""What is due, and what may start now: the scheduling rules of docs/agent-server.md section 4.

Pure logic over an injected `now` (a timezone-aware datetime), so it is tested with a fake clock.
A job's anchor is when it last started (or was last skipped); None means never. Interval jobs
are due at `anchor + every`; daily jobs when the latest slot at or before `now` is later than the
anchor (a missed slot runs once, late).
"""
from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from typing import Callable, Iterable

from .server_cfg import JobSpec

SKIP_RUNNING = "previous run still running"


def latest_slot(now: datetime, times: Iterable[time]) -> datetime | None:
    """The most recent daily slot at or before `now` (today's or yesterday's)."""
    best = None
    for day in (now.date() - timedelta(days=1), now.date()):
        for t in times:
            slot = datetime.combine(day, t, tzinfo=now.tzinfo)
            if slot <= now and (best is None or slot > best):
                best = slot
    return best


def next_slot(now: datetime, times: Iterable[time]) -> datetime:
    """The first daily slot after `now`."""
    for day in (now.date(), now.date() + timedelta(days=1)):
        for t in sorted(times):
            slot = datetime.combine(day, t, tzinfo=now.tzinfo)
            if slot > now:
                return slot
    raise ValueError("no slot")        # unreachable for a non-empty `times`


def is_due(job: JobSpec, anchor: datetime | None, now: datetime) -> bool:
    if anchor is None:
        return True
    if job.every is not None:
        return anchor + job.every <= now
    slot = latest_slot(now, job.at)
    return slot is not None and slot > anchor


def next_due(job: JobSpec, anchor: datetime | None, now: datetime) -> datetime:
    """When the job is next due (`now` when it already is)."""
    if is_due(job, anchor, now):
        return now
    if job.every is not None:
        return anchor + job.every      # type: ignore[operator]  (a None anchor is always due)
    return next_slot(now, job.at)


@dataclass
class Plan:
    start: list[JobSpec] = field(default_factory=list)
    skipped: list[tuple[JobSpec, str]] = field(default_factory=list)
    waiting: list[JobSpec] = field(default_factory=list)        # due, but the agent or the limit is busy
    deferred: list[tuple[JobSpec, str]] = field(default_factory=list)   # waiting because `hold` said the agent is busy (and why)


class Scheduler:
    def __init__(self, jobs: Iterable[JobSpec], anchors: dict[str, datetime | None] | None = None,
                 first_seen: dict[str, datetime] | None = None, agent_limits: dict[str, int] | None = None) -> None:
        """`anchors`: when each job last started. A job that never ran waits for its first slot
        (anchor = when the server first saw it, so `every` is due a full interval later and `at`
        at its next time of day), unless it has `run_on_start`: then it has no anchor and is due."""
        self.jobs = [j for j in jobs if j.enabled]
        self.anchors: dict[str, datetime | None] = {}
        for j in self.jobs:
            anchor = (anchors or {}).get(j.name)
            if anchor is None and not j.run_on_start:
                anchor = (first_seen or {}).get(j.name)
            self.anchors[j.name] = anchor
        self.running: dict[str, str] = {}       # job name -> agent name
        self.agent_limits = agent_limits or {}  # agent name -> jobs it takes at once (default 1)
        self._edit = threading.Lock()

    def add(self, job: JobSpec) -> None:
        """An ad-hoc job (the viewer's "scan this root"): it has no schedule, so it only ever starts
        when forced, and is dropped when it has finished."""
        with self._edit:
            self.anchors[job.name] = None
            self.jobs = [*self.jobs, job]

    def drop(self, name: str) -> None:
        with self._edit:
            self.jobs = [j for j in self.jobs if j.name != name]
            self.anchors.pop(name, None)

    def busy_agents(self) -> set[str]:
        """Agents that cannot take another job: they run as many as their `max_jobs`."""
        counts = Counter(self.running.values())
        return {a for a, n in counts.items() if n >= self.agent_limits.get(a, 1)}

    def plan(self, now: datetime, *, max_concurrent: int, down: Iterable[str] = (),
             unknown: Iterable[str] = (), forced: Iterable[str] = (),
             hold: Callable[[JobSpec], str | None] | None = None) -> Plan:
        """Decide for every due (or forced) job, in configuration order. Chosen jobs are marked
        running at once, so a later job of the same agent in this round waits. `hold` is asked
        last, for a job that would start: a reason keeps it due (it is not started, not
        skipped) and is reported in `Plan.deferred`."""
        down, unknown, forced = set(down), set(unknown), set(forced)
        plan = Plan()
        for job in self.jobs:
            if not (job.name in forced or is_due(job, self.anchors[job.name], now)):
                continue
            if job.name in self.running:
                plan.skipped.append((job, SKIP_RUNNING))
                self.anchors[job.name] = now
            elif job.agent in down:
                plan.skipped.append((job, f"agent {job.agent} is down"))
                self.anchors[job.name] = now
            elif (job.agent in unknown or job.agent in self.busy_agents()
                  or len(self.running) >= max_concurrent):
                plan.waiting.append(job)
            elif hold is not None and (reason := hold(job)):
                plan.waiting.append(job)
                plan.deferred.append((job, reason))
            else:
                plan.start.append(job)
                self.running[job.name] = job.agent
                self.anchors[job.name] = now
        return plan

    def finished(self, name: str) -> None:
        self.running.pop(name, None)

    def next_due(self, job: JobSpec, now: datetime) -> datetime:
        return next_due(job, self.anchors.get(job.name), now)
