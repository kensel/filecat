"""filecat scan: walk roots, measure entries, write documents, rebuild aggregates.

See file-catalog-requirements.md, "Run" and "How a large or remote tree is
walked". The walk itself (os.scandir, post-order directory records, resume
skip, per-entry timeout) lives in walker.py; this module measures one
regular file (`measure_file`) and drives a whole scan (`scan_roots`, `run`).
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any

from . import (aliases, cloudfiles, fsource, preflight, record, redaction, rollup, rootcase, rootinfo,
               secretfiles)
from .agent_client import AgentError, Measurement
from .backends import open_backend
from .backends.base import Backend
from .hashing import hash_file
from .identify import Identifier
from .options import ScanOptions
from .probe import probe_file
from .resume import ResumeState, resume_path_for
from .walker import resolve_unc, walk_root

HEAD_BYTES = 8 * 1024


class ScanCancelled(KeyboardInterrupt):
    """options.cancel was set (the filecat server shutting down, or a job over its time). A
    KeyboardInterrupt so the root is marked interrupted and the resume file is kept, as for Ctrl+C."""


def measure_file(root: str, rel_path: str, abs_path: str, st: os.stat_result,
                 options: ScanOptions, identifier: Any) -> dict[str, Any]:
    """Build the full document for one regular file: identity, hash policy,
    built-in probe, type identification. Used by scan and by enrich.
    Errors are recorded on the document, never raised. A file on a
    filecat-agent (abs_path is an fsource.RemotePath) is measured by one agent
    call that returns the head, the digest and the size and mtime they
    describe; the probes then read what else they need through the agent.
    A secret (secretfiles.py: a private key, a keystore, a file the agent
    refuses to read) is recorded from its directory entry alone, before any
    hash, sample or probe exists."""
    size = st.st_size
    mtime_ns = st.st_mtime_ns
    remote = abs_path if isinstance(abs_path, fsource.RemotePath) else None
    head = b""
    measured: Measurement | None = None
    measure_error: OSError | None = None
    ctime_ns = getattr(st, "st_birthtime_ns", None)
    if ctime_ns is None:
        ctime_ns = st.st_ctime_ns
    name = rel_path.rsplit("/", 1)[-1] if rel_path else os.path.basename(root.rstrip("\\/")) or root

    def unopened(probe: dict[str, Any]) -> dict[str, Any]:
        doc = secretfiles.listed(root, rel_path, name, size, mtime_ns, ctime_ns, probe, identifier)
        fsource.apply_stat_extras(doc, st)
        return doc

    if secretfiles.keystore_name(name):
        return unopened({"secret": "keystore"})
    if remote is not None and (size > 0 or options.hash == "full"):
        try:
            measured = remote.measure(options.hash, options.timeout_for(root) + 10)
        except AgentError as e:
            if e.code == "refused" and "denied by agent policy" in e.message:
                return unopened({"secret": "denied"})       # the agent's deny list: .env and the like
            measure_error = e
        except OSError as e:
            measure_error = e
        else:
            size, mtime_ns = measured.size, measured.mtime_ns   # what the digest was computed from
            remote.size = size
            if measured.unread == "private_key":
                return unopened({"secret": "private_key"})
            if measured.unread == "cloud_placeholder":
                return unopened({"cloud": cloudfiles.describe(str(remote), measured.attributes)
                                 or {"provider": None, "state": "online-only"}})
            head = measured.head

    doc = record.new_document(root, rel_path, kind="unknown", size=size,
                               mtime_ns=mtime_ns, ctime_ns=ctime_ns, name=name)

    fsource.apply_stat_extras(doc, st)
    if measure_error is not None:
        record.add_error(doc, "read", measure_error)
    elif remote is None and size > 0:
        try:
            with open(abs_path, "rb") as f:
                head = f.read(HEAD_BYTES)
        except OSError as e:
            record.add_error(doc, "read", e)
        else:
            if secretfiles.private_key_in(head):
                return unopened({"secret": "private_key"})      # before any hash, sample or probe

    if size == 0:
        # dir / link / empty are decided before probe_file is ever called
        # (see probe/__init__.py's module docstring).
        doc["kind"] = "empty"
    else:
        try:
            result = probe_file(abs_path, name, size, head, options)
        except Exception as e:  # a broken probe must not crash the scan
            record.add_error(doc, "probe", e)
        else:
            result.apply(doc)

    try:
        bytes_for_identify = head if options.identify_bytes_for(root) else None
        ident = identifier.identify(abs_path, name, bytes_for_identify, doc["kind"], size=size,
                                    probe_format=(doc.get("probe") or {}).get("format"))
    except Exception as e:  # a broken identifier must not crash the scan
        record.add_error(doc, "identify", e)
    else:
        if ident:
            if ident.get("mime") is not None:
                doc["mime"] = ident["mime"]
            if ident.get("probe"):
                doc.setdefault("probe", {}).update(ident["probe"])

    if remote is not None:
        if measure_error is not None:
            record.add_error(doc, "hash", measure_error)
        elif measured is not None:
            doc.update(measured.hashes)
    else:
        try:
            # the digest takes the mtime at 100 ns (SMB, the agent protocol), so a local scan of a
            # nanosecond filesystem and an agent scan of the same file give the same sha256_partial
            doc.update(hash_file(abs_path, size, mtime_ns - mtime_ns % 100, options.hash))
        except OSError as e:
            record.add_error(doc, "hash", e)

    return doc


class _Progress:
    """Prints a progress line to stderr no more often than `interval` seconds:

        ROOT: N files, N bytes | 18.4 files/s, measuring 3.1 files/s 2.1 MB/s (avg 12.0 files/s)
              | 1203 measured, 242252 unchanged, 9120 data listed, 6800 cloud-only,
              312 dirs resumed, 40 dropped, 6 rollups (1.2 GB) | last: PATH

    Rates are over the time since the previous line; "measured" files are
    new or changed ones that were read, and their bytes are what MB/s
    counts; "data listed" files (backup or database data) and "cloud-only"
    files (data not on the device) were recorded from their directory
    entry without being read; "dropped" records
    vanished from disk and were moved to the dropped store; a rollup is a
    group of files and folders counted but not listed (docs/rollups.md), shown
    by its own path (<folder>\\[TAG]), never by what is inside it. Only
    counters are kept, so this costs nothing per file."""

    def __init__(self, root: str, interval: float, stream: Any = None, via: str = "",
                 cancel: Any = None) -> None:
        self.cancel = cancel
        self.root = root + via      # via: " (filecat-agent NAME)" when read through an agent
        self.interval = interval
        self.stream = stream or sys.stderr
        self.files = 0
        self.bytes = 0
        self.measured = 0
        self.measured_bytes = 0
        self.unchanged = 0
        self.listed = 0
        self.cloud = 0
        self.resumed_dirs = 0
        self.dropped = 0
        self.rollups = 0
        self.rollup_bytes = 0
        self.carried = 0
        self.last_path = ""
        self._started = self._last_print = time.monotonic()
        self._mark = (0, 0, 0)  # files, measured, measured_bytes at the previous line

    def __call__(self, path: str, size: int, how: str = "measured") -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise ScanCancelled()
        if how == "resumed":
            self.resumed_dirs += 1
        elif how == "rollup":
            self.rollups += 1
            self.rollup_bytes += size
        elif how == "carried":
            self.rollups += 1       # a store's rollup kept as it was: its fingerprint did not change
            self.rollup_bytes += size
            self.carried += 1
        elif how == "summing":
            pass        # a long sum is still going: only the clock and the path move
        elif how == "dropped":
            self.dropped += size  # a count of records, not bytes
        else:
            self.files += 1
            self.bytes += size
            if how == "measured":
                self.measured += 1
                self.measured_bytes += size
            elif how == "listed":
                self.listed += 1
            elif how == "cloud":
                self.cloud += 1
            else:
                self.unchanged += 1
        self.last_path = path
        now = time.monotonic()
        if now - self._last_print >= self.interval:
            self.flush(now)

    def flush(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        span = max(now - self._last_print, 1e-6)
        files0, measured0, mbytes0 = self._mark
        rate = (self.files - files0) / span
        m_rate = (self.measured - measured0) / span
        mb_rate = (self.measured_bytes - mbytes0) / span / 1e6
        avg = self.files / max(now - self._started, 1e-6)
        resumed = f", {self.listed} data listed" if self.listed else ""
        resumed += f", {self.cloud} cloud-only" if self.cloud else ""
        resumed += f", {self.resumed_dirs} dirs resumed" if self.resumed_dirs else ""
        resumed += f", {self.dropped} dropped" if self.dropped else ""
        resumed += f", {self.rollups} rollups ({self.rollup_bytes} bytes)" if self.rollups else ""
        resumed += f", {self.carried} carried" if self.carried else ""
        print(f"{self.root}: {self.files} files, {self.bytes} bytes | {rate:.1f} files/s, "
              f"measuring {m_rate:.1f} files/s {mb_rate:.1f} MB/s (avg {avg:.1f} files/s) | "
              f"{self.measured} measured, {self.unchanged} unchanged{resumed} | last: {self.last_path}",
              file=self.stream)
        self._last_print = now
        self._mark = (self.files, self.measured, self.measured_bytes)


def _purge_dropped(backend: Backend, keep_days: int) -> None:
    """Remove dropped records moved out more than `keep_days` days ago."""
    from datetime import datetime, timedelta, timezone
    from .backends.base import dropped_now
    cutoff = dropped_now(datetime.now(timezone.utc) - timedelta(days=keep_days))
    try:
        n = backend.purge_dropped(cutoff)
    except NotImplementedError:
        return
    if n:
        print(f"purged {n} dropped records older than {keep_days} days", file=sys.stderr)


def scan_roots(roots: list[str], backend: Backend, options: ScanOptions,
               resume_path: str | None = None) -> int:
    """Scan every root into backend. Returns the process exit code (0 or 1).
    A root matching options.aliases is read from its path as given and
    recorded under the aliased root (see aliases.py). A root a configured
    filecat-agent covers is read through that agent (fsource.pick)."""
    paths = roots
    roots = [aliases.recorded_root(p, options.aliases) for p in paths]
    if options.agent and not any(a.name == options.agent for a in options.agents):
        print(f"filecat: --agent {options.agent}: no such [[agents]] in filecat.toml", file=sys.stderr)
        return 2
    agent_sources: dict[str, fsource.AgentSource] = {}      # one per agent, shared by its roots
    plans: list[tuple[fsource.AgentSource, str] | None] = []
    for path, root in zip(paths, roots):
        picked = fsource.pick(options, root, path)
        if picked is None:
            plans.append(None)
            continue
        config, unc = picked
        plans.append((agent_sources.setdefault(config.name, fsource.AgentSource(config)), unc))
    try:
        rootcase.reconcile(roots, plans, backend, options.agents)
        return _scan(paths, roots, plans, backend, options, resume_path)
    finally:
        for src in agent_sources.values():
            src.close()


def _scan(paths: list[str], roots: list[str], plans: list[tuple[fsource.AgentSource, str] | None],
          backend: Backend, options: ScanOptions, resume_path: str | None) -> int:
    # The rules, markers and sticky redactions of each root come first, and an
    # agent is given its half before anything is listed: not even a preflight
    # listing may carry the name of a folder that is to be rolled up.
    try:
        rollup_plans = [rollup.make_plan(options, root, path, backend,
                                         source=plans[i][0] if plans[i] else None)
                        for i, (path, root) in enumerate(zip(paths, roots))]
    except redaction.RedactionKeyError as exc:
        print(f"filecat: {exc}", file=sys.stderr)
        return 2
    groups: dict[int, tuple[fsource.AgentSource, list]] = {}
    for i, plan in enumerate(rollup_plans):
        if plans[i]:
            groups.setdefault(id(plans[i][0]), (plans[i][0], []))[1].append((plan, plans[i][1]))
    for source, group in groups.values():
        try:
            source.configure_rollups(group)
        except AgentError as exc:
            if exc.code == "policy":
                print(f"filecat: {exc}", file=sys.stderr)
                return 2
        except OSError:
            pass        # unreachable: the preflight below says so, and the walk configures it again
    # Before anything is read: can each root be opened, with which account,
    # and is it the account the last scan used? Warnings only.
    checks = preflight.check(paths, roots, backend, options.timeout_for(paths[0]) if paths else 30.0,
                             agents=plans)
    for i, c in enumerate(checks):
        if plans[i] and c.error and options.agent_fallback:
            print(f"{c.root}: {plans[i][0].description} cannot be used ({c.error}); "
                  "reading over SMB (--agent-fallback)", file=sys.stderr)
            plans[i] = None
    problems = preflight.report(checks)
    if options.check_only:
        return 1 if problems else 0
    accounts = {c.path: None if plans[i] else c.account for i, c in enumerate(checks)}
    for i, c in enumerate(checks):      # an agent root that fell back to SMB is ruled in SMB terms
        if rollup_plans[i].agent_cfg is not None and plans[i] is None:
            rollup_plans[i] = rollup.make_plan(options, roots[i], paths[i], backend)
    announced: set[str] = set()
    for plan in rollup_plans:
        for message in plan.messages:
            if message not in announced:
                announced.add(message)
                print(f"filecat: {message}", file=sys.stderr)

    if resume_path is None:
        resume_path = resume_path_for(getattr(backend, "name", "backend"),
                                       getattr(backend, "path", None))
    # Records reach the backend before the resume file says they are done.
    resume = ResumeState(resume_path, before_save=backend.flush)
    identifier = Identifier(options)
    # Identifier.scan_errors is scan-level (e.g. `sf` missing with --pronom);
    # record it once, on the first root's directory document.
    scan_level_errors = list(identifier.scan_errors)
    had_errors = False
    try:
        for i, (path, root) in enumerate(zip(paths, roots)):
            source = None
            if plans[i]:
                source, path = plans[i]     # the agent knows the root by this UNC path
            try:
                unc = resolve_unc(path)
            except Exception:
                unc = None
            if source is not None:
                print(f"{root}: scanning through {source.description}", file=sys.stderr)
            elif path != root:
                print(f"{root}: reading through {path}", file=sys.stderr)
            progress = _Progress(root, options.progress_interval,
                                 via=f" (filecat-agent {source.name})" if source else "",
                                 cancel=options.cancel)
            if resume.resuming(root) and not options.force:
                print(f"{root}: resuming an unfinished scan; {resume.done_count(root)} finished "
                      "folders are skipped unless they changed", file=sys.stderr)
            # The root index records the attempt first, so a scan that is
            # killed outright still shows up as started and never finished.
            tracker = rootinfo.ScanTracker(backend, root)
            try:
                attempt = rootinfo.begin(backend, root, tracker, path=path,
                                         account=accounts.get(path),
                                         agent=source.name if source else None)
            except NotImplementedError:
                attempt = None
            try:
                root_had_errors = walk_root(
                    root, options, tracker, identifier, resume, measure_file,
                    unc=unc, progress=progress,
                    extra_root_errors=scan_level_errors if i == 0 else None,
                    path=path, source=source, rollups=rollup_plans[i],
                )
            except BaseException as exc:
                resume.flush()  # keep what finished, for the rerun
                if attempt is not None:
                    rootinfo.finish(backend, root, attempt, tracker, exc)
                raise
            progress.flush()
            if attempt is not None:
                plan = rollup_plans[i]
                extra: dict[str, Any] = {"rollup_unresolved": list(plan.unresolved)}
                if plan.complete:       # a partial scan leaves the suggestions as they were
                    extra["suggestions"] = {**plan.suggestion_rows(), "at": rootinfo.now()}
                rootinfo.finish(backend, root, attempt, tracker, extra=extra)
            had_errors = had_errors or root_had_errors

        try:
            for root in dict.fromkeys(roots):  # only what this scan touched; other roots keep theirs
                backend.rebuild_aggregates(root=root)
        except NotImplementedError:
            pass
        except ImportError:
            # aggregate.build_aggregates() is still a stub in this worktree
            # (owned by another branch); don't let that fail a scan.
            pass

        _purge_dropped(backend, options.keep_dropped)
        if any(plan.purged for plan in rollup_plans):
            backend.scrub()     # after the aggregates were rebuilt: they held the purged folder names too

        if options.ollama:
            from .ollama import annotate_backend
            annotate_backend(backend, options)
    finally:
        resume.flush()
        identifier.close()

    return 1 if had_errors else 0


def run(args) -> int:
    backend = open_backend(args.backend, getattr(args, "out", None), getattr(args, "dsn", None))
    options = ScanOptions.from_args(args)
    try:
        return scan_roots(args.roots, backend, options)
    finally:
        backend.close()
