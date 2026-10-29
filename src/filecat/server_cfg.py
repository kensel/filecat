"""`[server]` and `[[server.jobs]]` of filecat.toml (docs/agent-server.md section 5).

load_server validates them and expands a job with agent = "*" into one job per agent. A job's
`options` are command-line words of the equivalent command (`filecat scan`, `filecat storage
collect`); parse_cli runs them through the real parser, so they mean what they mean there.
"""
from __future__ import annotations

import argparse
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import time, timedelta
from typing import Any, Iterator

from . import control_auth, tls
from .config import AgentConfig, ConfigError, expand

KINDS = ("storage-collect", "scan", "store-resum", "summaries")
LOCAL_AGENT = "(local)"     # the "agent" of work that reads the catalog or the local disk, not through an agent
SERVER_KEYS = ("health_interval", "health_timeout", "health_backoff_max", "max_concurrent", "lease_ttl",
               "shutdown_grace", "history_keep", "history_days", "serve", "control_password_hash", "login_max_failures", "login_window", "login_block",
               "login_global_max_failures", "login_required_for_view", "tls", "jobs")
JOB_KEYS = ("name", "kind", "agent", "roots", "every", "at", "options", "enabled", "min_age", "max_runtime",
            "run_on_start")
# the catalog and the agent are the server's to decide
FORBIDDEN_OPTIONS = ("--backend", "--out", "--dsn", "--agent", "--no-agent", "--check", "--config")
MIN_EVERY = timedelta(minutes=1)
_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd])\s*$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_CLOCK = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def parse_duration(value: Any, what: str) -> timedelta:
    """`30s`, `10m`, `24h`, `7d` (a plain number of seconds is accepted too)."""
    if isinstance(value, bool):
        raise ConfigError(f"{what} = {value!r}; want a duration like \"30s\", \"10m\", \"24h\" or \"7d\"")
    if isinstance(value, (int, float)):
        if value <= 0:
            raise ConfigError(f"{what} = {value!r}; want a positive duration")
        return timedelta(seconds=value)
    m = _DURATION.match(value) if isinstance(value, str) else None
    if not m or float(m.group(1)) <= 0:
        raise ConfigError(f"{what} = {value!r}; want a duration like \"30s\", \"10m\", \"24h\" or \"7d\"")
    return timedelta(seconds=float(m.group(1)) * _UNITS[m.group(2)])


def parse_clock(value: Any, what: str) -> time:
    m = _CLOCK.match(value.strip()) if isinstance(value, str) else None
    if not m:
        raise ConfigError(f"{what} = {value!r}; want a time of day like \"02:30\"")
    return time(int(m.group(1)), int(m.group(2)))


@dataclass(frozen=True)
class JobSpec:
    name: str
    kind: str
    agent: str
    roots: tuple[str, ...] | None = None
    every: timedelta | None = None
    at: tuple[time, ...] = ()
    options: tuple[str, ...] = ()
    enabled: bool = True
    min_age: timedelta | None = None
    max_runtime: timedelta | None = None
    run_on_start: bool = False              # never ran: run at server start, not at its first slot

    @property
    def schedule_text(self) -> str:
        if self.every is not None:
            secs = int(self.every.total_seconds())
            for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
                if secs % n == 0:
                    return f"every {secs // n}{unit}"
            return f"every {secs}s"
        return "daily at " + ", ".join(t.strftime("%H:%M") for t in self.at)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "agent": self.agent,
                "roots": list(self.roots) if self.roots is not None else None,
                "schedule": self.schedule_text, "options": list(self.options), "enabled": self.enabled,
                "run_on_start": self.run_on_start}


@dataclass(frozen=True)
class ServerConfig:
    health_interval: timedelta = timedelta(seconds=60)
    health_timeout: timedelta = timedelta(seconds=5)
    health_backoff_max: timedelta = timedelta(minutes=10)
    max_concurrent: int | None = None       # None: 1 on file catalogs, else 2 (Coordinator decides)
    lease_ttl: timedelta = timedelta(seconds=90)
    shutdown_grace: timedelta = timedelta(seconds=30)
    history_keep: int = 500
    history_days: int = 90
    serve: str | None = None
    control_password_hash: str | None = None    # as written (a hash or ${NAME}); resolve_password_hash()
    login_max_failures: int = 5                 # per address, within login_window: then blocked
    login_window: timedelta = timedelta(minutes=15)
    login_block: timedelta = timedelta(minutes=15)
    login_global_max_failures: int = 20         # across all addresses within login_window: all logins refused
    login_required_for_view: bool = False       # the whole viewer needs a session, not only "run now"
    tls: tls.TlsConfig | None = None            # [server.tls]: serve the viewer over HTTPS (tls.py)
    jobs: tuple[JobSpec, ...] = field(default_factory=tuple)

    def resolve_password_hash(self) -> str | None:
        """The stored scrypt hash for the viewer's login, from the environment when it is a ${NAME}."""
        return expand(self.control_password_hash).strip() if self.control_password_hash else None


@contextmanager
def _parser_errors() -> Iterator[None]:
    """argparse exits the process on a bad command line; make it a ConfigError instead."""
    original = argparse.ArgumentParser.error

    def error(self: argparse.ArgumentParser, message: str) -> Any:
        raise ConfigError(message)
    argparse.ArgumentParser.error = error          # type: ignore[method-assign]
    try:
        yield
    finally:
        argparse.ArgumentParser.error = original   # type: ignore[method-assign]


def parse_cli(argv: list[str]) -> argparse.Namespace:
    """The namespace `filecat <argv>` would run with, before the config file is applied."""
    from . import cli
    with _parser_errors():
        return cli.build_parser().parse_args(argv)


def _job(table: Any, index: int, agents: dict[str, AgentConfig]) -> list[JobSpec]:
    label = f"[[server.jobs]] #{index}"
    if not isinstance(table, dict):
        raise ConfigError(f"{label}: wants a table with name, kind, agent and a schedule")
    if isinstance(table.get("name"), str) and table["name"]:
        label += f" ({table['name']})"

    def bad(message: str) -> ConfigError:
        return ConfigError(f"{label}: {message}")

    unknown = [k for k in table if k not in JOB_KEYS]
    if unknown:
        raise bad(f"unknown key {unknown[0]!r}; the keys are {', '.join(JOB_KEYS)}")
    name = table.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise bad("name is required: letters, digits, '.', '_' and '-'")
    kind = table.get("kind")
    if kind not in KINDS:
        raise bad(f"kind = {kind!r}; choose from {', '.join(KINDS)}")
    agent = table.get("agent")
    if kind == "summaries":
        if agent is not None:
            raise bad("agent does not apply to summaries: it reads the catalog, not an agent")
        agent = LOCAL_AGENT
    elif not isinstance(agent, str) or not agent:
        raise bad('agent is required: an [[agents]] name, or "*" for every agent')
    if agent not in ("*", LOCAL_AGENT) and agent not in agents:
        raise bad(f"agent = {agent!r}: no such [[agents]] in filecat.toml ({', '.join(agents) or 'none configured'})")
    if "every" in table and "at" in table or "every" not in table and "at" not in table:
        raise bad('give exactly one of every = "24h" or at = "02:30"')
    every, at = None, ()
    if "every" in table:
        every = parse_duration(table["every"], f"{label}: every")
        if every < MIN_EVERY:
            raise bad("every must be at least 1m")
    else:
        raw = table["at"]
        items = raw if isinstance(raw, list) and raw else [raw]
        at = tuple(sorted({parse_clock(t, f"{label}: at") for t in items}))
    options = table.get("options", [])
    if not isinstance(options, list) or not all(isinstance(o, str) for o in options):
        raise bad("options wants a list of command-line words, e.g. [\"--hash\", \"none\"]")
    for opt in options:
        for forbidden in FORBIDDEN_OPTIONS:
            if opt == forbidden or opt.startswith(forbidden + "="):
                raise bad(f"options must not contain {forbidden}: the server decides the catalog and the agent")
    roots = table.get("roots")
    if roots is not None:
        if kind == "storage-collect":
            raise bad("roots does not apply to storage-collect")
        if not isinstance(roots, list) or not roots or not all(isinstance(r, str) and r for r in roots):
            raise bad("roots wants a non-empty list of root paths")
    min_age = table.get("min_age")
    if min_age is not None and kind != "store-resum":
        raise bad("min_age applies to store-resum only")
    enabled = table.get("enabled", True)
    if not isinstance(enabled, bool):
        raise bad("enabled wants true or false")
    run_on_start = table.get("run_on_start", False)
    if not isinstance(run_on_start, bool):
        raise bad("run_on_start wants true or false")
    names = list(agents) if agent == "*" else [agent]      # summaries: the one local slot
    specs = []
    for target in names:
        spec = JobSpec(
            name=name if agent != "*" else f"{name}@{target}", kind=kind, agent=target,
            roots=tuple(roots) if roots is not None else None, every=every, at=at, options=tuple(options),
            enabled=enabled, run_on_start=run_on_start,
            min_age=parse_duration(min_age, f"{label}: min_age") if min_age is not None else None,
            max_runtime=(parse_duration(table["max_runtime"], f"{label}: max_runtime")
                         if "max_runtime" in table else None))
        _check_options(spec, label)
        specs.append(spec)
    return specs


def _check_options(spec: JobSpec, label: str) -> None:
    """Run the options through the real parser now, so a typo is a config error at start-up."""
    try:
        argv = {"storage-collect": ["storage", "collect"], "summaries": ["summaries"]}.get(spec.kind, ["scan", "ROOT"])
        parse_cli([*argv, *spec.options])
    except ConfigError as exc:
        raise ConfigError(f"{label}: options: {exc}") from None


def load_server(cfg: dict[str, Any], agents: list[AgentConfig]) -> ServerConfig:
    """The validated [server] table and [[server.jobs]], in file order. No [server] table is a
    valid, empty server: it checks agent health and runs nothing."""
    section = cfg.get("server")
    if section is None:
        return ServerConfig()
    if not isinstance(section, dict):
        raise ConfigError("server: write a [server] table and [[server.jobs]] tables")
    unknown = [k for k in section if k not in SERVER_KEYS]
    if unknown:
        raise ConfigError(f"[server]: unknown key {unknown[0]!r}; the keys are {', '.join(SERVER_KEYS)}")
    by_name = {a.name: a for a in agents}

    def duration(key: str, default: timedelta, low: timedelta = timedelta(seconds=1)) -> timedelta:
        if key not in section:
            return default
        value = parse_duration(section[key], f"[server] {key}")
        if value < low:
            raise ConfigError(f"[server] {key} = {section[key]!r}; at least {low.total_seconds():g}s")
        return value

    def count(key: str, default: int | None, low: int) -> int | None:
        value = section.get(key, default)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < low:
            raise ConfigError(f"[server] {key} = {value!r}; want a whole number of at least {low}")
        return value

    serve = section.get("serve")
    if serve is not None and (not isinstance(serve, str) or not parse_listen(serve)):
        raise ConfigError(f"[server] serve = {serve!r}; want HOST:PORT")
    pw_hash = section.get("control_password_hash")
    if pw_hash is not None:
        if not isinstance(pw_hash, str) or not pw_hash.strip():
            raise ConfigError('[server] control_password_hash wants a string: the line `filecat server '
                              'set-password` prints, or "${FILECAT_SERVER_PASSWORD_HASH}"')
        if "${" not in pw_hash and not control_auth.valid_hash(pw_hash):
            raise ConfigError("[server] control_password_hash is not a scrypt$n$r$p$salt$hash string: "
                              "make one with `filecat server set-password` (never write the password itself)")
    required = section.get("login_required_for_view", False)
    if not isinstance(required, bool):
        raise ConfigError("[server] login_required_for_view wants true or false")
    tls_cfg = tls.parse_table(section.get("tls"))
    tables = section.get("jobs", [])
    if not isinstance(tables, list):
        raise ConfigError("server.jobs: write one [[server.jobs]] table per job (double brackets)")
    jobs: list[JobSpec] = []
    for i, table in enumerate(tables, 1):
        jobs.extend(_job(table, i, by_name))
    seen: set[str] = set()
    for job in jobs:
        if job.name in seen:
            raise ConfigError(f"[[server.jobs]]: name {job.name!r} is used twice")
        seen.add(job.name)
    return ServerConfig(
        health_interval=duration("health_interval", ServerConfig.health_interval),
        health_timeout=duration("health_timeout", ServerConfig.health_timeout),
        health_backoff_max=duration("health_backoff_max", ServerConfig.health_backoff_max),
        max_concurrent=count("max_concurrent", None, 1),
        lease_ttl=duration("lease_ttl", ServerConfig.lease_ttl, timedelta(seconds=3)),
        shutdown_grace=duration("shutdown_grace", ServerConfig.shutdown_grace),
        history_keep=count("history_keep", 500, 1) or 500,
        history_days=count("history_days", 90, 1) or 90,
        serve=serve, control_password_hash=pw_hash,
        login_max_failures=count("login_max_failures", 5, 1) or 5,
        login_window=duration("login_window", ServerConfig.login_window),
        login_block=duration("login_block", ServerConfig.login_block),
        login_global_max_failures=count("login_global_max_failures", 20, 1) or 20,
        login_required_for_view=required, tls=tls_cfg, jobs=tuple(jobs))


def parse_listen(text: str | None) -> tuple[str, int] | None:
    """`HOST:PORT`, `:PORT` or `PORT` as (host, port); None when it is not one."""
    if text is None:
        return None
    host, sep, port = text.strip().rpartition(":")
    if not port.isdigit() or not 0 <= int(port) <= 65535:
        return None
    return (host or "127.0.0.1", int(port)) if sep or port else None
