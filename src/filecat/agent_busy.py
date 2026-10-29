"""Who else is using an agent: the `activity` reply read as "is it busy", and as text.

A session is *working* when it is authenticated and either runs a command now or has a label
and made a request in the last minute. The connections filecat itself makes to look (health
checks, the busy check, `agents status`, the viewer) are labelled so they never count.
`filecat server` asks before it starts a job that uses an agent (docs/agent-server.md).
"""
from __future__ import annotations

from typing import Sequence

from . import config
from .agent_client import (LABEL_BUSY_CHECK, LABEL_HEALTH, LABEL_VIEWER, Activity, ActivityUnsupported,
                           AgentClient, AgentError, AgentSession)

WORKING_WINDOW = 60                     # seconds since a labelled session's last request
NOT_WORK = (LABEL_HEALTH, LABEL_BUSY_CHECK, "agents ", LABEL_VIEWER)    # label prefixes


def human_duration(secs: float | int | None) -> str:
    s = int(secs or 0)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    return f"{s // 3600}h{s % 3600 // 60:02d}m"


def human_bytes(n: int) -> str:
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= size:
            return f"{n / size:.2f} {unit}"
    return f"{n} B"


def is_working(s: AgentSession) -> bool:
    if not s.authenticated or s.label.startswith(NOT_WORK):
        return False
    if s.command is not None:
        return True
    return bool(s.label) and s.last_request_secs is not None and s.last_request_secs <= WORKING_WINDOW


def working(act: Activity) -> list[AgentSession]:
    """The sessions other than the asker's own that are doing work, longest-running first."""
    return sorted((s for s in act.others() if is_working(s)), key=lambda s: -s.connected_secs)


def describe(s: AgentSession) -> str:
    """`scan \\\\nas3\\Apps by kense@DESKTOP for 12m`"""
    return f"{s.label or 'an unlabelled connection from ' + s.peer} for {human_duration(s.connected_secs)}"


def summary(sessions: Sequence[AgentSession]) -> str:
    text = describe(sessions[0])
    return text + (f" and {len(sessions) - 1} more" if len(sessions) > 1 else "")


def fetch(agent: config.AgentConfig, timeout: float) -> Activity | None:
    """The agent's activity, or None when it cannot be had (an agent older than 0.2.1, unreachable,
    refused): the caller then goes by its own running jobs only."""
    client = AgentClient(agent.host, agent.port, agent.cert_sha256, agent.resolved_token(),
                         timeout=timeout, io_timeout=timeout, name=agent.name, label=LABEL_BUSY_CHECK)
    try:
        return client.activity()
    except (ActivityUnsupported, AgentError, OSError, ValueError, config.ConfigError):
        return None
    finally:
        client.close()
