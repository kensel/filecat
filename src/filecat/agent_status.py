"""One agent's health and capabilities, as `filecat agents status` and `filecat server` read them.

`probe` connects (TLS, certificate pin, hello, auth), asks `capabilities` and compares the
agent's `allowlist_sha256` and `deny_sha256` with what this filecat version expects
(agent_expected.py). It never raises: every failure is a field of the result.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import agent_expected, config
from .agent_client import AgentClient, AgentError, FingerprintMismatch

_PATHLIKE = re.compile(r"""(\\\\[^\s'"]+|[A-Za-z]:[\\/][^\s'"]*|/[^\s'"]+)""")


def scrub(message: str, limit: int = 300) -> str:
    """A message safe to log and store: anything that looks like a path is replaced, so an error
    cannot carry the name of a folder (docs/rollups.md section 3.1), and it is cut short."""
    text = " ".join(str(message).split())
    return _PATHLIKE.sub("<path>", text)[:limit]


def error_text(exc: BaseException) -> str:
    """`Type: message` with paths scrubbed; an OSError's filename is not repeated."""
    return f"{type(exc).__name__}: {scrub(str(exc))}" if str(exc) else type(exc).__name__


@dataclass
class AgentStatus:
    name: str
    endpoint: str
    reachable: bool = False
    cert_pin: str | None = None             # "ok" | "mismatch" | None (not reached)
    error: str | None = None
    error_code: str | None = None
    version: str | None = None
    protocol: int | None = None
    hostname: str | None = None
    platform: str | None = None             # "linux/aarch64"
    allow_roots: list[str] | None = None
    allow_roots_source: str | None = None
    product_type: int | None = None
    runs_available: list[str] = field(default_factory=list)
    runs_unavailable: list[str] = field(default_factory=list)
    allowlist_sha256: str | None = None
    deny_sha256: str | None = None
    allowlist_match: bool | None = None     # None: not known (agent silent, or nothing expected)
    deny_match: bool | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.reachable and self.cert_pin == "ok" and self.error is None

    @property
    def mismatch(self) -> bool:
        return self.allowlist_match is False or self.deny_match is False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ok"] = self.ok
        d["mismatch"] = self.mismatch
        return d


def probe(agent: config.AgentConfig, timeout: float = 5.0,
          table: dict[str, Any] | None = None) -> AgentStatus:
    st = AgentStatus(agent.name, agent.endpoint)
    try:
        client = AgentClient(agent.host, agent.port, agent.cert_sha256, agent.resolved_token(),
                             timeout=timeout, io_timeout=timeout, name=agent.name)
    except (config.ConfigError, ValueError) as exc:         # an unset ${VAR} for the token
        st.error, st.error_code = error_text(exc), "config"
        return st
    try:
        info = client.connect()
        st.reachable, st.cert_pin = True, "ok"
        st.version, st.protocol, st.hostname = info.agent_version, info.protocol, info.hostname
        st.platform = f"{info.os}/{info.arch}"
        try:
            caps = client.capabilities()
        except AgentError as exc:
            st.warnings.append(f"capabilities not available: {exc.code}")
            return st
        st.allow_roots = list(caps.allow_roots) if caps.allow_roots is not None else None
        st.allow_roots_source = caps.allow_roots_source
        st.product_type = caps.product_type
        st.runs_available = sorted(i for i, c in caps.entries.items() if c.available)
        st.runs_unavailable = sorted(i for i, c in caps.entries.items() if not c.available)
        st.allowlist_sha256, st.deny_sha256 = caps.allowlist_sha256, caps.deny_sha256
        st.allowlist_match, st.deny_match = agent_expected.compare(
            info.protocol, caps.platform or info.os, caps.allowlist_sha256, caps.deny_sha256, table)
        if st.mismatch:
            st.warnings.append(agent_expected.MISMATCH_WARNING)
    except FingerprintMismatch as exc:
        st.reachable, st.cert_pin = True, "mismatch"
        st.error, st.error_code = error_text(exc), exc.code
    except AgentError as exc:                                # reached it: auth, protocol
        st.reachable = True
        st.error, st.error_code = error_text(exc), exc.code
    except OSError as exc:                                   # refused, timed out, no route
        st.error, st.error_code = error_text(exc), type(exc).__name__
    finally:
        client.close()
    return st
