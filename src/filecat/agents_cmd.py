"""`filecat agents`: the filecat-agent hosts in filecat.toml.

    list           the configured [[agents]], token masked
    test [NAME..]  connect to each (all when none named): TLS, certificate
                   fingerprint, hello, token; prints the agent's protocol,
                   version and host with the connect and round-trip times.
                   Exit 1 when any agent fails.

See docs/agent-protocol.md.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from . import config
from .agent_client import AgentClient, time_call


def _describe(agent: config.AgentConfig) -> dict[str, Any]:
    return {"name": agent.name, "host": agent.host, "port": agent.port, "alias": agent.alias,
            "cert_sha256": agent.cert_sha256, "token": config.mask_token(agent.token),
            "shares": agent.shares, "volume": agent.volume, "exclude": list(agent.exclude),
            "rollup_groups": agent.rollup_groups}


def _list(agents: list[config.AgentConfig], as_json: bool) -> int:
    if as_json:
        for agent in agents:
            print(json.dumps(_describe(agent), ensure_ascii=False))
        return 0
    if not agents:
        print("(no [[agents]] in filecat.toml)")
    for a in agents:
        print(f"{a.name}  {a.endpoint}  alias {a.alias}")
        print(f"  cert_sha256 {a.cert_sha256}")
        unset = config.missing_vars(a.token)
        print(f"  token       {config.mask_token(a.token)}"
              + (f"   (not set: {', '.join(unset)})" if unset else ""))
        for prefix, unc in a.shares.items():
            print(f"  share       {prefix} = {unc}")
        extras = [f"{len(a.exclude)} excluded paths" if a.exclude else "",
                  f"{len(a.rollup_groups)} rollup groups" if a.rollup_groups else ""]
        if any(extras):
            print("  policy      " + ", ".join(e for e in extras if e))
    return 0


def _test(agent: config.AgentConfig, timeout: float) -> dict[str, Any]:
    """Connect, then time one more hello. Raises on any failure."""
    client = AgentClient(agent.host, agent.port, agent.cert_sha256, agent.resolved_token(),
                         timeout=timeout, io_timeout=timeout, name=agent.name)
    try:
        info, connect_s = time_call(client.connect)
        _, hello_s = time_call(client.hello)
    finally:
        client.close()
    return {"agent": f"filecat-agent {info.agent_version}", "protocol": info.protocol,
            "hostname": info.hostname, "platform": f"{info.os}/{info.arch}",
            "connect_ms": round(connect_s * 1000, 1), "roundtrip_ms": round(hello_s * 1000, 1)}


def _run_tests(agents: list[config.AgentConfig], timeout: float, as_json: bool) -> int:
    failed = 0
    if not agents:
        print("filecat agents: no [[agents]] to test", file=sys.stderr)
        return 1
    for agent in agents:
        try:
            info = _test(agent, timeout)
        except Exception as exc:  # report every agent, whatever fails
            failed += 1
            message = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
            if as_json:
                print(json.dumps({"name": agent.name, "ok": False, "error": type(exc).__name__,
                                  "code": getattr(exc, "code", None), "message": message}))
            else:
                print(f"FAIL {agent.name:8} {agent.endpoint}  {type(exc).__name__}: {message}")
            continue
        if as_json:
            print(json.dumps({"name": agent.name, "ok": True, **info}))
        else:
            print(f"ok   {agent.name:8} {agent.endpoint}  {info['agent']}, protocol {info['protocol']}, "
                  f"host {info['hostname']} ({info['platform']}); connect {info['connect_ms']} ms, "
                  f"round trip {info['roundtrip_ms']} ms")
    return 1 if failed else 0


def run(args: Any) -> int:
    try:
        agents = config.load_agents(config.load(config.find(getattr(args, "config", None))))
    except config.ConfigError as exc:
        print(f"filecat agents: {exc}", file=sys.stderr)
        return 2
    if args.action == "list":
        return _list(agents, args.json)
    if args.names:
        by_name = {a.name: a for a in agents}
        unknown = [n for n in args.names if n not in by_name]
        if unknown:
            print(f"filecat agents: no agent named {unknown[0]!r}; configured: "
                  f"{', '.join(by_name) or '(none)'}", file=sys.stderr)
            return 2
        agents = [by_name[n] for n in args.names]
    return _run_tests(agents, args.timeout, args.json)
