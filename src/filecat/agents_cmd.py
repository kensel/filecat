"""`filecat agents`: the filecat-agent hosts in filecat.toml.

    list           the configured [[agents]], token masked
    test [NAME..]  connect to each (all when none named): TLS, certificate
                   fingerprint, hello, token; prints the agent's protocol,
                   version and host with the connect and round-trip times.
                   Exit 1 when any agent fails.
    status [NAME..] [--json] [--strict]
                   hello + capabilities of each agent: version, reachable, certificate pin,
                   allowed roots and where they come from, product type, the run ids that are
                   available, and whether the agent's allowlist_sha256 and deny_sha256 are the
                   ones this filecat expects (data/agent_expected.json). A mismatch is a warning;
                   --strict makes it exit 1. Unreachable agents always exit 1.
    enroll NAME --host HOST[:PORT] [--alias \\\\SERVER] [--write] [--token HEX|-]
                   make a token (or reuse the 64 hex digits of --token, `-` reads stdin; a supplied
                   token is never printed back), print the agent's .env lines and the [[agents]] stanza (the
                   token is never in the toml: token = "${FILECAT_<NAME>_TOKEN}"), fetch the
                   certificate fingerprint once (trust on first use) for the admin to compare
                   with what the agent printed. Writes filecat.toml only with --write.
    fingerprint HOST[:PORT]
                   the certificate fingerprint the agent presents (for after the agent started).

See docs/agent-protocol.md and docs/agent-server.md.
"""
from __future__ import annotations

import json
import re
import secrets
import sys
from pathlib import Path
from typing import Any

from . import agent_status, config
from .agent_client import DEFAULT_PORT, AgentClient, fetch_fingerprint, normalize_fingerprint, time_call


def _describe(agent: config.AgentConfig) -> dict[str, Any]:
    return {"name": agent.name, "host": agent.host, "port": agent.port, "alias": agent.alias,
            "cert_sha256": agent.cert_sha256, "token": config.mask_token(agent.token),
            "shares": agent.shares, "volume": agent.volume, "exclude": list(agent.exclude)}


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
        if a.exclude:
            print(f"  policy      {len(a.exclude)} excluded paths")
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


# --- status ------------------------------------------------------------------------------------
def _yesno(match: bool | None) -> str:
    return "unknown" if match is None else "match" if match else "MISMATCH"


def _print_status(st: agent_status.AgentStatus) -> None:
    if not st.ok:
        pin = "" if st.cert_pin is None else f"  (certificate pin: {st.cert_pin})"
        print(f"FAIL {st.name:8} {st.endpoint}  {st.error}{pin}")
        return
    print(f"ok   {st.name:8} {st.endpoint}  filecat-agent {st.version}, protocol {st.protocol}, "
          f"host {st.hostname} ({st.platform})")
    print(f"  cert pin     {st.cert_pin}")
    if st.allow_roots is not None:
        print(f"  allow roots  {':'.join(st.allow_roots)}  (source {st.allow_roots_source or '?'})")
    else:
        print("  allow roots  not reported")
    if st.product_type is not None:
        print(f"  product type {st.product_type}")
    total = len(st.runs_available) + len(st.runs_unavailable)
    line = f"  run ids      {len(st.runs_available)} of {total} available"
    if st.runs_unavailable:
        line += f"; not on this host: {', '.join(st.runs_unavailable)}"
    print(line)
    print(f"  allowlist    {_yesno(st.allowlist_match)}  {st.allowlist_sha256 or '-'}")
    print(f"  deny list    {_yesno(st.deny_match)}  {st.deny_sha256 or '-'}")
    for w in st.warnings:
        print(f"  warning: {w}")


def _status(agents: list[config.AgentConfig], timeout: float, as_json: bool, strict: bool) -> int:
    if not agents:
        print("filecat agents: no [[agents]] to check", file=sys.stderr)
        return 1
    code = 0
    for agent in agents:
        st = agent_status.probe(agent, timeout)
        if as_json:
            print(json.dumps(st.to_dict(), ensure_ascii=False))
        else:
            _print_status(st)
        if not st.ok or (strict and (st.mismatch or st.warnings)):
            code = 1
    return code


# --- enroll ------------------------------------------------------------------------------------
def env_var_for(name: str) -> str:
    return "FILECAT_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper() + "_TOKEN"


def _split_host(text: str) -> tuple[str, int]:
    host, sep, port = text.strip().rpartition(":")
    if not sep or not port.isdigit():
        return text.strip(), DEFAULT_PORT
    if not host or not 1 <= int(port) <= 65535:
        raise config.ConfigError(f"--host {text!r}: want HOST or HOST:PORT")
    return host, int(port)


def stanza(name: str, host: str, port: int, cert: str, alias: str | None) -> str:
    lines = ["[[agents]]", f'name = "{name}"', f'host = "{host}"']
    if port != DEFAULT_PORT:
        lines.append(f"port = {port}")
    if alias:
        lines.append(f"alias = '{alias}'")
    lines.append(f'cert_sha256 = "{cert}"')
    lines.append(f'token = "${{{env_var_for(name)}}}"')
    return "\n".join(lines) + "\n"


def _enroll(args: Any) -> int:
    name = args.name
    if not name or any(c.isspace() for c in name) or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise config.ConfigError(f"NAME {name!r}: use letters, digits, '.', '_' and '-' only")
    host, port = _split_host(args.host)
    path = config.find(getattr(args, "config", None))
    if args.write:
        if path is None:
            raise config.ConfigError("--write: there is no filecat.toml to append to "
                                     "(`filecat config init` writes one, or pass --config PATH)")
        if any(a.name == name for a in config.load_agents(config.load(path))):
            raise config.ConfigError(f"[[agents]] {name!r} already exists in {path}; nothing written, "
                                     "no token made")
    elif path is not None and any(a.name == name for a in config.load_agents(config.load(path))):
        print(f"filecat agents: note: {name!r} is already in {path}; this prints a new token and "
              "stanza but --write would refuse", file=sys.stderr)
    cert, cert_note = None, ""
    if args.cert_sha256:
        try:
            cert = normalize_fingerprint(args.cert_sha256)
        except ValueError as exc:
            raise config.ConfigError(f"--cert-sha256: {exc}") from None
    elif not args.no_connect:
        try:
            cert = fetch_fingerprint(host, port, args.timeout)
        except OSError as exc:
            cert_note = f"could not connect to {host}:{port} ({agent_status.error_text(exc)})"
    given = getattr(args, "token", None)
    if given is not None:
        if given == "-":
            given = sys.stdin.readline().strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", given):
            raise config.ConfigError("--token: want 64 hex digits (32 bytes, what `openssl rand -hex 32` "
                                     "prints); nothing written")
    token = given.lower() if given else secrets.token_hex(32)
    # a token the admin supplied is not printed back: it is in their shell history already, and
    # anything we print lands in the terminal scrollback and logs once more
    shown_token = "<the token you supplied>" if given else token
    var = env_var_for(name)
    shown = cert or "<cert_sha256 the agent prints at its first start>"
    print(f"Enrolling agent {name!r} at {host}:{port}\n")
    print("1. On the agent host, in the .env next to filecat-agent "
          + ("(the token you supplied; it is not repeated here):" if given
             else "(shown once; it is not stored anywhere):"))
    print(f"     FILECAT_AGENT_TOKEN={shown_token}")
    print("     # FILECAT_AGENT_ALLOW_ROOTS=/volume1/Share:/proc:/sys:/dev/disk:/etc/samba:/etc/space:/etc/VERSION")
    print("     chmod 600 .env, then start the agent. It prints its cert_sha256 at first start.\n")
    print(f"2. On the filecat host, put the token in the environment of the process that runs filecat "
          f"({var}):")
    print(f'     PowerShell:  [Environment]::SetEnvironmentVariable("{var}", "{shown_token}", "User")')
    print(f'     sh:          export {var}={shown_token}\n')
    print("3. filecat.toml:\n")
    print("".join("     " + line + "\n" for line in stanza(name, host, port, shown, args.agent_alias).splitlines()))
    if cert:
        print(f"Certificate fingerprint seen at {host}:{port} (trust on first use):\n     {cert}")
        print("   Compare it with the cert_sha256 the agent printed at its first start. If they differ,\n"
              "   something answered that is not your agent; do not use the stanza.")
    else:
        print((cert_note or "not connected (--no-connect)") + ".")
        print("   Start the agent, then `filecat agents fingerprint " + f"{host}:{port}` and compare the value\n"
              "   with the cert_sha256 the agent printed; put it in cert_sha256 above.")
    if args.write:
        if not cert:
            raise config.ConfigError("--write needs the certificate fingerprint: start the agent first, "
                                     "or pass --cert-sha256; nothing written")
        text = path.read_text(encoding="utf-8")
        sep = "" if text.endswith("\n\n") else "\n" if text.endswith("\n") else "\n\n"
        path.write_text(text + sep + stanza(name, host, port, cert, args.agent_alias), encoding="utf-8", newline="\n")
        print(f"\nAppended [[agents]] {name!r} to {path}. Set {var} before `filecat agents test {name}`.")
    else:
        print("\nNothing written (use --write to append the stanza to filecat.toml). "
              + ("The token you supplied is not stored." if given else "The token above is shown only now."))
    return 0


def _fingerprint(args: Any) -> int:
    host, port = _split_host(args.target)
    try:
        print(fetch_fingerprint(host, port, args.timeout))
    except OSError as exc:
        print(f"filecat agents: {host}:{port}: {agent_status.error_text(exc)}", file=sys.stderr)
        return 1
    return 0


def run(args: Any) -> int:
    try:
        if args.action == "enroll":
            return _enroll(args)
        if args.action == "fingerprint":
            return _fingerprint(args)
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
    if args.action == "status":
        return _status(agents, args.timeout, args.json, args.strict)
    return _run_tests(agents, args.timeout, args.json)
