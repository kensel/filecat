"""filecat.toml: default backend, catalog paths, DSNs and the Ollama model.

Lookup order (first hit wins, FILECAT_CONFIG=none disables every file):
    --config PATH, $FILECAT_CONFIG, ./filecat.toml, the user file
    (%APPDATA%\\filecat\\filecat.toml, or ~/.config/filecat/filecat.toml).

Command-line flags beat environment variables (FILECAT_DSN, OLLAMA_HOST),
which beat the file. `${NAME}` in a value is replaced from the environment
when that value is used, so passwords can stay out of the file.

`filecat config`:
    init    write a commented filecat.toml; sections for database servers
            listening on 127.0.0.1 are filled in, the rest left commented
    show    the file in use and the effective settings, passwords masked
    test    read-only: driver, connect, server version, database, user,
            whether filecat's tables exist
    verify  test, then open the backend as scan would (creating tables or
            collections) and put/get/delete one record and its members under
            a throwaway root

`[[agents]]` tables name the NAS hosts running filecat-agent (see
docs/agent-protocol.md); load_agents validates them and agent_for picks the
one that covers a UNC path. `filecat agents` lists and tests them.
"""
from __future__ import annotations

import os
import re
import socket
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .agent_client import DEFAULT_PORT, ShareMap, normalize_fingerprint
from .backends import BACKENDS, DEFAULT_OUT

FILE_NAME = "filecat.toml"
FILE_BACKENDS = ("jsonl", "sqlite")
SERVER_BACKENDS = tuple(b for b in BACKENDS if b not in FILE_BACKENDS)
VERIFY_ROOT = "filecat-config-verify:"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "gemma4:31b-cloud"

# Local defaults written by `config init`, with the port detection uses.
SERVER_DEFAULTS = {
    "postgres": (5432, "postgresql://filecat:${FILECAT_PG_PASSWORD}@127.0.0.1:5432/filecat"),
    "mysql": (3306, "mysql://filecat:${FILECAT_MYSQL_PASSWORD}@127.0.0.1:3306/filecat"),
    "mssql": (1433, ("DRIVER={%s};SERVER=127.0.0.1,1433;DATABASE=filecat;"
                     "Trusted_Connection=yes;TrustServerCertificate=yes")),
    "mongodb": (27017, "mongodb://127.0.0.1:27017/filecat"),
}
DRIVER_HINT = {
    "postgres": 'uv pip install -e ".[postgres]"',
    "mysql": 'uv pip install -e ".[mysql]"',
    "mssql": 'uv pip install -e ".[mssql]" (plus an ODBC driver for SQL Server)',
    "mongodb": 'uv pip install -e ".[mongo]"',
}

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(ValueError):
    pass


# --- finding and reading ----------------------------------------------
def user_path() -> Path:
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "filecat" / FILE_NAME
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "filecat" / FILE_NAME


def find(explicit: str | None = None) -> Path | None:
    """The config file to use, or None. An explicit path must exist."""
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        return path
    env = os.environ.get("FILECAT_CONFIG")
    if env:
        if env.lower() == "none":
            return None
        path = Path(env)
        if not path.is_file():
            raise ConfigError(f"FILECAT_CONFIG points at a missing file: {path}")
        return path
    for path in (Path.cwd() / FILE_NAME, user_path()):
        if path.is_file():
            return path
    return None


def load(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        with open(path, "rb") as fh:
            cfg = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    backend = cfg.get("backend")
    if backend is not None and backend not in BACKENDS:
        raise ConfigError(f"{path}: backend = {backend!r}; choose from {', '.join(BACKENDS)}")
    return cfg


def expand(value: str | None, *, strict: bool = True) -> str | None:
    """Replace ${NAME} from the environment. strict: an unset NAME is an error."""
    if value is None:
        return None

    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name in os.environ:
            return os.environ[name]
        if strict:
            raise ConfigError(f"${{{name}}} is used in filecat.toml but {name} is not set")
        return m.group(0)
    return _VAR.sub(sub, value)


def missing_vars(value: str | None) -> list[str]:
    return [n for n in _VAR.findall(value or "") if n not in os.environ]


def mask(dsn: str | None) -> str | None:
    """Hide passwords in URL (user:pw@) and ODBC/kwargs (PWD=...;) forms.
    ${NAME} references are left visible: they are not secrets."""
    if dsn is None:
        return None
    dsn = re.sub(r"(://[^:/@]*:)(?!\$\{)[^@]*(@)", r"\1***\2", dsn)
    return re.sub(r"(?i)\b(pwd|password)=(?!\$\{)(\{[^}]*\}|[^;\s]*)", r"\1=***", dsn)


# --- [[agents]] ---------------------------------------------------------
AGENT_KEYS = ("name", "host", "port", "cert_sha256", "token", "alias", "shares", "volume",
              "exclude", "rollup_groups", "timeout")


@dataclass(frozen=True)
class AgentConfig:
    """One [[agents]] table, validated. `token` is as written (it may hold
    ${NAME}); resolved_token() reads the environment."""
    name: str
    host: str
    cert_sha256: str                    # 64 lowercase hex digits
    token: str
    alias: str                          # \\nas-main: the server SMB scans record it under
    port: int = DEFAULT_PORT
    shares: dict[str, str] = field(default_factory=dict)    # POSIX prefix -> UNC root
    volume: int = 1                     # the /volumeN whose /<share> folders are \\alias\<share>
    exclude: tuple[str, ...] = ()
    rollup_groups: dict[str, list[str]] = field(default_factory=dict)
    timeout: float = 30.0

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def resolved_token(self) -> str:
        return expand(self.token)

    def policy(self) -> dict[str, Any]:
        """The configure_policy payload; empty when nothing is configured."""
        policy: dict[str, Any] = {}
        if self.exclude:
            policy["exclude"] = list(self.exclude)
        if self.rollup_groups:
            policy["rollup_groups"] = {k: list(v) for k, v in self.rollup_groups.items()}
        return policy

    def share_map(self) -> ShareMap:
        return ShareMap(self.alias, self.shares, self.volume)


def _agent(table: Any, index: int) -> AgentConfig:
    label = f"[[agents]] #{index}"
    if not isinstance(table, dict):
        raise ConfigError(f"{label}: wants a table with name, host, cert_sha256 and token")
    if isinstance(table.get("name"), str) and table["name"]:
        label += f" ({table['name']})"

    def bad(message: str) -> ConfigError:
        return ConfigError(f"{label}: {message}")

    unknown = [k for k in table if k not in AGENT_KEYS]
    if unknown:
        raise bad(f"unknown key {unknown[0]!r}; the keys are {', '.join(AGENT_KEYS)}")

    def text(key: str, default: str | None = None) -> str:
        value = table.get(key, default)
        if value is None:
            raise bad(f"{key} is required")
        if not isinstance(value, str) or not value.strip():
            raise bad(f"{key} wants a non-empty string")
        return value.strip()

    def number(key: str, default: Any, low: float, high: float | None, kind: type) -> Any:
        value = table.get(key, default)
        ok = (isinstance(value, (int, float)) and not isinstance(value, bool)
              and (kind is float or isinstance(value, int)))
        if not ok or value < low or (high is not None and value > high):
            span = f"from {low:g} to {high:g}" if high is not None else f"of at least {low:g}"
            raise bad(f"{key} = {value!r}; want a number {span}")
        return kind(value)

    name = text("name")
    if any(c.isspace() for c in name):
        raise bad("name must not contain spaces")
    host = text("host")
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        raise bad(f"host = {host!r} includes a port; put it in port = {host.rsplit(':', 1)[1]}")
    try:
        cert = normalize_fingerprint(text("cert_sha256"))
    except ValueError as exc:
        raise bad(f"cert_sha256: {exc}") from None
    shares = table.get("shares", {})
    if not isinstance(shares, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                               for k, v in shares.items()):
        raise bad("[agents.shares] wants '/volume1/Share' = '\\\\server\\Share' string pairs")
    volume = number("volume", 1, 1, None, int)
    try:
        smap = ShareMap(text("alias", "\\\\" + name), shares, volume)
    except ValueError as exc:
        raise bad(str(exc)) from None
    exclude = table.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(x, str) and x for x in exclude):
        raise bad("exclude wants a list of paths or names")
    groups = table.get("rollup_groups", {})
    if (not isinstance(groups, dict)
            or not all(isinstance(k, str) and k and "/" not in k for k in groups)
            or not all(isinstance(v, list) and all(isinstance(x, str) and x for x in v)
                       for v in groups.values())):
        raise bad('[agents.rollup_groups] wants "[TAG]" = ["pattern", ...] pairs')
    return AgentConfig(
        name=name, host=host, cert_sha256=cert, token=text("token"), alias=smap.alias,
        port=number("port", DEFAULT_PORT, 1, 65535, int), shares=dict(shares), volume=volume,
        exclude=tuple(exclude), rollup_groups={k: list(v) for k, v in groups.items()},
        timeout=number("timeout", 30.0, 0.001, None, float))


def load_agents(cfg: dict[str, Any]) -> list[AgentConfig]:
    """The validated [[agents]] tables, in file order."""
    tables = cfg.get("agents")
    if tables is None:
        return []
    if not isinstance(tables, list):
        raise ConfigError("agents: write one [[agents]] table per host (double brackets)")
    agents = [_agent(t, i) for i, t in enumerate(tables, 1)]
    names = [a.name for a in agents]
    for name in names:
        if names.count(name) > 1:
            raise ConfigError(f"[[agents]]: name {name!r} is used twice")
    return agents


def agent_for(agents: list[AgentConfig], unc_path: str) -> AgentConfig | None:
    """The agent that covers a UNC path: the one with the longest matching
    alias or share root (components, case-insensitively); the first listed
    wins a tie. None when no agent does."""
    best, best_len = None, 0
    for agent in agents:
        length = agent.share_map().covers(unc_path)
        if length > best_len:
            best, best_len = agent, length
    return best


def mask_token(token: str) -> str:
    """***, except a ${NAME} reference, which is not a secret (as in mask)."""
    return token if "${" in token else "***"


# --- applying to parsed arguments ---------------------------------------
def apply(args: Any, cfg: dict[str, Any]) -> None:
    """Fill backend/out/dsn/model/ollama_url that the command line left unset,
    merge [aliases] under the command line's --alias, and hand
    scan-everything its [everything] section."""
    if hasattr(args, "alias"):
        from . import aliases
        table = cfg.get("aliases") or {}
        if not isinstance(table, dict) or not all(isinstance(v, str) for v in table.values()):
            raise ConfigError("[aliases] wants 'PATH' = 'ROOT' string pairs")
        try:
            args.aliases = {**table, **aliases.parse(args.alias)}
        except ValueError as exc:
            raise ConfigError(str(exc)) from None
    if getattr(args, "command", None) == "scan-everything":
        everything = cfg.get("everything") or {}
        if not isinstance(everything, dict):
            raise ConfigError("[everything] wants servers = [...], drives = [...]")
        args.everything = everything
    if hasattr(args, "backend"):
        if args.backend is None:
            args.backend = cfg.get("backend") or "sqlite"
        _fill(args, cfg, args.backend, "out", "dsn")
    if hasattr(args, "src_backend"):
        _fill(args, cfg, args.src_backend, "src_out", "src_dsn", env_dsn=False)
        _fill(args, cfg, args.dst_backend, "dst_out", "dst_dsn")
    ollama = cfg.get("ollama") or {}
    if hasattr(args, "model") and args.model is None and ollama.get("model"):
        args.model = ollama["model"]
    if (hasattr(args, "ollama_url") and args.ollama_url is None and ollama.get("url")
            and not os.environ.get("OLLAMA_HOST")):
        args.ollama_url = expand(ollama["url"])


def _fill(args: Any, cfg: dict[str, Any], backend: str, out_attr: str, dsn_attr: str,
          env_dsn: bool = True) -> None:
    section = cfg.get(backend) or {}
    if backend in FILE_BACKENDS:
        if getattr(args, out_attr, None) is None and section.get("out"):
            setattr(args, out_attr, expand(section["out"]))
    elif getattr(args, dsn_attr, None) is None and section.get("dsn"):
        if not (env_dsn and os.environ.get("FILECAT_DSN")):
            setattr(args, dsn_attr, expand(section["dsn"]))


# --- config init --------------------------------------------------------
def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def listening(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _odbc_driver() -> str:
    try:
        import pyodbc
        drivers = [d for d in pyodbc.drivers() if re.fullmatch(r"ODBC Driver \d+ for SQL Server", d)]
        if drivers:
            return max(drivers, key=lambda d: int(re.search(r"\d+", d).group()))
    except ImportError:
        pass
    return "ODBC Driver 18 for SQL Server"


def server_default(name: str) -> str:
    dsn = SERVER_DEFAULTS[name][1]
    return dsn % _odbc_driver() if name == "mssql" else dsn


def render(*, backend: str = "sqlite", dsns: dict[str, str] | None = None,
           outs: dict[str, str] | None = None, model: str = DEFAULT_MODEL,
           ollama_url: str = DEFAULT_OLLAMA_URL, notes: dict[str, str] | None = None) -> str:
    """filecat.toml text. Server sections named in `dsns` are live; the rest
    are written commented out with a local default."""
    dsns = dsns or {}
    outs = outs or {}
    notes = notes or {}
    lines = [
        "# filecat configuration. Command-line flags override these settings;",
        "# FILECAT_DSN and OLLAMA_HOST override the dsn / url here.",
        "# ${NAME} is replaced from the environment when used, e.g.",
        "#   $env:FILECAT_PG_PASSWORD = '...'     (PowerShell)",
        "# Check with: filecat config show / filecat config test / filecat config verify",
        "",
        "# Backend used when --backend is not given: " + " | ".join(BACKENDS),
        f"backend = {_toml_str(backend)}",
        "",
    ]
    for name in FILE_BACKENDS:
        lines += [f"[{name}]", f"out = {_toml_str(outs.get(name, DEFAULT_OUT[name]))}", ""]
    for name in SERVER_BACKENDS:
        if notes.get(name):
            lines.append(f"# {notes[name]}")
        if name in dsns:
            lines += [f"[{name}]", f"dsn = {_toml_str(dsns[name])}", ""]
        else:
            lines += [f"# [{name}]", f"# dsn = {_toml_str(server_default(name))}", ""]
    lines += [
        "[ollama]",
        f"url = {_toml_str(ollama_url)}",
        f"model = {_toml_str(model)}",
        "",
        "# filecat-agent on a NAS (docs/agent-protocol.md), one [[agents]] per host. The agent prints",
        "# its cert_sha256 when it starts; the token is the one it was started with.",
        "# [[agents]]",
        '# name = "nas-main"',
        '# host = "192.0.2.13"',
        "# port = 9876",
        '# cert_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        '# token = "${FILECAT_NAS_MAIN_TOKEN}"',
        "# alias = '\\\\nas-main'      # the server SMB scans record it under (default \\\\NAME)",
        "# [agents.shares]           # folders that are not /volume1/<share>",
        "# '/volume2/Archive' = '\\\\nas-main\\Archive'",
        "",
    ]
    return "\n".join(lines)


def cmd_init(args: Any) -> int:
    path = Path(args.path) if args.path else (user_path() if args.user else Path.cwd() / FILE_NAME)
    if path.exists() and not args.force and not args.stdout:
        print(f"filecat config init: {path} exists (use --force to overwrite)", file=sys.stderr)
        return 1
    dsns: dict[str, str] = {}
    notes: dict[str, str] = {}
    if not args.no_detect:
        for name, (port, _) in SERVER_DEFAULTS.items():
            if listening(port):
                dsns[name] = server_default(name)
                notes[name] = f"detected: something is listening on 127.0.0.1:{port}"
    backend = args.backend or "sqlite"
    if args.dsn:
        if backend not in SERVER_BACKENDS:
            print("filecat config init: --dsn needs --backend " + "|".join(SERVER_BACKENDS), file=sys.stderr)
            return 2
        dsns[backend] = args.dsn
        notes.pop(backend, None)
    elif backend in SERVER_BACKENDS:
        dsns.setdefault(backend, server_default(backend))
    outs = {backend: args.out} if args.out and backend in FILE_BACKENDS else {}
    text = render(backend=backend, dsns=dsns, outs=outs, model=args.model or DEFAULT_MODEL, notes=notes)
    if args.stdout:
        sys.stdout.write(text)
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path}")
    for name, note in notes.items():
        print(f"  {name}: {note}")
    print("next: filecat config test")
    return 0


# --- config show --------------------------------------------------------
def cmd_show(args: Any, path: Path | None, cfg: dict[str, Any]) -> int:
    print(f"config file: {path if path else '(none; built-in defaults)'}")
    if not path:
        print(f"  searched: ./{FILE_NAME}, {user_path()}  (create one with: filecat config init)")
    print(f"backend:     {cfg.get('backend') or 'sqlite'}")
    for name in FILE_BACKENDS:
        out = (cfg.get(name) or {}).get("out") or DEFAULT_OUT[name]
        print(f"  {name:8} out = {out}")
    for name in SERVER_BACKENDS:
        dsn = (cfg.get(name) or {}).get("dsn")
        if dsn is None:
            continue
        shown = dsn if args.reveal else mask(dsn)
        unset = missing_vars(dsn)
        warn = f"   (not set: {', '.join(unset)})" if unset else ""
        print(f"  {name:8} dsn = {shown}{warn}")
    if os.environ.get("FILECAT_DSN"):
        print(f"  FILECAT_DSN is set and overrides the dsn above: "
              f"{os.environ['FILECAT_DSN'] if args.reveal else mask(os.environ['FILECAT_DSN'])}")
    ollama = cfg.get("ollama") or {}
    url = os.environ.get("OLLAMA_HOST") or ollama.get("url") or DEFAULT_OLLAMA_URL
    print(f"ollama:      {url}  model = {ollama.get('model') or '(none; pass --model)'}")
    try:
        agents = load_agents(cfg)
    except ConfigError as exc:
        print(f"agents:      invalid: {exc}")
        return 1
    if agents:
        print(f"agents:      {len(agents)} configured (filecat agents test)")
    for a in agents:
        unset = missing_vars(a.token)
        warn = f"   (not set: {', '.join(unset)})" if unset else ""
        print(f"  {a.name:8} {a.endpoint}  alias = {a.alias}  cert_sha256 = {a.cert_sha256}")
        print(f"  {'':8} token = {a.token if args.reveal else mask_token(a.token)}{warn}")
        for prefix, unc in a.shares.items():
            print(f"  {'':8} share {prefix} = {unc}")
    return 0


# --- config test / verify -------------------------------------------------
def _targets(args: Any, cfg: dict[str, Any]) -> list[str]:
    if args.targets:
        bad = [t for t in args.targets if t not in BACKENDS + ("ollama",)]
        if bad:
            raise ConfigError(f"unknown target {bad[0]!r}; choose from {', '.join(BACKENDS + ('ollama',))}")
        return list(args.targets)
    targets = [cfg.get("backend") or "sqlite"]
    targets += [n for n in SERVER_BACKENDS if (cfg.get(n) or {}).get("dsn") and n not in targets]
    if cfg.get("ollama"):
        targets.append("ollama")
    return targets


def _location(name: str, args: Any, cfg: dict[str, Any]) -> str | None:
    section = cfg.get(name) or {}
    single = args.targets and len(args.targets) == 1
    if name in FILE_BACKENDS:
        return (single and args.out) or expand(section.get("out")) or DEFAULT_OUT[name]
    if single and args.dsn:
        return args.dsn
    if os.environ.get("FILECAT_DSN") and name == (cfg.get("backend") or "sqlite"):
        return os.environ["FILECAT_DSN"]
    return expand(section.get("dsn"))


def _test_file(name: str, out: str) -> dict[str, Any]:
    path = Path(out)
    info: dict[str, Any] = {"path": str(path.resolve())}
    parent = path.resolve().parent
    if not parent.is_dir():
        raise ConfigError(f"directory {parent} does not exist")
    if not os.access(parent, os.W_OK):
        raise ConfigError(f"directory {parent} is not writable")
    if not path.exists():
        layout = "directory" if name == "jsonl" and path.suffix.lower() != ".jsonl" else "file"
        info["note"] = f"{layout} does not exist yet; the first scan creates it"
        return info
    if path.is_dir():
        from .backends.jsonl_dir import _ROOT_FILE
        files = [p for p in path.iterdir() if p.is_file()]
        info["layout"] = "one file per root"
        info["roots"] = sum(1 for p in files if _ROOT_FILE.match(p.name))
        info["size_mb"] = round(sum(p.stat().st_size for p in files) / 1e6, 1)
        return info
    info["size_mb"] = round(path.stat().st_size / 1e6, 1)
    if name == "sqlite":
        import sqlite3
        conn = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=5)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            info["tables"] = sorted(tables & {"files", "members"})
            if "files" in tables:
                info["files_estimate"] = conn.execute("SELECT max(rowid) FROM files").fetchone()[0] or 0
        finally:
            conn.close()
    return info


def _ollama_url(cfg: dict[str, Any]) -> str:
    url = os.environ.get("OLLAMA_HOST") or expand((cfg.get("ollama") or {}).get("url")) or DEFAULT_OLLAMA_URL
    if "://" not in url:
        url = "http://" + url
    return url.rstrip("/")


def _test_ollama(cfg: dict[str, Any], timeout: float, generate: bool) -> dict[str, Any]:
    import json
    import urllib.request
    url = _ollama_url(cfg)
    model = (cfg.get("ollama") or {}).get("model")
    try:
        with urllib.request.urlopen(url + "/api/version", timeout=timeout) as resp:
            version = json.load(resp).get("version")
    except OSError as exc:
        reason = getattr(exc, "reason", exc)
        raise ConfigError(f"cannot reach Ollama at {url} ({reason}); is it running?") from None
    with urllib.request.urlopen(url + "/api/tags", timeout=timeout) as resp:
        names = [m.get("name") for m in json.load(resp).get("models", [])]
    info: dict[str, Any] = {"server": f"Ollama {version} at {url}", "models": len(names)}
    if model:
        if model not in names and f"{model}:latest" not in names:
            raise ConfigError(f"model {model} is not pulled (ollama pull {model})")
        info["model"] = model
        if generate:
            body = json.dumps({"model": model, "prompt": "Reply with OK.", "stream": False,
                               "options": {"num_predict": 4}}).encode()
            req = urllib.request.Request(url + "/api/generate", data=body,
                                         headers={"Content-Type": "application/json"})
            t = time.monotonic()
            with urllib.request.urlopen(req, timeout=max(timeout, 60)) as resp:
                reply = json.load(resp).get("response", "").strip()
            info["generate"] = f"{reply[:20]!r} in {time.monotonic() - t:.1f}s"
    return info


def _roundtrip(name: str, location: str) -> dict[str, Any]:
    """Open the backend as scan does (creates its schema), then write, read
    back and delete one record plus two member rows under VERIFY_ROOT."""
    from .backends import open_backend
    from .record import new_document
    t = time.monotonic()
    backend = open_backend(name, dsn=location)
    try:
        doc = new_document(VERIFY_ROOT, "probe/check.txt", kind="text", size=3)
        doc["probe"] = {"verify": True, "nested": {"list": [1, 2, 3]}, "text": "café ✓"}
        backend.put(doc)
        backend.flush()
        got = backend.get(VERIFY_ROOT, "probe/check.txt")
        if got != doc:
            raise ConfigError(f"read back a different record: {got!r}")
        members = [{"index": 0, "path": "a.txt", "size": 1}, {"index": 1, "path": "b/ü.bin", "size": 2}]
        backend.put_members(VERIFY_ROOT, "probe/check.txt", members)
        backend.flush()
        listed = [m.get("path") for m in backend.list_members(VERIFY_ROOT, "probe/check.txt")]
        if listed != ["a.txt", "b/ü.bin"]:
            raise ConfigError(f"members read back as {listed!r}")
        backend.delete(VERIFY_ROOT, "probe/check.txt")
        backend.flush()
        if backend.get(VERIFY_ROOT, "probe/check.txt") is not None:
            raise ConfigError("record still present after delete")
        if list(backend.list_members(VERIFY_ROOT, "probe/check.txt")):
            raise ConfigError("members still present after delete")
    finally:
        backend.close()
    return {"roundtrip": f"schema, put/get, members, delete ok in {time.monotonic() - t:.2f}s"}


def _check(name: str, args: Any, cfg: dict[str, Any], verify: bool) -> dict[str, Any]:
    if name == "ollama":
        return _test_ollama(cfg, args.timeout, generate=verify)
    location = _location(name, args, cfg)
    if name in FILE_BACKENDS:
        return _test_file(name, location)
    if not location:
        raise ConfigError(f"no dsn: add [{name}] dsn = \"...\" to filecat.toml or pass --dsn")
    import importlib
    module = importlib.import_module(f".backends.{name}", __package__)
    try:
        info = module.ping(location, args.timeout)
    except ImportError as exc:
        raise ConfigError(f"driver missing ({exc}); {DRIVER_HINT[name]}") from None
    info["dsn"] = mask(location)
    if verify:
        info.update(_roundtrip(name, location))
    return info


def cmd_test(args: Any, cfg: dict[str, Any], verify: bool) -> int:
    failed = 0
    for name in _targets(args, cfg):
        try:
            info = _check(name, args, cfg, verify)
        except Exception as exc:  # report every target, whatever its driver raises
            failed += 1
            message = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
            print(f"FAIL {name:8} {type(exc).__name__}: {message}")
            if name in SERVER_BACKENDS and _location(name, args, cfg):
                print(f"     {'':8} dsn={mask(_location(name, args, cfg))}")
            continue
        warning = info.pop("warning", None)
        print(f"ok   {name:8} " + ", ".join(f"{k}={v}" for k, v in info.items()))
        if warning:
            print(f"     {'':8} warning: {warning}")
    return 1 if failed else 0


def run(args: Any) -> int:
    try:
        path = find(getattr(args, "config", None))
        cfg = load(path)
        if args.action == "init":
            return cmd_init(args)
        if args.action == "show":
            return cmd_show(args, path, cfg)
        return cmd_test(args, cfg, verify=args.action == "verify")
    except ConfigError as exc:
        print(f"filecat config: {exc}", file=sys.stderr)
        return 2
