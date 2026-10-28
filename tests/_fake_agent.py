"""A filecat-agent speaking protocol 1 (docs/agent-protocol.md), in Python,
for the agent client's tests.

It serves a temp directory as "/": the agent path /volume1/Backup/a.zip is
<root>/volume1/Backup/a.zip. Digests come from filecat.hashing, the
reference the Rust agent must reproduce, fed the 100 ns-floored mtime the
protocol demands. TLS uses the self-signed pair in tests/data (generated
once with openssl, ed25519, valid to 2126; the key protects nothing).

The agent side of docs/rollups.md (section 8) is here too, written from the
document and not from filecat.rollup: importing the Python matcher would
test it against itself. Rules are matched with regular expressions built from
the patterns (ASCII case folding is re.ASCII | re.IGNORECASE); the HMAC and
the wire policy id are computed with hashlib and hmac. Everything a test
needs to look at is public: `requests` (parsed), `wire` (every line in both
directions, as text), `log` (what the agent would log: never a name inside a
folded folder), `unreadable` (names that fail to open), `mounts` (folder
names treated as another file system), `sum_delay`, `progress_always`,
`max_sums`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any

from filecat.hashing import hash_file

DATA = Path(__file__).parent / "data"
CERT = DATA / "agent.crt"
KEY = DATA / "agent.key"
MAX_READ = 4 * 1024 * 1024
READ_FILE_DEFAULT = 256 * 1024
MAX_STDOUT = 4 * 1024 * 1024
MAX_STDERR = 64 * 1024
# The compiled-in allowlist of docs/agent-allowlist.md (the entries the tests need): id -> argument
# kind (None: the request carries no `arg`). The real table is Rust; this one is the contract.
ALLOWLIST: dict[str, str | None] = {
    "lsblk_json": None, "lsblk_json_legacy": None, "lsblk_pairs": None, "blkid_export": None,
    "findmnt_json": None, "btrfs_show": None, "btrfs_usage": "btrfs_mount",
    "mdadm_detail_scan": None, "mdadm_detail": "md_device",
    "smartctl_info_json": "block_device", "smartctl_info_json_sat": "block_device",
    "smartctl_info": "block_device", "smartctl_all_json": "block_device", "smartctl_version": None,
    "zpool_list": None, "zpool_status": None, "zfs_list": None, "zpool_get": None,
}

# --- the agent's read scope (docs/agent-protocol.md, "Allowed roots and the deny list") --------
# Deny list, compiled into the real agent: wins over the allowed roots, no configuration changes
# it. It applies to commands that return file content (read_file, read_range, measure), to the
# canonical path (symlinks resolved). `*` matches inside one path component.
from filecat.agent_expected import (DENY_POSIX, DENY_WINDOWS, ENV_ALLOWED, SIGNATURE_LINES,  # noqa: E402
                                    deny_sha256)
# Private keys are denied by content: the head of the file (first SIGNATURE_WINDOW bytes, after an
# optional UTF-8 BOM and leading ASCII whitespace) decides, whatever the name. A regex per rule,
# written from docs/agent-protocol.md and not from filecat.secretfiles.
SIGNATURE_WINDOW = 256
KEY_SIGNATURES = (rb"-----BEGIN [^\n]*PRIVATE KEY-----[ \t\r]*(?:\n|\Z)",
                  rb"-----BEGIN PGP PRIVATE KEY BLOCK-----", rb"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
                  rb"PuTTY-User-Key-File-")
# deny_sha256 covers the path rules, the env-file exceptions, the Windows rules and the key
# signatures one per line (filecat.agent_expected computes it, as the Rust agent does).
DENY_SHA256 = deny_sha256()
# Files the agent serves with credentials blanked (read_file only): path -> keys whose value becomes
# REDACTED. A table in the binary so a file can be added; not configurable.
REDACTED = b"<filecat-redacted>"
REDACT_FILES: dict[str, tuple[bytes, ...]] = {
    "/usr/syno/etc/iscsi_target.conf": (b"username", b"password", b"mutual_username", b"mutual_password"),
}
# Windows file attributes of a file that is not on the device (filecat.cloudfiles): never opened.
RECALL_ON_DATA_ACCESS, RECALL_ON_OPEN, OFFLINE = 0x400000, 0x40000, 0x1000
NOT_LOCAL = RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE
ARCHIVE = 0x20


def private_key_head(head: bytes) -> bool:
    """The deny list's content rule on the first bytes of a file."""
    h = re.sub(rb"\A(?:\xef\xbb\xbf)?[ \t\r\n]*", b"", head[:SIGNATURE_WINDOW])
    return any(re.match(sig, h) for sig in KEY_SIGNATURES)


def redact_credentials(data: bytes, keys: tuple[bytes, ...]) -> bytes:
    """Every `key=value` line whose key is in `keys` gets the marker as its value."""
    out = []
    for line in data.splitlines(keepends=True):
        key, eq, rest = line.partition(b"=")
        if eq and key.strip() in keys:
            body = rest.rstrip(b"\r\n")
            line = key + eq + REDACTED + rest[len(body):]
        out.append(line)
    return b"".join(out)


def default_windows_roots(product_type: int, system_drive: str, fixed_volumes: list[str],
                          disk_shares: list[str]) -> list[str]:
    """The default allowed roots of a Windows agent: every local fixed volume, the system drive only
    on a client (Win32_OperatingSystem.ProductType 1: Windows 10/11; 2 domain controller and 3
    server leave it out, and so does an unknown type), plus the path of each disk share not already
    under one of them."""
    volumes = [v for v in fixed_volumes if product_type == 1 or v.lower() != system_drive.lower()]
    return volumes + [s for s in disk_shares if not any(under(v, s, "\\", True) for v in volumes)]


def _comp_match(pattern: str, name: str, fold: bool = False) -> bool:
    if fold:
        pattern, name = pattern.lower(), name.lower()
    return re.fullmatch(".*".join(re.escape(p) for p in pattern.split("*")), name) is not None


def under(pattern: str, path: str, sep: str = "/", fold: bool = False) -> bool:
    """`path` is `pattern` or below it, component by component; `*` is a glob inside one component."""
    pp, xs = [c for c in pattern.split(sep) if c], [c for c in path.split(sep) if c]
    return len(xs) >= len(pp) and all(_comp_match(a, b, fold) for a, b in zip(pp, xs))


def is_env_file(name: str, fold: bool = False) -> bool:
    n = name.lower() if fold else name
    return (n == ".env" or n.startswith(".env.")) and n not in ENV_ALLOWED


def denied(path: str) -> bool:
    """POSIX deny list on a canonical path."""
    return (any(under(p, path) for p in DENY_POSIX) or is_env_file(path.rsplit("/", 1)[-1]))


def denied_windows(path: str, system_root: str = r"C:\Windows") -> bool:
    """Windows deny list on a canonical (final, long-name, case-insensitive) path."""
    low = path.lower()
    if any(under(d.replace("%SystemRoot%", system_root), path, "\\", True) for d in DENY_WINDOWS):
        return True
    name = low.rsplit("\\", 1)[-1]
    return (is_env_file(name, True) or name.endswith(".dit") or name.startswith(("ntuser.dat", "usrclass.dat")))


def resolve_allow_roots(environ: dict[str, str], dotenv: str | None, default: list[str]
                        ) -> tuple[list[str], str]:
    """The effective allowed roots and where they came from: FILECAT_AGENT_ALLOW_ROOTS in the
    environment wins over the same key in the `.env` file next to the agent binary; neither: the
    built-in default. A variable that is set but empty means no roots (every path is refused)."""
    sep = ";" if os.name == "nt" else ":"
    raw, source = environ.get("FILECAT_AGENT_ALLOW_ROOTS"), "env"
    if raw is None and dotenv is not None:
        for line in dotenv.splitlines():
            key, eq, value = line.strip().partition("=")
            if eq and key.strip() == "FILECAT_AGENT_ALLOW_ROOTS":
                raw, source = value.strip().strip("\"'"), "env_file"
    if raw is None:
        return list(default), "default"
    return [r for r in raw.split(sep) if r], source


MAX_RULES = 1024
MAX_PATTERN_BYTES = 4096
MAX_PATTERNS_BYTES = 64 * 1024
MAX_REDACTION = 10_000


def cert_fingerprint(cert: Path = CERT) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()


def floor100(ns: int) -> int:
    return ns - ns % 100


class _Fail(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# --- the matcher, from the document ---------------------------------------------
def _glob_re(comp: str) -> str:
    return "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in comp)


def compile_pattern(pattern: str, insensitive: bool) -> tuple[str, "re.Pattern[str]"]:
    """("name" | "path", regex). A name pattern is matched against a child's
    name; anything else against its whole absolute path, anchored at both ends
    (a leading ** is a suffix pattern)."""
    flags = re.ASCII | re.IGNORECASE if insensitive else 0
    if "/" not in pattern:
        return "name", re.compile(_glob_re(pattern), flags)
    comps = [c for c in pattern.split("/") if c]
    out = ""
    for i, c in enumerate(comps):
        if c == "**":
            out += "(?:/[^/]+)+" if i == len(comps) - 1 else "(?:/[^/]+)*"
        else:
            out += "/" + _glob_re(c)
    return "path", re.compile(out, flags)


class _Rule:
    def __init__(self, raw: dict[str, Any]) -> None:
        self.id = raw.get("id")
        self.tag = raw.get("tag")
        self.type = raw.get("type", "any")
        self.keep = bool(raw.get("keep"))
        self.private = bool(raw.get("private"))
        self.suggest = bool(raw.get("suggest"))
        insensitive = raw.get("case", "sensitive") == "insensitive"
        self.patterns = [compile_pattern(p, insensitive) for p in raw.get("match", [])]

    def matches(self, name: str, path: str, is_dir: bool) -> bool:
        if self.type == "dir" and not is_dir or self.type == "file" and is_dir:
            return False
        for kind, rx in self.patterns:
            if rx.fullmatch(name if kind == "name" else path):
                return True
        return False


def policy_id(rules: list[dict[str, Any]], marker_names: list[str]) -> str:
    """The first 12 hex digits of the SHA-256 of the compact JSON of
    [rules, marker names]; a rule is {"tag","match","type","case","keep",
    "private","suggest"}, tag null for keep and the booleans false when absent."""
    canon = [{"tag": r.get("tag"), "match": r.get("match", []), "type": r.get("type", "any"),
              "case": r.get("case", "sensitive"), "keep": bool(r.get("keep")),
              "private": bool(r.get("private")), "suggest": bool(r.get("suggest"))} for r in rules]
    text = json.dumps([canon, marker_names], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def redaction_hash(key: bytes, root: str, rel: str) -> str:
    data = b"filecat-redact-v1\0" + root.encode() + b"\0" + rel.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()[:32]


def storage_name(raw: bytes) -> str:
    """The catalog's spelling of a name: each byte of an invalid UTF-8 sequence b
    becomes U+F700 + b."""
    text = raw.decode("utf-8", "surrogateescape")
    return "".join(chr(0xF700 + (ord(c) - 0xDC00)) if 0xDC80 <= ord(c) <= 0xDCFF else c for c in text)


class _Policy:
    def __init__(self, raw: dict[str, Any]) -> None:
        self.exclude = set(raw.get("exclude", []))
        self.raw_rules = list(raw.get("rules", []))
        self.rules = [_Rule(r) for r in self.raw_rules]
        self.markers = list(raw.get("markers", []))
        red = raw.get("redaction") or {}
        self.key = bytes.fromhex(red["key"]) if red.get("key") else None
        self.redaction_roots = list(red.get("roots", []))
        self.has_rules = bool(self.rules or self.markers)

    def policy_id(self) -> str:
        return policy_id(self.raw_rules, [m["name"] for m in self.markers])


class FakeAgent:
    def __init__(self, root: Path, token: str = "s3cret", *, protocol: int = 1,
                 cert: Path = CERT, key: Path = KEY, allow_roots: list[str] | None = None) -> None:
        self.root = root
        self.token = token
        self.protocol = protocol
        self.allow_roots = allow_roots                  # None: this fake imposes no roots (the deny list always applies)
        self.allow_roots_source = "env"
        self.allowlist_sha256: str | None = None        # capabilities report this instead of the fake's own digest
        self.deny_sha256: str | None = None             # ... and this instead of DENY_SHA256
        self.product_type: int | None = None            # a Windows agent's Win32_OperatingSystem.ProductType
        self.requests: list[dict[str, Any]] = []        # every request received, in order
        self.wire: list[tuple[str, str]] = []           # ("in" | "out", the line as text), both ways
        self.log: list[str] = []                        # what the agent would log
        self.connections = 0
        self.entry_errors: set[str] = set()             # names list_dir reports with an error
        self.extra_entries: list[dict[str, Any]] = []   # raw entries appended to every list_dir
        self.extras: dict[str, list[dict[str, Any]]] = {}   # ... or only to list_dir of this path
        self.served_as: dict[str, bytes] = {}           # real name -> the (non-UTF-8) bytes it is listed as
        self.unreadable: set[str] = set()               # names that fail to open when summed (EACCES)
        self.mounts: set[str] = set()                   # folder names that count as another file system
        self.sum_delay = 0.0                            # seconds per folder entered while summing
        self.progress_always = False                    # send a progress line whenever progress_ms is set
        self.max_sums = 4                               # concurrent long sums before `busy`
        self.cancelled: list[str] = []                  # ids of requests a cancel stopped
        self.run_outputs: dict[str, dict[str, Any]] = {}    # "id" or "id@arg" -> {"stdout", "stderr", "exit_code", ...}
        self.unavailable: set[str] = set()              # allowlist ids whose binary is missing on this host
        self.statfs_data: dict[str, dict[str, Any]] = {}    # path -> the statfs reply fields
        self.subtree_overrides: dict[str, dict[str, Any]] = {}  # path -> a recorded sum_subtree reply (paths a test machine cannot have: a 512 GiB ROD)
        self.ran: list[tuple[str, str | None]] = []     # (id, arg) of every command the agent ran
        self.attributes_after_list: dict[str, int] = {}     # served path -> attributes at read time, when they changed since list_dir
        self.windows_attributes: dict[str, int] | None = None   # a Windows agent: served path -> file attribute bits (default ARCHIVE); None: POSIX
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._open: list[socket.socket] = []
        self._lock = threading.Lock()
        self._running: dict[str, threading.Event] = {}
        self._sums = 0
        self._stop = False
        self._acceptor = threading.Thread(target=self._accept, daemon=True)
        self._acceptor.start()

    def __enter__(self) -> "FakeAgent":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def stop(self) -> None:
        self._stop = True
        # Linux: close() does not wake a thread blocked in accept(), and the socket keeps listening
        # until that thread leaves it; shutdown() wakes it, then the port really refuses connections.
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._listener.close()
        except OSError:
            pass
        if threading.current_thread() is not self._acceptor:
            self._acceptor.join(2)
        self.drop_connections()

    def drop_connections(self) -> None:
        """Close every open connection, as an agent restart or an idle timeout would."""
        with self._lock:
            sockets, self._open = self._open, []
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    # --- connections ---
    def _accept(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, raw: socket.socket) -> None:
        try:
            conn = self._ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            return
        with self._lock:
            self._open.append(conn)
            self.connections += 1
        authed = False
        state: dict[str, Any] = {"policy": _Policy({})}

        def send(obj: dict[str, Any]) -> None:
            data = json.dumps(obj)
            with self._lock:
                self.wire.append(("out", data))
            conn.sendall(data.encode() + b"\n")

        try:
            rfile = conn.makefile("rb")
            while True:
                line = rfile.readline()
                if not line:
                    return
                with self._lock:
                    self.wire.append(("in", line.decode("utf-8", "replace").rstrip("\n")))
                close = False
                try:
                    req = json.loads(line)
                    if not isinstance(req, dict):
                        raise _Fail("bad_request", "not an object")
                    with self._lock:
                        self.requests.append(req)
                    cmd = req.get("cmd")
                    if cmd == "hello":
                        resp = {"ok": True, "protocol": self.protocol, "agent_version": "0.2.0-test",
                                "hostname": "fake-nas", "os": "linux", "arch": "x86_64"}
                    elif cmd == "auth":
                        if req.get("token") != self.token:
                            close = True
                            raise _Fail("unauthorized", "invalid token")
                        authed, resp = True, {"ok": True}
                    elif not authed:
                        raise _Fail("unauthorized", "authenticate first")
                    elif cmd == "configure_policy":
                        state["policy"] = self._configure(req.get("policy") or {})
                        resp = {"ok": True}
                        if state["policy"].has_rules:
                            resp.update(policy_id=state["policy"].policy_id(),
                                        rules=len(state["policy"].rules),
                                        markers=len(state["policy"].markers))
                    elif cmd == "cancel":
                        with self._lock:
                            ev = self._running.get(str(req.get("id")))
                        if ev is not None:
                            ev.set()
                        resp = {"ok": True, "found": ev is not None}
                    else:
                        resp = self._command(cmd, req, state["policy"], send)
                except _Fail as exc:
                    resp = {"ok": False, "error": str(exc), "code": exc.code}
                except FileNotFoundError as exc:
                    resp = {"ok": False, "error": str(exc), "code": "not_found"}
                except PermissionError as exc:
                    resp = {"ok": False, "error": str(exc), "code": "permission_denied"}
                except json.JSONDecodeError:
                    resp = {"ok": False, "error": "bad json", "code": "bad_request"}
                except OSError as exc:
                    resp = {"ok": False, "error": str(exc), "code": "io"}
                send(resp)
                if close:
                    return
        except OSError:
            return
        finally:
            conn.close()

    # --- policy ---
    @staticmethod
    def _configure(raw: dict[str, Any]) -> _Policy:
        rules = raw.get("rules", [])
        if len(rules) > MAX_RULES:
            raise _Fail("bad_request", "too many rules")
        total = 0
        for r in rules:
            for p in r.get("match", []):
                if len(p.encode()) > MAX_PATTERN_BYTES:
                    raise _Fail("bad_request", "pattern too long")
                total += len(p.encode())
        if total > MAX_PATTERNS_BYTES:
            raise _Fail("bad_request", "patterns too big")
        for entry in (raw.get("redaction") or {}).get("roots", []):
            if len(entry.get("hashes", [])) + len(entry.get("inodes", [])) > MAX_REDACTION:
                raise _Fail("bad_request", "too many redactions")
        return _Policy(raw)

    # --- commands ---
    def real(self, req: dict[str, Any], content: bool | str = False) -> Path:
        """The served file of a request. The scope is checked on the canonical path (symlinks
        resolved), before the file is looked up, so a path outside gets `refused` whether or not
        it exists: the allowed roots for every command, the deny list for those that return content."""
        if "path_b64" in req:
            raw = base64.b64decode(req["path_b64"])
            back = {v: k.encode() for k, v in self.served_as.items()}
            path = b"/".join(back.get(part, part) for part in raw.split(b"/")).decode("utf-8")
        else:
            path = req.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise _Fail("bad_request", "path must be absolute")
        real = self.root / path.lstrip("/")
        try:
            rel = real.resolve().relative_to(self.root.resolve()).as_posix()
            canon = "/" if rel == "." else "/" + rel
        except ValueError:
            canon = "/\0outside"        # a link out of the served tree
        if self.allow_roots is not None and not any(under(r, canon) for r in self.allow_roots):
            raise _Fail("refused", f"{path}: outside the agent's allowed roots (FILECAT_AGENT_ALLOW_ROOTS on the agent host)")
        if content and denied(canon):
            raise _Fail("refused", f"{path}: denied by agent policy")
        real.lstat()                    # FileNotFoundError -> not_found
        if content and content is True and self._attributes(canon) & NOT_LOCAL:
            raise _Fail("refused", f"{path}: not on this device (cloud placeholder), not read")
        return real

    def _attributes(self, posix: str, listing: bool = False) -> int:
        if self.windows_attributes is None:
            return 0
        if not listing and posix in self.attributes_after_list:
            return self.attributes_after_list[posix]
        return self.windows_attributes.get(posix, ARCHIVE)

    def _head_is_key(self, path: Path) -> bool:
        with open(path, "rb") as f:
            return private_key_head(f.read(SIGNATURE_WINDOW))

    def _posix(self, real: Path) -> str:
        rel = real.relative_to(self.root).as_posix()
        return "/" if rel == "." else "/" + rel

    def _command(self, cmd: Any, req: dict[str, Any], policy: _Policy, send: Any) -> dict[str, Any]:
        if cmd == "list_dir":
            return self._list_dir(req, policy, send)
        if cmd == "measure":
            return self._measure(req)
        if cmd == "read_range":
            return self._read_range(req)
        if cmd == "sum_subtree":
            return self._sum_subtree(req, policy, send)
        if cmd == "read_file":
            return self._read_file(req)
        if cmd == "statfs":
            return self._statfs(req)
        if cmd == "run":
            return self._run(req)
        if cmd == "capabilities":
            return self._capabilities()
        raise _Fail("bad_request", f"unknown cmd {cmd!r}")     # storage_topology and wmi included

    @staticmethod
    def _numbers(st: os.stat_result) -> dict[str, int]:
        return {"size": st.st_size, "allocated_size": -(-st.st_size // 4096) * 4096,
                "ino": st.st_ino, "dev": st.st_dev, "nlink": st.st_nlink,
                "mtime_ns": floor100(st.st_mtime_ns), "ctime_ns": floor100(st.st_ctime_ns)}

    def _child_rel(self, base: str, child_posix: str, name_of: dict[str, str]) -> str:
        """The child's path below `base` in the catalog's spelling of names."""
        rest = child_posix[len(base):].strip("/")
        return "/".join(name_of.get(c, c) for c in rest.split("/"))

    def _storage_names(self) -> dict[str, str]:
        return {k: storage_name(v) for k, v in self.served_as.items()}

    def _redacted(self, policy: _Policy, posix: str, st: os.stat_result, sticky_only: bool = True
                  ) -> tuple[str, int, int] | None:
        """(hash, dev, ino) of a child folder under a root with redaction sets:
        only when the sets hold it (`sticky_only`), or whatever it is."""
        if policy.key is None:
            return None
        names = self._storage_names()
        for entry in policy.redaction_roots:
            base = entry.get("base", "")
            if not (posix == base or posix.startswith(base.rstrip("/") + "/")):
                continue
            h = redaction_hash(policy.key, entry["root"], self._child_rel(base, posix, names))
            if (not sticky_only or h in entry.get("hashes", [])
                    or [st.st_dev, st.st_ino] in entry.get("inodes", [])):
                return h, st.st_dev, st.st_ino
        return None

    def _classify(self, policy: _Policy, child: os.DirEntry, posix: str, st: os.stat_result
                  ) -> tuple[str | None, bool, Any, dict[str, Any] | None]:
        """(tag to fold into | None, private, rule id | "marker" | "sticky", folded info)
        in the order of docs/rollups.md section 2; a suggestion rule answers
        (None, False, rule, None) so the caller counts it."""
        is_dir = child.is_dir(follow_symlinks=False)
        if is_dir and not child.is_symlink():
            if self._redacted(policy, posix, st) is not None:
                return "[REDACTED]", True, "sticky", None
        for rule in policy.rules:
            if rule.tag == "[REDACTED]" and rule.matches(child.name, posix, is_dir):
                return rule.tag, True, rule.id, None
        if is_dir and not child.is_symlink():
            for marker in policy.markers:
                if os.path.lexists(os.path.join(child.path, marker["name"])):
                    return marker["tag"], bool(marker.get("private")), "marker", None
        for rule in policy.rules:
            if rule.tag == "[REDACTED]":
                continue
            if rule.matches(child.name, posix, is_dir):
                if rule.keep:
                    return None, False, None, None
                if rule.suggest:
                    return None, False, rule, None
                return rule.tag, rule.private, rule.id, None
        return None, False, None, None

    def _list_dir(self, req: dict[str, Any], policy: _Policy, send: Any) -> dict[str, Any]:
        path = self.real(req)
        if not path.is_dir():
            raise _Fail("bad_request", "not a directory")
        self.log.append(f"list_dir {self._posix(path)}")
        dst = path.stat()
        base = self._posix(path).rstrip("/")
        errors: list[dict[str, Any]] = []
        kids: list[list[Any]] = []          # [child, lstat, tag, private, why, folded info]
        suggest: dict[str, int] = {}
        for child in sorted(os.scandir(path), key=lambda e: e.name):
            posix = f"{base}/{child.name}"
            if child.name in policy.exclude or posix in policy.exclude:
                continue
            if child.name in self.entry_errors:
                errors.append({"name": child.name, "kind": "file",
                               "error": {"code": "permission_denied", "message": "denied"}})
                continue
            st = os.lstat(child.path)
            tag, private, why, info = self._classify(policy, child, posix, st)
            if tag is None and isinstance(why, _Rule):
                suggest[why.tag] = suggest.get(why.tag, 0) + 1
            kids.append([child, st, tag, private, why, info])
        # a real child named like a tag produced here is folded in too
        wanted = {k[2].lower(): k[2] for k in kids if k[2]}
        for k in kids:
            if k[2] is None and k[0].name.lower() in wanted:
                k[2], k[3], k[4] = wanted[k[0].name.lower()], False, None
        entries = list(errors)
        for child, st, tag, _, _, _ in kids:
            if tag is not None:
                continue
            entry: dict[str, Any] = {"kind": "file", **self._numbers(st)}
            if child.is_symlink():
                entry.update(kind="link", link_target=os.readlink(child.path))
            elif child.is_dir(follow_symlinks=False):
                entry["kind"] = "dir"
            elif not child.is_file(follow_symlinks=False):
                entry["kind"] = "other"
            if self.windows_attributes is not None:
                entry["attributes"] = self._attributes(f"{base}/{child.name}", listing=True)
            if child.name in self.served_as:
                raw = self.served_as[child.name]
                entry.update(name=raw.decode("utf-8", "replace"), name_b64=base64.b64encode(raw).decode())
            else:
                entry["name"] = child.name
            entries.append(entry)
        produced = sorted({k[2] for k in kids if k[2]})
        if produced:
            cancel = self._begin(req)
            try:
                for tag in produced:
                    members = [k for k in kids if k[2] == tag]
                    acc = self._new_acc(dst.st_dev)
                    for k in members:
                        self._sum_into(acc, Path(k[0].path), cancel, req.get("deadline_ms"), send, req)
                    first = members[0][4]
                    roll = {"tag": tag, "matched": len(members), "total_files": acc["files"],
                            "total_dirs": acc["dirs"], "total_size": acc["size"],
                            "total_allocated_size": acc["alloc"], "newest_mtime_ns": acc["newest"],
                            "errors": acc["errors"], "error_codes": dict(acc["codes"]),
                            "vanished": acc["vanished"], "skipped_mounts": acc["mounts"],
                            "hardlink_names": acc["links"], "complete": not acc["late"]}
                    if isinstance(first, (int, str)):
                        roll["rule"] = first
                    if acc["files"]:
                        roll["oldest_mtime_ns"] = acc["oldest"]
                    if tag == "[REDACTED]":
                        found = [self._redacted(policy, f"{base}/{k[0].name}", k[1], sticky_only=False)
                                 for k in members if k[0].is_dir(follow_symlinks=False)]
                        roll["folded"] = [{"h": h, "dev": d, "ino": i} for h, d, i in filter(None, found)]
                    entries.append({"name": tag, "kind": "rollup", "size": acc["size"],
                                    "allocated_size": acc["alloc"], "ino": 0, "dev": dst.st_dev,
                                    "nlink": 1, "mtime_ns": acc["newest"], "ctime_ns": acc["newest"],
                                    "rollup": roll})
            finally:
                self._end(req)
        entries.sort(key=lambda e: e["name"])
        entries += self.extra_entries + self.extras.get(req.get("path"), [])
        resp = {"ok": True, "path": req.get("path"), "dev": dst.st_dev,
                "mtime_ns": floor100(dst.st_mtime_ns), "ctime_ns": floor100(dst.st_ctime_ns),
                "entries": entries}
        if policy.has_rules:
            resp["policy_id"] = policy.policy_id()
        if suggest:
            resp["suggest"] = [{"tag": t, "matched": n} for t, n in sorted(suggest.items())]
        return resp

    # --- sums ---
    def _begin(self, req: dict[str, Any]) -> threading.Event:
        ev = threading.Event()
        rid = req.get("id")
        with self._lock:
            if self._sums >= self.max_sums:
                raise _Fail("busy", "too many sums running")
            self._sums += 1
            if rid:
                self._running[str(rid)] = ev
        return ev

    def _end(self, req: dict[str, Any]) -> None:
        with self._lock:
            self._sums -= 1
            self._running.pop(str(req.get("id")), None)

    @staticmethod
    def _new_acc(dev: int) -> dict[str, Any]:
        return {"files": 0, "dirs": 0, "size": 0, "alloc": 0, "newest": 0, "oldest": None,
                "errors": 0, "codes": {}, "vanished": 0, "mounts": 0, "links": 0, "seen": set(),
                "dev": dev, "late": False, "matched": 0, "entries": 0}

    def _sum_into(self, acc: dict[str, Any], top: Path, cancel: threading.Event,
                  deadline_ms: int | None, send: Any, req: dict[str, Any],
                  exclude: tuple[re.Pattern[str], ...] = (), one_fs: bool = True,
                  exclude_names: frozenset[str] = frozenset()) -> None:
        """Add the tree at `top` (a file or a folder, itself counted) to `acc`.
        Counters only: no name ever goes into `acc`, a log line or an error."""
        started = time.monotonic()
        progress_ms = req.get("progress_ms")
        last = [started]
        sent = [False]

        def tick() -> None:
            acc["entries"] += 1
            if cancel.is_set():
                self.cancelled.append(str(req.get("id")))
                raise _Fail("cancelled", "cancelled")
            if deadline_ms is not None and (time.monotonic() - started) * 1000 > deadline_ms:
                acc["late"] = True
                raise _Stop()
            if progress_ms and (self.progress_always and not sent[0]
                                or (time.monotonic() - last[0]) * 1000 >= progress_ms):
                send({"progress": {"entries": acc["entries"], "bytes": acc["size"]}})
                last[0] = time.monotonic()
                sent[0] = True

        def error(exc: OSError) -> None:
            if isinstance(exc, FileNotFoundError):
                acc["vanished"] += 1
                return
            code = "permission_denied" if isinstance(exc, PermissionError) else "io"
            acc["errors"] += 1
            acc["codes"][code] = acc["codes"].get(code, 0) + 1

        def add_file(path: str, st: os.stat_result) -> None:
            acc["files"] += 1
            mtime = floor100(st.st_mtime_ns)
            acc["newest"] = max(acc["newest"], mtime)
            acc["oldest"] = mtime if acc["oldest"] is None else min(acc["oldest"], mtime)
            if st.st_nlink > 1:
                key = (st.st_dev, st.st_ino)
                if key in acc["seen"]:
                    acc["links"] += 1
                    return
                acc["seen"].add(key)
            acc["size"] += st.st_size
            acc["alloc"] += -(-st.st_size // 4096) * 4096

        try:
            try:
                st = os.lstat(top)
            except OSError as exc:
                error(exc)
                return
            if not os.path.isdir(top) or os.path.islink(top):
                add_file(str(top), st)
                return
            stack = [(str(top), True)]
            while stack:
                folder, counted = stack.pop()
                if counted:
                    acc["dirs"] += 1
                tick()
                if self.sum_delay:
                    time.sleep(self.sum_delay)
                if os.path.basename(folder) in self.unreadable:
                    error(PermissionError(13, "denied"))
                    continue
                try:
                    kids = list(os.scandir(folder))
                except OSError as exc:
                    error(exc)
                    continue
                for kid in kids:
                    tick()
                    if kid.name in self.unreadable:
                        error(PermissionError(13, "denied"))
                        continue
                    rel = os.path.relpath(kid.path, str(top)).replace(os.sep, "/")
                    if kid.name in exclude_names or any(
                            rx.fullmatch(rel) or rx.fullmatch(kid.name) for rx in exclude):
                        continue
                    try:
                        kst = os.lstat(kid.path)    # DirEntry.stat() has no dev, ino or nlink on Windows
                    except OSError as exc:
                        error(exc)
                        continue
                    if kid.is_dir(follow_symlinks=False) and not kid.is_symlink():
                        if one_fs and (kid.name in self.mounts or kst.st_dev != acc["dev"]):
                            acc["mounts"] += 1
                            continue
                        stack.append((kid.path, True))
                    else:
                        add_file(kid.path, kst)
        except _Stop:
            return

    def _sum_subtree(self, req: dict[str, Any], policy: _Policy, send: Any) -> dict[str, Any]:
        if req.get("path") in self.subtree_overrides:
            row = self.subtree_overrides[req["path"]]
            resp = {"ok": True, "total_files": 0, "total_dirs": 1, "newest_mtime_ns": 0, "errors": 0,
                    "error_codes": {}, "vanished": 0, "skipped_mounts": 0, "complete": True,
                    "path": req["path"], **row}
            return resp
        top = self.real(req)
        if not top.is_dir():
            raise _Fail("bad_request", "not a directory")
        private = bool(req.get("private"))
        if not private:
            self.log.append(f"sum_subtree {self._posix(top)}")
        exclude = tuple(re.compile(_path_glob(p)) for p in req.get("exclude", []))
        cancel = self._begin(req)
        try:
            acc = self._new_acc(top.stat().st_dev)
            self._sum_into(acc, top, cancel, req.get("deadline_ms"), send, req, exclude,
                           req.get("one_filesystem", True), frozenset(policy.exclude))
        finally:
            self._end(req)
        resp: dict[str, Any] = {
            "ok": True, "total_files": acc["files"], "total_dirs": acc["dirs"],
            "total_size": acc["size"], "total_allocated_size": acc["alloc"],
            "newest_mtime_ns": acc["newest"], "errors": acc["errors"], "error_codes": dict(acc["codes"]),
            "vanished": acc["vanished"], "skipped_mounts": acc["mounts"], "hardlink_names": acc["links"],
            "complete": not acc["late"]}
        if acc["files"]:
            resp["oldest_mtime_ns"] = acc["oldest"]
        if not private:
            resp["path"] = req.get("path")
        return resp

    def load_recording(self, rec: Path) -> None:
        """Serve a recorded host (tests/data/raw/<host>, see filecat.topology_collect.source):
        its files become the served tree, its run/ outputs the allowlist replies, statfs.json
        and subtree.json the recorded answers."""
        import shutil
        from urllib.parse import unquote
        shutil.copytree(rec / "files", self.root, dirs_exist_ok=True)
        for f in sorted((rec / "run").glob("*.stdout")):
            stem = f.name[:-len(".stdout")]
            entry, _, arg = stem.partition("@")
            key = entry if not arg else f"{entry}@{unquote(arg)}"
            code = f.with_suffix(".exit")
            self.run_outputs[key] = {"stdout": f.read_text(encoding="utf-8"),
                                     "exit_code": int(code.read_text()) if code.is_file() else 0}
        if (rec / "statfs.json").is_file():
            self.statfs_data.update(json.loads((rec / "statfs.json").read_text(encoding="utf-8")))
        if (rec / "subtree.json").is_file():
            self.subtree_overrides.update(json.loads((rec / "subtree.json").read_text(encoding="utf-8")))

    # --- read_file, statfs, run, capabilities ---
    def _read_file(self, req: dict[str, Any]) -> dict[str, Any]:
        maximum = req.get("max", READ_FILE_DEFAULT)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1 or maximum > MAX_READ:
            raise _Fail("bad_request", f"max must be 1 to {MAX_READ}")
        path = self.real(req, content=True)
        if path.is_symlink() or not path.is_file():
            raise _Fail("bad_request", "not a regular file")
        keys = REDACT_FILES.get(self._posix(path))
        if keys:                                    # served with its credentials blanked
            if path.stat().st_size > MAX_READ:
                raise _Fail("io", "file too large")
            data = redact_credentials(path.read_bytes(), keys)[:maximum + 1]
        else:
            if self._head_is_key(path):
                raise _Fail("refused", f"{req.get('path')}: denied by agent policy")
            with open(path, "rb") as f:
                data = f.read(maximum + 1)
        return {"ok": True, "data_b64": base64.b64encode(data[:maximum]).decode(), "truncated": len(data) > maximum}

    def _statfs(self, req: dict[str, Any]) -> dict[str, Any]:
        path = self.real(req)
        row = self.statfs_data.get(self._posix(path))
        if row is None:
            import shutil
            usage = shutil.disk_usage(path)
            row = {"total_bytes": usage.total, "free_bytes": usage.free, "avail_bytes": usage.free,
                   "block_size": 4096}
        return {"ok": True, "files": 0, "files_free": 0, "flags": 0, **row}

    def _mounts_text(self) -> str:
        out = ""
        for name in ("proc/self/mountinfo", "proc/mounts"):
            f = self.root / name
            if f.is_file():
                out += f.read_text(encoding="utf-8", errors="replace") + "\n"
        return out

    def _validate_arg(self, kind: str, arg: Any) -> None:
        """The agent's own check of an argument kind, against the host's live state."""
        if (not isinstance(arg, str) or not arg.startswith("/") or arg.startswith("-") or "\n" in arg
                or "\0" in arg or "//" in arg or "/./" in arg or "/../" in arg or arg.endswith("/") and arg != "/"):
            raise _Fail("refused", f"{kind}: {arg!r} is not an acceptable argument")
        if kind == "block_device":
            name = arg[len("/dev/"):] if arg.startswith("/dev/") else ""
            sysblock = self.root / "sys" / "block"
            if (not re.fullmatch(r"[A-Za-z0-9._-]+", name or "/") or re.match(r"(loop|ram)", name)
                    or not (sysblock / name).is_dir()):
                raise _Fail("refused", f"block_device: {arg} is not a whole disk of /sys/block")
        elif kind == "btrfs_mount":
            listed = {parts[1] for line in self._mounts_text().splitlines()
                      if len(parts := line.split()) >= 3 and parts[2] == "btrfs"}
            if arg not in listed:
                raise _Fail("refused", f"btrfs_mount: {arg} is not a btrfs mount point")
        elif kind == "md_device":
            mdstat = self.root / "proc" / "mdstat"
            text = mdstat.read_text(encoding="utf-8") if mdstat.is_file() else ""
            if not (arg.startswith("/dev/md") and re.search(rf"^{re.escape(arg[5:])} :", text, re.M)):
                raise _Fail("refused", f"md_device: {arg} is not an array of /proc/mdstat")
        else:
            raise _Fail("refused", f"unknown argument kind {kind!r}")

    def _run(self, req: dict[str, Any]) -> dict[str, Any]:
        entry = req.get("id")
        if not isinstance(entry, str) or entry not in ALLOWLIST:
            raise _Fail("bad_request", f"unknown allowlist id {entry!r}")
        kind = ALLOWLIST[entry]
        arg = req.get("arg")
        if kind is None and arg is not None:
            raise _Fail("bad_request", f"{entry} takes no argument")
        if kind is not None:
            if arg is None:
                raise _Fail("bad_request", f"{entry} needs an argument ({kind})")
            self._validate_arg(kind, arg)
        if entry in self.unavailable:
            raise _Fail("not_found", f"no binary for {entry}")
        out = self.run_outputs.get(entry if arg is None else f"{entry}@{arg}")
        if out is None:
            raise _Fail("not_found", f"no binary for {entry}")
        self.ran.append((entry, arg))
        stdout, stderr = out.get("stdout", ""), out.get("stderr", "")
        resp: dict[str, Any] = {
            "ok": True, "id": entry, "binary": f"/usr/bin/{entry.split('_')[0]}",
            "exit_code": out.get("exit_code", 0), "timed_out": bool(out.get("timed_out")),
            "stdout": stdout[:MAX_STDOUT], "stderr": stderr[:MAX_STDERR],
            "stdout_truncated": len(stdout) > MAX_STDOUT, "stderr_truncated": len(stderr) > MAX_STDERR,
            "duration_ms": 3}
        if resp["timed_out"]:
            resp["exit_code"] = None
        return resp

    def _capabilities(self) -> dict[str, Any]:
        entries = []
        for entry, kind in sorted(ALLOWLIST.items()):
            ok = entry not in self.unavailable and any(
                k == entry or k.startswith(entry + "@") for k in self.run_outputs)
            entries.append({"id": entry, "available": ok, "binary": f"/usr/bin/{entry.split('_')[0]}" if ok else None,
                            "version": None, "arg_kind": kind})
        digest = hashlib.sha256("\0".join(f"{e}={k}" for e, k in sorted(ALLOWLIST.items())).encode()).hexdigest()
        resp = {"ok": True, "allowlist_version": 1,
                "allowlist_sha256": self.allowlist_sha256 or digest,
                "deny_sha256": self.deny_sha256 or DENY_SHA256,
                "platform": "linux", "entries": entries}
        if self.product_type is not None:
            resp["product_type"] = self.product_type
        if self.allow_roots is not None:
            resp.update(allow_roots=list(self.allow_roots), allow_roots_source=self.allow_roots_source)
        return resp

    def _measure(self, req: dict[str, Any]) -> dict[str, Any]:
        policy = req.get("hash", "auto")
        head_bytes = req.get("head_bytes", 8192)
        if policy not in ("auto", "full", "none") or not 0 <= head_bytes <= 1024 * 1024:
            raise _Fail("bad_request", "bad hash or head_bytes")
        path = self.real(req, content="measure")
        if not path.is_file():
            raise _Fail("bad_request", "not a regular file")
        if self._posix(path) in REDACT_FILES:
            raise _Fail("refused", f"{req.get('path')}: denied by agent policy")    # read_file only
        if (attrs := self._attributes(self._posix(path))) & NOT_LOCAL:      # attributes first: no open
            st = path.lstat()
            return {"ok": True, "size": st.st_size, "mtime_ns": floor100(st.st_mtime_ns),
                    "unread": "cloud_placeholder", "attributes": attrs}
        with open(path, "rb") as f:
            st = os.fstat(f.fileno())
            size, mtime_ns = st.st_size, floor100(st.st_mtime_ns)
            head = f.read(min(size, max(head_bytes, SIGNATURE_WINDOW)))
        if private_key_head(head):                   # the head and the digest of a key never leave
            return {"ok": True, "size": size, "mtime_ns": mtime_ns, "unread": "private_key"}
        head = head[:head_bytes]
        resp: dict[str, Any] = {"ok": True, "size": size, "mtime_ns": mtime_ns,
                                "head_b64": base64.b64encode(head).decode()}
        resp.update(hash_file(str(path), size, mtime_ns, policy))
        return resp

    def _read_range(self, req: dict[str, Any]) -> dict[str, Any]:
        offset, length = req.get("offset"), req.get("len")
        if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length < 0:
            raise _Fail("bad_request", "bad offset or len")
        if length > MAX_READ:
            raise _Fail("bad_request", f"len {length} is over the maximum {MAX_READ}")
        path = self.real(req, content=True)
        if not path.is_file():
            raise _Fail("bad_request", "not a regular file")
        if self._posix(path) in REDACT_FILES or self._head_is_key(path):
            raise _Fail("refused", f"{req.get('path')}: denied by agent policy")
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
            eof = offset + len(data) >= os.fstat(f.fileno()).st_size
        return {"ok": True, "data_b64": base64.b64encode(data).decode(), "eof": eof}


class _Stop(Exception):
    """The deadline passed: the sum so far is the answer."""


def _path_glob(pattern: str) -> str:
    """A sum_subtree exclude pattern as a regex over the path below the summed folder."""
    comps = [c for c in pattern.split("/") if c]
    out = ""
    for i, c in enumerate(comps):
        if c == "**":
            out += "(?:[^/]+/)*" if i < len(comps) - 1 else "(?:[^/]+)(?:/[^/]+)*"
        else:
            out += _glob_re(c) + ("/" if i < len(comps) - 1 else "")
    return out


if os.environ.get("FILECAT_TEST_AGENT_BIN"):
    # Conformance run: every test that builds a FakeAgent gets the real Rust agent instead
    # (tests/_real_agent.py, agent/README.md). The helpers above stay the executable specification.
    from _real_agent import RealAgent as FakeAgent  # noqa: E402,F811
