"""Client for filecat-agent, the Rust daemon that runs on a NAS.

The wire protocol is docs/agent-protocol.md (version 1): newline-delimited
JSON over TLS, one request then one response at a time. This module is the
Python end of it and nothing else; scans use it through fsource.py.

    with AgentClient("192.0.2.13", 9876, cert_sha256, token) as agent:
        listing = agent.list_dir("/volume1/Backup")
        m = agent.measure("/volume1/Backup/a.zip")       # head bytes + hashes
        with open_remote(agent, "/volume1/Backup/a.zip", m.size) as f:
            zipfile.ZipFile(f).namelist()

The agent's certificate is self-signed. The client skips chain and host
name validation and instead compares the SHA-256 of the DER certificate with
the fingerprint configured for that agent, before the token is sent.

`ShareMap` maps the agent's POSIX paths to the UNC paths an SMB scan of the
same share records, and back, so the two kinds of scan give the same roots
and rel_paths.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .options import HEAD_BYTES, MiB

if TYPE_CHECKING:
    from .config import AgentConfig

PROTOCOL = 1
DEFAULT_PORT = 9876
MAX_READ = 4 * MiB                  # largest `len` the agent accepts in one read_range
CONNECT_TIMEOUT = 30.0
IO_TIMEOUT = 120.0
SUBTREE_TIMEOUT = 3600.0            # sum_subtree walks a whole tree
HASH_POLICIES = ("auto", "full", "none")
REMOTE_BUFFER = 128 * 1024          # BufferedReader size of open_remote: one round trip per fill

_HEX64 = re.compile(r"[0-9a-f]{64}")


class AgentError(OSError):
    """The agent answered {"ok": false}, or the connection to it cannot be
    trusted. `code` is the protocol's error code (unauthorized, bad_request,
    not_found, permission_denied, io) or one the client adds (protocol,
    fingerprint)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class ProtocolError(AgentError):
    """The peer is not a protocol-1 filecat-agent: a line that is not a JSON
    object, or a `hello` naming another protocol version."""

    def __init__(self, message: str) -> None:
        super().__init__("protocol", message)


class FingerprintMismatch(AgentError):
    """The certificate the agent presented is not the one pinned in the config."""

    def __init__(self, message: str) -> None:
        super().__init__("fingerprint", message)


def normalize_fingerprint(text: str) -> str:
    """64 lowercase hex digits from `AA:BB:..` or plain hex, any case."""
    fp = re.sub(r"[:\s]", "", text or "").lower()
    if not _HEX64.fullmatch(fp):
        raise ValueError("a certificate fingerprint is 64 hex digits (SHA-256), "
                         "optionally separated by colons")
    return fp


# --- results ---------------------------------------------------------------
@dataclass(frozen=True)
class Hello:
    protocol: int
    agent_version: str
    hostname: str
    os: str
    arch: str


@dataclass(frozen=True)
class DirEntry:
    """One child from list_dir. `name` is round-trippable: bytes that are not
    UTF-8 come back as lone surrogates (os.fsdecode style), which
    AgentClient.child() turns back into the exact bytes. A failed lstat sets
    `error` ({code, message}) and leaves the numbers 0."""
    name: str
    kind: str                       # file | dir | link | rollup | other
    size: int = 0
    allocated_size: int = 0
    ino: int = 0
    dev: int = 0
    nlink: int = 1
    mtime_ns: int = 0
    ctime_ns: int = 0
    link_target: str | None = None
    rollup: dict[str, Any] | None = None
    error: dict[str, str] | None = None


@dataclass(frozen=True)
class DirListing:
    path: str
    dev: int
    mtime_ns: int
    ctime_ns: int
    entries: list[DirEntry]


@dataclass(frozen=True)
class Measurement:
    """What `measure` read. `hashes` has the shape hashing.hash_file returns:
    {}, {"sha256": hex} or {"sha256_partial": hex}. `size` and `mtime_ns`
    (floored to 100 ns) are what the digest was computed from."""
    size: int
    mtime_ns: int
    head: bytes
    hashes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SubtreeSummary:
    total_files: int
    total_dirs: int
    total_size: int
    total_allocated_size: int
    newest_mtime_ns: int
    errors: int


# --- wire helpers ----------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def path_fields(path: str | bytes) -> dict[str, str]:
    """`path`, or `path_b64` when the bytes are not valid UTF-8."""
    if isinstance(path, bytes):
        try:
            path = path.decode("utf-8")
        except UnicodeDecodeError:
            return {"path_b64": _b64(path)}
    if not path.startswith("/"):
        raise ValueError(f"an agent path is an absolute POSIX path, got {path!r}")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:      # lone surrogates: the bytes of a non-UTF-8 name
        return {"path_b64": _b64(path.encode("utf-8", "surrogateescape"))}
    return {"path": path}


def _text(obj: dict[str, Any], key: str) -> str | None:
    """A byte-string field: `key_b64` (exact bytes) wins over the lossy `key`."""
    if obj.get(key + "_b64") is not None:
        return base64.b64decode(obj[key + "_b64"]).decode("utf-8", "surrogateescape")
    return obj.get(key)


def _entry(obj: dict[str, Any]) -> DirEntry:
    return DirEntry(
        name=_text(obj, "name") or "", kind=obj.get("kind", "other"),
        size=obj.get("size", 0), allocated_size=obj.get("allocated_size", 0),
        ino=obj.get("ino", 0), dev=obj.get("dev", 0), nlink=obj.get("nlink", 1),
        mtime_ns=obj.get("mtime_ns", 0), ctime_ns=obj.get("ctime_ns", 0),
        link_target=_text(obj, "link_target"), rollup=obj.get("rollup"), error=obj.get("error"))


def _hello(resp: dict[str, Any]) -> Hello:
    try:
        info = Hello(int(resp["protocol"]), str(resp.get("agent_version", "?")),
                     str(resp.get("hostname", "?")), str(resp.get("os", "?")),
                     str(resp.get("arch", "?")))
    except (KeyError, TypeError, ValueError):
        raise ProtocolError("not a filecat-agent: hello has no protocol number") from None
    if info.protocol != PROTOCOL:
        raise ProtocolError(f"agent {info.agent_version} speaks protocol {info.protocol}; "
                            f"this filecat speaks protocol {PROTOCOL}")
    return info


# --- the client ------------------------------------------------------------
class AgentClient:
    """One connection to one agent. Safe to share between threads: a lock
    covers each request and its response. The connection is made on first use
    and, when a connection that had been working turns out to be closed,
    remade once and the request repeated (every command is idempotent; the
    policy is sent again).

    `timeout` bounds connecting, the TLS handshake, hello and auth;
    `io_timeout` bounds each later request unless a call passes its own."""

    def __init__(self, host: str, port: int, cert_sha256: str, token: str, *,
                 timeout: float = CONNECT_TIMEOUT, io_timeout: float = IO_TIMEOUT,
                 policy: dict[str, Any] | None = None, name: str | None = None) -> None:
        self.host = host
        self.port = port
        self.expected_fp = normalize_fingerprint(cert_sha256)
        self.token = token
        self.timeout = timeout
        self.io_timeout = io_timeout
        self.name = name or host
        self.info: Hello | None = None          # from the last connect
        self._policy = policy
        self._lock = threading.Lock()
        self._sock: ssl.SSLSocket | None = None
        self._rfile: Any = None

    @classmethod
    def from_config(cls, agent: "AgentConfig") -> "AgentClient":
        return cls(agent.host, agent.port, agent.cert_sha256, agent.resolved_token(),
                   timeout=agent.timeout, policy=agent.policy() or None, name=agent.name)

    def __enter__(self) -> "AgentClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"AgentClient({self.name!r}, {self.host}:{self.port})"

    # --- connection ---
    def connect(self) -> Hello:
        """Connect now (calls connect on first use anyway): TLS, pin the
        certificate, hello, auth, policy. Returns the agent's hello."""
        with self._lock:
            if self._sock is None:
                self._connect()
            assert self.info is not None
            return self.info

    def close(self) -> None:
        with self._lock:
            self._drop()

    def _drop(self) -> None:
        sock, self._sock, self._rfile = self._sock, None, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _connect(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            sock = ctx.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise
        try:
            der = sock.getpeercert(binary_form=True) or b""
            actual = hashlib.sha256(der).hexdigest()
            if not hmac.compare_digest(actual.encode(), self.expected_fp.encode()):
                raise FingerprintMismatch(
                    f"{self.name}: certificate fingerprint {actual} is not the pinned "
                    f"{self.expected_fp}; update cert_sha256 if the agent was reinstalled")
            self._sock, self._rfile = sock, sock.makefile("rb")
            self.info = _hello(self._exchange({"cmd": "hello"}))
            self._exchange({"cmd": "auth", "token": self.token})
            if self._policy:
                self._exchange({"cmd": "configure_policy", "policy": self._policy})
            sock.settimeout(self.io_timeout)
        except BaseException:
            self._drop()
            sock.close()
            raise

    def _exchange(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send one request on the open connection and read its response."""
        assert self._sock is not None and self._rfile is not None
        self._sock.sendall(json.dumps(payload, ensure_ascii=True).encode("ascii") + b"\n")
        line = self._rfile.readline()
        if not line:
            raise ConnectionError(f"{self.name}: the agent closed the connection")
        try:
            resp = json.loads(line)
        except ValueError:
            resp = None
        if not isinstance(resp, dict) or "ok" not in resp:
            self._drop()
            raise ProtocolError(f"{self.name}: a reply that is not a protocol-1 response")
        if not resp["ok"]:
            raise AgentError(str(resp.get("code") or "io"),
                             str(resp.get("error") or "the agent reported an error"))
        return resp

    def _call(self, payload: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        with self._lock:
            for attempt in (0, 1):
                reused = self._sock is not None
                try:
                    if self._sock is None:
                        self._connect()
                    if timeout is not None:
                        self._sock.settimeout(timeout)
                    try:
                        return self._exchange(payload)
                    finally:
                        if timeout is not None and self._sock is not None:
                            self._sock.settimeout(self.io_timeout)
                except AgentError:
                    raise
                except TimeoutError:
                    self._drop()        # the stream is out of step now
                    raise
                except OSError:         # reset, EOF, TLS closed under us
                    self._drop()
                    if not reused or attempt:
                        raise
            raise AssertionError("unreachable")

    # --- commands ---
    def hello(self) -> Hello:
        return _hello(self._call({"cmd": "hello"}))

    def configure_policy(self, exclude: list[str] | tuple[str, ...] = (),
                         rollup_groups: dict[str, list[str]] | None = None) -> None:
        """Set this connection's exclude list and rollup groups (replaces any
        earlier policy). Remembered and sent again after a reconnect."""
        policy = {"exclude": list(exclude), "rollup_groups": dict(rollup_groups or {})}
        self._call({"cmd": "configure_policy", "policy": policy})
        self._policy = policy

    def list_dir(self, path: str | bytes) -> DirListing:
        resp = self._call({"cmd": "list_dir", **path_fields(path)})
        return DirListing(path=_text(resp, "path") or "", dev=resp.get("dev", 0),
                          mtime_ns=resp.get("mtime_ns", 0), ctime_ns=resp.get("ctime_ns", 0),
                          entries=[_entry(e) for e in resp.get("entries", [])])

    def measure(self, path: str | bytes, hash: str = "auto", head_bytes: int = HEAD_BYTES,
                timeout: float | None = None) -> Measurement:
        """Hash a file as hashing.hash_file would and read its first
        `head_bytes`. Hashing a big file with hash="full" can outlast
        io_timeout; pass `timeout`."""
        if hash not in HASH_POLICIES:
            raise ValueError(f"unknown hash policy {hash!r}")
        resp = self._call({"cmd": "measure", **path_fields(path), "hash": hash,
                           "head_bytes": head_bytes}, timeout)
        hashes = {k: resp[k] for k in ("sha256", "sha256_partial") if resp.get(k)}
        return Measurement(size=resp["size"], mtime_ns=resp["mtime_ns"],
                           head=base64.b64decode(resp.get("head_b64") or ""), hashes=hashes)

    def read_range(self, path: str | bytes, offset: int, length: int) -> bytes:
        """`length` bytes from `offset`, fewer at the end of the file. Asks
        for no more than MAX_READ at a time."""
        if offset < 0 or length < 0:
            raise ValueError("offset and length must not be negative")
        fields = path_fields(path)
        parts: list[bytes] = []
        while length > 0:
            want = min(length, MAX_READ)
            resp = self._call({"cmd": "read_range", **fields, "offset": offset, "len": want})
            data = base64.b64decode(resp.get("data_b64") or "")
            parts.append(data)
            offset += len(data)
            length -= len(data)
            if resp.get("eof") or len(data) < want:
                break
        return b"".join(parts)

    def sum_subtree(self, path: str | bytes, timeout: float | None = SUBTREE_TIMEOUT) -> SubtreeSummary:
        resp = self._call({"cmd": "sum_subtree", **path_fields(path)}, timeout)
        return SubtreeSummary(resp["total_files"], resp["total_dirs"], resp["total_size"],
                              resp["total_allocated_size"], resp["newest_mtime_ns"],
                              resp.get("errors", 0))

    def storage_topology(self) -> list[dict[str, Any]]:
        return self._call({"cmd": "storage_topology"}).get("volumes", [])

    @staticmethod
    def child(parent: str | bytes, entry: DirEntry) -> str:
        """The agent path of a list_dir entry, with non-UTF-8 bytes kept as
        surrogates (path_fields turns them back into bytes)."""
        base = parent.decode("utf-8", "surrogateescape") if isinstance(parent, bytes) else parent
        return base.rstrip("/") + "/" + entry.name


# --- a remote file as a file object ---------------------------------------
class RemoteFileProxy(io.RawIOBase):
    """A read-only, seekable file object over read_range. Wrap it in
    io.BufferedReader (open_remote does) before handing it to zipfile, pefile
    or a probe, so small reads become one request per buffer. `size` is the
    file's size from the listing or from measure; the proxy never reads past
    it."""

    def __init__(self, client: AgentClient, path: str | bytes, size: int) -> None:
        super().__init__()
        self.client = client
        self.path = path
        self.size = size
        self.name = path if isinstance(path, str) else path.decode("utf-8", "replace")
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            pos = offset
        elif whence == io.SEEK_CUR:
            pos = self._pos + offset
        elif whence == io.SEEK_END:
            pos = self.size + offset
        else:
            raise ValueError(f"invalid whence ({whence})")
        if pos < 0:
            raise OSError(22, "negative seek position")
        self._pos = pos             # past the end is allowed; reads return b""
        return pos

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer).cast("B")
        want = min(len(view), self.size - self._pos)
        if want <= 0:
            return 0
        data = self.client.read_range(self.path, self._pos, want)
        view[:len(data)] = data
        self._pos += len(data)
        return len(data)

    def readall(self) -> bytes:
        want = self.size - self._pos
        if want <= 0:
            return b""
        data = self.client.read_range(self.path, self._pos, want)
        self._pos += len(data)
        return data


def open_remote(client: AgentClient, path: str | bytes, size: int,
                buffer_size: int = REMOTE_BUFFER) -> io.BufferedReader:
    """A buffered, seekable binary file for a file on the agent's host."""
    return io.BufferedReader(RemoteFileProxy(client, path, size), buffer_size)


# --- POSIX path on the NAS <-> UNC path in the catalog ----------------------
def _unc_parts(unc: str) -> list[str]:
    """['nas-main', 'Backup', 'x'] from '\\\\nas-main\\Backup\\x' (also '//')."""
    norm = unc.replace("/", "\\")
    if not norm.startswith("\\\\"):
        raise ValueError(f"not a UNC path: {unc!r}")
    parts = norm[2:].rstrip("\\").split("\\")
    if not parts[0] or "" in parts:
        raise ValueError(f"not a UNC path: {unc!r}")
    return parts


def _posix_parts(path: str) -> list[str]:
    if not path.startswith("/"):
        raise ValueError(f"not an absolute POSIX path: {path!r}")
    if path == "/":
        return []
    parts = path[1:].split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"not a canonical POSIX path: {path!r}")
    return parts


class ShareMap:
    """Maps an agent's POSIX paths to the catalog's UNC paths and back.

    The catalog names a file `\\\\nas-main\\Backup\\x\\y` (root
    `\\\\nas-main\\Backup`, rel_path `x/y`) whichever way it was scanned.
    The agent knows it as `/volume1/Backup/x/y`. Rules, in order:

    1. `shares`, an explicit table of POSIX prefix -> UNC root, longest
       prefix wins. These are matched on whole components.
    2. Synology's layout: `/volume<volume>/<share>/rest` is
       `<alias>\\<share>\\rest`. A top-level name starting with `@` or `#`
       (`@appstore`, `@eaDir`) is not a share and falls through.
    3. Anything else: `<alias>\\$root\\<path without the leading slash>`.

    Every POSIX path has exactly one UNC form and `to_posix_path` inverts it.
    Case: POSIX names are case-sensitive, UNC share names are not. Going to
    UNC the share keeps the spelling it has on the agent's host (what an SMB
    listing of that server shows). Going to POSIX the alias's server name and
    the explicit UNC roots match case-insensitively, as in aliases.py;
    everything after them is passed through unchanged, so a catalog path,
    which came from a listing, keeps the file system's own case. Fallback
    shares are not looked up: `\\\\nas-main\\backup` reads `/volume1/backup`.
    A POSIX name containing a backslash has no UNC form (ValueError).
    """

    ROOT = "$root"

    def __init__(self, alias: str, shares: dict[str, str] | None = None, volume: int = 1) -> None:
        parts = _unc_parts(alias)
        if len(parts) != 1:
            raise ValueError(f"alias must be a bare server, like \\\\nas-main, got {alias!r}")
        self.alias = "\\\\" + parts[0]
        self.volume = volume
        self._server = parts[0].lower()
        self._volume_dir = f"volume{volume}"
        # (posix parts, unc parts as given, unc parts lowercased), longest first
        self._explicit: list[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = []
        seen: set[tuple[str, ...]] = set()
        for prefix, unc in (shares or {}).items():
            pparts = tuple(_posix_parts(prefix))
            uparts = tuple(_unc_parts(unc))
            if not pparts or len(uparts) < 2:
                raise ValueError(f"share map {prefix!r} = {unc!r}: want a POSIX folder "
                                 "and a UNC share, like '/volume1/Backup' = '\\\\nas-main\\Backup'")
            low = tuple(p.lower() for p in uparts)
            if pparts in seen or low in {e[2] for e in self._explicit}:
                raise ValueError(f"share map lists {prefix!r} or {unc!r} twice")
            seen.add(pparts)
            self._explicit.append((pparts, uparts, low))
        self._explicit.sort(key=lambda e: -len(e[0]))

    def to_catalog_path(self, posix_path: str) -> str:
        parts = _posix_parts(posix_path)
        if any("\\" in p for p in parts):
            raise ValueError(f"{posix_path!r} has a backslash in a name; it has no UNC form")
        for pparts, uparts, _ in self._explicit:
            if tuple(parts[:len(pparts)]) == pparts:
                return "\\".join(("\\\\" + uparts[0],) + uparts[1:] + tuple(parts[len(pparts):]))
        if (len(parts) >= 2 and parts[0] == self._volume_dir and parts[1][:1] not in ("@", "#")
                and parts[1].lower() != self.ROOT):
            return "\\".join([self.alias] + parts[1:])
        return "\\".join([self.alias, self.ROOT] + parts)

    def to_posix_path(self, unc_path: str) -> str:
        parts = _unc_parts(unc_path)
        low = [p.lower() for p in parts]
        for pparts, uparts, ulow in sorted(self._explicit, key=lambda e: -len(e[2])):
            if low[:len(ulow)] == list(ulow):
                return "/" + "/".join(pparts + tuple(parts[len(uparts):]))
        if low[0] == self._server:
            rest = parts[1:]
            if rest and low[1] == self.ROOT:
                return "/" + "/".join(rest[1:])
            if rest:
                return "/" + "/".join([self._volume_dir] + rest)
        raise ValueError(f"{unc_path!r} is not under a share of {self.alias}")

    def explicit_spelling(self, unc_path: str) -> str | None:
        """`unc_path` with the share spelled as `shares` spells it, when an
        explicit share root covers it; None when none does. The config is
        the NAS's own spelling of that share."""
        try:
            parts = _unc_parts(unc_path)
        except ValueError:
            return None
        low = [p.lower() for p in parts]
        for _, uparts, ulow in self._explicit:
            if low[:len(ulow)] == list(ulow):
                return "\\".join(("\\\\" + uparts[0],) + uparts[1:] + tuple(parts[len(uparts):]))
        return None

    def canonical(self, unc_path: str, list_names: Any = None) -> str:
        """`unc_path` with its server and share spelled as the agent's host
        spells them, so a scan records the NAS's name for the share whatever
        case it was typed in (Windows and SMB do not care, Linux does).
        An explicit share root gives its configured spelling. Under the
        Synology layout `list_names(posix_folder)`, when given, lists the
        entries of the volume folder and the one that equals the typed share
        ignoring case is used (the typed one when it is exact or the match is
        ambiguous). The server is spelled as `alias` has it. Everything below
        the share is left as given: names there are case-sensitive on both
        sides. A path this map does not cover comes back unchanged."""
        spelled = self.explicit_spelling(unc_path)
        if spelled is not None:
            return spelled
        try:
            parts = _unc_parts(unc_path)
        except ValueError:
            return unc_path
        if parts[0].lower() != self._server or len(parts) < 2 or parts[1].lower() == self.ROOT:
            return unc_path
        share = parts[1]
        if list_names is not None:
            names = list(list_names("/" + self._volume_dir))
            if share not in names:
                same = [n for n in names if n.lower() == share.lower()]
                if len(same) == 1:
                    share = same[0]
        return "\\".join([self.alias, share] + parts[2:])

    def covers(self, unc_path: str) -> int:
        """How many leading UNC components of `unc_path` this map owns: the
        server for the alias, more for an explicit root. 0 when none."""
        try:
            low = [p.lower() for p in _unc_parts(unc_path)]
        except ValueError:
            return 0
        best = 1 if low[0] == self._server and len(low) > 1 else 0
        for _, _, ulow in self._explicit:
            if low[:len(ulow)] == list(ulow):
                best = max(best, len(ulow))
        return best


def time_call(fn: Any, *args: Any, **kwargs: Any) -> tuple[Any, float]:
    """(result, seconds) of one call, for latency reports."""
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, time.perf_counter() - start
