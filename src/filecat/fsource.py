"""Where a scan reads a tree from: the local file system (the default; the
walker uses os.scandir directly), or a filecat-agent on the NAS.

An agent scan hands the walker objects that answer what it asks of
os.DirEntry and os.stat_result, so the walk itself is shared:

    AgentEntry   .name, .stat(), .is_symlink(), .is_dir(), .is_file(),
                 plus .link_target and .special (a FIFO, socket or device,
                 recorded and never opened)
    AgentStat    st_size, st_mtime_ns, st_ctime_ns, and the extras the agent
                 knows: allocated_size, st_ino, st_dev, st_nlink

and the file measure_file and the probes open is a RemotePath: a str (the
UNC path, so name and suffix logic is unchanged) that remembers its agent.
The probes open files through fopen() and size them with fsize(), which are
plain open() and os.path.getsize() for any other path; for a RemotePath
they read through the agent's read_range (agent_client.open_remote).

Paths. The walker works in the catalog's terms (UNC root, '/'-separated
rel_path); AgentSource turns a UNC path into the agent's POSIX path with the
agent's ShareMap on every call.

Names that are not UTF-8. The agent sends such a name as lossy text plus its
exact bytes, which agent_client decodes to lone surrogates (U+DC80..U+DCFF).
Those cannot go to JSON, MongoDB or most SQL drivers, so every name and link
target is stored with each such byte b as the private-use character
U+F700 + b (U+F780..U+F7FF): same length, valid Unicode, one character per
byte, and from_storage() reverses it exactly when a path goes back to the
agent. A name that really contains a character in U+F780..U+F7FF is
ambiguous (it would be sent as raw bytes); no file system has such names in
practice. A name containing a backslash has no UNC form and is recorded
with a stat error.

Connections. An AgentClient serialises its calls, so each thread that reads
(the walker, the LIST_THREADS listing threads, the measuring workers) gets
a client of its own, made on first use: about LIST_THREADS + workers + 1
connections to the agent, each authenticated and given the exclude policy.
"""
from __future__ import annotations

import errno
import io
import logging
import os
import re
import threading
from typing import TYPE_CHECKING, Any

from . import record
from .agent_client import AgentClient, AgentError, DirEntry, Measurement, open_remote
from .options import HEAD_BYTES

if TYPE_CHECKING:
    from .config import AgentConfig
    from .options import ScanOptions

log = logging.getLogger(__name__)

_LOW, _HIGH = 0xDC80, 0xDCFF            # surrogateescape of bytes 0x80..0xFF
_PUA = 0xF780                           # where they are stored
_TO_STORAGE = {c: c - _LOW + _PUA for c in range(_LOW, _HIGH + 1)}
_FROM_STORAGE = {v: k for k, v in _TO_STORAGE.items()}
_PUA_RE = re.compile("[-]")


def to_storage(text: str) -> str:
    """`text` as it is stored: lone surrogates from non-UTF-8 bytes become
    private-use characters (see the module docstring)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.translate(_TO_STORAGE)
    return text


def from_storage(text: str) -> str:
    """The inverse of to_storage: the form agent_client turns back into bytes."""
    if text.isascii() or not _PUA_RE.search(text):
        return text
    return text.translate(_FROM_STORAGE)


# --- what the walker sees ---------------------------------------------------
class AgentStat:
    """The os.stat_result fields the scan uses, from a list_dir entry."""
    __slots__ = ("st_size", "st_mtime_ns", "st_ctime_ns", "st_ino", "st_dev", "st_nlink",
                 "allocated_size")

    def __init__(self, size: int, mtime_ns: int, ctime_ns: int, ino: int = 0, dev: int = 0,
                 nlink: int = 1, allocated_size: int = 0) -> None:
        self.st_size = size
        self.st_mtime_ns = mtime_ns
        self.st_ctime_ns = ctime_ns
        self.st_ino = ino
        self.st_dev = dev
        self.st_nlink = nlink
        self.allocated_size = allocated_size


def apply_stat_extras(doc: dict[str, Any], st: Any) -> None:
    """allocated_size, ino, dev and nlink on a record, when `st` came from an
    agent; an os.stat_result (an SMB or local scan) adds nothing."""
    if isinstance(st, AgentStat):
        record.add_fs_info(doc, allocated_size=st.allocated_size, ino=st.st_ino,
                           dev=st.st_dev, nlink=st.st_nlink)


class AgentEntry:
    """A list_dir entry that quacks like os.DirEntry for the walker."""
    __slots__ = ("name", "kind", "link_target", "_stat", "_error")

    def __init__(self, name: str, kind: str, stat: AgentStat | None, error: OSError | None,
                 link_target: str | None = None) -> None:
        self.name = name
        self.kind = kind
        self.link_target = link_target
        self._stat = stat
        self._error = error

    def stat(self, follow_symlinks: bool = True) -> AgentStat:
        if self._error is not None:
            raise self._error
        assert self._stat is not None
        return self._stat

    def is_symlink(self) -> bool:
        return self.kind == "link"

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return self.kind == "dir"

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return self.kind == "file"

    @property
    def special(self) -> bool:
        """A FIFO, socket or device: recorded, never opened."""
        return self.kind == "other"


_ERRORS = {"not_found": (FileNotFoundError, errno.ENOENT),
           "permission_denied": (PermissionError, errno.EACCES)}


def _entry_error(code: str, message: str) -> OSError:
    cls, number = _ERRORS.get(code, (OSError, errno.EIO))
    return cls(number, f"{message} ({code})")


class RemotePath(str):
    """The catalog path of a file on an agent. As a str it is the UNC path;
    open() reads it through the agent."""
    source: "AgentSource"
    posix: str
    size: int

    def __new__(cls, unc: str, source: "AgentSource", posix: str, size: int) -> "RemotePath":
        obj = super().__new__(cls, unc)
        obj.source, obj.posix, obj.size = source, posix, size
        return obj

    def open(self, mode: str = "rb", **kwargs: Any) -> Any:
        raw = open_remote(self.source.client(), self.posix, self.size)
        if "b" in mode:
            return raw
        return io.TextIOWrapper(raw, encoding=kwargs.get("encoding"), errors=kwargs.get("errors"),
                                newline=kwargs.get("newline"))

    def measure(self, hash: str, timeout: float, head_bytes: int = HEAD_BYTES) -> Measurement:
        return self.source.client().measure(self.posix, hash, head_bytes, timeout)


def fopen(path: str, mode: str = "rb", **kwargs: Any) -> Any:
    """open(), for a path that may be a file on an agent."""
    if isinstance(path, RemotePath):
        return path.open(mode, **kwargs)
    return open(path, mode, **kwargs)


def fsize(path: str) -> int:
    """os.path.getsize(), for a path that may be a file on an agent."""
    return path.size if isinstance(path, RemotePath) else os.path.getsize(path)


def sibling(path: str, other: str) -> str | None:
    """`other`, a path beside `path`, as something fopen() opens; None when
    `path` is on an agent and `other` is not there. For any other path it is
    `other` as given."""
    if not isinstance(path, RemotePath):
        return other
    try:
        posix = path.source.posix(other)
        m = path.source.client().measure(posix, "none", 0)
    except (OSError, ValueError):
        return None
    return RemotePath(other, path.source, posix, m.size)


def isfile(path: str) -> bool:
    """os.path.isfile(); a sibling() result is a file."""
    return True if isinstance(path, RemotePath) else os.path.isfile(path)


# --- the source -----------------------------------------------------------
class AgentSource:
    """A tree read through one filecat-agent. Shared by all roots of that
    agent and by every thread; see the module docstring."""
    remote = True

    def __init__(self, config: "AgentConfig", client_factory: Any = None) -> None:
        self.config = config
        self.name = config.name
        self.map = config.share_map()
        self._factory = client_factory or (lambda: AgentClient.from_config(config))
        self._local = threading.local()
        self._clients: list[AgentClient] = []
        self._lock = threading.Lock()
        self._root_listings: dict[str, tuple[AgentStat, list[AgentEntry]]] = {}

    # --- connections ---
    def client(self) -> AgentClient:
        client = getattr(self._local, "client", None)
        if client is None:
            client = self._factory()
            self._local.client = client
            with self._lock:
                self._clients.append(client)
        return client

    def close(self) -> None:
        with self._lock:
            clients, self._clients = self._clients, []
        for c in clients:
            c.close()
        self._local = threading.local()

    @property
    def description(self) -> str:
        return f"filecat-agent {self.name} ({self.config.endpoint})"

    def _wrap(self, exc: BaseException) -> OSError:
        if isinstance(exc, AgentError):
            return AgentError(exc.code, f"{self.description}: {exc.message}")
        return OSError(f"{self.description}: {type(exc).__name__}: {exc}")

    # --- paths ---
    def posix(self, unc: str) -> str:
        """The agent's path for a catalog path (UNC, '\\' separators)."""
        return from_storage(self.map.to_posix_path(unc))

    @staticmethod
    def join(root: str, rel_path: str) -> str:
        if not rel_path:
            return root
        return root.rstrip("\\/") + "\\" + rel_path.replace("/", "\\")

    def file_path(self, unc: str, size: int) -> RemotePath:
        return RemotePath(unc, self, self.posix(unc), size)

    # --- what the walker asks ---
    def _list(self, unc: str) -> tuple[AgentStat, list[AgentEntry]]:
        try:
            listing = self.client().list_dir(self.posix(unc))
        except ValueError as e:         # the path has no POSIX form on this agent
            raise OSError(f"{self.description}: {e}") from None
        except OSError as e:
            raise self._wrap(e) from None
        entries = [x for x in map(self._entry, listing.entries) if x is not None]
        entries.sort(key=lambda e: e.name)
        return AgentStat(0, listing.mtime_ns, listing.ctime_ns, dev=listing.dev), entries

    def _entry(self, e: DirEntry) -> AgentEntry | None:
        if e.kind == "rollup":
            # rollup groups are not used by scans yet; the folded children
            # are not in the catalog
            log.debug("%s: skipping rollup entry %r", self.description, e.name)
            return None
        name = to_storage(e.name)
        error = None
        stat = None
        if e.error:
            error = _entry_error(e.error.get("code", "io"), e.error.get("message", "cannot stat"))
        elif "\\" in name:
            error = OSError(errno.EINVAL, f"{name!r}: a name with a backslash has no UNC form")
        else:
            stat = AgentStat(e.size, e.mtime_ns, e.ctime_ns, e.ino, e.dev, e.nlink, e.allocated_size)
        target = to_storage(e.link_target) if e.link_target is not None else None
        return AgentEntry(name, e.kind, stat, error, target)

    def stat_root(self, unc: str) -> AgentStat:
        """The root folder's own times; raises OSError, with the agent named,
        when it cannot be reached or read. Its listing is kept for list_dir."""
        st, entries = self._list(unc)
        self._root_listings[unc] = (st, entries)
        return st

    def list_dir(self, unc: str) -> list[AgentEntry]:
        """A folder's entries in name order. The root's listing is the one
        stat_root just read."""
        kept = self._root_listings.pop(unc, None)
        return kept[1] if kept is not None else self._list(unc)[1]

    def canonical_unc(self, unc: str) -> str:
        """`unc` with the server and share as the NAS spells them (see
        ShareMap.canonical); `unc` itself when the agent cannot be asked."""
        def names(folder: str) -> list[str]:
            return [to_storage(e.name) for e in self.client().list_dir(folder).entries]
        try:
            return self.map.canonical(unc, names)
        except (OSError, ValueError):
            return unc

    def check(self, unc: str) -> None:
        """Can the root be listed through the agent (preflight)?"""
        self._list(unc)

    def link_target(self, entry: AgentEntry) -> str | None:
        return entry.link_target


def pick(options: "ScanOptions", root: str, path: str) -> tuple["AgentConfig", str] | None:
    """(agent, the UNC form of the root the agent knows it by) when a
    configured agent reads this root, else None. `root` is what is recorded
    and `path` what is read (they differ under an alias); the agent may match
    either. --no-agent turns agents off; --agent NAME picks that agent for
    any root it covers."""
    from .config import agent_for
    if options.no_agent or not options.agents:
        return None
    agents = options.agents
    if options.agent:
        agents = [a for a in agents if a.name == options.agent]
    for candidate in (root, path):
        found = agent_for(agents, candidate)
        if found is not None:
            return found, candidate
    return None
