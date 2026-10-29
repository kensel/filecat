"""Where a collector gets its raw sources: the "source fetcher" interface.

A collector never talks to the network or the disk itself. It asks a `Source` for files,
directory listings, file system totals, subtree sums and allowlisted command output, and builds
the topology from what comes back. Two sources exist:

* `AgentSource` wraps an `AgentClient`: read_file, list_dir, statfs, sum_subtree, run and
  capabilities of a filecat-agent (docs/agent-protocol.md).
* `RecordedSource` serves a directory of recorded raw outputs, so tests (and a bug report) feed
  a collector what a real host printed without an agent.

Both raise `AgentError` with the protocol's codes (`not_found`, `permission_denied`, `refused`,
`bad_request`, ...), which is what collectors catch: a source that cannot be read leaves its
nodes out and adds a note to the snapshot, never fails the collection.

A recording is a directory:

    meta.json                 {"hostname": "nas3", "os": "linux", "arch": "x86_64"}
    files/<absolute path>     the contents of a file, as read_file would return them; a
                              directory of files is list_dir-able; an empty file stands for a
                              name that is only listed (a sysfs link)
    links.json                {"/dev/disk/by-uuid/<uuid>": "../../dm-1"}: entries that list_dir
                              reports as links, with their target
    statfs.json               {"/volume1": {"total_bytes": ..., "free_bytes": ..., ...}}
    subtree.json              {"/volume1/@iSCSI/LUN/BLUN/<uuid>": {"total_size": ..., "total_allocated_size": ...}}
    run/<id>.stdout           output of an allowlist entry; with an argument the file is
                              <id>@<argument, percent-encoded>.stdout (/dev/sata1 is
                              %2Fdev%2Fsata1); optional .stderr and .exit (the exit status,
                              default 0)
    capabilities.json         ["mdadm_detail_scan", ...]: the entries available (default: every
                              entry that has a run/ file)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

from ..agent_client import (AgentClient, AgentError, Capabilities, DirEntry, FileData, RunResult,
                            StatFs, SubtreeSummary)


class Source(Protocol):
    """What a collector reads. `hostname` is the host's own name (the agent's hello)."""
    hostname: str

    def read_file(self, path: str, max: int = ...) -> FileData: ...
    def list_dir(self, path: str) -> list[DirEntry]: ...
    def statfs(self, path: str) -> StatFs: ...
    def sum_subtree(self, path: str, deadline_ms: int | None = ...) -> SubtreeSummary: ...
    def run(self, entry_id: str, arg: str | None = ...) -> RunResult: ...
    def has(self, entry_id: str) -> bool: ...


class AgentSource:
    """A live filecat-agent. `capabilities` is asked once, on first use; an agent that answers
    `bad_request` (an older one) is treated as having no allowlist entries."""

    def __init__(self, client: AgentClient) -> None:
        self.client = client
        self.hostname = client.connect().hostname
        self._caps: Capabilities | None = None

    def read_file(self, path: str, max: int = 1024 * 1024) -> FileData:
        return self.client.read_file(path, max)

    def list_dir(self, path: str) -> list[DirEntry]:
        return self.client.list_dir(path).entries

    def statfs(self, path: str) -> StatFs:
        return self.client.statfs(path)

    def sum_subtree(self, path: str, deadline_ms: int | None = None) -> SubtreeSummary:
        return self.client.sum_subtree(path, deadline_ms=deadline_ms, progress_ms=5000)

    def run(self, entry_id: str, arg: str | None = None) -> RunResult:
        return self.client.run(entry_id, arg)

    def capabilities(self) -> Capabilities:
        if self._caps is None:
            try:
                self._caps = self.client.capabilities()
            except AgentError as exc:
                if exc.code != "bad_request":
                    raise
                self._caps = Capabilities(0, None, "", {})
        return self._caps

    def has(self, entry_id: str) -> bool:
        return self.capabilities().has(entry_id)


@dataclass
class _Rec:
    root: Path
    files: Path
    links: dict[str, str]
    statfs: dict[str, dict[str, Any]]
    subtree: dict[str, dict[str, Any]]


def _json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


class RecordedSource:
    """Raw outputs recorded from a host, served as an agent would. See the module docstring."""

    def __init__(self, root: str | Path) -> None:
        root = Path(root)
        self._rec = _Rec(root, root / "files", _json(root / "links.json", {}),
                         _json(root / "statfs.json", {}), _json(root / "subtree.json", {}))
        meta = _json(root / "meta.json", {})
        self.hostname = meta.get("hostname", root.name)
        self.os = meta.get("os", "linux")
        self.reads: list[str] = []          # every path asked for, in order (tests look at it)
        self.runs: list[tuple[str, str | None]] = []
        run_dir = root / "run"
        recorded = sorted({p.name.split("@", 1)[0].rsplit(".", 1)[0] for p in run_dir.glob("*.stdout")}
                          ) if run_dir.is_dir() else []
        self._available = set(_json(root / "capabilities.json", recorded))

    def _real(self, path: str) -> Path:
        if not path.startswith("/") or ".." in path.split("/"):
            raise AgentError("bad_request", f"not an absolute canonical path: {path!r}")
        return self._rec.files / path.lstrip("/")

    def read_file(self, path: str, max: int = 1024 * 1024) -> FileData:
        self.reads.append(path)
        real = self._real(path)
        if not real.exists():
            raise AgentError("not_found", f"{path}: no such file in the recording")
        if not real.is_file():
            raise AgentError("bad_request", f"{path}: not a regular file")
        data = real.read_bytes()
        return FileData(data[:max], len(data) > max)

    def list_dir(self, path: str) -> list[DirEntry]:
        self.reads.append(path)
        real = self._real(path)
        names: dict[str, DirEntry] = {}
        if real.is_dir():
            for child in sorted(real.iterdir()):
                full = path.rstrip("/") + "/" + child.name
                kind = "link" if full in self._rec.links else "dir" if child.is_dir() else "file"
                names[child.name] = DirEntry(child.name, kind, size=0 if kind == "dir" else child.stat().st_size,
                                             link_target=self._rec.links.get(full))
        prefix = path.rstrip("/") + "/"
        for full, target in self._rec.links.items():       # links that are only recorded, with no file
            if full.startswith(prefix) and "/" not in full[len(prefix):]:
                names.setdefault(full[len(prefix):], DirEntry(full[len(prefix):], "link", link_target=target))
        if not real.is_dir() and not names:
            raise AgentError("not_found", f"{path}: no such directory in the recording")
        return [names[k] for k in sorted(names)]

    def statfs(self, path: str) -> StatFs:
        row = self._rec.statfs.get(path)
        if row is None:
            raise AgentError("not_found", f"{path}: no statfs recorded")
        return StatFs(row["total_bytes"], row["free_bytes"], row.get("avail_bytes", row["free_bytes"]),
                      row.get("block_size", 4096), row.get("fs_type_id"), row.get("flags", 0),
                      row.get("files", 0), row.get("files_free", 0))

    def sum_subtree(self, path: str, deadline_ms: int | None = None) -> SubtreeSummary:
        row = self._rec.subtree.get(path)
        if row is None:
            raise AgentError("not_found", f"{path}: no subtree sum recorded")
        return SubtreeSummary(row.get("total_files", 0), row.get("total_dirs", 1), row["total_size"],
                              row["total_allocated_size"], row.get("newest_mtime_ns", 0), row.get("errors", 0))

    def run(self, entry_id: str, arg: str | None = None) -> RunResult:
        self.runs.append((entry_id, arg))
        if entry_id not in self._available:
            raise AgentError("not_found", f"{entry_id}: not available on the recorded host")
        stem = entry_id if arg is None else f"{entry_id}@{quote(arg, safe='')}"
        out = self._rec.root / "run" / f"{stem}.stdout"
        if not out.is_file():
            raise AgentError("not_found", f"{stem}: no output recorded")
        err = out.with_suffix(".stderr")
        code = out.with_suffix(".exit")
        return RunResult(entry_id, f"/recorded/{entry_id}",
                         int(code.read_text().strip()) if code.is_file() else 0,
                         out.read_text(encoding="utf-8"), err.read_text(encoding="utf-8") if err.is_file() else "")

    def has(self, entry_id: str) -> bool:
        return entry_id in self._available
