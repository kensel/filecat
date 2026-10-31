"""Where a collector gets its raw sources: the "source fetcher" interface.

A collector never talks to the network or the disk itself. It asks a `Source` for files,
directory listings, file system totals, subtree sums and allowlisted command output, and builds
the topology from what comes back. Two sources exist:

* `AgentSource` wraps an `AgentClient`: read_file, list_dir, statfs, sum_subtree, run and
  capabilities of a filecat-agent (docs/agent-protocol.md).
* `RecordedSource` serves a directory of recorded raw outputs, so tests (and a bug report) feed
  a collector what a real host printed without an agent; `RecordingSource` wraps a live source
  and writes one (`filecat storage collect --record DIR`).

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
        self.hello = client.connect()
        self.hostname = self.hello.hostname
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


class RecordingSource:
    """Wraps a source and writes everything read through it as a recording (the layout above),
    so a host's raw outputs can be replayed with `RecordedSource` (a new collector's tests, a bug
    report). `record_runs()` also runs every argument-free allowlist entry the host has, so a
    platform the collector does not know yet (TrueNAS, Proxmox) is captured whole. `save()`
    writes the json files. A name the local file system cannot hold (`:` on Windows) is skipped
    and listed in meta.json's `skipped`. The recording holds whatever the host printed (serial
    numbers, share names, middleware query output): look at it before sharing it."""

    def __init__(self, inner: Any, root: str | Path) -> None:
        self.inner = inner
        self.root = Path(root)
        self.hostname = inner.hostname
        self._links: dict[str, str] = {}
        self._statfs: dict[str, dict[str, Any]] = {}
        self._subtree: dict[str, dict[str, Any]] = {}
        self._skipped: list[str] = []
        (self.root / "files").mkdir(parents=True, exist_ok=True)
        (self.root / "run").mkdir(exist_ok=True)

    def _path(self, path: str) -> Path | None:
        if not path.startswith("/") or ".." in path.split("/"):
            return None
        return self.root / "files" / path.lstrip("/")

    def _write(self, label: str, real: Path | None, data: bytes, *, keep: bool = False) -> None:
        if real is None:
            return
        try:
            real.parent.mkdir(parents=True, exist_ok=True)
            if keep and real.exists():
                return
            real.write_bytes(data)
        except OSError:
            self._skipped.append(label)

    def read_file(self, path: str, max: int = 1024 * 1024) -> FileData:
        data = self.inner.read_file(path, max)
        self._write(path, self._path(path), data.data)
        return data

    def list_dir(self, path: str) -> list[DirEntry]:
        entries = self.inner.list_dir(path)
        base = self._path(path)
        if base is not None:
            try:
                base.mkdir(parents=True, exist_ok=True)
            except OSError:
                self._skipped.append(path)
                return entries
            for e in entries:
                full = path.rstrip("/") + "/" + e.name
                if e.kind == "link" and e.link_target is not None:
                    self._links[full] = e.link_target
                elif e.kind == "dir":
                    try:
                        (base / e.name).mkdir(exist_ok=True)
                    except OSError:
                        self._skipped.append(full)
                else:                           # listed only: an empty file, unless it is read too
                    self._write(full, base / e.name, b"", keep=True)
        return entries

    def statfs(self, path: str) -> StatFs:
        st = self.inner.statfs(path)
        self._statfs[path] = {"total_bytes": st.total_bytes, "free_bytes": st.free_bytes,
                              "avail_bytes": st.avail_bytes, "block_size": st.block_size,
                              "fs_type_id": st.fs_type_id, "flags": st.flags, "files": st.files,
                              "files_free": st.files_free}
        return st

    def sum_subtree(self, path: str, deadline_ms: int | None = None) -> SubtreeSummary:
        s = self.inner.sum_subtree(path, deadline_ms)
        self._subtree[path] = {"total_files": s.total_files, "total_dirs": s.total_dirs,
                               "total_size": s.total_size, "total_allocated_size": s.total_allocated_size,
                               "newest_mtime_ns": s.newest_mtime_ns, "errors": s.errors}
        return s

    def run(self, entry_id: str, arg: str | None = None) -> RunResult:
        res = self.inner.run(entry_id, arg)
        stem = entry_id if arg is None else f"{entry_id}@{quote(arg, safe='')}"
        out = self.root / "run" / f"{stem}.stdout"
        self._write(f"run {stem}", out, res.stdout.encode("utf-8"))
        if res.stderr:
            self._write(f"run {stem}", out.with_suffix(".stderr"), res.stderr.encode("utf-8"))
        if res.exit_code not in (0, None):
            self._write(f"run {stem}", out.with_suffix(".exit"), f"{res.exit_code}\n".encode())
        return res

    def has(self, entry_id: str) -> bool:
        return self.inner.has(entry_id)

    def record_runs(self) -> list[str]:
        """Run every available allowlist entry that takes no argument; returns the ids run. One
        that fails is left out (its error is in the result list as `id: error`)."""
        caps = self.inner.capabilities() if hasattr(self.inner, "capabilities") else None
        done = []
        for cap in sorted((caps.entries.values() if caps else ()), key=lambda c: c.id):
            if not cap.available or cap.arg_kind:
                continue
            try:
                self.run(cap.id)
                done.append(cap.id)
            except AgentError as exc:
                done.append(f"{cap.id}: {exc.code}")
        return done

    def save(self) -> None:
        caps = self.inner.capabilities() if hasattr(self.inner, "capabilities") else None
        hello = getattr(self.inner, "hello", None)
        meta: dict[str, Any] = {"hostname": self.hostname, "os": getattr(hello, "os", "linux"),
                                "arch": getattr(hello, "arch", "")}
        if self._skipped:
            meta["skipped"] = sorted(set(self._skipped))
        for name, value in (("meta.json", meta), ("links.json", self._links),
                            ("statfs.json", self._statfs), ("subtree.json", self._subtree)):
            (self.root / name).write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        if caps is not None:
            available = sorted(c.id for c in caps.entries.values() if c.available)
            (self.root / "capabilities.json").write_text(json.dumps(available, indent=1) + "\n", encoding="utf-8")
