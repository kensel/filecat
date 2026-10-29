"""What every collector needs: a tolerant reader over a Source, and the snapshot envelope."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .. import topology
from ..agent_client import AgentError
from .source import Source

COLLECTOR_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Reader:
    """A Source that does not raise for what is missing. A file that is not there is simply
    None; any other failure (permission, a refused command) is also None, and is written
    down in `notes`, which end up in the snapshot's `collector.notes`, so a partial
    collection says what it could not read."""

    def __init__(self, source: Source) -> None:
        self.source = source
        self.notes: list[str] = []

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def _failed(self, what: str, exc: AgentError, quiet_missing: bool) -> None:
        if exc.code == "not_found" and quiet_missing:
            return
        self.note(f"{what}: {exc.code}: {exc.message}")

    def text(self, path: str, *, max: int = 1024 * 1024, quiet: bool = True,
             silent: bool = False) -> str | None:
        """The file's text; None when it cannot be read. `silent` leaves no note whatever the
        failure (a path that was only guessed, possibly outside the allowed roots)."""
        try:
            data = self.source.read_file(path, max)
        except AgentError as exc:
            if not silent:
                self._failed(path, exc, quiet)
            return None
        if data.truncated:
            self.note(f"{path}: longer than {max} bytes, read the first part")
        return data.text()

    def json(self, path: str) -> Any | None:
        text = self.text(path)
        if text is None:
            return None
        try:
            return json.loads(text)
        except ValueError as exc:
            self.note(f"{path}: not JSON: {exc}")
            return None

    def names(self, path: str) -> list[str] | None:
        """Entry names of a directory, sorted; None when it cannot be listed."""
        try:
            return sorted(e.name for e in self.source.list_dir(path))
        except AgentError as exc:
            self._failed(path, exc, True)
            return None

    def entries(self, path: str) -> list[Any]:
        try:
            return list(self.source.list_dir(path))
        except AgentError as exc:
            self._failed(path, exc, True)
            return []

    def run(self, entry_id: str, arg: str | None = None) -> str | None:
        """stdout of an allowlist entry, or None when this host does not have it. A non-zero exit
        status is kept (smartctl's is a bit mask); a timeout is a note."""
        if not self.source.has(entry_id):
            return None
        try:
            res = self.source.run(entry_id, arg)
        except AgentError as exc:
            self._failed(f"{entry_id}{' ' + arg if arg else ''}", exc, False)
            return None
        if res.timed_out:
            self.note(f"{entry_id}: timed out")
            return None
        return res.stdout


def finish(platform: str, host: dict[str, Any], nodes: list[dict[str, Any]], reader: Reader, *,
           name: str, collected_at: str | None = None, extra: dict[str, Any] | None = None
           ) -> topology.Topology:
    """The validated snapshot. `collector` is added only when something could not be read."""
    doc: dict[str, Any] = {"version": topology.VERSION, "platform": platform, "host": host,
                           "collected_at": collected_at or now_iso(), "nodes": nodes}
    if reader.notes:
        doc["collector"] = {"name": name, "version": COLLECTOR_VERSION, "notes": reader.notes}
    doc.update(extra or {})
    return topology.parse(doc)
