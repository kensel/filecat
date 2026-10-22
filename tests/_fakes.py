"""Fake probe_file / Identifier for scan.py tests. probe_file and Identifier
are still NotImplementedError stubs in this worktree (owned by other
branches), so scan-level tests monkeypatch the names scan.py imports with
these instead of the real implementations.
"""
from __future__ import annotations

from typing import Any

from filecat.probe import ProbeResult


def fake_probe_file(path: str, name: str, size: int, head: bytes, options: Any = None) -> ProbeResult:
    if name == "boom-probe.bin":
        raise RuntimeError("fake probe blew up")
    is_text = bool(head) and b"\x00" not in head
    if is_text:
        return ProbeResult(kind="text", container="plain",
                           probe={"fake_probed": True},
                           sample=head.decode("utf-8", errors="replace"))
    return ProbeResult(kind="unknown", container="plain", probe={"fake_probed": True})


class FakeIdentifier:
    """Stands in for filecat.identify.Identifier."""

    def __init__(self, options: Any = None) -> None:
        self.options = options
        self.scan_errors: list[dict[str, str]] = []

    def by_name(self, name: str, size: int | None = None,
                probe_format: str | None = None) -> dict[str, Any]:
        return {}

    def identify(self, path: str | None, name: str, head: bytes | None, kind: str,
                 size: int | None = None, probe_format: str | None = None) -> dict[str, Any]:
        if name == "boom-identify.bin":
            raise RuntimeError("fake identify blew up")
        return {"mime": "application/x-fake", "probe": {"identify_basis": "name"}}

    def close(self) -> None:
        pass
