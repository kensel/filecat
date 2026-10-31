"""Storage topology collectors: raw sources in, the generic topology out.

The agent is a primitive engine (docs/agent-protocol.md, docs/agent-allowlist.md): it reads
files, lists directories, reports `statfs`, sums subtrees and runs allowlisted commands. What
those bytes mean is decided here, so a new rule, format or platform never needs an agent
rebuild. A collector is a function over a `Source`:

    from filecat.topology_collect import AgentSource, collect
    with AgentClient.from_config(agent) as client:
        topo = collect(AgentSource(client), name="nas3", unc_server="\\\\\\\\nas3")

Collectors: `synology` (DSM 7: disks, md, LVM, volumes, shares, LUNs, VMM) and `linux` (disks,
mounted file systems). TrueNAS and Proxmox follow the same pattern: one module, a `collect`
function, recorded raw outputs under tests/data/raw/<host>/ to test it with `RecordedSource`.
"""
from __future__ import annotations

from typing import Any, Callable

from .. import topology
from . import linux, synology
from .source import AgentSource, RecordedSource, RecordingSource, Source

COLLECTORS: dict[str, Callable[..., topology.Topology]] = {
    synology.PLATFORM: synology.collect,
    linux.PLATFORM: linux.collect,
}


def detect_platform(source: Source) -> str:
    """The most specific collector that applies to the host: `synology` for a DSM host, else `linux`."""
    return synology.PLATFORM if synology.is_synology(source) else linux.PLATFORM


def collect(source: Source, platform: str | None = None, **kwargs: Any) -> topology.Topology:
    """Collect the topology of the host behind `source` (name, unc_server, now, measure_shares
    are the keywords every collector takes)."""
    platform = platform or detect_platform(source)
    if platform not in COLLECTORS:
        raise ValueError(f"no collector for platform {platform!r}; choose from {', '.join(COLLECTORS)}")
    return COLLECTORS[platform](source, **kwargs)


__all__ = ["AgentSource", "RecordedSource", "RecordingSource", "Source", "COLLECTORS", "collect", "detect_platform"]
