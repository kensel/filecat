"""Options shared by scan, enrich, probes and identifiers.

Built from argparse by ScanOptions.from_args, or directly in tests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MiB = 1024 * 1024
PARTIAL_HASH_CUTOFF = 64 * MiB      # F1: larger files get sha256_partial
PARTIAL_HASH_EDGE = 1 * MiB
LOCAL_TIMEOUT = 30.0
UNC_TIMEOUT = 120.0
HEAD_BYTES = 8 * 1024               # one read feeds magic and the built-in probe
SAMPLE_BYTES = 4 * 1024
GZIP_PROBE_CAP = 4 * MiB


@dataclass
class ScanOptions:
    hash: str = "auto"                  # auto | full | none
    identify: str = "local"             # local | always | never
    timeout: float | None = None        # None -> LOCAL_TIMEOUT / UNC_TIMEOUT
    force: bool = False
    default_skips: bool = True
    pronom: bool = False
    trid_defs: str | None = None
    magika: bool = False
    list_zip_cap: int = 100
    expand_dat: bool = False
    member_cap: int = 1000
    archive_scan_cap: int = 64 * MiB    # bytes decompressed to list a .tar.gz/.bz2/.xz
    deep_archives: bool = False         # list compressed tarballs to the end
    max_members: int = 100_000          # member rows stored per archive
    expand_compound: bool = False       # store every entry of a .docx/.jar/... (probe/compound.py)
    disk_scan_cap: int = 8 * MiB        # bytes read per volume for the disk content scan (0 = off)
    workers: int = 4
    ollama: bool = False
    model: str | None = None
    ollama_url: str | None = None
    ollama_kinds: list[str] = field(default_factory=lambda: ["unknown"])
    ollama_max_files: int = 200
    ollama_max_size: int = 256 * 1024
    progress_interval: float = 5.0
    keep_dropped: int = 90              # days a vanished file's record stays in the dropped store
    aliases: dict[str, str] = field(default_factory=dict)  # read PATH, record ROOT (aliases.py)
    measure_backups: bool = False       # read backup data files (chunks, volumes) like any other
    verify_backups: int = 0             # --verify-backups[=N]: 0 nothing, 1 rolled-up totals against the manifest (docs/rollups.md 4.5)
    measure_databases: bool = False     # read database data files that are quiet and big enough (dbfiles/)
    exclude: list[str] = field(default_factory=list)  # folders/files not walked (walker.excluded)
    check_only: bool = False            # preflight (open each root, account) and stop
    agents: list[Any] = field(default_factory=list)  # config.AgentConfig: filecat-agent hosts (fsource.pick)
    agent: str | None = None            # --agent NAME: use that agent for the roots it covers
    no_agent: bool = False              # --no-agent: read every root over SMB, whatever agents are configured
    agent_fallback: bool = False        # --agent-fallback: an unreachable agent's roots are read over SMB
    rollup_config: Any = None           # rollup.RollupConfig: the [rollups] modes and rules (None: all manual)
    rollup_workers: int = 4             # threads that sum rolled-up folders
    rollup_timeout: float | None = None  # seconds one rollup may take on an SMB or local scan
    new_redaction_key: bool = False     # --new-redaction-key: write a key although sticky entries exist
    cancel: Any = None                  # threading.Event: when set the scan stops at the next entry (filecat server)

    @classmethod
    def from_args(cls, args: Any) -> "ScanOptions":
        opts = cls()
        for name in cls.__dataclass_fields__:
            if hasattr(args, name):
                value = getattr(args, name)
                if value is not None:
                    setattr(opts, name, value)
        if getattr(args, "no_default_skips", False):
            opts.default_skips = False
        return opts

    def timeout_for(self, root: str) -> float:
        if self.timeout is not None:
            return self.timeout
        return UNC_TIMEOUT if is_unc(root) else LOCAL_TIMEOUT

    def identify_bytes_for(self, root: str) -> bool:
        if self.identify == "always":
            return True
        if self.identify == "never":
            return False
        return not is_unc(root)


def is_unc(path: str) -> bool:
    return path.startswith("\\\\") or path.startswith("//")
