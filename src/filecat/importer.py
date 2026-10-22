"""filecat import: load PowerShell `Get-ChildItem | ConvertTo-Json` exports (one JSON
object per line) or filecat's own jsonl output into a catalog backend.

See file-catalog-requirements.md, "Record" and "How a large or remote tree is walked",
plus the task note this module was built from for the exact field mapping.

Public API:
    import_file(path, backend, *, fmt="auto", root=None, synthesize_dirs=True,
                progress=None) -> ImportStats
    run(args) -> int
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .backends import open_backend
from .backends.base import Backend
from .record import ROOT_REL, new_document, root_id as compute_root_id

BATCH_SIZE = 5000
PROGRESS_INTERVAL = 3.0
MAX_EXAMPLES = 10  # malformed / out-of-root line numbers kept for the report

# filecat's own document shape, as produced by a scan / written to jsonl.
_FILECAT_KEYS = ("root_id", "rel_path")
# A PowerShell Get-ChildItem export: FullName is the absolute path; Length or
# Attributes distinguishes it from an arbitrary JSON object.
_POWERSHELL_KEYS = ("FullName",)

_TS_RE = re.compile(
    r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})T(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

ProgressFn = Callable[[int, int, str], None]


# --------------------------------------------------------------------------- stats

@dataclass
class ImportStats:
    """Result of importing one input file."""
    file: str = ""
    lines: int = 0           # every line read, including blank ones
    non_blank: int = 0       # lines with content after stripping BOM/whitespace
    records: int = 0         # documents written (files + dirs seen in the stream)
    dirs_synthesized: int = 0
    skipped_existing: int = 0
    malformed: int = 0
    out_of_root: int = 0
    elapsed: float = 0.0
    open_error: str | None = None
    malformed_examples: list[tuple[int, str]] = field(default_factory=list)
    out_of_root_examples: list[tuple[int, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """False when the file could not be opened, or every non-blank line failed."""
        if self.open_error is not None:
            return False
        if self.non_blank > 0 and self.malformed == self.non_blank:
            return False
        return True

    def summary_line(self) -> str:
        if self.open_error is not None:
            return f"{self.file}: could not open ({self.open_error})"
        return (f"{self.file}: {self.lines} lines, {self.records} records, "
                f"{self.dirs_synthesized} dirs synthesized, "
                f"{self.skipped_existing} skipped (already probed), "
                f"{self.malformed} malformed, {self.out_of_root} out-of-root, "
                f"{self.elapsed:.1f}s")


# --------------------------------------------------------------------------- timestamps

def parse_dotnet_ts_ns(value: str | None) -> int | None:
    """Parse a .NET round-trip UTC timestamp ("...8237918Z") to integer nanoseconds
    since the Unix epoch. 7 fractional digits are 100 ns ticks; fewer digits are
    padded with zeros (never routed through float). Handles a missing fraction and
    a numeric UTC offset in place of "Z"."""
    if not value:
        return None
    m = _TS_RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(k)) for k in ("y", "mo", "d", "h", "mi", "s"))
    frac = m.group("frac") or ""
    ns_frac = int((frac + "0" * 9)[:9]) if frac else 0
    tz = m.group("tz")
    if tz is None or tz == "Z":
        tzinfo = dt.timezone.utc
    else:
        sign = 1 if tz[0] == "+" else -1
        oh, om = int(tz[1:3]), int(tz[4:6])
        tzinfo = dt.timezone(sign * dt.timedelta(hours=oh, minutes=om))
    local_dt = dt.datetime(y, mo, d, h, mi, s, tzinfo=tzinfo)
    delta = local_dt - _EPOCH
    epoch_s = delta.days * 86400 + delta.seconds
    return epoch_s * 1_000_000_000 + ns_frac


# --------------------------------------------------------------------------- roots / paths

def _norm_sep(p: str) -> str:
    return p.replace("/", "\\")


def infer_root(full_name: str) -> str | None:
    """`\\\\server\\share` for a UNC path, `C:\\` for a drive path. Preserves the
    casing of FullName exactly; no trailing backslash for UNC, one for a drive."""
    norm = _norm_sep(full_name)
    if norm.startswith("\\\\"):
        parts = norm[2:].split("\\")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return None
        return "\\\\" + parts[0] + "\\" + parts[1]
    if len(norm) >= 3 and norm[1] == ":" and norm[2] == "\\":
        return norm[0:2] + "\\"
    return None


def rel_path_under(root: str, full_name: str) -> str | None:
    """FullName relative to root, '/'-separated. None when root is not a path-
    boundary-respecting, case-insensitive prefix of full_name."""
    root_n = _norm_sep(root).rstrip("\\")
    full_n = _norm_sep(full_name)
    if not full_n.casefold().startswith(root_n.casefold()):
        return None
    rest = full_n[len(root_n):]
    if rest == "":
        return ROOT_REL
    if not rest.startswith("\\"):
        return None
    return rest[1:].replace("\\", "/")


def _parent_rel(rel_path: str) -> str:
    if "/" not in rel_path:
        return ROOT_REL
    return rel_path.rsplit("/", 1)[0]


def _account_for(root: str, rel_path: str, all_dirs: set[tuple[str, str]],
                  child_count: dict[tuple[str, str], int]) -> None:
    """Record that rel_path (a file or directory) is a direct child of its
    parent directory, and make sure that parent and every ancestor up to and
    including the root ("") will get a directory record. Each ancestor
    directory counts as exactly one child of *its* parent, the first time it
    is discovered -- regardless of how many descendants are under it."""
    parent = _parent_rel(rel_path)
    key = (root, parent)
    child_count[key] = child_count.get(key, 0) + 1
    cur = parent
    while (root, cur) not in all_dirs:
        all_dirs.add((root, cur))
        if cur == ROOT_REL:
            break
        grandparent = _parent_rel(cur)
        gkey = (root, grandparent)
        child_count[gkey] = child_count.get(gkey, 0) + 1
        cur = grandparent


# --------------------------------------------------------------------------- powershell mapping

def _split_attrs(attributes: str | None) -> list[str]:
    if not attributes:
        return []
    return [a.strip() for a in attributes.split(",") if a.strip()]


def _kind_for(attrs: list[str], length: int, link_target: Any) -> str:
    if "Directory" in attrs:
        return "dir"
    if link_target is not None or "ReparsePoint" in attrs:
        return "link"
    if length == 0:
        return "empty"
    return "unknown"


def _from_powershell(obj: dict[str, Any], explicit_root: str | None,
                      source_file: str, line_no: int) -> tuple[dict[str, Any] | None, str]:
    """Returns (document, status). status is one of "ok", "malformed", "out_of_root"."""
    full_name = obj.get("FullName")
    if not full_name or not isinstance(full_name, str):
        return None, "malformed"
    if explicit_root:
        root = explicit_root
        rel = rel_path_under(root, full_name)
        if rel is None:
            return None, "out_of_root"
    else:
        root = infer_root(full_name)
        if root is None:
            return None, "malformed"
        rel = rel_path_under(root, full_name)
        if rel is None:
            return None, "malformed"

    length = obj.get("Length")
    if length is None:
        length = 0
    attrs = _split_attrs(obj.get("Attributes"))
    link_target = obj.get("LinkTarget")
    kind = _kind_for(attrs, length, link_target)
    size = 0 if kind == "dir" else int(length)

    mtime_ns = parse_dotnet_ts_ns(obj.get("LastWriteTimeUtc"))
    ctime_ns = parse_dotnet_ts_ns(obj.get("CreationTimeUtc"))
    name = obj.get("Name") or obj.get("BaseName") or (rel.rsplit("/", 1)[-1] if rel else None)

    doc = new_document(root, rel, kind=kind, size=size, mtime_ns=mtime_ns,
                        ctime_ns=ctime_ns, name=name)

    probe: dict[str, Any] = {"attributes": attrs}
    if "IsReadOnly" in obj and obj["IsReadOnly"] is not None:
        probe["readonly"] = bool(obj["IsReadOnly"])
    atime_ns = parse_dotnet_ts_ns(obj.get("LastAccessTimeUtc"))
    if atime_ns is not None:
        probe["atime_ns"] = atime_ns
    if kind == "link" and link_target:
        probe["link_target"] = link_target
    doc["probe"] = probe
    doc["source"] = {"format": "powershell", "file": source_file, "line": line_no}
    return doc, "ok"


def _from_filecat(obj: dict[str, Any], explicit_root: str | None) -> tuple[dict[str, Any] | None, str]:
    if not all(k in obj for k in _FILECAT_KEYS) or "root" not in obj or "kind" not in obj:
        return None, "malformed"
    doc = dict(obj)
    if explicit_root:
        doc["root"] = explicit_root
        doc["root_id"] = compute_root_id(explicit_root)
    return doc, "ok"


def _detect_format(obj: dict[str, Any], forced: str) -> str | None:
    if forced != "auto":
        return forced
    if all(k in obj for k in _FILECAT_KEYS):
        return "filecat"
    if any(k in obj for k in _POWERSHELL_KEYS):
        return "powershell"
    return None


# --------------------------------------------------------------------------- dir synthesis

def _should_skip_existing(backend: Backend, doc: dict[str, Any]) -> bool:
    existing = backend.get(doc["root"], doc["rel_path"])
    if existing is None:
        return False
    return (existing.get("container") is not None
            and existing.get("size") == doc.get("size")
            and existing.get("mtime_ns") == doc.get("mtime_ns"))


def _write_synthesized_dirs(backend: Backend, all_dirs: set[tuple[str, str]],
                             child_count: dict[tuple[str, str], int],
                             source_file: str, stats: ImportStats) -> None:
    batch: list[dict[str, Any]] = []
    for root, rel in sorted(all_dirs):
        existing = backend.get(root, rel)
        if existing is not None and existing.get("mtime_ns") is not None:
            stats.skipped_existing += 1
            continue
        doc = new_document(root, rel, kind="dir", size=0)
        doc["probe"] = {"child_count": child_count.get((root, rel), 0)}
        doc["source"] = {"format": "powershell-synth", "file": source_file}
        batch.append(doc)
        stats.dirs_synthesized += 1
        if len(batch) >= BATCH_SIZE:
            backend.put_many(batch)
            batch.clear()
    if batch:
        backend.put_many(batch)


# --------------------------------------------------------------------------- main entry point

def import_file(path: str, backend: Backend, *, fmt: str = "auto", root: str | None = None,
                 synthesize_dirs: bool = True, progress: ProgressFn | None = None) -> ImportStats:
    """Stream one JSONL file into backend. See module docstring."""
    source_file = os.path.basename(path)
    stats = ImportStats(file=source_file)
    started = time.monotonic()

    try:
        fh = open(path, encoding="utf-8-sig", newline="")
    except OSError as exc:
        stats.open_error = str(exc)
        stats.elapsed = time.monotonic() - started
        return stats

    all_dirs: set[tuple[str, str]] = set()
    child_count: dict[tuple[str, str], int] = {}
    batch: list[dict[str, Any]] = []
    last_progress = started
    last_name = ""

    def flush() -> None:
        if batch:
            backend.put_many(batch)
            batch.clear()

    with fh:
        for line_no, raw in enumerate(fh, start=1):
            stats.lines += 1
            line = raw.lstrip("\ufeff").strip()
            if not line:
                continue
            stats.non_blank += 1

            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                stats.malformed += 1
                if len(stats.malformed_examples) < MAX_EXAMPLES:
                    stats.malformed_examples.append((line_no, str(exc)))
                continue
            if not isinstance(obj, dict):
                stats.malformed += 1
                if len(stats.malformed_examples) < MAX_EXAMPLES:
                    stats.malformed_examples.append((line_no, "not a JSON object"))
                continue

            detected = _detect_format(obj, fmt)
            if detected == "filecat":
                doc, status = _from_filecat(obj, root)
            elif detected == "powershell":
                doc, status = _from_powershell(obj, root, source_file, line_no)
            else:
                doc, status = None, "malformed"

            if status == "malformed":
                stats.malformed += 1
                if len(stats.malformed_examples) < MAX_EXAMPLES:
                    stats.malformed_examples.append((line_no, "missing required identity fields"))
                continue
            if status == "out_of_root":
                stats.out_of_root += 1
                if len(stats.out_of_root_examples) < MAX_EXAMPLES:
                    stats.out_of_root_examples.append((line_no, obj.get("FullName", "")))
                continue

            assert doc is not None
            last_name = doc.get("name", "")

            if synthesize_dirs:
                _account_for(doc["root"], doc["rel_path"], all_dirs, child_count)

            if _should_skip_existing(backend, doc):
                stats.skipped_existing += 1
                continue

            batch.append(doc)
            stats.records += 1
            if len(batch) >= BATCH_SIZE:
                flush()

            now = time.monotonic()
            if progress is not None and now - last_progress >= PROGRESS_INTERVAL:
                progress(stats.lines, stats.records, last_name)
                last_progress = now

        flush()

    if synthesize_dirs and all_dirs:
        _write_synthesized_dirs(backend, all_dirs, child_count, source_file, stats)

    stats.elapsed = time.monotonic() - started
    return stats


def _default_progress(source_file: str) -> ProgressFn:
    def _report(lines: int, records: int, current: str) -> None:
        print(f"import: {source_file}: {lines} lines, {records} records, current {current}",
              file=sys.stderr, flush=True)
    return _report


def run(args) -> int:
    started = time.monotonic()
    any_open_error = False
    any_total_failure = False
    with open_backend(args.backend, args.out, args.dsn) as backend:
        all_stats: list[ImportStats] = []
        for path in args.files:
            stats = import_file(path, backend, fmt=args.format, root=args.root,
                                 synthesize_dirs=not args.no_dirs,
                                 progress=_default_progress(os.path.basename(path)))
            all_stats.append(stats)
            print(f"import: {stats.summary_line()}")
            for line_no, msg in stats.malformed_examples:
                print(f"import:   malformed line {line_no}: {msg}", file=sys.stderr)
            for line_no, full_name in stats.out_of_root_examples:
                print(f"import:   out-of-root line {line_no}: {full_name}", file=sys.stderr)
            if stats.open_error is not None:
                any_open_error = True
            elif not stats.ok:
                any_total_failure = True

        if any(s.records or s.dirs_synthesized for s in all_stats):
            try:
                backend.rebuild_aggregates()
            except (NotImplementedError, ImportError):
                # Aggregates are a best-effort convenience; a sibling module
                # (aggregate.py / a backend) may still be a stub mid-build.
                pass

    total_lines = sum(s.lines for s in all_stats)
    total_records = sum(s.records for s in all_stats)
    total_dirs = sum(s.dirs_synthesized for s in all_stats)
    print(f"import: {len(all_stats)} file(s), {total_lines} lines, {total_records} records, "
          f"{total_dirs} dirs synthesized, in {time.monotonic() - started:.1f}s")
    return 1 if (any_open_error or any_total_failure) else 0
