"""Backup stores: folders written by a backup program, recognised by layout.

A backup store holds data that is only meaningful to the program that wrote
it -- deduplicated chunks, numbered zip volumes, encrypted tar volumes. By
default the walker records those files from the directory listing alone
(name, size, mtimes, kind "data", probe.backup_data = format) without
opening them, so a 1 TB chunk pool costs a listing instead of a full read.
`scan --measure-backups` measures them like any other file.

What the store is *for* comes from its own manifest instead: when the
store's folder is finished, `summarize` reads the program's metadata and the
folder's record gets probe.backup:

    {"format": "synology-abb", "machines": [...], "versions": int,
     "latest": iso, "problems": [str], "copy_keys": [str],
     "machine_keys": [str], ...format-specific fields}

`problems` lists what the manifest says should be there and is not (a
missing volume, a size that does not match, a failed or partial version).
`copy_keys` identify the backed-up data itself (a version UUID, a set's
timestamps): two stores sharing one are copies of each other.
`machine_keys` identify the source computer: two stores sharing one but no
copy key are separate backup jobs of the same machine. `filecat backups`
lists stores and groups them by these keys.

Formats: abb.py (Synology Active Backup for Business), abg.py (its Google
Workspace module), hyperbackup.py (Synology Hyper Backup .hbk targets),
thunderbird.py (ImportExportTools NG copies of a Thunderbird profile),
veeam.py (Veeam .vbm/.vbk/.vib job folders), windows.py (Windows Backup and
Restore file backups, WindowsImageBackup), duplicity.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


class Format(Protocol):
    name: str

    def matches(self, dir_name: str, names: set[str]) -> bool:
        """Is a folder called `dir_name` holding entries `names` a store root?"""

    def opaque(self, inner: str) -> bool:
        """Is the file at `inner` ('/'-separated, relative to the store root)
        backup data to record from the listing only?"""

    def summarize(self, path: str, names: set[str]) -> dict[str, Any]:
        """probe.backup for the store at OS path `path`. May raise; the
        walker records that as a `backup`-stage error."""

    # A format may set `uses_listing = True`: summarize() then also takes
    # `listing`, a callable returning {inner path: size} of every file the
    # walk recorded beneath the store, so checks against the manifest cost
    # no second listing of the target.
    #
    # A format may set `verifies = True`: summarize() then also takes
    # `verify` (scan --verify-backups), asking it to read the data and check
    # it against the manifest's checksums instead of sizes alone.
    #
    # A format may set `virtual = True`: its folder shows data that lives
    # elsewhere (ABB's ActiveBackupData), so the walker records the folder
    # and its summary but does not descend into it.
    #
    # Database data folders (dbfiles/) use the same hooks and also set
    # `probe_key` (the folder's summary key, default "backup"), `data_key`
    # (the listed file's tag, default "backup_data"), `measured(st, options)`
    # (read this data file after all? default: options.measure_backups) and
    # `tag_measured` (a measured data file keeps its tag).


@dataclass(frozen=True)
class Store:
    format: Format
    rel_path: str           # of the store root within the scan root

    @property
    def virtual(self) -> bool:
        return bool(getattr(self.format, "virtual", False))

    @property
    def probe_key(self) -> str:
        return getattr(self.format, "probe_key", "backup")

    @property
    def data_key(self) -> str:
        return getattr(self.format, "data_key", "backup_data")

    def measured(self, st: Any, options: Any) -> bool:
        """Is this data file read like any other instead of listed only?"""
        fn = getattr(self.format, "measured", None)
        return fn(st, options) if fn else options.measure_backups

    def opaque(self, rel_path: str) -> bool:
        prefix = f"{self.rel_path}/" if self.rel_path else ""
        return rel_path.startswith(prefix) and self.format.opaque(rel_path[len(prefix):])


def formats() -> list[Format]:
    from . import abb, abg, duplicity, hyperbackup, thunderbird, veeam, windows
    return [abb.FORMAT, abb.VIEW, abg.FORMAT, hyperbackup.FORMAT, thunderbird.FORMAT, veeam.FORMAT,
            windows.FILE_BACKUP, windows.IMAGE_BACKUP, duplicity.FORMAT]


def detect(rel_path: str, dir_name: str, names: set[str]) -> Store | None:
    """The store rooted at this folder, if its entries look like one."""
    for fmt in formats():
        if fmt.matches(dir_name, names):
            return Store(fmt, rel_path)
    return None


def summarize(store: Store, path: str, names: set[str],
              listing: Callable[[], dict[str, int]] | None = None, verify: bool = False) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if getattr(store.format, "uses_listing", False):
        kwargs["listing"] = listing
    if verify and getattr(store.format, "verifies", False):
        kwargs["verify"] = True
    out = store.format.summarize(path, names, **kwargs)
    out.setdefault("format", store.format.name)
    out.setdefault("problems", [])
    if store.probe_key == "backup":
        out.setdefault("copy_keys", [])
        out.setdefault("machine_keys", [])
    return out
