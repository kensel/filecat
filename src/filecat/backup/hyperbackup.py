"""Synology Hyper Backup (multi-version backups of a NAS, "<task>_<n>.hbk").

Synology does not document the format; this is read from real targets
(Hyper Backup 4.x, target_ver 0.3, index_ver 0.9). Layout::

    <host>_<n>.hbk/                  <- the store root
        SynologyHyperBackup.bkpi       empty marker Hyper Backup Explorer opens
        _Syno_TaskConfig               INI: task name, source host_name/model,
                                       unikey, backup_folders, encryption, rotation
        last_status.conf               INI: [last_backup] start/end/version
        storage_statistics.db          SQLite: source_table (per version, KiB),
                                       target_table (target_size in KiB over time)
        synobkpinfo.db                 SQLite: task id, formatType, dataEnc/dataComp
        Config/                        opaque:
            version_info.db            SQLite version_info: one row per version
                                       (id, timestamp, status, locked, share,
                                       statistics JSON with per-version counts)
            @Share/<share>/<ver>.db    file list of each share per version
            @cand_file/[<n>/]<id>_<k>.cand, file_chunk<k>.index/, virtual_file.index/,
            candidate_chunk.db ...     dedup indexes (and *_dup copies of each)
        Pool/                          opaque:
            0/<b // 2048>/<b % 2048>.bucket|.index|.lock   chunk buckets (~50 MiB)
            chunk_index/<n>.idx, file_pool/<n>.file
        Guard/                         opaque:
            local_bucket.db            SQLite file_info: every bucket and bucket
            local_file.db              index / every other data file, with size and CRC
            config.json                {"state": "committed" | "ready", ...}
            detect.prog, detect/error.log   the last integrity check
        Versionlog/log_<ver>.zip       opaque: per-version change logs

Checks:
- every file Guard lists is in the listing with Guard's size (the listing
  is the walk's own, so the check costs no extra reads of the target);
- with `scan --verify-backups` only: every one of those files is read and
  its CRC32 compared with Guard's (reads the whole target);
- versions whose status is a failure;
- error lines the last integrity check wrote to Guard/detect/error.log.

With the store's `Pool/` rolled up (docs/rollups.md, section 4) the listing
does not hold it: at verify level 0 nothing is compared, and at level 1 the
pool's total bytes and file count are compared with the sum of Guard's entries
under `Pool/` (and the files outside it with the listing); `checked` is
"totals".

Files under the store's subfolders are listed only; the small files at its
top are read like any other. The full on-disk format, as far as it is
known, is in docs/formats/synology-hyperbackup.md.
"""
from __future__ import annotations

import configparser
import json
import os
import re
import zlib
from typing import Any, Callable

from .util import iso, listdir, read_json, sqlite_rows

KiB = 1024
_FAILED = re.compile(r"fail|error|partial|broken", re.I)
_MAX_EXAMPLES = 5
_READ = 1 << 20

# Guard/local_file.db file_info.type -> path of the file it describes
# (name and idx are that row's columns).
_FILE_PATHS: dict[int, Callable[[str, int], str]] = {
    1: lambda name, idx: name,
    2: lambda name, idx: f"Config/@Share/{name}/{idx}.db",
    3: lambda name, idx: f"Config/virtual_file.index/{idx}.idx",
    4: lambda name, idx: f"Config/file_chunk{name}.index/{idx}.idx",
    5: lambda name, idx: f"Pool/chunk_index/{idx}.idx",
    8: lambda name, idx: f"Pool/file_pool/{idx}.file",
    9: lambda name, idx: (f"Config/@cand_file/{idx}_{name}.cand" if idx < 4096
                          else f"Config/@cand_file/{idx // 4096}/{idx}_{name}.cand"),
    10: lambda name, idx: f"Versionlog/log_{idx}.zip",
}
# Guard/local_bucket.db: 6 the bucket's index, 7 the bucket.
_BUCKET_EXT = {6: "index", 7: "bucket"}


def _value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return raw.strip('"')


def read_conf(path: str) -> dict[str, dict[str, Any]]:
    """An INI file of Hyper Backup's (values JSON or "quoted"), by section."""
    parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    parser.optionxform = str
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        parser.read_file(f)
    return {s: {k: _value(v) for k, v in parser.items(s)} for s in parser.sections()}


def _rows(path: str, sql: str) -> list[dict[str, Any]]:
    """sqlite_rows, falling back to the *_dup copy Hyper Backup keeps of each database."""
    try:
        return sqlite_rows(path, sql)
    except Exception:
        if not os.path.isfile(f"{path}_dup"):
            raise
        return sqlite_rows(f"{path}_dup", sql)


def _json(text: Any) -> Any:
    try:
        return json.loads(text) if isinstance(text, str) and text else None
    except ValueError:
        return None


def _os_listing(path: str) -> dict[str, int]:
    """{inner path: size} of every file beneath the store, read from disk."""
    out: dict[str, int] = {}
    stack = [""]
    while stack:
        rel = stack.pop()
        for name, e in listdir(os.path.join(path, rel) if rel else path).items():
            inner = f"{rel}/{name}" if rel else name
            try:
                if e.is_dir(follow_symlinks=False):
                    stack.append(inner)
                else:
                    out[inner] = e.stat(follow_symlinks=False).st_size
            except OSError:
                pass
    return out


def _crc32(path: str) -> int:
    crc = 0
    with open(path, "rb") as f:
        while block := f.read(_READ):
            crc = zlib.crc32(block, crc)
    return crc


class _HyperBackup:
    name = "synology-hyperbackup"
    uses_listing = True     # summarize() takes the walk's listing of the store
    verifies = True         # and verify=True: check Guard's CRC32 of every file
    uses_rollup = True      # and rollup=, level=: the pool is a rollup, not in the listing
    verify_level = 2        # the CRC32 read of every file is the per-file level (docs/rollups.md 4.5)
    manifests = ("_Syno_TaskConfig", "last_status.conf", "storage_statistics.db", "synobkpinfo.db",
                 "Config/version_info.db", "Guard/local_bucket.db", "Guard/local_file.db",
                 "Guard/config.json", "Guard/detect.prog")

    def matches(self, dir_name: str, names: set[str]) -> bool:
        if "SynologyHyperBackup.bkpi" in names:
            return True
        return dir_name.lower().endswith(".hbk") and {"Config", "Pool"} <= names

    def opaque(self, inner: str) -> bool:
        return "/" in inner

    def summarize(self, path: str, names: set[str],
                  listing: Callable[[], dict[str, int]] | None = None,
                  verify: bool = False, rollup: dict[str, Any] | None = None,
                  level: int = 0) -> dict[str, Any]:
        out: dict[str, Any] = {"format": self.name}
        problems: list[str] = []

        try:
            cfg = read_conf(os.path.join(path, "_Syno_TaskConfig")).get("task_config", {})
        except (OSError, configparser.Error) as e:
            cfg = {}
            problems.append(f"_Syno_TaskConfig unreadable: {type(e).__name__}: {e}")
        unikey = cfg.get("unikey")
        compat = cfg.get("compatible_info") if isinstance(cfg.get("compatible_info"), dict) else {}
        out.update({
            "task": cfg.get("name"), "task_uuid": unikey, "created": iso(cfg.get("create_time")),
            "source_host": cfg.get("host_name"), "source_model": cfg.get("source_model"),
            "source_ip": cfg.get("ip"),
            "hyper_backup_version": compat.get("source_hb_version"),
            "folders": cfg.get("backup_folders") or [], "apps": cfg.get("backup_apps") or [],
            "encrypted": cfg.get("enable_data_encrypt"), "compressed": bool(cfg.get("data_compress_type")),
            "rotation": cfg.get("rotate_option"),
        })
        out["machines"] = [cfg["host_name"]] if cfg.get("host_name") else []

        versions = self._versions(path, problems)
        out["version_list"] = versions
        out["versions"] = len(versions)
        out["latest"] = max((v["start"] for v in versions if v.get("start")), default=None)
        complete = [v for v in versions if v.get("status") == "Complete"]
        if not out["folders"] and versions:     # older task configs leave backup_folders out
            out["folders"] = [f"/{s}" for s in versions[-1]["shares"] if not s.startswith("@")]
        out["latest_complete"] = max((v["start"] for v in complete if v.get("start")), default=None)

        try:
            last = read_conf(os.path.join(path, "last_status.conf")).get("last_backup") or {}
            out["last_backup"] = {"start": iso(last.get("start")), "end": iso(last.get("end")),
                                  "version": (last.get("version") or [None])[0]}
        except (OSError, configparser.Error):
            pass

        storage: dict[str, Any] = {}
        if complete:
            storage["source_bytes"] = complete[-1].get("source_bytes")
        try:
            target = _rows(os.path.join(path, "storage_statistics.db"),
                           "SELECT target_size FROM target_table ORDER BY end_time DESC LIMIT 1")
            if target and target[0]["target_size"] is not None:
                storage["target_bytes"] = int(target[0]["target_size"]) * KiB
        except Exception:
            pass

        guard = self._guard(path, listing, problems, verify, rollup, level)
        if rollup is not None:
            out["checked"] = "totals" if level >= 1 and not rollup.get("partial") else "none"
        if guard:
            storage["stored_bytes"] = guard.pop("bytes")
            out["guard"] = guard
        used = storage.get("target_bytes") or storage.get("stored_bytes")
        if storage.get("source_bytes") and used:
            storage["reduction_ratio"] = round(storage["source_bytes"] / used, 2)
        out["storage"] = storage

        check = self._integrity_check(path)
        if check:
            out["integrity_check"] = check
            problems += [f"integrity check: {line}" for line in check.get("errors", [])]

        out["problems"] = problems
        out["copy_keys"] = sorted(f"hyperbackup:{unikey}:{v['id']}" for v in complete if unikey)
        keys = {f"host:{m.lower()}" for m in out["machines"]}
        if isinstance(unikey, str) and "_" in unikey:
            keys.add(f"synology:{unikey.split('_', 1)[0].lower()}")
        out["machine_keys"] = sorted(keys)
        return out

    def _versions(self, path: str, problems: list[str]) -> list[dict[str, Any]]:
        try:
            rows = _rows(os.path.join(path, "Config", "version_info.db"),
                         "SELECT id, timestamp, status, locked, share, statistics, suspend_history"
                         " FROM version_info ORDER BY id")
        except Exception as e:
            problems.append(f"Config/version_info.db unreadable: {type(e).__name__}: {e}")
            return []
        out = []
        for r in rows:
            stats = _json(r.get("statistics")) or {}
            summary = stats.get("summary") or {}
            share, app = summary.get("share") or {}, summary.get("app") or {}
            history = _json(r.get("suspend_history")) or []
            end = next((h.get("server_time") for h in reversed(history)
                        if isinstance(h, dict) and h.get("event_desc") == "complete"), None)
            v: dict[str, Any] = {
                "id": r["id"], "start": iso(r.get("timestamp")), "end": iso(end),
                "status": r.get("status"), "locked": bool(r.get("locked")),
                "shares": [s for s in (r.get("share") or "").split(",") if s],
            }
            if share or app:
                v.update({
                    "source_bytes": (share.get("total_size") or 0) + (app.get("total_size") or 0),
                    "files": (share.get("total_cnt") or 0) + (app.get("total_cnt") or 0),
                    "new": share.get("new_cnt"), "modified": share.get("mod_cnt"),
                    "deleted": share.get("del_cnt"), "stored_new_bytes": stats.get("compress_size"),
                })
            if _FAILED.search(str(r.get("status") or "")):
                problems.append(f"version {r['id']} ({(v['start'] or '?')[:16].replace('T', ' ')}): "
                                f"{r.get('status')}")
            out.append(v)
        return out

    def _guard(self, path: str, listing: Callable[[], dict[str, int]] | None,
               problems: list[str], verify: bool = False, rollup: dict[str, Any] | None = None,
               level: int = 0) -> dict[str, Any] | None:
        """Every file Guard's manifest lists, against the listing of the store
        (and, with verify, against Guard's CRC32 of its contents)."""
        expected: dict[str, int] = {}
        crcs: dict[str, bytes] = {}
        unknown = 0
        try:
            for r in _rows(os.path.join(path, "Guard", "local_bucket.db"),
                           "SELECT type, idx, size, crc FROM file_info"):
                ext = _BUCKET_EXT.get(r["type"])
                if ext is None:
                    unknown += 1
                    continue
                idx = r["idx"]
                inner = f"Pool/0/{idx // 2048}/{idx % 2048}.{ext}"
                expected[inner], crcs[inner] = r["size"], r["crc"]
            for r in _rows(os.path.join(path, "Guard", "local_file.db"),
                           "SELECT type, name, idx, size, crc FROM file_info"):
                fn = _FILE_PATHS.get(r["type"])
                if fn is None:
                    unknown += 1
                    continue
                inner = fn(r["name"] or "", r["idx"])
                expected[inner], crcs[inner] = r["size"], r["crc"]
        except Exception as e:
            problems.append(f"Guard manifest unreadable: {type(e).__name__}: {e}")
            return None

        guard: dict[str, Any] = {"files": len(expected), "bytes": sum(s or 0 for s in expected.values())}
        if unknown:
            guard["unknown_entries"] = unknown
        try:
            guard["state"] = (read_json(os.path.join(path, "Guard", "config.json")) or {}).get("state")
        except (OSError, ValueError, AttributeError):
            pass

        if rollup is not None:
            self._check_rolled(guard, expected, listing, problems, rollup, level)
            return guard

        on_disk = listing() if listing else _os_listing(path)
        missing = sorted(p for p in expected if p not in on_disk)
        differ = sorted(p for p, s in expected.items() if p in on_disk and s is not None and on_disk[p] != s)
        guard["missing"], guard["size_mismatch"] = len(missing), len(differ)
        if missing:
            problems.append(f"{len(missing)} of {len(expected)} files in Guard's manifest are missing, "
                            f"e.g. {', '.join(missing[:_MAX_EXAMPLES])}")
        if differ:
            problems.append(f"{len(differ)} files differ in size from Guard's manifest, e.g. "
                            + ", ".join(f"{p} ({on_disk[p]} bytes, manifest {expected[p]})"
                                        for p in differ[:_MAX_EXAMPLES]))
        if verify:
            bad, unreadable, checked = [], [], 0
            skip = set(missing) | set(differ)
            for p in sorted(expected):
                want = crcs.get(p)
                if p in skip or not isinstance(want, bytes) or len(want) != 4:
                    continue
                try:
                    got = _crc32(os.path.join(path, *p.split("/")))
                except OSError as e:
                    unreadable.append(f"{p} ({type(e).__name__}: {e})")
                    continue
                checked += 1
                if got != int.from_bytes(want, "big"):
                    bad.append(p)
            guard.update({"crc_checked": checked, "crc_mismatch": len(bad), "crc_unreadable": len(unreadable)})
            if bad:
                problems.append(f"{len(bad)} files do not match Guard's CRC32, e.g. {', '.join(bad[:_MAX_EXAMPLES])}")
            if unreadable:
                problems.append(f"{len(unreadable)} files could not be read to check their CRC32, e.g. "
                                + ", ".join(unreadable[:_MAX_EXAMPLES]))
        return guard

    def _check_rolled(self, guard: dict[str, Any], expected: dict[str, int],
                      listing: Callable[[], dict[str, int]] | None, problems: list[str],
                      rollup: dict[str, Any], level: int) -> None:
        """Guard's manifest against a store whose `Pool/` is a rollup. Level 0
        compares nothing. Level 1 compares the bytes and file count Guard lists
        under the rolled folders with the rollup's, and the other files with
        the walk's listing."""
        if level < 1:
            return
        prefixes = tuple(f"{c}/" for c in rollup.get("children", ()))
        pool = {p: s for p, s in expected.items() if p.startswith(prefixes)}
        rest = {p: s for p, s in expected.items() if p not in pool}
        want_bytes, want_files = sum(s or 0 for s in pool.values()), len(pool)
        guard["rollup"] = {"guard_files": want_files, "guard_bytes": want_bytes,
                           "files": rollup.get("files"), "bytes": rollup.get("bytes")}
        if rollup.get("partial"):
            problems.append("the pool's totals could not be compared with Guard's: some of it could not "
                            "be read, so its sum is a lower bound")
        else:
            got_bytes, got_files = rollup.get("bytes") or 0, rollup.get("files") or 0
            if got_bytes != want_bytes:
                problems.append(f"the pool holds {got_bytes} bytes; Guard's manifest lists {want_bytes}")
            if got_files < want_files:
                problems.append(f"the pool holds {got_files} files; Guard's manifest lists {want_files}")
            elif got_files > want_files:
                guard["rollup"]["unlisted_files"] = got_files - want_files
        if listing is not None:
            on_disk = listing()
            missing = sorted(p for p in rest if p not in on_disk)
            differ = sorted(p for p, s in rest.items() if p in on_disk and s is not None and on_disk[p] != s)
            guard["missing"], guard["size_mismatch"] = len(missing), len(differ)
            if missing:
                problems.append(f"{len(missing)} of {len(rest)} files in Guard's manifest outside the pool "
                                f"are missing, e.g. {', '.join(missing[:_MAX_EXAMPLES])}")
            if differ:
                problems.append(f"{len(differ)} files differ in size from Guard's manifest, e.g. "
                                + ", ".join(f"{p} ({on_disk[p]} bytes, manifest {rest[p]})"
                                            for p in differ[:_MAX_EXAMPLES]))

    def _integrity_check(self, path: str) -> dict[str, Any] | None:
        out: dict[str, Any] = {}
        try:
            prog = read_conf(os.path.join(path, "Guard", "detect.prog")).get("progress") or {}
        except (OSError, configparser.Error):
            prog = {}
        if prog:
            data = prog.get("data_end")
            data = _json(data.strip()) if isinstance(data, str) else data
            out.update({"start": iso(prog.get("launch_time")), "end": iso(prog.get("end_time")),
                        "percent": prog.get("percent"), "result": prog.get("result"),
                        "error_code": prog.get("error_code")})
            if isinstance(data, dict):
                out.update({"checked_bytes": data.get("checked_size"),
                            "total_checked_bytes": data.get("total_checked_size"),
                            "total_bytes": data.get("total_size")})
        try:
            with open(os.path.join(path, "Guard", "detect", "error.log"), encoding="utf-8",
                      errors="replace") as f:
                lines = [ln.strip() for ln in f]
            out["errors"] = [ln for ln in lines
                             if ln and not ln.startswith(("Error Detect Start", "Error Detect Finish"))]
        except OSError:
            pass
        return out or None


FORMAT = _HyperBackup()
