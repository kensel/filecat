"""Synology Active Backup for Business (PC / physical server image backups).

Layout of a backup destination share::

    @ActiveBackup/                     <- the store root
        storage_info.json              {"db_serial": ABB install id, ...}
        storage.cache                  {"size": {task_dir: [backed_up_bytes, n]}}
        @data/                         the deduplicated pool, opaque:
            Pool/<n>/<m>/<k>.buk         chunk buckets (~32 MiB each)
            Hot/, Composition/, sample.index ...
            repo_size                  binary header + [usage, ?, compression_saved]
            file_map.db                SQLite: one row per image in the pool
        PC-<HOST>-<task>/              one folder per backup task
            config.json                device_table (host, OS, UUID), task_table
            target.db                  SQLite: version_table, object_table, device_table
            ActiveBackup_<date>_<time>/  one folder per version (small files only;
                                         the volume images live in the pool)
    ActiveBackupData/                  <- a second store: a virtual view
        PC-<HOST>-<task>/ActiveBackup_<date>_<time>/0.img ...
                                       every volume as a full-size image file,
                                       served from the pool (1 TB per 1 TB disk,
                                       per version). Recorded, never walked:
                                       its sizes are not disk space.

The numbers ABB's Storage page shows come straight from these files:
backed-up size = sum of storage.cache, storage usage = repo_size[0], saved
by compression = repo_size[2], saved by deduplication = the remainder,
reduction ratio = backed-up / usage.

Checks per version (target.db is the manifest):
- status: 5 succeeded, 4 failed (as ABB's log reports it). Other codes are
  reported as numbers and are not problems by themselves: 3 is seen on
  finished versions whose images are all in the pool;
- the version folder exists;
- every small object (device_spec, *.img.delta, backup_db.sqlite) is on disk
  with its recorded size (empty ones are never written, so they are skipped);
- every volume image is in the pool's file_map.db with its recorded size;
  an image still named *.suspend there stopped part way.
Version folders on disk that target.db does not list are reported too.

config.json carries an agent token; only named fields are copied out of it.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .storefs import LOCAL, StoreFS
from .util import iso

STATUS = {5: "succeeded", 4: "failed"}
_VERSION_DIR = re.compile(r"^ActiveBackup_\d{4}-\d{2}-\d{2}_\d{6}$")


def _repo_size(path: str, fs: StoreFS = LOCAL) -> list[int] | None:
    try:
        with fs.open(path, "rb") as f:
            data = f.read(4096)
    except OSError:
        return None
    m = re.search(rb"\[(\d+),(\d+),(\d+)\]", data)
    return [int(x) for x in m.groups()] if m else None


def _json_field(text: str | None) -> Any:
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


class _ActiveBackup:
    name = "synology-abb"
    manifests = ("storage_info.json", "storage.cache", "@data/repo_size", "@data/file_map.db")

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return dir_name == "@ActiveBackup" and "@data" in names and "storage_info.json" in names

    def opaque(self, inner: str) -> bool:
        return inner.startswith(("@data/", "@Fuse/"))

    def summarize(self, path: str, names: set[str], fs: StoreFS = LOCAL) -> dict[str, Any]:
        out: dict[str, Any] = {"format": self.name}
        problems: list[str] = []
        try:
            out["install_id"] = fs.read_json(fs.join(path, "storage_info.json")).get("db_serial")
        except (OSError, ValueError, AttributeError):
            pass

        try:
            cache = (fs.read_json(fs.join(path, "storage.cache")) or {}).get("size") or {}
        except (OSError, ValueError, AttributeError):
            cache = {}
        storage: dict[str, Any] = {}
        backed_up = sum(int(v[0]) for v in cache.values() if v)
        if cache:
            storage["backed_up_bytes"] = backed_up
        repo = _repo_size(fs.join(path, "@data", "repo_size"), fs)
        if repo:
            usage, _, compressed = repo
            storage["usage_bytes"] = usage
            storage["compression_saved_bytes"] = compressed
            if cache:
                storage["dedup_saved_bytes"] = max(backed_up - usage - compressed, 0)
                if usage:
                    storage["reduction_ratio"] = round(backed_up / usage, 2)
        out["storage"] = storage

        pool: dict[str, int] = {}
        map_db = fs.join(path, "@data", "file_map.db")
        try:
            pool = {r["path"]: r["size"] for r in fs.sqlite_rows(map_db, "SELECT path, size FROM file_map")}
        except Exception as e:
            problems.append(f"pool index @data/file_map.db unreadable: {type(e).__name__}: {e}")

        tasks = []
        for name in sorted(names):
            task_path = fs.join(path, name)
            if fs.isfile(fs.join(task_path, "target.db")):
                task = _task(task_path, name, pool, cache.get(name), fs)
                tasks.append(task)
                problems += [f"{name}: {p}" for p in task.pop("problems")]
        out["tasks"] = tasks
        out["machines"] = sorted({t["machine"] for t in tasks if t.get("machine")})
        versions = [v for t in tasks for v in t["versions"]]
        out["versions"] = len(versions)
        out["latest"] = max((v["start"] for v in versions if v.get("start")), default=None)
        out["problems"] = problems
        out["copy_keys"] = sorted(f"abb-version:{v['uuid']}" for v in versions if v.get("uuid"))
        out["machine_keys"] = sorted({f"device:{t['device_uuid']}" for t in tasks if t.get("device_uuid")}
                                     | {f"host:{m.lower()}" for m in out["machines"]})
        return out


def _task(path: str, folder: str, pool: dict[str, int], cached: list | None,
          fs: StoreFS = LOCAL) -> dict[str, Any]:
    task: dict[str, Any] = {"folder": folder}
    problems: list[str] = []
    try:
        cfg = fs.read_json(fs.join(path, "config.json"))
    except (OSError, ValueError):
        cfg = {}
    dev = ((cfg or {}).get("device_table") or [{}])[0]
    tsk = ((cfg or {}).get("task_table") or [{}])[0]
    task.update({
        "machine": dev.get("host_name"), "os": dev.get("os_name"),
        "device_uuid": dev.get("device_uuid"), "host_ip": dev.get("host_ip"),
        "login_user": dev.get("login_user"),
        "task": tsk.get("task_name"), "task_uuid": tsk.get("unikey"),
        "dedup": tsk.get("enable_dedup"), "compress_transfer": tsk.get("enable_compress_transfer"),
        "encrypt_transfer": tsk.get("enable_encrypt_transfer"),
        "retention": tsk.get("retention_policy"),
    })
    if cached:
        task["backed_up_bytes"] = int(cached[0])

    db = fs.join(path, "target.db")
    try:
        versions, objects, devices = fs.sqlite_many(db, [
            ("SELECT * FROM version_table ORDER BY version_id", ()),
            ("SELECT * FROM object_table ORDER BY object_id", ()),
            ("SELECT version_id, host_name, os_name, mount_map FROM device_table", ())])
    except Exception as e:
        task["versions"] = []
        task["problems"] = problems + [f"target.db unreadable: {type(e).__name__}: {e}"]
        return task

    on_disk = fs.listdir(path)
    mounts_by_version: dict[int, dict[str, str]] = {}
    for d in devices:
        task["machine"] = task.get("machine") or d.get("host_name")
        task["os"] = task.get("os") or d.get("os_name")
        mm = _json_field(d.get("mount_map")) or {}
        mounts_by_version[d["version_id"]] = {
            v.get("image_path"): letter for letter, v in mm.items() if isinstance(v, dict)}

    out_versions = []
    for v in versions:
        vid, folder_name = v["version_id"], v["folder_name"]
        status = v.get("status")
        ver: dict[str, Any] = {
            "folder": folder_name, "uuid": v.get("version_uuid"),
            "start": iso(v.get("time_start")), "end": iso(v.get("time_end")),
            "status": STATUS.get(status, f"status {status}"),
            "full": v.get("full_backup") == 1, "volumes": [],
        }
        vp: list[str] = []
        if status == 4:
            vp.append("backup failed")
        vdir = fs.join(path, folder_name)
        if folder_name not in on_disk:
            vp.append("version folder missing")
        files = fs.listdir(vdir)
        mounts = mounts_by_version.get(vid, {})
        transferred = 0
        for o in (o for o in objects if o["version_id"] == vid):
            rel = o["file_path"]
            base = rel.rsplit("/", 1)[-1]
            if o.get("dedup_object"):
                meta = _json_field(o.get("object_meta")) or {}
                vol = {"image": base, "mount": mounts.get(base),
                       "capacity": meta.get("capacity", o.get("file_size")),
                       "transferred": meta.get("trans_size")}
                transferred += meta.get("trans_size") or 0
                key = f"{folder}/{rel}"
                if key in pool:
                    if pool[key] != o["file_size"]:
                        vp.append(f"{base}: pool has {pool[key]} bytes, manifest {o['file_size']}")
                elif f"{key}.suspend" in pool:
                    vol["partial_bytes"] = pool[f"{key}.suspend"]
                    vp.append(f"{base}{' (' + vol['mount'] + ')' if vol['mount'] else ''}: stopped at "
                              f"{pool[key + '.suspend']} of {vol['capacity']} bytes")
                else:
                    vp.append(f"{base}{' (' + vol['mount'] + ')' if vol['mount'] else ''}: not in the pool")
                ver["volumes"].append(vol)
            elif o.get("file_size"):
                entry = files.get(base)
                if entry is None:
                    vp.append(f"{base}: missing")
                else:
                    try:
                        size = entry.stat().st_size
                    except OSError:
                        size = fs.file_size(fs.join(vdir, base))
                    if size is not None and size != o["file_size"]:
                        vp.append(f"{base}: {size} bytes on disk, manifest {o['file_size']}")
        ver["transferred_bytes"] = transferred
        ver["problems"] = vp
        problems += [f"{folder_name}: {p}" for p in vp]
        out_versions.append(ver)

    known = {v["folder_name"] for v in versions}
    for name, e in sorted(on_disk.items()):
        if _VERSION_DIR.match(name) and name not in known:
            problems.append(f"{name}: folder not in target.db")
    task["versions"] = out_versions
    task["problems"] = problems
    return task


class _View:
    """ActiveBackupData/: the pool's versions shown as image files."""
    name = "synology-abb-view"
    virtual = True      # the walker records the folder but does not descend

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return dir_name == "ActiveBackupData"

    def opaque(self, inner: str) -> bool:
        return True

    def summarize(self, path: str, names: set[str], fs: StoreFS = LOCAL) -> dict[str, Any]:
        tasks, versions, apparent = [], 0, 0
        for task, e in sorted(fs.listdir(path).items()):
            if not e.is_dir():
                continue
            vers = [n for n, v in fs.listdir(fs.join(path, task)).items() if v.is_dir()]
            for v in vers:
                for f in fs.listdir(fs.join(path, task, v)).values():
                    try:
                        apparent += f.stat().st_size
                    except OSError:
                        pass
            tasks.append(task)
            versions += len(vers)
        return {"format": self.name, "virtual": True, "tasks": tasks, "versions": versions,
                "apparent_bytes": apparent,
                "note": "virtual images of the @ActiveBackup versions; not walked, not disk space"}


FORMAT = _ActiveBackup()
VIEW = _View()
