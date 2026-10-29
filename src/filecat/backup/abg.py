"""Synology Active Backup for Google Workspace (Gmail, Calendar, Contacts, Drive).

Synology does not document the layout; this is read from a real task
(ABG 2.x, task-config version 13). Layout of a task folder::

    ActiveBackupForGoogleWorkspace/task_<n>/       <- the store root
        @ActiveBackupGSuite-Databases/
            task-config.sqlite     task_info_table: name, domain, admin, policy,
                                   retention (also an encrypted key: never copied)
            account.sqlite         user_info_table: one row per user with its
                                   folder name, status and used bytes per service
                                   (also an OAuth token: never copied)
            service-log.sqlite     one row per run, user and service that had work
            mail-log.sqlite ...    the text of each run's log line, per service
            <user id>/             per-user databases: mail.sqlite (mail_table),
                                   calendar-event.sqlite, contact.sqlite, ...;
                                   *-content-search/ (Lucene) and
            single-instancing.db/  (LevelDB) are opaque
        <user folder>/                                  (user_repo_name)
            Mail/<xx>/<yy>/<message id>/v<ver>-<k>-SKEL     the message without
                                                        its attachments (RFC 822)
                                    v<ver>-<k>-ATT_<n>  each attachment, decoded
                                    v<ver>-<k>-META     JSON: Gmail metadata, the
                                                        fragment list with sizes
                                                        and MD5s of attachments
            Calendar/<xx>/<yy>/<b64 calendar id>-<b64 event id>/v<ver>-<k>-META
                                   (the encoded name is cut into 64-character folders)
            Contact/<xx>/<yy>/<b64 contact id>/v<ver>-<k>-META
            MyDrive/<path>         the latest copy of every Drive file, by name
                    #SynoVersionRepo/<path>/#SynoVersions/GMT-<time>-v<n>[.metadata]
                                   every kept version, with a JSON sidecar
                                   holding Drive's md5Checksum
                    #SynoRepo/     LevelDB: Drive id to path (opaque)

Checks (the per-user databases are the manifest, the walk's listing is what
is on disk, so nothing beyond the databases is read):
- every message, event and contact version a database lists has its folder
  and its META fragment (and a message its SKEL);
- item folders on disk that no database lists;
- every MyDrive file has a version history whose latest version has its size;
- the latest run of each enabled user and service: a failure is reported
  with the log's own text.
With `scan --verify-backups` every META and Drive .metadata is read and each
fragment or version it names is checked for size and MD5.

Mail, Calendar, Contact and the version repositories are listed only; the
MyDrive files are the user's own files under their own names, so they are
read like any other. The format, as far as it is known, is in
docs/formats/synology-abg.md.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable

from .storefs import LOCAL, StoreFS, long_path
from .util import iso

DATABASES = "@ActiveBackupGSuite-Databases"
FOREVER = 4294967295            # end_time of a version still current in Google
SERVICES = {0: "drive", 1: "mail", 2: "contact", 3: "calendar"}
_LOGS = {0: ("file-log.sqlite", "file_log_table"), 1: ("mail-log.sqlite", "mail_log_table"),
         2: ("contact-log.sqlite", "contact_log_table"), 3: ("calendar-log.sqlite", "calendar_log_table")}
STATUS = {1: "succeeded", 5: "failed", 6: "partly failed"}
_ITEM_FOLDERS = ("Mail", "Calendar", "Contact")
_SYNO = ("#SynoVersionRepo", "#SynoRepo")
_FRAG = re.compile(r"^v(\d+)-(\d+)-(.+)$")
_VERSION = re.compile(r"^GMT-[\d.-]+-v(\d+)$")
_MAX_EXAMPLES = 3
_READ = 1 << 20


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


_long = long_path


def _relist(path: str, sub: str = "") -> dict[str, int]:
    """{inner path: size} of every file under the store, or under its
    folder `sub`, read with long paths."""
    base = _long(path)
    out: dict[str, int] = {}
    for dirpath, _dirs, files in os.walk(os.path.join(base, *sub.split("/")) if sub else base):
        rel = os.path.relpath(dirpath, base).replace(os.sep, "/")
        for f in files:
            try:
                out[f if rel == "." else f"{rel}/{f}"] = os.stat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return out


def _os_listing(path: str, fs: StoreFS = LOCAL) -> dict[str, int]:
    """The listing when the walker did not pass its own."""
    return _relist(path) if fs.local else fs.sizes(path)


def _md5(path: str, fs: StoreFS = LOCAL) -> str:
    h = hashlib.md5()
    with fs.open(fs.lpath(path), "rb") as f:
        while chunk := f.read(_READ):
            h.update(chunk)
    return h.hexdigest()


def _eg(items: Iterable[str]) -> str:
    items = list(items)
    return ", ".join(items[:_MAX_EXAMPLES]) + (", ..." if len(items) > _MAX_EXAMPLES else "")


class _Repo:
    """What the listing holds for one user folder."""

    def __init__(self) -> None:
        # service -> item key -> {(version, postfix): (inner path, size)}
        self.items: dict[str, dict[str, dict[tuple[int, str], tuple[str, int]]]] = {
            s: defaultdict(dict) for s in _ITEM_FOLDERS}
        self.drive: dict[str, int] = {}                      # MyDrive path -> size
        self.versions: dict[str, dict[str, tuple[str, int]]] = defaultdict(dict)  # path -> leaf -> (inner, size)
        self.bytes: dict[str, int] = defaultdict(int)        # Mail, ..., MyDrive, versions


def _index(on_disk: dict[str, int]) -> dict[str, _Repo]:
    repos: dict[str, _Repo] = defaultdict(_Repo)
    for inner, size in on_disk.items():
        parts = inner.split("/")
        if len(parts) < 3 or parts[0] == DATABASES:
            continue
        repo, svc = repos[parts[0]], parts[1]
        if svc in _ITEM_FOLDERS:
            repo.bytes[svc] += size
            m = _FRAG.match(parts[-1])
            if len(parts) >= 6 and m:
                key = "".join(parts[4:-1])
                repo.items[svc][key][(int(m.group(1)), m.group(3))] = (inner, size)
        elif svc == "MyDrive":
            rest = parts[2:]
            if rest[0] == "#SynoVersionRepo":
                repo.bytes["versions"] += size
                tail = "/".join(rest[1:])
                if "/#SynoVersions/" in tail:
                    item, leaf = tail.split("/#SynoVersions/", 1)
                    repo.versions[item][leaf] = (inner, size)
            elif rest[0] == "#SynoRepo":
                repo.bytes["versions"] += size
            else:
                repo.bytes["MyDrive"] += size
                repo.drive["/".join(rest)] = size
    for repo in repos.values():
        for svc in _ITEM_FOLDERS:
            repo.items[svc] = dict(repo.items[svc])
    return repos


def _key(svc: str, row: dict[str, Any]) -> str:
    if svc == "Mail":
        return row["mail_id"]
    if svc == "Calendar":
        return f"{_b64(row['calendar_id'])}-{_b64(row['event_id'])}"
    return _b64(row["contact_id"])


_ITEM_DB = {
    "Mail": ("mail.sqlite", "SELECT mail_id, version_number, start_time, end_time FROM mail_table"),
    "Calendar": ("calendar-event.sqlite",
                 "SELECT calendar_id, event_id, version_number, start_time, end_time FROM calendar_event_table"),
    "Contact": ("contact.sqlite", "SELECT contact_id, version_number, start_time, end_time FROM contact_table"),
}
_NEEDS = {"Mail": ("META", "SKEL"), "Calendar": ("META",), "Contact": ("META",)}


class _GoogleWorkspace:
    name = "synology-abg"
    uses_listing = True     # summarize() takes the walk's listing of the store
    verifies = True         # and with --verify-backups reads META and .metadata files

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return DATABASES in names

    def opaque(self, inner: str) -> bool:
        parts = inner.split("/")
        if parts[0] == DATABASES:
            return not inner.endswith(".sqlite")
        if len(parts) > 2 and parts[1] in _ITEM_FOLDERS:
            return True
        return any(p in _SYNO for p in parts[1:-1])

    def summarize(self, path: str, names: set[str],
                  listing: Callable[[], dict[str, int]] | None = None,
                  verify: bool = False, fs: StoreFS = LOCAL) -> dict[str, Any]:
        db = fs.join(path, DATABASES)
        problems: list[str] = []

        def rows(rel: str, sql: str) -> list[dict[str, Any]] | None:
            try:
                return fs.sqlite_rows(fs.join(db, rel), sql)
            except Exception as e:
                problems.append(f"{rel} unreadable: {type(e).__name__}: {e}")
                return None

        task = (rows("task-config.sqlite",
                     "SELECT task_id, timestamp, task_name, backup_policy, enable_schedule, enable_dedup,"
                     " retention_policy, retention_days, admin_unique_id, admin_primary_email, domain"
                     " FROM task_info_table") or [{}])[0]
        accounts = rows("account.sqlite",
                        "SELECT user_id, name, email, account_status, user_repo_name, local_used_storage,"
                        " drive_used_storage, mail_used_storage, contact_used_storage, calendar_used_storage,"
                        " enable_drive, enable_mail, enable_contact, enable_calendar FROM user_info_table") or []
        runs = rows("service-log.sqlite",
                    "SELECT count(DISTINCT task_execution_id) AS runs, min(start_run_time) AS first,"
                    " max(end_run_time) AS last FROM service_log_table") or [{}]
        latest = rows("service-log.sqlite",
                      "SELECT s.user_id, s.service_type, s.execution_status, s.error_code, s.end_run_time,"
                      " s.task_execution_id, (SELECT max(x.end_run_time) FROM service_log_table x"
                      "  WHERE x.user_id = s.user_id AND x.service_type = s.service_type"
                      "  AND x.execution_status = 1) AS last_ok"
                      " FROM service_log_table s JOIN (SELECT max(row_id) AS r FROM service_log_table"
                      "  GROUP BY user_id, service_type) l ON s.row_id = l.r") or []

        domain = task.get("domain")
        out: dict[str, Any] = {
            "format": self.name, "task": task.get("task_name"), "task_id": task.get("task_id"),
            "domain": domain, "admin": task.get("admin_primary_email"),
            "created": iso(task.get("timestamp")), "backup_policy": task.get("backup_policy"),
            "scheduled": bool(task.get("enable_schedule")), "dedup": bool(task.get("enable_dedup")),
            "retention_policy": task.get("retention_policy"), "retention_days": task.get("retention_days"),
            "machines": [domain] if domain else [],
            "versions": runs[0].get("runs") or 0,
            "first": iso(runs[0].get("first")), "latest": iso(runs[0].get("last")),
        }

        last_run: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        for r in latest:
            svc = SERVICES.get(r["service_type"], str(r["service_type"]))
            last_run[r["user_id"]][svc] = r

        on_disk = listing() if listing else _os_listing(path, fs)
        repos = _index(on_disk)
        users, totals = [], defaultdict(int)
        known_repos = set()
        for a in sorted(accounts, key=lambda a: a["email"].lower()):
            known_repos.add(a["user_repo_name"])
            u, up = self._user(db, a, repos.get(a["user_repo_name"]), last_run.get(a["user_id"], {}), path,
                               verify, fs)
            users.append(u)
            problems += [f"{a['email']}: {p}" for p in up]
            for k, v in u["files"].items():
                totals[k] += v
        stray = sorted(r for r in repos if r not in known_repos)
        if stray:
            problems.append(f"{len(stray)} user folders are not in account.sqlite: {_eg(stray)}")

        out["users"] = users
        out["user_count"] = len(users)
        out["removed_users"] = [u["email"] for u in users if u["status"] != 1]
        out["items"] = {k: sum(u["items"].get(k, 0) for u in users)
                        for k in ("mail", "mail_deleted", "calendar", "contacts", "drive_files", "drive_versions")}
        out["storage"] = {
            "used_bytes": sum(a["local_used_storage"] or 0 for a in accounts),
            "on_disk_bytes": sum(on_disk.values()),
            "by_service": {k: sum(r.bytes.get(k, 0) for r in repos.values())
                           for k in ("Mail", "Calendar", "Contact", "MyDrive", "versions")},
        }
        out["files"] = dict(totals)
        if verify:
            out["verified"] = {k: sum(u.get("verified", {}).get(k, 0) for u in users)
                               for k in ("files", "bad")}
        out["problems"] = problems
        if domain and task.get("task_id") is not None:
            out["copy_keys"] = [f"abg-task:{task.get('admin_unique_id')}:{task['task_id']}:{task.get('timestamp')}"]
        out["machine_keys"] = [f"google-workspace:{domain.lower()}"] if domain else []
        return out

    def _user(self, db: str, a: dict[str, Any], repo: _Repo | None, runs: dict[str, dict[str, Any]],
              path: str, verify: bool, fs: StoreFS = LOCAL) -> tuple[dict[str, Any], list[str]]:
        problems: list[str] = []
        u: dict[str, Any] = {
            "email": a["email"], "name": a["name"], "folder": a["user_repo_name"], "status": a["account_status"],
            "used_bytes": a["local_used_storage"],
            "used": {s: a[f"{s}_used_storage"] for s in ("drive", "mail", "contact", "calendar")},
            "enabled": [s for s in ("drive", "mail", "contact", "calendar") if a[f"enable_{s}"]],
        }
        files = {"missing": 0, "incomplete": 0, "unlisted": 0, "size_mismatch": 0, "after_listing": 0}
        items: dict[str, int] = {}
        if repo is None:
            repo = _Repo()
            if a["local_used_storage"]:
                problems.append(f"folder {a['user_repo_name']} is missing")

        udb = fs.join(db, a["user_id"])
        for svc, (rel, sql) in _ITEM_DB.items():
            try:
                rows = fs.sqlite_rows(fs.join(udb, rel), sql) if fs.isfile(fs.join(udb, rel)) else []
            except Exception as e:
                problems.append(f"{rel} unreadable: {type(e).__name__}: {e}")
                continue
            folder = a["user_repo_name"]
            missing, incomplete, unlisted, later = self._compare(svc, rows, repo.items[svc])
            if fs.local and os.name == "nt" and any(self._too_long(path, folder, svc, _key(svc, r)) for r in missing):
                # a walk without long paths cannot open folders past 260
                # characters: list this service again before calling them missing
                again = _index(_relist(path, f"{folder}/{svc}")).get(folder)
                if again is not None:
                    repo.items[svc] = again.items[svc]
                    missing, incomplete, unlisted, later = self._compare(svc, rows, repo.items[svc])
            missing = [f"{_key(svc, r)} v{r['version_number']}" for r in missing]
            files["after_listing"] += len(later)
            name = {"Mail": "messages", "Calendar": "calendar events", "Contact": "contacts"}[svc]
            if missing:
                problems.append(f"{len(missing)} of {len(rows)} {name} in {rel} have no files: {_eg(missing)}")
            if incomplete:
                problems.append(f"{len(incomplete)} {name} lack their SKEL fragment: {_eg(incomplete)}")
            if unlisted:
                problems.append(f"{len(unlisted)} {name} folders are not in {rel}: {_eg(unlisted)}")
            files["missing"] += len(missing)
            files["incomplete"] += len(incomplete)
            files["unlisted"] += len(unlisted)
            if svc == "Mail":
                items["mail"] = len(rows)
                items["mail_deleted"] = sum(1 for r in rows if r["end_time"] != FOREVER)
            else:
                items["calendar" if svc == "Calendar" else "contacts"] = len(rows)

        no_history, differ = [], []
        for item, size in repo.drive.items():
            vers = repo.versions.get(item)
            data = sorted(((int(m.group(1)), leaf) for leaf in vers or ()
                           if (m := _VERSION.match(leaf))), reverse=True)
            if not data:
                no_history.append(item)
            elif vers[data[0][1]][1] != size:
                differ.append(f"{item} ({size} bytes, latest version {vers[data[0][1]][1]})")
        if no_history:
            problems.append(f"{len(no_history)} MyDrive files have no version in #SynoVersionRepo: "
                            f"{_eg(sorted(no_history))}")
        if differ:
            problems.append(f"{len(differ)} MyDrive files differ in size from their latest version: "
                            f"{_eg(sorted(differ))}")
        files["missing"] += len(no_history)
        files["size_mismatch"] += len(differ)
        items["drive_files"] = len(repo.drive)
        items["drive_deleted"] = sum(1 for i, v in repo.versions.items()
                                     if i not in repo.drive and any(_VERSION.match(x) for x in v))
        items["drive_versions"] = sum(1 for v in repo.versions.values() for x in v if _VERSION.match(x))

        u["items"] = items
        u["files"] = files
        u["on_disk"] = dict(repo.bytes)
        u["last_run"] = {svc: {"end": iso(r["end_run_time"]),
                               "status": STATUS.get(r["execution_status"], f"status {r['execution_status']}"),
                               "last_ok": iso(r["last_ok"])}
                         for svc, r in sorted(runs.items())}
        if a["account_status"] == 1:
            for svc, r in sorted(runs.items()):
                if r["execution_status"] != 1 and svc in u["enabled"]:
                    text = self._log_text(db, r, fs)
                    problems.append(f"{svc}: last run {iso(r['end_run_time'])} "
                                    f"{STATUS.get(r['execution_status'], 'status ' + str(r['execution_status']))}"
                                    + (f": {text}" if text else f" (error {r['error_code']})")
                                    + (f"; last success {iso(r['last_ok'])}" if r["last_ok"] else "; never succeeded"))
        if verify:
            u["verified"] = self._verify(path, a["user_repo_name"], repo, problems, fs)
        return u, problems

    @staticmethod
    def _compare(svc: str, rows: list[dict[str, Any]],
                 have: dict[str, dict[tuple[int, str], tuple[str, int]]]
                 ) -> tuple[list[dict[str, Any]], list[str], list[str], list[dict[str, Any]]]:
        """(rows with no META, versions lacking another needed fragment,
        item folders no row names, rows backed up after the listing) of one
        service. A live task keeps backing up while a long walk lists it, so
        a missing row newer than every row that was found is counted as
        later than the listing, not as missing."""
        missing, incomplete, listed, newest = [], [], set(), 0
        for r in rows:
            key, ver = _key(svc, r), r["version_number"]
            listed.add(key)
            frags = have.get(key)
            if frags is None or (ver, "META") not in frags:
                missing.append(r)
            else:
                newest = max(newest, r["start_time"] or 0)
                if any((ver, need) not in frags for need in _NEEDS[svc]):
                    incomplete.append(f"{key} v{ver}")
        later = [r for r in missing if (r["start_time"] or 0) > newest]
        missing = [r for r in missing if (r["start_time"] or 0) <= newest]
        return missing, incomplete, sorted(k for k in have if k not in listed), later

    @staticmethod
    def _too_long(path: str, folder: str, svc: str, key: str) -> bool:
        """Is the item's META further than MAX_PATH from the drive (the
        bucket folders are 2 characters each, the name is cut every 64)?"""
        return len(path) + len(folder) + len(svc) + len(key) + len(key) // 64 + 22 >= 260

    @staticmethod
    def _log_text(db: str, run: dict[str, Any], fs: StoreFS = LOCAL) -> str | None:
        rel, table = _LOGS.get(run["service_type"], (None, None))
        if not rel:
            return None
        try:
            got = fs.sqlite_rows(fs.join(db, rel),
                              f"SELECT descript_string FROM {table} WHERE task_execution_id = ? AND user_id = ?"
                              " ORDER BY row_id DESC LIMIT 1", (run["task_execution_id"], run["user_id"]))
        except Exception:
            return None
        return got[0]["descript_string"] if got else None

    @staticmethod
    def _verify(path: str, folder: str, repo: _Repo, problems: list[str],
                fs: StoreFS = LOCAL) -> dict[str, int]:
        """Read every META and .metadata the listing holds and check the
        fragments and versions they name: present, of that size, same MD5."""
        jobs: list[tuple[str, str, int]] = []      # (kind, inner path of the sidecar, version)
        for svc in _ITEM_FOLDERS:
            for frags in repo.items[svc].values():
                for (ver, post), (inner, _size) in frags.items():
                    if post == "META":
                        jobs.append((svc, inner, ver))
        for vers in repo.versions.values():
            for leaf, (inner, _size) in vers.items():
                if leaf.endswith(".metadata") and _VERSION.match(leaf[:-9]):
                    jobs.append(("Drive", inner, 0))
        sizes = {p: s for frags in (f for svc in _ITEM_FOLDERS for f in repo.items[svc].values())
                 for (p, s) in frags.values()}
        sizes.update({p: s for vers in repo.versions.values() for (p, s) in vers.values()})
        cut = len(folder) + 1       # messages name paths within the user's folder

        def check(job: tuple[str, str, int]) -> list[str]:
            kind, inner, ver = job
            full = fs.lpath(fs.join(path, *inner.split("/")))
            try:
                with fs.open(full, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except (OSError, ValueError) as e:
                return [f"{inner[cut:]}: unreadable ({type(e).__name__})"]
            folder = inner.rsplit("/", 1)[0]
            bad = []
            if kind == "Drive":
                # a folder's version is a -DIR marker with no content to check
                targets = [] if meta.get("is_dir") else [(inner[:-9], meta.get("size"), meta.get("hash"))]
            else:
                targets = [(f"{folder}/v{ver}-{i}-{c.get('path_postfix')}", c.get("size"), c.get("hash"))
                           for i, c in enumerate(meta.get("content_list") or [], 1)]
            for target, size, digest in targets:
                if target not in sizes:
                    bad.append(f"{target[cut:]}: missing")
                    continue
                if size not in (None, "") and int(size) != sizes[target]:
                    bad.append(f"{target[cut:]}: {sizes[target]} bytes, metadata {size}")
                    continue
                if digest:
                    try:
                        if _md5(fs.join(path, *target.split("/")), fs) != digest.lower():
                            bad.append(f"{target[cut:]}: MD5 differs")
                    except OSError as e:
                        bad.append(f"{target[cut:]}: unreadable ({type(e).__name__})")
            return bad

        bad: list[str] = []
        with ThreadPoolExecutor(8) as pool:
            for got in pool.map(check, jobs):
                bad += got
        if bad:
            bad.sort()      # the order the threads finished in is no order at all
            problems.append(f"{len(bad)} files fail their metadata's size or MD5: {_eg(bad)}")
        return {"files": len(jobs), "bad": len(bad)}


FORMAT = _GoogleWorkspace()
