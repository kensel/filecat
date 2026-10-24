"""Thunderbird profile copies made by ImportExportTools NG's profile backup.

The add-on (src/chrome/content/mboximport/autobackup.js) copies the whole
profile, or only its mail, file by file into a new folder per run::

    <backup dir>/
        <profile with . as _>-<yyyymmdd>-<hhmm>/   <- the store root, one per run
            Backup.log            "Backup date: <local time>", then every saved
                                  file by its original path, one per line, and
                                  "***Error with file <path>" for each failure
            ExternalMailFolders/  accounts stored outside the profile, by
                                  their folder name (always created)
            prefs.js, ImapMail/, Mail/, global-messages-db.sqlite, ...
                                  the profile as it was, as plain files

Mail is kept per account (prefs.js mail.server.serverN: directory-rel
"[ProfD]ImapMail/<host>" or "[ProfD]Mail/<name>", storeContractID), each
account in one of two stores, and one profile can mix them:

    mbox (berkeleystore, the old default)   maildir (maildirstore)
    <folder>       all its messages          <folder>/cur/<msg>.eml   one file each
    <folder>.msf   the folder's index        <folder>.msf             the index
    <folder>.sbd/  its subfolders            <folder>.sbd/            its subfolders

.msf files are Mork indexes Thunderbird rebuilds from the messages. The add-on
copies both stores the same way, file by file, so a copy's mail is counted
from the listing alone: mbox folders and bytes, maildir message files.

It keeps the newest N runs (retainNumBackups) and removes older folders. With
a fixed custom folder name it copies only files changed since the last run
into one folder instead, so the log then lists just those.

Every file is a plain copy of a profile file, so the copies are near
duplicates of each other and of the live profile: all of it is listed only,
except Backup.log and the small files the summary reads.

Checks (Backup.log is the manifest; it has no sizes or checksums):
- every file the log saved is in the walk's listing of the copy;
- files in a dated copy that the log does not name;
- the log's own copy errors.
The log has no end marker, so a run cut short looks like a smaller backup.
"""
from __future__ import annotations

import configparser
import os
import re
from datetime import datetime
from typing import Any, Callable

from .storefs import LOCAL, StoreFS

READ = ("Backup.log", "prefs.js", "compatibility.ini", "times.json")
_DATED = re.compile(r"^(?P<profile>.+)-(?P<date>\d{8})-(?P<time>\d{4})$")
_MAILDIR = re.compile(r"^\d+\.M\d+P\d+Q\d+\.(?P<host>[^.]+)(\.eml)?$")
_DATE_FORMATS = ("%m/%d/%Y, %I:%M:%S %p", "%d/%m/%Y, %H:%M:%S", "%d.%m.%Y, %H:%M:%S",
                 "%Y-%m-%d, %H:%M:%S", "%Y/%m/%d %H:%M:%S")
_MAX_EXAMPLES = 3


def _eg(items: list[str]) -> str:
    return ", ".join(items[:_MAX_EXAMPLES]) + (", ..." if len(items) > _MAX_EXAMPLES else "")


def _local_time(text: str) -> str | None:
    """The log's date (JavaScript toLocaleString, in the writer's locale) as
    a naive ISO time; None when the locale is not one of the common ones."""
    text = text.replace(" ", " ").strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).isoformat()
        except ValueError:
            pass
    return None


def read_log(path: str, fs: StoreFS = LOCAL) -> dict[str, Any]:
    """{"date": raw text, "saved": [original paths], "errors": [paths or messages]}."""
    out: dict[str, Any] = {"date": None, "saved": [], "errors": []}
    pending_error = False
    with fs.open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if out["date"] is None and line.startswith("Backup date: "):
                out["date"] = line[len("Backup date: "):]
            elif line.startswith("***Error with file "):
                out["errors"].append(line[len("***Error with file "):])
                pending_error = True
            elif line.startswith("***Error"):
                out["errors"].append(line.lstrip("*").strip())
            elif pending_error and line.startswith("Error Type: "):
                pending_error = False
            elif line and (line[1:3] == ":\\" or line.startswith(("\\\\", "/"))):
                out["saved"].append(line)
    return out


_PREF = re.compile(r'^user_pref\("mail\.server\.(server\d+)\.(type|hostname|name|storeContractID|'
                   r'directory-rel|directory)",\s*"((?:[^"\\]|\\.)*)"\);', re.M)
_DEFAULT_STORE = re.compile(r'^user_pref\("mail\.serverDefaultStoreContractID",\s*"([^"]*)"\);', re.M)
STORES = {"@mozilla.org/msgstore/berkeleystore;1": "mbox", "@mozilla.org/msgstore/maildirstore;1": "maildir"}
_NOT_MBOX = (".msf", ".dat", ".json", ".html", ".sqlite", ".log", ".txt", ".js")


def read_accounts(prefs_text: str) -> list[dict[str, Any]]:
    """Each mail account's server from prefs.js: name, type, host, its
    folder (relative to the profile, or absolute when kept outside it) and
    its message store (mbox: one file per folder; maildir: one per message).
    An account with no storeContractID uses Thunderbird's default, mbox
    unless mail.serverDefaultStoreContractID says otherwise."""
    servers: dict[str, dict[str, str]] = {}
    for sid, key, value in _PREF.findall(prefs_text):
        servers.setdefault(sid, {})[key] = value.replace("\\\\", "\\").replace('\\"', '"')
    m = _DEFAULT_STORE.search(prefs_text)
    default = STORES.get(m.group(1), "mbox") if m else "mbox"
    out = []
    for sid, s in sorted(servers.items(), key=lambda kv: int(kv[0][6:])):
        rel = s.get("directory-rel", "")
        folder = rel[len("[ProfD]"):] if rel.startswith("[ProfD]") else None
        out.append({"server": sid, "name": s.get("name"), "type": s.get("type"), "host": s.get("hostname"),
                    "folder": folder.replace("\\", "/") if folder else None,
                    "external": None if folder else (s.get("directory") or rel or None),
                    "store": STORES.get(s.get("storeContractID", ""), default if "storeContractID" not in s
                                        else s["storeContractID"])})
    return out


def _mail_counts(files: dict[str, int], prefix: str) -> dict[str, int]:
    """Folders and messages under one account's folder, from the listing:
    maildir messages are files in cur/ or new/; an mbox folder is a file with
    no extension beside its .msf index (an .msf alone is a folder never
    downloaded, or empty)."""
    out = {"files": 0, "bytes": 0, "maildir_messages": 0, "mbox_folders": 0, "mbox_bytes": 0, "indexes": 0}
    names = {p for p in files if p.startswith(prefix)}
    for p in names:
        size = files[p]
        out["files"] += 1
        out["bytes"] += size
        parent, _, leaf = p.rpartition("/")
        if parent.endswith(("/cur", "/new")):
            out["maildir_messages"] += 1
        elif leaf.endswith(".msf"):
            out["indexes"] += 1
        elif not leaf.lower().endswith(_NOT_MBOX) and f"{p}.msf" in names and not parent.endswith("/tmp"):
            out["mbox_folders"] += 1
            out["mbox_bytes"] += size
    return out


def _split(path: str) -> list[str]:
    return [p for p in re.split(r"[\\/]", path) if p]


def _os_listing(path: str, fs: StoreFS = LOCAL) -> dict[str, int]:
    if not fs.local:
        return fs.sizes(path)
    out: dict[str, int] = {}
    for dirpath, _dirs, files in os.walk(path):
        rel = os.path.relpath(dirpath, path).replace(os.sep, "/")
        for f in files:
            try:
                out[f if rel == "." else f"{rel}/{f}"] = os.stat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return out


class _ProfileBackup:
    name = "thunderbird-ietng"
    uses_listing = True     # summarize() takes the walk's listing of the copy

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return "Backup.log" in names and "ExternalMailFolders" in names

    def opaque(self, inner: str) -> bool:
        return inner not in READ

    def summarize(self, path: str, names: set[str],
                  listing: Callable[[], dict[str, int]] | None = None,
                  fs: StoreFS = LOCAL) -> dict[str, Any]:
        folder = fs.basename(path)
        dated = _DATED.match(folder)
        log = read_log(fs.join(path, "Backup.log"), fs)
        problems: list[str] = []
        out: dict[str, Any] = {"format": self.name, "made_by": "ImportExportTools NG",
                               "mode": "dated folder per run" if dated else "one folder, changed files only",
                               "backup_date": log["date"]}

        # the profile folder is the saved path component whose dots-as-underscores
        # name the copy (the add-on names it so); without that, the most common parent
        profile_dir = None
        if dated:
            base = dated.group("profile")
            for p in log["saved"][:50]:
                parts = _split(p)
                for i, part in enumerate(parts):
                    if part.replace(".", "_") == base:
                        profile_dir = parts[:i + 1]
                        break
                if profile_dir:
                    break
        if profile_dir is None and log["saved"]:
            profile_dir = _split(log["saved"][0])[:-1]
        if profile_dir:
            out["profile"] = profile_dir[-1]
            out["source_path"] = "\\".join(profile_dir) if log["saved"][0][1:3] == ":\\" else "/".join(profile_dir)
            if len(profile_dir) > 2 and profile_dir[1].lower() == "users":
                out["user"] = profile_dir[2]

        when = _local_time(log["date"] or "")
        if when is None and dated:
            d, t = dated.group("date"), dated.group("time")
            when = f"{d[:4]}-{d[4:6]}-{d[6:]}T{t[:2]}:{t[2:]}:00"
        out["latest"] = when
        out["versions"] = 1

        try:
            cp = configparser.ConfigParser(interpolation=None)
            try:
                with fs.open(fs.join(path, "compatibility.ini"), "r", encoding="utf-8") as f:
                    cp.read_file(f)
            except OSError:
                pass        # a copy without one, as ConfigParser.read
            version = cp.get("Compatibility", "LastVersion", fallback=None)
            out["thunderbird_version"] = version.split("_", 1)[0] if version else None
        except (OSError, configparser.Error):
            pass

        on_disk = listing() if listing else _os_listing(path, fs)
        logged: set[str] = set()
        external = {p for p in on_disk if p.startswith("ExternalMailFolders/")}
        missing = []
        n = len(profile_dir or [])
        for p in log["saved"]:
            parts = _split(p)
            if profile_dir and parts[:n] == profile_dir:
                inner = "/".join(parts[n:])
            else:
                # an account outside the profile: copied to ExternalMailFolders/<its folder>/...
                inner = next((c for k in range(len(parts) - 1)
                              if (c := "ExternalMailFolders/" + "/".join(parts[k:])) in external), None)
                if inner is None:
                    missing.append(p)
                    continue
            logged.add(inner)
            if inner not in on_disk:
                missing.append(inner)
        unlisted = sorted(p for p in on_disk if p not in logged and p != "Backup.log") if dated else []

        # accounts: from prefs.js when the copy has it (a mail-only run does not),
        # else one per folder under ImapMail/, Mail/ and ExternalMailFolders/
        try:
            with fs.open(fs.join(path, "prefs.js"), "r", encoding="utf-8", errors="replace") as f:
                accounts = read_accounts(f.read())
        except OSError:
            accounts = []
        if not accounts:
            accounts = [{"name": d, "folder": d, "store": None} for d in sorted(
                {"/".join(p.split("/")[:2]) for p in on_disk
                 if p.startswith(("ImapMail/", "Mail/", "ExternalMailFolders/")) and p.count("/") >= 2})]
        for a in accounts:
            prefix = (f"{a['folder']}/" if a.get("folder") else
                      f"ExternalMailFolders/{_split(a['external'])[-1]}/" if a.get("external") else None)
            if prefix:
                counts = _mail_counts(on_disk, prefix)
                a.update(counts)
                if a.get("store") is None and counts["files"]:
                    a["store"] = "maildir" if counts["maildir_messages"] else "mbox"
                if not counts["files"] and a.get("external"):
                    problems.append(f"account {a.get('name')}: its folder outside the profile "
                                    f"({a['external']}) is not in ExternalMailFolders")
        hosts: dict[str, int] = {}
        for p in on_disk:
            if ("/cur/" in p or "/new/" in p) and len(hosts) < 20:
                m = _MAILDIR.match(p.rsplit("/", 1)[-1])
                if m:
                    hosts[m.group("host")] = hosts.get(m.group("host"), 0) + 1
        host = max(hosts, key=hosts.get) if hosts else None
        out["host"] = host
        out["machines"] = [host] if host else ([out["profile"]] if out.get("profile") else [])
        out["accounts"] = accounts
        out["mail"] = {k: sum(a.get(k, 0) for a in accounts)
                       for k in ("bytes", "maildir_messages", "mbox_folders", "mbox_bytes")}
        out["mail"]["stores"] = sorted({a["store"] for a in accounts if a.get("store")})
        out["storage"] = {"files": len(on_disk), "bytes": sum(on_disk.values())}
        out["files"] = {"logged": len(log["saved"]), "missing": len(missing), "unlisted": len(unlisted),
                        "copy_errors": len(log["errors"])}
        out["copy_errors"] = log["errors"][:20]
        if not log["date"]:
            problems.append("Backup.log has no 'Backup date:' line")
        if missing:
            problems.append(f"{len(missing)} of {len(log['saved'])} files Backup.log saved are not in the copy: "
                            f"{_eg(missing)}")
        if unlisted:
            problems.append(f"{len(unlisted)} files in the copy are not in Backup.log: {_eg(unlisted)}")
        if log["errors"]:
            cut = len(out.get("source_path") or "") + 1
            errs = [e[cut:] if out.get("source_path") and e.startswith(out["source_path"]) else e
                    for e in log["errors"]]
            problems.append(f"{len(errs)} files could not be copied: {_eg(errs)}")
        out["problems"] = problems
        if out.get("profile") and when:
            out["copy_keys"] = [f"tb-profile-backup:{out['profile'].lower()}:{when}"]
        out["machine_keys"] = sorted({f"host:{host.lower()}"} if host else set()) + (
            [f"thunderbird-profile:{out['profile'].lower()}"] if out.get("profile") else [])
        return out


FORMAT = _ProfileBackup()
