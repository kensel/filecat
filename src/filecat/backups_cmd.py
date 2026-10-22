"""`filecat backups`: the backup stores scans have recognised (backup/).

One block per store -- format, machines, versions, storage figures and the
problems found against its manifest -- then two groupings across every
store in the catalog:

- copies: stores sharing a copy key (a version UUID, a set's timestamps)
  hold the same backed-up data, e.g. a backup folder copied to another
  share or into an old-drives folder;
- separate jobs: stores sharing a machine key (device UUID, host name) but
  no copy key back up the same computer independently. Each keeps its own
  full copy, since deduplication never spans two stores.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterator

from .backends import open_backend
from .record import join_root
from .summary import _human_bytes


def stores(backend: Any, roots: list[str] | None = None) -> Iterator[dict[str, Any]]:
    """{"root", "rel_path", "path", "backup"} for every store folder record."""
    for root in roots or backend.roots():
        for d in backend.list(kind="dir", root=root):
            b = (d.get("probe") or {}).get("backup")
            if b:
                yield {"root": d["root"], "rel_path": d["rel_path"],
                       "path": join_root(d["root"], d["rel_path"]), "backup": b,
                       "errors": d.get("errors") or []}


def _when(iso: str | None) -> str:
    return (iso or "?").replace("T", " ")[:16]


def _abb_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    out = []
    s = b.get("storage") or {}
    if s:
        out.append(f"  storage   backed up {_human_bytes(s.get('backed_up_bytes', 0))}, stored "
                   f"{_human_bytes(s.get('usage_bytes', 0))} (dedup saved "
                   f"{_human_bytes(s.get('dedup_saved_bytes', 0))}, compression saved "
                   f"{_human_bytes(s.get('compression_saved_bytes', 0))})"
                   + (f", {s['reduction_ratio']}x" if s.get("reduction_ratio") else ""))
    for t in b.get("tasks", []):
        vers = t.get("versions", [])
        out.append(f"  {t.get('machine') or '?'}  task {t.get('task')}  {t.get('os') or ''}  "
                   f"{len(vers)} versions, {_human_bytes(t.get('backed_up_bytes', 0))} backed up")
        for v in vers if all_versions else vers[-1:]:
            vols = ", ".join(f"{x.get('mount') or x['image']} {_human_bytes(x.get('capacity') or 0)}"
                             for x in v.get("volumes", []))
            out.append(f"    {_when(v.get('start'))}  {v.get('status'):<10} "
                       f"{'full' if v.get('full') else 'incr'}  sent "
                       f"{_human_bytes(v.get('transferred_bytes', 0))}  [{vols}]")
    return out


def _winbackup_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    out = []
    for s in b.get("sets", []):
        out.append(f"  {s['folder']}  {_human_bytes(s.get('bytes', 0))}")
        for p in s.get("parts", []) if all_versions else s.get("parts", [])[-1:]:
            out.append(f"    {_when(p.get('time'))}  {p['zips']} zips  {_human_bytes(p.get('bytes', 0))}")
    return out


def _wib_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    imgs = b.get("images", [])
    return [f"  {_when(v.get('time'))}  {len(v.get('disks', []))} disk images  "
            f"{_human_bytes(v.get('bytes', 0))}" + (f"  OS {v['os_version']}" if v.get("os_version") else "")
            for v in (imgs if all_versions else imgs[-1:])]


def _duplicity_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    out = [f"  chain {_when(c['start'])} -> {_when(c['end'])}  {c['sets']} sets" for c in b.get("chains", [])]
    if all_versions:
        out += [f"    {s['type']:<4} {_when(s['end'])}  {s['volume_count']} volumes  "
                f"{_human_bytes(s.get('bytes', 0))}" + ("  encrypted" if s.get("encrypted") else "")
                for s in b.get("sets", [])]
    return out


def _hbk_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    out = [f"  task      {b.get('task') or '?'} from {b.get('source_host') or '?'}"
           + (f" ({b['source_model']})" if b.get("source_model") else "")
           + f": {', '.join(b.get('folders') or []) or 'no folders'}"
           + (f" + {len(b['apps'])} apps" if b.get("apps") else "")
           + ("  encrypted" if b.get("encrypted") else "")]
    s = b.get("storage") or {}
    if s:
        out.append(f"  storage   source {_human_bytes(s.get('source_bytes') or 0)}, target "
                   f"{_human_bytes(s.get('target_bytes') or s.get('stored_bytes') or 0)}"
                   + (f", {s['reduction_ratio']}x" if s.get("reduction_ratio") else ""))
    g = b.get("guard")
    if g:
        out.append(f"  guard     {g['files']} files in the manifest, {g.get('missing', 0)} missing, "
                   f"{g.get('size_mismatch', 0)} differ in size" + (f"  ({g['state']})" if g.get("state") else ""))
    c = b.get("integrity_check")
    if c and c.get("end"):
        checked = (f", checked {_human_bytes(c['checked_bytes'])}" if c.get("checked_bytes") else "")
        out.append(f"  checked   {_when(c.get('start'))} -> {_when(c.get('end'))}{checked}, "
                   f"{len(c.get('errors') or [])} errors")
    vers = b.get("version_list", [])
    for v in vers if all_versions else vers[-1:]:
        out.append(f"    {_when(v.get('start'))}  #{v['id']:<5} {v.get('status') or '?':<10} "
                   f"{_human_bytes(v.get('source_bytes') or 0)} in {v.get('files') or 0} files"
                   + ("  locked" if v.get("locked") else ""))
    return out


def _veeam_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    out = [f"  job       {b.get('job') or '?'}" + (f" ({b['os']})" if b.get("os") else "")
           + (f", written to {b['written_to']}" if b.get("written_to") else "")
           + ("  encrypted" if b.get("encrypted") else "")]
    s, f = b.get("storage") or {}, b.get("files") or {}
    out.append(f"  storage   {f.get('listed', 0)} files ({b.get('fulls', 0)} full) of "
               f"{_human_bytes(s.get('backup_bytes') or 0)} in the .vbm, "
               f"{_human_bytes(s.get('on_disk_bytes') or 0)} of backup files on disk, "
               f"{_human_bytes(s.get('data_bytes') or 0)} read from the source")
    out.append(f"  files     {f.get('missing', 0)} missing, {f.get('size_mismatch', 0)} differ in size, "
               f"{f.get('unlisted', 0)} not in the .vbm")
    if "verified" in b:
        bad = sum(1 for v in b["verified"] if v.get("banks_bad") or "eof" not in v)
        out.append(f"  verified  {len(b['verified'])} files' own metadata, {bad} failed")
    pts = b.get("points", [])
    for p in pts if all_versions else pts[-1:]:
        out.append(f"    {_when(p.get('created'))}  {p['type']:<9} {_human_bytes(p.get('backup_bytes') or 0):>9}  "
                   f"{p['file']}" + ("  corrupt" if p.get("corrupt") else "")
                   + ("" if p.get("on_disk", True) else "  missing"))
    return out


def _abg_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    removed = len(b.get("removed_users") or [])
    out = [f"  task      {b.get('task') or '?'} for {b.get('domain') or '?'}"
           + (f" (admin {b['admin']})" if b.get("admin") else "")
           + f", {b.get('user_count', 0)} users" + (f" ({removed} removed)" if removed else "")
           + f", {b.get('versions', 0)} runs since {_when(b.get('first'))}"]
    s, i, f = b.get("storage") or {}, b.get("items") or {}, b.get("files") or {}
    by = s.get("by_service") or {}
    out.append(f"  storage   {_human_bytes(s.get('used_bytes') or 0)} used by ABG's count, "
               f"{_human_bytes(s.get('on_disk_bytes') or 0)} on disk: mail {_human_bytes(by.get('Mail') or 0)}, "
               f"Drive {_human_bytes(by.get('MyDrive') or 0)} + {_human_bytes(by.get('versions') or 0)} "
               f"of versions, calendar {_human_bytes(by.get('Calendar') or 0)}, "
               f"contacts {_human_bytes(by.get('Contact') or 0)}")
    out.append(f"  items     {i.get('mail', 0)} messages ({i.get('mail_deleted', 0)} deleted in Google, kept), "
               f"{i.get('calendar', 0)} events, {i.get('contacts', 0)} contacts, "
               f"{i.get('drive_files', 0)} Drive files ({i.get('drive_versions', 0)} versions)")
    out.append(f"  files     {f.get('missing', 0)} missing, {f.get('incomplete', 0)} incomplete, "
               f"{f.get('unlisted', 0)} not in the databases, {f.get('size_mismatch', 0)} differ in size"
               + (f" ({f['after_listing']} backed up after the scan listed them)" if f.get("after_listing") else ""))
    if b.get("verified"):
        v = b["verified"]
        out.append(f"  verified  {v.get('files', 0)} metadata files' fragments and versions, {v.get('bad', 0)} failed")
    users = sorted(b.get("users") or [], key=lambda u: -(u.get("used_bytes") or 0))
    shown = users if all_versions else users[:10]
    for u in shown:
        used = u.get("used") or {}
        parts = ", ".join(f"{k} {_human_bytes(v)}" for k, v in used.items() if v)
        runs = u.get("last_run") or {}
        last = max((r["end"] for r in runs.values() if r.get("end")), default=None)
        bad = sorted(k for k, r in runs.items() if r.get("status") != "succeeded")
        out.append(f"    {u['email']:<32} {_human_bytes(u.get('used_bytes') or 0):>9}  {parts or 'empty'}"
                   + (f"  last change {_when(last)}" if last else "")
                   + ("  removed" if u.get("status") != 1 else "")
                   + (f"  last run failed: {', '.join(bad)}" if bad else ""))
    if len(users) > len(shown):
        out.append(f"    ... {len(users) - len(shown)} more users (--versions lists them all)")
    return out


def _thunderbird_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    f, m, s = b.get("files") or {}, b.get("mail") or {}, b.get("storage") or {}
    out = [f"  profile   {b.get('profile') or '?'}"
           + (f" (Thunderbird {b['thunderbird_version']})" if b.get("thunderbird_version") else "")
           + (f" from {b['source_path']}" if b.get("source_path") else "")
           + f", copied by {b.get('made_by')} ({b.get('mode')})"]
    out.append(f"  storage   {s.get('files', 0)} files, {_human_bytes(s.get('bytes') or 0)}; mail "
               f"{_human_bytes(m.get('bytes') or 0)} in {len(b.get('accounts') or [])} accounts"
               + (f", {m['maildir_messages']} maildir messages" if m.get("maildir_messages") else "")
               + (f", {m['mbox_folders']} mbox folders ({_human_bytes(m.get('mbox_bytes') or 0)})"
                  if m.get("mbox_folders") else ""))
    out.append(f"  files     {f.get('logged', 0)} in Backup.log, {f.get('missing', 0)} missing, "
               f"{f.get('unlisted', 0)} not in the log, {f.get('copy_errors', 0)} copy errors")
    for a in b.get("accounts") or []:
        if not all_versions and not a.get("files"):
            continue
        what = (f"{a.get('maildir_messages', 0)} messages" if a.get("store") == "maildir" else
                f"{a.get('mbox_folders', 0)} folders")
        out.append(f"    {a.get('name') or '?':<34} {a.get('store') or '?':<8} "
                   f"{_human_bytes(a.get('bytes') or 0):>9}  {what}  {a.get('folder') or a.get('external') or ''}")
    return out


def _view_lines(b: dict[str, Any], all_versions: bool) -> list[str]:
    return [f"  virtual view: {len(b.get('tasks', []))} tasks, {b.get('versions', 0)} versions, "
            f"{_human_bytes(b.get('apparent_bytes', 0))} apparent (not walked, not disk space)"]


_DETAIL = {"synology-abb": _abb_lines, "synology-abb-view": _view_lines,
           "synology-hyperbackup": _hbk_lines, "synology-abg": _abg_lines, "thunderbird-ietng": _thunderbird_lines,
           "veeam": _veeam_lines,
           "windows-backup": _winbackup_lines,
           "windows-image-backup": _wib_lines, "duplicity": _duplicity_lines}


def _print_store(st: dict[str, Any], all_versions: bool) -> None:
    b = st["backup"]
    problems = b.get("problems", [])
    flag = f"  {len(problems)} problems" if problems else ""
    print(f"{st['path']}  [{b.get('format')}]{flag}")
    if not b.get("virtual"):
        print(f"  machines  {', '.join(b.get('machines') or ['?'])}; {b.get('versions', 0)} versions, "
              f"latest {_when(b.get('latest'))}")
    for line in _DETAIL.get(b.get("format"), lambda *_: [])(b, all_versions):
        print(line)
    for p in problems:
        print(f"  ! {p}")
    for e in st["errors"]:
        if e.get("stage") == "backup":
            print(f"  ! manifest not read: {e.get('message')}")
    print()


def groups(found: list[dict[str, Any]]) -> tuple[list[list[str]], dict[str, list[str]]]:
    """(copies, separate jobs). copies: lists of store paths holding the
    same data. separate jobs: {machine key: store paths} for machines
    backed up by more than one store that are not copies of each other."""
    by_copy: dict[str, set[str]] = defaultdict(set)
    by_machine: dict[str, set[str]] = defaultdict(set)
    for st in found:
        for k in st["backup"].get("copy_keys", []):
            by_copy[k].add(st["path"])
        for k in st["backup"].get("machine_keys", []):
            by_machine[k].add(st["path"])
    copies = sorted({tuple(sorted(v)) for v in by_copy.values() if len(v) > 1})
    copied_together = {frozenset(c) for c in copies}
    jobs = {}
    for k, paths in sorted(by_machine.items()):
        if len(paths) > 1 and frozenset(paths) not in copied_together:
            jobs[k] = sorted(paths)
    # one line per set of stores, under the most specific key (device before host)
    seen: set[tuple[str, ...]] = set()
    unique_jobs = {}
    for k, paths in jobs.items():
        if tuple(paths) not in seen:
            seen.add(tuple(paths))
            unique_jobs[k] = paths
    return [list(c) for c in copies], unique_jobs


def run(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        found = list(stores(backend, args.root))
    finally:
        backend.close()
    if args.json:
        for st in found:
            print(json.dumps(st, ensure_ascii=False))
        return 0
    if not found:
        print("(no backup stores recorded; they are recognised when a scan walks them)")
        return 0
    for st in found:
        _print_store(st, args.versions)
    copies, jobs = groups(found)
    if copies:
        print("Copies (the same backed-up data in more than one place):")
        for paths in copies:
            print("  " + "\n    = ".join(paths))
        print()
    if jobs:
        print("Separate backup jobs of one machine (each stores its own copy):")
        for key, paths in jobs.items():
            print(f"  {key}")
            for p in paths:
                print(f"    {p}")
        print()
    return 0
