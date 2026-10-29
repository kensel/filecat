"""`filecat rollups migrate`: turn the rows an existing catalog holds for what
rollups now replace into rollups, without a rescan (docs/rollups.md 4.4).

Two kinds of target, found in one read-only plan:

* a rule target: stored records that the current rules, markers' tags in the
  config, or the sticky store match (so a rule added after the catalog was
  made purges and sums what it matches, [REDACTED] included);
* a store target: a backup or database store whose type is `automatic`, or
  whose folder is listed in `[[rollups.backup_store]]` /
  `[[rollups.database_store]]`: the rows of its bulk folders (store_formats.json
  `rollup_children`) become the store's `[BACKUP]` / `[DATABASE]`.

Per target (a parent folder, a tag and the children it folds in), in three
phases that are safe to stop at any point and to run again:

1. Totals. Page through the rows beneath each child, summing size, files,
   folders and times (hard links by `(dev, ino)` where the rows have them),
   then write the rollup record with `probe.rollup.migrated`. One document
   write: until it exists nothing has changed, and a rerun recomputes.
2. Delete. With the rollup written, delete the rows beneath each child in
   batches (the child's own record last, so a rerun still finds it), saving a
   checkpoint after each batch. A rerun finds the rollup with `migrated` and
   goes straight to deleting; deleting what is gone is a no-op.
3. Clean up, once per run: the places a plain delete misses (redaction.cleanup
   for [REDACTED]; samples and member sets nothing names any more for the
   rest), the resume file, the root's aggregates.

The checkpoint file only reports where a run stopped; the catalog itself
(the `migrated` rollup, the rows still present) is what a rerun trusts. A scan
after a migration finds the rollup and the now empty folder and replaces the
rollup with an exact sum.

Nothing here prints a name of anything a rule rolled up: counts and the
folder the rollup sits in.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import backup, browse, dbfiles, record, redaction, rollup, rootinfo, summaries
from .backends.base import Backend, Document
from .fsutil import replace as _replace
from .options import ScanOptions
from .resume import ResumeState, resume_path_for

CHECKPOINT_VERSION = 1


@dataclass
class Target:
    root: str
    parent: str                      # rel_path of the folder the rollup sits in
    tag: str
    rule: str                        # user:3, builtin:cache, sticky, store:<format id>
    private: bool
    members: list[str] = field(default_factory=list)       # rel_paths folded in
    store: dict[str, str] | None = None

    @property
    def path(self) -> str:
        return rollup.rollup_path(self.parent, self.tag)

    @property
    def key(self) -> str:
        return f"{self.root}::{self.path}"


@dataclass
class Result:
    targets: int = 0
    migrated: int = 0
    skipped: list[str] = field(default_factory=list)       # reasons, no names
    rows: int = 0                    # rows summed (phase 1)
    deleted: int = 0                 # rows deleted (phase 2)
    bytes: int = 0
    resumed: bool = False
    done: bool = False


class _Entry:
    """A stored record standing in for a directory entry, for the rule matcher."""

    def __init__(self, name: str, is_dir: bool) -> None:
        self.name, self._dir = name, is_dir

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return self._dir


def _beneath(backend: Backend, root: str, member: str, offset: int, limit: int) -> list[Document]:
    q = browse.normalize({"root": root, "dir": member, "depth": len(member.split("/")),
                          "sort": "rel_path", "desc": "0", "offset": offset, "limit": limit})
    return backend.query(q)["rows"]


# --- the plan (read only) -----------------------------------------------------------
def _plan_rules(backend: Backend, root: str, options: ScanOptions, tags: set[str] | None
                ) -> tuple[list[Target], rollup.RollupPlan]:
    plan = rollup.make_plan(options, root, root, backend)
    found: dict[tuple[str, str], Target] = {}
    if not plan.ruleset.rules and not (plan.sticky is not None and plan.sticky.hashes):
        return [], plan
    docs = [(d["rel_path"], d.get("kind")) for d in backend.list(root=root)
            if d.get("rel_path") and d.get("kind") != "rollup"]
    docs.sort()
    taken: set[str] = set()
    for rel, kind in docs:
        parts = rel.split("/")
        if any("/".join(parts[:i]) in taken for i in range(1, len(parts))):
            continue        # beneath a child that is folded in already
        parent, _, name = rel.rpartition("/")
        hit = plan.classify(_Entry(name, kind == "dir"), name, parent,
                            plan.comps_of(parent) if plan.ruleset.needs_path else None, count=False)
        if hit is None or hit.tag is None or (tags and hit.tag not in tags):
            continue
        t = found.setdefault((parent, hit.tag), Target(root, parent, hit.tag, hit.rule, hit.private))
        t.members.append(rel)
        taken.add(rel)
    return list(found.values()), plan


def _store_format(doc: Document) -> tuple[Any, str] | None:
    """(format object, "backup" | "database") of a store's directory record."""
    probe = doc.get("probe") or {}
    if (probe.get("backup") or {}).get("format"):
        name, kind = probe["backup"]["format"], "backup"
    elif (probe.get("database") or {}).get("engine"):
        name, kind = probe["database"]["engine"], "database"
    elif probe.get("store_note"):
        name = probe["store_note"].split(":", 1)[0]
        kind = "database" if dbfiles.engine(name) else "backup"
    else:
        return None
    fmt = dbfiles.engine(name) if kind == "database" else next(
        (f for f in backup.formats() if f.name == name), None)
    return (fmt, kind) if fmt is not None else None


def _norm(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").lower()


def _plan_stores(backend: Backend, root: str, cfg: rollup.RollupConfig, tags: set[str] | None,
                 claimed: list[str]) -> list[Target]:
    out: list[Target] = []
    for d in backend.list(kind="dir", root=root):
        rel = d["rel_path"]
        found = _store_format(d)
        if found is None or any(rel == c or rel.startswith(c + "/") for c in claimed):
            continue
        fmt, kind = found
        mode = cfg.mode_of(kind)
        listed = cfg.database_stores if kind == "database" else cfg.backup_stores
        if mode == "disabled" or not (mode == "automatic" or any(
                _norm(p) == _norm(record.join_root(root, rel)) for p in listed)):
            continue
        store = backup.Store(fmt, rel)
        if (tags and store.tag not in tags) or not store.rollup_patterns:
            continue
        kids = [k["rel_path"] for k in _children(backend, root, rel)
                if k.get("kind") == "dir" and any(
                    _match(k["name"], pat) for pat in store.rollup_patterns)]
        if kids:
            out.append(Target(root, rel, store.tag, f"store:{fmt.name}", False, sorted(kids),
                              {"format": fmt.name, "path": rel}))
    return out


def _match(name: str, pattern: str) -> bool:
    import fnmatch
    return fnmatch.fnmatchcase(name, pattern)


def _children(backend: Backend, root: str, rel: str) -> list[Document]:
    out: list[Document] = []
    offset = 0
    while True:
        q = browse.normalize({"root": root, "parent": rel, "sort": "rel_path", "desc": "0",
                              "offset": offset, "limit": browse.MAX_LIMIT})
        page = backend.query(q)
        out += page["rows"]
        offset += len(page["rows"])
        if not page["rows"] or offset >= page["total"]:
            return out


# --- phase 1: totals ------------------------------------------------------------------
class NotMigratable(Exception):
    """A target that cannot be turned into a rollup without losing information."""


def sum_members(backend: Backend, target: Target, batch: int, on_page: Callable[[int], None] | None = None
                ) -> tuple[rollup.Totals, int]:
    """(totals, rows) of everything beneath the target's members and the members
    themselves. Raises NotMigratable when a row was read, not just listed
    (a hash: the information would be lost)."""
    t = rollup.Totals(matched=len(target.members))
    rows = 0
    seen: set[tuple[int, int]] = set()
    alloc_missing = False
    alloc = 0
    stored_tag = ("backup_data", "db_data")
    for member in target.members:
        own = backend.get(target.root, member)
        t.total_dirs += 1 if own is None or own.get("kind") == "dir" else 0
        if own is not None and own.get("kind") != "dir":
            _file(t, own, seen)
            rows += 1
        offset = 0
        while True:
            page = _beneath(backend, target.root, member, offset, batch)
            if not page:
                break
            for d in page:
                rows += 1
                kind = d.get("kind")
                if kind == "dir":
                    t.total_dirs += 1
                    continue
                if kind == "rollup":
                    raise NotMigratable("holds a rollup already")
                if target.store is not None and (
                        d.get("sha256") or d.get("sha256_partial")
                        or not any((d.get("probe") or {}).get(k) for k in stored_tag)):
                    raise NotMigratable("holds files that were read, not just listed")
                _file(t, d, seen)
                if d.get("allocated_size") is None:
                    alloc_missing = True
                else:
                    alloc += d["allocated_size"]
            offset += len(page)
            if on_page is not None:
                on_page(rows)
    t.allocated = None if alloc_missing or not alloc else alloc
    return t, rows


def _file(t: rollup.Totals, d: Document, seen: set[tuple[int, int]]) -> None:
    mtime = d.get("mtime_ns") or 0
    if d.get("errors"):
        t.count_error("io")
    ino, dev = d.get("ino"), d.get("dev")
    if ino and (d.get("nlink") or 1) > 1:
        key = (dev or 0, ino)
        if key in seen:
            t.total_files += 1
            t.newest = max(t.newest, mtime - mtime % 100)
            return
        seen.add(key)
    t.seen_file(d.get("size") or 0, mtime)


# --- the run -------------------------------------------------------------------------
class _Checkpoint:
    def __init__(self, path: str, tag: str) -> None:
        self.path, self.tag = path, tag
        self.state: dict[str, Any] = {"version": CHECKPOINT_VERSION, "catalog": tag, "done": [], "current": None}
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if loaded.get("version") == CHECKPOINT_VERSION and loaded.get("catalog") == tag:
                self.state = loaded
                self.resumed = True
                return
        except (OSError, ValueError):
            pass
        self.resumed = False

    def save(self, **update: Any) -> None:
        self.state.update(update)
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh)
            fh.flush()
            os.fsync(fh.fileno())
        _replace(tmp, self.path)

    def remove(self) -> None:
        try:
            os.remove(self.path)
        except OSError:
            pass


def checkpoint_path_for(backend_name: str, catalog_path: str | None) -> str:
    if catalog_path:
        return f"{catalog_path}.rollups-migrate.json"
    return f".filecat-{backend_name}.rollups-migrate.json"


def migrate(backend: Backend, options: ScanOptions, checkpoint: str, *, tag: str = "",
            roots: list[str] | None = None, tags: set[str] | None = None, dry_run: bool = False,
            batch: int = 1000, progress: Callable[[str], None] | None = None,
            resume_path: str | None = None) -> Result:
    """Plan and perform the migration. Raises RuntimeError when a scan of a
    root is running. See the module docstring for the phases."""
    say = progress or (lambda _m: None)
    cfg = options.rollup_config or rollup.RollupConfig()
    batch = max(1, min(batch, browse.MAX_LIMIT))
    result = Result()
    chosen = [r for r in backend.roots() if not roots or r in roots]
    running = rootinfo.in_progress(backend)
    busy = [r for r in chosen if r in running]
    if busy:
        raise RuntimeError(f"a scan is running on {', '.join(busy)}; migrate when it has finished")
    ck = _Checkpoint(checkpoint, tag)
    result.resumed = ck.resumed
    purged_redacted: dict[str, list[str]] = {}
    purged_any: set[str] = set()
    for root in chosen:
        plan_targets, plan = _plan_rules(backend, root, options, tags)
        claimed = [m for t in plan_targets for m in t.members]
        targets = plan_targets + _plan_stores(backend, root, cfg, tags, claimed)
        try:
            for target in targets:
                result.targets += 1
                _one(backend, root, target, plan, cfg, ck, result, say, dry_run, batch,
                     purged_redacted, purged_any)
        finally:
            if plan.sticky is not None and not dry_run:
                plan.sticky.finish()
    if not dry_run:
        _cleanup(backend, purged_redacted, purged_any, resume_path)
        for root in dict.fromkeys(chosen):
            rootinfo.touch(backend, root)       # rows became rollups: the stored summaries are stale
            try:
                summaries.after_scan(backend, root)
            except (NotImplementedError, ImportError):
                pass
        if purged_redacted:
            backend.scrub()
        ck.remove()
        result.done = True
    return result


def _one(backend: Backend, root: str, target: Target, plan: rollup.RollupPlan, cfg: rollup.RollupConfig,
         ck: _Checkpoint, result: Result, say: Callable[[str], None], dry_run: bool, batch: int,
         purged_redacted: dict[str, list[str]], purged_any: set[str]) -> None:
    label = f"{root}  {target.path}"
    existing = backend.get(root, target.path)
    info = ((existing or {}).get("probe") or {}).get("rollup") or {}
    if existing is not None and existing.get("kind") != "rollup":
        # a real folder of that name: the rollup replaces it, as a scan would
        existing = None
    if existing is not None and not info.get("migrated"):
        result.skipped.append(f"{label}: already a rollup made by a scan; scan to refresh it")
        return
    if existing is not None and len(target.members) > info.get("matched", 0):
        result.skipped.append(f"{label}: more children match than the rollup holds; scan to refresh it")
        return
    if existing is None:
        try:
            totals, rows = sum_members(backend, target, batch, lambda n: say(f"{label}: {n} rows read"))
        except NotMigratable as exc:
            result.skipped.append(f"{label}: {exc}")
            return
        result.rows += rows
        result.bytes += totals.size
        if dry_run:
            say(f"{label}: would fold {len(target.members)} children, {rows} rows, {totals.total_files} files, "
                f"{totals.size} bytes into a {target.tag} rollup and delete the rows")
            result.migrated += 1
            return
        doc = rollup.rollup_document(root, target.parent, target.tag, totals, rule=target.rule, via="python",
                                     policy=rollup.catalog_policy_id(cfg), store=target.store, migrated=True)
        _register_sticky(plan, target)
        backend.put(doc)             # phase 1 ends with this one write
        backend.flush()
        say(f"{label}: rollup written ({rows} rows, {totals.size} bytes)")
    elif dry_run:
        say(f"{label}: already written; would delete the rows that remain beneath {len(target.members)} children")
        result.migrated += 1
        return
    _delete_members(backend, root, target, ck, result, say, label, batch)
    _fix_parent(backend, root, target)
    result.migrated += 1
    purged_any.update(target.members)
    if target.tag == rollup.REDACTED:
        purged_redacted.setdefault(root, []).extend(target.members)
    ck.save(done=ck.state["done"] + [target.key], current=None)


def _register_sticky(plan: rollup.RollupPlan, target: Target) -> None:
    """A folder migrated into [REDACTED] stays redacted for later scans."""
    if target.tag != rollup.REDACTED or plan.sticky is None:
        return
    for rel in target.members:
        plan.sticky.register(target.parent, rel, "config" if target.rule.startswith("user") else "sticky")


def _delete_members(backend: Backend, root: str, target: Target, ck: _Checkpoint, result: Result,
                    say: Callable[[str], None], label: str, batch: int) -> None:
    """Phase 2. Each member's rows go in batches from the front of the sorted
    list (deleting shifts the next page to the start); the member's own record
    goes last, so a rerun still finds it."""
    if target.key in ck.state["done"]:
        return
    for member in target.members:
        while True:
            page = _beneath(backend, root, member, 0, batch)
            if not page:
                break
            paths = [d["rel_path"] for d in page]
            backend.delete_many(root, paths)
            backend.flush()
            result.deleted += len(paths)
            ck.save(current={"target": target.key, "after": paths[-1] if target.tag != rollup.REDACTED else None})
            say(f"{label}: {result.deleted} rows deleted")
        backend.delete_many(root, [member])
        result.deleted += 1


def _fix_parent(backend: Backend, root: str, target: Target) -> None:
    """The folder the rollup sits in: its child count and tags, as a scan would have left them."""
    parent = backend.get(root, target.parent) if target.parent else backend.get(root, record.ROOT_REL)
    if parent is None or parent.get("kind") != "dir":
        return
    probe = parent.setdefault("probe", {})
    tags = set(probe.get("rollup_tags") or ())
    if target.tag in tags:
        return
    tags.add(target.tag)
    probe["rollup_tags"] = sorted(tags)
    if probe.get("child_count") is not None:
        probe["child_count"] = max(0, probe["child_count"] - len(target.members) + 1)
    backend.put(parent)


def _cleanup(backend: Backend, redacted: dict[str, list[str]], purged: set[str], resume_path: str | None) -> None:
    """Phase 3."""
    backend.flush()
    for root, paths in redacted.items():
        redaction.cleanup(backend, root, paths)
    if purged and not redacted:
        for prune in (backend.prune_samples, backend.prune_member_sets):
            try:
                prune()
            except NotImplementedError:
                pass
    if purged:
        path = resume_path or resume_path_for(getattr(backend, "name", "backend"), getattr(backend, "path", None))
        if os.path.exists(path):
            state = ResumeState(path)
            for root in {r for r in backend.roots()}:
                for rel in purged:
                    state.forget_beneath(root, rel)
            state.flush()


# --- the command ----------------------------------------------------------------------
def run(args: Any) -> int:
    from . import config
    from .backends import open_backend
    from .samples import catalog_tag
    try:
        cfg = config.load(config.find(getattr(args, "config", None)))
        agents = config.load_agents(cfg)
    except config.ConfigError as exc:
        print(f"filecat rollups: {exc}", file=sys.stderr)
        return 2
    rollup_config = getattr(args, "rollup_config", None) or config.load_rollups(cfg)
    options = ScanOptions(rollup_config=rollup_config, agents=agents,
                          new_redaction_key=getattr(args, "new_redaction_key", False))
    tags = {t.upper() if t.startswith("[") else f"[{t.upper()}]" for t in args.tags} if args.tags else None
    catalog = args.out if args.backend in ("sqlite", "jsonl", "jsonl_dir") else None
    last = [0.0]

    def progress(message: str) -> None:
        now = time.monotonic()
        if args.dry_run or now - last[0] >= args.progress_interval or "written" in message:
            last[0] = now
            print(f"rollups migrate: {message}", file=sys.stderr, flush=True)

    with open_backend(args.backend, args.out, args.dsn) as backend:
        path = args.checkpoint or checkpoint_path_for(backend.name, catalog)
        try:
            result = migrate(backend, options, path, tag=catalog_tag(backend.name, args.out or args.dsn),
                             roots=args.root, tags=tags, dry_run=args.dry_run, batch=args.batch,
                             progress=progress)
        except RuntimeError as exc:
            print(f"filecat rollups migrate: {exc}", file=sys.stderr)
            return 1
        except redaction.RedactionKeyError as exc:
            print(f"filecat: {exc}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print(f"rollups migrate: interrupted; run it again to continue ({path})", file=sys.stderr)
            return 130
    for line in result.skipped:
        print(f"skipped: {line}")
    verb = "would migrate" if args.dry_run else "migrated"
    print(f"rollups migrate: {verb} {result.migrated} of {result.targets} targets; {result.rows} rows summed "
          f"({result.bytes} bytes), {result.deleted} rows deleted"
          + (", resumed from a checkpoint" if result.resumed else ""))
    return 0
