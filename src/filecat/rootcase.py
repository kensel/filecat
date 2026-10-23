"""Roots that differ only in the case of server\\share, and merging them.

Windows and SMB ignore case in a server and share name, a Linux NAS does
not, so `\\\\nas-main\\backup` (typed on Windows) and `\\\\nas-main\\Backup`
(what a filecat-agent on the NAS reports) are one share that the catalog
would otherwise hold as two roots. Only server\\share is case-insensitive
here; every path below it stays case-sensitive, because the NAS's file
system is.

    filecat roots case-check [--sample N] [--json]
    filecat roots case-merge [OLD NEW] [--sample N] [--force] [--dry-run]

Detection (`find_groups`): roots with the same server\\share ignoring case
and the same path below the share, spelled differently.

Verification (`verify`): is it really one share? Up to N files (default
500, 200..1000) are taken by the smallest SHA-1 of their rel_path across
both roots, so a rerun picks the same ones, and each is looked up in both.
Kind, size, mtime_ns (within 100 ns, the agent's resolution) and the
sha256 / sha256_partial that both records have must agree. A file whose
mtime is not before the start of the older of the two scans is left out (the
share may legitimately have changed between scans taken at different
times); everything else is matched, mismatched or missing on one side. Of
the files judged, at least 95% must match (SAME_SHARE_RATIO) and at least
min(10, files available) must have been judged. The 5% allows for files
deleted, moved or touched since the scans without an mtime to show it;
two different shares under one name would match almost nothing.

Canonical spelling (`canonical_of`): the NAS's own. In order, the spelling a
configured agent's `[agents.shares]` gives, else the spelling of the one
root that was scanned through an agent. Neither known: the user names it
(`case-merge OLD NEW` keeps NEW).

Merge (`merge`): moves the records of the other spelling into the canonical
root (the record of the root scanned later wins a path both hold; a tie goes
to the canonical root), their archive members with them, then removes the
old root's index entry, stored aggregates, treemaps and resume state. It
runs in batches that write the moved records before deleting the old ones,
and a marker on the canonical root's index entry says a merge is under way,
so a killed merge is finished by running the command again (verification is
not repeated). It refuses while a scan of either root is running.
Dropped-record entries of the old root are left to expire (90 days).
"""
from __future__ import annotations

import hashlib
import heapq
import itertools
import json
import ntpath
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from . import rootinfo
from .backends.base import Backend, Document
from .record import root_id

SAMPLE_MIN, SAMPLE_MAX, SAMPLE_DEFAULT = 200, 1000, 500
SAME_SHARE_RATIO = 0.95
MIN_JUDGED = 10
MTIME_SLACK_NS = 100
BATCH = 1000


# --- spelling ------------------------------------------------------------
def split_unc(root: str) -> tuple[str, str] | None:
    """('server\\share', 'rest') of a UNC root; None for any other path.
    The rest is '' for a share root, else '\\folder\\...'."""
    norm = root.replace("/", "\\")
    if not norm.startswith("\\\\"):
        return None
    parts = norm[2:].rstrip("\\").split("\\")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    rest = "\\".join(parts[2:])
    return f"{parts[0]}\\{parts[1]}", ("\\" + rest if rest else "")


def key_of(root: str) -> tuple[str, str] | None:
    """What two spellings of one root have in common: server\\share lower
    case and the path below it, as written."""
    split = split_unc(root)
    return None if split is None else (split[0].lower(), split[1])


def respell(root: str, like: str) -> str:
    """`root` with its server\\share spelled as in `like` (same key)."""
    a, b = split_unc(root), split_unc(like)
    assert a is not None and b is not None
    return f"\\\\{b[0]}{a[1]}"


def find_groups(roots: list[str]) -> list[list[str]]:
    """Groups of roots that are one root spelled more than one way, each
    group sorted; groups sorted by their first member."""
    by_key: dict[tuple[str, str], list[str]] = {}
    for root in sorted(set(roots)):
        k = key_of(root)
        if k is not None:
            by_key.setdefault(k, []).append(root)
    groups = []
    for members in by_key.values():
        if len({split_unc(m)[0] for m in members}) > 1:
            groups.append(members)
    return sorted(groups)


def _attempt(info: Document | None) -> dict[str, Any]:
    return (info or {}).get("last_attempt") or {}


def via_agent(info: Document | None) -> str | None:
    """The agent a root's last scan went through, if any."""
    return _attempt(info).get("agent") or ((info or {}).get("last_scan") or {}).get("agent")


def scan_started(info: Document | None) -> str | None:
    last = (info or {}).get("last_scan") or {}
    return last.get("started_at") or _attempt(info).get("started_at")


def canonical_of(group: list[str], infos: dict[str, Document], agents: list[Any] = ()) -> tuple[str | None, str]:
    """(the NAS's spelling among `group`, why) or (None, why not)."""
    spelled = []
    for agent in agents:
        for root in group:
            s = agent.share_map().explicit_spelling(root)
            if s is not None and s in group:
                spelled.append((s, f"agent {agent.name}'s share map"))
    if spelled:
        winners = {s for s, _ in spelled}
        if len(winners) == 1:
            return spelled[0]
        return None, "the agents' share maps disagree"
    scanned = [r for r in group if via_agent(infos.get(r))]
    if len(scanned) == 1:
        return scanned[0], f"scanned through filecat-agent {via_agent(infos.get(scanned[0]))}"
    if scanned:
        return None, "more than one spelling was scanned through an agent"
    return None, "no spelling was scanned through an agent or is in a share map"


def existing_spelling(root: str, existing: list[str], infos: dict[str, Document],
                      agents: list[Any] = ()) -> str | None:
    """The spelling already in the catalog for `root`, when it holds one that
    differs only in the case of server\\share (None when `root` itself is
    there or nothing like it is). With several the NAS's wins, else the most
    recently scanned."""
    k = key_of(root)
    if k is None or root in existing:
        return None
    like = [e for e in existing if key_of(e) == k and e != root]
    if not like:
        return None
    best, _ = canonical_of(like, infos, agents)
    if best is not None:
        return best
    return max(like, key=lambda e: (scan_started(infos.get(e)) or "", e))


def known_roots(backend: Backend) -> tuple[list[str], dict[str, Document]]:
    try:
        infos = {i["root"]: i for i in backend.list_root_info()}
    except NotImplementedError:
        infos = {}
    return sorted(set(backend.roots()) | set(infos)), infos


def reconcile(roots: list[str], plans: list[Any], backend: Backend, agents: list[Any] = (),
              stream: Any = None) -> None:
    """Before a scan, keep it from splitting a share in two: `roots` and
    `plans` (as scan_roots builds them: the (AgentSource, UNC path) that reads
    each root, or None) are changed in place.

    A root read through an agent is recorded under the NAS's own spelling of
    server\\share (AgentSource.canonical_unc), whatever case it was typed in.
    A root read over SMB takes the spelling the catalog already holds for that
    share, since SMB ignores case. Either way, when the catalog holds the share
    under another spelling that is not used, one line points at
    `filecat roots case-check`."""
    stream = stream or sys.stderr
    if not any(key_of(r) for r in roots):
        return
    existing, infos = known_roots(backend)
    for i, root in enumerate(roots):
        if plans[i]:
            source, unc = plans[i]
            canon = source.canonical_unc(unc)
            if canon != unc:
                if unc == root:
                    roots[i] = canon
                plans[i] = (source, canon)
            root = roots[i]
        elif key_of(root) is not None:
            same = existing_spelling(root, existing, infos, agents)
            if same is not None:
                print(f"{root}: recorded as {same}, the spelling the catalog already holds for this "
                      "share (SMB ignores case)", file=stream)
                roots[i] = root = same
        k = key_of(root)
        others = [e for e in existing if k is not None and key_of(e) == k and e != root]
        if others:
            print(f"{root}: the catalog also holds this share as {', '.join(others)}; "
                  "see: filecat roots case-check", file=stream)


# --- verification --------------------------------------------------------
@dataclass
class Verdict:
    a: str
    b: str
    sample: int
    candidates: int = 0           # distinct files ranked for the sample (at most 2 x sample)
    sampled: int = 0
    matched: int = 0
    changed_since: int = 0        # left out: modified at or after the older scan started
    mismatched: list[dict[str, Any]] = field(default_factory=list)
    missing_a: list[str] = field(default_factory=list)   # in b, not in a
    missing_b: list[str] = field(default_factory=list)   # in a, not in b
    cutoff: str | None = None
    note: str = ""

    @property
    def judged(self) -> int:
        return self.matched + len(self.mismatched) + len(self.missing_a) + len(self.missing_b)

    @property
    def ratio(self) -> float:
        return self.matched / self.judged if self.judged else 0.0

    @property
    def same(self) -> bool:
        return self.judged >= min(MIN_JUDGED, self.candidates) and self.judged > 0 \
            and self.ratio >= SAME_SHARE_RATIO

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.update(judged=self.judged, ratio=round(self.ratio, 4), same=self.same)
        return d


def _digest(rel_path: str) -> bytes:
    return hashlib.sha1(rel_path.encode("utf-8", "surrogatepass")).digest()


def _ns(iso: str | None) -> int | None:
    try:
        return int(datetime.fromisoformat(iso).timestamp() * 1e9) if iso else None
    except ValueError:
        return None


def pick_sample(backend: Backend, a: str, b: str, n: int) -> tuple[list[str], int]:
    """The n rel_paths of readable files with the smallest hash across both
    roots, in that order, and how many distinct files were ranked."""
    top: set[str] = set()
    for root in (a, b):
        paths = (row[0] for row in backend.sizes(root))
        top.update(heapq.nsmallest(n, paths, key=_digest))
    return heapq.nsmallest(n, top, key=_digest), len(top)


def differences(da: Document, db: Document) -> list[str]:
    out = []
    if da.get("kind") != db.get("kind"):
        out.append(f"kind {da.get('kind')} != {db.get('kind')}")
    if da.get("size") != db.get("size"):
        out.append(f"size {da.get('size')} != {db.get('size')}")
    ma, mb = da.get("mtime_ns"), db.get("mtime_ns")
    if ma is not None and mb is not None and abs(ma - mb) > MTIME_SLACK_NS:
        out.append(f"mtime_ns {ma} != {mb}")
    for h in ("sha256", "sha256_partial"):
        if da.get(h) and db.get(h) and da[h] != db[h]:
            out.append(f"{h} differs")
    return out


def verify(backend: Backend, a: str, b: str, sample: int = SAMPLE_DEFAULT,
           infos: dict[str, Document] | None = None) -> Verdict:
    """Is root `a` the same share as root `b`? See the module docstring."""
    if not SAMPLE_MIN <= sample <= SAMPLE_MAX:
        raise ValueError(f"sample size must be {SAMPLE_MIN}..{SAMPLE_MAX}, got {sample}")
    if infos is None:
        infos = {i["root"]: i for i in _list_infos(backend)}
    v = Verdict(a, b, sample)
    starts = [t for t in (_ns(scan_started(infos.get(a))), _ns(scan_started(infos.get(b)))) if t is not None]
    cutoff = min(starts) if starts else None
    if cutoff is not None:
        v.cutoff = datetime.fromtimestamp(cutoff / 1e9).astimezone().isoformat(timespec="seconds")
    backend.flush()
    paths, v.candidates = pick_sample(backend, a, b, sample)
    v.sampled = len(paths)
    if not paths:
        v.note = "neither root has any readable files to compare"
        return v
    for rel in paths:
        da, db = backend.get(a, rel), backend.get(b, rel)
        times = [d.get("mtime_ns") for d in (da, db) if d is not None and d.get("mtime_ns") is not None]
        if cutoff is not None and times and max(times) >= cutoff:
            v.changed_since += 1
        elif da is None:
            v.missing_a.append(rel)
        elif db is None:
            v.missing_b.append(rel)
        else:
            why = differences(da, db)
            if why:
                v.mismatched.append({"rel_path": rel, "reasons": why})
            else:
                v.matched += 1
    return v


def _list_infos(backend: Backend) -> list[Document]:
    try:
        return list(backend.list_root_info())
    except NotImplementedError:
        return []


# --- merge ---------------------------------------------------------------
@dataclass
class MergeStats:
    moved: int = 0              # records of the old root now under the canonical one
    kept: int = 0               # records the canonical root already had and keeps
    batches: int = 0
    resumed: bool = False


class MergeRefused(Exception):
    pass


def merge(backend: Backend, old: str, new: str, *, resume_path: str | None = None,
          batch: int = BATCH, progress: Any = None) -> MergeStats:
    """Move root `old` into root `new` (same share, `new` the canonical
    spelling). Safe to run again after a crash. Does not verify and does not
    check for a running scan; run_merge does both."""
    if old == new or key_of(old) != key_of(new):
        raise ValueError(f"{old!r} and {new!r} are not the same root in another case")
    infos = {i["root"]: i for i in _list_infos(backend)}
    new_info = infos.get(new)
    old_wins = (scan_started(infos.get(old)) or "") > (scan_started(new_info) or "")
    stats = MergeStats(resumed=bool((new_info or {}).get("case_merge", {}).get("from") == old))
    # the marker goes first: from here on a rerun finishes the job
    marked = dict(new_info or {"root_id": root_id(new), "root": new})
    marked["case_merge"] = {"from": old, "started_at": rootinfo.now()}
    backend.put_root_info(marked)

    last_first = None
    while True:
        docs = list(itertools.islice(backend.list(root=old), batch))
        if not docs:
            break
        rels = [d["rel_path"] for d in docs]
        if rels[0] == last_first:
            raise RuntimeError(f"{old}: {rels[0]!r} was not removed; stopping")
        last_first = rels[0]
        existing = backend.get_stats(new, rels)
        written = 0
        for d in docs:
            rel = d["rel_path"]
            if rel in existing and not old_wins:
                stats.kept += 1
                continue
            moved = dict(d, root=new, root_id=root_id(new))
            if rel == "":
                moved["name"] = ntpath.basename(new.rstrip("\\/")) or new
            if not d.get("members_id"):
                try:
                    members = list(backend.list_members(old, rel))
                except NotImplementedError:
                    members = None
                if members:
                    backend.put_members(new, rel, [_bare(m) for m in members])
                elif members is not None and rel in existing:
                    backend.delete_members(new, rel)
            backend.put(moved)
            written += 1
        stats.moved += written
        backend.flush()
        for rel in rels:
            backend.delete(old, rel)
        backend.flush()
        stats.batches += 1
        if progress is not None:
            progress(stats)

    # the old root's bookkeeping, then the marker: a killed merge reruns from the top
    for meta in _safely(backend.list_treemaps, old) or []:
        _safely(backend.delete_treemap, meta["id"])
    _safely(backend.replace_aggregates, {}, 2, rootinfo.now(), old)
    final = dict(backend.get_root_info(new) or marked)
    old_info = infos.get(old)
    if old_info and not final.get("last_attempt") and not final.get("last_scan"):
        for k in ("last_attempt", "last_scan", "last_error", "newest_file"):
            if k in old_info:
                final[k] = old_info[k]
    final.pop("case_merge", None)
    final["root_id"], final["root"] = root_id(new), new
    backend.put_root_info(final)
    backend.delete_root_info(old)
    if resume_path:
        from .resume import ResumeState
        ResumeState(resume_path).forget_root(old)
    try:
        backend.rebuild_aggregates(root=new)
    except (NotImplementedError, ImportError):
        pass
    return stats


def _bare(member: Document) -> Document:
    return {k: v for k, v in member.items() if k not in ("root_id", "root", "archive_rel_path")}


def _safely(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except NotImplementedError:
        return None


# --- commands --------------------------------------------------------------
def _load_agents(args: Any) -> list[Any]:
    from . import config
    try:
        return config.load_agents(config.load(config.find(getattr(args, "config", None))))
    except config.ConfigError:
        return []


def _describe(v: Verdict) -> list[str]:
    lines = [f"  sampled {v.sampled} files: {v.matched} matched, "
             f"{len(v.mismatched)} mismatched, {len(v.missing_a)} only in {v.b}, "
             f"{len(v.missing_b)} only in {v.a}, {v.changed_since} changed since the older scan "
             f"(left out{', before ' + v.cutoff if v.cutoff else ''})"]
    for m in v.mismatched[:5]:
        lines.append(f"    mismatch {m['rel_path']}: {'; '.join(m['reasons'])}")
    for rel in v.missing_a[:3]:
        lines.append(f"    only in {v.b}: {rel}")
    for rel in v.missing_b[:3]:
        lines.append(f"    only in {v.a}: {rel}")
    if v.note:
        lines.append(f"  {v.note}")
    lines.append(f"  {v.ratio:.0%} of {v.judged} judged files match (need {SAME_SHARE_RATIO:.0%}): "
                 + ("the same share" if v.same else "NOT shown to be the same share"))
    return lines


def pairs(backend: Backend, agents: list[Any], sample: int) -> list[dict[str, Any]]:
    """For each group of roots that are one root in different case: the
    canonical spelling (when known and why), and each other spelling
    verified against it (or against the first, when none is known)."""
    roots, infos = known_roots(backend)
    out = []
    for group in find_groups(roots):
        canon, why = canonical_of(group, infos, agents)
        anchor = canon or group[0]
        entry = {"roots": group, "canonical": canon, "reason": why, "checks": []}
        for other in group:
            if other == anchor:
                continue
            merging = (infos.get(anchor) or {}).get("case_merge", {}).get("from") == other
            v = None if merging else verify(backend, other, anchor, sample, infos)
            entry["checks"].append({"root": other, "against": anchor, "merge_in_progress": merging,
                                    "verdict": v})
        out.append(entry)
    return out


def run_check(args: Any) -> int:
    from .backends import open_backend
    with open_backend(args.backend, args.out, args.dsn) as backend:
        found = pairs(backend, _load_agents(args), args.sample)
    if args.json:
        for e in found:
            print(json.dumps({**e, "checks": [{**c, "verdict": c["verdict"].as_dict() if c["verdict"] else None}
                                               for c in e["checks"]]}, ensure_ascii=False))
        return 1 if found else 0
    if not found:
        print("(no roots that differ only in the case of server\\share)")
        return 0
    for e in found:
        print("same share, spelled differently: " + "  |  ".join(e["roots"]))
        print(f"  canonical: {e['canonical'] or '(not known: ' + e['reason'] + ')'}"
              + (f"  ({e['reason']})" if e["canonical"] else ""))
        for c in e["checks"]:
            print(f"  {c['root']} against {c['against']}:")
            if c["merge_in_progress"]:
                print("  a case-merge into it was interrupted; run case-merge again to finish")
            else:
                print("\n".join(_describe(c["verdict"])))
        print()
    print("merge a pair with: filecat roots case-merge OLD NEW   (NEW's spelling is kept)")
    return 1


def run_merge(args: Any) -> int:
    from .backends import open_backend
    from .resume import resume_path_for
    agents = _load_agents(args)
    with open_backend(args.backend, args.out, args.dsn) as backend:
        roots, infos = known_roots(backend)
        todo: list[tuple[str, str]] = []
        if args.names:
            if len(args.names) != 2:
                print("filecat: case-merge wants OLD NEW (or nothing, to merge every pair whose "
                      "canonical spelling is known)", file=sys.stderr)
                return 2
            old, new = args.names
            if old == new or key_of(old) is None or key_of(old) != key_of(new):
                print(f"filecat: {old} and {new} are not UNC roots differing only in the case of "
                      "server\\share", file=sys.stderr)
                return 2
            for r in (old, new):
                if r not in roots:
                    print(f"filecat: no root {r} in the catalog", file=sys.stderr)
                    return 2
            group = [r for r in roots if key_of(r) == key_of(old)]
            canon, why = canonical_of(group, infos, agents)
            if canon is not None and canon != new and not args.force:
                print(f"filecat: {canon} is the NAS's spelling ({why}); merge into it, or --force "
                      f"to keep {new}", file=sys.stderr)
                return 1
            todo.append((old, new))
        else:
            for group in find_groups(roots):
                canon, why = canonical_of(group, infos, agents)
                if canon is None:
                    print(f"{'  |  '.join(group)}: canonical spelling not known ({why}); "
                          "name it with: filecat roots case-merge OLD NEW")
                    continue
                todo.extend((r, canon) for r in group if r != canon)
        if not todo:
            print("nothing to merge")
            return 0
        busy = set(rootinfo.in_progress(backend))
        status = 0
        for old, new in todo:
            if ({old, new} & busy) and not args.force:
                print(f"filecat: a scan is running on {', '.join(sorted({old, new} & busy))}; merge when "
                      "it has finished (--force to merge anyway)", file=sys.stderr)
                status = 1
                continue
            merging = (infos.get(new) or {}).get("case_merge", {}).get("from") == old
            if not merging:
                v = verify(backend, old, new, args.sample, infos)
                print(f"{old} -> {new}")
                print("\n".join(_describe(v)))
                if not v.same and not args.force:
                    print(f"  not merged (--force to merge anyway)")
                    status = 1
                    continue
            else:
                print(f"{old} -> {new}: finishing an interrupted merge")
            if args.dry_run:
                print("  dry run: nothing moved")
                continue
            resume = resume_path_for(getattr(backend, "name", "backend"), getattr(backend, "path", None))
            try:
                stats = merge(backend, old, new, resume_path=resume)
            except KeyboardInterrupt:
                print("case-merge: interrupted; run it again to finish", file=sys.stderr)
                return 130
            print(f"  merged: {stats.moved} records moved, {stats.kept} already in {new} kept; "
                  f"{old} removed from the root index")
    return status
