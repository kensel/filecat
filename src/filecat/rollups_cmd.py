"""`filecat rollups`: rollup groups (docs/rollups.md).

    rules                           the built-in rules and each type's mode, the
                                    user's rules as counts (never patterns)
    list [--root R] [--json]        the rollup records in the catalog: by tag and
                                    parent folder, with how each was made
    suggest [--root R] [--json]     what a built-in rule of a type that is not
                                    automatic would match, from the last complete
                                    scan of each root
    redacted list|release|approve   the sticky redactions: ids, status and the
                                    folder they sit in, never a name or a hash;
                                    releasing is two commands

Everything printed here comes from counts. A [REDACTED] folder appears as the
folder it sits in and its totals.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any

from . import config, redaction, rollup
from .backends import open_backend
from .summary import _human_bytes


def _config(args: Any) -> tuple[rollup.RollupConfig, list[Any]]:
    cfg = config.load(config.find(getattr(args, "config", None)))
    return config.load_rollups(cfg), config.load_agents(cfg)


def _mtime(ns: int | None) -> str:
    return datetime.fromtimestamp(ns / 1e9).strftime("%Y-%m-%d") if ns else "?"


# --- rules -------------------------------------------------------------------
def _rules(args: Any) -> int:
    cfg, _ = _config(args)
    types = []
    for name, tag in rollup.TYPES.items():
        groups = rollup.BUILTIN_PATTERNS.get(name, [])
        types.append({"type": name, "tag": tag, "mode": cfg.mode_of(name),
                      "marker": rollup.marker_name(tag),
                      "builtin": [{"type": t, "match": list(m)} for t, m in groups]})
    user = [{"index": s.index, "tag": s.tag, "keep": s.keep, "patterns": len(s.match), "type": s.type,
             "case": s.case, "private": s.private, "host": s.host} for s in cfg.rules]
    if args.json:
        print(json.dumps({"types": types, "rules": user, "tags": cfg.user_tags,
                          "policy": rollup.catalog_policy_id(cfg), "warnings": list(cfg.warnings)},
                         ensure_ascii=False))
        return 0
    for line in cfg.warnings:
        print(f"warning: {line}", file=sys.stderr)
    print("types (a mode per type: automatic applies the built-in rules, manual only what is listed, "
          "disabled ignores it)")
    for t in types:
        note = " (always on)" if t["type"] == "redacted" else ""
        print(f"  {t['tag']:<12} {t['mode']:<10} marker {t['marker']}{note}")
        for group in t["builtin"]:
            print(f"      {group['type']:<5} {', '.join(group['match'])}")
    if cfg.user_tags:
        print(f"your tags: {', '.join(cfg.user_tags)} (always manual; markers "
              + ", ".join(rollup.marker_name(x) for x in cfg.user_tags) + ")")
    print(f"your rules: {len(cfg.rules)}")
    for line in rollup.describe_rules(cfg):
        print(f"  {line}")
    print(f"rule set id: {rollup.catalog_policy_id(cfg)}")
    return 0


# --- list ----------------------------------------------------------------------
def _list(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        totals = backend.rollup_totals()
    finally:
        backend.close()
    totals = {r: rows for r, rows in totals.items() if not args.root or r in args.root}
    if args.json:
        for root, rows in totals.items():
            print(json.dumps({"root": root, "rollups": rows}, ensure_ascii=False))
        return 0
    if not totals:
        print("(no rollups)")
    for root, rows in totals.items():
        print(root)
        for r in rows:
            made = ", ".join(f"{n} {k}" for k, n in sorted(r["rules"].items()))
            where = r["parent"] or "(the root)"
            alloc = f" ({_human_bytes(r['allocated_size'])} allocated)" if r["allocated_size"] else ""
            print(f"  {r['tag']:<12} in {where}: {r['folders']} rollups, {r['matched']} folded in, "
                  f"{r['total_files']} files, {r['total_dirs']} folders, {_human_bytes(r['size'])}{alloc}, "
                  f"newest {_mtime(r['newest_mtime_ns'])}"
                  + (f", {r['partial']} partial" if r["partial"] else "") + f"  [{made}]")
    return 0


# --- suggest ---------------------------------------------------------------------
def _suggest(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        infos = [i for i in backend.list_root_info() if not args.root or i["root"] in args.root]
    finally:
        backend.close()
    if args.json:
        for i in infos:
            print(json.dumps({"root": i["root"], "suggestions": i.get("suggestions") or {}},
                             ensure_ascii=False))
        return 0
    shown = 0
    for i in infos:
        sug = i.get("suggestions") or {}
        items = sug.get("items") or []
        if not items:
            continue
        shown += 1
        print(f"{i['root']}  (scan of {sug.get('at', '?')[:10]})")
        by_tag: dict[str, list[dict[str, Any]]] = {}
        for item in items:
            by_tag.setdefault(item["tag"], []).append(item)
        for tag, rows in sorted(by_tag.items()):
            type_ = rollup.TAG_TYPES.get(tag, "?")
            print(f"  {tag}: {sum(r['matched'] for r in rows)} matches in {len(rows)} folders")
            for r in rows[:10]:
                print(f"      {r['parent'] or '(the root)'}: {r['matched']}")
            if len(rows) > 10:
                print(f"      ... {len(rows) - 10} more folders")
            print(f"    to roll them all up, scan with --rollup {type_}=automatic, or write in "
                  f"filecat.toml:\n        [rollups]\n        {type_} = \"automatic\"")
        if sug.get("more"):
            print(f"  ({sug['more']} more matches not listed)")
    if not shown:
        print("(no suggestions: every match is already rolled up, or no complete scan has run since "
              "this was added)")
    return 0


# --- redacted ---------------------------------------------------------------------
def _redacted(args: Any) -> int:
    action = args.redacted_action
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        if action == "list":
            return _redacted_list(args, backend)
        _, agents = _config(args)
        try:
            if action == "release":
                root, rel = redaction.locate(backend, args.path, agents)
                entry = redaction.release(backend, root, rel)
                print(f"redaction {entry['id']} ({root}, in {entry.get('parent') or 'the root'}) is pending; "
                      "the folder is still redacted.\nTo make it visible again run, separately: "
                      f"filecat rollups redacted approve {entry['id']}")
                return 0
            return _approve(args, backend, agents)
        except ValueError as exc:
            print(f"filecat: {exc}", file=sys.stderr)
            return 2
    finally:
        backend.close()


def _redacted_list(args: Any, backend: Any) -> int:
    rows = [e for e in backend.redactions() if not args.root or e["root"] in args.root]
    totals = {}
    for root, items in backend.rollup_totals().items():
        for r in items:
            if r["tag"] == rollup.REDACTED:
                totals[(root, r["parent"])] = r
    out = []
    for e in rows:
        t = totals.get((e["root"], e.get("parent", "")), {})
        out.append({"id": e["id"], "root": e["root"], "parent": e.get("parent", ""),
                    "status": e.get("status"), "source": e.get("source"), "created": e.get("created"),
                    "last_seen": e.get("last_seen"), "released": e.get("released"),
                    "files": t.get("total_files"), "bytes": t.get("size")})
    if args.json:
        for row in out:
            print(json.dumps(row, ensure_ascii=False))
        return 0
    if not out:
        print("(no sticky redactions)")
    for row in out:
        counts = (f"; the [REDACTED] there holds {row['files']} files, {_human_bytes(row['bytes'])}"
                  if row["files"] is not None else "")
        print(f"{row['id']}  {row['status']:<8} {row['source']:<7} {row['root']}  in "
              f"{row['parent'] or '(the root)'}  last seen {(row['last_seen'] or '?')[:10]}{counts}")
    return 0


def _approve(args: Any, backend: Any, agents: list[Any]) -> int:
    entry = redaction.pending_entry(backend, args.ref, agents)
    root, parent = entry["root"], entry.get("parent", "")
    here = next((r for r in backend.rollup_totals(root).get(root, [])
                 if r["tag"] == rollup.REDACTED and r["parent"] == parent), None)
    print(f"redaction {entry['id']}: the next scan of {root} will list and record the contents of one "
          f"folder in {parent or 'the root'}"
          + (f" (the [REDACTED] there now holds {here['total_files']} files, "
             f"{_human_bytes(here['size'])} in all folders folded into it)" if here else "") + ".")
    if os.path.exists(args.ref):
        marker = os.path.join(args.ref, rollup.marker_name(rollup.REDACTED))
        if os.path.exists(marker):
            print("  a .filecat-redacted marker is still in it; it will be redacted again until the marker goes.")
    cfg, _ = _config(args)
    if any(s.tag == rollup.REDACTED for s in cfg.rules):
        print("  a [[rollups.rule]] for [REDACTED] is configured; if it still matches this folder it "
              "is redacted again at the next scan.")
    if not args.yes:
        if not sys.stdin.isatty():
            print("filecat: not a terminal; pass --yes to approve", file=sys.stderr)
            return 2
        if input("approve? [y/N] ").strip().lower() not in ("y", "yes"):
            print("left pending")
            return 1
    redaction.approve(backend, entry)
    print("approved: the redaction is forgotten")
    return 0


def run(args: Any) -> int:
    try:
        if args.action == "rules":
            return _rules(args)
        if args.action == "list":
            return _list(args)
        if args.action == "suggest":
            return _suggest(args)
        return _redacted(args)
    except config.ConfigError as exc:
        print(f"filecat rollups: {exc}", file=sys.stderr)
        return 2
