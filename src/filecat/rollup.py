"""Rollups: a set of files and folders the catalog counts but does not list
(docs/rollups.md). This module holds everything a scan needs to decide what
to roll up and to sum it, and nothing that reads a catalog:

* patterns and rules: `normalize_pattern`, `Rule`, `RuleSet` (the matcher
  the agent must reproduce; tests/data/rollup_match_vectors.json is the
  conformance file), the built-in rules, `[rollups]` parsing (`RollupConfig`)
* the two rule-set ids, `catalog_policy_id` and `wire_policy_id`
* markers: `.filecat-<tag>` files found in a folder's own listing
* `RollupPlan`: one root's rules, markers and sticky redactions as the walker
  uses them
* `sum_tree`: the name-free sum of a tree, and `Totals`, `rollup_document`

Privacy rule for this module: a name that a rule, a marker or the sticky
store sent to a rollup lives only in local variables here. `sum_tree` never
passes a path to a callback, a log call or an exception, never formats an
OSError (its message holds the file name) and re-raises nothing but
RollupError("rollup failed").
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from . import record

TAG_RE = re.compile(r"\[[A-Z][A-Z0-9_-]{0,31}\]")
MODES = ("automatic", "manual", "disabled")
# type -> tag; the order is the order markers win when a folder has several
TYPES = {"redacted": "[REDACTED]", "backup": "[BACKUP]", "database": "[DATABASE]",
         "cache": "[CACHE]", "synology": "[SYNOLOGY]", "windows": "[WINDOWS]"}
TAG_TYPES = {tag: name for name, tag in TYPES.items()}
REDACTED = "[REDACTED]"
MARKER_PREFIX = ".filecat-"
MAX_RULES, MAX_PATTERN_BYTES, MAX_PATTERNS_BYTES = 1024, 4096, 64 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CHECK_EVERY = 1024                      # entries between two looks at cancel and the deadline

_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


class RollupError(Exception):
    """A rollup could not be built. Never carries a name or an OS message."""


def fold(text: str) -> str:
    """ASCII letters lower-cased, every other character as it is (the one
    case folding of the matcher; str.lower() would fold Unicode too)."""
    return text.lower() if text.isascii() else text.translate(_ASCII_LOWER)


def marker_name(tag: str) -> str:
    return MARKER_PREFIX + tag[1:-1].lower()


def default_modes() -> dict[str, str]:
    return {name: "manual" for name in TYPES}


# --- patterns ------------------------------------------------------------
def pattern_form(text: str) -> str:
    """name | suffix | agent | share | local (docs/rollups.md, pattern semantics)."""
    if text.startswith(("\\\\", "//")):
        return "share"
    if text.startswith(("/", "\\")):
        return "agent"
    if re.match(r"[A-Za-z?*]:(?:[\\/]|$)", text):
        return "local"
    if text.startswith(("**/", "**\\")):
        return "suffix"
    if "/" not in text and "\\" not in text:
        return "name"
    raise ValueError("a path pattern starts with / or \\, \\\\, a drive letter or **/; "
                     "a name pattern has no separator")


def normalize_pattern(text: str) -> tuple[str, tuple[str, ...], bool]:
    """(form, components, dir_only) of a pattern; a trailing separator means
    directories only. Repeated separators collapse; / and \\ are the same."""
    if not isinstance(text, str) or not text:
        raise ValueError("a pattern is a non-empty string")
    core = text.rstrip("/\\")
    if not core:
        raise ValueError("a pattern names something below the root")
    form = pattern_form(core)
    comps = tuple(p for p in core.replace("\\", "/").split("/") if p)
    if len(text.encode("utf-8", "surrogatepass")) > MAX_PATTERN_BYTES:
        raise ValueError(f"a pattern is at most {MAX_PATTERN_BYTES} bytes")
    return form, comps, core != text


def pattern_text(form: str, comps: tuple[str, ...]) -> str:
    """The normalised spelling: / separated, //server/share for a share form."""
    body = "/".join(comps)
    return {"agent": "/" + body, "share": "//" + body}.get(form, body)


def _fold_prefix(form: str) -> int:
    """Leading components compared ignoring ASCII case whatever the rule says:
    server and share of a share form, the drive letter of a local form."""
    return {"share": 2, "local": 1}.get(form, 0)


def _glob(p: str, s: str) -> bool:
    """`*` any run, `?` one character; nothing else is special."""
    if "*" not in p and "?" not in p:
        return p == s
    pi = si = 0
    star, mark = -1, 0
    while si < len(s):
        if pi < len(p) and p[pi] == "*":
            star, mark = pi, si
            pi += 1
        elif pi < len(p) and (p[pi] == "?" or p[pi] == s[si]):
            pi += 1
            si += 1
        elif star != -1:
            pi = star + 1
            mark += 1
            si = mark
        else:
            return False
    while pi < len(p) and p[pi] == "*":
        pi += 1
    return pi == len(p)


def _match_comps(pat: tuple[str, ...], path: tuple[str, ...], fold_n: int, insensitive: bool) -> bool:
    """Anchored at both ends; `**` as a whole component is zero or more
    components, except last, where it needs at least one (`x/**` is what is
    inside x, not x)."""
    def rec(i: int, j: int) -> bool:
        while i < len(pat):
            p = pat[i]
            if p == "**":
                if i == len(pat) - 1:
                    return j < len(path)
                return any(rec(i + 1, k) for k in range(j, len(path) + 1))
            if j >= len(path):
                return False
            s = path[j]
            if insensitive or i < fold_n:
                p, s = fold(p), fold(s)
            if not _glob(p, s):
                return False
            i += 1
            j += 1
        return j == len(path)
    return rec(0, 0)


@dataclass(frozen=True)
class Pattern:
    form: str                                   # name | suffix | agent | share | local
    comps: tuple[str, ...] = field(repr=False)

    @property
    def text(self) -> str:
        return pattern_text(self.form, self.comps)

    @property
    def fold_n(self) -> int:
        return _fold_prefix(self.form)

    @property
    def last_literal(self) -> str | None:
        last = self.comps[-1]
        return None if "*" in last or "?" in last else last


def parse_patterns(texts: Iterable[str]) -> tuple[tuple[Pattern, ...], bool]:
    """(patterns, any pattern had a trailing separator)."""
    out, dir_only = [], False
    for t in texts:
        form, comps, d = normalize_pattern(t)
        out.append(Pattern(form, comps))
        dir_only = dir_only or d
    return tuple(out), dir_only


@dataclass(frozen=True)
class Rule:
    """A rule as the matcher uses it. `tag` is None for `keep`; `suggest`
    counts matches and folds nothing; `source` says where it came from
    (`user:<n>`, `builtin:<type>`), never what it matches."""
    tag: str | None
    patterns: tuple[Pattern, ...] = field(repr=False)
    type: str = "any"
    case: str = "sensitive"
    keep: bool = False
    private: bool = False
    suggest: bool = False
    source: str = ""
    host: str | None = None

    def to_wire(self, rule_id: int, match: list[str] | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"id": rule_id}
        if self.tag:
            out["tag"] = self.tag
        out["match"] = match if match is not None else [p.text for p in self.patterns]
        out["type"], out["case"] = self.type, self.case
        if self.keep:
            out["keep"] = True
        if self.private:
            out["private"] = True
        if self.suggest:
            out["suggest"] = True
        return out


def path_form(path: str) -> str:
    """The form a literal path is written in (share, agent or local)."""
    if path.startswith(("\\\\", "//")):
        return "share"
    if path.startswith(("/", "\\")):
        return "agent"
    return "local"


def path_comps(path: str) -> tuple[str, ...]:
    return tuple(p for p in path.replace("\\", "/").split("/") if p)


class RuleSet:
    """Ordered rules, first match wins. Name and path patterns whose last
    component is a literal are found by one dict lookup on the entry's name,
    so an entry that no rule could match costs a lower-casing and two
    lookups."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = tuple(rules)
        self._exact_s: dict[str, list[tuple[int, Rule, Pattern]]] = {}
        self._exact_i: dict[str, list[tuple[int, Rule, Pattern]]] = {}
        self._wild: list[tuple[int, Rule, Pattern]] = []
        self.needs_path = False
        for n, rule in enumerate(self.rules):
            insens = rule.case == "insensitive"
            for pat in rule.patterns:
                item = (n, rule, pat)
                last = pat.last_literal
                if pat.form != "name":
                    self.needs_path = True
                if last is None:
                    self._wild.append(item)
                elif insens:
                    self._exact_i.setdefault(fold(last), []).append(item)
                else:
                    self._exact_s.setdefault(last, []).append(item)

    def __bool__(self) -> bool:
        return bool(self.rules)

    def first(self, name: str, is_dir: Callable[[], bool],
              comps: Callable[[], tuple[str, ...]], pform: str | None = None) -> Rule | None:
        """The first rule matching an entry called `name`. `is_dir()` and
        `comps()` (the entry's whole path as components) are called only when
        a candidate needs them. `pform` limits path patterns to one form (the
        form of the path); None means the rules were already made for it."""
        cands = self._exact_s.get(name)
        low = fold(name)
        ci = self._exact_i.get(low)
        if ci:
            cands = ci if not cands else cands + ci
        if self._wild:
            cands = self._wild if not cands else cands + self._wild
        if not cands:
            return None
        if len(cands) > 1:
            cands = sorted(cands, key=lambda c: c[0])
        isdir: bool | None = None
        path: tuple[str, ...] | None = None
        for _, rule, pat in cands:
            if rule.type != "any":
                if isdir is None:
                    isdir = is_dir()
                if (rule.type == "dir") != isdir:
                    continue
            insens = rule.case == "insensitive"
            if pat.form == "name":
                if _glob(fold(pat.comps[0]) if insens else pat.comps[0], low if insens else name):
                    return rule
                continue
            if pform is not None and pat.form not in ("suffix", pform):
                continue
            if path is None:
                path = comps()
            pcomps = tuple(fold(c) for c in pat.comps) if insens else pat.comps
            if _match_comps(pcomps, path, pat.fold_n, insens):
                return rule
        return None

    def match_path(self, path: str, is_dir: bool) -> Rule | None:
        """A rule for a literal path in any form (tests, the conformance
        vectors, `rollups release`)."""
        comps = path_comps(path)
        if not comps:
            return None
        return self.first(comps[-1], lambda: is_dir, lambda: comps, path_form(path))


# --- built-in rules ----------------------------------------------------------
_WINDOWS_DIRS = ("System Volume Information", "$Recycle.Bin")
_WINDOWS_FILES = ("pagefile.sys", "hiberfil.sys", "swapfile.sys")
BUILTIN_PATTERNS: dict[str, list[tuple[str, tuple[str, ...]]]] = {
    "cache": [("dir", ("__pycache__", "node_modules", ".cache", "**/AppData/Local/Temp",
                       "**/AppData/Local/Microsoft/Windows/INetCache",
                       "**/AppData/Local/CrashDumps", "**/.gradle/caches", "**/.npm/_cacache",
                       "**/Library/Caches"))],
    "synology": [("dir", ("@eaDir", "#recycle", "#snapshot", "@Recycle", "@tmp", "@SynoEAStream",
                          "@appstore", "@appdata", "@apphome", "@database"))],
    "windows": [("dir", _WINDOWS_DIRS),
                ("file", tuple(f"?:/{n}" for n in _WINDOWS_FILES)
                 + tuple(f"//*/*$/{n}" for n in _WINDOWS_FILES))],
}


def builtin_rules(mode_of: Callable[[str], str], default_skips: bool = True) -> list[Rule]:
    """Rules of the types that are `automatic`, then the others as
    suggestions (a `disabled` type has none). The `windows` rule is the
    former default skip, so --no-default-skips takes it away."""
    auto: list[Rule] = []
    suggestions: list[Rule] = []
    for name, groups in BUILTIN_PATTERNS.items():
        mode = mode_of(name)
        if mode == "disabled" or (name == "windows" and not default_skips):
            continue
        for type_, texts in groups:
            pats, _ = parse_patterns(texts)
            rule = Rule(TYPES[name], pats, type_, "insensitive", suggest=mode != "automatic",
                        source=f"builtin:{name}")
            (auto if mode == "automatic" else suggestions).append(rule)
    return auto + suggestions


# --- [rollups] configuration -------------------------------------------------
@dataclass(frozen=True)
class RuleSpec:
    """One [[rollups.rule]], validated. `match` is as written; it is never
    printed (repr=False) and no message here repeats it."""
    index: int
    tag: str | None
    match: tuple[str, ...] = field(repr=False)
    type: str = "any"
    case: str = "sensitive"
    keep: bool = False
    private: bool = False
    host: str | None = None

    @property
    def label(self) -> str:
        return f"[[rollups.rule]] #{self.index + 1}" + (f" ({self.tag})" if self.tag else "")


@dataclass(frozen=True)
class RollupConfig:
    modes: dict[str, str] = field(default_factory=default_modes)
    rules: tuple[RuleSpec, ...] = ()
    backup_stores: tuple[str, ...] = ()          # stage B
    database_stores: tuple[str, ...] = ()        # stage B
    store_resum_days: int = 30
    manifest_cap: int = 256 * 1024 * 1024
    warnings: tuple[str, ...] = ()

    def with_modes(self, overrides: dict[str, str]) -> "RollupConfig":
        from dataclasses import replace
        modes, warnings = apply_modes({**self.modes}, overrides)
        return replace(self, modes=modes, warnings=self.warnings + tuple(warnings))

    @property
    def user_tags(self) -> list[str]:
        return sorted({r.tag for r in self.rules if r.tag and r.tag not in TAG_TYPES})

    def mode_of(self, type_: str) -> str:
        return self.modes.get(type_, "manual")


def apply_modes(modes: dict[str, str], overrides: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """`modes` with `overrides` applied (validated); `redacted = disabled` is
    refused with a warning and stays manual."""
    warnings: list[str] = []
    for key, value in overrides.items():
        if key not in TYPES:
            raise ValueError(f"rollups: unknown type {key!r}; the types are {', '.join(TYPES)}")
        if value not in MODES:
            raise ValueError(f"rollups: {key} = {value!r}; the modes are {', '.join(MODES)}")
        if key == "redacted" and value == "disabled":
            warnings.append("rollups: redacted cannot be disabled; it stays manual (redaction is always on)")
            value = "manual"
        modes[key] = value
    return modes, warnings


def parse_rule(table: Any, index: int) -> RuleSpec:
    label = f"[[rollups.rule]] #{index + 1}"
    if not isinstance(table, dict):
        raise ValueError(f"{label}: wants a table with tag and match")
    keys = ("tag", "match", "type", "case", "keep", "private", "host")
    unknown = [k for k in table if k not in keys]
    if unknown:
        raise ValueError(f"{label}: unknown key {unknown[0]!r}; the keys are {', '.join(keys)}")
    keep = table.get("keep", False)
    if not isinstance(keep, bool):
        raise ValueError(f"{label}: keep wants true or false")
    tag = table.get("tag")
    if keep:
        if tag is not None:
            raise ValueError(f"{label}: a keep rule has no tag")
    else:
        if not isinstance(tag, str) or not TAG_RE.fullmatch(tag.strip()):
            raise ValueError(f"{label}: tag wants a name like [CACHE] (capital letters, digits, - and _)")
        tag = tag.strip()
        label += f" ({tag})"
    match = table.get("match", [])
    if (not isinstance(match, list) or not all(isinstance(m, str) and m for m in match)
            or (keep and not match)):
        raise ValueError(f"{label}: match wants a list of patterns")
    type_, case = table.get("type", "any"), table.get("case", "sensitive")
    if type_ not in ("any", "dir", "file"):
        raise ValueError(f"{label}: type wants any, dir or file")
    if case not in ("sensitive", "insensitive"):
        raise ValueError(f"{label}: case wants sensitive or insensitive")
    private = table.get("private", False)
    if not isinstance(private, bool):
        raise ValueError(f"{label}: private wants true or false")
    host = table.get("host")
    if host is not None and (not isinstance(host, str) or not host.strip()):
        raise ValueError(f"{label}: host wants an agent name or a server")
    total = 0
    for n, text in enumerate(match, 1):
        try:
            form, _, dir_only = normalize_pattern(text)
        except ValueError as exc:
            raise ValueError(f"{label}: pattern {n}: {exc}") from None
        if dir_only and type_ == "file":
            raise ValueError(f"{label}: pattern {n} ends with a separator (directories) but type is file")
        total += len(text.encode("utf-8", "surrogatepass"))
    if total > MAX_PATTERNS_BYTES:
        raise ValueError(f"{label}: patterns total over {MAX_PATTERNS_BYTES} bytes")
    return RuleSpec(index, tag, tuple(match), type_, case, keep, private or tag == REDACTED,
                    host.strip().lstrip("\\/") if host else None)


def _size(value: Any, label: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([KMGT]?i?B?)\s*", str(value), re.I)
    if not m:
        raise ValueError(f"rollups: {label} wants a size like 256MiB")
    unit = m.group(2).upper().rstrip("B").rstrip("I")
    return int(m.group(1)) * 1024 ** ("", "K", "M", "G", "T").index(unit)


def _days(value: Any, label: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*d?\s*", str(value))
    if not m:
        raise ValueError(f"rollups: {label} wants a number of days like 30d")
    return int(m.group(1))


def parse_config(cfg: dict[str, Any]) -> RollupConfig:
    """The [rollups] table and its [[rollups.rule]] / store tables. Raises
    ValueError; no message repeats a pattern."""
    section = cfg.get("rollups")
    if section is None:
        return RollupConfig()
    if not isinstance(section, dict):
        raise ValueError("rollups: write [rollups] with modes and [[rollups.rule]] tables")
    known = tuple(TYPES) + ("rule", "backup_store", "database_store", "store_resum", "manifest_cap")
    unknown = [k for k in section if k not in known]
    if unknown:
        raise ValueError(f"rollups: unknown key {unknown[0]!r}; the keys are {', '.join(known)}")
    modes, warnings = apply_modes(default_modes(), {k: v for k, v in section.items() if k in TYPES})
    tables = section.get("rule", [])
    if not isinstance(tables, list):
        raise ValueError("rollups: write one [[rollups.rule]] table per rule (double brackets)")
    if len(tables) > MAX_RULES:
        raise ValueError(f"rollups: at most {MAX_RULES} rules")
    rules = tuple(parse_rule(t, i) for i, t in enumerate(tables))
    stores: dict[str, tuple[str, ...]] = {}
    for key in ("backup_store", "database_store"):
        items = section.get(key, [])
        if not isinstance(items, list) or not all(isinstance(t, dict) and set(t) <= {"path"}
                                                  and isinstance(t.get("path"), str) for t in items):
            raise ValueError(f"rollups: [[rollups.{key}]] tables take path only")
        stores[key] = tuple(t["path"] for t in items)
    return RollupConfig(
        modes=modes, rules=rules, backup_stores=stores["backup_store"],
        database_stores=stores["database_store"],
        store_resum_days=_days(section.get("store_resum", "30d"), "store_resum"),
        manifest_cap=_size(section.get("manifest_cap", "256MiB"), "manifest_cap"),
        warnings=tuple(warnings))


def describe_rules(cfg: RollupConfig) -> list[str]:
    """What `config show` and `rollups rules` print for the user's rules:
    counts, never patterns."""
    out = []
    for spec in cfg.rules:
        what = "keep" if spec.keep else spec.tag
        n = len(spec.match)
        extra = ", private" if spec.private else ""
        out.append(f"#{spec.index + 1} {what}: {n} pattern{'s' if n != 1 else ''}, type {spec.type}, "
                   f"case {spec.case}{extra}" + (f", host {spec.host}" if spec.host else ""))
    return out


# --- the two rule-set ids ------------------------------------------------------
def _digest(payload: Any) -> str:
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def catalog_policy_id(cfg: RollupConfig) -> str:
    """The id kept on the root's directory record (`probe.rollup_policy`) and
    on every rollup: modes, the user rules after normalisation, the store
    paths and the user tags whose markers are looked for. Computed from the
    written form, so an agent scan and an SMB scan of one share agree."""
    rules = []
    for spec in cfg.rules:
        pats, dir_only = parse_patterns(spec.match)
        rules.append({"tag": spec.tag, "match": [p.text for p in pats],
                      "type": "dir" if dir_only and spec.type == "any" else spec.type,
                      "case": spec.case, "keep": spec.keep, "private": spec.private, "host": spec.host})
    return _digest({"modes": [cfg.modes[k] for k in TYPES], "rules": rules,
                    "stores": [list(cfg.backup_stores), list(cfg.database_stores)],
                    "markers": cfg.user_tags})


def default_policy_id() -> str:
    return catalog_policy_id(RollupConfig())


def wire_policy_id(rules: list[dict[str, Any]], markers: list[str]) -> str:
    """The id `configure_policy` and `list_dir` answer with: the first 12 hex
    digits of the SHA-256 of the compact JSON (UTF-8, ensure_ascii off) of
    [rules, marker names], each rule as {"tag","match","type","case","keep",
    "private","suggest"} in that key order (tag null for keep, the booleans
    false when absent)."""
    canon = [{"tag": r.get("tag"), "match": list(r.get("match", [])), "type": r.get("type", "any"),
              "case": r.get("case", "sensitive"), "keep": bool(r.get("keep")),
              "private": bool(r.get("private")), "suggest": bool(r.get("suggest"))} for r in rules]
    return _digest([canon, list(markers)])


# --- markers -----------------------------------------------------------------
@dataclass(frozen=True)
class Marker:
    name: str               # ".filecat-cache"
    tag: str
    private: bool


class Marked:
    """What a folder's listing becomes when it holds a marker file: the
    listing is dropped and the folder is rolled up under `marker.tag`."""
    __slots__ = ("marker",)

    def __init__(self, marker: Marker) -> None:
        self.marker = marker


def find_marker(names: Iterable[str], markers: dict[str, Marker]) -> Marker | None:
    """The marker (by priority: redacted, then the plan's order) among
    `names`, matched ignoring ASCII case. A set lookup per dotted name."""
    hits: list[Marker] = []
    for n in names:
        if n[:1] == "." and n[:9].lower() == MARKER_PREFIX:
            m = markers.get(fold(n))
            if m is not None:
                hits.append(m)
    if len(hits) < 2:
        return hits[0] if hits else None
    order = list(markers.values())
    return min(hits, key=order.index)


# --- the plan for one root -----------------------------------------------------
@dataclass
class Hit:
    tag: str | None         # None: listed normally (a keep rule)
    rule: str               # user:3, builtin:cache, marker:[CACHE], sticky
    private: bool = False
    suggest: bool = False


STICKY_HIT = Hit(REDACTED, "sticky", True)


def host_names_for(root: str, agent: Any = None) -> set[str]:
    """What a rule's `host =` may name for this scan: the agent's name and
    server, or the root's server, or this machine."""
    out: set[str] = set()
    if agent is not None:
        out |= {agent.name.lower(), agent.alias.strip("\\/").lower()}
    elif root.startswith(("\\\\", "//")):
        out.add(path_comps(root)[0].lower())
    else:
        out |= {socket.gethostname().lower(), "localhost"}
    return out


class RollupPlan:
    """Everything one root's walk needs: the compiled rules (for SMB and local
    scans; an agent scan sends them instead), the marker names to look for in
    a listing, the sticky redactions, and what the walk finds out (suggestions,
    purged paths) for the scan to store."""

    def __init__(self, cfg: RollupConfig, *, root: str, scan_form: str, default_skips: bool = True,
                 agent: Any = None, agents: list[Any] | None = None, sticky: Any = None,
                 on_message: Callable[[str], None] | None = None) -> None:
        self.cfg = cfg
        self.root = root
        self.scan_form = scan_form                  # share | local | agent
        self.default_skips = default_skips
        self.sticky = sticky
        self.messages: list[str] = []
        self.unresolved: list[str] = []             # labels of rules with an unconvertible pattern
        self.suggestions: dict[tuple[str, str], int] = {}
        self.purged: list[str] = []                 # rel_paths whose stored records were replaced (memory only)
        self.complete = True
        self.policy_id = catalog_policy_id(cfg)
        self.policy_changed = False
        self.root_comps = path_comps(root)
        self._say = on_message or self.messages.append
        for w in cfg.warnings:
            self._say(w)

        disabled = [t for t in TYPES if cfg.mode_of(t) == "disabled"]
        user: list[tuple[RuleSpec, Rule]] = []
        hosts = host_names_for(root, agent)
        for spec in cfg.rules:
            if spec.tag in TAG_TYPES and cfg.mode_of(TAG_TYPES[spec.tag]) == "disabled":
                continue
            if spec.host and spec.host.lower() not in hosts:
                continue
            pats, dir_only = parse_patterns(spec.match)
            type_ = "dir" if dir_only and spec.type == "any" else spec.type
            rule = Rule(spec.tag, pats, type_, spec.case, spec.keep, spec.private,
                        source=f"user:{spec.index}", host=spec.host)
            user.append((spec, rule))
        for t in disabled:
            if t == "redacted":
                continue
            n = sum(1 for s in cfg.rules if s.tag == TYPES[t])
            self._say(f"{t} is disabled: {n} rules and {marker_name(TYPES[t])} markers are ignored")
        self.markers: dict[str, Marker] = {}
        for t, tag in TYPES.items():
            if cfg.mode_of(t) != "disabled":
                self.markers[marker_name(tag)] = Marker(marker_name(tag), tag, tag == REDACTED)
        for tag in cfg.user_tags:
            self.markers[marker_name(tag)] = Marker(marker_name(tag), tag, any(
                s.private for s in cfg.rules if s.tag == tag))
        # order: redacted first, then the user's rules, then built-ins (docs/rollups.md section 2)
        redacted = [r for s, r in user if r.tag == REDACTED]
        others = [r for s, r in user if r.tag != REDACTED]
        self.rules_in_order: list[Rule] = redacted + others + builtin_rules(
            cfg.mode_of, default_skips)
        self._specs = {r.source: s for s, r in user}
        self.windows_rule = cfg.mode_of("windows") == "automatic" and default_skips
        self.agent_cfg = agent
        self.agents = agents or []
        self.ruleset = RuleSet(())
        self.python_side = scan_form != "agent" or agent is None
        self.wire_sources: list[str] = []
        if self.python_side:
            self._compile_python_rules()
        # an agent scan: AgentSource.configure() converts and sends rules_in_order

    # --- Python side --------------------------------------------------------
    def _compile_python_rules(self) -> None:
        out = []
        for rule in self.rules_in_order:
            kept, unresolved = self._for_scan(rule)
            if unresolved:
                self.unresolved.append(self._specs[rule.source].label if rule.source in self._specs
                                       else rule.source)
            if kept is not None:
                out.append(kept)
        self.ruleset = RuleSet(out)
        for label in self.unresolved:
            self._say(f"{self.root}: {label} has a pattern no agent map can place under this root; "
                      "it is not applied here")

    def _for_scan(self, rule: Rule) -> tuple[Rule | None, bool]:
        """`rule` with its patterns in this scan's form; (None, ...) when none
        applies; unresolved when an agent form could not be placed."""
        keep: list[Pattern] = []
        unresolved = False
        for pat in rule.patterns:
            if pat.form in ("name", "suffix", self.scan_form):
                keep.append(pat)
            elif pat.form == "agent" and self.scan_form == "share":
                shared = self._agent_to_share(pat)
                if shared is None:
                    unresolved = True
                else:
                    keep.append(shared)
        if not keep:
            return None, unresolved
        return Rule(rule.tag, tuple(keep), rule.type, rule.case, rule.keep, rule.private,
                    rule.suggest, rule.source, rule.host), unresolved

    def _agent_to_share(self, pat: Pattern) -> Pattern | None:
        from .config import agent_for
        found = agent_for(self.agents, self.root)
        if found is None:
            return None
        try:
            unc = found.share_map().to_catalog_path(pat.text)
        except ValueError:
            return None
        return Pattern("share", path_comps(unc))

    def classify(self, entry: Any, name: str, parent_rel: str,
                 parent_comps: tuple[str, ...] | None, count: bool = True) -> Hit | None:
        """Which rule rolls this child of a listing up (None: record it). A
        suggestion is counted and answered as None. Thread-safe unless
        `count` (the walk's own thread counts, read-ahead threads do not)."""
        sticky = self.sticky
        if not self.python_side:
            return None
        if sticky is not None and sticky.hashes:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir and sticky.matches(f"{parent_rel}/{name}" if parent_rel else name):
                return STICKY_HIT
        rs = self.ruleset
        if not rs.rules:
            return None
        rule = rs.first(name, lambda: _is_dir(entry),
                        lambda: (parent_comps or ()) + (name,))
        if rule is None or rule.keep:
            return None
        if rule.suggest:
            if count:
                key = (rule.tag, parent_rel)
                self.suggestions[key] = self.suggestions.get(key, 0) + 1
            return None
        return Hit(rule.tag, rule.source, rule.private)

    def comps_of(self, rel_path: str) -> tuple[str, ...]:
        """The path components of a folder of this root, for path patterns."""
        return self.root_comps + (tuple(rel_path.split("/")) if rel_path else ())

    def partition(self, entries: list, rel_path: str,
                  skipped: Callable[[Any, str], bool] | None = None) -> tuple[list, dict[str, "Group"]]:
        """(entries to record, rolled groups by tag) for a listing. An entry
        `skipped` says is excluded (or skipped by default): it is left as it is
        for the walk to skip, never rolled up."""
        if not self.ruleset.rules and not (self.sticky is not None and self.sticky.hashes):
            return entries, {}
        comps = self.comps_of(rel_path) if self.ruleset.needs_path else None
        recorded: list = []
        groups: dict[str, Group] = {}
        for e in entries:
            if skipped is not None and skipped(e, rel_path):
                recorded.append(e)
                continue
            hit = self.classify(e, e.name, rel_path, comps)
            if hit is None:
                recorded.append(e)
                continue
            g = groups.get(hit.tag)
            if g is None:
                g = groups[hit.tag] = Group(hit.tag, hit.rule, hit.private)
            g.add(e)
        if groups and recorded:
            # a real child named like a tag in play is folded into it
            by_name = {fold(t): t for t in groups}
            keep = []
            for e in recorded:
                tag = by_name.get(fold(e.name)) if e.name[:1] == "[" else None
                if tag is not None:
                    groups[tag].add(e)
                else:
                    keep.append(e)
            recorded = keep
        return recorded, groups

    def agent_rule(self, rule: Any, tag: str) -> str:
        """`rollup.rule` of an agent's rollup entry from its optional `rule`
        field: a rule id of the policy sent, "marker" or "sticky"."""
        if isinstance(rule, int) and 0 <= rule < len(self.wire_sources):
            return self.wire_sources[rule]
        if rule == "marker":
            return f"marker:{tag}"
        return rule if rule == "sticky" else "agent"

    def note_suggest(self, parent_rel: str, items: Iterable[dict[str, Any]]) -> None:
        """The agent's `suggest` answer for one folder."""
        for item in items or ():
            key = (item.get("tag"), parent_rel)
            self.suggestions[key] = self.suggestions.get(key, 0) + int(item.get("matched", 0))

    def suggestion_rows(self, limit: int = 1000) -> dict[str, Any]:
        rows = [{"tag": t, "parent": p, "matched": n} for (t, p), n in sorted(self.suggestions.items())]
        out: dict[str, Any] = {"items": rows[:limit]}
        if len(rows) > limit:
            out["more"] = len(rows) - limit
        return out

    # --- the wire form ------------------------------------------------------------
    def wire_policy(self, to_agent: Callable[[Pattern], str | None]) -> dict[str, Any]:
        """rules, markers and the id of what an agent is sent. `to_agent`
        gives the agent-form text of a share-form pattern, or None when this
        agent does not cover it (not sent). Local forms are never sent."""
        rules: list[dict[str, Any]] = []
        sources: list[str] = []
        for rule in self.rules_in_order:
            texts = []
            for pat in rule.patterns:
                if pat.form in ("name", "suffix", "agent"):
                    texts.append(pat.text)
                elif pat.form == "share":
                    t = to_agent(pat)
                    if t is not None:
                        texts.append(t)
            if not texts:
                continue
            rules.append(rule.to_wire(len(rules), texts))
            sources.append(rule.source)
        markers = [{"name": m.name, "tag": m.tag, "private": m.private} for m in self.markers.values()]
        names = [m["name"] for m in markers]
        self.wire_sources = sources
        return {"rules": rules, "markers": markers, "sources": sources,
                "policy_id": wire_policy_id(rules, names)}


def _is_dir(entry: Any) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


class Group:
    """The children of one folder that roll up into one record: the
    entries (names, in memory only), how they were matched, and for an agent
    scan the rollup entry the agent made."""
    __slots__ = ("tag", "rule", "private", "members", "agent", "matched", "store")

    def __init__(self, tag: str, rule: str, private: bool) -> None:
        self.tag, self.rule, self.private = tag, rule, private
        self.members: list[Any] = []            # entries (os.DirEntry) or (path, is_dir)
        self.agent: dict[str, Any] | None = None
        self.matched = 0
        self.store: Any = None                  # the backup.Store whose bulk folders these are

    def add(self, member: Any) -> None:
        self.members.append(member)
        self.matched += 1


# --- summing -------------------------------------------------------------------
def classify(exc: BaseException) -> str:
    """The protocol's code for an OSError: permission_denied, not_found or
    io. Reads the numbers only, never the message (it holds the file name)."""
    number = getattr(exc, "errno", None)
    win = getattr(exc, "winerror", None)
    if isinstance(exc, PermissionError) or number in (errno.EACCES, errno.EPERM) or win in (5, 1314):
        return "permission_denied"
    if isinstance(exc, FileNotFoundError) or number == errno.ENOENT or win in (2, 3):
        return "not_found"
    return "io"


@dataclass
class Totals:
    matched: int = 0
    total_files: int = 0
    total_dirs: int = 0
    size: int = 0
    allocated: int | None = None            # agent sums only
    newest: int = 0
    oldest: int | None = None
    errors: int = 0
    error_codes: dict[str, int] = field(default_factory=dict)
    vanished: int = 0
    skipped_mounts: int = 0
    hardlink_names: int | None = None       # agent sums only
    complete: bool = True

    def count_error(self, code: str) -> None:
        if code == "not_found":
            self.vanished += 1
            return
        self.errors += 1
        self.error_codes[code] = self.error_codes.get(code, 0) + 1

    def seen_file(self, size: int, mtime_ns: int) -> None:
        mtime_ns -= mtime_ns % 100          # rolled up at 100 ns, the agent protocol's resolution
        self.total_files += 1
        self.size += size
        if mtime_ns > self.newest:
            self.newest = mtime_ns
        if self.oldest is None or mtime_ns < self.oldest:
            self.oldest = mtime_ns

    def merge(self, other: "Totals") -> None:
        self.matched += other.matched
        self.total_files += other.total_files
        self.total_dirs += other.total_dirs
        self.size += other.size
        if other.allocated is not None:
            self.allocated = (self.allocated or 0) + other.allocated
        self.newest = max(self.newest, other.newest)
        if other.oldest is not None and (self.oldest is None or other.oldest < self.oldest):
            self.oldest = other.oldest
        self.errors += other.errors
        for code, n in other.error_codes.items():
            self.error_codes[code] = self.error_codes.get(code, 0) + n
        self.vanished += other.vanished
        self.skipped_mounts += other.skipped_mounts
        if other.hardlink_names is not None:
            self.hardlink_names = (self.hardlink_names or 0) + other.hardlink_names
        self.complete = self.complete and other.complete

    @classmethod
    def from_summary(cls, s: Any) -> "Totals":
        """The totals of an agent's `sum_subtree` answer (agent_client.SubtreeSummary)."""
        return cls(total_files=s.total_files, total_dirs=s.total_dirs, size=s.total_size,
                   allocated=s.total_allocated_size, newest=s.newest_mtime_ns, oldest=s.oldest_mtime_ns,
                   errors=s.errors, error_codes=dict(s.error_codes), vanished=s.vanished,
                   skipped_mounts=s.skipped_mounts, hardlink_names=s.hardlink_names or None,
                   complete=s.complete)

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> "Totals":
        """The totals a stored rollup record holds (a carried-forward store rollup)."""
        info = (doc.get("probe") or {}).get("rollup") or {}
        return cls(matched=info.get("matched", 0), total_files=info.get("total_files", 0),
                   total_dirs=info.get("total_dirs", 0), size=doc.get("size") or 0,
                   allocated=doc.get("allocated_size"), newest=info.get("newest_mtime_ns", 0),
                   oldest=info.get("oldest_mtime_ns"), errors=info.get("errors", 0),
                   error_codes=dict(info.get("error_codes") or {}), vanished=info.get("vanished", 0),
                   skipped_mounts=info.get("skipped_mounts", 0), hardlink_names=info.get("hardlink_names"))

    def to_probe(self, tag: str, rule: str, via: str, policy: str,
                 now: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tag": tag, "rule": rule, "matched": self.matched, "total_files": self.total_files,
            "total_dirs": self.total_dirs, "newest_mtime_ns": self.newest}
        if self.oldest is not None and self.total_files:
            out["oldest_mtime_ns"] = self.oldest
        out.update(errors=self.errors, error_codes=dict(self.error_codes), vanished=self.vanished,
                   skipped_mounts=self.skipped_mounts)
        if self.hardlink_names is not None:
            out["hardlink_names"] = self.hardlink_names
        out.update(partial=self.errors > 0, via=via,
                   summed_at=now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   policy=policy)
        return out

    def error_message(self) -> str | None:
        """The one `errors` entry a rollup record may carry: only when some
        failure other than permission_denied happened, and counts only."""
        if not self.errors or self.errors == self.error_codes.get("permission_denied", 0):
            return None
        detail = ", ".join(f"{c} {n}" for c, n in sorted(self.error_codes.items()))
        return f"{self.errors} entries could not be read ({detail}); the totals are a lower bound"


def rollup_path(parent_rel: str, tag: str) -> str:
    return f"{parent_rel}/{tag}" if parent_rel else tag


def store_tag(store: Any) -> str:
    """The tag a store's bulk folders roll up under."""
    return "[DATABASE]" if getattr(store, "probe_key", "backup") == "database" else "[BACKUP]"


def rollup_document(root: str, parent_rel: str, tag: str, totals: Totals, *, rule: str, via: str,
                    policy: str, store: dict[str, Any] | None = None, fp: str | None = None,
                    migrated: bool = False) -> dict[str, Any]:
    """The record of a rollup: `<parent>/[TAG]`, kind "rollup", the totals,
    and no name of anything inside. A store's rollup also says which store
    (`rollup.store`) and carries its fingerprint (`rollup.fp`)."""
    doc = record.new_document(root, rollup_path(parent_rel, tag), kind="rollup", size=totals.size,
                              mtime_ns=totals.newest, name=tag)
    if totals.allocated is not None:
        doc["allocated_size"] = totals.allocated
    doc["probe"] = {"rollup": totals.to_probe(tag, rule, via, policy)}
    if store is not None:
        doc["probe"]["rollup"]["store"] = store
    if fp is not None:
        doc["probe"]["rollup"]["fp"] = fp
    if migrated:
        doc["probe"]["rollup"]["migrated"] = True
    message = totals.error_message()
    if message:
        record.add_error(doc, "rollup", message)
    return doc


def _reparse(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def sum_tree(path: str, *, is_dir: bool = True, count_self: bool = True,
             cancel: threading.Event | None = None, deadline: float | None = None) -> Totals:
    """Totals of the tree at `path` (or of the one file): an iterative
    scandir walk that keeps only integers. A link is a file of its own size
    and a folder reached through one is not entered (`skipped_mounts`). Every
    OSError is counted by code where it happens and dropped; `deadline` is a
    time.monotonic() value; `cancel` stops the walk with RollupError.
    Hard links are told apart only where the platform lists them (POSIX)."""
    t = Totals()
    failed = False
    try:
        _sum_into(t, path, is_dir, count_self, cancel, deadline)
    except RollupError:
        raise
    except OSError as exc:
        t.count_error(classify(exc))
    except Exception:
        failed = True
    if failed:
        raise RollupError("rollup failed")      # outside the except block: no cause, no context
    return t


def _sum_into(t: Totals, path: str, is_dir: bool, count_self: bool,
              cancel: threading.Event | None, deadline: float | None) -> None:
    if not is_dir:
        _sum_entry(t, os.lstat(path))
        return
    t.total_dirs += 1 if count_self else 0
    stack = [path]
    seen: set[tuple[int, int]] = set()
    n = 0
    while stack:
        top = stack.pop()
        try:
            it = os.scandir(top)
        except OSError as exc:
            t.count_error(classify(exc))
            continue
        with it:
            while True:
                try:
                    e = next(it, None)
                except OSError as exc:
                    t.count_error(classify(exc))
                    break
                if e is None:
                    break
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError as exc:
                    t.count_error(classify(exc))
                    continue
                n += 1
                if n % CHECK_EVERY == 0:
                    if cancel is not None and cancel.is_set():
                        raise RollupError("rollup cancelled")
                    if deadline is not None and time.monotonic() > deadline:
                        t.complete = False
                        return
                link = _reparse(st) or e.is_symlink()
                if not link and e.is_dir(follow_symlinks=False):
                    t.total_dirs += 1
                    stack.append(e.path)
                    continue
                if link:
                    try:
                        if e.is_dir():
                            t.skipped_mounts += 1
                    except OSError:
                        pass
                elif st.st_nlink > 1 and os.name != "nt":
                    key = (st.st_dev, st.st_ino)
                    if key in seen:
                        t.total_files += 1
                        t.newest = max(t.newest, st.st_mtime_ns - st.st_mtime_ns % 100)
                        continue
                    seen.add(key)
                _sum_entry(t, st)


def _sum_entry(t: Totals, st: os.stat_result) -> None:
    t.seen_file(st.st_size, st.st_mtime_ns)


def make_plan(options: Any, root: str, path: str, backend: Any, *, source: Any = None) -> RollupPlan:
    """The plan for one root of a scan: the configured rules and modes, the
    sticky redactions the backend holds and the key that goes with them. Raises
    redaction.RedactionKeyError when sticky entries exist and their key is
    gone (the scan then stops before it reads anything)."""
    from . import redaction
    cfg = getattr(options, "rollup_config", None) or RollupConfig()
    if source is not None:
        scan_form = "agent"
    elif root.startswith(("\\\\", "//")):
        scan_form = "share"
    else:
        scan_form = "agent" if root.startswith("/") else "local"
    sticky = redaction.open_set(backend, root, create_key_now=source is not None,
                                new_key=getattr(options, "new_redaction_key", False),
                                agent=source is not None)
    return RollupPlan(cfg, root=root, scan_form=scan_form, default_skips=options.default_skips,
                      agent=source.config if source is not None else None,
                      agents=list(getattr(options, "agents", None) or []), sticky=sticky)


def rule_from_wire(raw: dict[str, Any]) -> Rule:
    """A rule as `configure_policy` carries it (patterns normalised), for the
    conformance vectors and tests."""
    pats, dir_only = parse_patterns(raw.get("match", []))
    type_ = raw.get("type", "any")
    return Rule(raw.get("tag"), pats, "dir" if dir_only and type_ == "any" else type_,
                raw.get("case", "sensitive"), bool(raw.get("keep")), bool(raw.get("private")),
                bool(raw.get("suggest")), source=f"wire:{raw.get('id', '')}")


def ruleset_from_wire(raws: list[dict[str, Any]]) -> RuleSet:
    return RuleSet(rule_from_wire(r) for r in raws)
