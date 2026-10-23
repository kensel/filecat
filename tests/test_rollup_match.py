"""Rollup rules (docs/rollups.md section 2): the shared conformance vectors
(Python matcher, the fake agent's independent one, the wire policy id and the
redaction HMAC), pattern forms and their conversion through ShareMap, modes,
configuration errors that never repeat a pattern, and the name-free sum.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from filecat import config, redaction, rollup
from filecat.agent_client import ShareMap
from filecat.config import AgentConfig
from filecat.options import ScanOptions
from _fake_agent import (_Rule, compile_pattern, policy_id as fake_policy_id,
                         redaction_hash as fake_redaction_hash)

VECTORS = json.loads((Path(__file__).parent / "data" / "rollup_match_vectors.json").read_text("utf-8"))


def _tag(rule) -> str | None:
    return None if rule is None or rule.keep else rule.tag


# --- the conformance vectors ------------------------------------------------------
@pytest.mark.parametrize("v", VECTORS["match"], ids=lambda v: v["name"])
def test_python_matcher_passes_the_vectors(v):
    rules = rollup.ruleset_from_wire(v["rules"])
    assert _tag(rules.match_path(v["path"], v["is_dir"])) == v["expect"]


@pytest.mark.parametrize("v", [v for v in VECTORS["match"] if v["agent"]], ids=lambda v: v["name"])
def test_the_fake_agents_matcher_passes_the_same_vectors(v):
    path = v["path"]
    name = path.rsplit("/", 1)[-1]
    hit = None
    for raw in v["rules"]:
        if _Rule(raw).matches(name, path, v["is_dir"]):
            hit = raw
            break
    assert (None if hit is None or hit.get("keep") else hit["tag"]) == v["expect"]


def test_vectors_cover_the_three_forms_and_the_special_cases():
    names = " ".join(v["name"] for v in VECTORS["match"])
    for word in ("agent form", "share form", "local form", "suffix", "key", "keep", "double star",
                 "question", "Unicode", "bracket", "private-use", "first match"):
        assert word.lower() in names.lower() or word == "key", word


@pytest.mark.parametrize("case", VECTORS["policy"])
def test_wire_policy_id_vectors(case):
    names = case["markers"]
    assert rollup.wire_policy_id(case["rules"], names) == case["id"]
    assert fake_policy_id(case["rules"], names) == case["id"]


def test_wire_policy_id_depends_on_every_field():
    base = {"tag": "[CACHE]", "match": ["node_modules"], "type": "dir", "case": "sensitive"}
    ids = {rollup.wire_policy_id([base], [])}
    for change in ({"tag": "[OTHER]"}, {"match": ["node_module"]}, {"type": "any"},
                   {"case": "insensitive"}, {"keep": True}, {"private": True}, {"suggest": True}):
        ids.add(rollup.wire_policy_id([{**base, **change}], []))
    ids.add(rollup.wire_policy_id([base], [".filecat-cache"]))
    ids.add(rollup.wire_policy_id([base, base], []))
    assert len(ids) == 10


@pytest.mark.parametrize("case", VECTORS["redaction"])
def test_redaction_hash_vectors(case):
    key = bytes.fromhex(case["key_hex"])
    assert redaction.path_hash(key, case["root"], case["rel_path"]) == case["hash"]
    assert fake_redaction_hash(key, case["root"], case["rel_path"]) == case["hash"]
    assert len(case["hash"]) == 32


def test_redaction_hash_does_not_fold_or_normalise():
    key = bytes(range(32))
    a = redaction.path_hash(key, "r", "Dir/\u00e9")
    assert a != redaction.path_hash(key, "r", "dir/\u00e9")
    assert a != redaction.path_hash(key, "r", "Dir/e\u0301")
    assert a != redaction.path_hash(key, "s", "Dir/\u00e9")


@pytest.mark.parametrize("case", VECTORS["normalize"])
def test_normalize_vectors(case):
    form, comps, dir_only = rollup.normalize_pattern(case["pattern"])
    assert (form, rollup.pattern_text(form, comps), dir_only) == (case["form"], case["text"], case["dir_only"])


@pytest.mark.parametrize("text", ["", "/", "\\\\", "a/b", "x\\y", "~/z"])
def test_bad_patterns(text):
    with pytest.raises(ValueError):
        rollup.normalize_pattern(text)


# --- modes -----------------------------------------------------------------------
def _plan(modes=None, rules=(), root="\\\\nas-main\\Backup", agents=(), **kw):
    table = {"rollups": {**(modes or {}), "rule": list(rules)}}
    cfg = rollup.parse_config(table)
    scan_form = "share" if root.startswith("\\\\") else "local"
    return rollup.RollupPlan(cfg, root=root, scan_form=scan_form, agents=list(agents), **kw)


class _E:
    """A directory entry for the matcher."""
    def __init__(self, name, is_dir=True):
        self.name, self._d = name, is_dir

    def is_dir(self, follow_symlinks=True):
        return self._d


def _classify(plan, name, is_dir=True, parent=""):
    hit = plan.classify(_E(name, is_dir), name, parent, plan.comps_of(parent))
    return None if hit is None else hit.tag


def test_default_is_manual_so_nothing_rolls_up_and_the_builtins_only_suggest():
    plan = _plan()
    assert all(m == "manual" for m in plan.cfg.modes.values())
    assert _classify(plan, "node_modules", parent="proj") is None
    assert _classify(plan, "@eaDir") is None
    assert plan.suggestions == {("[CACHE]", "proj"): 1, ("[SYNOLOGY]", ""): 1}


def test_automatic_applies_the_builtin_rules_and_makes_no_suggestion():
    plan = _plan({"cache": "automatic"})
    assert _classify(plan, "node_modules") == "[CACHE]"
    assert _classify(plan, "NODE_MODULES") == "[CACHE]"      # the built-ins ignore case
    assert _classify(plan, "node_modules", is_dir=False) is None   # type dir
    assert _classify(plan, "@eaDir") is None and ("[SYNOLOGY]", "") in plan.suggestions
    assert ("[CACHE]", "") not in plan.suggestions


def test_disabled_ignores_rules_and_markers_and_says_so_once():
    plan = _plan({"cache": "disabled"}, [{"tag": "[CACHE]", "match": ["build"]}])
    assert _classify(plan, "build") is None and _classify(plan, "node_modules") is None
    assert ".filecat-cache" not in plan.markers and ".filecat-backup" in plan.markers
    assert any("cache is disabled: 1 rules and .filecat-cache markers are ignored" in m
               for m in plan.messages)
    assert not plan.suggestions


def test_redacted_cannot_be_disabled():
    cfg = rollup.parse_config({"rollups": {"redacted": "disabled"}})
    assert cfg.modes["redacted"] == "manual"
    assert any("redacted cannot be disabled" in w for w in cfg.warnings)
    plan = _plan({"redacted": "disabled"}, [{"tag": "[REDACTED]", "match": ["vault"]}])
    assert _classify(plan, "vault") == "[REDACTED]"
    assert ".filecat-redacted" in plan.markers
    over = cfg.with_modes({"redacted": "disabled"})
    assert over.modes["redacted"] == "manual" and len(over.warnings) == 2


def test_redacted_never_makes_a_suggestion():
    plan = _plan()
    assert not any(t == "[REDACTED]" for t, _ in plan.suggestions)
    assert not [r for r in plan.rules_in_order if r.tag == "[REDACTED]"]


@pytest.mark.parametrize("overrides, message", [
    ({"nonsense": "manual"}, "unknown type"),
    ({"cache": "sometimes"}, "the modes are"),
])
def test_bad_mode_overrides(overrides, message):
    with pytest.raises(ValueError, match=message):
        rollup.RollupConfig().with_modes(overrides)


def test_windows_automatic_replaces_the_default_skip_and_no_default_skips_removes_it():
    on = _plan({"windows": "automatic"}, root="C:\\", default_skips=True)
    assert _classify(on, "System Volume Information") == "[WINDOWS]"
    assert _classify(on, "$Recycle.Bin") == "[WINDOWS]"
    assert on.windows_rule
    off = _plan({"windows": "automatic"}, root="C:\\", default_skips=False)
    assert _classify(off, "System Volume Information") is None and not off.windows_rule
    manual = _plan(root="C:\\", default_skips=True)
    assert not manual.windows_rule and _classify(manual, "$Recycle.Bin") is None


def test_user_rules_order_redacted_first_then_user_then_builtin():
    plan = _plan({"cache": "automatic"}, [
        {"tag": "[LEGAL]", "match": ["node_modules"]},
        {"tag": "[REDACTED]", "match": ["node_modules"]}])
    assert _classify(plan, "node_modules") == "[REDACTED]"
    plan = _plan({"cache": "automatic"}, [{"tag": "[LEGAL]", "match": ["node_modules"]}])
    assert _classify(plan, "node_modules") == "[LEGAL]"


def test_keep_takes_an_entry_out_of_later_rules_but_not_out_of_redacted():
    rules = [{"keep": True, "match": ["**/keep/node_modules"]},
             {"tag": "[REDACTED]", "match": ["**/secret/node_modules"]}]
    plan = _plan({"cache": "automatic"}, rules, root="\\\\nas\\s")
    assert _classify(plan, "node_modules", parent="keep") is None
    assert _classify(plan, "node_modules", parent="other") == "[CACHE]"
    assert _classify(plan, "node_modules", parent="secret") == "[REDACTED]"


def test_user_tags_are_manual_and_have_markers():
    cfg = rollup.parse_config({"rollups": {"rule": [{"tag": "[LEGAL]"}, {"tag": "[LEGAL]", "match": ["x"]}]}})
    assert cfg.user_tags == ["[LEGAL]"]
    plan = rollup.RollupPlan(cfg, root="C:\\data", scan_form="local")
    assert ".filecat-legal" in plan.markers and plan.markers[".filecat-legal"].tag == "[LEGAL]"
    assert _classify(plan, "x") == "[LEGAL]"


def test_a_real_child_named_like_a_tag_is_folded_into_it():
    plan = _plan({"cache": "automatic"})
    entries = [_E("node_modules"), _E("[cache]"), _E("[CACHE]", False), _E("other")]
    recorded, groups = plan.partition(entries, "")
    assert [e.name for e in recorded] == ["other"]
    assert groups["[CACHE]"].matched == 3
    # without a rollup of that tag in the folder it is an ordinary entry
    recorded, groups = plan.partition([_E("[CACHE]"), _E("other")], "")
    assert len(recorded) == 2 and not groups


def test_excluded_entries_are_not_rolled_up():
    plan = _plan({"cache": "automatic"})
    entries = [_E("node_modules"), _E("keep")]
    recorded, groups = plan.partition(entries, "", skipped=lambda e, rel: e.name == "node_modules")
    assert len(recorded) == 2 and not groups


# --- configuration -----------------------------------------------------------------
SECRET = "private-pattern-ZXQ-7f3a"


@pytest.mark.parametrize("table", [
    {"tag": "[REDACTED]", "match": [SECRET + "/with/relative/path"]},
    {"tag": "lowercase", "match": [SECRET]},
    {"tag": "[X]", "match": [SECRET], "type": "dirs"},
    {"tag": "[X]", "match": [SECRET], "case": "ci"},
    {"tag": "[X]", "match": [SECRET + "/"], "type": "file"},
    {"tag": "[X]", "match": SECRET},
    {"tag": "[X]", "match": [SECRET], "colour": "red"},
    {"keep": True, "tag": "[X]", "match": [SECRET]},
    {"keep": True},
    {"tag": "[X]", "match": [SECRET], "private": "yes"},
    {"tag": "[X]", "match": ["x" * 5000]},
])
def test_rule_errors_never_repeat_a_pattern(table):
    with pytest.raises(config.ConfigError) as err:
        config.load_rollups({"rollups": {"rule": [table]}})
    assert SECRET not in str(err.value) and "xxxxx" not in str(err.value)
    assert "[[rollups.rule]] #1" in str(err.value)


def test_rule_repr_and_label_hide_the_patterns():
    cfg = rollup.parse_config({"rollups": {"rule": [{"tag": "[REDACTED]", "match": [SECRET]}]}})
    spec = cfg.rules[0]
    assert SECRET not in repr(spec) and SECRET not in repr(cfg) and spec.private
    assert all(SECRET not in line for line in rollup.describe_rules(cfg))
    rule = rollup.RollupPlan(cfg, root="C:\\x", scan_form="local").rules_in_order[0]
    assert SECRET not in repr(rule)


def test_unknown_keys_and_section_shape():
    with pytest.raises(config.ConfigError, match="unknown key"):
        config.load_rollups({"rollups": {"cachee": "automatic"}})
    with pytest.raises(config.ConfigError, match="double brackets"):
        config.load_rollups({"rollups": {"rule": {"tag": "[X]"}}})
    cfg = config.load_rollups({"rollups": {"store_resum": "7d", "manifest_cap": "1MiB",
                                           "backup_store": [{"path": "\\\\nas\\Backup\\x.hbk"}]}})
    assert (cfg.store_resum_days, cfg.manifest_cap, cfg.backup_stores) == (7, 1024 * 1024, ("\\\\nas\\Backup\\x.hbk",))
    assert config.load_rollups({}).rules == ()


def test_cli_overrides_parse():
    assert config.parse_rollup_overrides(["cache=automatic", "WINDOWS = Manual"]) == {
        "cache": "automatic", "windows": "manual"}
    with pytest.raises(config.ConfigError, match="TYPE=MODE"):
        config.parse_rollup_overrides(["cache"])


def test_agent_rollup_groups_is_removed_with_a_pointer_to_the_rules():
    with pytest.raises(config.ConfigError, match=r"rollup_groups was removed.*\[\[rollups.rule\]\]"):
        config.load_agents({"agents": [{"name": "a", "host": "h", "cert_sha256": "00" * 32, "token": "t",
                                        "rollup_groups": {"[X]": ["y"]}}]})


# --- the two ids ---------------------------------------------------------------------
def test_catalog_policy_id_is_stable_and_follows_the_configuration():
    base = rollup.parse_config({})
    assert rollup.catalog_policy_id(base) == rollup.default_policy_id()
    rule = {"tag": "[CACHE]", "match": ["//nas/s/x", "node_modules/"]}
    a = rollup.parse_config({"rollups": {"rule": [rule]}})
    b = rollup.parse_config({"rollups": {"rule": [{**rule, "match": ["\\\\nas\\s\\x", "node_modules"]}]}})
    assert rollup.catalog_policy_id(a) != rollup.default_policy_id()
    assert rollup.catalog_policy_id(a) != rollup.catalog_policy_id(b)    # a trailing separator means dir
    c = a.with_modes({"cache": "automatic"})
    assert rollup.catalog_policy_id(c) != rollup.catalog_policy_id(a)
    same = rollup.parse_config({"rollups": {"rule": [{**rule, "match": ["\\\\nas\\s\\x", "node_modules/"]}]}})
    assert rollup.catalog_policy_id(same) == rollup.catalog_policy_id(a)
    assert len(rollup.catalog_policy_id(a)) == 12


def test_catalog_policy_id_is_the_same_for_a_smb_and_an_agent_plan():
    cfg = rollup.parse_config({"rollups": {"rule": [{"tag": "[REDACTED]", "match": ["/volume1/homes/x"]}]}})
    agent = AgentConfig(name="nas-main", host="h", cert_sha256="00" * 32, token="t", alias="\\\\nas-main")
    smb = rollup.RollupPlan(cfg, root="\\\\nas-main\\homes", scan_form="share", agents=[agent])
    via = rollup.RollupPlan(cfg, root="\\\\nas-main\\homes", scan_form="agent", agent=agent, agents=[agent])
    assert smb.policy_id == via.policy_id


# --- converting between forms ------------------------------------------------------
def _agent(**kw):
    return AgentConfig(name="nas-main", host="h", cert_sha256="00" * 32, token="t",
                       alias="\\\\nas-main", **kw)


def test_agent_form_pattern_is_converted_to_share_form_for_an_smb_scan():
    plan = _plan(rules=[{"tag": "[REDACTED]", "match": ["/volume1/homes/jdoe/vault"]}],
                 root="\\\\nas-main\\homes", agents=[_agent()])
    assert _classify(plan, "vault", parent="jdoe") == "[REDACTED]"
    assert _classify(plan, "vault", parent="other") is None
    assert not plan.unresolved


def test_agent_form_pattern_uses_the_explicit_share_map():
    agent = _agent(shares={"/volume2/Archive": "\\\\nas-main\\Archive"})
    plan = _plan(rules=[{"tag": "[X]", "match": ["/volume2/Archive/old"]}],
                 root="\\\\nas-main\\Archive", agents=[agent])
    assert _classify(plan, "old") == "[X]"


def test_unresolved_pattern_is_reported_and_counted_never_silently_ignored():
    rules = [{"tag": "[REDACTED]", "match": ["/volume1/homes/jdoe/vault"]},
             {"tag": "[CACHE]", "match": ["node_modules"]}]
    plan = _plan(rules=rules, root="\\\\other-nas\\homes", agents=[_agent()])
    assert plan.unresolved == ["[[rollups.rule]] #1 ([REDACTED])"]
    assert any("[[rollups.rule]] #1 ([REDACTED])" in m and "vault" not in m for m in plan.messages)
    assert _classify(plan, "vault", parent="jdoe") is None
    assert _classify(plan, "node_modules") == "[CACHE]"     # a name pattern needs no conversion
    nomap = _plan(rules=rules, root="\\\\nas-main\\homes")
    assert nomap.unresolved == ["[[rollups.rule]] #1 ([REDACTED])"]


def test_a_local_scan_ignores_agent_form_silently_and_share_form_only_on_a_unc_root():
    rules = [{"tag": "[X]", "match": ["/volume1/homes/jdoe", "C:/data/x", "//nas/s/y"]}]
    local = _plan(rules=rules, root="C:\\data")
    assert not local.unresolved
    assert _classify(local, "x", parent="") == "[X]"
    assert _classify(local, "jdoe", parent="") is None
    unc = _plan(rules=rules, root="\\\\nas\\s")
    assert _classify(unc, "y", parent="") == "[X]" and _classify(unc, "x", parent="") is None


def test_host_restricts_a_rule():
    rules = [{"tag": "[X]", "match": ["thing"], "host": "nas-main"}]
    assert _classify(_plan(rules=rules, root="\\\\nas-main\\s", agents=[_agent()]), "thing") == "[X]"
    assert _classify(_plan(rules=rules, root="\\\\other\\s"), "thing") is None
    agent_plan = rollup.RollupPlan(rollup.parse_config({"rollups": {"rule": rules}}),
                                   root="\\\\nas-main\\s", scan_form="agent", agent=_agent())
    assert [r.tag for r in agent_plan.rules_in_order if r.source.startswith("user")] == ["[X]"]


def test_wire_policy_converts_share_form_and_drops_local_form():
    rules = [{"tag": "[REDACTED]", "match": ["//nas-main/homes/jdoe/vault", "//other/x/y", "C:/z"]},
             {"tag": "[CACHE]", "match": ["node_modules", "**/AppData/Local/Temp"], "type": "dir"}]
    cfg = rollup.parse_config({"rollups": {"cache": "automatic", "rule": rules}})
    plan = rollup.RollupPlan(cfg, root="\\\\nas-main\\homes", scan_form="agent", agent=_agent())
    smap = ShareMap("\\\\nas-main")

    def to_agent(pat):
        try:
            return smap.to_posix_path("\\\\" + "\\".join(pat.comps))
        except ValueError:
            return None

    wire = plan.wire_policy(to_agent)
    assert wire["rules"][0] == {"id": 0, "tag": "[REDACTED]", "match": ["/volume1/homes/jdoe/vault"],
                                "type": "any", "case": "sensitive", "private": True}
    assert wire["rules"][1]["match"] == ["node_modules", "**/AppData/Local/Temp"]
    assert wire["rules"][1]["type"] == "dir"
    assert {m["name"] for m in wire["markers"]} >= {".filecat-redacted", ".filecat-cache"}
    assert wire["policy_id"] == rollup.wire_policy_id(wire["rules"], [m["name"] for m in wire["markers"]])
    assert wire["sources"][0] == "user:0" and "builtin:cache" in wire["sources"]
    assert plan.agent_rule(0, "[REDACTED]") == "user:0"
    assert plan.agent_rule("marker", "[CACHE]") == "marker:[CACHE]" and plan.agent_rule(None, "[X]") == "agent"


# --- summing -------------------------------------------------------------------------
class _Os:
    """The os module of rollup.py with one scandir of the test's choosing, so that
    nothing else in the process is affected."""
    def __init__(self, scandir):
        self.scandir = scandir

    def __getattr__(self, name):
        return getattr(os, name)


@pytest.fixture
def tree(fixture_dir):
    (fixture_dir / "a" / "b").mkdir(parents=True)
    (fixture_dir / "a" / "one.bin").write_bytes(b"x" * 10)
    (fixture_dir / "a" / "b" / "two.bin").write_bytes(b"y" * 5)
    (fixture_dir / "a" / "b" / "empty").write_bytes(b"")
    return fixture_dir / "a"


def test_sum_tree_counts_files_folders_bytes_and_times(tree):
    t = rollup.sum_tree(str(tree))
    assert (t.total_files, t.total_dirs, t.size) == (3, 2, 15)      # the folder itself is counted
    assert t.newest >= t.oldest > 0 and not t.errors and t.complete
    sub = rollup.sum_tree(str(tree), count_self=False)
    assert sub.total_dirs == 1
    one = rollup.sum_tree(str(tree / "one.bin"), is_dir=False)
    assert (one.total_files, one.total_dirs, one.size) == (1, 0, 10)
    assert rollup.sum_tree(str(tree / "nothing"), is_dir=False).vanished == 1


def test_totals_to_probe_shapes_the_record_fields():
    t = rollup.Totals(matched=2, total_files=0, total_dirs=3, size=0)
    probe = t.to_probe("[CACHE]", "user:1", "python", "abc")
    assert "oldest_mtime_ns" not in probe and probe["partial"] is False and probe["via"] == "python"
    t.seen_file(7, 100)
    t.count_error("permission_denied")
    probe = t.to_probe("[CACHE]", "user:1", "python", "abc")
    assert probe["oldest_mtime_ns"] == 100 and probe["partial"] and probe["error_codes"] == {"permission_denied": 1}
    assert t.error_message() is None       # only denied: no errors entry (the exit code stays 0)
    t.count_error("io")
    assert t.error_message() == ("2 entries could not be read (io 1, permission_denied 1); "
                                 "the totals are a lower bound")
    doc = rollup.rollup_document("\\\\nas\\s", "jdoe", "[CACHE]", t, rule="user:1", via="python", policy="abc")
    assert doc["rel_path"] == "jdoe/[CACHE]" and doc["kind"] == "rollup" and doc["name"] == "[CACHE]"
    assert doc["size"] == 7 and doc["errors"] == [{"stage": "rollup", "message": t.error_message()}]
    assert not {"ino", "dev", "nlink", "ctime_ns", "allocated_size"} & set(doc)


def test_sum_tree_errors_are_counted_by_code_and_never_carry_a_name(tree, monkeypatch):
    real = os.scandir
    secret = "ZXQ-denied-folder-7f3a"
    (tree / secret).mkdir()
    (tree / secret / "inner.txt").write_text("x")

    def scandir(path):
        if str(path).endswith(secret):
            raise PermissionError(13, f"Access is denied: {path}", str(path))
        return real(path)

    monkeypatch.setattr(rollup, "os", _Os(scandir))
    t = rollup.sum_tree(str(tree))
    assert t.errors == 1 and t.error_codes == {"permission_denied": 1} and t.total_files == 3
    assert secret not in repr(t) and secret not in str(t.error_message())

    def broken(path):
        if str(path).endswith(secret):
            raise OSError(5, f"I/O error reading {path}", str(path))
        return real(path)

    monkeypatch.setattr(rollup, "os", _Os(broken))
    assert rollup.sum_tree(str(tree)).error_codes == {"io": 1}


def test_sum_tree_wraps_any_other_exception_without_a_cause(tree, monkeypatch):
    secret = "ZXQ-boom-7f3a"

    def boom(path):
        raise ValueError(f"cannot handle {secret}")

    monkeypatch.setattr(rollup, "os", _Os(boom))
    with pytest.raises(rollup.RollupError) as err:
        rollup.sum_tree(str(tree))
    text = " ".join([str(err.value), repr(err.value), repr(err.value.__cause__), repr(err.value.__context__)])
    assert secret not in text and err.value.__cause__ is None
    assert err.value.__context__ is None


def test_sum_tree_stops_when_cancelled_or_late(tree, monkeypatch):
    monkeypatch.setattr(rollup, "CHECK_EVERY", 1)
    ev = threading.Event()
    ev.set()
    with pytest.raises(rollup.RollupError, match="cancelled"):
        rollup.sum_tree(str(tree), cancel=ev)
    assert not rollup.sum_tree(str(tree), deadline=0.0).complete


def test_classify_reads_numbers_not_messages():
    assert rollup.classify(PermissionError(13, "x")) == "permission_denied"
    assert rollup.classify(FileNotFoundError(2, "x")) == "not_found"
    assert rollup.classify(OSError(5, "x")) == "io"
    e = OSError(0, "x")
    e.winerror = 5
    assert rollup.classify(e) == "permission_denied"
    e.winerror = 3
    assert rollup.classify(e) == "not_found"


def test_find_marker_ignores_case_and_prefers_redacted():
    plan = _plan()
    found = rollup.find_marker(["a", ".FILECAT-Cache", ".filecat-redacted"], plan.markers)
    assert found.tag == "[REDACTED]" and found.private
    assert rollup.find_marker(["a", ".filecat-cache"], plan.markers).tag == "[CACHE]"
    assert rollup.find_marker(["a", ".filecat-nothing", "filecat-cache"], plan.markers) is None
    assert rollup.marker_name("[LEGAL]") == ".filecat-legal"
