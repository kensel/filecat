"""Scanning with rollups (docs/rollups.md): rules and markers on local and
agent scans, the record, rescans that replace and clean up, the policy id, the
sticky store, the commands that audit it. The privacy guarantees are in
test_rollup_privacy.py.
"""
from __future__ import annotations

import io
import json
import os
import sys
import uuid
from pathlib import Path

import pytest

import filecat.scan as scan
import filecat.walker as walker_mod
from filecat import cli, redaction, rollup
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.config import AgentConfig
from filecat.options import ScanOptions
from tests.conftest import FIXTURE_ROOT
from tests.test_rollup_match import _Os
from _fake_agent import FakeAgent, cert_fingerprint, floor100

UNC = "\\\\nas-main\\Backup"
MARKERS = {"cache": "[CACHE]", "backup": "[BACKUP]", "database": "[DATABASE]", "synology": "[SYNOLOGY]",
           "windows": "[WINDOWS]", "redacted": "[REDACTED]", "legal": "[LEGAL]"}


def _resume_path() -> str:
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    return str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")


def config(modes: dict | None = None, rules: list | None = None) -> rollup.RollupConfig:
    return rollup.parse_config({"rollups": {**(modes or {}), "rule": rules or []}})


def options(cfg: rollup.RollupConfig | None = None, fake: FakeAgent | None = None, **kw) -> ScanOptions:
    kw.setdefault("identify", "never")
    if fake is not None:
        kw["agents"] = [AgentConfig(name="nas-main", host="127.0.0.1", port=fake.port,
                                    cert_sha256=cert_fingerprint(), token=fake.token,
                                    alias="\\\\nas-main", timeout=5)]
    return ScanOptions(rollup_config=cfg, **kw)


def run_scan(root: str, opts: ScanOptions, backend=None) -> tuple[MemoryBackend, dict, int]:
    backend = backend or MemoryBackend()
    code = scan.scan_roots([root], backend, opts, resume_path=_resume_path())
    return backend, {d["rel_path"]: d for d in backend.list(root=root)}, code


def write(path: Path, data: bytes | str = b"") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


@pytest.fixture
def share(fixture_dir) -> Path:
    root = fixture_dir / "share"
    write(root / "proj" / "node_modules" / "pkg" / "a.js", b"12345")
    write(root / "proj" / "node_modules" / "b.js", b"1234567")
    write(root / "proj" / ".cache" / "c.bin", b"x" * 100)
    write(root / "proj" / "[CACHE]" / "real.txt", b"abc")
    write(root / "proj" / "src" / "m.py", b"print(1)\n")
    write(root / "docs" / "readme.txt", b"hello\n")
    return root


def add_markers(root: Path) -> Path:
    """One folder per marker type under mk/, each with a file of 10 bytes."""
    for name in MARKERS:
        write(root / "mk" / f"m-{name}" / "f.bin", b"y" * 10)
        write(root / "mk" / f"m-{name}" / f".filecat-{name}")
    return root


def rollups_of(docs: dict) -> dict:
    return {rel: d for rel, d in docs.items() if d["kind"] == "rollup"}


# --- the record -------------------------------------------------------------------
def test_cache_rules_roll_up_and_the_record_has_the_counts_and_no_names(share):
    cfg = config({"cache": "automatic"})
    backend, docs, code = run_scan(str(share), options(cfg))
    assert code == 0
    roll = docs["proj/[CACHE]"]
    assert roll["kind"] == "rollup" and roll["name"] == "[CACHE]" and roll["size"] == 5 + 7 + 100 + 3
    info = roll["probe"]["rollup"]
    assert (info["tag"], info["rule"], info["matched"]) == ("[CACHE]", "builtin:cache", 3)
    assert (info["total_files"], info["total_dirs"]) == (4, 4)      # node_modules, pkg, .cache, [CACHE]
    assert info["newest_mtime_ns"] == roll["mtime_ns"] > info["oldest_mtime_ns"] - 1
    assert (info["errors"], info["error_codes"], info["vanished"], info["skipped_mounts"]) == (0, {}, 0, 0)
    assert info["partial"] is False and info["via"] == "python" and info["policy"] == rollup.catalog_policy_id(cfg)
    assert not {"ino", "dev", "nlink", "ctime_ns", "allocated_size", "errors"} & set(roll)
    assert "hardlink_names" not in info
    # nothing is recorded beneath it, and the folded names are nowhere
    assert not [r for r in docs if r.startswith("proj/node_modules") or r.startswith("proj/.cache")]
    assert not [r for r in docs if r.startswith("proj/[CACHE]/")]
    assert docs["proj"]["probe"]["child_count"] == 2 and docs["proj"]["probe"]["rollup_tags"] == ["[CACHE]"]
    assert docs["proj"]["size"] == 0
    assert "proj/src/m.py" in docs
    assert not list(backend.list_dropped(str(share)))


def test_the_default_changes_nothing_but_makes_suggestions(share):
    backend, docs, _ = run_scan(str(share), options())
    assert docs["proj/[CACHE]"]["kind"] == "dir"        # manual: the real folder of that name is just a folder
    assert "proj/node_modules/pkg/a.js" in docs and "proj/.cache/c.bin" in docs
    info = backend.get_root_info(str(share))
    sug = info["suggestions"]
    assert {"tag": "[CACHE]", "parent": "proj", "matched": 2} in sug["items"]      # node_modules, .cache
    assert all(i["tag"] != "[REDACTED]" for i in sug["items"])
    assert "rollup_policy" not in docs[""]["probe"]         # the default policy id is not stored


def test_markers_of_every_type_roll_their_folder_up_under_its_parent(share):
    add_markers(share)
    cfg = config(rules=[{"tag": "[LEGAL]"}])
    backend, docs, code = run_scan(str(share), options(cfg))
    assert code == 0
    for name, tag in MARKERS.items():
        roll = docs[f"mk/{tag}"]
        assert roll["probe"]["rollup"]["rule"] == f"marker:{tag}"
        assert roll["probe"]["rollup"]["total_files"] == 2 and roll["size"] == 10     # the marker is a file inside
    assert not [r for r in docs if r.startswith("mk/m-")]
    assert docs["mk"]["probe"]["child_count"] == 7 and len(docs["mk"]["probe"]["rollup_tags"]) == 7


def test_a_disabled_types_markers_are_ignored(share, capsys):
    add_markers(share)
    cfg = config({"cache": "disabled"})
    _, docs, _ = run_scan(str(share), options(cfg))
    assert "mk/m-cache/f.bin" in docs and "mk/[CACHE]" not in docs
    assert "cache is disabled" in capsys.readouterr().err


def test_a_marker_in_the_scanned_root_rolls_the_whole_root_up(fixture_dir):
    root = fixture_dir / "everything"
    write(root / "a" / "x.bin", b"123")
    write(root / "y.bin", b"45")
    write(root / ".filecat-cache")
    backend, docs, code = run_scan(str(root), options())
    assert code == 0 and set(docs) == {"", "[CACHE]"}
    info = docs["[CACHE]"]["probe"]["rollup"]
    assert (info["total_files"], info["total_dirs"], docs["[CACHE]"]["size"]) == (3, 1, 5)
    assert docs[""]["probe"]["child_count"] == 1
    # records of an earlier scan, made before the marker, are replaced (deleted, not dropped)
    root2 = fixture_dir / "later"
    write(root2 / "a" / "x.bin", b"123")
    b2, d2, _ = run_scan(str(root2), options())
    assert "a/x.bin" in d2
    write(root2 / ".filecat-cache")
    _, d2, _ = run_scan(str(root2), options(), b2)
    assert set(d2) == {"", "[CACHE]"} and not list(b2.list_dropped(str(root2)))


def test_a_folder_marked_after_a_scan_is_replaced_even_when_its_parent_did_not_change(share):
    backend, docs, _ = run_scan(str(share), options())
    assert "docs/readme.txt" in docs
    parent_mtime = os.stat(share).st_mtime_ns
    write(share / "docs" / ".filecat-redacted")
    os.utime(share, ns=(parent_mtime, parent_mtime))        # the parent folder looks unchanged
    _, docs, _ = run_scan(str(share), options(), backend)
    assert "docs/readme.txt" not in docs and "docs" not in docs
    assert docs["[REDACTED]"]["probe"]["rollup"]["total_files"] == 2
    assert not list(backend.list_dropped(str(share)))


def test_rescan_replaces_the_rollup_and_counts_change(share):
    cfg = config({"cache": "automatic"})
    backend, docs, _ = run_scan(str(share), options(cfg))
    before = docs["proj/[CACHE]"]["size"]
    write(share / "proj" / ".cache" / "more.bin", b"z" * 50)
    _, docs, _ = run_scan(str(share), options(cfg), backend)
    assert docs["proj/[CACHE]"]["size"] == before + 50
    assert len(list(backend.list(kind="rollup", root=str(share)))) == 1
    # nothing recorded under it appears after a rescan either
    assert not [r for r in docs if r.startswith("proj/.cache")]


def test_a_rule_that_stops_matching_deletes_the_stale_rollup(share):
    cfg = config({"cache": "automatic"})
    backend, docs, _ = run_scan(str(share), options(cfg))
    assert "proj/[CACHE]" in docs
    _, docs, _ = run_scan(str(share), options(config()), backend)
    assert "proj/[CACHE]" not in [r for r, d in docs.items() if d["kind"] == "rollup"]
    assert "proj/node_modules/pkg/a.js" in docs         # recorded as before
    assert docs["proj"]["probe"]["child_count"] == 4     # .cache, [CACHE], node_modules, src


def test_names_now_rolled_up_are_deleted_not_dropped_and_the_policy_relists(share):
    backend, docs, _ = run_scan(str(share), options())
    assert "proj/node_modules/pkg/a.js" in docs
    measured: list[str] = []
    real = scan.measure_file

    def counting(root, rel, abs_path, st, opts, ident):
        measured.append(rel)
        return real(root, rel, abs_path, st, opts, ident)

    cfg = config({"cache": "automatic"})
    code = None
    import filecat.scan
    orig = filecat.scan.measure_file
    filecat.scan.measure_file = counting
    try:
        _, docs, code = run_scan(str(share), options(cfg), backend)
    finally:
        filecat.scan.measure_file = orig
    assert code == 0
    assert not [r for r in docs if r.startswith("proj/node_modules/") or r.startswith("proj/.cache/")]
    assert "proj/[CACHE]" in docs and docs["proj"]["probe"]["child_count"] == 2
    assert not list(backend.list_dropped(str(share)))
    assert measured == []       # relisted, but nothing that matched its record was measured again
    assert docs[""]["probe"]["rollup_policy"] == rollup.catalog_policy_id(cfg)


def test_the_stale_pass_is_not_run_for_unchanged_folders_with_rollups(share):
    cfg = config({"cache": "automatic"})
    add_markers(share)
    backend, _, _ = run_scan(str(share), options(cfg))
    run_scan(str(share), options(cfg), backend)     # NTFS bumps a folder's mtime lazily: settle it first
    queried: list[dict] = []
    real_query = backend.query
    backend.query = lambda q: (queried.append(q), real_query(q))[1]
    _, _, code = run_scan(str(share), options(cfg), backend)
    assert code == 0 and not [q for q in queried if "parent" in q]      # no folder's children were listed


def test_windows_automatic_replaces_the_default_skip_with_a_rollup(fixture_dir):
    root = fixture_dir / "drive"
    write(root / "$Recycle.Bin" / "S-1" / "gone.txt", b"123456")
    write(root / "System Volume Information" / "tracking.log", b"12")
    write(root / "keep.txt", b"k")
    _, docs, _ = run_scan(str(root), options())
    assert set(docs) == {"", "keep.txt"}                 # skipped, not recorded, not counted
    cfg = config({"windows": "automatic"})
    _, docs, _ = run_scan(str(root), options(cfg))
    assert docs["[WINDOWS]"]["probe"]["rollup"]["matched"] == 2 and docs["[WINDOWS]"]["size"] == 8
    _, docs, _ = run_scan(str(root), options(cfg, default_skips=False))
    assert "$Recycle.Bin/S-1/gone.txt" in docs and "[WINDOWS]" not in docs      # walked as before


def test_unreadable_folders_inside_a_rollup_are_counted_and_the_exit_code_stays_0(share, monkeypatch):
    real = os.scandir

    def scandir(path):
        if os.path.basename(str(path)) == "pkg":
            raise PermissionError(13, "Access is denied", str(path))
        return real(path)

    monkeypatch.setattr(rollup, "os", _Os(scandir))
    _, docs, code = run_scan(str(share), options(config({"cache": "automatic"})))
    info = docs["proj/[CACHE]"]["probe"]["rollup"]
    assert code == 0 and info["errors"] == 1 and info["error_codes"] == {"permission_denied": 1}
    assert info["partial"] is True and "errors" not in docs["proj/[CACHE]"]
    assert info["total_files"] == 3        # a.js is under the folder that could not be read


def test_other_failures_put_a_counts_only_error_on_the_rollup_and_exit_1(share, monkeypatch):
    real = os.scandir

    def scandir(path):
        if os.path.basename(str(path)) == "pkg":
            raise OSError(5, f"I/O error on {path}", str(path))
        return real(path)

    monkeypatch.setattr(rollup, "os", _Os(scandir))
    _, docs, code = run_scan(str(share), options(config({"cache": "automatic"})))
    assert code == 1
    assert docs["proj/[CACHE]"]["errors"] == [{"stage": "rollup", "message":
                                               "1 entries could not be read (io 1); the totals are a lower bound"}]


def test_the_progress_line_names_the_rollup_not_what_is_in_it(share, capsys):
    run_scan(str(share), options(config({"cache": "automatic"}), progress_interval=0))
    err = capsys.readouterr().err
    assert "rollups (" in err and "[CACHE]" in err
    assert "node_modules" not in err and "pkg" not in err


def test_the_root_index_counts_rollups_apart_from_files(share):
    backend, docs, _ = run_scan(str(share), options(config({"cache": "automatic"})))
    last = backend.get_root_info(str(share))["last_scan"]
    assert last["rollups"] == 1 and last["rollup_bytes"] == 115
    files = sum(1 for d in docs.values() if d["kind"] not in ("dir", "rollup"))
    assert last["files"] == files and last["dirs"] == sum(1 for d in docs.values() if d["kind"] == "dir")
    assert last["bytes"] == sum(d["size"] for d in docs.values() if d["kind"] not in ("dir", "rollup"))


def test_ollama_kinds_rejects_rollup(capsys):
    assert cli.main(["scan", "x", "--ollama", "--model", "m", "--ollama-kinds", "unknown,rollup"]) == 2
    assert "not a file" in capsys.readouterr().err


# --- readers ignore rollups ------------------------------------------------------------
def test_aggregates_browse_and_enrich_treat_a_rollup_as_not_a_file(share):
    from filecat import browse, enrich
    backend, docs, _ = run_scan(str(share), options(config({"cache": "automatic"})))
    files = [d for d in docs.values() if d["kind"] not in ("dir", "rollup")]
    summary = backend.summary(root=str(share))["roots"][str(share)]
    assert summary["total_files"] == len(files) and summary["total_bytes"] == sum(d["size"] for d in files)
    q = browse.normalize({"root": str(share), "files_only": "1", "limit": "500"})
    assert backend.query(q)["total"] == len(files)
    q = browse.normalize({"root": str(share), "kind": "rollup"})
    assert backend.query(q)["total"] == len(rollups_of(docs))
    q = browse.normalize({"root": str(share), "parent": "proj", "limit": "50"})
    kinds = [r["kind"] for r in backend.query(q)["rows"]]
    assert kinds.index("rollup") > kinds.index("dir") and "rollup" in kinds
    assert all(r["kind"] != "rollup" for r in backend.list_sized(0, root=str(share)))
    assert enrich.needs(docs["proj/[CACHE]"], set(enrich.STAGES), ScanOptions(), True) == (False, False)
    assert not [r for r in backend.sizes(str(share), "proj") if "[CACHE]" in r[0]]
    assert backend.subtree(str(share), "")[0]["files"] >= 1
    roll = backend.rollup_totals(str(share))[str(share)]
    assert {r["tag"] for r in roll} == {"[CACHE]"} and roll[0]["size"] == 115 and roll[0]["parent"] == "proj"
    assert [d["rel_path"] for d in backend.rollups(str(share), "proj")] == ["proj/[CACHE]"]
    assert list(backend.rollups(str(share), "docs")) == []


def test_dupes_skip_rollups():
    from filecat import dupes_cmd
    docs = [{"kind": "rollup", "size": 10 ** 9, "root": "r", "rel_path": "a/[CACHE]"},
            {"kind": "rollup", "size": 10 ** 9, "root": "r", "rel_path": "b/[CACHE]"}]
    clusters, errors = dupes_cmd.find_duplicates(docs, lambda r, p: "x", min_size=1, samples=2, window=1)
    assert clusters == [] and errors == []


# --- the same tree through a filecat-agent ---------------------------------------------
@pytest.fixture
def nas(fixture_dir) -> Path:
    return fixture_dir / "nas"


def build_nas(nas: Path, markers: bool = False) -> Path:
    share = nas / "volume1" / "Backup"
    write(share / "proj" / "node_modules" / "pkg" / "a.js", b"12345")
    write(share / "proj" / "node_modules" / "b.js", b"1234567")
    write(share / "proj" / ".cache" / "c.bin", b"x" * 100)
    write(share / "proj" / "[CACHE]" / "real.txt", b"abc")
    write(share / "proj" / "src" / "m.py", b"print(1)\n")
    write(share / "docs" / "readme.txt", b"hello\n")
    return add_markers(share) if markers else share


COMPARE = ("kind", "size", "name", "rel_path")
VOLATILE = ("via", "summed_at")


def shape(docs: dict) -> dict:
    out = {}
    for rel, d in docs.items():
        if d["kind"] != "rollup":
            continue
        probe = {k: v for k, v in d["probe"]["rollup"].items() if k not in VOLATILE}
        out[rel] = ({k: d[k] for k in COMPARE}, floor100(d["mtime_ns"]), probe)
    return out


def test_the_same_tree_gives_the_same_rollups_locally_and_through_the_agent(nas):
    local = build_nas(nas, markers=True)
    cfg = config({"cache": "automatic"}, [{"tag": "[LEGAL]"}])
    with FakeAgent(nas) as fake:
        _, a, code_a = run_scan(UNC, options(cfg, fake))
        _, b, code_b = run_scan(str(local), options(cfg))
    assert code_a == code_b == 0
    assert {d["probe"]["rollup"]["via"] for d in rollups_of(a).values()} == {"agent"}
    assert {d["probe"]["rollup"]["via"] for d in rollups_of(b).values()} == {"python"}
    sa, sb = shape(a), shape(b)
    assert len(sa) == 8
    for rel in sb:
        assert sa[rel][1:] == sb[rel][1:], rel
        assert {k: v for k, v in sa[rel][0].items() if k != "name"} == \
            {k: v for k, v in sb[rel][0].items() if k != "name"}, rel
    assert "allocated_size" in a["proj/[CACHE]"] and "allocated_size" not in b["proj/[CACHE]"]
    assert a["proj/[CACHE]"]["probe"]["rollup"]["rule"] == "builtin:cache"
    assert a["mk/[REDACTED]"]["probe"]["rollup"]["rule"] == "marker:[REDACTED]"
    assert set(r for r, d in a.items() if d["kind"] != "rollup") == set(r for r, d in b.items() if d["kind"] != "rollup")


def test_agent_hard_links_are_counted_once_across_the_rollup_and_mounts_are_skipped(nas):
    share = build_nas(nas)
    os.link(share / "proj" / "node_modules" / "b.js", share / "proj" / ".cache" / "b-link.js")
    write(share / "proj" / "node_modules" / "mnt" / "huge.bin", b"h" * 1000)
    with FakeAgent(nas) as fake:
        fake.mounts = {"mnt"}
        _, docs, _ = run_scan(UNC, options(config({"cache": "automatic"}), fake))
    info = docs["proj/[CACHE]"]["probe"]["rollup"]
    assert info["hardlink_names"] == 1 and info["skipped_mounts"] == 1
    assert docs["proj/[CACHE]"]["size"] == 5 + 7 + 100 + 3      # the link and the mount add nothing
    assert info["total_files"] == 5      # names, hard links counted per name


def test_the_agent_gets_rules_markers_and_an_id_it_answers_with(nas):
    build_nas(nas)
    cfg = config({"cache": "automatic"}, [{"tag": "[REDACTED]", "match": ["//nas-main/Backup/docs"]}])
    with FakeAgent(nas) as fake:
        _, docs, code = run_scan(UNC, options(cfg, fake))
        policies = [r["policy"] for r in fake.requests if r["cmd"] == "configure_policy" and r["policy"].get("rules")]
    assert code == 0
    assert policies and all(p["rules"][0]["match"] == ["/volume1/Backup/docs"] for p in policies)
    assert all(p["rules"][0]["private"] for p in policies)
    assert {m["name"] for m in policies[0]["markers"]} >= {".filecat-redacted", ".filecat-cache"}
    assert docs["[REDACTED]"]["probe"]["rollup"]["rule"] == "user:0"
    assert "docs/readme.txt" not in docs


def test_a_policy_id_mismatch_stops_the_scan_before_anything_is_listed(nas, monkeypatch, capsys):
    build_nas(nas)
    import _fake_agent
    monkeypatch.setattr(_fake_agent, "policy_id", lambda rules, markers: "000000000000")
    with FakeAgent(nas) as fake:
        code = scan.scan_roots([UNC], MemoryBackend(), options(config({"cache": "automatic"}), fake),
                               resume_path=_resume_path())
        listed = [r for r in fake.requests if r["cmd"] == "list_dir"]
    assert code == 2 and [r["path"] for r in listed] == ["/volume1"]     # only the share names, to spell a pattern
    assert "policy id differs" in capsys.readouterr().err


def test_suggestions_through_the_agent_are_counted_without_names(nas):
    build_nas(nas)
    with FakeAgent(nas) as fake:
        backend, docs, _ = run_scan(UNC, options(config(), fake))
    assert "proj/node_modules/b.js" in docs
    items = backend.get_root_info(UNC)["suggestions"]["items"]
    assert {"tag": "[CACHE]", "parent": "proj", "matched": 2} in items or \
        {"tag": "[CACHE]", "parent": "proj", "matched": 3} in items
    assert all(i["tag"] != "[REDACTED]" for i in items)


def test_a_rule_naming_a_folder_other_than_the_agents_is_not_sent_and_is_counted(nas):
    build_nas(nas)
    cfg = config(rules=[{"tag": "[REDACTED]", "match": ["//other/share/x"]}])
    with FakeAgent(nas) as fake:
        backend, docs, code = run_scan(UNC, options(cfg, fake))
        sent = [r["policy"] for r in fake.requests if r["cmd"] == "configure_policy"]
    assert code == 0 and not any(p.get("rules") for p in sent if p.get("rules") and "other" in json.dumps(p))
    assert "docs/readme.txt" in docs


# --- sticky redaction --------------------------------------------------------------------
def secret_tree(root: Path) -> Path:
    write(root / "vault" / "notes.txt", b"private notes")
    write(root / "vault" / ".filecat-redacted")
    write(root / "open" / "pub.txt", b"public")
    return root


def test_a_marker_makes_a_sticky_entry_that_outlives_the_marker(fixture_dir):
    root = secret_tree(fixture_dir / "s")
    backend, docs, _ = run_scan(str(root), options())
    assert "[REDACTED]" in docs and "vault" not in docs
    (entry,) = backend.redactions(str(root))
    assert entry["status"] == "active" and entry["source"] == "marker" and entry["parent"] == ""
    assert len(entry["path_hash"]) == 32 and "vault" not in json.dumps(entry)
    os.remove(root / "vault" / ".filecat-redacted")             # the marker is gone
    _, docs, _ = run_scan(str(root), options(), backend)
    assert "[REDACTED]" in docs and "vault/notes.txt" not in docs
    assert docs["[REDACTED]"]["probe"]["rollup"]["rule"] == "sticky"
    assert len(backend.redactions(str(root))) == 1


def test_a_restored_folder_is_still_redacted_by_its_path(fixture_dir):
    import shutil
    root = secret_tree(fixture_dir / "s")
    backend, _, _ = run_scan(str(root), options())
    shutil.rmtree(root / "vault")
    write(root / "vault" / "other-content.txt", b"restored")
    _, docs, _ = run_scan(str(root), options(), backend)
    assert "vault/other-content.txt" not in docs and docs["[REDACTED]"]["probe"]["rollup"]["total_files"] == 1


def test_a_rule_registers_the_folder_and_it_stays_redacted_after_the_rule_goes(fixture_dir):
    root = fixture_dir / "s"
    write(root / "cfg-1" / "a.txt", b"x")
    write(root / "keep" / "b.txt", b"y")
    cfg = config(rules=[{"tag": "[REDACTED]", "match": ["cfg-*"]}])
    backend, docs, _ = run_scan(str(root), options(cfg))
    assert "[REDACTED]" in docs and backend.redactions(str(root))[0]["source"] == "config"
    _, docs, _ = run_scan(str(root), options(), backend)        # the rule is gone
    assert "cfg-1/a.txt" not in docs and "[REDACTED]" in docs


def test_a_renamed_folder_is_followed_by_inode_through_the_agent(nas):
    share = build_nas(nas)
    write(share / "vault" / "inside.txt", b"hidden")
    write(share / "vault" / ".filecat-redacted")
    with FakeAgent(nas) as fake:
        backend, docs, _ = run_scan(UNC, options(config(), fake))
        (entry,) = backend.redactions(UNC)
        assert entry["ino"] and entry["source"] in ("marker", "agent")
        old_hash = entry["path_hash"]
        os.remove(share / "vault" / ".filecat-redacted")
        os.rename(share / "vault", share / "renamed-vault")
        _, docs, _ = run_scan(UNC, options(config(), fake), backend)
        (entry,) = backend.redactions(UNC)
    assert "renamed-vault/inside.txt" not in docs and not [r for r in docs if "vault" in r]
    assert entry["path_hash"] != old_hash and entry["id"]
    assert docs["[REDACTED]"]["probe"]["rollup"]["total_files"] == 1


def test_a_smb_scan_then_an_agent_scan_find_the_same_sticky_entry(nas):
    share = build_nas(nas)
    write(share / "vault" / "inside.txt", b"hidden")
    write(share / "vault" / ".filecat-redacted")
    with FakeAgent(nas) as fake:
        backend, _, _ = run_scan(UNC, options(config(), fake))
        (entry,) = backend.redactions(UNC)
        os.remove(share / "vault" / ".filecat-redacted")
        # the same root scanned over SMB (here: from disk, recorded under the same name)
        _, docs, _ = run_scan(UNC, options(config(), fake), backend)
    assert backend.redactions(UNC)[0]["id"] == entry["id"] and "vault/inside.txt" not in docs


def test_release_then_approve_in_two_invocations(fixture_dir, capsys):
    root = secret_tree(fixture_dir / "s")
    db = str(fixture_dir / "c.sqlite")
    base = ["--backend", "sqlite", "--out", db]
    backend = SqliteBackend(db)
    run_scan(str(root), options(), backend)
    backend.close()
    assert cli.main(["rollups", "redacted", "list", *base]) == 0
    listing = capsys.readouterr().out
    (entry_id,) = [line.split()[0] for line in listing.splitlines() if line.strip()]
    assert "vault" not in listing and "active" in listing
    assert cli.main(["rollups", "redacted", "approve", entry_id, "--yes", *base]) == 2     # not pending yet
    assert "release" in capsys.readouterr().err
    assert cli.main(["rollups", "redacted", "release", str(root / "vault"), *base]) == 0
    out = capsys.readouterr().out
    assert entry_id in out and "still redacted" in out
    # pending still redacts
    os.remove(root / "vault" / ".filecat-redacted")
    backend = SqliteBackend(db)
    _, docs, _ = run_scan(str(root), options(), backend)
    backend.close()
    assert "vault/notes.txt" not in docs
    assert cli.main(["rollups", "redacted", "list", *base]) == 0 and "pending" in capsys.readouterr().out
    assert cli.main(["rollups", "redacted", "approve", entry_id, "--yes", *base]) == 0
    approved = capsys.readouterr().out
    assert "will list and record the contents of one folder" in approved
    backend = SqliteBackend(db)
    assert backend.redactions() == []
    _, docs, _ = run_scan(str(root), options(), backend)
    backend.close()
    assert "vault/notes.txt" in docs and "[REDACTED]" not in docs


def test_approve_refuses_without_a_terminal_unless_yes(fixture_dir, capsys, monkeypatch):
    root = secret_tree(fixture_dir / "s")
    db = str(fixture_dir / "c.sqlite")
    backend = SqliteBackend(db)
    run_scan(str(root), options(), backend)
    backend.close()
    base = ["--backend", "sqlite", "--out", db]
    assert cli.main(["rollups", "redacted", "release", str(root / "vault"), *base]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    (entry_id,) = [r.split()[0] for r in _lines(cli, ["rollups", "redacted", "list", *base], capsys)]
    assert cli.main(["rollups", "redacted", "approve", entry_id, *base]) == 2
    assert "--yes" in capsys.readouterr().err


def _lines(cli_mod, argv, capsys) -> list[str]:
    capsys.readouterr()
    assert cli_mod.main(argv) == 0
    return [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]


def test_a_lost_key_stops_the_scan_unless_a_new_one_is_asked_for(fixture_dir, capsys):
    root = secret_tree(fixture_dir / "s")
    backend, _, _ = run_scan(str(root), options())
    key = redaction.key_path()
    assert key.exists()
    kid = redaction.key_id(key.read_bytes())
    key.unlink()
    code = scan.scan_roots([str(root)], backend, options(), resume_path=_resume_path())
    err = capsys.readouterr().err
    assert code == 2 and f"redaction key not found (key_id {kid})" in err
    os.remove(root / "vault" / ".filecat-redacted")
    code = scan.scan_roots([str(root)], backend, options(new_redaction_key=True), resume_path=_resume_path())
    assert code == 0 and key.exists() and redaction.key_id(key.read_bytes()) != kid
    docs = {d["rel_path"]: d for d in backend.list(root=str(root))}
    assert "vault/notes.txt" in docs        # a path-hash entry cannot match without its key (no inode on SMB)


def test_a_fresh_install_creates_its_key_silently_only_when_needed(fixture_dir):
    root = fixture_dir / "plain"
    write(root / "a.txt", b"x")
    run_scan(str(root), options())
    assert not redaction.key_path().exists()
    secret_tree(root)
    run_scan(str(root), options())
    assert redaction.key_path().exists() and len(redaction.key_path().read_bytes()) == 32


def test_redacted_list_and_the_other_commands_show_counts_only(fixture_dir, capsys):
    root = secret_tree(fixture_dir / "s")
    db = str(fixture_dir / "c.sqlite")
    backend = SqliteBackend(db)
    run_scan(str(root), options(config({"cache": "automatic"})), backend)
    backend.close()
    base = ["--backend", "sqlite", "--out", db]
    out = "\n".join(_lines(cli, ["rollups", "list", *base], capsys))
    assert "[REDACTED]" in out and "1 rollups" in out and "vault" not in out
    out = "\n".join(_lines(cli, ["rollups", "list", "--json", *base], capsys))
    assert json.loads(out.splitlines()[0])["rollups"][0]["tag"] == "[REDACTED]"
    out = "\n".join(_lines(cli, ["rollups", "redacted", "list", "--json", *base], capsys))
    row = json.loads(out)
    assert set(row) >= {"id", "status", "parent", "source", "files", "bytes"} and "vault" not in out
    assert "path_hash" not in row
    out = "\n".join(_lines(cli, ["rollups", "rules", *base[:0]], capsys))
    assert "[CACHE]" in out and "node_modules" in out and "always on" in out


def test_suggest_lists_what_a_manual_type_would_match(fixture_dir, capsys):
    root = fixture_dir / "s"
    write(root / "p1" / "node_modules" / "x.js", b"1")
    write(root / "p2" / "__pycache__" / "x.pyc", b"1")
    write(root / "q" / "@eaDir" / "t", b"1")
    db = str(fixture_dir / "c.sqlite")
    backend = SqliteBackend(db)
    run_scan(str(root), options(), backend)
    backend.close()
    base = ["--backend", "sqlite", "--out", db]
    out = "\n".join(_lines(cli, ["rollups", "suggest", *base], capsys))
    assert "[CACHE]: 2 matches in 2 folders" in out and "[SYNOLOGY]: 1 matches in 1 folders" in out
    assert '--rollup cache=automatic' in out and "p1" in out
    rows = [json.loads(ln) for ln in _lines(cli, ["rollups", "suggest", "--json", *base], capsys)]
    assert rows[0]["suggestions"]["items"]
    # adopting it: the next scan rolls them up and the suggestions are gone
    backend = SqliteBackend(db)
    run_scan(str(root), options(config({"cache": "automatic", "synology": "automatic"})), backend)
    backend.close()
    out = "\n".join(_lines(cli, ["rollups", "suggest", *base], capsys))
    assert "no suggestions" in out
