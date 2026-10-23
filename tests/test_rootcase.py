"""Roots that differ only in the case of server\\share: finding them, checking
that they are one share, merging them, and not creating them in the first place."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

import pytest

import filecat.rootcase as rootcase
from filecat import cli, rootinfo
from filecat.agent_client import ShareMap
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.config import AgentConfig
from filecat.record import root_id

OLD = "\\\\nas-main\\backup"
NEW = "\\\\nas-main\\Backup"
T0 = 1_700_000_000_000_000_000        # mtime of the files, well before any scan below
SCAN_A = "2024-03-01T10:00:00+00:00"
SCAN_B = "2024-03-05T10:00:00+00:00"


def ns(iso: str) -> int:
    return int(datetime.fromisoformat(iso).timestamp() * 1e9)


def doc(root: str, rel: str, size: int = 10, mtime: int | None = None, **extra) -> dict:
    d = {"root_id": root_id(root), "root": root, "rel_path": rel, "name": rel.rsplit("/", 1)[-1],
         "size": size, "kind": "data", "suffix": "", "mtime_ns": T0 + size if mtime is None else mtime}
    d.update(extra)
    return d


def fill(backend, root: str, count: int = 300, **kw) -> None:
    backend.put(doc(root, "", 0, kind="dir", name=root.rsplit("\\", 1)[-1]))
    for i in range(count):
        backend.put(doc(root, f"d{i % 7}/f{i}.bin", size=100 + i, sha256=f"{i:064x}", **kw))
    backend.flush()


def info(backend, root: str, started: str, agent: str | None = None, status: str = "ok",
         heartbeat: str | None = None) -> None:
    attempt = {"started_at": started, "finished_at": started, "status": status, "host": "h", "pid": 1,
               "heartbeat_at": heartbeat or started}
    if agent:
        attempt["agent"] = agent
    backend.put_root_info({"root_id": root_id(root), "root": root, "last_attempt": attempt,
                           "last_scan": {"started_at": started, "finished_at": started, "status": "ok"}})


def two_roots(count: int = 300) -> MemoryBackend:
    be = MemoryBackend()
    fill(be, OLD, count)
    fill(be, NEW, count)
    info(be, OLD, SCAN_A)
    info(be, NEW, SCAN_B, agent="nas-main")
    return be


def agent_config(**kw) -> AgentConfig:
    return AgentConfig(name="nas-main", host="127.0.0.1", cert_sha256="0" * 64, token="t",
                       alias="\\\\nas-main", **kw)


# --- detection -----------------------------------------------------------------
def test_groups_differ_only_in_server_share_case():
    roots = [OLD, NEW, "\\\\NAS-MAIN\\Backup", "\\\\nas-main\\Backup\\Sub", "\\\\nas-main\\backup\\sub",
             "\\\\nas-main\\Backup\\sub", "C:\\data", "c:\\DATA", "\\\\nas-main\\home"]
    groups = rootcase.find_groups(roots)
    # the path below the share is case-sensitive: Sub and sub are different roots
    assert groups == [["\\\\NAS-MAIN\\Backup", NEW, OLD],
                      ["\\\\nas-main\\Backup\\sub", "\\\\nas-main\\backup\\sub"]]
    assert rootcase.find_groups([NEW, "\\\\nas-main\\Backup\\"]) == []     # same spelling
    assert rootcase.key_of("C:\\x") is None and rootcase.key_of("\\\\nas-main") is None


def test_canonical_is_the_agent_scanned_or_configured_spelling():
    be = two_roots(5)
    infos = {i["root"]: i for i in be.list_root_info()}
    assert rootcase.canonical_of([OLD, NEW], infos)[0] == NEW
    info(be, OLD, SCAN_A, agent="nas-main")
    both = {i["root"]: i for i in be.list_root_info()}
    assert rootcase.canonical_of([OLD, NEW], both)[0] is None       # ambiguous
    # an explicit share in [agents.shares] is the NAS's spelling, with or without a scan
    cfg = agent_config(shares={"/volume1/Backup": NEW})
    assert rootcase.canonical_of([OLD, NEW], both, [cfg])[0] == NEW
    assert rootcase.canonical_of([OLD, NEW], {}, [cfg]) == (NEW, "agent nas-main's share map")
    assert rootcase.canonical_of([OLD, NEW], {})[0] is None


def test_share_map_canonical_spelling():
    m = ShareMap("\\\\NAS-Main", {"/volume2/Archive": "\\\\nas-main\\Archive"})
    names = lambda folder: {"/volume1": ["Backup", "home", "backup-old"]}[folder]   # noqa: E731
    assert m.canonical(OLD + "\\x\\y", names) == "\\\\NAS-Main\\Backup\\x\\y"       # listing, rest untouched
    assert m.canonical("\\\\nas-main\\HOME", names) == "\\\\NAS-Main\\home"
    assert m.canonical("\\\\nas-main\\Backup", names) == "\\\\NAS-Main\\Backup"
    assert m.canonical("\\\\nas-main\\nothere", names) == "\\\\NAS-Main\\nothere"   # no match: as typed
    assert m.canonical("\\\\nas-main\\ARCHIVE\\Q", names) == "\\\\nas-main\\Archive\\Q"   # explicit spelling
    assert m.canonical("\\\\other\\Backup", names) == "\\\\other\\Backup"
    assert m.explicit_spelling(OLD) is None
    ambiguous = lambda folder: ["Backup", "BACKUP"]   # noqa: E731
    assert m.canonical("\\\\nas-main\\backup", ambiguous) == "\\\\NAS-Main\\backup"


# --- verification --------------------------------------------------------------
def test_same_share_matches_and_the_sample_is_stable():
    be = two_roots(600)
    v = rootcase.verify(be, OLD, NEW, 500)
    assert v.same and v.sampled == 500 and v.matched == 500
    assert not v.mismatched and not v.missing_a and not v.missing_b and v.changed_since == 0
    again = rootcase.verify(be, OLD, NEW, 500)
    assert again.as_dict() == v.as_dict()
    first, _ = rootcase.pick_sample(be, OLD, NEW, 200)
    assert first == rootcase.pick_sample(be, NEW, OLD, 200)[0]            # either order
    assert set(first) <= set(rootcase.pick_sample(be, OLD, NEW, 500)[0])  # a bigger sample extends it
    with pytest.raises(ValueError):
        rootcase.verify(be, OLD, NEW, 199)
    with pytest.raises(ValueError):
        rootcase.verify(be, OLD, NEW, 1001)


def test_different_shares_do_not_match():
    be = MemoryBackend()
    fill(be, OLD, 300)
    for i in range(300):            # same names, other content
        be.put(doc(NEW, f"d{i % 7}/f{i}.bin", size=5000 + i, sha256=f"{i + 1:064x}"))
    info(be, OLD, SCAN_A)
    info(be, NEW, SCAN_B)
    v = rootcase.verify(be, OLD, NEW, 200)
    assert not v.same and v.matched == 0 and len(v.mismatched) == 200
    reasons = v.mismatched[0]["reasons"]
    assert any(r.startswith("size ") for r in reasons) and "sha256 differs" in reasons


def test_mismatch_reasons_are_reported():
    be = two_roots(300)
    docs = {d["rel_path"]: d for d in be.list(root=NEW)}
    rel_size, rel_hash, rel_time, rel_kind = sorted(docs)[1:5]
    be.put({**docs[rel_size], "size": docs[rel_size]["size"] + 1})
    be.put({**docs[rel_hash], "sha256": "f" * 64})
    be.put({**docs[rel_time], "mtime_ns": docs[rel_time]["mtime_ns"] + 5000})
    be.put({**docs[rel_kind], "kind": "text"})
    be.put({**docs[sorted(docs)[5]], "mtime_ns": docs[sorted(docs)[5]]["mtime_ns"] + 100})   # 100 ns: the agent's step
    v = rootcase.verify(be, OLD, NEW, 1000)
    assert v.sampled == 300                    # files only; the folder record is not sampled
    by_path = {m["rel_path"]: m["reasons"] for m in v.mismatched}
    assert by_path[rel_size][0].startswith("size ")
    assert by_path[rel_hash] == ["sha256 differs"]
    assert by_path[rel_time][0].startswith("mtime_ns ")
    assert by_path[rel_kind][0].startswith("kind ")
    assert len(by_path) == 4 and v.same        # 4 of 300 is within the tolerance


def test_missing_on_one_side():
    be = two_roots(300)
    for i in range(0, 300, 4):                 # 75 files gone from NEW
        be.delete(NEW, f"d{i % 7}/f{i}.bin")
    for i in range(300, 330):                  # 30 only there
        be.put(doc(NEW, f"extra/f{i}.bin"))
    v = rootcase.verify(be, OLD, NEW, 1000)
    assert len(v.missing_b) == 75 and len(v.missing_a) == 30
    assert v.matched == 225 and not v.same     # 225 of 330 judged
    be2 = MemoryBackend()
    fill(be2, OLD, 300)
    be2.put(doc(NEW, "only.bin"))
    assert not rootcase.verify(be2, OLD, NEW, 200).same


def test_files_changed_since_the_older_scan_are_left_out():
    be = two_roots(300)
    later = ns(SCAN_A) + 3_600_000_000_000      # an hour into the older scan
    docs = {d["rel_path"]: d for d in be.list(root=NEW) if d["kind"] != "dir"}
    for rel in sorted(docs)[:100]:              # modified after scan A: a different size on NEW
        be.put({**docs[rel], "size": 1, "mtime_ns": later})
    for i in range(300, 320):                   # created after scan A, only on NEW
        be.put(doc(NEW, f"new/{i}.bin", mtime=later))
    v = rootcase.verify(be, OLD, NEW, 1000)
    assert v.changed_since == 120
    assert v.matched == 200 and not v.mismatched and not v.missing_a and v.same
    # without scan times nothing can be excused, and the same files count against the pair
    for root in (OLD, NEW):
        be.delete_root_info(root)
    bare = rootcase.verify(be, OLD, NEW, 1000)
    assert bare.changed_since == 0 and len(bare.mismatched) == 100 and len(bare.missing_a) == 20
    assert not bare.same        # 200 of 320 judged


def test_too_little_to_judge():
    be = MemoryBackend()
    assert not rootcase.verify(be, OLD, NEW, 200).same          # nothing in either
    fill(be, OLD, 4)
    fill(be, NEW, 4)
    v = rootcase.verify(be, OLD, NEW, 200)
    assert v.judged == 4 and v.same                              # all there is, and it matches
    fill(be, OLD, 40)
    assert not rootcase.verify(be, OLD, NEW, 200).same           # 4 of 40 files match


# --- merging -------------------------------------------------------------------
def args(**kw) -> argparse.Namespace:
    base = dict(names=[], sample=200, force=False, dry_run=False, json=False, config=None,
                backend="sqlite", out=None, dsn=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_merge_moves_records_and_keeps_the_newer_scan_on_overlap():
    be = MemoryBackend()
    fill(be, OLD, 40)
    fill(be, NEW, 20)                     # NEW has the first 20 files; OLD scanned earlier
    be.put(doc(NEW, "d0/f0.bin", size=999))        # NEW's own, newer, version of one of them
    be.put(doc(OLD, "arch.zip", members_id=None, kind="archive"))
    be.put_members(OLD, "arch.zip", [{"index": 0, "path": "a.txt"}])
    info(be, OLD, SCAN_A)
    info(be, NEW, SCAN_B, agent="nas-main")
    stats = rootcase.merge(be, OLD, NEW, batch=7)
    # 20 files and the archive moved; the folder record and 20 files were in both
    assert stats.moved == 21 and stats.kept == 21 and stats.batches == 6
    assert be.roots() == [NEW]
    docs = {d["rel_path"]: d for d in be.list(root=NEW)}
    assert len(docs) == 1 + 40 + 1 and all(d["root"] == NEW and d["root_id"] == root_id(NEW) for d in docs.values())
    assert docs["d0/f0.bin"]["size"] == 999                      # the newer scan's record
    assert docs[""]["name"] == "Backup"
    assert [m["path"] for m in be.list_members(NEW, "arch.zip")] == ["a.txt"]
    assert be.get_root_info(OLD) is None
    kept = be.get_root_info(NEW)
    assert "case_merge" not in kept and kept["last_scan"]["started_at"] == SCAN_B
    # again: nothing left to move, the result is the same
    again = rootcase.merge(be, OLD, NEW)
    assert again.moved == 0 and again.batches == 0
    assert {d["rel_path"]: d for d in be.list(root=NEW)} == docs


def test_merge_takes_the_old_root_when_it_was_scanned_later():
    be = MemoryBackend()
    fill(be, OLD, 10)
    fill(be, NEW, 10)
    be.put(doc(OLD, "d0/f0.bin", size=777))
    info(be, OLD, SCAN_B)
    info(be, NEW, SCAN_A, agent="nas-main")
    rootcase.merge(be, OLD, NEW)
    assert be.get(NEW, "d0/f0.bin")["size"] == 777


def test_merge_without_a_root_index_entry_for_the_new_root_inherits_the_old_one():
    be = MemoryBackend()
    fill(be, OLD, 3)
    fill(be, NEW, 3)
    info(be, OLD, SCAN_A)
    rootcase.merge(be, OLD, NEW)
    assert be.get_root_info(NEW)["last_scan"]["started_at"] == SCAN_A
    assert be.get_root_info(NEW)["root"] == NEW


def test_merge_survives_a_crash_and_resumes(fixture_dir, capsys):
    path = str(fixture_dir / "catalog.sqlite")
    be = SqliteBackend(path)
    fill(be, OLD, 300)
    fill(be, NEW, 300)
    info(be, OLD, SCAN_A)
    info(be, NEW, SCAN_B, agent="nas-main")
    real_delete, calls = be.delete, [0]

    def dying_delete(root, rel):
        calls[0] += 1
        if calls[0] == 150:
            raise RuntimeError("power cut")
        real_delete(root, rel)

    be.delete = dying_delete
    with pytest.raises(RuntimeError):
        rootcase.merge(be, OLD, NEW, batch=100)
    be.delete = real_delete
    assert be.get_root_info(NEW)["case_merge"]["from"] == OLD and be.get_root_info(OLD) is not None
    # the half-done state does not pass verification any more, but the marker lets it finish
    code = rootcase.run_merge(args(names=[OLD, NEW], backend="sqlite", out=path))
    assert code == 0
    out = capsys.readouterr().out
    assert "finishing an interrupted merge" in out
    assert be.roots() == [NEW] and len(list(be.list(root=NEW))) == 301
    assert be.get_root_info(OLD) is None and "case_merge" not in be.get_root_info(NEW)
    be.close()


def test_run_merge_verifies_and_refuses_what_is_not_the_same_share(fixture_dir, capsys):
    path = str(fixture_dir / "catalog.sqlite")
    be = SqliteBackend(path)
    fill(be, OLD, 300)
    for i in range(300):
        be.put(doc(NEW, f"d{i % 7}/f{i}.bin", size=9000 + i))
    info(be, OLD, SCAN_A)
    info(be, NEW, SCAN_B, agent="nas-main")
    be.close()
    assert rootcase.run_merge(args(names=[OLD, NEW], out=path)) == 1
    assert "not merged" in capsys.readouterr().out
    with SqliteBackend(path) as be:
        assert be.roots() == sorted([OLD, NEW])
    assert rootcase.run_merge(args(names=[OLD, NEW], out=path, force=True)) == 0
    with SqliteBackend(path) as be:
        assert be.roots() == [NEW]


def test_dry_run_and_the_canonical_spelling_guard(fixture_dir, capsys):
    path = str(fixture_dir / "catalog.sqlite")
    with SqliteBackend(path) as be:
        fill(be, OLD, 300)
        fill(be, NEW, 300)
        info(be, OLD, SCAN_A)
        info(be, NEW, SCAN_B, agent="nas-main")
    assert rootcase.run_merge(args(names=[OLD, NEW], out=path, dry_run=True)) == 0
    assert "dry run" in capsys.readouterr().out
    with SqliteBackend(path) as be:
        assert be.roots() == sorted([OLD, NEW])
    # keeping the other spelling needs --force: the NAS spells it NEW
    assert rootcase.run_merge(args(names=[NEW, OLD], out=path)) == 1
    assert "NAS's spelling" in capsys.readouterr().err
    # no names: the NAS's spelling is known, so the pair is merged into it
    assert rootcase.run_merge(args(out=path)) == 0
    with SqliteBackend(path) as be:
        assert be.roots() == [NEW]


def test_merge_with_no_names_skips_a_pair_with_no_known_canonical(fixture_dir, capsys):
    path = str(fixture_dir / "catalog.sqlite")
    with SqliteBackend(path) as be:
        fill(be, OLD, 3)
        fill(be, NEW, 3)
    assert rootcase.run_merge(args(out=path)) == 0
    assert "canonical spelling not known" in capsys.readouterr().out
    with SqliteBackend(path) as be:
        assert be.roots() == sorted([OLD, NEW])


@pytest.mark.parametrize("busy", [OLD, NEW])
def test_merge_refuses_while_a_scan_is_running(fixture_dir, capsys, busy):
    path = str(fixture_dir / "catalog.sqlite")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with SqliteBackend(path) as be:
        fill(be, OLD, 300)
        fill(be, NEW, 300)
        info(be, OLD, SCAN_A)
        info(be, NEW, SCAN_B, agent="nas-main")
        info(be, busy, now, status="running", agent="nas-main" if busy == NEW else None)
        assert rootinfo.in_progress(be) == [busy]
    assert rootcase.run_merge(args(names=[OLD, NEW], out=path)) == 1
    assert "a scan is running" in capsys.readouterr().err
    with SqliteBackend(path) as be:
        assert be.roots() == sorted([OLD, NEW]) and be.get_root_info(NEW).get("case_merge") is None
    assert rootcase.run_merge(args(names=[OLD, NEW], out=path, force=True)) == 0
    with SqliteBackend(path) as be:
        assert be.roots() == [NEW]


def test_a_scan_of_some_other_root_does_not_hold_the_merge_back(fixture_dir):
    path = str(fixture_dir / "catalog.sqlite")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    other = "\\\\nas-main\\media"
    with SqliteBackend(path) as be:
        fill(be, OLD, 300)
        fill(be, NEW, 300)
        fill(be, other, 2)
        info(be, OLD, SCAN_A)
        info(be, NEW, SCAN_B, agent="nas-main")
        info(be, other, now, status="running")
    assert rootcase.run_merge(args(names=[OLD, NEW], out=path)) == 0


def test_cli_case_check_reports_and_validates(fixture_dir, capsys):
    path = str(fixture_dir / "catalog.sqlite")
    with SqliteBackend(path) as be:
        fill(be, OLD, 300)
        fill(be, NEW, 300)
        info(be, OLD, SCAN_A)
        info(be, NEW, SCAN_B, agent="nas-main")
    assert cli.main(["roots", "case-check", "--backend", "sqlite", "--out", path]) == 1
    out = capsys.readouterr().out
    assert "canonical: " + NEW in out and "the same share" in out and "300 matched" in out
    assert cli.main(["roots", "case-check", "--backend", "sqlite", "--out", path, "--json"]) == 1
    row = json.loads(capsys.readouterr().out)
    assert row["canonical"] == NEW and row["checks"][0]["verdict"]["same"] is True
    assert cli.main(["roots", "case-check", "--backend", "sqlite", "--out", path, "--sample", "50"]) == 2
    assert cli.main(["roots", "case-merge", "--backend", "sqlite", "--out", path, OLD, NEW]) == 0
    assert cli.main(["roots", "case-check", "--backend", "sqlite", "--out", path]) == 0
    assert "no roots that differ" in capsys.readouterr().out
    assert cli.main(["roots", "--backend", "sqlite", "--out", path, "--json"]) == 0      # list still works


# --- keeping scans from splitting a share ------------------------------------
def test_smb_scan_reuses_the_spelling_the_catalog_holds(capsys):
    be = two_roots(3)
    roots = ["\\\\NAS-MAIN\\BACKUP\\sub", "\\\\NAS-Main\\backup", "\\\\nas-main\\Home"]
    be.put(doc("\\\\NAS-MAIN\\Backup\\sub", "x"))
    rootcase.reconcile(roots, [None, None, None], be)
    # the agent-scanned NEW wins over OLD; the rest of the path is not touched
    assert roots == ["\\\\NAS-MAIN\\Backup\\sub", NEW, "\\\\nas-main\\Home"]
    err = capsys.readouterr().err
    assert "\\\\NAS-Main\\backup: recorded as " + NEW + "," in err and "SMB ignores case" in err
    assert f"{NEW}: the catalog also holds this share as {OLD}; see: filecat roots case-check" in err


def test_smb_scan_of_a_known_spelling_changes_nothing_but_hints(capsys):
    be = two_roots(3)
    roots = [OLD]
    rootcase.reconcile(roots, [None], be)
    assert roots == [OLD]
    assert f"{OLD}: the catalog also holds this share as {NEW}" in capsys.readouterr().err
    clean = MemoryBackend()
    fill(clean, NEW, 2)
    roots = [NEW, "C:\\data"]
    rootcase.reconcile(roots, [None, None], clean)
    assert roots == [NEW, "C:\\data"] and capsys.readouterr().err == ""


def test_most_recent_spelling_is_reused_when_none_is_the_nas(capsys):
    be = MemoryBackend()
    fill(be, OLD, 2)
    fill(be, "\\\\nas-main\\BACKUP", 2)
    info(be, OLD, SCAN_A)
    info(be, "\\\\nas-main\\BACKUP", SCAN_B)
    roots = ["\\\\nas-main\\Backup"]
    rootcase.reconcile(roots, [None], be)
    assert roots == ["\\\\nas-main\\BACKUP"]
