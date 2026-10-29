"""What the readers show of rollups (docs/rollups.md section 6): summary,
roots, show, dupes, the treemap with its tiles and pins, and the serve API the
inspector card reads.
"""
from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from filecat import browse, cli, dupes_cmd, serve, treemap
from filecat.backends.sqlite import SqliteBackend
from tests.test_hyperbackup import make_hbk
from tests.test_rollup_walk import config, options, run_scan, write


@pytest.fixture
def catalog(fixture_dir):
    """A sqlite catalog of a tree with a rolled-up store and caches; (root, db path)."""
    root = fixture_dir / "tree"
    make_hbk(root / "Backup")
    write(root / "Backup" / "other.txt", b"o" * 11)
    write(root / "proj" / "node_modules" / "pkg" / "a.js", b"12345")
    write(root / "proj" / "node_modules" / "b.js", b"1234567")
    write(root / "proj" / "src" / "m.py", b"print(1)\n")
    write(root / "[BACKUP]x" / "keep.txt", b"k")
    db = str(fixture_dir / "cat.sqlite")
    backend = SqliteBackend(db)
    run_scan(str(root), options(config({"backup": "automatic", "cache": "automatic"}), verify_backups=1), backend)
    backend.close()
    return str(root), db


def run_cli(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_summary_has_a_rollups_table_and_the_combined_totals_line(catalog, capsys):
    root, db = catalog
    code, out, _ = run_cli(capsys, "summary", "--backend", "sqlite", "--out", db, "--root", root, "--by", "extension")
    assert code == 0
    assert "-- Rollups --" in out
    lines = out.splitlines()
    table = lines[lines.index("-- Rollups --") + 1:]
    assert table[0].split() == ["tag", "rollups", "files", "bytes", "allocated", "newest"]
    tags = [ln.split()[0] for ln in table[1:3]]
    assert set(tags) == {"[BACKUP]", "[CACHE]"}
    assert any(ln.startswith("recorded files: ") and "; rollups: 6, " in ln and "; together " in ln for ln in lines)
    # a root without rollups has no table
    with SqliteBackend(db) as b:
        for d in list(b.list(kind="rollup")):
            b.delete(d["root"], d["rel_path"])
    _, out, _ = run_cli(capsys, "summary", "--backend", "sqlite", "--out", db, "--root", root, "--by", "extension")
    assert "-- Rollups --" not in out and "recorded files" not in out


def test_roots_shows_the_top_tags_and_last_scan_counts(catalog, capsys):
    root, db = catalog
    _, out, _ = run_cli(capsys, "roots", "--backend", "sqlite", "--out", db)
    assert "rollups     [BACKUP] " in out and "[CACHE]" in out and "not listed" in out
    assert "2 rollups (" in out                      # last scan: rollup_bytes beside files
    _, out, _ = run_cli(capsys, "roots", "--backend", "sqlite", "--out", db, "--json")
    row = json.loads(out.splitlines()[0])
    assert {r["tag"] for r in row["rollups"]} == {"[BACKUP]", "[CACHE]"}


def test_show_prints_a_rollup_with_a_one_line_summary(catalog, capsys):
    root, db = catalog
    code, out, err = run_cli(capsys, "show", "proj/[CACHE]", "--root", root, "--backend", "sqlite", "--out", db)
    assert code == 0 and json.loads(out)["kind"] == "rollup"
    assert "[CACHE] rollup: 2 files in 2 folders" in err


def test_the_dupes_line_counts_what_it_did_not_examine(catalog, capsys):
    root, db = catalog
    with SqliteBackend(db) as b:
        skipped = dupes_cmd.rollups_not_examined(b)
    assert skipped["folders"] == 2 and skipped["files"] == 6 and skipped["bytes"] == 629 + 12
    assert set(skipped["by_tag"]) == {"[BACKUP]", "[CACHE]"}
    _, _, err = run_cli(capsys, "dupes", "--backend", "sqlite", "--out", db)
    assert "dupes: not examined: 2 rollup folders, " in err and "in 6 files ([BACKUP] " in err
    _, out, _ = run_cli(capsys, "dupes", "--backend", "sqlite", "--out", db, "--json")
    last = json.loads(out.splitlines()[-1])
    assert last["rollups_not_examined"]["folders"] == 2


# --- the treemap -------------------------------------------------------------------------------
def test_treemap_draws_a_rollup_as_a_tile_at_its_path(catalog):
    root, db = catalog
    with SqliteBackend(db) as b:
        plain = treemap.build(b.sizes(root, ""), "", 3)
        tm = treemap.build(b.sizes(root, ""), "", 3, rollups=b.rollups(root, ""))
    folders = {f["path"]: f for f in tm["folders"]}
    tile = folders["Backup/NAS-LEGACY_1.hbk/[BACKUP]"]
    assert (tile["files"], tile["bytes"]) == (4, 629)
    assert tile["rollup"]["tag"] == "[BACKUP]" and tile["rollup"]["matched"] == 1 and tile["rollup"]["total_dirs"] == 3
    keys = {k["key"] for k in tm["keys"]["suffix"]}
    assert {"[BACKUP]", "[CACHE]"} <= keys
    names = [tm["keys"]["suffix"][i]["key"] for i, _ in tile["suffix"]]
    assert names == ["[BACKUP]"]
    assert tm["bytes"] == plain["bytes"] + 629 + 12 and tm["files"] == plain["files"] + 4 + 2
    assert "rollup" not in folders["proj/src"]


def test_a_deeper_rollup_joins_its_folder_and_a_merged_entry_keeps_no_rollup(catalog, monkeypatch):
    root, db = catalog
    with SqliteBackend(db) as b:
        shallow = treemap.build(b.sizes(root, ""), "", 1, rollups=b.rollups(root, ""))
        folders = {f["path"]: f for f in shallow["folders"]}
        assert "Backup/NAS-LEGACY_1.hbk/[BACKUP]" not in folders and "rollup" not in folders["Backup"]
        assert folders["Backup"]["bytes"] >= 629
        monkeypatch.setattr(treemap, "MAX_FOLDERS", 2)
        merged = treemap.build(b.sizes(root, ""), "", 3, rollups=b.rollups(root, ""))
    assert any("merged" in f and "rollup" not in f for f in merged["folders"])


# --- serve -------------------------------------------------------------------------------
@pytest.fixture
def served(catalog):
    root, db = catalog
    args = SimpleNamespace(backend="sqlite", out=db, dsn=None, quiet=True, no_save=False)
    cat = serve.Catalog(args)
    server = ThreadingHTTPServer(("127.0.0.1", 0), serve.make_handler(cat, b"<html></html>"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", root
    server.shutdown()
    server.server_close()
    cat.close()


def get(base, path, **params):
    with urllib.request.urlopen(f"{base}{path}?{urllib.parse.urlencode(params)}") as r:
        return json.load(r)


def post(base, path, body):
    req = urllib.request.Request(base + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def test_serve_treemap_subtree_records_and_the_inspector_card(served):
    base, root = served
    tm = get(base, "/api/treemap", root=root, depth=3)
    tile = next(f for f in tm["folders"] if f["path"] == "Backup/NAS-LEGACY_1.hbk/[BACKUP]")
    assert tile["rollup"]["tag"] == "[BACKUP]"
    sub = {f["name"]: f for f in get(base, "/api/subtree", root=root, parent="")["folders"]}
    assert sub["Backup"]["rollup_bytes"] == 629 and sub["Backup"]["rollup_files"] == 4
    assert sub["proj"]["rollup_bytes"] == 12
    store = {f["name"]: f for f in get(base, "/api/subtree", root=root, parent="Backup")["folders"]}
    assert store["NAS-LEGACY_1.hbk"]["rollup_bytes"] == 629
    rows = get(base, "/api/records", root=root, parent="proj")["rows"]
    kinds = [r["kind"] for r in rows]
    assert kinds.index("rollup") > kinds.index("dir")
    roll = next(r for r in rows if r["kind"] == "rollup")
    assert roll["rollup"] == {"tag": "[CACHE]", "total_files": 2, "total_dirs": 2, "matched": 1,
                              "partial": False, "errors": 0, "newest_mtime_ns": roll["rollup"]["newest_mtime_ns"]}
    by_tag = get(base, "/api/records", root=root, kind="rollup", q="[CACHE]")
    assert by_tag["total"] == 1
    d = get(base, "/api/record", root=root, rel_path="Backup/NAS-LEGACY_1.hbk/[BACKUP]")
    assert d["kind"] == "rollup" and d["store_record"]["rel_path"] == "Backup/NAS-LEGACY_1.hbk"
    backup = d["store_record"]["probe"]["backup"]
    assert backup["checked"] == "totals" and backup["task"] == "Synology NAS 1" and backup["versions"] == 3
    cache = get(base, "/api/record", root=root, rel_path="proj/[CACHE]")
    assert "store_record" not in cache


def test_a_pinned_snapshot_diffs_on_rollup_tiles(served, catalog):
    base, root = served
    from pathlib import Path
    tm = get(base, "/api/treemap", root=root, depth=2)
    pinned = post(base, "/api/pin", {"ids": [tm["id"]], "label": "before"})
    write(Path(root) / "proj" / "node_modules" / "c.js", b"c" * 100)
    _, db = catalog
    with SqliteBackend(db) as b:
        run_scan(root, options(config({"backup": "automatic", "cache": "automatic"})), b)
    now = get(base, "/api/treemap", root=root, depth=2, refresh=1)
    then = get(base, "/api/treemap", id=pinned["snapshots"][0]["id"])
    path = "proj/[CACHE]"
    new_tile = next(f for f in now["folders"] if f["path"] == path)
    old_tile = next(f for f in then["folders"] if f["path"] == path)
    assert (old_tile["bytes"], new_tile["bytes"]) == (12, 112)
    assert old_tile["rollup"]["tag"] == new_tile["rollup"]["tag"] == "[CACHE]"


def test_browse_helper_adds_folders_that_hold_only_rollups():
    rows = browse.with_rollups(
        [{"name": "a", "files": 1, "bytes": 10}],
        [{"rel_path": "a/[CACHE]", "size": 5, "probe": {"rollup": {"total_files": 2}}},
         {"rel_path": "z/x/[BACKUP]", "size": 50, "probe": {"rollup": {"total_files": 9}}},
         {"rel_path": "[CACHE]", "size": 7, "probe": {"rollup": {"total_files": 1}}}], "")
    assert [r["name"] for r in rows] == ["z", "a"]
    assert rows[0] == {"name": "z", "files": 0, "bytes": 0, "rollup_bytes": 50, "rollup_files": 9}
    assert rows[1]["rollup_bytes"] == 5      # [CACHE] directly in the root is listed beside the folders
