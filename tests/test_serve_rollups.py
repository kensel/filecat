"""`GET /api/rollups` (rollups_view.py): the audit of `filecat rollups list` by root, tag and
parent folder, filters, and [REDACTED] as counts only (docs/rollups.md section 3)."""
from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from filecat import cli, serve
from filecat.backends.sqlite import SqliteBackend
from tests.test_rollup_walk import config, options, run_scan, write

SECRET = "ZXQ-secret-folder-31"
SECRET_FILE = "ZXQ-secret-file-77.txt"


@pytest.fixture
def paths(fixture_dir):
    """A scanned tree: caches (two parents), a redacted folder by marker and the one by rule."""
    root = fixture_dir / "tree"
    write(root / "proj" / "node_modules" / "pkg" / "a.js", b"12345")
    write(root / "proj" / "node_modules" / "b.js", b"1234567")
    write(root / "proj" / "src" / "m.py", b"print(1)\n")
    write(root / "other" / ".cache" / "c.bin", b"x" * 100)
    write(root / "other" / "keep.txt", b"keep")
    write(root / "vault" / SECRET / SECRET_FILE, b"s" * 40)
    write(root / "vault" / SECRET / ".filecat-redacted")
    write(root / "vault" / f"cfg-{SECRET}" / SECRET_FILE, b"t" * 9)
    write(root / "vault" / "open.txt", b"open")
    db = str(fixture_dir / "cat.sqlite")
    backend = SqliteBackend(db)
    cfg = config({"cache": "automatic"}, rules=[{"tag": "[REDACTED]", "match": ["cfg-*"]}])
    run_scan(str(root), options(cfg), backend)
    backend.close()
    return str(root), db


@pytest.fixture
def served(paths):
    root, db = paths
    args = SimpleNamespace(backend="sqlite", out=db, dsn=None, quiet=True, no_save=False)
    catalog = serve.Catalog(args)
    server = ThreadingHTTPServer(("127.0.0.1", 0), serve.make_handler(catalog, b"<html></html>"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", root
    server.shutdown()
    server.server_close()
    catalog.close()


def get(base, path, **params):
    with urllib.request.urlopen(f"{base}{path}?{urllib.parse.urlencode(params)}") as r:
        return json.load(r)


def test_rows_are_rollups_list_by_root_tag_and_parent(served, paths, capsys):
    base, root = served
    doc = get(base, "/api/rollups")
    rows = {(r["tag"], r["parent"]): r for r in doc["rows"]}
    assert set(rows) == {("[CACHE]", "proj"), ("[CACHE]", "other"), ("[REDACTED]", "vault")}
    cache = rows[("[CACHE]", "proj")]
    assert (cache["root"], cache["files"], cache["dirs"], cache["size"], cache["matched"]) == (root, 2, 2, 12, 1)
    assert cache["rel_path"] == "proj/[CACHE]" and cache["partial"] == 0 and cache["rules"] == {"builtin": 1}
    assert cache["newest_mtime_ns"] and cache["redacted"] is False
    assert doc["roots"] == [root] and doc["tags"] == ["[CACHE]", "[REDACTED]"]
    assert doc["totals"]["rollups"] == 3 and doc["totals"]["size"] == sum(r["size"] for r in doc["rows"])
    assert {t["tag"]: t["rollups"] for t in doc["by_tag"]} == {"[CACHE]": 2, "[REDACTED]": 1}
    assert [r["root"] for r in doc["by_root"]] == [root]
    # the same counts as the command
    _, db = paths
    cli.main(["rollups", "list", "--backend", "sqlite", "--out", db, "--json"])
    listed = json.loads(capsys.readouterr().out.splitlines()[0])["rollups"]
    assert sorted((r["tag"], r["parent"], r["total_files"], r["size"]) for r in listed) == sorted(
        (r["tag"], r["parent"], r["files"], r["size"]) for r in doc["rows"])


def test_filters_by_root_and_tag(served):
    base, root = served
    assert {r["tag"] for r in get(base, "/api/rollups", tag="[CACHE]")["rows"]} == {"[CACHE]"}
    assert [r["parent"] for r in get(base, "/api/rollups", tag="[cache]", root=root)["rows"]].count("proj") == 1
    nothing = get(base, "/api/rollups", root="\\\\nowhere\\x")
    assert nothing["rows"] == [] and nothing["totals"]["rollups"] == 0
    assert nothing["tags"] == ["[CACHE]", "[REDACTED]"]          # the drop-downs keep every choice


def test_a_redacted_row_is_counts_only(served):
    base, root = served
    doc = get(base, "/api/rollups")
    red = next(r for r in doc["rows"] if r["tag"] == "[REDACTED]")
    assert red["redacted"] is True and red["parent"] == "vault"
    assert red["newest_mtime_ns"] is None and "rel_path" not in red and red["files"] == 3 and red["size"] == 40 + 9
    text = json.dumps(doc, ensure_ascii=False)
    assert SECRET not in text and SECRET_FILE not in text and f"cfg-{SECRET}" not in text
    assert "ZXQ" not in text
    assert get(base, "/api/rollups", tag="[REDACTED]")["rows"] == [red]


def test_an_empty_catalog_has_no_rollups(tmp_path):
    db = str(tmp_path / "c.sqlite")
    SqliteBackend(db).close()
    args = SimpleNamespace(backend="sqlite", out=db, dsn=None, quiet=True, no_save=False)
    catalog = serve.Catalog(args)
    try:
        doc = catalog.rollups({})
    finally:
        catalog.close()
    assert doc["rows"] == [] and doc["roots"] == [] and doc["totals"]["rollups"] == 0
