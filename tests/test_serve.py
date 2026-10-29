"""filecat serve: the JSON API over a real sqlite catalog on a free port."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from filecat import serve
from filecat.backends.sqlite import SqliteBackend
from filecat.record import new_document

ROOT = r"\nas\share"
OTHER = r"\nas\other"


def _start(out: str, no_save: bool = False):
    args = SimpleNamespace(backend="sqlite", out=out, dsn=None, quiet=True, no_save=no_save)
    catalog = serve.Catalog(args)
    server = ThreadingHTTPServer(("127.0.0.1", 0), serve.make_handler(catalog, b"<html>page</html>"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return catalog, server


@pytest.fixture
def catalog_path(tmp_path):
    out = str(tmp_path / "c.sqlite")
    with SqliteBackend(out) as b:
        b.put(new_document(ROOT, "", kind="dir"))
        b.put(new_document(ROOT, "docs", kind="dir"))
        b.put({**new_document(ROOT, "docs/a.txt", kind="text", size=10), "mime": "text/plain"})
        b.put(new_document(ROOT, "docs/deep/b.zip", kind="archive", size=90))
        b.put_members(ROOT, "docs/deep/b.zip", [{"index": i, "path": f"m{i}", "size": i} for i in range(5)])
        b.put({**new_document(ROOT, "top.bin", kind="data", size=0)})
    return out


@pytest.fixture(params=[False, True], ids=["save", "no-save"])
def served(request, catalog_path):
    catalog, server = _start(catalog_path, no_save=request.param)
    yield f"http://127.0.0.1:{server.server_address[1]}", request.param
    server.shutdown()
    server.server_close()
    catalog.close()


@pytest.fixture
def base_url(served):
    return served[0]


def get(base, path, **params):
    with urllib.request.urlopen(f"{base}{path}?{urllib.parse.urlencode(params)}") as r:
        return json.load(r)


def settled(base, path, until=None, **params):
    """GET until the stored summary is neither being built nor rebuilt (and `until(data)`, if given)."""
    deadline = time.monotonic() + 20
    while True:
        data = get(base, path, **params)
        if not data.get("building") and not data.get("refreshing") and (until is None or until(data)):
            return data
        assert time.monotonic() < deadline, data
        time.sleep(0.05)


def test_page_and_info(base_url):
    with urllib.request.urlopen(base_url + "/") as r:
        assert r.read() == b"<html>page</html>"
    assert get(base_url, "/api/info")["roots"] == [ROOT]


def test_summary_drills_into_records(base_url):
    s = get(base_url, "/api/summary", root=ROOT, depth=1)
    assert s["total_files"] == 3 and s["total_bytes"] == 100
    for row in s["suffix"]:
        r = get(base_url, "/api/records", root=ROOT, suffix=row["suffix"], files_only=1)
        assert (r["total"], r["bytes"]) == (row["files"], row["bytes"])
    r = get(base_url, "/api/records", root=ROOT, dir="docs", depth=1, files_only=1)
    assert [x["rel_path"] for x in r["rows"]] == ["docs/deep/b.zip", "docs/a.txt"]
    assert set(r["rows"][0]) <= set(serve.ROW_FIELDS) | {"errors", "unreadable", "child_count"}


def test_browse_and_record(base_url):
    assert get(base_url, "/api/subtree", root=ROOT, parent="")["folders"] == [
        {"name": "docs", "files": 2, "bytes": 100}]
    r = get(base_url, "/api/records", root=ROOT, parent="")
    assert [x["rel_path"] for x in r["rows"]] == ["docs", "top.bin"]  # folders first
    assert get(base_url, "/api/record", root=ROOT, rel_path="docs/a.txt")["mime"] == "text/plain"


def test_members_paging(base_url):
    m = get(base_url, "/api/members", root=ROOT, rel_path="docs/deep/b.zip", offset=1, limit=3)
    assert [x["path"] for x in m["rows"]] == ["m1", "m2", "m3"] and m["more"] is True
    m = get(base_url, "/api/members", root=ROOT, rel_path="docs/deep/b.zip", offset=3, limit=3)
    assert len(m["rows"]) == 2 and m["more"] is False


@pytest.mark.parametrize("path,params,status", [
    ("/api/record", {"root": ROOT, "rel_path": "missing"}, 404),
    ("/api/record", {"root": ROOT}, 400),
    ("/api/records", {"limit": "x"}, 400),
    ("/api/nope", {}, 404),
])
def test_errors(base_url, path, params, status):
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(base_url, path, **params)
    assert exc.value.code == status
    assert "error" in json.load(exc.value)


def _stored(path):
    with SqliteBackend(path) as b:
        return b.stored_aggregates(ROOT).get(ROOT)


def test_summary_is_saved_once_and_rebuilt_on_request(served, catalog_path):
    base, no_save = served
    first = get(base, "/api/summary", root=ROOT, depth=2)
    if no_save:
        assert first["source"] == "computed" and first["can_save"] is False
        assert _stored(catalog_path) is None
        return
    assert first["building"] is True and first["source"] == "building" and first["stale"] is True
    first = settled(base, "/api/summary", root=ROOT, depth=2)      # built in the background, then stored
    assert first["source"] == "stored" and first["total_bytes"] == 100 and first["stale"] is False
    saved = _stored(catalog_path)
    assert saved["depth"] == 2 and saved["built_at"] == first["built_at"]

    again = get(base, "/api/summary", root=ROOT, depth=2)
    assert again["source"] == "stored" and again["built_at"] == saved["built_at"]

    # another depth is computed but does not replace what is saved
    other = get(base, "/api/summary", root=ROOT, depth=1)
    assert other["source"] == "computed" and other["stored_depth"] == 2
    assert _stored(catalog_path)["depth"] == 2

    rebuilt = get(base, "/api/summary", root=ROOT, depth=1, rebuild=1)
    assert rebuilt["source"] == "saved" and _stored(catalog_path)["depth"] == 1


def test_treemap_is_reused_until_refresh(served, catalog_path):
    base, no_save = served
    t = get(base, "/api/treemap", root=ROOT)
    if not no_save:
        assert t["building"] is True and t["source"] == "building"
        t = settled(base, "/api/treemap", root=ROOT)
    assert t["source"] == ("computed" if no_save else "stored")
    assert (t["files"], t["bytes"], t["depth"]) == (3, 100, 2)
    assert {f["path"]: f["bytes"] for f in t["folders"]} == {"": 0, "docs": 10, "docs/deep": 90}
    with SqliteBackend(catalog_path) as b:
        b.put(new_document(ROOT, "docs/more.bin", kind="data", size=5))
        assert len(b.list_treemaps(ROOT)) == (0 if no_save else 1)
    again = get(base, "/api/treemap", root=ROOT)
    assert again["source"] == ("memory" if no_save else "stored") and again["bytes"] == 100
    fresh = get(base, "/api/treemap", root=ROOT, refresh=1)     # saved: queued, the stored one is served meanwhile
    if not no_save:
        assert fresh["source"] == "stored"
        fresh = settled(base, "/api/treemap", until=lambda d: d["bytes"] == 105, root=ROOT)
    assert fresh["source"] in ("computed", "stored") and fresh["bytes"] == 105
    with SqliteBackend(catalog_path) as b:  # the older unpinned snapshot is gone
        assert [m["bytes"] for m in b.list_treemaps(ROOT)] == ([] if no_save else [105])
    sub = get(base, "/api/treemap", root=ROOT, prefix="docs", depth=1)
    assert sub["prefix"] == "docs" and {f["path"] for f in sub["folders"]} == {"", "deep"}


def test_snapshots_outlive_the_server_and_expire(catalog_path):
    catalog, server = _start(catalog_path)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        first = settled(base, "/api/treemap", root=ROOT)
    finally:
        server.shutdown(), server.server_close(), catalog.close()
    catalog, server = _start(catalog_path)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        again = get(base, "/api/treemap", root=ROOT)
        assert again["source"] == "stored" and again["id"] == first["id"]
        catalog.max_age = serve.timedelta(0)  # as if two hours had passed
        # the root's top at depth 2 is judged by the root, not by age ...
        kept = get(base, "/api/treemap", root=ROOT)
        assert kept["source"] == "stored" and kept["id"] == first["id"] and kept["stale"] is False
        # ... any other view is built on demand and reused for --graph-max-age only
        assert get(base, "/api/treemap", root=ROOT, depth=3)["source"] == "saved"
        assert get(base, "/api/treemap", root=ROOT, depth=3)["source"] == "saved"
    finally:
        server.shutdown(), server.server_close(), catalog.close()


def test_pin_view_and_unpin(served, catalog_path):
    base, no_save = served
    t = get(base, "/api/treemap", root=ROOT)
    if not no_save:
        t = settled(base, "/api/treemap", root=ROOT)
    if no_save:
        assert t["can_pin"] is False and t["id"] is None
        with pytest.raises(urllib.error.HTTPError) as exc:
            post(base, "/api/pin", {"ids": ["x"]})
        assert exc.value.code == 400
        assert get(base, "/api/pins")["pins"] == []
        return
    pinned = post(base, "/api/pin", {"ids": [t["id"]], "label": " before cleanup "})
    at = pinned["pin"]["at"]
    assert pinned["pin"]["label"] == "before cleanup"
    with SqliteBackend(catalog_path) as b:
        b.put(new_document(ROOT, "docs/more.bin", kind="data", size=5))
    get(base, "/api/treemap", root=ROOT, refresh=1)
    fresh = settled(base, "/api/treemap", until=lambda d: d["id"] != t["id"], root=ROOT)
    assert fresh["bytes"] == 105
    [group] = get(base, "/api/pins")["pins"]
    assert group["at"] == at and [s["id"] for s in group["snapshots"]] == [t["id"]]
    old = get(base, "/api/treemap", id=t["id"])
    assert old["source"] == "pinned" and old["bytes"] == 100 and old["root"] == ROOT
    assert get(base, "/api/pins", root=ROOT, prefix="docs")["pins"] == []  # another view
    assert post(base, "/api/unpin", {"at": at}) == {"unpinned": 1}
    assert get(base, "/api/pins")["pins"] == []
    with pytest.raises(urllib.error.HTTPError) as exc:  # replaced by the fresh one, so deleted
        get(base, "/api/treemap", id=t["id"])
    assert exc.value.code == 404
    for body in ({}, {"ids": "x"}, {"ids": ["missing"]}):
        with pytest.raises(urllib.error.HTTPError) as exc:
            post(base, "/api/pin", body)
        assert exc.value.code == 400


def test_roots_index(base_url, catalog_path):
    from filecat import rootinfo
    rows = get(base_url, "/api/roots")["roots"]
    assert [(r["root"], r["state"], r["info"]) for r in rows] == [(ROOT, "never", None)]
    with SqliteBackend(catalog_path) as b:
        tracker = rootinfo.ScanTracker(b, ROOT)
        rootinfo.begin(b, ROOT, tracker)
    row = get(base_url, "/api/roots")["roots"][0]
    assert row["state"] == "in_progress" and row["info"]["last_attempt"]["status"] == "running"
    with SqliteBackend(catalog_path) as b:
        rootinfo.finish(b, ROOT, b.get_root_info(ROOT)["last_attempt"], tracker)
    row = get(base_url, "/api/roots")["roots"][0]
    assert row["state"] == "ok" and row["info"]["last_scan"]["status"] == "ok"
    r = get(base_url, "/api/records", root=ROOT, errors=1)
    assert r["total"] == 0


# --- backend selector ------------------------------------------------------
def post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def _toml_path(p):
    return str(p).replace("\\", "/")  # a basic TOML string would read \n, \t in a Windows path


@pytest.fixture
def selector(tmp_path, catalog_path, monkeypatch):
    """A server on catalog_path whose config lists the sqlite catalog, a
    missing jsonl one, a MongoDB DSN with a password, and a Postgres DSN that
    needs an unset variable. Yields (url, other catalog, rewrite(sqlite_out))."""
    monkeypatch.delenv("FILECAT_TEST_PG_PASSWORD", raising=False)
    other = str(tmp_path / "other.sqlite")
    with SqliteBackend(other) as b:
        b.put(new_document(OTHER, "x.txt", kind="text", size=1))
    config = tmp_path / "filecat.toml"

    def write(sqlite_out):
        lines = ["[jsonl]", f'out = "{_toml_path(tmp_path / "none.jsonl")}"',
                 "[mongodb]", 'dsn = "mongodb://filecat:s3cret@db.example:27017/filecat"',
                 "[postgres]", 'dsn = "postgresql://filecat:${FILECAT_TEST_PG_PASSWORD}@pg.example:5432/cat"']
        if sqlite_out:
            lines += ["[sqlite]", f'out = "{_toml_path(sqlite_out)}"']
        config.write_text("\n".join(lines), encoding="utf-8")

    write(catalog_path)
    args = SimpleNamespace(backend="sqlite", out=catalog_path, dsn=None, quiet=True, no_save=False,
                           config=str(config))
    catalog = serve.Catalog(args)
    server = ThreadingHTTPServer(("127.0.0.1", 0), serve.make_handler(catalog, b"<html>page</html>"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", other, write
    server.shutdown()
    server.server_close()
    catalog.close()


def test_backends_list(selector):
    base, other, write = selector
    rows = {b["key"]: b for b in get(base, "/api/backends")["backends"]}
    assert list(rows) == ["jsonl", "sqlite", "postgres", "mongodb"]
    assert rows["sqlite"]["active"] and rows["sqlite"]["location"] == "c.sqlite"
    assert [k for k, b in rows.items() if b["active"]] == ["sqlite"]
    assert rows["mongodb"]["available"] and rows["mongodb"]["location"] == "db.example:27017/filecat"
    assert "s3cret" not in json.dumps(rows) and "***" in rows["mongodb"]["title"]
    assert not rows["postgres"]["available"] and "FILECAT_TEST_PG_PASSWORD" in rows["postgres"]["error"]
    assert not rows["jsonl"]["available"]  # opening it would create an empty catalog


def test_backends_lists_startup_backend_missing_from_config(selector):
    base, other, write = selector
    write(other)  # the file now names another catalog than the one being served
    rows = {b["key"]: b for b in get(base, "/api/backends")["backends"]}
    assert rows["startup"]["active"] and rows["startup"]["location"] == "c.sqlite"
    assert not rows["sqlite"]["active"] and rows["sqlite"]["location"] == "other.sqlite"


def test_switch_backend_shows_other_roots(selector):
    base, other, write = selector
    assert get(base, "/api/info")["roots"] == [ROOT]
    write(other)
    info = post(base, "/api/backend", {"key": "sqlite"})
    assert info["roots"] == [OTHER] and info["location"].endswith("other.sqlite")
    assert get(base, "/api/info")["roots"] == [OTHER]
    assert get(base, "/api/records", root=OTHER)["total"] == 1
    rows = get(base, "/api/backends")["backends"]
    assert [b["key"] for b in rows if b["active"]] == ["sqlite"]
    assert post(base, "/api/backend", {"key": "startup"})["roots"] == [ROOT]  # and back


def test_failed_switch_keeps_active_backend(selector, tmp_path):
    base, other, write = selector
    bad = tmp_path / "isdir.sqlite"
    bad.mkdir()  # it exists, so it is offered, but sqlite cannot open a directory
    write(bad)
    with pytest.raises(urllib.error.HTTPError) as exc:
        post(base, "/api/backend", {"key": "sqlite"})
    assert exc.value.code == 500 and "error" in json.load(exc.value)
    # unavailable and unknown keys are refused as bad requests
    for key in ("postgres", "jsonl", "nope"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            post(base, "/api/backend", {"key": key})
        assert exc.value.code == 400
    assert get(base, "/api/info")["roots"] == [ROOT]
    assert [b["key"] for b in get(base, "/api/backends")["backends"] if b["active"]] == ["startup"]


def test_switch_needs_json(selector):
    base, other, write = selector
    req = urllib.request.Request(base + "/api/backend", data=b"key=sqlite",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 415
