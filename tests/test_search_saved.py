"""Saved searches (/api/searches*) and the search export (/api/search/export) over HTTP on a
SQLite catalog, with and without a viewer password."""
from __future__ import annotations

import argparse
import csv
import http.client
import io
import json

import pytest

from filecat import control_auth, serve
from filecat.backends.sqlite import SqliteBackend
from filecat.record import root_id

NAS = r"\\nas-main\homes"
LOCAL = "/data/local"
PASSWORD = "correct horse battery"
HASH = control_auth.hash_password(PASSWORD)
T2024 = 1_704_067_200 * 1_000_000_000


def doc(root, rel, size=10, kind="file", **extra):
    name = rel.rsplit("/", 1)[-1]
    suffix = "" if kind in ("dir", "rollup") or "." not in name else name.rsplit(".", 1)[1].lower()
    return {"root_id": root_id(root), "root": root, "rel_path": rel, "name": name, "size": size,
            "mtime_ns": T2024, "kind": kind, "suffix": suffix, **extra}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "c.sqlite")
    with SqliteBackend(path) as b:
        for i in range(12):
            b.put(doc(NAS, f"a/report{i:02d}.pdf", 100 + i, sha256=f"{i:064x}"))
        b.put(doc(NAS, 'a/say "hi", ok.pdf', 5))
        b.put(doc(LOCAL, "x/local.pdf", 7))
        b.put(doc(NAS, "[REDACTED]", 4000, kind="rollup", probe={"rollup": {"tag": "[REDACTED]", "matched": 1}}))
        b.put(doc(NAS, "cache/[CACHE]", 9000, kind="rollup", probe={"rollup": {"tag": "[CACHE]", "matched": 2}}))
    return path


class Viewer:
    def __init__(self, db, *, password=False, view_login=False, **extra):
        self.auth = None
        if password:
            self.auth = control_auth.ControlAuth(HASH, control_auth.LoginGuard(), control_auth.Sessions(),
                                                 view_login, fail_delay=0.0)
        ns = argparse.Namespace(backend="sqlite", out=db, dsn=None, host="127.0.0.1", port=0, quiet=True,
                                no_save=False, graph_max_age=120, open=False, control_auth=self.auth, **extra)
        self.viewer = serve.start_viewer(ns, object() if password else None)
        self.port = self.viewer.httpd.server_address[1]

    def request(self, method, path, body=None, *, cookie=None, csrf=True, ctype="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        h = {"Content-Type": ctype}
        if csrf:
            h["X-Filecat-Control"] = "run"
        if cookie:
            h["Cookie"] = cookie
        conn.request(method, path, json.dumps(body) if body is not None else None, h)
        res = conn.getresponse()
        raw = res.read()
        out = (res.status, raw, dict(res.getheaders()))
        conn.close()
        return out

    def json(self, method, path, body=None, **kw):
        status, raw, headers = self.request(method, path, body, **kw)
        return status, (json.loads(raw) if raw else {})

    def login(self):
        status, raw, headers = self.request("POST", "/api/login", {"password": PASSWORD})
        assert status == 200
        return headers["Set-Cookie"].split(";")[0]

    def close(self):
        self.viewer.stop()


@pytest.fixture
def v(db):
    viewer = Viewer(db)
    yield viewer
    viewer.close()


def save(v, name="Reports", q="report*.pdf", **extra):
    status, data = v.json("POST", "/api/searches/save", {"name": name, "params": {"q": q}, **extra})
    assert status == 200, data
    return data["search"]


# --- saved searches ------------------------------------------------------------------
def test_create_list_update_pin_delete(v):
    assert v.json("GET", "/api/searches")[1]["searches"] == []
    a = save(v, "Reports", "report*.pdf", params={"q": "report*.pdf", "sort": "size", "desc": "1", "host": "nas-main"})
    b = save(v, "alpha", "*.zip")
    assert a["pinned"] is False and a["created_at"] and a["id"] != b["id"]
    assert a["params"] == {"q": "report*.pdf", "sort": "size", "desc": "1", "host": "nas-main"}
    status, data = v.json("POST", "/api/searches/save", {"id": a["id"], "pinned": True})
    assert status == 200 and data["search"]["pinned"] is True and data["search"]["name"] == "Reports"
    assert data["search"]["created_at"] == a["created_at"]
    status, data = v.json("POST", "/api/searches/save", {"id": b["id"], "name": "  Zips  ", "params": {"q": "x*.zip", "ext": "zip"}})
    assert data["search"]["name"] == "Zips" and data["search"]["params"] == {"q": "x*.zip", "ext": "zip"}
    listed = v.json("GET", "/api/searches")[1]["searches"]
    assert [s["name"] for s in listed] == ["Reports", "Zips"]          # pinned first
    assert v.json("POST", "/api/searches/delete", {"id": a["id"]})[1] == {"deleted": True}
    assert v.json("POST", "/api/searches/delete", {"id": a["id"]})[1] == {"deleted": False}
    assert [s["name"] for s in v.json("GET", "/api/searches")[1]["searches"]] == ["Zips"]


def test_saved_searches_survive_a_restart(db):
    one = Viewer(db)
    try:
        save(one, "Kept", "x*")
    finally:
        one.close()
    two = Viewer(db)
    try:
        assert [s["name"] for s in two.json("GET", "/api/searches")[1]["searches"]] == ["Kept"]
    finally:
        two.close()


@pytest.mark.parametrize("body", [
    {"name": "", "params": {"q": "x"}},
    {"name": "x" * 500, "params": {"q": "x"}},
    {"name": "n"},
    {"params": {"q": "x"}},
    {"name": "n", "params": {"q": "x", "limit": "5"}},          # not a search key
    {"name": "n", "params": {"q": "size:huge"}},                # a query that does not parse
    {"name": "n", "params": {"sort": "size"}},                  # no criterion
    {"name": "n", "params": {"q": "x" * 600}},
    {"name": "n", "params": "q=x"},
    {"name": "n", "params": {"q": "x"}, "pinned": "yes"},
    {"id": "nope", "name": "n"},
])
def test_validation(v, body):
    status, data = v.json("POST", "/api/searches/save", body)
    assert status == 400 and data["error"]
    assert v.json("GET", "/api/searches")[1]["searches"] == []


def test_delete_needs_an_id(v):
    assert v.json("POST", "/api/searches/delete", {})[0] == 400


def test_the_number_of_saved_searches_is_capped(v, monkeypatch):
    from filecat import search_saved
    monkeypatch.setattr(search_saved, "MAX_SAVED", 3)
    for i in range(3):
        save(v, f"s{i}", f"x{i}")
    status, data = v.json("POST", "/api/searches/save", {"name": "more", "params": {"q": "y"}})
    assert status == 400 and "at most 3" in data["error"]


def test_saved_search_writes_need_a_session_when_a_password_is_set(db):
    v = Viewer(db, password=True)
    try:
        body = {"name": "n", "params": {"q": "x"}}
        assert v.json("POST", "/api/searches/save", body)[0] == 401                  # no session
        assert v.json("POST", "/api/searches/save", body, csrf=False, cookie=v.login())[0] == 403   # no CSRF header
        assert v.json("POST", "/api/searches/save", body, cookie=v.login(), ctype="text/plain")[0] == 415
        assert v.json("GET", "/api/searches")[1]["searches"] == []                   # reading is open here
        cookie = v.login()
        status, data = v.json("POST", "/api/searches/save", body, cookie=cookie)
        assert status == 200
        assert v.json("POST", "/api/searches/delete", {"id": data["search"]["id"]})[0] == 401
        assert v.json("POST", "/api/searches/delete", {"id": data["search"]["id"]}, cookie=cookie)[1] == {"deleted": True}
    finally:
        v.close()


def test_login_required_for_view_gates_the_saved_searches_and_the_export(db):
    v = Viewer(db, password=True, view_login=True)
    try:
        assert v.json("GET", "/api/searches")[0] == 401
        assert v.request("GET", "/api/search/export?q=report*")[0] == 401
        assert v.json("POST", "/api/searches/save", {"name": "n", "params": {"q": "x"}})[0] == 401
        cookie = v.login()
        assert v.json("GET", "/api/searches", cookie=cookie)[0] == 200
        assert v.request("GET", "/api/search/export?q=report*", cookie=cookie)[0] == 200
    finally:
        v.close()


# --- export --------------------------------------------------------------------------
def export(v, fmt="csv", **params):
    from urllib.parse import urlencode
    status, raw, headers = v.request("GET", "/api/search/export?" + urlencode({"format": fmt, **params}))
    return status, raw, headers


def csv_rows(raw):
    assert raw.startswith(b"\xef\xbb\xbf")                       # the BOM Excel wants
    return list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))


def test_csv_header_rows_and_quoting(v):
    status, raw, headers = export(v, "csv", q='hi ext:pdf', root=NAS)
    assert status == 200 and headers["Content-Type"].startswith("text/csv")
    assert headers["Content-Disposition"].startswith('attachment; filename="filecat-search-') \
        and headers["Content-Disposition"].endswith('.csv"')
    assert "X-Filecat-Truncated" not in headers
    rows = csv_rows(raw)
    assert rows[0] == ["host", "root", "path", "name", "ext", "size", "mtime", "kind", "sha256"]
    assert rows[1] == ["nas-main", NAS, NAS + '\\a\\say "hi", ok.pdf', 'say "hi", ok.pdf', "pdf", "5",
                       "2024-01-01T00:00:00Z", "file", ""]
    assert len(rows) == 2
    assert b'"say ""hi"", ok.pdf"' in raw                         # doubled quotes, quoted field


def test_a_csv_cell_never_starts_a_formula():
    from filecat.search_saved import csv_cell
    for text in ("=cmd|' /C calc'!A0", "+1", "-x.txt", "@sum", "\tx", "\rx"):
        assert csv_cell(text) == "'" + text
    assert csv_cell("a=b.txt") == "a=b.txt" and csv_cell(5) == 5 and csv_cell(None) == ""


def test_jsonl_and_sha256(v):
    status, raw, headers = export(v, "jsonl", q="report00.pdf")
    assert status == 200 and "ndjson" in headers["Content-Type"] and headers["Content-Disposition"].endswith('.jsonl"')
    lines = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    assert len(lines) == 1 and lines[0]["sha256"] == "0" * 64
    assert lines[0]["size"] == 100 and lines[0]["ext"] == "pdf" and lines[0]["host"] == "nas-main"
    assert lines[0]["path"] == NAS + "\\a\\report00.pdf"


def test_a_local_root_path_uses_slashes(v):
    rows = csv_rows(export(v, "csv", q="local.pdf")[1])
    assert rows[1][0] == "" and rows[1][2] == "/data/local/x/local.pdf"


def test_every_page_is_exported_whatever_offset_and_limit(v, monkeypatch):
    monkeypatch.setattr("filecat.search_saved.EXPORT_CHUNK", 5)       # 14 matches: three chunks
    status, raw, headers = export(v, "csv", q="*.pdf", limit="2", offset="3", sort="name")
    rows = csv_rows(raw)[1:]
    assert status == 200 and len(rows) == 14 and "X-Filecat-Truncated" not in headers
    assert len({r[2] for r in rows}) == 14
    assert [r[3] for r in rows] == sorted((r[3] for r in rows), key=str.lower)


def test_the_cap_truncates_and_says_so(db, monkeypatch):
    monkeypatch.setattr("filecat.search_saved.EXPORT_CHUNK", 4)
    v = Viewer(db, search_export_max_rows=6)
    try:
        status, raw, headers = export(v, "csv", q="*.pdf")
        assert status == 200 and headers["X-Filecat-Truncated"] == "1" and len(csv_rows(raw)) == 1 + 6
        lines = [json.loads(x) for x in export(v, "jsonl", q="*.pdf")[1].decode().splitlines()]
        assert len(lines) == 7 and lines[-1] == {"truncated": True, "max_rows": 6}
        exact = Viewer(db, search_export_max_rows=14)                 # exactly all of them: not truncated
        try:
            status, raw, headers = export(exact, "csv", q="*.pdf")
            assert "X-Filecat-Truncated" not in headers and len(csv_rows(raw)) == 15
            assert b"truncated" not in export(exact, "jsonl", q="*.pdf")[1]
        finally:
            exact.close()
    finally:
        v.close()


def test_a_redacted_rollup_is_never_exported(v):
    raw = export(v, "csv", q="kind:rollup")[1]
    rows = csv_rows(raw)
    assert [r[3] for r in rows[1:]] == ["[CACHE]"]
    assert b"REDACTED" not in export(v, "jsonl", q="redacted")[1]
    assert b"REDACTED" not in export(v, "csv", q="*")[1]


def test_export_errors(v):
    assert export(v, "csv")[0] == 400                                  # no criterion
    assert export(v, "xml", q="x")[0] == 400
    assert export(v, "csv", q="size:huge")[0] == 400
    status, raw, _ = export(v, "csv", q="x", root="no-such-root")      # no root matches: header only
    assert status == 200 and len(csv_rows(raw)) == 1


def test_the_export_cap_comes_from_config():
    from filecat import server_cfg
    assert server_cfg.load_server({"server": {"search_export_max_rows": 50}}, {}).search_export_max_rows == 50
    assert server_cfg.load_server({}, {}).search_export_max_rows == 1_000_000
    with pytest.raises(Exception):
        server_cfg.load_server({"server": {"search_export_max_rows": 0}}, {})
