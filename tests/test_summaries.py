"""Stored per-root summaries (summaries.py): one pass for the Summary and Graph pages, judged by the
root's change stamp and not by age, rebuilt in the background by the viewer, the scan, the
`summaries` server job and `filecat summaries`; plus the cheap Roots page and the response headers
(Server-Timing, gzip, ETag)."""
from __future__ import annotations

import argparse
import gzip
import http.client
import json
import threading
import time
import urllib.parse
from datetime import timedelta
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from filecat import cli, config, rootcase, rootinfo, root_remove, serve, server, server_cfg, summaries
from filecat.backends import open_backend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.record import new_document
from test_roots_actions import rig, roots_of, TYPO, FULL, BACKUP                                # noqa: F401
from test_server import agents_cfg, spec

ROOT = r"\\nas\share"
OTHER = r"\\nas\other"


def put_files(backend, root=ROOT, n=3, prefix="docs"):
    backend.put(new_document(root, "", kind="dir"))
    for i in range(n):
        backend.put({**new_document(root, f"{prefix}/f{i}.txt", kind="text", size=10 * (i + 1)), "mime": "text/plain",
                     "suffix": "txt"})
    backend.flush()


def scanned(backend, root=ROOT, *, write=None, remove=None):
    """What a scan of `root` leaves in the root index: it wrote the `write` records, removed `remove`."""
    tracker = rootinfo.ScanTracker(backend, root)
    attempt = rootinfo.begin(backend, root, tracker)
    for doc in write or ():
        tracker.put(doc)
    for rel in remove or ():
        tracker.delete(root, rel)
    rootinfo.finish(backend, root, attempt, tracker)
    time.sleep(0.01)        # a later build is newer than the stamp whatever the clock's resolution


def make(kind, tmp_path):
    out = str(tmp_path / ("c.sqlite" if kind == "sqlite" else "c.jsonl" if kind == "jsonl" else "catalog-dir"))
    return open_backend("jsonl" if kind == "jsonl_dir" else kind, out, None), out


# --- the builder ------------------------------------------------------------------------------------
@pytest.mark.parametrize("kind", ["sqlite", "jsonl", "jsonl_dir", "memory"])
def test_refresh_stores_the_aggregates_and_the_treemap_from_one_pass(kind, tmp_path):
    backend = MemoryBackend() if kind == "memory" else make(kind, tmp_path)[0]
    put_files(backend)
    reads = []
    real = backend.summary_docs
    backend.summary_docs = lambda root: (reads.append(root), real(root))[1]
    done = summaries.refresh(backend, ROOT)
    assert reads == [ROOT]                              # the records were read once, for both
    agg = backend.stored_aggregates(ROOT)[ROOT]
    [meta] = backend.list_treemaps(ROOT)
    assert agg["built_at"] == meta["built_at"] == done["built_at"] and agg["depth"] == 2
    assert (agg["total_files"], agg["total_bytes"]) == (3, 60) == (meta["files"], meta["bytes"])
    assert backend.stored_totals(ROOT)[ROOT]["total_files"] == 3
    # the same numbers the separate builders give
    from filecat.aggregate import build_aggregates
    want = build_aggregates(backend.list(root=ROOT), depth=2)["roots"][ROOT]
    assert {k: agg[k] for k in want} == want
    assert summaries.status(backend, ROOT)["state"] == "fresh"
    backend.close()


def test_a_root_with_no_files_still_gets_a_summary():
    backend = MemoryBackend()
    backend.put(new_document(ROOT, "", kind="dir"))
    summaries.refresh(backend, ROOT)
    assert backend.stored_totals(ROOT)[ROOT]["total_files"] == 0
    assert summaries.status(backend, ROOT)["state"] == "fresh"


def test_the_state_follows_the_root_not_the_clock():
    backend = MemoryBackend()
    put_files(backend)
    assert summaries.status(backend, ROOT)["state"] == "missing"
    scanned(backend, write=[new_document(ROOT, "docs/new.txt", kind="text", size=1)])
    summaries.refresh(backend, ROOT)
    assert summaries.status(backend, ROOT)["state"] == "fresh"
    # a scan that wrote nothing a summary counts (only the folder records, as every scan does)
    scanned(backend, write=[new_document(ROOT, "docs", kind="dir")])
    assert summaries.status(backend, ROOT)["state"] == "fresh"
    # one that wrote or removed a file
    scanned(backend, write=[new_document(ROOT, "docs/new2.txt", kind="text", size=1)])
    assert summaries.status(backend, ROOT)["state"] == "stale"
    summaries.refresh(backend, ROOT)
    scanned(backend, remove=["docs/new2.txt"])
    assert summaries.status(backend, ROOT)["state"] == "stale"
    summaries.refresh(backend, ROOT)
    # one is running: what is stored is served, marked, and rebuilt when the scan ends
    rootinfo.begin(backend, ROOT)
    assert summaries.status(backend, ROOT)["state"] == "scanning"
    assert not summaries.needs_refresh("scanning") and summaries.needs_refresh("stale")


def test_every_writer_of_a_roots_records_stamps_it():
    backend = MemoryBackend()
    put_files(backend)
    summaries.refresh(backend, ROOT)
    rootinfo.touch(backend, ROOT)
    assert summaries.status(backend, ROOT)["state"] == "stale"
    # roots case-merge: the records of `old` move into `new`
    new = r"\\NAS\Share"
    put_files(backend, new, prefix="more")
    summaries.refresh(backend, new)
    rootcase.merge(backend, ROOT, new)
    assert backend.get_root_info(new)["changed_at"]
    assert summaries.status(backend, new)["state"] == "fresh"       # the merge summarised it again
    assert backend.stored_totals(new)[new]["total_files"] == 6
    # roots remove: everything the viewer could serve for the root goes with it
    summaries.refresh(backend, new)
    root_remove.remove_root(backend, new, force=True)
    assert new not in backend.stored_totals() and backend.list_treemaps(new) == []
    assert backend.get_root_info(new) is None


def test_a_store_resum_scan_stamps_the_root_it_changed(fixture_dir):
    """store re-sum is a scan (server.run_store_resum_job): the stamp comes from the scan's own finish."""
    from filecat import scan
    from filecat.options import ScanOptions
    root = fixture_dir / "share"
    (root / "a").mkdir(parents=True)
    (root / "a" / "x.txt").write_text("x")
    backend = MemoryBackend()
    opts = ScanOptions()
    scan.scan_roots([str(root)], backend, opts, resume_path=str(fixture_dir / "r.json"))
    assert summaries.status(backend, str(root))["state"] == "fresh"     # the scan summarised it at its end
    first = backend.stored_totals(str(root))[str(root)]["built_at"]
    scan.scan_roots([str(root)], backend, opts, resume_path=str(fixture_dir / "r2.json"))
    assert backend.stored_totals(str(root))[str(root)]["built_at"] == first      # nothing changed: not rebuilt
    (root / "a" / "y.txt").write_text("yy")
    scan.scan_roots([str(root)], backend, opts, resume_path=str(fixture_dir / "r3.json"))
    assert backend.stored_totals(str(root))[str(root)]["built_at"] > first
    assert backend.stored_totals(str(root))[str(root)]["total_files"] == 2


# --- the viewer --------------------------------------------------------------------------------------
class Viewer:
    def __init__(self, kind, tmp_path, *, no_save=False, populate=True):
        self.backend, self.out = make(kind, tmp_path)
        if populate:
            put_files(self.backend)
        self.kind = kind
        self.args = SimpleNamespace(backend=kind, out=self.out, dsn=None, quiet=True, no_save=no_save)

    def start(self):
        self.backend.close()
        self.catalog = serve.Catalog(self.args)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), serve.make_handler(self.catalog, b"<html></html>"))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        return self

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.catalog.close()

    def get(self, path, headers=None, **params):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        conn.request("GET", path + "?" + urllib.parse.urlencode(params), headers=headers or {})
        res = conn.getresponse()
        raw = res.read()
        out = (res.status, dict(res.getheaders()), raw)
        conn.close()
        return out

    def json(self, path, **params):
        status, _, raw = self.get(path, **params)
        assert status == 200, raw
        return json.loads(raw)

    def settled(self, path, **params):
        deadline = time.monotonic() + 20
        while True:
            data = self.json(path, **params)
            if not data.get("building") and not data.get("refreshing"):
                return data
            assert time.monotonic() < deadline, data
            time.sleep(0.02)

    def with_backend(self, fn):
        """Change the catalog under the viewer, as a scan would (on its own backend thread)."""
        return self.catalog.call(fn)


@pytest.fixture(params=["sqlite", "jsonl"])
def viewer(request, tmp_path, monkeypatch):
    v = Viewer(request.param, tmp_path)
    v.counts = counts = {"refresh": 0, "reads": 0}
    real = summaries.refresh

    def counting(*a, **kw):
        counts["refresh"] += 1
        return real(*a, **kw)
    monkeypatch.setattr(summaries, "refresh", counting)
    v.start()
    yield v
    v.close()


def build(v):
    """Have the viewer's summary built (the first look queues it) and reset the counter."""
    first = v.json("/api/summary", root=ROOT)
    assert first["building"] is True and first["source"] == "building"
    done = v.settled("/api/summary", root=ROOT)
    assert done["source"] == "stored" and done["stale"] is False
    v.counts["refresh"] = 0
    v.json("/api/roots")        # the first look lists the distinct roots (a jsonl catalog does it itself)
    v.catalog.refresher.wait_idle()
    return done


def test_a_fresh_summary_is_served_without_reading_the_records(viewer, monkeypatch):
    build(viewer)
    from filecat.backends.jsonl import JsonlBackend
    spied = []
    for cls in (SqliteBackend, MemoryBackend, JsonlBackend):
        for name in ("sizes", "list", "summary_docs", "rollups", "query", "roots"):
            real = getattr(cls, name)

            def spy(self, *a, _real=real, _name=name, **kw):
                spied.append(_name)
                return _real(self, *a, **kw)
            monkeypatch.setattr(cls, name, spy)
    for _ in range(3):
        s = viewer.json("/api/summary", root=ROOT)
        t = viewer.json("/api/treemap", root=ROOT)
        assert s["source"] == t["source"] == "stored" and not s["stale"] and not t["stale"]
        assert (s["total_files"], t["files"]) == (3, 3)
        viewer.json("/api/roots")
    assert spied == [] and viewer.counts["refresh"] == 0


def test_the_summary_and_the_graph_come_from_one_build(viewer):
    s = viewer.settled("/api/summary", root=ROOT)
    t = viewer.settled("/api/treemap", root=ROOT)
    assert s["built_at"] == t["built_at"]
    assert viewer.counts["refresh"] == 1                  # not one for each page


def test_a_changed_root_is_served_stale_and_rebuilt_once(viewer, monkeypatch):
    if viewer.kind == "jsonl":
        pytest.skip("a jsonl catalog rebuilds on the backend thread, so a rebuild cannot be held half way")
    build(viewer)
    release = threading.Event()
    real = summaries.refresh

    def slow(*a, **kw):
        release.wait(10)
        return real(*a, **kw)
    monkeypatch.setattr(summaries, "refresh", slow)
    viewer.with_backend(lambda b: scanned(b, write=[{**new_document(ROOT, "docs/new.txt", kind="text", size=100),
                                                     "suffix": "txt"}]))
    seen = []
    for _ in range(4):
        seen.append(viewer.json("/api/summary", root=ROOT))
        seen.append(viewer.json("/api/treemap", root=ROOT))
        viewer.json("/api/roots")
    assert all(d["stale"] and d["source"] == "stored" and d["refreshing"] for d in seen)
    assert {d["total_files"] for d in seen if "total_files" in d} == {3}            # the old one, at once
    row = {r["root"]: r for r in viewer.json("/api/roots")["roots"]}[ROOT]
    assert row["summary_state"] == "stale" and row["refreshing"]
    release.set()
    done = viewer.settled("/api/summary", root=ROOT)
    assert done["stale"] is False and done["total_files"] == 4
    assert viewer.counts["refresh"] == 1                  # exactly one rebuild for all those requests
    assert viewer.settled("/api/treemap", root=ROOT)["files"] == 4


def test_an_unchanged_root_is_not_rebuilt_however_old_the_graph_max_age(viewer):
    build(viewer)
    viewer.catalog.max_age = timedelta(0)
    for _ in range(3):
        assert viewer.json("/api/treemap", root=ROOT)["stale"] is False
        assert viewer.json("/api/summary", root=ROOT)["stale"] is False
    assert viewer.counts["refresh"] == 0
    # a scan that found nothing to write leaves it as it was
    viewer.with_backend(lambda b: scanned(b, write=[new_document(ROOT, "docs", kind="dir")]))
    assert viewer.json("/api/summary", root=ROOT)["stale"] is False and viewer.counts["refresh"] == 0
    # any other view is on demand and reused for --graph-max-age
    assert viewer.json("/api/treemap", root=ROOT, depth=3)["source"] == "saved"
    assert viewer.json("/api/treemap", root=ROOT, depth=3)["source"] == "saved"


def test_a_scan_in_progress_marks_the_summary_stale_but_does_not_rebuild_it(viewer):
    build(viewer)
    viewer.with_backend(lambda b: rootinfo.begin(b, ROOT, rootinfo.ScanTracker(b, ROOT)))
    s = viewer.json("/api/summary", root=ROOT)
    assert s["stale"] is True and s["state"] == "scanning" and s["refreshing"] is False
    assert viewer.counts["refresh"] == 0


def test_refresh_param_queues_a_rebuild_and_serves_the_stored_summary(viewer):
    old = build(viewer)
    t = viewer.json("/api/treemap", root=ROOT, refresh=1)
    assert t["source"] == "stored" and t["refreshing"] is True
    new = viewer.settled("/api/treemap", root=ROOT)
    assert viewer.counts["refresh"] == 1 and new["built_at"] > old["built_at"]
    s = viewer.json("/api/summary", root=ROOT, rebuild=1)
    assert s["source"] == "stored" and s["refreshing"] is True
    viewer.settled("/api/summary", root=ROOT)
    assert viewer.counts["refresh"] == 2


def test_the_roots_page_asks_the_catalog_nothing_per_root(tmp_path, monkeypatch):
    v = Viewer("sqlite", tmp_path)
    for i in range(5):
        put_files(v.backend, rf"\\nas\r{i}")
    v.start()
    try:
        assert len(v.json("/api/roots")["roots"]) == 6
        v.catalog.refresher.wait_idle()
        calls = []
        for name in ("roots", "list", "query", "sizes", "get", "rollups", "get_stats"):
            real = getattr(SqliteBackend, name)

            def spy(self, *a, _real=real, _name=name, **kw):
                calls.append(_name)
                return _real(self, *a, **kw)
            monkeypatch.setattr(SqliteBackend, name, spy)
        for _ in range(3):
            rows = v.json("/api/roots")["roots"]
            v.json("/api/info")
        assert calls == [] and len(rows) == 6                   # no distinct, no query, no record read
        assert all(r["summary_state"] == "missing" and r["removable"] is False for r in rows)
    finally:
        v.close()


def test_roots_with_records_but_no_index_entry_still_appear(tmp_path):
    v = Viewer("sqlite", tmp_path).start()
    try:
        assert v.json("/api/info")["roots"] == [ROOT]           # from the distinct, listed once in the background
        assert [r["root"] for r in v.json("/api/roots")["roots"]] == [ROOT]
        v.with_backend(lambda b: put_files(b, OTHER))
        v.catalog._distinct_at = v.catalog._distinct_at - serve.ROOTS_TTL - timedelta(seconds=1)
        v.json("/api/roots")                                    # old cache: served, and listed again
        v.catalog.refresher.wait_idle()
        assert [r["root"] for r in v.json("/api/roots")["roots"]] == [OTHER, ROOT]
    finally:
        v.close()


def test_no_save_and_backends_without_stores_keep_the_in_memory_path(tmp_path, monkeypatch):
    v = Viewer("sqlite", tmp_path, no_save=True).start()
    try:
        s = v.json("/api/summary", root=ROOT)
        t = v.json("/api/treemap", root=ROOT)
        assert s["source"] == "computed" and t["source"] == "computed" and "building" not in s
        assert v.json("/api/treemap", root=ROOT)["source"] == "memory"
        assert v.catalog.refresher.state((v.catalog._where(), "summary", ROOT)) is None
        assert v.json("/api/roots")["stores"] is False
    finally:
        v.close()


# --- headers --------------------------------------------------------------------------------------------
def test_server_timing_gzip_and_etag(tmp_path):
    v = Viewer("sqlite", tmp_path, populate=False)
    for i in range(400):
        v.backend.put({**new_document(ROOT, f"folder{i:03}/file{i}.bin", kind="data", size=i + 1), "suffix": "bin"})
    v.backend.flush()
    v.start()
    try:
        v.settled("/api/treemap", root=ROOT)
        status, headers, raw = v.get("/api/treemap", {"Accept-Encoding": "gzip"}, root=ROOT)
        assert status == 200 and headers["Content-Encoding"] == "gzip" and headers["Vary"] == "Accept-Encoding"
        body = json.loads(gzip.decompress(raw))
        assert body["files"] == 400 and body["source"] == "stored"
        assert float(headers["X-Filecat-Time"].rstrip("ms")) >= 0 and headers["Server-Timing"].startswith("app;dur=")
        # without Accept-Encoding, or for a small body, it is sent as it is
        status, headers, raw = v.get("/api/treemap", root=ROOT)
        assert "Content-Encoding" not in headers and json.loads(raw)["files"] == 400
        status, headers, raw = v.get("/api/info", {"Accept-Encoding": "gzip"})
        assert "Content-Encoding" not in headers
        # the stored summary has an ETag that changes with its build and its state
        status, headers, raw = v.get("/api/summary", root=ROOT)
        tag = headers["ETag"]
        assert tag.startswith('W/"') and headers["Cache-Control"] == "no-cache"
        status, headers2, raw = v.get("/api/summary", {"If-None-Match": tag}, root=ROOT)
        assert status == 304 and raw == b"" and headers2["ETag"] == tag
        status, _, raw = v.get("/api/summary", {"If-None-Match": 'W/"other"'}, root=ROOT)
        assert status == 200 and json.loads(raw)["total_files"] == 400
        v.with_backend(lambda b: rootinfo.touch(b, ROOT))           # stale now: not the same answer
        status, headers3, raw = v.get("/api/summary", {"If-None-Match": tag}, root=ROOT)
        assert status == 200 and headers3["ETag"] != tag and json.loads(raw)["stale"] is True
        v.catalog.refresher.wait_idle()
    finally:
        v.close()


# --- refreshing from the page: the same login as Scan now ---------------------------------------------
def test_the_refresh_action_needs_the_session_and_the_csrf_checks(rig):
    path, body = "/api/summaries/refresh", {"root": FULL}
    status, data, headers = rig.request("GET", path)
    assert status == 405 and ("Allow", "POST") in headers
    assert rig.request("POST", path, body)[0] == 401                                          # no session
    session = rig.cookie()
    assert rig.request("POST", path, body, cookie=session, origin="http://evil.example")[0] == 403
    assert rig.request("POST", path, body, cookie=session, headers={"X-Filecat-Control": None})[0] == 403
    assert rig.request("POST", path, "x=1", cookie=session, ctype="application/x-www-form-urlencoded")[0] == 415
    assert rig.request("POST", path, {"root": r"\\nope\nope"}, cookie=session)[0] == 404
    assert rig.request("POST", path, {"root": 5}, cookie=session)[0] == 400
    catalog = rig.viewer.catalog
    assert catalog.refresher.wait_idle() and not rig.viewer.catalog.refresher.errors
    status, data, _ = rig.request("POST", path, body, cookie=session)
    assert status == 202 and data["root"] == FULL
    assert catalog.refresher.wait_idle()
    with SqliteBackend(rig.coord.catalog.out) as b:
        assert b.stored_totals(FULL)[FULL]["total_files"] == 1
        assert summaries.status(b, FULL)["state"] == "fresh"
    roots, body = roots_of(rig)
    assert roots[FULL]["summary_state"] == "fresh" and roots[TYPO]["removable"] is True and body["stores"] is True


# --- the server job, the config and the command ------------------------------------------------------------
def test_summaries_is_a_job_kind_without_an_agent():
    cfg = server_cfg.load_server({"server": {"jobs": [
        {"name": "sum", "kind": "summaries", "every": "1h", "roots": [ROOT], "options": ["--all"]},
        {"name": "all", "kind": "summaries", "at": "03:00"}]}}, agents_cfg("nas3"))
    sum_, all_ = cfg.jobs
    assert sum_.agent == all_.agent == server_cfg.LOCAL_AGENT == server.LOCAL_AGENT and sum_.roots == (ROOT,)
    bad = lambda **kw: server_cfg.load_server({"server": {"jobs": [{"name": "s", "kind": "summaries", "every": "1h", **kw}]}},
                                              agents_cfg("nas3"))
    for kw, text in (({"agent": "nas3"}, "agent does not apply"), ({"min_age": "1d"}, "min_age applies to store-resum"),
                     ({"options": ["--nope"]}, "options"), ({"options": ["--out", "x"]}, "must not contain --out")):
        with pytest.raises(config.ConfigError, match=text):
            bad(**kw)


def test_the_summaries_job_rebuilds_only_what_changed(tmp_path):
    backend, out = make("sqlite", tmp_path)
    put_files(backend)
    put_files(backend, OTHER)
    scanned(backend, OTHER)
    summaries.refresh(backend, OTHER)
    backend.close()
    ns = argparse.Namespace(backend="sqlite", out=out, dsn=None)
    ctx = server.JobContext(spec("sum", server_cfg.LOCAL_AGENT, kind="summaries"), None, [], {}, ns, threading.Event())
    result = server.run_summaries_job(ctx)
    assert result.outcome == "ok" and result.counts == {"roots": 2, "refreshed": 1, "skipped": 1, "failed": 0}
    assert server.run_summaries_job(ctx).counts["refreshed"] == 0
    ctx.spec = spec("sum", server_cfg.LOCAL_AGENT, kind="summaries", options=("--all",))
    assert server.run_summaries_job(ctx).counts["refreshed"] == 2
    ctx.cancel.set()
    with pytest.raises(KeyboardInterrupt):                          # the server records it as cancelled
        server.run_summaries_job(ctx)


def test_the_command_refreshes_and_reports(tmp_path, capsys):
    backend, out = make("sqlite", tmp_path)
    put_files(backend)
    backend.close()
    base = ["summaries", "--backend", "sqlite", "--out", out]
    status = ["summaries", "status", "--backend", "sqlite", "--out", out]
    assert cli.main([*status, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "missing"
    assert cli.main(base) == 0
    assert "1 of 1 roots refreshed" in capsys.readouterr().out
    assert cli.main(base) == 0
    assert "0 of 1 roots refreshed, 1 already current" in capsys.readouterr().out
    assert cli.main([*base, "--root", ROOT]) == 0
    assert "1 of 1 roots refreshed" in capsys.readouterr().out
    assert cli.main([*base, "--root", ROOT, "--stale"]) == 0
    assert "0 of 1 roots refreshed" in capsys.readouterr().out
    assert cli.main([*base, "--all", "--stale"]) == 2
    assert cli.main(status) == 0
    assert "fresh" in capsys.readouterr().out


def test_a_build_stamped_the_same_instant_as_a_change_is_stale():
    # Windows' clock ticks coarsely: a change and a build can carry one timestamp
    at = "2026-10-29T19:18:47.540000+00:00"
    assert summaries.state_of({"changed_at": at}, at) == "stale"
    # and a pass begun at that instant waits for the clock to move on, so it comes out fresh
    backend = MemoryBackend()
    put_files(backend)
    rootinfo.touch(backend, ROOT, at=rootinfo.now_precise())
    summaries.refresh(backend, ROOT)
    assert summaries.status(backend, ROOT)["state"] == "fresh"
