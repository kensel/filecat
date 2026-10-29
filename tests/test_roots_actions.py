"""The Roots page actions: an ad-hoc scan of one root (Coordinator.request_scan, POST
/api/roots/scan) and removing a root that holds nothing (root_remove, POST /api/roots/remove,
`filecat roots remove`). Same guards as "run now": docs/agent-server.md section 7."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

import pytest

from filecat import cli, root_remove, rootinfo
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.record import root_id
from filecat.server import ADHOC_KIND, LOCAL_AGENT, JobResult
from test_server import make_coord, spec, wait_for                                   # noqa: F401
from test_server_control import GOOD, Rig, start                                       # noqa: F401

BACKUP = r"\\nas3\Backup"
TYPO = r"\\nas3\Bakcup"
FULL = r"\\nas4\Full"
LOCAL = "/srv/local-root"


def put_doc(backend, root, rel, kind="file", **extra):
    backend.put({"root_id": root_id(root), "root": root, "rel_path": rel, "name": rel.rsplit("/", 1)[-1],
                 "kind": kind, "size": 5, "mtime_ns": 1, "suffix": "txt", **extra})


def put_info(backend, root, attempt="failed", **last):
    info = {"root_id": root_id(root), "root": root,
            "last_attempt": {"status": attempt, "started_at": "2026-01-01T00:00:00+00:00",
                             "heartbeat_at": datetime.now(timezone.utc).isoformat(), "finished_at": None}}
    if last:
        info["last_scan"] = last
    backend.put_root_info(info)


def put_snapshot(backend, root):
    backend.put_treemap({"id": "tm-" + root_id(root), "root_id": root_id(root), "root": root, "prefix": "",
                         "depth": 2, "built_at": "2026-01-01T00:00:00+00:00", "files": 0, "bytes": 0, "pin": None},
                        {"root": root, "children": []})


def seed(path):
    """TYPO: a root of nothing (index entry, empty summary, a treemap); FULL: one file."""
    b = SqliteBackend(path)
    put_info(b, TYPO, "failed")
    put_snapshot(b, TYPO)
    b.replace_aggregates({TYPO: {"suffix": [], "mime": [], "dir": [], "total_files": 0, "total_bytes": 0,
                                 "unreadable": 0}}, 2, "2026-01-01T00:00:00+00:00", TYPO)
    put_doc(b, FULL, "a.txt")
    put_info(b, FULL, "ok", files=1, dirs=0, status="ok")
    put_doc(b, BACKUP, "keep.txt")
    put_info(b, BACKUP, "ok", files=1, dirs=0, status="ok")
    b.close()


# --- the coordinator ------------------------------------------------------------------------------
def test_request_scan_goes_through_the_covering_agent_or_smb_and_is_recorded():
    seen: list[tuple] = []
    release = threading.Event()

    def scan_root(ctx):
        seen.append((ctx.spec.name, ctx.spec.kind, ctx.spec.roots, ctx.agent.name if ctx.agent else None))
        release.wait(10)
        return JobResult("ok", 0, {"files": 2})
    coord, clock, _ = make_coord([], runners={ADHOC_KIND: scan_root}, max_concurrent=5)
    start(coord, clock)
    status, body = coord.request_scan(BACKUP, "10.0.0.7")
    assert status == 202 and body["agent"] == "nas3" and body["queued"] is True
    assert coord.request_scan(BACKUP, "10.0.0.8")[0] == 409                    # queued already
    assert coord.scanning(BACKUP) == "a scan of this root is queued"
    status, body = coord.request_scan(LOCAL, "10.0.0.7")
    assert status == 202 and body["agent"] == LOCAL_AGENT
    assert coord.request_scan(r"\\nas3\Other", "10.0.0.7")[0] == 202           # nas3 is busy: it waits
    assert coord.request_scan("", "x")[0] == 400
    coord.tick()
    assert wait_for(lambda: len(seen) == 2)
    assert sorted(seen) == sorted([("scan:" + BACKUP, ADHOC_KIND, (BACKUP,), "nas3"),
                                   ("scan:" + LOCAL, ADHOC_KIND, (LOCAL,), None)])
    assert coord.request_scan(BACKUP, "10.0.0.8")[0] == 409                    # running now
    assert "running" in coord.scanning(BACKUP)
    jobs = {j["name"]: j for j in coord.jobs_snapshot()}
    assert jobs["scan:" + BACKUP]["running"] and jobs["scan:" + BACKUP]["adhoc"] and jobs["scan:" + BACKUP]["schedule"] == "ad hoc"
    assert jobs["scan:" + r"\\nas3\Other"]["queued"]
    coord.tick()
    assert len(seen) == 2                                                      # per-agent exclusivity holds
    release.set()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs and len(seen) == 3)
    assert wait_for(lambda: coord.tick() is not None and not coord.runs and not coord.manual)
    rows = {r["job"]: r for r in coord.store.recent(10)}
    row = rows["scan:" + BACKUP]
    assert row["kind"] == ADHOC_KIND and row["trigger"] == "manual" and row["requested_from"] == "10.0.0.7"
    assert row["agent"] == "nas3" and row["roots"] == [BACKUP] and row["outcome"] == "ok" and row["counts"] == {"files": 2}
    assert rows["scan:" + LOCAL]["agent"] == LOCAL_AGENT
    assert coord.sched.jobs == [] and coord.scanning(BACKUP) is None          # an ad-hoc job leaves nothing behind
    assert coord.request_scan(BACKUP, "10.0.0.7")[0] == 202                    # and can be asked for again
    coord.shutdown()


def test_request_scan_refuses_a_down_agent_a_running_job_and_a_stopping_server():
    down = {"nas3"}

    def probe(agent, timeout=5.0, table=None):
        from filecat import agent_status
        if agent.name in down:
            return agent_status.AgentStatus(agent.name, agent.endpoint, error="refused")
        return agent_status.AgentStatus(agent.name, agent.endpoint, reachable=True, cert_pin="ok", version="0.2.0")
    release = threading.Event()
    job = spec("backup", "nas4", roots=(FULL,), run_on_start=True)
    coord, clock, _ = make_coord([job], probe=probe, runners={"scan": lambda ctx: (release.wait(10), JobResult("ok", 0, {}))[1]})
    start(coord, clock)
    status, body = coord.request_scan(BACKUP, "x")
    assert status == 409 and "nas3 is down" in body["error"]
    coord.tick()
    assert wait_for(lambda: "backup" in coord.runs)
    status, body = coord.request_scan(FULL, "x")
    assert status == 409 and "job backup is scanning it" in body["error"]
    release.set()
    wait_for(lambda: coord.tick() is not None and not coord.runs)
    coord.stopping = True
    assert coord.request_scan(FULL, "x")[0] == 409
    coord.stopping = False
    coord.shutdown()


# --- over HTTP ------------------------------------------------------------------------------------
@pytest.fixture
def rig(fixture_dir):
    seed(str(fixture_dir / "cat.sqlite"))
    r = Rig(fixture_dir, runners={"scan": lambda ctx: JobResult("ok", 0, {}),
                                  ADHOC_KIND: lambda ctx: JobResult("ok", 0, {"files": 0})})
    yield r
    r.close()


def roots_of(rig, cookie=None):
    status, body, _ = rig.request("GET", "/api/roots", cookie=cookie)
    assert status == 200
    return {r["root"]: r for r in body["roots"]}, body


def test_the_roots_api_marks_the_roots_that_may_be_removed(rig):
    roots, body = roots_of(rig)
    assert roots[TYPO]["removable"] is True
    assert roots[FULL]["removable"] is False and roots[BACKUP]["removable"] is False
    assert body["control"]["available"] is True


@pytest.mark.parametrize("path,body", [("/api/roots/scan", {"root": TYPO}),
                                       ("/api/roots/remove", {"root": TYPO, "confirm": TYPO})])
def test_both_actions_have_the_guards_of_run_now(rig, path, body):
    status, data, headers = rig.request("GET", path)
    assert status == 405 and ("Allow", "POST") in headers
    assert rig.request("POST", path, body)[0] == 401                                          # no session
    session = rig.cookie()
    assert rig.request("POST", path, body, cookie=session, origin="http://evil.example")[0] == 403
    assert rig.request("POST", path, body, cookie=session, origin="null")[0] == 403
    assert rig.request("POST", path, body, cookie=session, headers={"X-Filecat-Control": None})[0] == 403
    assert rig.request("POST", path, "x=1", cookie=session, ctype="application/x-www-form-urlencoded")[0] == 415
    assert rig.request("POST", path, body, cookie=session, headers={"Host": "evil.example"})[0] == 403
    assert rig.request("POST", path, "[1]", cookie=session)[0] == 400
    assert rig.coord.manual == {} and TYPO in roots_of(rig)[0]                                # nothing happened


def test_no_password_or_no_coordinator_disables_both_actions(fixture_dir):
    seed(str(fixture_dir / "cat.sqlite"))
    r = Rig(fixture_dir, with_hash=False)
    try:
        assert r.request("POST", "/api/roots/scan", {"root": TYPO})[0] == 403
        assert r.request("POST", "/api/roots/remove", {"root": TYPO, "confirm": TYPO})[0] == 403
        assert roots_of(r)[1]["control"]["available"] is False
    finally:
        r.close()
    import argparse
    import http.client
    from filecat import serve
    ns = argparse.Namespace(backend="sqlite", out=str(fixture_dir / "cat.sqlite"), dsn=None, host="127.0.0.1",
                            port=0, quiet=True, no_save=False, graph_max_age=120, open=False)
    viewer = serve.start_viewer(ns)                                    # a plain `filecat serve`
    try:
        for path, body in (("/api/roots/scan", {"root": TYPO}), ("/api/roots/remove", {"root": TYPO, "confirm": TYPO})):
            conn = http.client.HTTPConnection("127.0.0.1", viewer.httpd.server_address[1])
            conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json", "X-Filecat-Control": "run"})
            assert conn.getresponse().status == 404
    finally:
        viewer.stop()


def test_scan_queues_exactly_that_root(rig):
    session = rig.cookie()
    assert rig.request("POST", "/api/roots/scan", {"root": r"\\nas3\Nope"}, cookie=session)[0] == 404
    assert rig.request("POST", "/api/roots/scan", {}, cookie=session)[0] == 400
    status, body, _ = rig.request("POST", "/api/roots/scan", {"root": BACKUP}, cookie=session)
    assert status == 202 and body["queued"] and body["agent"] == "nas3"
    assert roots_of(rig)[0][BACKUP]["busy"] == "a scan of this root is queued"
    assert rig.request("POST", "/api/roots/scan", {"root": BACKUP}, cookie=session)[0] == 409
    rig.coord.tick()
    assert wait_for(lambda: rig.coord.tick() is not None and not rig.coord.runs and not rig.coord.manual)
    row = next(r for r in rig.coord.store.recent(5) if r["job"] == "scan:" + BACKUP)
    assert row["trigger"] == "manual" and row["requested_from"] == "127.0.0.1" and row["outcome"] == "ok"
    status, jobs, _ = rig.request("GET", "/api/jobs")
    assert any(r["job"] == "scan:" + BACKUP for r in jobs["recent"])
    assert all(not j.get("adhoc") for j in jobs["jobs"])                                       # gone once finished


def test_remove_deletes_the_root_and_what_belongs_to_it(rig, fixture_dir):
    session = rig.cookie()
    path = "/api/roots/remove"
    assert rig.request("POST", path, {"root": TYPO, "confirm": "wrong"}, cookie=session)[0] == 400
    assert rig.request("POST", path, {"root": TYPO}, cookie=session)[0] == 400
    assert rig.request("POST", path, {"root": r"\\nas3\Nope", "confirm": r"\\nas3\Nope"}, cookie=session)[0] == 404
    status, body, _ = rig.request("POST", path, {"root": FULL, "confirm": FULL}, cookie=session)
    assert status == 409 and "still has 1 record" in body["error"]                              # records: never from the web
    resume = fixture_dir / "cat.sqlite.resume.json"
    resume.write_text(json.dumps({"version": 2, "roots": {TYPO: {"x": {"mtime_ns": 1, "child_count": 0}}, FULL: {}}}))
    status, body, _ = rig.request("POST", path, {"root": TYPO, "confirm": TYPO}, cookie=session)
    assert status == 200 and body["removed"]["treemaps"] == 1 and body["removed"]["resume_files"] == 1
    assert TYPO not in roots_of(rig)[0] and FULL in roots_of(rig)[0]
    assert TYPO not in json.loads(resume.read_text())["roots"]
    b = SqliteBackend(str(fixture_dir / "cat.sqlite"))
    try:
        assert b.get_root_info(TYPO) is None and b.list_treemaps(TYPO) == [] and b.stored_aggregates(TYPO) == {}
        assert b.get(FULL, "a.txt") is not None and b.get_root_info(FULL) is not None
    finally:
        b.close()
    assert rig.request("POST", path, {"root": TYPO, "confirm": TYPO}, cookie=session)[0] == 404   # gone


def test_remove_refuses_a_root_being_scanned(rig, fixture_dir):
    session = rig.cookie()
    b = SqliteBackend(str(fixture_dir / "cat.sqlite"))
    put_info(b, TYPO, "running")                      # a scan elsewhere (the CLI) with a fresh heartbeat
    b.close()
    assert roots_of(rig)[0][TYPO]["removable"] is False
    status, body, _ = rig.request("POST", "/api/roots/remove", {"root": TYPO, "confirm": TYPO}, cookie=session)
    assert status == 409 and "scan is running" in body["error"]
    b = SqliteBackend(str(fixture_dir / "cat.sqlite"))
    put_info(b, TYPO, "failed")
    b.close()
    assert rig.request("POST", "/api/roots/scan", {"root": TYPO}, cookie=session)[0] == 202   # queued here now
    status, body, _ = rig.request("POST", "/api/roots/remove", {"root": TYPO, "confirm": TYPO}, cookie=session)
    assert status == 409 and "being scanned here" in body["error"]


# --- root_remove and the command ---------------------------------------------------------------
def make(kind, d):
    return {"memory": lambda: MemoryBackend(), "sqlite": lambda: SqliteBackend(str(d / "c.sqlite")),
            "jsonl": lambda: JsonlBackend(str(d / "c.jsonl"))}[kind]()


@pytest.mark.parametrize("kind", ["memory", "sqlite", "jsonl"])
def test_remove_root_with_and_without_force(kind, fixture_dir):
    b = make(kind, fixture_dir)
    put_info(b, TYPO, "failed")
    put_snapshot(b, TYPO)
    put_doc(b, FULL, "d", kind="dir")
    put_doc(b, FULL, "d/[CACHE]", kind="rollup")                    # a rollup counts as a record
    for i in range(5):
        put_doc(b, FULL, f"d/f{i}.txt")
    put_doc(b, BACKUP, "keep.txt")
    b.flush()
    assert root_remove.count_records(b, FULL) == 7 and root_remove.count_records(b, TYPO) == 0
    assert root_remove.has_records(b, FULL) and not root_remove.has_records(b, TYPO)
    with pytest.raises(root_remove.RootError, match="still has 7 records") as exc:
        root_remove.remove_root(b, FULL)
    assert exc.value.status == 409 and root_remove.count_records(b, FULL) == 7
    with pytest.raises(root_remove.RootError) as exc:
        root_remove.remove_root(b, r"\\nas3\Nope")
    assert exc.value.status == 404
    done = root_remove.remove_root(b, TYPO)
    assert done["records"] == 0 and done["treemaps"] == 1
    assert TYPO not in [r["root"] for r in rootinfo.index(b)]
    done = root_remove.remove_root(b, FULL, force=True)
    assert done["records"] == 7
    assert FULL not in b.roots() and BACKUP in b.roots() and b.get(BACKUP, "keep.txt") is not None
    b.close()


def test_remove_root_refuses_while_a_scan_runs_even_with_force():
    b = MemoryBackend()
    put_doc(b, FULL, "a.txt")
    put_info(b, FULL, "running")
    with pytest.raises(root_remove.RootError, match="scan is running"):
        root_remove.remove_root(b, FULL, force=True)
    assert root_remove.count_records(b, FULL) == 1


def run_cli(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_roots_remove_command(fixture_dir, capsys, monkeypatch):
    db = str(fixture_dir / "cat.sqlite")
    seed(db)
    base = ["roots", "remove", "--backend", "sqlite", "--out", db]
    assert run_cli(capsys, *base)[0] == 2                                             # no root named
    assert run_cli(capsys, *base, r"\\nas3\Nope")[0] == 2
    code, out, err = run_cli(capsys, *base, FULL)
    assert code == 1 and "still has 1 record" in err and "--force" in err
    code, out, _ = run_cli(capsys, *base, TYPO, "--dry-run")
    assert code == 0 and "would remove" in out
    code, out, err = run_cli(capsys, *base, TYPO)
    assert code == 0 and f"{TYPO}: removed" in out and "1 treemap snapshots" in out
    # --force deletes records: not without --yes when there is no terminal, never on a wrong confirmation
    assert run_cli(capsys, *base, FULL, "--force")[0] == 2
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert run_cli(capsys, *base, FULL, "--force")[0] == 1
    monkeypatch.setattr("builtins.input", lambda prompt="": FULL)
    code, out, _ = run_cli(capsys, *base, FULL, "--force")
    assert code == 0 and "1 records" in out
    code, out, _ = run_cli(capsys, *base, BACKUP, "--force", "--yes")
    assert code == 0
    b = SqliteBackend(db)
    try:
        assert b.roots() == [] and list(b.list_root_info()) == []
    finally:
        b.close()
