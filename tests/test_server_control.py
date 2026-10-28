"""filecat server: the first run of a job, "run now", and the viewer's login (docs/agent-server.md)."""
from __future__ import annotations

import argparse
import http.client
import json
import threading
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path

import pytest

from filecat import cli, config, control_auth, serve, server, server_cfg, server_store
from filecat.backends import open_backend
from filecat.server import Coordinator, JobResult
from filecat.server_cfg import ServerConfig
from filecat.server_store import Handle, ServerStore
from test_server import (Clock, JOBS, T0, agents_cfg, make_coord, nas3, ok_probe, run_cli, spec,  # noqa: F401
                         wait_for, write_config)


def start(coord, clock):
    coord.acquire()
    coord.probe_due(clock(), wait=True)


# --- the first run of a job ---------------------------------------------------------------------
def test_an_every_job_waits_one_interval_from_first_seen_and_a_restart_does_not_push_it_back():
    started: list[str] = []
    runners = {"scan": lambda ctx: started.append(ctx.spec.name) or JobResult("ok", 0, {})}
    jobs = [spec("nightly", "nas3", every=timedelta(hours=24), run_on_start=False)]
    coord, clock, shared = make_coord(jobs, runners=runners)
    start(coord, clock)
    coord.tick()
    clock.advance(hours=23)
    coord.tick()
    assert started == []                                    # not at start, not before the interval
    coord.shutdown()
    # a restart 23 h in: the first-seen time (persisted) still anchors the first run
    coord2, _, _ = make_coord(jobs, clock=clock, runners=runners, shared=shared)
    start(coord2, clock)
    coord2.tick()
    assert started == []
    clock.advance(hours=1, minutes=1)                       # T0 + 24 h 1 m: not 24 h after the restart
    coord2.tick()
    assert wait_for(lambda: started == ["nightly"])
    coord2.shutdown()


def test_a_daily_job_waits_for_its_next_time_of_day_and_run_on_start_keeps_the_old_behaviour():
    started: list[str] = []
    runners = {"scan": lambda ctx: started.append(ctx.spec.name) or JobResult("ok", 0, {})}
    jobs = [spec("at-0230", "nas3", every=None, at=(dtime(2, 30),), run_on_start=False),
            spec("eager", "nas4", every=timedelta(hours=24), run_on_start=True)]
    coord, clock, _ = make_coord(jobs, runners=runners)     # T0 is 01:00
    start(coord, clock)
    coord.tick()
    assert wait_for(lambda: started == ["eager"])           # run_on_start: at once
    clock.advance(hours=1)
    coord.tick()
    assert started == ["eager"]                             # 02:00: the slot is not here yet
    clock.advance(minutes=31)
    coord.tick()
    assert wait_for(lambda: sorted(started) == ["at-0230", "eager"])
    coord.shutdown()


def test_dry_run_says_when_a_never_run_job_will_first_run(fixture_dir, nas3, capsys):
    toml = JOBS.replace("run_on_start = true\n", "", 1)     # the first job waits, the second runs at start
    cfg = write_config(fixture_dir, nas3, toml)
    code, out, err = run_cli(capsys, "--config", cfg, "server", "--backend", "sqlite", "--out",
                             str(fixture_dir / "cat.sqlite"), "--dry-run")
    assert code == 0
    assert "first run 1d after the server first starts (never ran)" in out
    assert "at server start (never ran; run_on_start)" in out


def test_run_on_start_is_validated():
    with pytest.raises(config.ConfigError, match="run_on_start wants true or false"):
        server_cfg.load_server({"server": {"jobs": [{"name": "a", "kind": "scan", "agent": "nas3", "every": "1h",
                                                     "run_on_start": "yes"}]}}, agents_cfg("nas3"))


# --- run now: the coordinator -------------------------------------------------------------------
def test_a_manual_run_goes_through_the_scheduler_is_recorded_as_manual_and_reanchors_every_jobs():
    release = threading.Event()
    started: list[str] = []

    def slow(ctx):
        started.append(ctx.spec.name)
        release.wait(10)
        return JobResult("ok", 0, {"files": 1})
    jobs = [spec("hourly", "nas3", run_on_start=False), spec("a2", "nas3", run_on_start=False),
            spec("off", "nas4", enabled=False)]
    coord, clock, _ = make_coord(jobs, runners={"scan": slow})
    start(coord, clock)
    assert coord.request_run("nope", "10.0.0.5")[0] == 404
    assert coord.request_run("off", "10.0.0.5")[0] == 409
    assert coord.request_run("hourly", "10.0.0.5")[0] == 202
    assert coord.request_run("hourly", "10.0.0.5")[0] == 409            # already queued
    assert coord.request_run("a2", "10.0.0.6")[0] == 202                # same agent: must wait for hourly
    coord.tick()
    assert wait_for(lambda: started == ["hourly"])
    assert coord.request_run("hourly", "10.0.0.5")[0] == 409            # now: running
    coord.tick()
    assert started == ["hourly"]                                        # per-agent exclusivity holds
    release.set()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs and "a2" in started)
    rows = {r["job"]: r for r in coord.store.recent(10) if r["outcome"] == "ok"}
    assert rows["hourly"]["trigger"] == "manual" and rows["hourly"]["requested_from"] == "10.0.0.5"
    assert rows["a2"]["requested_from"] == "10.0.0.6"
    # a manual run is a start: the interval counts from it, so the job is not due again 30 m later
    assert coord.sched.anchors["hourly"] == clock()
    clock.advance(minutes=30)
    started.clear()
    coord.tick()
    assert started == []
    coord.shutdown()


# --- run now and login: over HTTP ---------------------------------------------------------------
GOOD = "correct horse battery"
HASH = control_auth.hash_password(GOOD)


class Tick:
    """A fake clock in seconds for the login guard and the sessions."""
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


class Rig:
    def __init__(self, fixture_dir, *, with_hash=True, view_login=False, runners=None, **guard):
        self.clock = Tick()
        db = str(fixture_dir / "cat.sqlite")
        fake = Clock(datetime.now(timezone.utc))
        self.logs: list[str] = []
        self.coord = Coordinator(
            ServerConfig(jobs=(spec("nightly", "nas3", run_on_start=False),)), agents_cfg("nas3", "nas4"),
            ServerStore(Handle(lambda: open_backend("sqlite", db)), fake), file_cfg={},
            catalog=argparse.Namespace(backend="sqlite", out=db, dsn=None), clock=fake, probe=ok_probe,
            runners=runners or {"scan": lambda ctx: JobResult("ok", 0, {"files": 7})}, logger=self.logs.append, holder="A")
        self.coord.acquire()
        self.coord.probe_due(fake(), wait=True)
        self.auth = control_auth.ControlAuth(
            HASH if with_hash else None,
            control_auth.LoginGuard(self.clock, log=self.logs.append, **guard),
            control_auth.Sessions(self.clock), view_login, fail_delay=0.0)
        ns = argparse.Namespace(backend="sqlite", out=db, dsn=None, host="127.0.0.1", port=0, quiet=True,
                                no_save=False, graph_max_age=120, open=False, control_auth=self.auth)
        self.viewer = serve.start_viewer(ns, self.coord)
        self.port = self.viewer.httpd.server_address[1]

    def request(self, method, path, body=None, *, cookie=None, headers=None, origin="same", ctype="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Content-Type": ctype, "X-Filecat-Control": "run"}
        if origin == "same":
            h["Origin"] = f"http://127.0.0.1:{self.port}"
        elif origin:
            h["Origin"] = origin
        if cookie:
            h["Cookie"] = cookie
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        data = json.dumps(body) if isinstance(body, (dict, list)) else body
        conn.request(method, path, data, h)
        res = conn.getresponse()
        raw = res.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:          # the page itself
            parsed = {"html": True}
        out = (res.status, parsed, res.getheaders())
        conn.close()
        return out

    def login(self, password=GOOD, **kw):
        return self.request("POST", "/api/login", {"password": password}, **kw)

    def cookie(self) -> str:
        status, _, headers = self.login()
        assert status == 200
        return next(v for k, v in headers if k == "Set-Cookie").split(";")[0]

    def close(self):
        self.viewer.stop()
        self.coord.shutdown()


@pytest.fixture
def rig(fixture_dir):
    r = Rig(fixture_dir)
    yield r
    r.close()


def test_login_sets_a_strict_httponly_cookie_and_run_now_needs_the_session(rig):
    assert rig.request("POST", "/api/jobs/nightly/run", {})[0] == 401            # no session
    assert rig.login("wrong password")[0] == 401
    status, body, headers = rig.login()
    assert status == 200
    cookie = next(v for k, v in headers if k == "Set-Cookie")
    assert cookie.startswith("filecat_session=") and "HttpOnly" in cookie and "SameSite=Strict" in cookie \
        and "Path=/" in cookie and "Secure" not in cookie
    https = rig.login(origin=None, headers={"Origin": f"https://127.0.0.1:{rig.port}"})
    assert https[0] == 200 and "Secure" in next(v for k, v in https[2] if k == "Set-Cookie")   # behind https: Secure
    session = cookie.split(";")[0]
    status, body, _ = rig.request("POST", "/api/jobs/nightly/run", {}, cookie=session)
    assert status == 202 and body["queued"] is True
    assert rig.request("POST", "/api/jobs/nightly/run", {}, cookie=session)[0] == 409
    assert rig.request("POST", "/api/jobs/nope/run", {}, cookie=session)[0] == 404
    rig.coord.tick()
    assert wait_for(lambda: rig.coord.tick() is not None and not rig.coord.runs)
    row = rig.coord.store.recent(1)[0]
    assert row["job"] == "nightly" and row["trigger"] == "manual" and row["requested_from"] == "127.0.0.1"
    assert rig.request("POST", "/api/logout", {}, cookie=session)[0] == 200      # logged out: the cookie is dead
    assert rig.request("POST", "/api/jobs/nightly/run", {}, cookie=session)[0] == 401


def test_csrf_checks_get_form_posts_and_foreign_origins_are_refused(rig):
    session = rig.cookie()
    url = "/api/jobs/nightly/run"
    status, body, headers = rig.request("GET", url, cookie=session)
    assert status == 405 and ("Allow", "POST") in headers
    assert rig.request("POST", url, {}, cookie=session, origin="http://evil.example")[0] == 403
    assert rig.request("POST", url, {}, cookie=session, origin="null")[0] == 403
    assert rig.request("POST", url, {}, cookie=session, headers={"X-Filecat-Control": None})[0] == 403
    assert rig.request("POST", url, "x=1", cookie=session, ctype="application/x-www-form-urlencoded")[0] == 415
    assert rig.request("POST", url, {}, cookie=session, headers={"Host": "evil.example"})[0] == 403   # rebinding
    assert rig.request("POST", "/api/login", {"password": GOOD}, headers={"X-Filecat-Control": None})[0] == 403
    assert rig.request("POST", "/api/login", {"password": GOOD}, origin="http://evil.example")[0] == 403
    assert rig.coord.manual == {} and not rig.coord.runs                         # nothing was queued
    assert rig.request("OPTIONS", url) [0] in (501, 405)                          # no CORS preflight answer


def test_no_password_hash_disables_control_and_plain_serve_shows_jobs_read_only(fixture_dir):
    r = Rig(fixture_dir, with_hash=False)
    try:
        status, body, _ = r.login()
        assert status == 403 and "set-password" in body["error"]
        assert r.request("POST", "/api/jobs/nightly/run", {})[0] == 403
        conn = http.client.HTTPConnection("127.0.0.1", r.port)
        conn.request("GET", "/api/jobs")
        jobs = json.loads(conn.getresponse().read())
        assert jobs["control"]["available"] is False and "set-password" in jobs["control"]["reason"]
    finally:
        r.close()
    # a plain `filecat serve` (no coordinator): the endpoints are not there, the page says why
    db = str(fixture_dir / "plain.sqlite")
    ns = argparse.Namespace(backend="sqlite", out=db, dsn=None, host="127.0.0.1", port=0, quiet=True,
                            no_save=False, graph_max_age=120, open=False)
    viewer = serve.start_viewer(ns)
    try:
        port = viewer.httpd.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request("GET", "/api/jobs")
        control = json.loads(conn.getresponse().read())["control"]
        assert control["available"] is False and "filecat server --serve" in control["reason"]
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request("POST", "/api/jobs/nightly/run", "{}", {"Content-Type": "application/json",
                                                             "X-Filecat-Control": "run"})
        assert conn.getresponse().status == 404
        page = serve.resources.files("filecat").joinpath("web/index.html").read_text(encoding="utf-8")
        assert "jobs.control.available" in page and "Run now" in page          # the button is disabled with the reason
    finally:
        viewer.stop()


def test_login_required_for_view_locks_the_apis_until_login(fixture_dir):
    r = Rig(fixture_dir, view_login=True)
    try:
        assert r.request("GET", "/api/info")[0] == 401
        cookie = r.cookie()
        assert r.request("GET", "/api/info", cookie=cookie)[0] == 200
        assert r.request("GET", "/")[0] in (200, 500)       # the page itself (a login form) is served
    finally:
        r.close()


def test_failures_block_an_address_with_retry_after_and_each_try_while_blocked_doubles_it(fixture_dir):
    r = Rig(fixture_dir)
    try:
        for _ in range(4):
            assert r.login("bad")[0] == 401
        status, body, headers = r.login("bad")                  # the 5th failure: still a 401 ...
        assert status == 401
        status, body, headers = r.login(GOOD)                   # ... and now blocked, whatever it sends
        assert status == 429 and dict(headers)["Retry-After"] == str(body["retry_after"]) and 1700 <= body["retry_after"] <= 1800
        r.clock.t += 10
        status, body, _ = r.login(GOOD)
        assert status == 429 and body["retry_after"] > 1800 * 2 - 100     # the try while blocked doubled it (30 min)
        r.clock.t += 24 * 3600 * 2
        assert r.login(GOOD)[0] == 200                          # blocks run out
    finally:
        r.close()


def test_the_global_block_stops_every_login_but_existing_sessions_keep_working(fixture_dir):
    r = Rig(fixture_dir, max_failures=100, global_max_failures=3)
    try:
        session = r.cookie()
        for _ in range(3):
            r.login("bad")
        assert any("warning" in m and "every login refused" in m for m in r.logs)
        status, body, _ = r.login(GOOD)
        assert status == 429                                    # even the right password
        assert r.request("POST", "/api/jobs/nightly/run", {}, cookie=session)[0] == 202   # the old session still works
        r.clock.t += 901
        assert r.login(GOOD)[0] == 200
    finally:
        r.close()


def test_sessions_expire_when_idle_and_after_the_absolute_limit(fixture_dir):
    r = Rig(fixture_dir)
    try:
        cookie = r.cookie()
        sid = cookie.split("=", 1)[1]
        r.clock.t += 25 * 60
        assert r.auth.sessions.valid(sid)                       # touched: the idle timer restarts
        r.clock.t += 25 * 60
        assert r.auth.sessions.valid(sid)
        r.clock.t += 31 * 60
        assert not r.auth.sessions.valid(sid)                   # idle > 30 min
        sid = r.cookie().split("=", 1)[1]
        for _ in range(26):                                     # kept busy, still ends at 12 h
            r.clock.t += 29 * 60
            r.auth.sessions.valid(sid)
        assert not r.auth.sessions.valid(sid)
    finally:
        r.close()


def test_no_password_reaches_the_logs_or_the_history(fixture_dir):
    r = Rig(fixture_dir)
    try:
        r.login("hunter2-hunter2-bad")
        cookie = r.cookie()
        r.request("POST", "/api/jobs/nightly/run", {}, cookie=cookie)
        r.coord.tick()
        assert wait_for(lambda: r.coord.tick() is not None and not r.coord.runs)
        blob = "\n".join(r.logs) + json.dumps(r.coord.store.recent(20)) + json.dumps(r.coord.store.lease())
        assert "hunter2" not in blob and GOOD not in blob and HASH not in blob
        assert any("failed login from 127.0.0.1" in m for m in r.logs)
    finally:
        r.close()


# --- the guard on its own: many addresses, resets, windows -------------------------------------
def test_guard_counts_per_address_resets_on_success_and_forgets_old_failures():
    t = Tick()
    g = control_auth.LoginGuard(t)
    for _ in range(4):
        g.fail("1.1.1.1")
    g.success("1.1.1.1")
    for _ in range(4):
        g.fail("1.1.1.1")
    assert g.retry_after("1.1.1.1") == 0                       # the success cleared its counter
    t.t += 16 * 60
    g.fail("1.1.1.1")                                          # the old four are outside the window
    assert g.retry_after("1.1.1.1") == 0
    for _ in range(4):
        g.fail("1.1.1.1")
    assert g.retry_after("1.1.1.1") == 900
    assert g.retry_after("2.2.2.2") == 0                       # other addresses are not blocked
    g.fail("1.1.1.1")
    assert g.retry_after("1.1.1.1") == 1800                    # one more try while blocked: doubled
    for _ in range(20):
        g.fail("1.1.1.1")
    assert g.retry_after("1.1.1.1") == 86400                   # up to 24 h, no more


def test_the_global_counter_spans_addresses_and_a_success_does_not_clear_it():
    t = Tick()
    g = control_auth.LoginGuard(t)
    for i in range(19):
        g.fail(f"10.0.0.{i}")
    g.success("10.0.0.1")
    assert g.retry_after("10.9.9.9") == 0
    g.fail("10.0.1.1")                                         # the 20th failure within 15 minutes
    assert g.retry_after("10.9.9.9") == 900                    # an address that never failed is refused too
    t.t += 901
    assert g.retry_after("10.9.9.9") == 0


# --- the password hash and `filecat server set-password` ----------------------------------------
def test_the_hash_format_round_trips_and_malformed_input_is_just_a_no():
    h = control_auth.hash_password("a long enough password")
    scheme, n, r, p, salt, key = h.split("$")
    assert (scheme, n, r, p) == ("scrypt", str(2 ** 14), "8", "1") and len(control_auth.base64.b64decode(salt)) == 16 \
        and len(control_auth.base64.b64decode(key)) == 32
    assert h != control_auth.hash_password("a long enough password")         # salted
    assert control_auth.verify_password("a long enough password", h)
    assert not control_auth.verify_password("a long enough passworD", h)
    for bad in (None, 5, ["x"], "", "x" * 10_000):
        assert not control_auth.verify_password(bad, h)
    assert not control_auth.verify_password("a long enough password", "not a hash")
    assert not control_auth.valid_hash("scrypt$1$2$3$x$y")


def test_set_password_prompts_twice_enforces_length_and_can_write_the_toml(fixture_dir, capsys):
    answers = iter(["short", ])
    args = argparse.Namespace(write=False, config=None)
    assert control_auth.set_password(args, ask=lambda prompt: next(answers)) == 2       # under 12 characters
    answers = iter(["a long enough password", "a different one....."])
    assert control_auth.set_password(args, ask=lambda prompt: next(answers)) == 2       # the two differ
    capsys.readouterr()
    answers = iter(["a long enough password"] * 2)
    assert control_auth.set_password(args, ask=lambda prompt: next(answers)) == 0
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if l.startswith('control_password_hash = "scrypt$'))
    stored = line.split('"')[1]
    assert control_auth.verify_password("a long enough password", stored) and "a long enough password" not in out
    cfgfile = fixture_dir / "filecat.toml"
    cfgfile.write_text('[server]\nhealth_interval = "30s"\n', encoding="utf-8")
    args = argparse.Namespace(write=True, config=str(cfgfile))
    answers = iter(["a long enough password"] * 2)
    assert control_auth.set_password(args, ask=lambda prompt: next(answers)) == 0
    cfg = config.load(cfgfile)
    assert server_cfg.load_server(cfg, []).resolve_password_hash().startswith("scrypt$")
    answers = iter(["another long password"] * 2)                                      # replaced, not duplicated
    assert control_auth.set_password(args, ask=lambda prompt: next(answers)) == 0
    assert cfgfile.read_text(encoding="utf-8").count("control_password_hash") == 1
    assert control_auth.verify_password("another long password", server_cfg.load_server(
        config.load(cfgfile), []).resolve_password_hash())


def test_the_config_takes_a_hash_or_an_env_reference_and_refuses_a_plaintext_password(monkeypatch):
    load = lambda **kw: server_cfg.load_server({"server": kw}, [])
    assert load(control_password_hash=HASH).resolve_password_hash() == HASH
    monkeypatch.setenv("FILECAT_SERVER_PASSWORD_HASH", HASH)
    assert load(control_password_hash="${FILECAT_SERVER_PASSWORD_HASH}").resolve_password_hash() == HASH
    with pytest.raises(config.ConfigError, match="not a scrypt"):
        load(control_password_hash="my-plain-password")
    cfg = load(login_max_failures=3, login_window="5m", login_block="1h", login_global_max_failures=9)
    assert (cfg.login_max_failures, cfg.login_window, cfg.login_block, cfg.login_global_max_failures) == (
        3, timedelta(minutes=5), timedelta(hours=1), 9)
    assert load().login_max_failures == 5 and load().login_global_max_failures == 20 and not load().login_required_for_view
