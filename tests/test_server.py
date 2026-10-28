"""`filecat server`: config, scheduler, health, lease, history, --once through the fake agent, the
viewer's API, shutdown (docs/agent-server.md)."""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path

import pytest

from filecat import agent_status, cli, config, scheduler, serve, server, server_cfg, server_store
from filecat.backends import open_backend
from filecat.backends.memory import MemoryBackend
from filecat.scan import ScanCancelled
from filecat.server import Coordinator, JobResult
from filecat.server_cfg import JobSpec, ServerConfig
from filecat.server_store import Handle, ServerStore
from _fake_agent import FakeAgent, cert_fingerprint

DATA = Path(__file__).parent / "data"
NAS3 = DATA / "raw" / "nas3"
T0 = datetime(2026, 10, 28, 1, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


def spec(name="j", agent="a", kind="scan", **kw) -> JobSpec:
    kw.setdefault("every", timedelta(hours=1))
    kw.setdefault("run_on_start", True)     # most tests want a never-run job due at once
    return JobSpec(name=name, kind=kind, agent=agent, **kw)


# --- configuration -------------------------------------------------------------------------------
def agents_cfg(*names) -> list[config.AgentConfig]:
    return [config.AgentConfig(name=n, host="127.0.0.1", cert_sha256=cert_fingerprint(), token="t",
                               alias=f"\\\\{n}") for n in names]


def load(text: str, *names) -> ServerConfig:
    import tomllib
    return server_cfg.load_server(tomllib.loads(text), agents_cfg(*(names or ("nas3",))))


def test_the_schema_loads_with_defaults_and_expands_a_star_agent():
    cfg = load("""
[server]
health_interval = "30s"
max_concurrent = 3
serve = "127.0.0.1:9000"
[[server.jobs]]
name = "topology"
kind = "storage-collect"
agent = "*"
every = "24h"
run_on_start = true
options = ["--measure-shares"]
[[server.jobs]]
name = "nightly"
kind = "scan"
agent = "nas3"
roots = ['\\\\nas3\\Backup']
at = ["14:30", "02:30"]
options = ["--hash", "none", "--workers", "8"]
max_runtime = "6h"
[[server.jobs]]
name = "resum"
kind = "store-resum"
agent = "nas3"
every = "1d"
min_age = "28d"
enabled = false
""", "nas3", "nas4")
    assert cfg.health_interval == timedelta(seconds=30) and cfg.max_concurrent == 3
    assert cfg.lease_ttl == timedelta(seconds=90) and cfg.history_keep == 500 and cfg.serve == "127.0.0.1:9000"
    assert [j.name for j in cfg.jobs] == ["topology@nas3", "topology@nas4", "nightly", "resum"]
    nightly = cfg.jobs[2]
    assert nightly.at == (dtime(2, 30), dtime(14, 30)) and nightly.roots == ("\\\\nas3\\Backup",)
    assert nightly.max_runtime == timedelta(hours=6) and nightly.schedule_text == "daily at 02:30, 14:30"
    assert cfg.jobs[0].schedule_text == "every 1d" or cfg.jobs[0].schedule_text == "every 24h"
    assert cfg.jobs[3].enabled is False and cfg.jobs[3].min_age == timedelta(days=28)
    assert load("").jobs == () and load("[server]\n").jobs == ()


@pytest.mark.parametrize("body, message", [
    ('name = "x"\nkind = "scan"\nagent = "nas3"', "exactly one of every"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nevery = "1h"\nat = "02:30"', "exactly one of every"),
    ('name = "x"\nkind = "nope"\nagent = "nas3"\nevery = "1h"', "kind = 'nope'"),
    ('name = "x"\nkind = "scan"\nagent = "ghost"\nevery = "1h"', "no such [[agents]]"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nevery = "30s"', "at least 1m"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nevery = "soon"', "want a duration"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nat = "25:00"', "time of day"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nat = "02:30"\noptions = ["--out", "x.sqlite"]', "must not contain --out"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nat = "02:30"\noptions = ["--agent=other"]', "must not contain --agent"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nat = "02:30"\noptions = ["--no-such-flag"]', "options:"),
    ('name = "x"\nkind = "storage-collect"\nagent = "nas3"\nat = "02:30"\nroots = ["r"]', "does not apply"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nat = "02:30"\nmin_age = "1d"', "store-resum only"),
    ('name = "x"\nkind = "scan"\nagent = "nas3"\nat = "02:30"\nbogus = 1', "unknown key 'bogus'"),
    ('kind = "scan"\nagent = "nas3"\nat = "02:30"', "name is required"),
])
def test_job_errors_name_the_table_and_key(body, message):
    with pytest.raises(config.ConfigError) as err:
        load("[[server.jobs]]\n" + body)
    assert message in str(err.value) and "[[server.jobs]] #1" in str(err.value)


def test_server_table_errors():
    for text, message in [("[server]\nhealth_interval = 'x'\n", "health_interval"),
                          ("[server]\nmax_concurrent = 0\n", "max_concurrent"),
                          ("[server]\nbogus = 1\n", "unknown key 'bogus'"),
                          ("[server]\nserve = 'nope'\n", "HOST:PORT"),
                          ('[[server.jobs]]\nname = "a"\nkind = "scan"\nagent = "nas3"\nevery = "1h"\n'
                           '[[server.jobs]]\nname = "a"\nkind = "scan"\nagent = "nas3"\nevery = "1h"\n', "used twice")]:
        with pytest.raises(config.ConfigError, match=message):
            load(text)


# --- the scheduler, on a fake clock -----------------------------------------------------------------
def test_interval_jobs_are_due_from_their_anchor():
    j = spec(every=timedelta(hours=1))
    s = scheduler.Scheduler([j], {"j": None})
    assert [x.name for x in s.plan(T0, max_concurrent=2).start] == ["j"]          # never ran: due at once
    s.finished("j")
    assert s.plan(T0 + timedelta(minutes=59), max_concurrent=2).start == []
    assert [x.name for x in s.plan(T0 + timedelta(minutes=60), max_concurrent=2).start] == ["j"]
    assert s.next_due(j, T0 + timedelta(minutes=60)) == T0 + timedelta(minutes=120)


def test_daily_jobs_run_once_per_slot_and_a_missed_slot_runs_once_late():
    j = spec(every=None, at=(dtime(2, 30),))
    s = scheduler.Scheduler([j], {"j": T0.replace(hour=2, minute=31)})           # ran at 02:31 today
    assert s.plan(T0.replace(hour=23), max_concurrent=1).start == []              # nothing new since
    assert [x.name for x in s.plan(T0 + timedelta(days=1, hours=1, minutes=45), max_concurrent=1).start] == ["j"]
    s.finished("j")
    # the server was off for three days: one run, not three
    s2 = scheduler.Scheduler([j], {"j": T0})
    assert len(s2.plan(T0 + timedelta(days=3, hours=4), max_concurrent=1).start) == 1
    assert s2.next_due(j, T0 + timedelta(days=3, hours=4)) == T0.replace(hour=2, minute=30) + timedelta(days=4)
    # several times a day
    two = spec(every=None, at=(dtime(2, 30), dtime(14, 30)))
    s3 = scheduler.Scheduler([two], {"j": T0.replace(hour=2, minute=31)})
    assert s3.plan(T0.replace(hour=14, minute=0), max_concurrent=1).start == []
    assert len(s3.plan(T0.replace(hour=14, minute=31), max_concurrent=1).start) == 1


def test_a_job_still_running_when_due_again_is_skipped_and_not_every_tick():
    j = spec(every=timedelta(hours=1))
    s = scheduler.Scheduler([j], {"j": None})
    s.plan(T0, max_concurrent=2)                                                   # started, never finished
    plan = s.plan(T0 + timedelta(hours=1), max_concurrent=2)
    assert plan.start == [] and plan.skipped == [(j, scheduler.SKIP_RUNNING)]
    again = s.plan(T0 + timedelta(hours=1, minutes=1), max_concurrent=2)
    assert again.skipped == [] and again.start == []                               # the anchor moved: not logged again
    s.finished("j")
    assert len(s.plan(T0 + timedelta(hours=2, minutes=1), max_concurrent=2).start) == 1


def test_one_job_per_agent_and_a_global_limit():
    a1, a2 = spec("a1", "nas3"), spec("a2", "nas3")
    b1, c1 = spec("b1", "nas4"), spec("c1", "nas5")
    s = scheduler.Scheduler([a1, a2, b1, c1], {})
    plan = s.plan(T0, max_concurrent=2)
    assert [x.name for x in plan.start] == ["a1", "b1"]                            # a2 waits for nas3, c1 for a slot
    assert [x.name for x in plan.waiting] == ["a2", "c1"] and plan.skipped == []
    s.finished("a1")
    plan = s.plan(T0 + timedelta(seconds=5), max_concurrent=2)
    assert [x.name for x in plan.start] == ["a2"] and [x.name for x in plan.waiting] == ["c1"]


def test_down_unknown_forced_and_disabled():
    a, b = spec("a", "nas3"), spec("b", "nas4", enabled=False)
    s = scheduler.Scheduler([a, b], {})
    assert [x.name for x in s.plan(T0, max_concurrent=1, unknown=["nas3"]).waiting] == ["a"]
    plan = s.plan(T0, max_concurrent=1, down=["nas3"])
    assert plan.skipped == [(a, "agent nas3 is down")] and plan.start == []
    assert s.plan(T0 + timedelta(minutes=1), max_concurrent=1).start == []         # skipped moved the anchor
    assert [x.name for x in s.plan(T0 + timedelta(minutes=1), max_concurrent=1, forced=["a"]).start] == ["a"]
    assert all(x.name != "b" for x in s.jobs)


# --- the lease ---------------------------------------------------------------------------------------
class SharedBackend:
    """Two servers on one catalog: both handles open the same in-memory backend."""

    def __init__(self) -> None:
        self.backend = MemoryBackend()

    def handle(self) -> Handle:
        return Handle(lambda: self.backend)


def test_lease_acquire_refuse_expire_renew_release():
    shared, clock = SharedBackend(), Clock()
    a = ServerStore(shared.handle(), clock)
    b = ServerStore(shared.handle(), clock)
    ttl = timedelta(seconds=90)
    assert a.acquire("A", "h1", 11, ttl).ok
    res = b.acquire("B", "h2", 22, ttl)
    assert not res.ok and res.holder["holder"] == "A" and res.holder["pid"] == 11
    assert a.acquire("A", "h1", 11, ttl).ok                                        # ours again
    clock.advance(seconds=60)
    assert a.renew("A", ttl) and not b.renew("B", ttl)
    clock.advance(seconds=80)                                                      # renewed at +60: expires at +150
    assert not b.acquire("B", "h2", 22, ttl).ok
    clock.advance(seconds=11)
    got = b.acquire("B", "h2", 22, ttl)                                            # expired: B takes it
    assert got.ok and got.holder["holder"] == "B"
    assert not a.renew("A", ttl)                                                   # A finds it was replaced
    a.release("A")                                                                 # not ours: does nothing
    assert b.lease()["holder"] == "B" and b.lease()["alive"]
    b.release("B")
    assert b.lease() is None


def test_the_coordinator_stops_when_it_loses_the_lease():
    shared, clock = SharedBackend(), Clock()
    store = ServerStore(shared.handle(), clock)
    other = ServerStore(shared.handle(), clock)
    coord = Coordinator(ServerConfig(), [], store, file_cfg={}, catalog=_catalog(), clock=clock,
                        logger=lambda m: None, holder="A")
    assert coord.acquire().ok
    clock.advance(seconds=31)
    assert other.acquire("B", "h2", 2, timedelta(seconds=90)).ok is False          # A's lease still stands
    clock.advance(seconds=100)
    assert other.acquire("B", "h2", 2, timedelta(seconds=90)).ok                   # A stalled past the ttl
    coord.tick()
    assert coord.lost
    stop = threading.Event()
    assert coord.run_forever(stop) == 3


def _catalog(**kw):
    import argparse
    return argparse.Namespace(backend="memory", out=None, dsn=None, **kw)


# --- history -----------------------------------------------------------------------------------------
def test_history_rows_prune_and_lost_runs():
    shared, clock = SharedBackend(), Clock()
    store = ServerStore(shared.handle(), clock)
    for i in range(5):
        store.put_run({"run": f"r{i}", "job": "j", "kind": "scan", "agent": "a", "started_at": server_store.iso(clock.now),
                       "outcome": "ok", "counts": {"files": i}})
        clock.advance(minutes=1)
    store.put_run({"run": "x", "job": "k", "kind": "scan", "agent": "a", "started_at": server_store.iso(clock.now),
                   "outcome": "running"})
    assert [r["counts"]["files"] for r in store.recent(3, job="j")] == [4, 3, 2]   # newest first
    assert store.mark_lost("A") == 1 and store.recent(1, job="k")[0]["outcome"] == "lost"
    assert store.prune(keep=2, days=90) == 4 and len(store.recent(10)) == 2
    clock.advance(days=100)
    assert store.prune(keep=500, days=90) == 2 and store.recent(10) == []
    assert store.last_starts() == {}


# --- health ------------------------------------------------------------------------------------------
def make_coord(jobs, *, clock=None, probe=None, runners=None, shared=None, **cfg):
    shared = shared or SharedBackend()
    clock = clock or Clock()
    store = ServerStore(shared.handle(), clock)
    logs: list[str] = []
    cfg.setdefault("shutdown_grace", timedelta(seconds=5))
    coord = Coordinator(ServerConfig(jobs=tuple(jobs), **cfg), agents_cfg("nas3", "nas4"), store, file_cfg={},
                        catalog=_catalog(), clock=clock, probe=probe or ok_probe, runners=runners,
                        logger=logs.append, holder="A")
    coord.logs = logs
    return coord, clock, shared


def ok_probe(agent, timeout=5.0, table=None):
    return agent_status.AgentStatus(agent.name, agent.endpoint, reachable=True, cert_pin="ok", version="0.2.0",
                                    platform="linux/x86_64")


def test_health_up_down_backoff_and_recovery():
    down = {"nas3"}
    seen: list[str] = []

    def probe(agent, timeout=5.0, table=None):
        seen.append(agent.name)
        if agent.name in down:
            return agent_status.AgentStatus(agent.name, agent.endpoint, error="ConnectionRefusedError: refused")
        return ok_probe(agent)
    coord, clock, _ = make_coord([], probe=probe, health_interval=timedelta(seconds=60),
                                 health_backoff_max=timedelta(seconds=200))
    coord.probe_due(clock(), wait=True)
    snap = {a["name"]: a for a in coord.agents_snapshot()}
    assert snap["nas3"]["state"] == "down" and snap["nas3"]["last_error"].startswith("ConnectionRefusedError")
    assert snap["nas4"]["state"] == "up" and snap["nas4"]["version"] == "0.2.0"
    assert any("agent nas3 is down" in m for m in coord.logs)
    # not due yet: no new probes; then the failures double the wait, up to the cap
    n = len(seen)
    clock.advance(seconds=30)
    coord.probe_due(clock(), wait=True)
    assert len(seen) == n
    waits = []
    for _ in range(4):
        before = clock.now
        clock.advance(seconds=300)
        coord.probe_due(clock(), wait=True)
        st = coord.health["nas3"]
        waits.append((st.next_check - clock.now).total_seconds())
    assert waits == [120, 200, 200, 200] and coord.health["nas3"].failures == 5
    down.clear()
    clock.advance(seconds=300)
    coord.probe_due(clock(), wait=True)
    st = coord.health["nas3"]
    assert st.state == "up" and st.failures == 0 and (st.next_check - clock.now).total_seconds() == 60
    assert any("agent nas3 is up" in m for m in coord.logs)


def test_a_hash_mismatch_is_a_logged_warning_not_an_outage():
    def probe(agent, timeout=5.0, table=None):
        st = ok_probe(agent)
        st.allowlist_match, st.warnings = False, [agent_status.agent_expected.MISMATCH_WARNING]
        return st
    coord, clock, _ = make_coord([], probe=probe)
    coord.probe_due(clock(), wait=True)
    nas3 = {a["name"]: a for a in coord.agents_snapshot()}["nas3"]
    assert nas3["state"] == "up" and nas3["allowlist_match"] is False and nas3["warnings"]
    assert any("different allowlist/deny list" in m for m in coord.logs)


# --- running jobs in the coordinator -----------------------------------------------------------------
def wait_for(cond, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_jobs_run_one_per_agent_skip_while_running_and_record_history():
    release = threading.Event()
    started: list[str] = []

    def slow(ctx):
        started.append(ctx.spec.name)
        release.wait(10)
        return JobResult("ok", 0, {"files": 3})
    jobs = [spec("a1", "nas3"), spec("a2", "nas3"), spec("b1", "nas4")]
    coord, clock, shared = make_coord(jobs, runners={"scan": slow}, max_concurrent=5)
    coord.acquire()
    coord.probe_due(clock(), wait=True)
    coord.tick()
    assert wait_for(lambda: len(started) == 2) and sorted(started) == ["a1", "b1"]   # a2 waits for nas3
    clock.advance(hours=1, minutes=1)
    coord.tick()                                                                      # a1 and b1 due again while running
    assert any("job a1 skipped: previous run still running" in m for m in coord.logs)
    rows = coord.store.recent(20)
    assert sorted((r["job"], r["outcome"]) for r in rows if r["outcome"] == "skipped")[:2] == [
        ("a1", "skipped"), ("b1", "skipped")]
    release.set()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs and "a2" in started, 10)
    rows = {r["job"]: r for r in coord.store.recent(50) if r["outcome"] == "ok"}
    assert set(rows) == {"a1", "a2", "b1"} and rows["a1"]["counts"] == {"files": 3}
    assert rows["a1"]["ended_at"] and rows["a1"]["trigger"] == "schedule" and rows["a1"]["server"] == "A"
    coord.shutdown()


def test_a_down_agent_skips_its_jobs_and_errors_are_stored_without_paths():
    def probe(agent, timeout=5.0, table=None):
        if agent.name == "nas4":
            return agent_status.AgentStatus(agent.name, agent.endpoint, error="down")
        return ok_probe(agent)

    def boom(ctx):
        raise OSError(2, "No such file", "\\\\nas3\\private\\secret-project\\x.txt")
    coord, clock, _ = make_coord([spec("a", "nas3"), spec("b", "nas4")], probe=probe, runners={"scan": boom})
    coord.acquire()
    coord.probe_due(clock(), wait=True)
    coord.tick()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs)
    rows = {r["job"]: r for r in coord.store.recent(10)}
    assert rows["b"]["outcome"] == "skipped" and "nas4 is down" in rows["b"]["error"]
    assert rows["a"]["outcome"] == "failed" and "secret-project" not in rows["a"]["error"]
    assert "secret-project" not in "\n".join(coord.logs) and rows["a"]["error"].startswith("FileNotFoundError")
    coord.shutdown()


def test_max_runtime_cancels_a_job():
    def hang(ctx):
        ctx.cancel.wait(10)
        raise ScanCancelled()
    coord, clock, _ = make_coord([spec("a", "nas3", max_runtime=timedelta(seconds=0.05))], runners={"scan": hang})
    coord.acquire()
    coord.probe_due(clock(), wait=True)
    coord.tick()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs)
    row = coord.store.recent(1)[0]
    assert row["outcome"] == "cancelled" and "max_runtime" in row["error"]
    coord.shutdown()


def test_shutdown_cancels_running_jobs_records_them_and_releases_the_lease():
    def hang(ctx):
        ctx.cancel.wait(30)
        raise ScanCancelled()
    coord, clock, _ = make_coord([spec("a", "nas3")], runners={"scan": hang})
    assert coord.acquire().ok
    coord.probe_due(clock(), wait=True)
    coord.tick()
    assert wait_for(lambda: coord.store.recent(1) and coord.store.recent(1)[0]["outcome"] == "running")
    assert coord.store.lease()["holder"] == "A"
    t0 = time.monotonic()
    coord.shutdown()
    assert time.monotonic() - t0 < 5
    row = coord.store.recent(1)[0]
    assert row["outcome"] == "cancelled" and row["ended_at"]
    assert coord.store.lease() is None                                              # released
    assert any("cancelling 1 running job" in m for m in coord.logs)
    saved = coord.store.agents()
    assert {a["name"] for a in saved["agents"]} == {"nas3", "nas4"}


def test_a_stuck_job_is_recorded_cancelled_when_the_grace_runs_out():
    block = threading.Event()

    def stuck(ctx):
        block.wait(10)                      # ignores the cancel event
        return JobResult("ok")
    coord, clock, _ = make_coord([spec("a", "nas3")], runners={"scan": stuck}, shutdown_grace=timedelta(seconds=0.2))
    coord.acquire()
    coord.probe_due(clock(), wait=True)
    coord.tick()
    assert wait_for(lambda: bool(coord.runs))
    coord.shutdown()
    assert coord.store.recent(1)[0]["outcome"] == "cancelled" and coord.store.lease() is None
    block.set()


def test_a_cancelled_scan_stops_at_the_next_entry_and_marks_the_root_interrupted(fixture_dir):
    root = fixture_dir / "nas" / "volume1" / "Backup"
    root.mkdir(parents=True)
    for i in range(5):
        (root / f"f{i}.txt").write_text("hello")
    from filecat import scan
    from filecat.options import ScanOptions
    backend = MemoryBackend()
    event = threading.Event()
    event.set()
    with pytest.raises(ScanCancelled):
        scan.scan_roots([str(root)], backend, ScanOptions(identify="never", cancel=event),
                        resume_path=str(fixture_dir / "r.json"))
    info = list(backend.list_root_info())
    assert info and info[0]["last_attempt"]["status"] == "interrupted"


# --- --once through the fake agent ----------------------------------------------------------------------
@pytest.fixture
def nas3(fixture_dir):
    root = fixture_dir / "served"
    root.mkdir()
    with FakeAgent(root) as agent:
        agent.load_recording(NAS3)
        share = root / "volume1" / "Backup" / "docs"
        share.mkdir(parents=True)
        (share / "a.txt").write_text("hello\n")
        (root / "volume1" / "Backup" / "b.txt").write_text("hello again\n")
        yield agent


def write_config(fixture_dir, agent, jobs: str) -> str:
    path = fixture_dir / "filecat.toml"
    path.write_text(
        f'[[agents]]\nname = "nas3"\nhost = "127.0.0.1"\nport = {agent.port}\n'
        f'cert_sha256 = "{cert_fingerprint()}"\ntoken = "{agent.token}"\nalias = \'\\\\nas3\'\n{jobs}',
        encoding="utf-8")
    return str(path)


JOBS = """
[server]
health_interval = "60s"
[[server.jobs]]
name = "topology"
kind = "storage-collect"
agent = "nas3"
every = "24h"
run_on_start = true
options = ["--measure-shares"]
[[server.jobs]]
name = "scan-backup"
kind = "scan"
agent = "nas3"
roots = ['\\\\nas3\\Backup']
every = "24h"
run_on_start = true
options = ["--identify", "never"]
"""


def run_cli(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_once_runs_a_storage_collect_and_a_scan_through_the_agent(nas3, fixture_dir, capsys):
    cfg = write_config(fixture_dir, nas3, JOBS)
    db = str(fixture_dir / "cat.sqlite")
    base = ["--config", cfg, "server", "--backend", "sqlite", "--out", db]
    code, out, err = run_cli(capsys, *base, "--once")
    assert code == 0, err
    assert "job topology (storage-collect, agent nas3) started" in err and "job scan-backup ok" in err and "agent nas3 is up" in err
    backend = open_backend("sqlite", db)
    try:
        rows = {r["job"]: r for r in server_store.recent_runs(backend, 10)}
        assert rows["topology"]["outcome"] == "ok" and rows["topology"]["counts"]["nodes"] == 23
        assert rows["topology"]["counts"]["first"] is True and rows["topology"]["trigger"] == "once"
        scan_row = rows["scan-backup"]
        assert scan_row["outcome"] == "ok" and scan_row["counts"]["files"] == 2 and scan_row["counts"]["dirs"] >= 2
        assert scan_row["exit_code"] == 0 and scan_row["agent"] == "nas3"
        assert backend.get_topology("nas3") is not None                                # the real storage-collect result
        assert any(r["root"].lower() == "\\\\nas3\\backup" for r in backend.list_root_info())
        assert server_store.read_lease(backend) is None                                # released
        agents = server_store.read_agents(backend)["agents"]
        assert agents[0]["name"] == "nas3" and agents[0]["state"] == "up"
    finally:
        backend.close()
    # not due again: a second --once starts nothing, a forced one runs the named job
    code, out, err = run_cli(capsys, *base, "--once")
    assert code == 0 and "started" not in err
    code, out, err = run_cli(capsys, *base, "--once", "--job", "topology")
    assert code == 0 and "job topology ok" in err and "job scan-backup" not in err
    backend = open_backend("sqlite", db)
    try:
        latest = server_store.recent_runs(backend, 1)[0]
        assert latest["job"] == "topology" and latest["trigger"] == "manual" and latest["counts"]["first"] is False
    finally:
        backend.close()


def test_once_scan_without_roots_uses_the_agents_shares(nas3, fixture_dir, capsys):
    jobs = JOBS.replace("roots = ['\\\\nas3\\Backup']\n", "")
    cfg = write_config(fixture_dir, nas3, jobs)
    db = str(fixture_dir / "cat.sqlite")
    code, out, err = run_cli(capsys, "--config", cfg, "server", "--backend", "sqlite", "--out", db, "--once")
    backend = open_backend("sqlite", db)
    try:
        row = {r["job"]: r for r in server_store.recent_runs(backend, 10)}["scan-backup"]
        # the shares of the stored snapshot are the roots; the ones the fake does not serve carry errors
        assert row["counts"]["roots"] >= 2 and row["outcome"] in ("ok", "errors")
    finally:
        backend.close()


def test_once_exit_code_and_a_failing_job(nas3, fixture_dir, capsys):
    cfg = write_config(fixture_dir, nas3, JOBS.replace('roots = [\'\\\\nas3\\Backup\']', "roots = ['C:\\\\nowhere']"))
    db = str(fixture_dir / "cat.sqlite")
    code, out, err = run_cli(capsys, "--config", cfg, "server", "--backend", "sqlite", "--out", db, "--once",
                             "--job", "scan-backup")
    assert code == 1                                                                   # the scan found a root it could not open
    backend = open_backend("sqlite", db)
    try:
        assert server_store.recent_runs(backend, 1)[0]["outcome"] in ("errors", "failed")
    finally:
        backend.close()


def test_a_second_server_is_refused_and_dry_run_touches_nothing(nas3, fixture_dir, capsys):
    cfg = write_config(fixture_dir, nas3, JOBS)
    db = str(fixture_dir / "cat.sqlite")
    base = ["--config", cfg, "server", "--backend", "sqlite", "--out", db]
    code, out, err = run_cli(capsys, *base, "--dry-run")
    assert code == 0 and "2 job(s)" in out and "job topology: every 1d" in out and "at server start (never ran; run_on_start)" in out
    assert "agent nas3" in out and not Path(db).exists()                                # nothing opened or created
    backend = open_backend("sqlite", db)
    try:
        backend.put_server_doc("server_state", {"key": "lease", "host": "other-box", "holder": "Z", "pid": 9,
                                                "scanned_at": "x", "started_at": server_store.iso(datetime.now(timezone.utc)),
                                                "renewed_at": server_store.iso(datetime.now(timezone.utc)),
                                                "expires_at": server_store.iso(datetime.now(timezone.utc) + timedelta(minutes=5))})
    finally:
        backend.close()
    code, out, err = run_cli(capsys, *base, "--once")
    assert code == 4 and "another server holds the catalog (other-box, pid 9)" in err and "started" not in err
    code, out, err = run_cli(capsys, *base, "--once", "--job", "nope")
    assert code == 2 and "no such job" in err
    code, out, err = run_cli(capsys, *base, "--job", "topology")
    assert code == 2 and "--job needs --once" in err


# --- the viewer's API ------------------------------------------------------------------------------------
def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as res:
        return json.loads(res.read())


def test_the_api_serves_live_state_from_the_coordinator_and_saved_state_without_one(fixture_dir):
    import argparse
    db = str(fixture_dir / "cat.sqlite")
    clock = Clock(datetime.now(timezone.utc))
    handle = Handle(lambda: open_backend("sqlite", db))
    store = ServerStore(handle, clock)
    coord = Coordinator(ServerConfig(jobs=(spec("nightly", "nas3"),)), agents_cfg("nas3", "nas4"), store, file_cfg={},
                        catalog=argparse.Namespace(backend="sqlite", out=db, dsn=None), clock=clock, probe=ok_probe,
                        runners={"scan": lambda ctx: JobResult("ok", 0, {"files": 7})}, logger=lambda m: None, holder="A")
    try:
        coord.acquire()
        coord.probe_due(clock(), wait=True)
        coord.tick()
        assert wait_for(lambda: coord.tick() is not None and not coord.runs)
        ns = argparse.Namespace(backend="sqlite", out=db, dsn=None, host="127.0.0.1", port=0, quiet=True,
                                no_save=False, graph_max_age=120, open=False)
        live = serve.start_viewer(ns, coord)
        try:
            agents = get(live.url + "api/agents")
            assert agents["source"] == "live" and agents["server"]["holder"] == "A" and agents["server"]["alive"]
            assert {a["name"]: a["state"] for a in agents["agents"]} == {"nas3": "up", "nas4": "up"}
            jobs = get(live.url + "api/jobs?limit=5")
            assert jobs["source"] == "live" and jobs["jobs"][0]["name"] == "nightly" and jobs["jobs"][0]["last_outcome"] == "ok"
            assert jobs["recent"][0]["job"] == "nightly" and jobs["recent"][0]["counts"] == {"files": 7}
            assert get(live.url + "api/jobs?job=other")["recent"] == []
            page = urllib.request.urlopen(live.url, timeout=10).read().decode()
            assert 'data-view="server"' in page and "/api/agents" in page
        finally:
            live.stop()
        coord.shutdown()
        # a plain `filecat serve` on the same catalog: no coordinator, the saved state and the history
        plain = serve.start_viewer(ns)
        try:
            agents = get(plain.url + "api/agents")
            assert agents["source"] == "catalog" and agents["server"] is None
            assert {a["name"] for a in agents["agents"]} == {"nas3", "nas4"} and agents["updated_at"]
            jobs = get(plain.url + "api/jobs")
            assert jobs["source"] == "catalog" and jobs["jobs"] == [] and jobs["recent"][0]["job"] == "nightly"
        finally:
            plain.stop()
    finally:
        handle.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite", "jsonl-file", "jsonl-dir"])
def test_server_documents_in_each_backend(kind, fixture_dir):
    """The stores exist in every file/memory backend (the SQL and MongoDB ones are the topology code)."""
    if kind == "memory":
        backend = MemoryBackend()
    elif kind == "sqlite":
        backend = open_backend("sqlite", str(fixture_dir / "c.sqlite"))
    elif kind == "jsonl-file":
        backend = open_backend("jsonl", str(fixture_dir / "c.jsonl"))
    else:
        (fixture_dir / "d").mkdir()
        (fixture_dir / "d" / "storage.json").write_text("{}")
        backend = open_backend("jsonl", str(fixture_dir / "d"))
    try:
        backend.put_server_doc("server_jobs", {"key": "k1", "host": "nas3", "scanned_at": "t1", "job": "j"})
        backend.put_server_doc("server_jobs", {"key": "k1", "host": "nas3", "scanned_at": "t1", "job": "j2"})
        backend.put_server_doc("server_state", {"key": "lease", "host": "h", "scanned_at": "t", "holder": "A"})
        assert [d["job"] for d in backend.server_docs("server_jobs")] == ["j2"]
        assert [d["holder"] for d in backend.server_docs("server_state")] == ["A"]
        assert backend.topologies() == []                                          # separate from the topology
        backend.delete_server_doc("server_state", "lease")
        assert backend.server_docs("server_state") == []
        with pytest.raises(AssertionError):
            backend.put_server_doc("storage_topology", {"key": "x", "host": "h"})
    finally:
        backend.close()


def test_scan_server_ps1_is_marked_legacy():
    text = (Path(__file__).parent.parent / "ScanServer.ps1").read_text(encoding="utf-8")
    assert "Legacy" in text and "filecat server" in text
