"""Agent activity and the server's busy check and progress lines (docs/agent-protocol.md `activity`,
docs/agent-server.md): the connection label, `activity`, `filecat agents status`, deferral while another
client works on an agent, `max_jobs`, and the progress interval on a fake clock."""
from __future__ import annotations

import json
import re
import threading
import types
from datetime import timedelta

import pytest

from filecat import agent_busy, agent_client, cli, config, scheduler, server_cfg
from filecat.agent_client import (LABEL_HEALTH, Activity, ActivityUnsupported, AgentClient, AgentSession,
                                  default_label)
from filecat.server import Coordinator, JobResult, job_label
from filecat.server_cfg import ServerConfig
from filecat.server_store import ServerStore, iso
from _fake_agent import FakeAgent, cert_fingerprint
from test_server import T0, Clock, SharedBackend, _catalog, agents_cfg, load, ok_probe, spec, wait_for

APPS = "scan \\\\nas3\\Apps by kense@DESKTOP"


@pytest.fixture
def tree(fixture_dir):
    root = fixture_dir / "nas"
    (root / "volume1" / "Backup" / "sub").mkdir(parents=True)
    (root / "volume1" / "Backup" / "a.txt").write_bytes(b"hello agent\n" * 100)
    (root / "volume1" / "Backup" / "sub" / "b.bin").write_bytes(bytes(range(256)) * 40)
    return root


@pytest.fixture
def agent(tree):
    with FakeAgent(tree) as fake:
        yield fake


def client_for(agent, **kwargs) -> AgentClient:
    kwargs.setdefault("timeout", 5)
    kwargs.setdefault("io_timeout", 20)
    return AgentClient("127.0.0.1", agent.port, cert_fingerprint(), agent.token, **kwargs)


def config_for(agent, name="fake") -> config.AgentConfig:
    return config.AgentConfig(name=name, host="127.0.0.1", port=agent.port, cert_sha256=cert_fingerprint(),
                              token=agent.token, alias="\\\\fake")


# --- the label and `activity` ---------------------------------------------------------------------
def test_the_label_goes_out_with_hello_and_the_agent_shows_it(agent):
    with client_for(agent, label=APPS) as worker, client_for(agent, label="agents status") as asker:
        worker.list_dir("/volume1/Backup")
        act = asker.activity()
    hello = next(r for r in agent.requests if r["cmd"] == "hello" and r.get("label") == APPS)
    assert hello == {"cmd": "hello", "label": APPS}
    mine = [s for s in act.sessions if s.label == APPS]
    assert len(mine) == 1 and mine[0].authenticated and mine[0].requests >= 1 and mine[0].dirs_listed == 1
    assert act.self_id not in {s.id for s in act.others()} and [s.label for s in act.others()] == [APPS]
    assert mine[0].peer.startswith("127.0.0.1:")


def test_the_default_label_names_the_user_and_host(agent):
    assert re.fullmatch(r"filecat by .+@.+", default_label())
    assert re.fullmatch(r"storage collect by .+@.+", default_label("storage collect"))
    with client_for(agent) as c:
        assert c.label == default_label()
        c.connect()
    assert agent.requests[0]["label"] == default_label()


def test_a_long_label_is_cut_and_control_characters_do_not_reach_the_agent(agent):
    with client_for(agent, label="x" * 500) as c:
        assert len(c.label) == 200
    with client_for(agent, label="job a\nb\x1b: scan") as c, client_for(agent, label="agents status") as asker:
        c.connect()
        labels = [s.label for s in asker.activity().others()]
    assert labels == ["job ab: scan"]


def test_activity_counts_work_and_names_no_paths(agent):
    with client_for(agent, label="job x: scan") as worker, client_for(agent, label="agents status") as asker:
        listing = worker.list_dir("/volume1/Backup")
        worker.measure("/volume1/Backup/a.txt")
        worker.sum_subtree("/volume1/Backup")
        row = [s for s in asker.activity().others() if s.label == "job x: scan"][0]
        wire = json.dumps([line for _, line in agent.wire if '"sessions"' in line])
    # list_dir: 1 folder and its 2 entries; sum_subtree then enters 2 folders and visits 5 entries
    assert (row.dirs_listed, row.entries_listed, row.files_measured) == (3, len(listing.entries) + 5, 1)
    assert row.files_summed == 2 and row.bytes_summed > 0 and row.bytes_read >= 1200 and row.errors == 0
    assert row.command is None and row.last_request_secs is not None and row.files == 3
    assert "volume1" not in wire and "Backup" not in wire


def test_activity_parsing_tolerates_missing_and_odd_fields():
    c = AgentClient("127.0.0.1", 1, "00" * 32, "t")
    c._call = lambda payload, *a, **k: {"ok": True, "self_id": 2, "sessions": [  # type: ignore[method-assign]
        {"id": 1, "peer": "10.0.0.5:4000", "authenticated": True, "label": APPS, "command": "sum_subtree",
         "command_secs": 180, "last_request_secs": 4, "connected_secs": 720, "files_summed": 40, "bytes_read": 2 ** 31},
        {"id": 2}, "junk"]}
    act = c.activity()
    assert act.self_id == 2 and [s.id for s in act.sessions] == [1, 2] and [s.id for s in act.others()] == [1]
    s = act.sessions[0]
    assert (s.command, s.command_secs, s.files, s.bytes_read) == ("sum_subtree", 180, 40, 2 ** 31)
    assert round(s.rate, 2) == 0.06 and act.sessions[1].command is None and act.sessions[1].last_request_secs is None


def test_an_agent_older_than_0_2_1_is_a_clear_answer_and_does_not_fail_callers(agent):
    agent.activity_supported = False
    with client_for(agent) as c:
        with pytest.raises(ActivityUnsupported) as err:
            c.activity()
        assert str(err.value) == "activity not supported (agent 0.2.1-test)" and err.value.code == "unsupported"
        assert c.hello().protocol == 1                      # the connection is still good
    assert agent_busy.fetch(config_for(agent), 5) is None


# --- who counts as working ---------------------------------------------------------------------------
def sess(id, label, *, command=None, last=3, authenticated=True, connected=720, **kw) -> AgentSession:
    return AgentSession(id, f"10.0.0.{id}:5000", connected, authenticated, label, command,
                        None if command is None else 60, last, **kw)


def test_working_sessions():
    act = Activity((
        sess(1, APPS, command="sum_subtree", last=70),         # a long request counts however old the last one is
        sess(2, "job nightly: scan", last=10),                 # labelled and recent
        sess(3, "old client", last=500),                       # labelled, idle for minutes
        sess(4, "", command=None, last=2),                     # no label, no command
        sess(5, LABEL_HEALTH, last=1), sess(6, "busy check", last=1), sess(7, "agents status", last=1),
        sess(8, "viewer", command="list_dir"), sess(9, "agents test", last=1),
        sess(10, "half open", authenticated=False, last=1), sess(11, "", command="list_dir"),
        sess(99, "me", command="activity")), self_id=99)
    assert [s.id for s in agent_busy.working(act)] == [1, 2, 11]
    assert agent_busy.summary(agent_busy.working(act)[:1]) == APPS + " for 12m"
    assert agent_busy.summary(agent_busy.working(act)[:2]).endswith("and 1 more")


def test_health_checks_and_viewers_do_not_count_against_a_real_connection(agent):
    with client_for(agent, label=LABEL_HEALTH) as health, client_for(agent, label="viewer") as viewer, \
            client_for(agent, label=APPS) as worker:
        health.capabilities()
        viewer.list_dir("/volume1/Backup")
        worker.list_dir("/volume1/Backup")
        act = agent_busy.fetch(config_for(agent), 5)
    assert act is not None and [s.label for s in agent_busy.working(act)] == [APPS]


# --- filecat agents status ---------------------------------------------------------------------------
def _toml(fixture_dir, agent) -> str:
    path = fixture_dir / "agents-activity.toml"
    path.write_text(f'[[agents]]\nname = "fake"\nhost = "127.0.0.1"\nport = {agent.port}\n'
                    f'cert_sha256 = "{cert_fingerprint()}"\ntoken = "{agent.token}"\n', encoding="utf-8")
    return str(path)


def test_agents_status_lists_the_other_sessions_and_never_its_own(fixture_dir, agent, capsys):
    path = _toml(fixture_dir, agent)
    with client_for(agent, label=APPS) as worker:
        worker.list_dir("/volume1/Backup")
        worker.measure("/volume1/Backup/a.txt")
        assert cli.main(["--config", path, "agents", "status"]) in (0, 1)       # 1: the fake's hashes differ
        out = capsys.readouterr().out
        assert "  sessions     1 other connection(s)" in out
        line = next(ln for ln in out.splitlines() if APPS in ln)
        assert re.fullmatch(r"    scan \\\\nas3\\Apps by kense@DESKTOP  127\.0\.0\.1:\d+  connected \d+s  idle  "
                            r"1 files, 1\.17 KB read, [\d.]+ files/s", line), line
        assert "agents status" not in out.replace("  sessions", "")
        assert cli.main(["--config", path, "agents", "status", "--json"]) in (0, 1)
        row = json.loads(capsys.readouterr().out)
    assert [s["label"] for s in row["sessions"]] == [APPS] and row["sessions"][0]["files"] == 1
    assert row["sessions"][0]["peer"].startswith("127.0.0.1:") and "rate" in row["sessions"][0]
    assert row["activity_note"] is None


def test_agents_status_with_nobody_else_and_with_an_old_agent(fixture_dir, agent, capsys):
    path = _toml(fixture_dir, agent)
    cli.main(["--config", path, "agents", "status"])
    assert "  sessions     no other connections" in capsys.readouterr().out
    agent.activity_supported = False
    cli.main(["--config", path, "agents", "status"])
    assert "  sessions     activity not supported (agent 0.2.1-test)" in capsys.readouterr().out
    cli.main(["--config", path, "agents", "status", "--json"])
    row = json.loads(capsys.readouterr().out)
    assert row["sessions"] is None and row["activity_note"] == "activity not supported (agent 0.2.1-test)"


# --- configuration -----------------------------------------------------------------------------------
def test_max_jobs_and_progress_interval_in_the_configuration():
    assert config.load_agents({"agents": [{"name": "a", "host": "h", "cert_sha256": "00" * 32, "token": "t"}]})[0].max_jobs == 1
    two = {"name": "a", "host": "h", "cert_sha256": "00" * 32, "token": "t", "max_jobs": 2}
    assert config.load_agents({"agents": [two]})[0].max_jobs == 2
    for bad in (0, -1, "2", 1.5, True):
        with pytest.raises(config.ConfigError, match="max_jobs"):
            config.load_agents({"agents": [{**two, "max_jobs": bad}]})
    assert load("").progress_interval == timedelta(minutes=10)
    assert load("[server]\nprogress_interval = '30s'\n").progress_interval == timedelta(seconds=30)
    assert load("[server]\nprogress_interval = 0\n").progress_interval == timedelta(0)
    for text in ("progress_interval = 'soon'", "progress_interval = -5", "progress_interval = false"):
        with pytest.raises(config.ConfigError, match="progress_interval"):
            load(f"[server]\n{text}\n")


def test_the_scheduler_gives_an_agent_as_many_jobs_as_its_limit():
    a1, a2, a3 = spec("a1", "nas3"), spec("a2", "nas3"), spec("a3", "nas3")
    s = scheduler.Scheduler([a1, a2, a3], {}, agent_limits={"nas3": 2})
    plan = s.plan(T0, max_concurrent=5)
    assert [x.name for x in plan.start] == ["a1", "a2"] and [x.name for x in plan.waiting] == ["a3"]


# --- the coordinator: busy deferral -----------------------------------------------------------------
def build(jobs, activity, *, max_jobs=1, runners=None, **cfg):
    shared, clock = SharedBackend(), Clock()
    logs: list[str] = []
    cfg.setdefault("shutdown_grace", timedelta(seconds=5))
    agents = [config.AgentConfig(name=a.name, host=a.host, cert_sha256=a.cert_sha256, token=a.token, alias=a.alias,
                                 max_jobs=max_jobs) for a in agents_cfg("nas3", "nas4")]
    asked: list[str] = []

    def fetch(agent, timeout):
        asked.append(agent.name)
        return activity() if callable(activity) else activity
    coord = Coordinator(ServerConfig(jobs=tuple(jobs), **cfg), agents, ServerStore(shared.handle(), clock),
                        file_cfg={}, catalog=_catalog(), clock=clock, probe=ok_probe, activity=fetch,
                        runners=runners or {"scan": lambda ctx: JobResult("ok", 0, {"files": 1})},
                        logger=logs.append, holder="A")
    coord.logs, coord.asked = logs, asked
    coord.acquire()
    coord.probe_due(clock(), wait=True)
    return coord, clock


def test_a_job_waits_while_another_client_works_on_its_agent_and_starts_when_it_is_free():
    other = [sess(1, APPS, command="sum_subtree", connected=720)]
    box = {"act": Activity(tuple(other), self_id=99)}
    coord, clock = build([spec("nightly", "nas3")], lambda: box["act"])
    for _ in range(3):                                  # three ticks, each past the activity cache
        clock.advance(seconds=10)
        coord.tick()
    expected = f"job nightly waits: nas3 busy ({APPS} for 12m)"
    assert coord.logs.count(expected) == 1              # logged once per busy spell, not every tick
    assert not coord.runs and coord.store.recent(5) == []
    snap = coord.jobs_snapshot()[0]
    assert snap["deferred"] == f"nas3 busy ({APPS} for 12m)" and snap["running"] is False
    box["act"] = Activity((), self_id=99)               # the other client finished
    clock.advance(seconds=10)
    coord.tick()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs)
    assert coord.store.recent(1)[0]["outcome"] == "ok" and coord.jobs_snapshot()[0]["deferred"] is None
    # a second busy spell is logged again
    box["act"] = Activity(tuple(other), self_id=99)
    clock.advance(hours=2)
    coord.tick()
    assert coord.logs.count(expected) == 2
    coord.shutdown()


def test_activity_is_asked_only_when_a_job_is_about_to_start_and_is_cached_between_ticks():
    coord, clock = build([spec("nightly", "nas3", every=timedelta(days=1), run_on_start=False)],
                         Activity((sess(1, APPS, command="measure"),), self_id=99))
    coord.tick()
    assert coord.asked == []                            # nothing due: no connection to the agent
    clock.advance(days=1, seconds=1)
    for _ in range(3):
        coord.tick()                                    # the clock does not move: one answer serves them
    assert coord.asked == ["nas3"]
    coord.shutdown()


def test_health_checks_viewers_and_our_own_session_never_defer_a_job():
    act = Activity((sess(1, LABEL_HEALTH, last=1), sess(2, "viewer", command="list_dir"),
                    sess(3, "busy check", last=1), sess(4, "agents status", last=1),
                    sess(5, "half open", authenticated=False), sess(99, "job nightly: scan", command="list_dir")),
                   self_id=99)
    coord, clock = build([spec("nightly", "nas3")], act)
    coord.tick()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs)
    assert coord.store.recent(1)[0]["outcome"] == "ok" and not any("waits" in m for m in coord.logs)
    coord.shutdown()


def test_an_agent_without_activity_falls_back_to_the_servers_own_running_jobs():
    release = threading.Event()

    def slow(ctx):
        release.wait(10)
        return JobResult("ok")
    coord, clock = build([spec("a1", "nas3"), spec("a2", "nas3")], None, runners={"scan": slow})
    coord.tick()
    assert wait_for(lambda: len(coord.runs) == 1) and list(coord.runs) == ["a1"]
    clock.advance(seconds=10)
    coord.tick()
    assert list(coord.runs) == ["a1"] and not any("busy" in m for m in coord.logs)    # waits on our own job only
    release.set()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs)
    coord.shutdown()


def test_max_jobs_two_allows_two_jobs_and_counts_other_clients():
    release = threading.Event()
    started: list[str] = []

    def slow(ctx):
        started.append(ctx.spec.name)
        release.wait(10)
        return JobResult("ok")
    coord, clock = build([spec("a1", "nas3"), spec("a2", "nas3"), spec("a3", "nas3")], None, max_jobs=2,
                         runners={"scan": slow}, max_concurrent=5)
    coord.tick()
    assert wait_for(lambda: sorted(started) == ["a1", "a2"]) and list(coord.runs) == ["a1", "a2"]
    release.set()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs and "a3" in started)
    coord.shutdown()
    # one other client already works there: one of ours fits, the second must wait; our own sessions are not counted twice
    started.clear()
    release.clear()
    ours = lambda: Activity((sess(1, APPS, command="sum_subtree"),                           # noqa: E731
                             *(sess(10 + i, f"job {n}: scan", command="list_dir") for i, n in enumerate(started))), self_id=99)
    coord, clock = build([spec("b1", "nas3"), spec("b2", "nas3")], ours, max_jobs=2, runners={"scan": slow},
                         max_concurrent=5)
    coord.tick()
    assert wait_for(lambda: started == ["b1"])
    clock.advance(seconds=10)
    coord.tick()
    assert list(coord.runs) == ["b1"] and coord.jobs_snapshot()[1]["deferred"].startswith("nas3 busy (")
    release.set()
    coord.shutdown()


def test_labels_of_the_servers_jobs():
    assert job_label(spec("nightly-apps", kind="scan")) == "job nightly-apps: scan"
    assert job_label(spec("topology@nas3", kind="storage-collect")) == "job topology@nas3: storage-collect"
    assert job_label(spec("scan:\\\\nas3\\Apps", kind="scan-root")) == "job scan:\\\\nas3\\Apps: scan"


# --- the coordinator: progress ----------------------------------------------------------------------
def progress_run(**cfg):
    release = threading.Event()
    attached = threading.Event()

    def slow(ctx):
        ctx.live.attach(types.SimpleNamespace(files=1200, bytes=5 * 2 ** 30), "\\\\nas3\\Apps")
        attached.set()
        release.wait(10)
        return JobResult("ok")
    coord, clock = build([spec("nightly", "nas3")], None, runners={"scan": slow}, **cfg)
    coord.tick()
    assert attached.wait(10) and wait_for(lambda: coord.runs["nightly"].live.snapshot()[0] == 1200)
    return coord, clock, release


def test_progress_is_logged_and_stored_at_the_interval_on_a_fake_clock():
    coord, clock, release = progress_run(progress_interval=timedelta(minutes=10))
    started = clock.now
    clock.advance(minutes=9)
    coord.tick()
    assert not any("progress" in m for m in coord.logs) and "progress" not in coord.store.recent(1)[0]
    clock.advance(minutes=1)
    coord.tick()
    lines = [m for m in coord.logs if "progress" in m]
    assert lines == ["job nightly progress: scan on nas3, 10m elapsed, 1200 files, 5.00 GB, 2.0 files/s, "
                     "root \\\\nas3\\Apps"]
    row = coord.store.recent(1)[0]
    assert row["outcome"] == "running" and row["progress"] == {
        "at": iso(started + timedelta(minutes=10)), "files": 1200, "bytes": 5 * 2 ** 30, "rate": 2.0,
        "root": "\\\\nas3\\Apps"}
    assert coord.jobs_snapshot()[0]["progress"]["files"] == 1200
    clock.advance(minutes=10)
    coord.tick()                                            # nothing new was counted: rate 0
    assert len([m for m in coord.logs if "progress" in m]) == 2 and coord.store.recent(1)[0]["progress"]["rate"] == 0.0
    release.set()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs)
    assert coord.store.recent(1)[0]["outcome"] == "ok" and coord.store.recent(1)[0]["progress"]["files"] == 1200
    coord.shutdown()


def test_progress_interval_zero_turns_the_lines_off():
    coord, clock, release = progress_run(progress_interval=timedelta(0))
    clock.advance(minutes=45)
    coord.tick()
    assert not any("progress" in m for m in coord.logs) and "progress" not in coord.store.recent(1)[0]
    release.set()
    assert wait_for(lambda: coord.tick() is not None and not coord.runs)
    coord.shutdown()
