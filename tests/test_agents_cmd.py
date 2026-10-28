"""`filecat agents enroll|status|fingerprint` and the expected-hash file
(src/filecat/data/agent_expected.json)."""
from __future__ import annotations

import json
import re

import pytest

from filecat import agent_expected, cli, config
from _fake_agent import FakeAgent, cert_fingerprint


@pytest.fixture
def agent(fixture_dir):
    root = fixture_dir / "served"
    root.mkdir()
    with FakeAgent(root) as fake:
        yield fake


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def toml_for(fixture_dir, agent, body: str = "", name: str = "filecat.toml", subs: dict | None = None) -> str:
    path = fixture_dir / name
    text = f"""
[[agents]]
name = "nas3"
host = "127.0.0.1"
port = {agent.port}
cert_sha256 = "{cert_fingerprint()}"
token = "{agent.token}"
{body}
"""
    for old, new in (subs or {}).items():
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    return str(path)


# --- the expected-hash file ---------------------------------------------------------------------
def test_expected_file_deny_hash_is_recomputed_in_python():
    table = agent_expected.load()
    assert table["1"]["deny_sha256"] == agent_expected.deny_sha256()
    linux = table["1"]["allowlist_sha256"]["linux"]
    assert re.fullmatch(r"[0-9a-f]{64}", linux)
    assert table["1"]["allowlist_sha256"]["windows"] is None       # phase 2: not known, no warning


def test_compare_knows_what_it_does_not_know():
    table = {"1": {"deny_sha256": "a" * 64, "allowlist_sha256": {"linux": "b" * 64, "windows": None}}}
    assert agent_expected.compare(1, "linux", "b" * 64, "a" * 64, table) == (True, True)
    assert agent_expected.compare(1, "linux", "c" * 64, "A" * 64, table) == (False, True)
    assert agent_expected.compare(1, "windows", "c" * 64, "a" * 64, table) == (None, True)
    assert agent_expected.compare(2, "linux", "c" * 64, "a" * 64, table) == (None, None)
    assert agent_expected.compare(1, "linux", None, None, table) == (None, None)


# --- enroll -------------------------------------------------------------------------------------
def test_enroll_prints_the_token_once_and_keeps_it_out_of_the_stanza(agent, fixture_dir, capsys):
    cfg = toml_for(fixture_dir, agent)
    code, out, err = run(capsys, "--config", cfg, "agents", "enroll", "nas9", "--host",
                         f"127.0.0.1:{agent.port}", "--alias", "\\\\nas9")
    assert code == 0, err
    token = re.search(r"FILECAT_AGENT_TOKEN=([0-9a-f]+)", out).group(1)
    assert len(token) == 64
    assert "FILECAT_NAS9_TOKEN" in out and '${FILECAT_NAS9_TOKEN}' in out
    assert "# FILECAT_AGENT_ALLOW_ROOTS=" in out
    assert cert_fingerprint() in out                                  # fetched once (trust on first use)
    assert "Nothing written" in out and "shown only now" in out
    stanza = out[out.index("[[agents]]"):].split("Certificate fingerprint")[0]
    assert token not in stanza
    assert token not in (fixture_dir / "filecat.toml").read_text()    # nothing written without --write
    code2, out2, _ = run(capsys, "--config", cfg, "agents", "enroll", "nas9", "--host", f"127.0.0.1:{agent.port}")
    assert re.search(r"FILECAT_AGENT_TOKEN=([0-9a-f]+)", out2).group(1) != token


def test_enroll_write_appends_a_loadable_stanza_and_refuses_duplicates(agent, fixture_dir, capsys):
    cfg = toml_for(fixture_dir, agent)
    code, out, err = run(capsys, "--config", cfg, "agents", "enroll", "nas9", "--host",
                         f"127.0.0.1:{agent.port}", "--alias", "\\\\NAS9", "--write")
    assert code == 0, err
    token = re.search(r"FILECAT_AGENT_TOKEN=([0-9a-f]+)", out).group(1)
    text = (fixture_dir / "filecat.toml").read_text()
    assert token not in text
    agents = {a.name: a for a in config.load_agents(config.load(fixture_dir / "filecat.toml"))}
    assert set(agents) == {"nas3", "nas9"}
    assert agents["nas9"].cert_sha256 == cert_fingerprint() and agents["nas9"].alias == "\\\\NAS9"
    assert agents["nas9"].token == "${FILECAT_NAS9_TOKEN}" and agents["nas9"].port == agent.port
    before = text
    code, out, err = run(capsys, "--config", cfg, "agents", "enroll", "nas9", "--host", "127.0.0.1", "--write")
    assert code == 2 and "already exists" in err and "FILECAT_AGENT_TOKEN" not in out
    assert (fixture_dir / "filecat.toml").read_text() == before


def test_enroll_write_needs_a_fingerprint(agent, fixture_dir, capsys):
    cfg = toml_for(fixture_dir, agent)
    before = (fixture_dir / "filecat.toml").read_text()
    code, out, err = run(capsys, "--config", cfg, "agents", "enroll", "nas9", "--host", "127.0.0.1:1",
                         "--timeout", "1", "--write")
    assert code == 2 and "needs the certificate fingerprint" in err
    assert "could not connect" in out and "agents fingerprint" in out
    assert (fixture_dir / "filecat.toml").read_text() == before
    code, out, err = run(capsys, "--config", cfg, "agents", "enroll", "nas9", "--host", "127.0.0.1:1",
                         "--no-connect", "--cert-sha256", "AB" * 32, "--write")
    assert code == 0, err
    assert {a.name for a in config.load_agents(config.load(fixture_dir / "filecat.toml"))} == {"nas3", "nas9"}


def test_enroll_rejects_bad_names_and_fingerprint_command(agent, fixture_dir, capsys):
    cfg = toml_for(fixture_dir, agent)
    code, _, err = run(capsys, "--config", cfg, "agents", "enroll", "bad name", "--host", "x", "--no-connect")
    assert code == 2 and "NAME" in err
    code, out, _ = run(capsys, "agents", "fingerprint", f"127.0.0.1:{agent.port}")
    assert code == 0 and out.strip() == cert_fingerprint()


# --- status -------------------------------------------------------------------------------------
def test_status_matching_and_mismatching_hashes(agent, fixture_dir, capsys):
    cfg = toml_for(fixture_dir, agent)
    want = agent_expected.expected(1, "linux")
    # the fake's own allowlist digest is not the Rust one: a mismatch, deny list matches
    code, out, _ = run(capsys, "--config", cfg, "agents", "status")
    assert code == 0                                                   # a warning, not an error
    assert "deny list    match" in out and "allowlist    MISMATCH" in out
    assert "agent built from a different allowlist/deny list (outdated or modified)" in out
    code, out, _ = run(capsys, "--config", cfg, "agents", "status", "--strict")
    assert code == 1
    # an agent that reports the expected values
    agent.allowlist_sha256 = want.allowlist_sha256
    code, out, _ = run(capsys, "--config", cfg, "agents", "status", "--strict")
    assert code == 0 and "MISMATCH" not in out and "warning" not in out
    assert "cert pin     ok" in out and "protocol 1" in out and "run ids" in out
    # a changed deny list
    agent.deny_sha256 = "0" * 64
    code, out, _ = run(capsys, "--config", cfg, "agents", "status", "--strict")
    assert code == 1 and "deny list    MISMATCH" in out
    code, out, _ = run(capsys, "--config", cfg, "agents", "status", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["mismatch"] and doc["deny_match"] is False and doc["allowlist_match"] is True
    assert doc["warnings"] and doc["ok"] and doc["reachable"] and doc["cert_pin"] == "ok"
    assert doc["version"] and doc["platform"] and isinstance(doc["runs_available"], list)


def test_status_reports_roots_product_type_and_failures(agent, fixture_dir, capsys, monkeypatch):
    agent_roots = FakeAgent(fixture_dir / "served", allow_roots=["/volume1/Backup", "/proc"])
    agent_roots.product_type = 3
    try:
        cfg = toml_for(fixture_dir, agent_roots)
        code, out, _ = run(capsys, "--config", cfg, "agents", "status", "nas3", "--json")
        doc = json.loads(out)
        assert doc["allow_roots"] == ["/volume1/Backup", "/proc"] and doc["allow_roots_source"] == "env"
        assert doc["product_type"] == 3
    finally:
        agent_roots.stop()
    # wrong pin, wrong token, nothing listening, token variable unset
    bad = toml_for(fixture_dir, agent, name="bad.toml", subs={cert_fingerprint(): "ab" * 32})
    code, out, err = run(capsys, "--config", bad, "agents", "status", "--json")
    doc = json.loads(out)
    assert code == 1 and doc["cert_pin"] == "mismatch" and not doc["ok"]
    tok = toml_for(fixture_dir, agent, name="tok.toml", subs={agent.token: "wrong"})
    code, out, _ = run(capsys, "--config", tok, "agents", "status", "--json")
    doc = json.loads(out)
    assert code == 1 and doc["reachable"] and doc["error_code"] and not doc["ok"]
    down = toml_for(fixture_dir, agent, name="down.toml", subs={f"port = {agent.port}": "port = 1"})
    code, out, _ = run(capsys, "--config", down, "agents", "status", "--timeout", "1")
    assert code == 1 and out.startswith("FAIL nas3")
    monkeypatch.delenv("FILECAT_NOPE_TOKEN", raising=False)
    unset = toml_for(fixture_dir, agent, name="unset.toml", subs={agent.token: "${FILECAT_NOPE_TOKEN}"})
    code, out, _ = run(capsys, "--config", unset, "agents", "status")
    assert code == 1 and "FILECAT_NOPE_TOKEN" in out


def test_status_scrubs_paths_from_errors():
    from filecat.agent_status import error_text
    text = error_text(OSError(2, "No such file", "\\\\nas\\private\\secret-project\\x.txt"))
    assert "secret-project" not in text
    assert "secret" not in error_text(ValueError("failed on /volume1/secret/dir and C:\\Users\\secret"))
