"""The filecat-agent client (docs/agent-protocol.md) against a fake agent in
Python (tests/_fake_agent.py): pinning, hello/auth, the commands, chunked
reads, RemoteFileProxy under zipfile, reconnecting, ShareMap, and
`filecat agents`.
"""
from __future__ import annotations

import base64
import io
import json
import os
import zipfile

import pytest

from filecat import agent_client, cli, config
from filecat.agent_client import (AgentClient, AgentError, FingerprintMismatch, ProtocolError,
                                  RemoteFileProxy, ShareMap, open_remote)
from filecat.hashing import hash_file
from filecat.options import PARTIAL_HASH_CUTOFF
from _fake_agent import FakeAgent, cert_fingerprint, floor100


@pytest.fixture
def tree(fixture_dir):
    root = fixture_dir / "nas"
    (root / "volume1" / "Backup" / "sub").mkdir(parents=True)
    (root / "volume1" / "Backup" / "a.txt").write_bytes(b"hello agent\n" * 100)
    (root / "volume1" / "Backup" / "empty.bin").write_bytes(b"")
    (root / "volume1" / "Backup" / "sub" / "b.bin").write_bytes(bytes(range(256)) * 40)
    return root


@pytest.fixture
def agent(tree):
    with FakeAgent(tree) as fake:
        yield fake


def client_for(agent: FakeAgent, **kwargs) -> AgentClient:
    kwargs.setdefault("timeout", 5)
    kwargs.setdefault("io_timeout", 20)
    return AgentClient("127.0.0.1", agent.port, cert_fingerprint(), agent.token, **kwargs)


# --- connecting -----------------------------------------------------------
def test_hello_and_auth(agent):
    with client_for(agent) as c:
        info = c.connect()
        assert (info.protocol, info.agent_version, info.hostname) == (1, "0.2.0-test", "fake-nas")
        assert (info.os, info.arch) == ("linux", "x86_64")
        assert c.hello() == info
    assert [r["cmd"] for r in agent.requests[:2]] == ["hello", "auth"]


@pytest.mark.parametrize("form", [
    lambda fp: fp.upper(),
    lambda fp: ":".join(fp[i:i + 2] for i in range(0, 64, 2)),
    lambda fp: ":".join(fp[i:i + 2].upper() for i in range(0, 64, 2)),
], ids=["upper", "colons", "colons-upper"])
def test_fingerprint_forms_accepted(agent, form):
    with AgentClient("127.0.0.1", agent.port, form(cert_fingerprint()), agent.token, timeout=5) as c:
        assert c.connect().protocol == 1


def test_bad_fingerprint_text_rejected():
    for text in ("", "abc", "zz" * 32, "00" * 31):
        with pytest.raises(ValueError):
            agent_client.normalize_fingerprint(text)


def test_fingerprint_mismatch_refused_before_token_is_sent(agent):
    other = "00" * 32
    c = AgentClient("127.0.0.1", agent.port, other, agent.token, timeout=5)
    with pytest.raises(FingerprintMismatch) as err:
        c.connect()
    assert err.value.code == "fingerprint"
    assert cert_fingerprint() in str(err.value)
    assert not any(r["cmd"] == "auth" for r in agent.requests)
    assert agent.requests == []             # not even hello


def test_bad_token_refused(agent):
    c = AgentClient("127.0.0.1", agent.port, cert_fingerprint(), "wrong", timeout=5)
    with pytest.raises(AgentError) as err:
        c.list_dir("/volume1")
    assert err.value.code == "unauthorized"
    assert isinstance(err.value, OSError)


def test_protocol_version_refused(tree):
    with FakeAgent(tree, protocol=2) as old:
        c = client_for(old)
        with pytest.raises(ProtocolError, match="protocol 2"):
            c.connect()
        assert not any(r["cmd"] == "auth" for r in old.requests)


def test_connection_refused_is_an_oserror(agent):
    agent.stop()
    with pytest.raises(OSError):
        client_for(agent, timeout=2).connect()


# --- commands -------------------------------------------------------------
def test_list_dir(agent, tree):
    with client_for(agent) as c:
        listing = c.list_dir("/volume1/Backup")
    assert [e.name for e in listing.entries] == ["a.txt", "empty.bin", "sub"]
    a = listing.entries[0]
    st = os.stat(tree / "volume1" / "Backup" / "a.txt")
    assert (a.kind, a.size, a.mtime_ns) == ("file", 1200, floor100(st.st_mtime_ns))
    assert a.allocated_size >= a.size and a.nlink == 1
    assert listing.entries[2].kind == "dir"
    assert listing.mtime_ns % 100 == 0 and listing.dev


def test_list_dir_errors(agent):
    agent.entry_errors = {"a.txt"}
    with client_for(agent) as c:
        entries = {e.name: e for e in c.list_dir("/volume1/Backup").entries}
        assert entries["a.txt"].error == {"code": "permission_denied", "message": "denied"}
        assert entries["a.txt"].size == 0
        with pytest.raises(AgentError) as err:
            c.list_dir("/volume1/nope")
        assert err.value.code == "not_found"
        with pytest.raises(AgentError) as err:
            c.list_dir("/volume1/Backup/a.txt")
        assert err.value.code == "bad_request"
        assert c.list_dir("/volume1/Backup/sub")      # the connection survived the errors


def test_relative_path_is_a_valueerror(agent):
    with client_for(agent) as c:
        with pytest.raises(ValueError):
            c.list_dir("volume1/Backup")
        with pytest.raises(ValueError):
            c.list_dir("\\\\nas-main\\Backup")


def test_non_utf8_names(agent):
    raw = b"caf\xe9.txt"
    agent.extra_entries = [{"name": "caf\ufffd.txt", "name_b64": base64.b64encode(raw).decode(),
                            "kind": "link", "link_target": "x\ufffd",
                            "link_target_b64": base64.b64encode(b"x\xff").decode()}]
    with client_for(agent) as c:
        entry = c.list_dir("/volume1/Backup").entries[-1]
        assert entry.name == "caf\udce9.txt" and entry.link_target == "x\udcff"
        assert os.fsencode(entry.name) == raw or entry.name.encode("utf-8", "surrogateescape") == raw
        path = AgentClient.child("/volume1/Backup", entry)
        assert agent_client.path_fields(path) == {"path_b64": base64.b64encode(b"/volume1/Backup/" + raw).decode()}
    assert agent_client.path_fields("/volume1/ok") == {"path": "/volume1/ok"}
    assert agent_client.path_fields(b"/v\xe9") == {"path_b64": base64.b64encode(b"/v\xe9").decode()}


def test_measure_small_file_matches_hashing(agent, tree):
    path = tree / "volume1" / "Backup" / "a.txt"
    st = os.stat(path)
    with client_for(agent) as c:
        m = c.measure("/volume1/Backup/a.txt")
        assert m.size == st.st_size and m.mtime_ns == floor100(st.st_mtime_ns)
        assert m.head == path.read_bytes()[:8192]
        assert m.hashes == hash_file(str(path), m.size, m.mtime_ns, "auto")
        assert set(m.hashes) == {"sha256"}
        assert c.measure("/volume1/Backup/a.txt", head_bytes=10).head == b"hello agen"
        none = c.measure("/volume1/Backup/a.txt", hash="none")
        assert none.hashes == {} and none.head
        with pytest.raises(ValueError):
            c.measure("/volume1/Backup/a.txt", hash="md5")


def test_measure_empty_file(agent):
    import hashlib
    with client_for(agent) as c:
        auto = c.measure("/volume1/Backup/empty.bin")
        assert auto.size == 0 and auto.head == b"" and auto.hashes == {}
        assert c.measure("/volume1/Backup/empty.bin", hash="full").hashes == {
            "sha256": hashlib.sha256(b"").hexdigest()}


def test_measure_big_file_partial_uses_100ns_mtime(agent, tree):
    path = tree / "volume1" / "Backup" / "big.bin"
    with open(path, "wb") as f:
        f.seek(PARTIAL_HASH_CUTOFF)
        f.write(b"\x01")
    os.utime(path, ns=(1_700_000_000_123_456_789, 1_700_000_000_123_456_789))
    size = PARTIAL_HASH_CUTOFF + 1
    with client_for(agent) as c:
        m = c.measure("/volume1/Backup/big.bin", head_bytes=16)
        assert m.size == size
        assert m.mtime_ns % 100 == 0
        # what an SMB scan of the same file computes: mtime in 100 ns ticks
        assert m.hashes == hash_file(str(path), size, floor100(1_700_000_000_123_456_789), "auto")
        assert set(m.hashes) == {"sha256_partial"}
        assert c.measure("/volume1/Backup/big.bin", head_bytes=0).head == b""


def test_read_range(agent, tree):
    data = (tree / "volume1" / "Backup" / "sub" / "b.bin").read_bytes()
    with client_for(agent) as c:
        assert c.read_range("/volume1/Backup/sub/b.bin", 0, 10) == data[:10]
        assert c.read_range("/volume1/Backup/sub/b.bin", 1000, 50) == data[1000:1050]
        assert c.read_range("/volume1/Backup/sub/b.bin", len(data) - 5, 100) == data[-5:]
        assert c.read_range("/volume1/Backup/sub/b.bin", len(data) + 10, 100) == b""
        assert c.read_range("/volume1/Backup/sub/b.bin", 0, 0) == b""
        with pytest.raises(AgentError) as err:
            c.read_range("/volume1/Backup/missing", 0, 10)
        assert err.value.code == "not_found"
        with pytest.raises(ValueError):
            c.read_range("/volume1/Backup/sub/b.bin", -1, 10)


def test_read_range_over_the_maximum_is_refused_by_the_agent(agent):
    with client_for(agent) as c:
        c.connect()
        with pytest.raises(AgentError) as err:
            c._call({"cmd": "read_range", "path": "/volume1/Backup/a.txt", "offset": 0,
                     "len": agent_client.MAX_READ + 1})
        assert err.value.code == "bad_request"


def test_read_range_splits_requests_above_the_maximum(agent, tree, monkeypatch):
    data = os.urandom(300_000)
    (tree / "volume1" / "Backup" / "r.bin").write_bytes(data)
    monkeypatch.setattr(agent_client, "MAX_READ", 100_000)
    monkeypatch.setattr("_fake_agent.MAX_READ", 100_000)
    with client_for(agent) as c:
        assert c.read_range("/volume1/Backup/r.bin", 10, 250_000) == data[10:250_010]
        reads = [r for r in agent.requests if r["cmd"] == "read_range"]
        assert [r["len"] for r in reads] == [100_000, 100_000, 50_000]
        assert [r["offset"] for r in reads] == [10, 100_010, 200_010]
        assert c.read_range("/volume1/Backup/r.bin", 0, 10_000_000) == data     # stops at eof
    assert max(r["len"] for r in agent.requests if r["cmd"] == "read_range") <= 100_000


def test_sum_subtree(agent, tree):
    base = tree / "volume1" / "Backup"
    os.link(base / "a.txt", base / "sub" / "a-link.txt")
    with client_for(agent) as c:
        s = c.sum_subtree("/volume1/Backup")
    assert (s.total_files, s.total_dirs) == (4, 2)      # the folder itself counts in total_dirs
    assert s.total_size == 1200 + 0 + 10240      # the hard link counted once
    assert s.newest_mtime_ns % 100 == 0 and s.errors == 0
    with client_for(agent) as c:
        with pytest.raises(AgentError) as err:
            c.sum_subtree("/volume1/Backup/a.txt")
        assert err.value.code == "bad_request"


def test_storage_topology(agent):
    with client_for(agent) as c:
        volumes = c.storage_topology()
    assert volumes[0]["mount_point"] == "/volume1" and volumes[0]["shares"] == ["Backup"]


def test_policy_exclude_and_rollup(agent, tree):
    base = tree / "volume1" / "Backup"
    (base / "node_modules").mkdir()
    (base / "node_modules" / "x.js").write_bytes(b"12345")
    (base / "node_modules" / "y.js").write_bytes(b"1234567")
    (base / "skip.tmp").write_bytes(b"x")
    with client_for(agent) as c:
        rules = [{"id": 0, "tag": "[CACHE]", "match": ["node_modules"], "type": "dir"}]
        reply = c.configure_policy(exclude=["skip.tmp"], rules=rules)
        assert reply["rules"] == 1 and len(reply["policy_id"]) == 12
        listing = c.list_dir("/volume1/Backup")
        entries = {e.name: e for e in listing.entries}
        assert "skip.tmp" not in entries and "node_modules" not in entries
        roll = entries["[CACHE]"]
        assert roll.kind == "rollup" and roll.size == 12
        assert roll.rollup["matched"] == 1 and roll.rollup["total_files"] == 2
        assert roll.rollup["total_dirs"] == 1 and roll.rollup["oldest_mtime_ns"] % 100 == 0
        assert listing.policy_id == reply["policy_id"]


def test_policy_from_the_constructor_and_after_reconnect(agent, tree):
    (tree / "volume1" / "Backup" / "skip.tmp").write_bytes(b"x")
    policy = {"exclude": ["skip.tmp"]}
    with client_for(agent, policy=policy) as c:
        assert "skip.tmp" not in [e.name for e in c.list_dir("/volume1/Backup").entries]
        agent.drop_connections()
        assert "skip.tmp" not in [e.name for e in c.list_dir("/volume1/Backup").entries]


# --- connection handling ----------------------------------------------------
def test_reconnects_once_after_the_server_drops_the_connection(agent):
    with client_for(agent) as c:
        c.list_dir("/volume1/Backup")
        assert agent.connections == 1
        agent.drop_connections()
        assert [e.name for e in c.list_dir("/volume1/Backup").entries][0] == "a.txt"
        assert agent.connections == 2
        hellos = [r["cmd"] for r in agent.requests].count("hello")
        assert hellos == 2          # the new connection said hello and auth again


def test_no_retry_when_a_fresh_connection_fails(agent):
    agent.stop()
    c = client_for(agent, timeout=2)
    with pytest.raises(OSError):
        c.list_dir("/volume1")


def test_agent_errors_do_not_drop_the_connection(agent):
    with client_for(agent) as c:
        with pytest.raises(AgentError):
            c.list_dir("/nope")
        c.list_dir("/volume1")
    assert agent.connections == 1


def test_threads_share_one_client(agent, tree):
    import threading
    data = (tree / "volume1" / "Backup" / "sub" / "b.bin").read_bytes()
    errors: list[BaseException] = []
    with client_for(agent) as c:
        def work(i: int) -> None:
            try:
                for _ in range(20):
                    assert c.read_range("/volume1/Backup/sub/b.bin", i * 100, 100) == data[i * 100:i * 100 + 100]
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
        threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert errors == []
    assert agent.connections == 1


def test_from_config(agent, monkeypatch):
    monkeypatch.setenv("FC_AGENT_TOKEN", agent.token)
    cfg = {"agents": [{"name": "fake", "host": "127.0.0.1", "port": agent.port,
                       "cert_sha256": cert_fingerprint(), "token": "${FC_AGENT_TOKEN}"}]}
    (a,) = config.load_agents(cfg)
    with AgentClient.from_config(a) as c:
        assert c.connect().hostname == "fake-nas"


# --- RemoteFileProxy ------------------------------------------------------
def test_proxy_is_a_real_file(agent, tree):
    data = (tree / "volume1" / "Backup" / "sub" / "b.bin").read_bytes()
    with client_for(agent) as c:
        raw = RemoteFileProxy(c, "/volume1/Backup/sub/b.bin", len(data))
        assert isinstance(raw, io.RawIOBase) and raw.readable() and raw.seekable() and not raw.writable()
        assert raw.read(10) == data[:10] and raw.tell() == 10
        assert raw.seek(-5, io.SEEK_END) == len(data) - 5
        assert raw.read() == data[-5:] and raw.read(10) == b""
        assert raw.seek(100) == 100 and raw.seek(20, io.SEEK_CUR) == 120
        buf = bytearray(8)
        assert raw.readinto(buf) == 8 and bytes(buf) == data[120:128]
        assert raw.seek(len(data) + 50) == len(data) + 50 and raw.read(5) == b""
        with pytest.raises(OSError):
            raw.seek(-1)
        raw.seek(0)
        assert raw.readall() == data
        raw.close()
        c.list_dir("/volume1")      # closing the proxy leaves the client open


def test_open_remote_buffers_small_reads(agent, tree):
    data = (tree / "volume1" / "Backup" / "sub" / "b.bin").read_bytes()
    with client_for(agent) as c:
        f = open_remote(c, "/volume1/Backup/sub/b.bin", len(data), buffer_size=4096)
        assert isinstance(f, io.BufferedReader)
        c.connect()
        before = len(agent.requests)
        assert [f.read(100) for _ in range(10)] == [data[i:i + 100] for i in range(0, 1000, 100)]
        assert len(agent.requests) - before == 1
        f.seek(5000)
        assert f.read(3) == data[5000:5003]
        assert f.peek(1)


def test_zipfile_through_the_proxy(agent, tree):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "hello zip\n" * 50)
        z.writestr("dir/data.bin", bytes(range(256)) * 20)
    blob = buf.getvalue()
    (tree / "volume1" / "Backup" / "t.zip").write_bytes(blob)
    with client_for(agent) as c:
        m = c.measure("/volume1/Backup/t.zip")
        with open_remote(c, "/volume1/Backup/t.zip", m.size) as f, zipfile.ZipFile(f) as z:
            assert z.namelist() == ["readme.txt", "dir/data.bin"]
            assert z.read("dir/data.bin") == bytes(range(256)) * 20
            assert z.testzip() is None
        reads = [r for r in agent.requests if r["cmd"] == "read_range"]
        assert reads and all(r["len"] <= agent_client.MAX_READ for r in reads)


# --- ShareMap ---------------------------------------------------------------
def test_sharemap_synology_fallback():
    m = ShareMap("\\\\nas-main")
    assert m.to_catalog_path("/volume1/Backup/x/y") == "\\\\nas-main\\Backup\\x\\y"
    assert m.to_catalog_path("/volume1/Backup") == "\\\\nas-main\\Backup"
    assert m.to_posix_path("\\\\nas-main\\Backup\\x\\y") == "/volume1/Backup/x/y"
    assert m.to_posix_path("\\\\nas-main\\Backup") == "/volume1/Backup"
    assert m.to_posix_path("//nas-main/Backup/x/") == "/volume1/Backup/x"


def test_sharemap_other_paths_use_the_root_form():
    m = ShareMap("\\\\nas-main", volume=1)
    for posix, unc in [("/volume2/Archive/z", "\\\\nas-main\\$root\\volume2\\Archive\\z"),
                       ("/volume1", "\\\\nas-main\\$root\\volume1"),
                       ("/volume1/@appstore/p", "\\\\nas-main\\$root\\volume1\\@appstore\\p"),
                       ("/volume1/#recycle", "\\\\nas-main\\$root\\volume1\\#recycle"),
                       ("/volume1/$root/q", "\\\\nas-main\\$root\\volume1\\$root\\q"),
                       ("/etc/hosts", "\\\\nas-main\\$root\\etc\\hosts"),
                       ("/", "\\\\nas-main\\$root")]:
        assert m.to_catalog_path(posix) == unc
        assert m.to_posix_path(unc) == posix


def test_sharemap_volume_setting():
    m = ShareMap("\\\\nas-old", volume=2)
    assert m.to_catalog_path("/volume2/home/a") == "\\\\nas-old\\home\\a"
    assert m.to_posix_path("\\\\nas-old\\home\\a") == "/volume2/home/a"
    assert m.to_catalog_path("/volume1/home/a") == "\\\\nas-old\\$root\\volume1\\home\\a"


def test_sharemap_explicit_shares_beat_the_fallback():
    m = ShareMap("\\\\nas-main", {"/volume2/Archive": "\\\\nas-main\\Archive",
                                  "/volume1/Backup/Old": "\\\\nas-old\\BackupOld",
                                  "/volume1/Backup": "\\\\nas-main\\Bak"})
    assert m.to_catalog_path("/volume2/Archive/a/b") == "\\\\nas-main\\Archive\\a\\b"
    assert m.to_catalog_path("/volume1/Backup/Old/z") == "\\\\nas-old\\BackupOld\\z"      # longest prefix
    assert m.to_catalog_path("/volume1/Backup/Older") == "\\\\nas-main\\Bak\\Older"      # whole components
    assert m.to_catalog_path("/volume1/Backup") == "\\\\nas-main\\Bak"
    assert m.to_catalog_path("/volume1/home/q") == "\\\\nas-main\\home\\q"
    for posix in ("/volume2/Archive", "/volume2/Archive/a/b", "/volume1/Backup/Old/z",
                  "/volume1/Backup/Older", "/volume1/Backup", "/volume1/home/q", "/tmp/x"):
        assert m.to_posix_path(m.to_catalog_path(posix)) == posix


def test_sharemap_case_rules():
    m = ShareMap("\\\\NAS-Main", {"/volume2/Archive": "\\\\nas-main\\Archive"})
    assert m.alias == "\\\\NAS-Main"
    # towards UNC: the spelling of the agent's host
    assert m.to_catalog_path("/volume1/BackUp/Mixed Case") == "\\\\NAS-Main\\BackUp\\Mixed Case"
    # towards POSIX: server and explicit roots match without case; the rest is kept
    assert m.to_posix_path("\\\\nas-main\\BackUp\\Mixed Case") == "/volume1/BackUp/Mixed Case"
    assert m.to_posix_path("\\\\NAS-MAIN\\ARCHIVE\\Sub") == "/volume2/Archive/Sub"
    assert m.to_catalog_path("/volume2/Archive/Sub") == "\\\\nas-main\\Archive\\Sub"
    assert m.to_catalog_path("/volume2/archive/Sub") == "\\\\NAS-Main\\$root\\volume2\\archive\\Sub"


def test_sharemap_errors():
    m = ShareMap("\\\\nas-main")
    for bad in ("volume1/x", "/volume1//x", "/volume1/../x", "/volume1/x/"):
        with pytest.raises(ValueError):
            m.to_catalog_path(bad)
    with pytest.raises(ValueError, match="backslash"):
        m.to_catalog_path("/volume1/Backup/a\\b")
    with pytest.raises(ValueError):
        m.to_posix_path("\\\\other\\Backup\\x")
    with pytest.raises(ValueError):
        m.to_posix_path("\\\\nas-main")
    with pytest.raises(ValueError):
        m.to_posix_path("C:\\x")
    for alias in ("nas-main", "\\\\nas-main\\Backup", "\\\\"):
        with pytest.raises(ValueError):
            ShareMap(alias)
    with pytest.raises(ValueError):
        ShareMap("\\\\nas", {"/volume1": "\\\\nas"})
    with pytest.raises(ValueError):
        ShareMap("\\\\nas", {"/a": "\\\\nas\\X", "/b": "\\\\NAS\\x"})


def test_sharemap_lines_up_with_an_smb_scan_root(fixture_dir):
    # An SMB scan of \\nas-main\Backup records root \\nas-main\Backup, rel_path "x/y"
    # (record.to_rel_path / join_root); the agent path must give the same pair.
    from filecat import record
    m = ShareMap("\\\\nas-main")
    unc = m.to_catalog_path("/volume1/Backup/x/y")
    root = "\\\\nas-main\\Backup"
    assert unc == record.join_root(root, "x/y") or os.sep == "/"
    assert unc[len(root) + 1:].replace("\\", "/") == "x/y"
    assert m.covers(root) == 1 and m.covers("\\\\other\\Backup") == 0


# --- [[agents]] config ------------------------------------------------------
FP = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _agents(*tables):
    return config.load_agents({"agents": list(tables)})


def _table(**over):
    return {"name": "nas-main", "host": "192.0.2.13", "cert_sha256": FP, "token": "t", **over}


def test_load_agents_defaults_and_normalising():
    (a,) = _agents(_table(cert_sha256=":".join(FP[i:i + 2].upper() for i in range(0, 64, 2))))
    assert (a.name, a.host, a.port, a.alias, a.volume, a.timeout) == (
        "nas-main", "192.0.2.13", 9876, "\\\\nas-main", 1, 30.0)
    assert a.cert_sha256 == FP and a.endpoint == "192.0.2.13:9876"
    assert a.policy() == {} and a.shares == {}
    assert a.share_map().to_catalog_path("/volume1/Backup/z") == "\\\\nas-main\\Backup\\z"


def test_load_agents_full_table(fixture_dir):
    path = fixture_dir / "c.toml"
    path.write_text(
        "[[agents]]\n"
        'name = "nas-main"\nhost = "nas.lan"\nport = 9000\n'
        f'cert_sha256 = "{FP}"\ntoken = "${{FC_T}}"\n'
        "alias = '\\\\NAS-MAIN'\nvolume = 2\nexclude = ['/volume1/@docker']\ntimeout = 12.5\n"
        "[agents.shares]\n'/volume2/Archive' = '\\\\nas-main\\Archive'\n"
        "[[agents]]\n"
        f'name = "nas-old"\nhost = "10.0.0.5"\ncert_sha256 = "{FP}"\ntoken = "x"\n',
        encoding="utf-8")
    main, old = config.load_agents(config.load(path))
    assert (main.port, main.alias, main.volume, main.timeout) == (9000, "\\\\NAS-MAIN", 2, 12.5)
    assert main.shares == {"/volume2/Archive": "\\\\nas-main\\Archive"}
    assert main.policy() == {"exclude": ["/volume1/@docker"]}
    assert old.alias == "\\\\nas-old" and old.token == "x"
    assert config.load_agents({}) == []


def test_token_expands_from_the_environment(monkeypatch):
    (a,) = _agents(_table(token="${FC_AGENT_T}"))
    monkeypatch.delenv("FC_AGENT_T", raising=False)
    with pytest.raises(config.ConfigError, match="FC_AGENT_T"):
        a.resolved_token()
    monkeypatch.setenv("FC_AGENT_T", "sekrit")
    assert a.resolved_token() == "sekrit"
    assert config.mask_token("hunter2") == "***"
    assert config.mask_token("${FC_AGENT_T}") == "${FC_AGENT_T}"


@pytest.mark.parametrize("table, message", [
    ({"foo": 1}, "unknown key 'foo'"),
    ({"name": None}, "name is required"),
    ({"name": "a b"}, "spaces"),
    ({"host": ""}, "host wants"),
    ({"host": "10.0.0.5:9876"}, "put it in port"),
    ({"port": 0}, "port = 0"),
    ({"port": "9876"}, "port = '9876'"),
    ({"port": True}, "port = True"),
    ({"cert_sha256": "abc"}, "64 hex digits"),
    ({"cert_sha256": None}, "cert_sha256 is required"),
    ({"token": ""}, "token wants"),
    ({"alias": "nas-main"}, "UNC"),
    ({"alias": "\\\\nas\\Backup"}, "bare server"),
    ({"shares": {"volume1": "\\\\nas\\X"}}, "absolute POSIX"),
    ({"shares": {"/volume1/X": "nas"}}, "not a UNC path"),
    ({"shares": ["x"]}, "string pairs"),
    ({"volume": 0}, "volume = 0"),
    ({"exclude": "x"}, "exclude wants"),
    ({"rollup_groups": {"[X]": ["*"]}}, r"rollup_groups was removed.*\[\[rollups.rule\]\]"),
    ({"timeout": 0}, "timeout"),
])
def test_load_agents_rejects(table, message):
    t = _table()
    t.update(table)
    t = {k: v for k, v in t.items() if v is not None}
    with pytest.raises(config.ConfigError, match=message) as err:
        _agents(t)
    assert str(err.value).startswith("[[agents]] #1")


def test_load_agents_structure_errors():
    with pytest.raises(config.ConfigError, match="double brackets"):
        config.load_agents({"agents": {"name": "x"}})
    with pytest.raises(config.ConfigError, match="wants a table"):
        config.load_agents({"agents": ["x"]})
    with pytest.raises(config.ConfigError, match="used twice"):
        _agents(_table(), _table(host="10.0.0.6"))
    with pytest.raises(config.ConfigError, match=r"#2 \(second\)"):
        _agents(_table(), _table(name="second", port=99999))


def test_agent_for_longest_match():
    main, old, odd = _agents(
        _table(),
        _table(name="nas-old", alias="\\\\nas-old"),
        _table(name="nas-odd", alias="\\\\nas-odd", shares={"/volume1/Backup": "\\\\nas-main\\Backup"}))
    agents = [main, old, odd]
    assert config.agent_for(agents, "\\\\nas-main\\Home\\x") is main
    assert config.agent_for(agents, "\\\\NAS-OLD\\Home") is old
    assert config.agent_for(agents, "\\\\nas-main\\Backup\\x") is odd     # explicit root is longer
    assert config.agent_for(agents, "\\\\nas-main\\backup") is odd        # share names are case-insensitive
    assert config.agent_for(agents, "\\\\nas-main") is None
    assert config.agent_for(agents, "\\\\elsewhere\\Home") is None
    assert config.agent_for(agents, "C:\\x") is None
    assert config.agent_for([], "\\\\nas-main\\Home") is None
    assert config.agent_for(_agents(_table(name="a", alias="\\\\z"), _table(name="b", alias="\\\\z")),
                            "\\\\z\\x").name == "a"                          # a tie goes to the first


def test_render_has_a_commented_agents_example():
    text = config.render()
    assert "# [[agents]]" in text and "# [agents.shares]" in text
    assert config.load_agents(__import__("tomllib").loads(text)) == []


def test_config_show_lists_agents_with_the_token_masked(fixture_dir, capsys):
    path = fixture_dir / "c.toml"
    path.write_text(f'[[agents]]\nname = "nas-main"\nhost = "h"\ncert_sha256 = "{FP}"\ntoken = "hunter2"\n'
                    '[[agents]]\nname = "b"\nhost = "h2"\n' f'cert_sha256 = "{FP}"\ntoken = "${{FC_NOT_SET_X}}"\n',
                    encoding="utf-8")
    assert cli.main(["--config", str(path), "config", "show"]) == 0
    out = capsys.readouterr().out
    assert "nas-main" in out and "h:9876" in out and "hunter2" not in out and "token = ***" in out
    assert "${FC_NOT_SET_X}" in out and "not set: FC_NOT_SET_X" in out
    assert cli.main(["--config", str(path), "config", "show", "--reveal"]) == 0
    assert "hunter2" in capsys.readouterr().out
    path.write_text('[[agents]]\nname = "x"\n', encoding="utf-8")
    assert cli.main(["--config", str(path), "config", "show"]) == 1
    assert "agents:      invalid: [[agents]] #1 (x): host is required" in capsys.readouterr().out


# --- filecat agents -----------------------------------------------------------
def _config_file(fixture_dir, agent, **over):
    fields = {"name": "fake", "host": "127.0.0.1", "port": agent.port,
              "cert_sha256": cert_fingerprint(), "token": agent.token, **over}
    shares = fields.pop("shares", {})
    lines = "[[agents]]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in fields.items())
    lines += "[agents.shares]\n" + "".join(f"{json.dumps(k)} = {json.dumps(v)}\n" for k, v in shares.items())
    path = fixture_dir / "agents.toml"
    path.write_text(lines, encoding="utf-8")
    return str(path)


def test_agents_test_ok(fixture_dir, agent, capsys):
    path = _config_file(fixture_dir, agent)
    assert cli.main(["--config", path, "agents", "test"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("ok   fake") and "protocol 1" in out and "filecat-agent 0.2.0-test" in out
    assert "host fake-nas (linux/x86_64)" in out and "round trip" in out
    assert cli.main(["--config", path, "agents", "test", "fake", "--json"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["ok"] and info["protocol"] == 1 and info["hostname"] == "fake-nas"
    assert info["roundtrip_ms"] >= 0 and info["connect_ms"] >= 0


def test_agents_test_failures_exit_nonzero(fixture_dir, agent, capsys, monkeypatch):
    path = _config_file(fixture_dir, agent, cert_sha256="00" * 32)
    assert cli.main(["--config", path, "agents", "test"]) == 1
    assert "FAIL fake" in capsys.readouterr().out
    assert cli.main(["--config", path, "agents", "test", "--json"]) == 1
    row = json.loads(capsys.readouterr().out)
    assert row["ok"] is False and row["code"] == "fingerprint"

    path = _config_file(fixture_dir, agent, token="wrong")
    assert cli.main(["--config", path, "agents", "test"]) == 1
    assert "unauthorized" not in capsys.readouterr().err

    monkeypatch.delenv("FC_AGENT_NOPE", raising=False)
    path = _config_file(fixture_dir, agent, token="${FC_AGENT_NOPE}")
    assert cli.main(["--config", path, "agents", "test"]) == 1
    assert "FC_AGENT_NOPE" in capsys.readouterr().out

    agent.stop()
    path = _config_file(fixture_dir, agent)
    assert cli.main(["--config", path, "agents", "test", "--timeout", "2"]) == 1
    assert "FAIL fake" in capsys.readouterr().out


def test_agents_test_protocol_mismatch(fixture_dir, tree, capsys):
    with FakeAgent(tree, protocol=3) as odd:
        assert cli.main(["--config", _config_file(fixture_dir, odd), "agents", "test"]) == 1
    assert "protocol 3" in capsys.readouterr().out


def test_agents_test_names_and_empty(fixture_dir, agent, capsys):
    path = _config_file(fixture_dir, agent)
    assert cli.main(["--config", path, "agents", "test", "nope"]) == 2
    assert "no agent named 'nope'" in capsys.readouterr().err
    empty = fixture_dir / "empty.toml"
    empty.write_text('backend = "sqlite"\n', encoding="utf-8")
    assert cli.main(["--config", str(empty), "agents", "test"]) == 1
    assert cli.main(["--config", str(empty), "agents", "list"]) == 0
    assert "no [[agents]]" in capsys.readouterr().out
    bad = fixture_dir / "bad.toml"
    bad.write_text('[[agents]]\nname = "x"\n', encoding="utf-8")
    assert cli.main(["--config", str(bad), "agents", "list"]) == 2


def test_agents_list(fixture_dir, agent, capsys):
    path = _config_file(fixture_dir, agent, shares={"/volume2/A": "\\\\fake\\A"})
    assert cli.main(["--config", path, "agents", "list"]) == 0
    out = capsys.readouterr().out
    assert "fake  127.0.0.1:" in out and "alias \\\\fake" in out
    assert agent.token not in out and "token       ***" in out
    assert "/volume2/A = \\\\fake\\A" in out
    assert cli.main(["--config", path, "agents", "list", "--json"]) == 0
    row = json.loads(capsys.readouterr().out)
    assert row["name"] == "fake" and row["token"] == "***" and row["shares"] == {"/volume2/A": "\\\\fake\\A"}
