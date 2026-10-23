"""A scan through filecat-agent (fsource.py), against the fake agent in
tests/_fake_agent.py: the same tree scanned from disk and through the
agent gives the same records, rescans skip unchanged files, probes read
through the agent, hard links, names that are not UTF-8, unreachable agents,
--no-agent.
"""
from __future__ import annotations

import io
import json
import os
import uuid
import zipfile

import pytest

import filecat.hashing as hashing
import filecat.preflight as preflight_mod
import filecat.scan as scan
import filecat.walker as walker_mod
from filecat import cli, fsource, record
from filecat.backends.memory import MemoryBackend
from filecat.config import AgentConfig, agent_for
from filecat.options import ScanOptions
from filecat.resume import ResumeState
from tests.conftest import FIXTURE_ROOT
from tests.test_probe_pe import _build_pe
from _fake_agent import FakeAgent, cert_fingerprint, floor100

UNC = "\\\\nas-main\\Backup"


def _resume_path() -> str:
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    return str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")


def _zip(names: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n in names:
            zf.writestr(n, n * 20)
    return buf.getvalue()


@pytest.fixture
def tree(fixture_dir):
    nas = fixture_dir / "nas"
    share = nas / "volume1" / "Backup"
    (share / "docs" / "deep").mkdir(parents=True)
    (share / "empty-dir").mkdir()
    (share / "readme.txt").write_text("hello from the nas\nsecond line\n")
    (share / "empty.bin").write_bytes(b"")
    (share / "docs" / "notes.csv").write_text("a,b,c\n1,2,3\n4,5,6\n")
    (share / "docs" / "pack.zip").write_bytes(_zip(["one.txt", "two/three.txt", "data/four.bin"]))
    (share / "docs" / "deep" / "blob.bin").write_bytes(bytes(range(256)) * 300)
    (share / "tiny.exe").write_bytes(_build_pe(linker_major=14, linker_minor=29))
    (share / "big stub.exe").write_bytes(_build_pe(linker_major=11, linker_minor=0, dos_stub_padding=9000))
    return nas


@pytest.fixture
def agent(tree):
    with FakeAgent(tree) as fake:
        yield fake


def config_for(agent: FakeAgent, **kwargs) -> AgentConfig:
    kwargs.setdefault("port", agent.port)
    return AgentConfig(name="nas-main", host="127.0.0.1", cert_sha256=cert_fingerprint(),
                       token=agent.token, alias="\\\\nas-main", timeout=5, **kwargs)


def options(fake: FakeAgent | None = None, **kwargs) -> ScanOptions:
    kwargs.setdefault("identify", "never")
    kwargs.setdefault("agents", [config_for(fake)] if fake else [])
    return ScanOptions(**kwargs)


def scan_into(root: str, opts: ScanOptions, backend: MemoryBackend | None = None,
              recorded: str | None = None) -> tuple[MemoryBackend, dict[str, dict], int]:
    backend = backend or MemoryBackend()
    code = scan.scan_roots([root], backend, opts, resume_path=_resume_path())
    return backend, {d["rel_path"]: d for d in backend.list(root=recorded or root)}, code


def measures(agent: FakeAgent) -> list[str]:
    return [r["path"] for r in agent.requests if r["cmd"] == "measure"]


# fields an agent scan and a local scan must agree on
SAME = ("name", "size", "kind", "suffix", "mtime_ns", "ctime_ns", "sha256", "sha256_partial", "mime",
        "sample", "encoding", "newlines", "container")


def test_agent_scan_matches_local_scan(tree, agent, monkeypatch):
    monkeypatch.setattr(hashing, "PARTIAL_HASH_CUTOFF", 20_000)    # blob.bin (76 800 bytes) is partial
    local_root = str(tree / "volume1" / "Backup")
    _, local, code = scan_into(local_root, options())
    assert code == 0
    _, remote, code = scan_into(UNC, options(agent))
    assert code == 0

    assert set(remote) == set(local) and len(local) > 8
    for rel, want in local.items():
        got = remote[rel]
        assert got["root"] == UNC
        for key in SAME:
            if key == "name" and not rel:
                continue        # the root's name is the root string, as over SMB
            if want["kind"] == "dir" and key in ("mtime_ns", "ctime_ns"):
                continue        # NTFS bumps a folder's times lazily, between the two scans
            if key in ("mtime_ns", "ctime_ns") and key in want:
                assert got.get(key) == floor100(want[key]), (rel, key)
            else:
                assert got.get(key) == want.get(key), (rel, key)
        want_probe = dict(want.get("probe") or {})
        assert (got.get("probe") or {}) == want_probe, rel
        assert got.get("errors") == want.get("errors"), rel
    assert "sha256_partial" in remote["docs/deep/blob.bin"] and "sha256" not in remote["docs/deep/blob.bin"]
    assert "sha256" not in remote["empty.bin"]
    assert remote["empty.bin"]["kind"] == "empty"

    # the zip and the PEs were probed through read_range, with the same members
    assert remote["docs/pack.zip"]["probe"]["entry_count"] == 3
    assert remote["tiny.exe"]["probe"]["pe"]["linker"] == "14.29"
    assert remote["big stub.exe"]["probe"]["pe"]["linker"] == "11.0"
    assert any(r["cmd"] == "read_range" for r in agent.requests)
    assert remote["docs/pack.zip"]["probe"]["entries"] == ["one.txt", "two/three.txt", "data/four.bin"]


def test_agent_records_carry_allocated_size_and_inode(tree, agent):
    _, docs, _ = scan_into(UNC, options(agent))
    doc = docs["readme.txt"]
    assert doc["allocated_size"] == 4096 and doc["ino"] > 0 and doc["nlink"] == 1
    assert "dev" in doc
    # a local scan knows none of them
    _, local, _ = scan_into(str(tree / "volume1" / "Backup"), options())
    assert not {"allocated_size", "ino", "dev", "nlink"} & set(local["readme.txt"])


def test_rescan_through_the_agent_skips_unchanged_files(tree, agent):
    backend, docs, _ = scan_into(UNC, options(agent))
    files = [r for r, d in docs.items() if d["kind"] != "dir"]
    assert len(measures(agent)) == len(files) - 1       # empty.bin: size 0, hash auto: no call

    agent.requests.clear()
    _, again, code = scan_into(UNC, options(agent), backend)
    assert code == 0 and not measures(agent)
    assert not [r for r in agent.requests if r["cmd"] == "read_range"]
    assert set(again) == set(docs)

    # one file changes: only it is measured again
    p = tree / "volume1" / "Backup" / "docs" / "notes.csv"
    p.write_text("a,b,c\n1,2,3\n4,5,6\n7,8,9\n")
    os.utime(p, ns=(p.stat().st_atime_ns, p.stat().st_mtime_ns + 5_000_000_000))
    agent.requests.clear()
    _, again, _ = scan_into(UNC, options(agent), backend)
    assert measures(agent) == ["/volume1/Backup/docs/notes.csv"]
    assert again["docs/notes.csv"]["size"] == p.stat().st_size


def test_force_measures_everything_again(tree, agent):
    backend, docs, _ = scan_into(UNC, options(agent))
    agent.requests.clear()
    scan_into(UNC, options(agent, force=True), backend)
    assert len(measures(agent)) == len([d for d in docs.values() if d["kind"] != "dir"]) - 1


def test_hash_none_still_reads_the_head(tree, agent):
    _, docs, _ = scan_into(UNC, options(agent, hash="none"))
    assert "sha256" not in docs["readme.txt"]
    assert docs["readme.txt"]["kind"] == "text"
    assert {r["hash"] for r in agent.requests if r["cmd"] == "measure"} == {"none"}


def test_hard_links_are_totalled_once(tree, agent):
    share = tree / "volume1" / "Backup"
    os.link(share / "docs" / "deep" / "blob.bin", share / "blob copy.bin")
    backend = MemoryBackend()
    _, docs, _ = scan_into(UNC, options(agent), backend)
    a, b = docs["docs/deep/blob.bin"], docs["blob copy.bin"]
    assert (a["dev"], a["ino"]) == (b["dev"], b["ino"]) and a["nlink"] == b["nlink"] == 2
    assert a["size"] == b["size"] == 76_800

    info = backend.get_root_info(UNC)
    files_bytes = sum(d["size"] for d in docs.values() if d["kind"] != "dir")
    assert info["last_scan"]["bytes"] == files_bytes - 76_800

    # and the progress line's total
    seen: list[int] = []
    scan_roots_progress = walker_mod.walk_root(
        UNC, options(agent), MemoryBackend(), None, ResumeState(_resume_path()),
        lambda root, rel, abs_path, st, opts, ident: record.new_document(
            root, rel, kind="data", size=st.st_size, mtime_ns=st.st_mtime_ns),
        progress=lambda path, size, how: seen.append(size),
        path=UNC, source=fsource.AgentSource(config_for(agent)))
    assert not scan_roots_progress
    assert sum(seen) == files_bytes - 76_800


def test_names_that_are_not_utf8_are_stored_as_private_use_characters(tree, agent):
    share = tree / "volume1" / "Backup"
    (share / "cafe-latin1.txt").write_text("not utf-8 named\n")
    agent.served_as["cafe-latin1.txt"] = b"caf\xe9.txt"
    backend, docs, code = scan_into(UNC, options(agent))
    assert code == 0
    stored = "caf\uf7e9.txt"
    doc = docs[stored]
    assert doc["name"] == stored and doc["suffix"] == "txt"
    assert doc["sha256"] and doc["kind"] == "text" and "errors" not in doc    # measure found it by its bytes
    json.dumps(doc).encode("utf-8")                       # storable
    assert fsource.from_storage(stored) == "caf\udce9.txt"
    # the measure request named the exact bytes
    req = [r for r in agent.requests if r["cmd"] == "measure" and "path_b64" in r]
    assert len(req) == 1


def test_storage_form_roundtrip():
    for raw in (b"plain", b"caf\xe9", b"\x80\xff mixed \xc3\xa9 \xe2"):
        text = raw.decode("utf-8", "surrogateescape")
        stored = fsource.to_storage(text)
        assert len(stored) == len(text)
        stored.encode("utf-8")
        assert fsource.from_storage(stored).encode("utf-8", "surrogateescape") == raw
    assert fsource.to_storage("ünïcode ✓") == "ünïcode ✓"


def test_links_special_files_and_rollups(tree, agent):
    num = {"size": 4, "allocated_size": 0, "ino": 77, "dev": 1, "nlink": 1,
           "mtime_ns": 1_700_000_000_000_000_000, "ctime_ns": 1_700_000_000_000_000_000}
    agent.extras["/volume1/Backup"] = [
        {"name": "shortcut", "kind": "link", "link_target": "docs/notes.csv", **num},
        {"name": "queue.fifo", "kind": "other", **num, "size": 0},
        {"name": "[CACHE]", "kind": "rollup", **num, "rollup": {"tag": "[CACHE]", "matched": 2}},
        {"name": "denied", "kind": "file", "error": {"code": "permission_denied", "message": "no"}},
    ]
    _, docs, code = scan_into(UNC, options(agent))
    assert docs["shortcut"]["kind"] == "link"
    assert docs["shortcut"]["probe"]["link_target"] == "docs/notes.csv"
    assert docs["queue.fifo"]["probe"]["special_file"] is True
    assert docs["[CACHE]"]["kind"] == "rollup"      # the agent's rollup entry is recorded, not listed
    assert docs["[CACHE]"]["probe"]["rollup"]["matched"] == 2
    assert docs["denied"]["errors"][0]["stage"] == "stat" and code == 1
    assert not [p for p in measures(agent) if p.endswith(("shortcut", "queue.fifo"))]
    assert docs[""]["probe"]["child_count"] == len(
        [r for r in docs if r and "/" not in r])


def test_exclude_policy_is_sent_at_start(tree, agent):
    cfg = config_for(agent, exclude=("deep",))
    _, docs, _ = scan_into(UNC, options(agents=[cfg]))
    assert "docs/deep/blob.bin" not in docs and "docs/pack.zip" in docs
    policies = [r["policy"] for r in agent.requests if r["cmd"] == "configure_policy"]
    assert policies and all(p["exclude"] == ["deep"] for p in policies)


def test_each_thread_gets_its_own_connection(tree, agent):
    scan_into(UNC, options(agent))
    # listing threads and workers each connected on their own, none more than once
    assert 1 < agent.connections <= walker_mod.LIST_THREADS + 4 + 2


def test_x3_catalogue_sibling_is_found_through_the_agent(tree, agent):
    share = tree / "volume1" / "Backup"
    raw = ("header line, skipped\n" + "a.dds 10\nb.dds 20\n").encode()
    (share / "01.cat").write_bytes(bytes(b ^ ((0xDB + i) & 0xFF) for i, b in enumerate(raw)))
    (share / "01.dat").write_bytes(bytes(30))
    _, docs, _ = scan_into(UNC, options(agent))
    _, local, _ = scan_into(str(share), options())
    assert docs["01.dat"]["probe"] == local["01.dat"]["probe"]
    assert docs["01.dat"]["probe"]["format"] == "x3-dat"


def test_store_folders_are_detected_but_their_manifest_is_not_read(tree, agent):
    share = tree / "volume1" / "Backup" / "dup"
    share.mkdir()
    stamp = "duplicity-full.20260101T000000Z"
    (share / f"{stamp}.manifest").write_text("Hostname nas\n")
    (share / f"{stamp}.vol1.difftar.gz").write_bytes(b"x" * 100)
    _, docs, _ = scan_into(UNC, options(agent))
    assert docs["dup"]["probe"]["store_note"].startswith("duplicity")
    assert "backup" not in docs["dup"]["probe"]
    assert docs[f"dup/{stamp}.vol1.difftar.gz"]["kind"] == "data"      # listed, never measured
    assert not [p for p in measures(agent) if "difftar" in p]


# --- choosing and reaching the agent -------------------------------------------
def test_pick_follows_the_options(agent):
    opts = options(agent)
    assert fsource.pick(opts, UNC, UNC)[1] == UNC
    assert fsource.pick(opts, "\\\\other\\Share", "\\\\other\\Share") is None
    assert fsource.pick(options(agent, no_agent=True), UNC, UNC) is None
    assert fsource.pick(options(agent, agent="other"), UNC, UNC) is None
    assert fsource.pick(options(agent, agent="nas-main"), UNC, UNC) is not None
    # an alias: read through \\192.0.2.13, recorded as \\nas-main
    picked = fsource.pick(opts, UNC, "\\\\192.0.2.13\\Backup")
    assert picked[1] == UNC
    assert agent_for(opts.agents, "C:\\local") is None


def unreachable_config(agent: FakeAgent) -> AgentConfig:
    agent.stop()
    return config_for(agent)


def test_unreachable_agent_fails_the_root_with_a_message(tree, agent, capsys):
    cfg = unreachable_config(agent)
    backend, docs, code = scan_into(UNC, options(agents=[cfg]))
    assert code == 1
    err = docs[""]["errors"][0]
    assert err["stage"] == "stat"
    assert "filecat-agent nas-main (127.0.0.1:" in err["message"]
    assert set(docs) == {""}
    assert backend.get_root_info(UNC)["last_attempt"]["status"] == "unreachable"
    assert "cannot open" in capsys.readouterr().err        # the preflight said so too


def test_agent_fallback_reads_over_smb(tree, agent, monkeypatch, capsys):
    cfg = unreachable_config(agent)
    smb = []

    def fake_stat(path, *a, **k):
        smb.append(path)
        raise OSError("smb says no")

    monkeypatch.setattr(walker_mod.os, "stat", fake_stat)
    monkeypatch.setattr(preflight_mod, "_open", lambda path: (_ for _ in ()).throw(OSError("smb says no")))
    _, docs, code = scan_into(UNC, options(agents=[cfg], agent_fallback=True))
    assert smb == [UNC] and code == 1
    assert docs[""]["errors"][0]["message"] == "OSError: smb says no"
    assert "reading over SMB" in capsys.readouterr().err


def test_no_agent_never_contacts_the_agent(tree, agent, monkeypatch):
    monkeypatch.setattr(walker_mod.os, "stat", lambda *a, **k: (_ for _ in ()).throw(OSError("smb says no")))
    monkeypatch.setattr(preflight_mod, "_open", lambda path: (_ for _ in ()).throw(OSError("smb says no")))
    _, docs, code = scan_into(UNC, options(agent, no_agent=True))
    assert code == 1 and agent.connections == 0
    assert docs[""]["errors"][0]["message"] == "OSError: smb says no"


def test_progress_and_start_line_say_the_agent_is_used(tree, agent, capsys):
    scan_into(UNC, options(agent, progress_interval=0))
    err = capsys.readouterr().err
    assert "scanning through filecat-agent nas-main (127.0.0.1:" in err
    assert f"{UNC} (filecat-agent nas-main): " in err


# --- the command line ---------------------------------------------------------
def write_config(fixture_dir, agent_port=9876) -> str:
    path = fixture_dir / "filecat.toml"
    path.write_text(f"""
[[agents]]
name = "nas-main"
host = "127.0.0.1"
port = {agent_port}
cert_sha256 = "{cert_fingerprint()}"
token = "s3cret"
alias = '\\\\nas-main'
""", encoding="utf-8")
    return str(path)


def test_cli_agent_flags(fixture_dir, agent, monkeypatch):
    cfg = write_config(fixture_dir, agent.port)
    seen = []
    monkeypatch.setattr(scan, "run", lambda args: seen.append(args) or 0)
    out = str(fixture_dir / "c.sqlite")
    base = ["--config", cfg, "scan", "--backend", "sqlite", "--out", out]
    assert cli.main(base + ["--agent", "nas-main", UNC]) == 0
    assert [a.name for a in seen[-1].agents] == ["nas-main"] and seen[-1].agent == "nas-main"
    assert ScanOptions.from_args(seen[-1]).agent == "nas-main"
    assert cli.main(base + ["--no-agent", UNC]) == 0
    assert seen[-1].agents == [] and ScanOptions.from_args(seen[-1]).no_agent
    assert cli.main(base + ["--agent-fallback", UNC]) == 0
    assert ScanOptions.from_args(seen[-1]).agent_fallback
    assert cli.main(base + ["--agent", "nope", UNC]) == 2
    with pytest.raises(SystemExit):
        cli.main(base + ["--agent", "nas-main", "--no-agent", UNC])


def test_cli_scan_end_to_end(fixture_dir, agent, capsys):
    cfg = write_config(fixture_dir, agent.port)
    out = str(fixture_dir / "c.sqlite")
    assert cli.main(["--config", cfg, "scan", "--backend", "sqlite", "--out", out, "--identify",
                     "never", UNC]) == 0
    assert "scanning through filecat-agent nas-main" in capsys.readouterr().err
    assert measures(agent)


# --- the NAS's spelling of server\\share -------------------------------------
def test_agent_scan_records_the_share_as_the_nas_spells_it(tree, agent, capsys):
    typed = "\\\\NAS-MAIN\\backup"
    backend, docs, code = scan_into(typed, options(agent), recorded=UNC)
    assert code == 0 and len(docs) > 8
    assert backend.roots() == [UNC]                     # not the typed spelling
    assert backend.get_root_info(UNC)["last_scan"]["agent"] == "nas-main"
    assert "case-check" not in capsys.readouterr().err


def test_agent_scan_hints_when_the_catalog_holds_another_spelling(tree, agent, capsys):
    other = "\\\\nas-main\\BACKUP"
    backend = MemoryBackend()
    backend.put(record.new_document(other, "", kind="dir"))
    backend, docs, _ = scan_into(other, options(agent), backend, recorded=UNC)
    err = capsys.readouterr().err
    assert backend.roots() == sorted([other, UNC]) and len(docs) > 8
    assert f"{UNC}: the catalog also holds this share as {other}; see: filecat roots case-check" in err


def test_smb_scan_takes_the_spelling_of_the_agent_scanned_root(tree, agent, capsys):
    backend, _, _ = scan_into(UNC, options(agent))
    local = str(tree / "volume1" / "Backup")
    other = "\\\\nas-main\\backup"
    capsys.readouterr()
    # SMB would read the typed path; here the read is by an alias onto the local copy
    scan.scan_roots([local], backend, options(aliases={local: other}), resume_path=_resume_path())
    assert backend.roots() == [UNC]
    assert "recorded as " + UNC in capsys.readouterr().err
