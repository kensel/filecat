"""Files that hold a secret (src/filecat/secretfiles.py, docs/scanning.md section 4): a private key,
a keystore by name and a file the agent will not read are recorded from the directory entry, on
every scan path, with no hash, head, sample or probe. The agent's side (measure and the read
commands), the credential blanking of /usr/syno/etc/iscsi_target.conf, the Windows attribute
rules and the default Windows roots are specified by tests/_fake_agent.py and tested here.
"""
from __future__ import annotations

import base64
import json
import os
import re
import uuid
from pathlib import Path

import pytest

import filecat.scan as scan
from filecat import cloudfiles, rollup, secretfiles
from filecat.agent_client import AgentClient, AgentError
from filecat.backends.memory import MemoryBackend
from filecat.config import AgentConfig
from filecat.identify import Identifier
from filecat.options import ScanOptions
from filecat.topology_collect import AgentSource, RecordedSource, collect
from tests.conftest import FIXTURE_ROOT
from _fake_agent import (FakeAgent, REDACTED, cert_fingerprint, default_windows_roots, private_key_head,
                         redact_credentials)

UNC = "\\\\nas-main\\Backup"
NAS3 = os.path.join(os.path.dirname(__file__), "data", "raw", "nas3")

OPENSSH = (b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA\n"
           b"-----END OPENSSH PRIVATE KEY-----\n")
RSA = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----\n"
PGP = (b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQcYBGRh7bQBEADa\n-----END PGP PRIVATE KEY BLOCK-----\n")
PUTTY = (b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: eddsa-key-20261001\n"
         b"Public-Lines: 2\nAAAAC3NzaC1lZDI1NTE5AAAAIA\nPrivate-Lines: 1\nAAAAIQD\nPrivate-MAC: 0f1e\n")
ENCRYPTED = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkqhkiG9w0BBQ0wQTAp\n-----END ENCRYPTED PRIVATE KEY-----\n"
SSH2 = b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nSubject: me\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n"
BOM_BLANK = b"\xef\xbb\xbf\r\n  \n" + RSA
KEYS = {"id_ed25519": OPENSSH, "server.pem": RSA, "me.asc": PGP, "putty.ppk": PUTTY, "enc.key": ENCRYPTED,
        "ssh2.key": SSH2, "bom.pem": BOM_BLANK}

CERT = b"-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUF\n-----END CERTIFICATE-----\n"
PUBLIC = {
    "cert.crt": CERT,
    "id_ed25519.pub": b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJq9 me@host\n",
    "pub.pem": b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n",
    "pub.asc": b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBGRh\n-----END PGP PUBLIC KEY BLOCK-----\n",
    "csr.pem": b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBVjCBwAIBADAS\n-----END CERTIFICATE REQUEST-----\n",
    "howto.txt": b"Generate one with:\n-----BEGIN RSA PRIVATE KEY-----\nand keep it safe.\n",    # not at the start
    "chain.pem": CERT + RSA,                          # a key after a certificate: only the start is looked at
}
KEYSTORES = {"backup.pfx": os.urandom(300), "old.P12": os.urandom(300), "vault.kdbx": os.urandom(300)}


def _resume_path() -> str:
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    return str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")


def scan_into(root: str, **kwargs):
    backend = MemoryBackend()
    opts = ScanOptions(identify="never", **kwargs)
    code = scan.scan_roots([root], backend, opts, resume_path=_resume_path())
    return code, {d["rel_path"]: d for d in backend.list(root=root)}


def assert_metadata_only(doc: dict, size: int, why: str) -> None:
    assert doc["size"] == size and "mtime_ns" in doc and doc["probe"]["secret"] == why
    assert doc["kind"] == "unknown" and "errors" not in doc
    for field in ("sha256", "sha256_partial", "sample", "sample_id", "encoding", "newlines", "container", "llm"):
        assert field not in doc, field
    assert all(k in ("secret", "identify_basis") or k.startswith("mime_glob") for k in doc["probe"])   # the name layer only


def put_files(base, files: dict[str, bytes]) -> None:
    base.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (base / name).write_bytes(data)


# --- the signatures --------------------------------------------------------------------------
@pytest.mark.parametrize("name,data", sorted(KEYS.items()))
def test_private_key_heads_are_recognised(name, data):
    assert secretfiles.private_key_in(data[:8192]) and private_key_head(data[:8192])    # Python and the agent's rule


@pytest.mark.parametrize("name,data", sorted(PUBLIC.items()))
def test_public_keys_certificates_and_mentions_are_not(name, data):
    assert not secretfiles.private_key_in(data[:8192]) and not private_key_head(data[:8192])


def test_the_signature_window_and_the_start_of_the_file():
    assert not secretfiles.private_key_in(b"x\n" + RSA)                     # something else comes first
    assert not secretfiles.private_key_in(b" " * 300 + RSA)                 # past the window
    assert secretfiles.private_key_in(b"\t \r\n" + RSA)
    assert not secretfiles.private_key_in(b"-----BEGIN RSA PRIVATE KEY")    # no closing dashes on the line
    assert not secretfiles.private_key_in(b"")
    assert secretfiles.keystore_name("A.PFX") and secretfiles.keystore_name("x.kdbx") and not secretfiles.keystore_name("pfx")


# --- local and SMB scans (the path is read directly) -----------------------------------------
def test_a_local_scan_records_keys_and_keystores_without_reading_them(fixture_dir, monkeypatch):
    base = fixture_dir / "tree"
    put_files(base, {**KEYS, **PUBLIC, **KEYSTORES})
    hashed: list[str] = []
    real_hash = scan.hash_file
    monkeypatch.setattr(scan, "hash_file", lambda path, *a, **k: hashed.append(os.path.basename(path)) or real_hash(path, *a, **k))
    code, docs = scan_into(str(base))
    assert code == 0
    for name, data in KEYS.items():
        assert_metadata_only(docs[name], len(data), "private_key")
    for name, data in KEYSTORES.items():
        assert_metadata_only(docs[name], len(data), "keystore")
    for name in PUBLIC:
        assert "sha256" in docs[name] and "secret" not in (docs[name].get("probe") or {}), name
    assert docs["id_ed25519.pub"]["kind"] == "text" and (docs["id_ed25519.pub"].get("sample") or docs["id_ed25519.pub"].get("sample_id"))
    assert not set(hashed) & (set(KEYS) | set(KEYSTORES)) and set(PUBLIC) <= set(hashed)


def test_hash_full_still_does_not_hash_a_key(fixture_dir):
    base = fixture_dir / "tree"
    put_files(base, {"id_rsa": RSA})
    _, docs = scan_into(str(base), hash="full")
    assert_metadata_only(docs["id_rsa"], len(RSA), "private_key")


def test_a_rescan_and_enrich_keep_the_record_metadata_only(fixture_dir):
    from filecat import enrich
    base = fixture_dir / "tree"
    put_files(base, {"id_rsa": RSA})
    opts = ScanOptions(identify="never")
    _, docs = scan_into(str(base))
    st = os.stat(base / "id_rsa")
    new = scan.measure_file(str(base), "id_rsa", str(base / "id_rsa"), st, opts, Identifier(opts))   # what enrich calls
    assert_metadata_only(enrich.merge_measured(docs["id_rsa"], new), len(RSA), "private_key")


def test_ollama_never_selects_a_secret(fixture_dir):
    from filecat import ollama
    backend = MemoryBackend()
    doc = {"root": "r", "root_id": "r", "rel_path": "k", "name": "k", "size": 10, "kind": "unknown",
           "sample": "text", "probe": {"secret": "private_key"}}
    backend.put(doc)
    assert ollama.select_candidates(backend, ScanOptions(ollama=True)) == []


# --- agent scans -----------------------------------------------------------------------------
@pytest.fixture
def served(fixture_dir):
    nas = fixture_dir / "nas"
    share = nas / "volume1" / "Backup"
    put_files(share, {**KEYS, **PUBLIC, **KEYSTORES, ".env": b"DB_PASSWORD=hunter2\n",
                      ".env.production": b"TOKEN=abc\n", ".env.example": b"DB_PASSWORD=\n"})
    with FakeAgent(nas) as agent:
        yield agent, share


def config_for(agent: FakeAgent) -> AgentConfig:
    return AgentConfig(name="nas-main", host="127.0.0.1", port=agent.port, cert_sha256=cert_fingerprint(),
                       token=agent.token, alias="\\\\nas-main", timeout=5)


def client(agent) -> AgentClient:
    return AgentClient("127.0.0.1", agent.port, cert_fingerprint(), agent.token, timeout=5, io_timeout=20)


@pytest.mark.parametrize("hash_policy", ["auto", "none"])
def test_an_agent_scan_records_keys_keystores_and_denied_files_without_content(served, hash_policy):
    agent, share = served
    code, docs = scan_into(UNC, agents=[config_for(agent)], hash=hash_policy)
    assert code == 0                                              # a refused read is not a scan error
    for name, data in KEYS.items():
        assert_metadata_only(docs[name], len(data), "private_key")
    for name, data in KEYSTORES.items():
        assert_metadata_only(docs[name], len(data), "keystore")
    assert_metadata_only(docs[".env"], len(b"DB_PASSWORD=hunter2\n"), "denied")
    assert_metadata_only(docs[".env.production"], len(b"TOKEN=abc\n"), "denied")
    assert docs[".env"]["mtime_ns"] and docs[".env"]["allocated_size"] >= 0
    if hash_policy == "auto":
        for name in list(PUBLIC) + [".env.example"]:
            assert "sha256" in docs[name] and "secret" not in (docs[name].get("probe") or {}), name
    # what the agent put on the wire has no head and no digest of a key, and a keystore is never asked about
    measured = {r["path"].rsplit("/", 1)[-1] for r in agent.requests if r["cmd"] == "measure"}
    assert not measured & set(KEYSTORES)
    out = " ".join(line for way, line in agent.wire if way == "out")
    assert "b3BlbnNzaC1r" not in out and "MIIEowIBAAKC" not in out and "hunter2" not in out


def test_the_agent_reports_a_key_as_unread_and_refuses_to_serve_it(served):
    agent, _ = served
    with client(agent) as c:
        for name, data in KEYS.items():
            m = c.measure(f"/volume1/Backup/{name}")
            assert m.unread == "private_key" and m.head == b"" and m.hashes == {} and m.size == len(data)
            for call in (lambda: c.read_file(f"/volume1/Backup/{name}"),
                         lambda: c.read_range(f"/volume1/Backup/{name}", 0, 16),
                         lambda: c.read_range(f"/volume1/Backup/{name}", 64, 16)):      # not only the start
                with pytest.raises(AgentError) as err:
                    call()
                assert err.value.code == "refused" and str(err.value) == f"/volume1/Backup/{name}: denied by agent policy"
        for name in PUBLIC:
            m = c.measure(f"/volume1/Backup/{name}")
            assert m.unread is None and m.hashes and m.head
            assert c.read_file(f"/volume1/Backup/{name}").data and c.read_range(f"/volume1/Backup/{name}", 0, 8)
        # still listed, with its size
        sizes = {e.name: e.size for e in c.list_dir("/volume1/Backup").entries}
        assert sizes["id_ed25519"] == len(OPENSSH)


# --- the agent blanks CHAP credentials -------------------------------------------------------
def test_the_agent_serves_the_target_file_with_credentials_blanked(fixture_dir):
    root = fixture_dir / "served"
    f = root / "usr" / "syno" / "etc" / "iscsi_target.conf"
    f.parent.mkdir(parents=True)
    raw = ("[iSCSI_T1]\ntid=1\nname=PVEC\nusername=chapuser\npassword=hunter2hunter2\nmutual=no\n"
           "mutual_username=peer\nmutual_password=s3cret\r\nmutual_password_x=keep\npassword=\n").encode()
    f.write_bytes(raw)
    with FakeAgent(root) as agent, client(agent) as c:
        served = c.read_file("/usr/syno/etc/iscsi_target.conf").data
        marker = REDACTED
        assert served == (b"[iSCSI_T1]\ntid=1\nname=PVEC\nusername=" + marker + b"\npassword=" + marker +
                          b"\nmutual=no\nmutual_username=" + marker + b"\nmutual_password=" + marker +
                          b"\r\nmutual_password_x=keep\npassword=" + marker + b"\n")
        assert b"hunter2" not in served and b"chapuser" not in served and b"s3cret" not in served
        assert len(served) != len(raw)                  # the size differs from the file's on disk
        assert c.list_dir("/usr/syno/etc").entries[0].size == len(raw)
        for call in (lambda: c.read_range("/usr/syno/etc/iscsi_target.conf", 0, 64),
                     lambda: c.measure("/usr/syno/etc/iscsi_target.conf")):
            with pytest.raises(AgentError) as err:      # only read_file, which serves the blanked text
                call()
            assert err.value.code == "refused"
        # other files in that folder are served as they are
        (f.parent / "iscsi_lun.conf").write_bytes(b"password=not-in-the-table\n")
        assert c.read_file("/usr/syno/etc/iscsi_lun.conf").data == b"password=not-in-the-table\n"


def test_redact_credentials_leaves_other_lines_alone():
    keys = (b"password",)
    assert redact_credentials(b"a=1\n password = x\nb", keys) == b"a=1\n password =" + REDACTED + b"\nb"
    assert redact_credentials(b"no keys here", keys) == b"no keys here"


def test_the_collector_over_a_redacted_target_file_has_no_credentials(fixture_dir):
    committed = open(os.path.join(NAS3, "files", "usr", "syno", "etc", "iscsi_target.conf"), "rb").read()
    for key in (b"username", b"password", b"mutual_username", b"mutual_password"):
        assert re.search(rb"(^|\n)" + key + b"=" + re.escape(REDACTED) + rb"\r?\n", committed)
    root = fixture_dir / "served"
    root.mkdir()
    with FakeAgent(root) as agent:
        agent.load_recording(Path(NAS3))
        # the host's real file has secrets; the agent blanks them before the collector sees the text
        target = root / "usr" / "syno" / "etc" / "iscsi_target.conf"
        target.write_bytes(committed.replace(REDACTED, b"CANARY-CHAP-SECRET"))
        with client(agent) as c:
            t = collect(AgentSource(c), "synology", name="nas3", unc_server="\\\\nas3", now="2026-10-22T09:00:00Z")
        sent = b"".join(base64.b64decode(json.loads(line).get("data_b64") or "") for way, line in agent.wire
                        if way == "out" and line.startswith("{"))
    assert b"CANARY" not in sent and REDACTED in sent                       # nothing secret on the wire
    assert "CANARY" not in json.dumps(t.to_dict()) and "filecat-redacted" not in json.dumps(t.to_dict())
    recorded = collect(RecordedSource(Path(NAS3)), unc_server="\\\\nas3", now="2026-10-22T09:00:00Z")
    assert t.to_dict() == recorded.to_dict() and any(n.target for n in t.of_type("lun"))


# --- Windows: cloud placeholders and the default roots ---------------------------------------
def test_an_agent_never_opens_a_cloud_placeholder_and_lists_the_attribute_bits(fixture_dir):
    nas = fixture_dir / "win"
    share = nas / "volume1" / "Backup"
    put_files(share, {"online.docx": b"x" * 50, "pinned.docx": b"y" * 40, "local.txt": b"hello\n", "gone.bin": b"z" * 30})
    base = "/volume1/Backup/"
    attrs = {base + "online.docx": 0x20 | cloudfiles.RECALL_ON_DATA_ACCESS, base + "gone.bin": cloudfiles.OFFLINE,
             base + "pinned.docx": 0x20 | cloudfiles.PINNED}
    with FakeAgent(nas) as agent:
        agent.windows_attributes = attrs
        with client(agent) as c:
            listing = {e.name: e for e in c.list_dir("/volume1/Backup").entries}
            assert listing["online.docx"].attributes & cloudfiles.RECALL_ON_DATA_ACCESS
            assert listing["local.txt"].attributes == 0x20
            m = c.measure("/volume1/Backup/online.docx")
            assert (m.unread, m.size, m.head, m.hashes) == ("cloud_placeholder", 50, b"", {})
            assert m.attributes & cloudfiles.RECALL_ON_DATA_ACCESS
            assert c.measure("/volume1/Backup/gone.bin").unread == "cloud_placeholder"
            assert c.measure("/volume1/Backup/pinned.docx").unread is None          # pinned: on the device, readable
            for call in (lambda: c.read_file("/volume1/Backup/online.docx"), lambda: c.read_range("/volume1/Backup/gone.bin", 0, 4)):
                with pytest.raises(AgentError) as err:
                    call()
                assert err.value.code == "refused" and "cloud placeholder" in str(err.value)
            assert c.read_file("/volume1/Backup/local.txt").data == b"hello\n"
            assert c.sum_subtree("/volume1/Backup").total_files == 4               # counted from lstat, nothing recalled
        # a scan through the agent marks them as a local scan does (probe.cloud), without reading them
        before = len(agent.requests)
        code, docs = scan_into(UNC, agents=[AgentConfig(
            name="nas-main", host="127.0.0.1", port=agent.port, cert_sha256=cert_fingerprint(), token=agent.token,
            alias="\\\\nas-main", timeout=5)])
    assert code == 0
    online, gone = docs["online.docx"], docs["gone.bin"]
    assert online["probe"]["cloud"] == {"provider": None, "state": "online-only"}
    assert gone["probe"]["cloud"]["state"] == "offline"
    assert "sha256" not in online and "sha256_partial" not in online and "sample" not in online
    assert "sha256" in docs["pinned.docx"] and "cloud" not in (docs["pinned.docx"].get("probe") or {})
    assert "sha256" in docs["local.txt"] and "cloud" not in (docs["local.txt"].get("probe") or {})
    measured = {r["path"] for r in agent.requests[before:] if r["cmd"] == "measure"}
    assert "/volume1/Backup/online.docx" not in measured and "/volume1/Backup/gone.bin" not in measured


def test_a_placeholder_the_listing_missed_is_still_recorded_from_the_measure_reply(fixture_dir):
    """The attributes changed between the listing and the measure: the agent's answer decides."""
    nas = fixture_dir / "win"
    put_files(nas / "volume1" / "Backup", {"late.docx": b"x" * 50})
    with FakeAgent(nas) as agent:
        agent.windows_attributes = {}
        agent.attributes_after_list = {"/volume1/Backup/late.docx": cloudfiles.RECALL_ON_DATA_ACCESS | 0x20}
        code, docs = scan_into(UNC, agents=[AgentConfig(
            name="nas-main", host="127.0.0.1", port=agent.port, cert_sha256=cert_fingerprint(), token=agent.token,
            alias="\\\\nas-main", timeout=5)])
    assert code == 0 and docs["late.docx"]["probe"]["cloud"]["state"] == "online-only" and "sha256" not in docs["late.docx"]


def test_windows_default_roots_by_product_type():
    fixed, shares = ["C:\\", "D:\\", "E:\\"], ["C:\\Shares\\Public", "D:\\Data", "F:\\Elsewhere"]
    for server in (2, 3, 0):                    # domain controller, server, unknown
        assert default_windows_roots(server, "C:\\", fixed, shares) == ["D:\\", "E:\\", "C:\\Shares\\Public", "F:\\Elsewhere"]
    assert default_windows_roots(1, "c:\\", fixed, shares) == ["C:\\", "D:\\", "E:\\", "F:\\Elsewhere"]   # a client adds C:\


# --- the deny list stops content, not counting ----------------------------------------------
def test_a_rollup_counts_denied_files_but_never_reads_them(fixture_dir):
    vault = fixture_dir / "tree" / "vault"
    put_files(vault, {".env": b"A=1\n" * 10, "id_rsa": RSA, "notes.txt": b"hello"})
    want_files, want_size = 3, 40 + len(RSA) + 5
    t = rollup.sum_tree(str(vault))
    assert t.total_files == want_files and t.size == want_size            # lstat only
    with FakeAgent(fixture_dir / "tree") as agent, client(agent) as c:
        s = c.sum_subtree("/vault")
        assert (s.total_files, s.total_size) == (want_files, want_size)
        assert not [r for r in agent.requests if r["cmd"] in ("measure", "read_file", "read_range")]
