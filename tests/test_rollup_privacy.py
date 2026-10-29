"""The privacy guarantee of [REDACTED] (docs/rollups.md section 3): the names
of a redacted folder, of what is inside it and of anything derived from them
appear nowhere. A tree with redacted subtrees whose folder, file and
sub-folder names are distinctive tokens is scanned locally and through the
fake agent, redacted by a marker, by a rule, by the sticky store after the
marker was deleted and (agent) by (dev, ino) after a rename, with an
unreadable folder inside so the error path runs. Everything a run leaves
behind is searched for every token, plain, as UTF-16, as base64 (at each of
the three alignments) and with non-UTF-8 bytes in their U+F700 form:

* every table of the backend the scan wrote to (records, dropped, members,
  samples, member sets, root index, treemap snapshots, redactions) through
  its API, and the catalog's files byte by byte
* the resume file
* stdout, stderr (progress, preflight, start lines) and every log record at DEBUG
* the commands that read the catalog: summary, roots, show, dupes, enrich,
  rollups, and the serve API
* the fake agent's wire (every line, both ways), its log and its requests

A redacted folder that a rule names by a wildcard pattern is the one
exception for the configuration itself: the pattern is in filecat.toml by
design, so the rule here is `cfg-*` and the distinctive part is not in it.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import filecat.scan as scan
from filecat import cli, rollup, serve, treemap
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.jsonl_dir import JsonlDirBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from tests.conftest import FIXTURE_ROOT
from tests.test_rollup_match import _Os
from tests.test_rollup_walk import UNC, config, options, write
from _fake_agent import FakeAgent

MARKER = "ZXQ-marker-7f3a"
CFG = "ZXQ-config-9c1d"
STICKY = "ZXQ-sticky-4e2b"
RENAME = "ZXQ-rename-5a6c"
RENAMED = "ZXQ-renamed-8d0f"
RAW_PREFIX = "ZXQ-raw-"
DENIED = "ZXQ-denied-dir"
FOLDERS = (MARKER, CFG, STICKY, RENAME, RENAMED)


def needles(token: str | bytes) -> list[bytes]:
    """The token plain, UTF-16, and its base64 at each alignment."""
    raw = token if isinstance(token, bytes) else token.encode("utf-8")
    out = [raw, raw.decode("utf-8", "surrogateescape").encode("utf-16-le", "surrogatepass")]
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + raw)
        out.append(enc[-(-8 * k // 6):(8 * (k + len(raw))) // 6])
    return out


def all_needles(tokens: list[str]) -> list[tuple[str, bytes]]:
    return [(t, n) for t in tokens for n in needles(t)]


def fill(folder: Path, tag: str, n: int = 2) -> list[str]:
    """Files, sub-folders and a locked sub-folder inside a redacted folder;
    returns the names created."""
    names = []
    for i in range(n):
        f = f"ZXQ-file-{tag}-{i}.zxqext{i}"
        s = f"ZXQ-sub-{tag}-{i}"
        write(folder / f, b"secret body %d" % i)
        write(folder / s / f"ZXQ-inner-{tag}-{i}.txt", b"deep secret")
        names += [f, s, f"ZXQ-inner-{tag}-{i}.txt"]
    (folder / DENIED).mkdir()
    write(folder / DENIED / f"ZXQ-locked-{tag}.bin", b"locked")
    return names + [DENIED, f"ZXQ-locked-{tag}.bin"]


def tree(root: Path, agent_names: bool = False) -> list[str]:
    """The tree, and every name in it that must not appear."""
    tokens = list(FOLDERS) + [f"cfg-{CFG}"]
    write(root / "open" / "readme.txt", b"public")
    write(root / "open" / "ZXQ-visible-ok.txt", b"visible")
    for folder, tag in ((MARKER, "m"), (f"cfg-{CFG}", "c"), (STICKY, "s")):
        tokens += fill(root / folder, tag)
    write(root / MARKER / ".filecat-redacted")
    write(root / STICKY / ".filecat-redacted")
    if agent_names:
        tokens += fill(root / RENAME, "r")
        write(root / RENAME / ".filecat-redacted")
        (root / (RAW_PREFIX + "x")).mkdir()
        write(root / (RAW_PREFIX + "x") / "ZXQ-raw-inside.bin", b"raw")
        write(root / (RAW_PREFIX + "x") / ".filecat-redacted")
        tokens += [RAW_PREFIX, "ZXQ-raw-inside.bin"]
    return tokens


def file_backend(kind: str, folder: Path):
    if kind == "memory":
        return MemoryBackend()
    if kind == "sqlite":
        return SqliteBackend(str(folder / "c.sqlite"))
    if kind == "jsonl":
        return JsonlBackend(str(folder / "c.jsonl"))
    return JsonlDirBackend(str(folder / "c-dir"))


def dump(backend, folder: Path) -> bytes:
    """Everything the backend holds, through its API, and its files as bytes."""
    backend.flush()
    parts: list[str] = []

    def add(rows):
        parts.extend(json.dumps(r, default=str, ensure_ascii=False) for r in rows)

    add(backend.list())
    for fn in (backend.list_dropped, backend.iter_all_members, backend.iter_samples,
               backend.iter_member_sets, backend.list_root_info, backend.list_programs):
        try:
            add(fn())
        except NotImplementedError:
            pass
    try:
        for meta in backend.list_treemaps():
            add([meta, backend.get_treemap(meta["id"])[1]])
    except NotImplementedError:
        pass
    add(backend.redactions())
    blob = "\n".join(parts).encode("utf-8", "surrogatepass")
    for p in sorted(folder.rglob("*")):
        if p.is_file() and p.name != "redact.key":
            blob += b"\n" + p.read_bytes()
    return blob


def assert_absent(haystacks: dict[str, bytes], tokens: list[str]) -> None:
    for where, blob in haystacks.items():
        for token, needle in all_needles(tokens):
            assert needle not in blob, f"{token!r} ({needle!r}) found in {where}"


@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.DEBUG)
    return caplog


def cli_output(capsys, argv) -> str:
    capsys.readouterr()
    cli.main(argv)
    out, err = capsys.readouterr()
    return out + err


def run_commands(capsys, base: list[str], root: str, rel_for_show: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for name, argv in (("summary", ["summary", "--root", root]),
                       ("summary dir", ["summary", "--root", root, "--by", "dir", "--depth", "3"]),
                       ("roots", ["roots"]), ("roots json", ["roots", "--json"]),
                       ("show", ["show", rel_for_show, "--root", root]),
                       ("dupes", ["dupes", "--root", root]),
                       ("enrich", ["enrich", "--root", root, "--what", "names", "--limit", "1000"]),
                       ("rollups list", ["rollups", "list"]), ("rollups suggest", ["rollups", "suggest"]),
                       ("rollups redacted", ["rollups", "redacted", "list"]),
                       ("rollups list json", ["rollups", "list", "--json"]),
                       ("rollups rules", ["rollups", "rules"])):
        argv = argv + (base if argv[0] not in ("rollups",) or argv[1] != "rules" else [])
        out[name] = cli_output(capsys, argv).encode("utf-8", "surrogatepass")
    return out


def serve_output(db: str, root: str) -> dict[str, bytes]:
    args = SimpleNamespace(backend="sqlite", out=db, dsn=None, quiet=True, no_save=False)
    catalog = serve.Catalog(args)
    out: dict[str, bytes] = {}
    try:
        calls = {"info": ({},), "roots": ({},), "summary": ({"root": root, "depth": "3"},),
                 "records": ({"root": root, "limit": "500", "sort": "rel_path"},),
                 "records folders": ({"root": root, "parent": "", "limit": "500"},),
                 "records rollup": ({"root": root, "kind": "rollup"},),
                 "rollups": ({},), "rollups by root": ({"root": root},),
                 "rollups by tag": ({"root": root, "tag": "[REDACTED]"},), "topology": ({},),
                 "subtree": ({"root": root, "parent": ""},),
                 "treemap": ({"root": root, "prefix": "", "depth": "3"},),
                 # file-name search: everything, by pattern, by extension, the rollups, by host
                 "search all": ({"q": "*", "limit": "1000"},),
                 "search token": ({"q": "ZXQ", "limit": "1000"},),
                 "search ext": ({"q": "ext:zxqext0;zxqext1 size:>0", "limit": "1000"},),
                 "search rollup": ({"q": "REDACTED", "root": root, "kind": "rollup"},),
                 "search dirs": ({"q": "kind:dir", "limit": "1000", "sort": "rel_path"},)}
        for name, (params,) in calls.items():
            fn = getattr(catalog, name.split()[0])
            if name == "search all":        # the control: a search for everything lists the visible names
                assert any(r["name"] == "ZXQ-visible-ok.txt" for r in fn(params)["rows"])
            out["serve " + name] = json.dumps(fn(params), default=str).encode("utf-8", "surrogatepass")
    finally:
        catalog.close()
    return out


@pytest.mark.parametrize("kind", ["memory", "sqlite", "jsonl", "jsonl_dir"])
def test_a_local_scan_leaves_no_name_of_a_redacted_folder_anywhere(kind, fixture_dir, capsys, logs, monkeypatch):
    root = fixture_dir / "share"
    tokens = tree(root)
    cfg = config(rules=[{"tag": "[REDACTED]", "match": ["cfg-*"]}])
    real = os.scandir

    def scandir(path):                          # the unreadable folder, with its name in the message
        if os.path.basename(str(path)) == DENIED:
            raise PermissionError(13, f"Access is denied: {path}", str(path))
        return real(path)

    monkeypatch.setattr(rollup, "os", _Os(scandir))
    resume = str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")
    store = fixture_dir / "store"
    store.mkdir()
    backend = file_backend(kind, store)
    code = scan.scan_roots([str(root)], backend, options(cfg, progress_interval=0), resume_path=resume)
    assert code == 0
    docs = {d["rel_path"]: d for d in backend.list(root=str(root))}
    assert docs["[REDACTED]"]["probe"]["rollup"]["matched"] == 3
    assert docs["[REDACTED]"]["probe"]["rollup"]["error_codes"] == {"permission_denied": 3}
    assert "open/ZXQ-visible-ok.txt" in docs           # the token filter finds the visible name; see below
    visible = ["ZXQ-visible-ok.txt"]
    # the marker of STICKY goes; the config and a rescan
    os.remove(root / STICKY / ".filecat-redacted")
    code = scan.scan_roots([str(root)], backend, options(cfg, progress_interval=0), resume_path=resume)
    assert code == 0
    docs = {d["rel_path"]: d for d in backend.list(root=str(root))}
    assert docs["[REDACTED]"]["probe"]["rollup"]["matched"] == 3       # still redacted by its path hash
    assert len(backend.redactions(str(root))) == 3
    # the rollup of a different tag, an unreadable root of its own: the failure path
    assert docs["[REDACTED]"]["probe"]["rollup"]["rule"] in ("user:0", "marker:[REDACTED]", "sticky")
    backend.close()

    out, err = capsys.readouterr()
    haystacks = {"stdout": out.encode(), "stderr": err.encode(),
                 "log": "\n".join(r.getMessage() + " " + str(r.args) for r in logs.records).encode(),
                 "resume": Path(resume).read_bytes() if os.path.exists(resume) else b""}
    reopened = file_backend(kind, store)
    haystacks["backend"] = dump(reopened, store)
    reopened.close()
    if kind in ("sqlite", "jsonl", "jsonl_dir"):
        base = ["--backend", "jsonl" if kind.startswith("jsonl") else "sqlite", "--out",
                str({"sqlite": store / "c.sqlite", "jsonl": store / "c.jsonl", "jsonl_dir": store / "c-dir"}[kind])]
        haystacks.update(run_commands(capsys, base, str(root), "open/readme.txt"))
        if kind == "sqlite":
            haystacks.update(serve_output(base[3], str(root)))
            reopened = file_backend(kind, store)
            haystacks["backend after serve"] = dump(reopened, store)
            reopened.close()
    haystacks["log after"] = "\n".join(r.getMessage() + " " + str(r.args) for r in logs.records).encode()
    assert_absent(haystacks, tokens)
    # control: a visible name is found where it should be, so the search works
    assert any(visible[0].encode() in blob for blob in haystacks.values())
    # the key file never carries a name either, and is not in the catalog's folder
    assert not (store / "redact.key").exists()


def test_an_exception_while_summing_leaves_no_name(fixture_dir, capsys, logs, monkeypatch):
    root = fixture_dir / "share"
    tokens = tree(root)
    cfg = config(rules=[{"tag": "[REDACTED]", "match": ["cfg-*"]}])

    def boom(path):
        if os.path.basename(str(path)) == DENIED:
            raise ValueError(f"cannot handle {path}")
        return os.scandir(path)

    monkeypatch.setattr(rollup, "os", _Os(boom))
    backend = MemoryBackend()
    code = scan.scan_roots([str(root)], backend, options(cfg), resume_path=str(FIXTURE_ROOT / f"r-{uuid.uuid4().hex}"))
    assert code == 1
    out, err = capsys.readouterr()
    docs = {d["rel_path"]: d for d in backend.list(root=str(root))}
    assert any(e["message"] == "a rollup could not be summed" for e in docs[""]["errors"])
    info = backend.get_root_info(str(root))
    assert info["last_error"]["stage"] == "rollup" and info["last_error"]["message"] == "a rollup could not be summed"
    blob = dump(backend, fixture_dir / "none")
    assert_absent({"stdout": out.encode(), "stderr": err.encode(), "backend": blob,
                   "log": "\n".join(r.getMessage() + " " + str(r.args) for r in logs.records).encode()}, tokens)


def agent_tree(nas: Path) -> tuple[Path, list[str]]:
    share = nas / "volume1" / "Backup"
    return share, tree(share, agent_names=True)


@pytest.mark.parametrize("kind", ["memory", "sqlite", "jsonl", "jsonl_dir"])
def test_an_agent_scan_leaves_no_name_on_the_wire_or_anywhere(kind, fixture_dir, capsys, logs):
    nas = fixture_dir / "nas"
    share, tokens = agent_tree(nas)
    cfg = config(rules=[{"tag": "[REDACTED]", "match": ["//nas-main/Backup/cfg-*"]}])
    resume = str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")
    store = fixture_dir / "store"
    store.mkdir()
    raw = b"ZXQ-raw-\xfe\xff"
    with FakeAgent(nas) as fake:
        fake.served_as[RAW_PREFIX + "x"] = raw
        fake.unreadable = {DENIED}
        backend = file_backend(kind, store)
        code = scan.scan_roots([UNC], backend, options(cfg, fake, progress_interval=0), resume_path=resume)
        assert code == 0
        docs = {d["rel_path"]: d for d in backend.list(root=UNC)}
        assert docs["[REDACTED]"]["probe"]["rollup"]["matched"] == 5
        assert docs["[REDACTED]"]["probe"]["rollup"]["error_codes"] == {"permission_denied": 4}
        assert len(backend.redactions(UNC)) == 5
        # the marker of STICKY goes, RENAME is renamed on the NAS: still redacted (hash; inode)
        os.remove(share / STICKY / ".filecat-redacted")
        os.remove(share / RENAME / ".filecat-redacted")
        os.rename(share / RENAME, share / RENAMED)
        code = scan.scan_roots([UNC], backend, options(cfg, fake, progress_interval=0), resume_path=resume)
        assert code == 0
        docs = {d["rel_path"]: d for d in backend.list(root=UNC)}
        assert docs["[REDACTED]"]["probe"]["rollup"]["matched"] == 5
        assert len(backend.redactions(UNC)) == 5        # the renamed folder is the same entry
        backend.close()
        sent = "\n".join(f"{way} {line}" for way, line in fake.wire)
        requests = json.dumps(fake.requests)
        agent_log = "\n".join(fake.log)
        marker_listing = [r for r in fake.requests if r["cmd"] == "list_dir"
                          and any(t in json.dumps(r) for t in (MARKER, STICKY, RENAME, RENAMED, RAW_PREFIX))]
        assert not marker_listing       # a redacted folder is never listed, let alone its contents
    out, err = capsys.readouterr()
    cfg_pattern_lines = [ln for ln in sent.splitlines() if "cfg-*" in ln]
    assert cfg_pattern_lines            # the configured pattern did cross, wildcard and all
    haystacks = {"stdout": out.encode(), "stderr": err.encode(), "wire": sent.encode("utf-8", "surrogatepass"),
                 "requests": requests.encode(), "agent log": agent_log.encode(),
                 "log": "\n".join(r.getMessage() + " " + str(r.args) for r in logs.records).encode(),
                 "resume": Path(resume).read_bytes() if os.path.exists(resume) else b""}
    reopened = file_backend(kind, store)
    haystacks["backend"] = dump(reopened, store)
    reopened.close()
    if kind == "sqlite":
        base = ["--backend", "sqlite", "--out", str(store / "c.sqlite")]
        haystacks.update(run_commands(capsys, base, UNC, "open/readme.txt"))
        haystacks.update(serve_output(base[3], UNC))
    assert_absent(haystacks, tokens + [RAW_PREFIX + ""])
    assert b"ZXQ-visible-ok.txt" in haystacks["wire"]       # control: visible names do cross the wire


def test_a_sticky_entry_stores_no_name_and_the_listing_shows_none(fixture_dir, capsys):
    root = fixture_dir / "share"
    tokens = tree(root)
    backend, docs, _ = None, None, None
    backend = MemoryBackend()
    scan.scan_roots([str(root)], backend, options(), resume_path=str(FIXTURE_ROOT / f"r-{uuid.uuid4().hex}"))
    entries = backend.redactions(str(root))
    assert len(entries) == 2
    for e in entries:
        assert set(e) == {"id", "root_id", "root", "parent", "path_hash", "status", "source", "created",
                          "last_seen", "key_id"}
        assert_absent({"entry": json.dumps(e).encode()}, tokens)
    out = cli_output(capsys, ["rollups", "redacted", "list", "--backend", "jsonl", "--out", str(fixture_dir / "x.jsonl")])
    assert "(no sticky redactions)" in out


# --- already cataloged names are purged ------------------------------------------------
def test_adding_a_rule_purges_what_the_catalog_already_holds(fixture_dir, capsys, logs):
    root = fixture_dir / "share"
    secret = root / f"cfg-{CFG}"
    write(secret / "ZXQ-note.txt", ("secret words " * 20).encode())
    write(secret / "ZXQ-gone.txt", b"will vanish")
    write(secret / "ZXQ-sub" / "ZXQ-pack.zip", _zip(["ZXQ-member-a.txt", "ZXQ-dir/ZXQ-member-b.txt"]))
    write(root / "open" / "ok.txt", b"fine")
    tokens = [f"cfg-{CFG}", "ZXQ-note.txt", "ZXQ-gone.txt", "ZXQ-sub", "ZXQ-pack.zip", "ZXQ-member-a.txt",
              "ZXQ-member-b.txt", "secret words"]
    (fixture_dir / "store").mkdir()
    db = str(fixture_dir / "store" / "c.sqlite")
    resume = str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")
    backend = SqliteBackend(db)
    opts = dict(identify="never")
    scan.scan_roots([str(root)], backend, options(**opts), resume_path=resume)
    docs = {d["rel_path"]: d for d in backend.list(root=str(root))}
    assert f"cfg-{CFG}/ZXQ-note.txt" in docs
    # the names are all over the catalog: records, a sample, members, and (after a delete) the dropped store
    before = dump(backend, fixture_dir / "store")
    assert b"ZXQ-member-a.txt" in before and b"secret words" in before
    os.remove(secret / "ZXQ-gone.txt")
    scan.scan_roots([str(root)], backend, options(**opts), resume_path=resume)
    assert any("ZXQ-gone.txt" in d["rel_path"] for d in backend.list_dropped(str(root)))
    # a treemap snapshot of the folder, pinned, and a root-index entry that names a file in it
    data = treemap.build(backend.sizes(str(root), ""), "", 4)
    meta = treemap.save(backend, str(root), data, "2026-10-23T00:00:00+00:00")
    treemap.pin(backend, [meta["id"]], "before", "2026-10-23T01:00:00+00:00")
    unpinned = treemap.save(backend, str(root), treemap.build(backend.sizes(str(root), ""), "", 1),
                            "2026-10-23T02:00:00+00:00")
    info = backend.get_root_info(str(root))
    info["last_error"] = {"at": "t", "rel_path": f"cfg-{CFG}/ZXQ-note.txt", "stage": "read", "message": "x"}
    backend.put_root_info(info)
    assert b"ZXQ-note.txt" in dump(backend, fixture_dir / "store")

    cfg = config(rules=[{"tag": "[REDACTED]", "match": ["cfg-*"]}])
    scan.scan_roots([str(root)], backend, options(cfg), resume_path=resume)
    docs = {d["rel_path"]: d for d in backend.list(root=str(root))}
    assert docs["[REDACTED]"]["probe"]["rollup"]["total_files"] == 2
    assert not [r for r in docs if r.startswith(f"cfg-{CFG}")]
    assert not [d for d in backend.list_dropped(str(root)) if "ZXQ" in d["rel_path"]]
    assert backend.get_treemap(unpinned["id"]) is None          # an unpinned snapshot is simply gone
    pinned_data = backend.get_treemap(meta["id"])[1]
    assert any(f["path"].endswith("[REDACTED]") for f in pinned_data["folders"])
    assert backend.get_root_info(str(root)).get("last_error") is None
    assert backend.prune_samples() == 0 and backend.prune_member_sets() == 0     # nothing left to prune
    out, err = capsys.readouterr()
    haystacks = {"after": dump(backend, fixture_dir / "store"), "stderr": err.encode(), "stdout": out.encode(),
                 "resume": Path(resume).read_bytes() if os.path.exists(resume) else b""}
    backend.close()
    haystacks["after, reopened"] = dump(SqliteBackend(db), fixture_dir / "store")
    # the before-state really held them (the purge did something)
    assert any(t.encode() in before for t in tokens)
    # the only place left is the first scans' progress lines, which printed the files they measured
    haystacks.pop("stderr")
    assert_absent(haystacks, tokens)


def _zip(names: list[str]) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n in names:
            zf.writestr(n, n * 5)
    return buf.getvalue()


def test_a_marker_in_the_middle_of_a_resumed_scan_forgets_what_the_resume_file_knew(fixture_dir):
    root = fixture_dir / "share"
    write(root / "keep" / "a.txt", b"a")
    write(root / "deep" / "ZXQ-resume-tree" / "inner" / "f.txt", b"f")
    from filecat.resume import ResumeState
    resume_path = str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")
    state = ResumeState(resume_path)
    state.mark_dir_complete(str(root), "deep/ZXQ-resume-tree/inner", 1, 1)
    state.mark_dir_complete(str(root), "deep/ZXQ-resume-tree", 1, 1, child_dirs=["inner"])
    state.flush()
    write(root / "deep" / "ZXQ-resume-tree" / ".filecat-redacted")
    backend = MemoryBackend()
    scan.scan_roots([str(root)], backend, options(), resume_path=resume_path)
    assert b"ZXQ-resume-tree" not in Path(resume_path).read_bytes() if os.path.exists(resume_path) else True


def test_the_unpinned_treemap_snapshots_of_a_root_go_when_a_folder_is_redacted(fixture_dir):
    root = fixture_dir / "share"
    write(root / "vault" / "x.bin", b"1" * 40)
    write(root / "open" / "y.bin", b"2" * 10)
    backend = MemoryBackend()
    scan.scan_roots([str(root)], backend, options(), resume_path=str(FIXTURE_ROOT / f"r-{uuid.uuid4().hex}"))
    meta = treemap.save(backend, str(root), treemap.build(backend.sizes(str(root), ""), "", 2), "2026-10-23T00:00:00+00:00")
    write(root / "vault" / ".filecat-redacted")
    scan.scan_roots([str(root)], backend, options(), resume_path=str(FIXTURE_ROOT / f"r-{uuid.uuid4().hex}"))
    assert backend.get_treemap(meta["id"]) is None
    assert backend.list_treemaps(str(root)) == []


# --- store rollups and `rollups migrate` ---------------------------------------------------
class _Boom(Exception):
    pass


def test_store_rollups_and_a_killed_and_resumed_migration_leave_no_redacted_name(fixture_dir, capsys, logs,
                                                                                tmp_path, monkeypatch):
    from tests.test_hyperbackup import make_hbk
    root = fixture_dir / "share"
    secret = root / f"cfg-{CFG}"
    tokens = [f"cfg-{CFG}"] + fill(secret, "c") + ["ZXQ-note.txt", "ZXQ-pack.zip", "ZXQ-member-a.txt",
                                                    "ZXQ-member-b.txt", "secret words"]
    write(secret / "ZXQ-note.txt", ("secret words " * 20).encode())
    write(secret / "ZXQ-pack.zip", _zip(["ZXQ-member-a.txt", "ZXQ-dir/ZXQ-member-b.txt"]))
    write(root / "open" / "readme.txt", b"public")
    make_hbk(root / "Backup")
    monkeypatch.setenv("FILECAT_REDACT_KEY_FILE", str(tmp_path / "redact.key"))
    toml = tmp_path / "filecat.toml"
    toml.write_text('[rollups]\nbackup = "automatic"\n[[rollups.rule]]\ntag = "[REDACTED]"\nmatch = ["cfg-*"]\n',
                    encoding="utf-8")
    store = fixture_dir / "store"
    store.mkdir()
    db = str(store / "c.sqlite")
    resume = str(FIXTURE_ROOT / f"resume-{uuid.uuid4().hex}.json")
    backend = SqliteBackend(db)
    scan.scan_roots([str(root)], backend, options(identify="never"), resume_path=resume)    # before: no rules
    before = dump(backend, store)
    assert b"ZXQ-member-a.txt" in before and b"secret words" in before
    backend.close()

    monkeypatch.setenv("FILECAT_CONFIG", str(toml))
    base = ["--backend", "sqlite", "--out", db, "--root", str(root)]
    haystacks: dict[str, bytes] = {}
    haystacks["dry run"] = cli_output(capsys, ["rollups", "migrate", "--dry-run", *base]).encode()
    assert "would migrate 2 of 2 targets" in haystacks["dry run"].decode()
    # the process dies in phase 2 of the second target ...
    real = SqliteBackend.delete_many
    calls = [0]

    def dying(self, root_, paths):
        calls[0] += 1
        if calls[0] == 2:
            raise _Boom
        return real(self, root_, paths)

    monkeypatch.setattr(SqliteBackend, "delete_many", dying)
    with pytest.raises(_Boom):
        cli.main(["rollups", "migrate", "--batch", "2", *base])
    monkeypatch.setattr(SqliteBackend, "delete_many", real)
    out, err = capsys.readouterr()
    haystacks["killed stdout"], haystacks["killed stderr"] = out.encode(), err.encode()
    ck = Path(db + ".rollups-migrate.json")
    assert ck.exists()
    haystacks["checkpoint"] = ck.read_bytes()
    # ... and a rerun finishes it
    haystacks["rerun"] = cli_output(capsys, ["rollups", "migrate", "--batch", "2", *base]).encode()
    assert not ck.exists()
    reopened = SqliteBackend(db)
    docs = {d["rel_path"]: d for d in reopened.list(root=str(root))}
    assert docs["[REDACTED]"]["probe"]["rollup"]["migrated"] is True and docs["[REDACTED]"]["size"] > 0
    assert docs["Backup/NAS-LEGACY_1.hbk/[BACKUP]"]["probe"]["rollup"]["migrated"] is True
    assert not [d for d in reopened.list_dropped(str(root)) if "ZXQ" in d["rel_path"]]
    haystacks["after"] = dump(reopened, store)
    reopened.close()
    haystacks["resume"] = Path(resume).read_bytes() if os.path.exists(resume) else b""
    haystacks["log"] = "\n".join(r.getMessage() + " " + str(r.args) for r in logs.records).encode()
    # and a scan over the migrated catalog (store rollup, redaction by rule and sticky entry) adds nothing
    reopened = SqliteBackend(db)
    scan.scan_roots([str(root)], reopened, options(config({"backup": "automatic"},
                    [{"tag": "[REDACTED]", "match": ["cfg-*"]}]), identify="never", progress_interval=0),
                    resume_path=resume)
    reopened.close()
    out, err = capsys.readouterr()
    haystacks["scan stdout"], haystacks["scan stderr"] = out.encode(), err.encode()
    haystacks["after scan"] = dump(SqliteBackend(db), store)
    haystacks.update(run_commands(capsys, base[:4], str(root), "open/readme.txt"))
    assert_absent(haystacks, tokens)
    assert any(t.encode() in before for t in tokens)           # control: they were there before
