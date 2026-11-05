"""File-name search (filecat/search.py): the query parser, the pattern translations and
Backend.search_names on every backend that runs here (memory, SQLite, JSONL, JSONL directory);
PostgreSQL, MySQL, SQL Server and MongoDB run when their FILECAT_TEST_* DSN is set, like the
backend contract tests. Plus Catalog.search (/api/search) on a SQLite catalog."""
from __future__ import annotations

import os
import re
from types import SimpleNamespace

import pytest

from filecat import search, serve
from filecat.backends.jsonl import JsonlBackend
from filecat.backends.jsonl_dir import JsonlDirBackend
from filecat.backends.memory import MemoryBackend
from filecat.backends.sqlite import SqliteBackend
from filecat.record import root_id

NAS = r"\\nas-main\homes"
OLD = r"\\nas-old\backup"
LOCAL = "/data/local"
DAY = 86_400 * 1_000_000_000
T2024 = 1_704_067_200 * 1_000_000_000          # 2024-01-01T00:00:00Z


def doc(root, rel, size=10, kind="file", mtime=T2024, **extra):
    name = rel.rsplit("/", 1)[-1]
    suffix = "" if kind in ("dir", "rollup") or "." not in name.strip(".") else name.rsplit(".", 1)[1].lower()
    return {"root_id": root_id(root), "root": root, "rel_path": rel, "name": name, "size": size,
            "mtime_ns": mtime, "kind": kind, "suffix": suffix, **extra}


def catalog_docs():
    return [
        doc(NAS, "a/Eve-Online.exe", 5_000_000, kind="executable"),
        doc(NAS, "a/everything.EXE", 2_000_000, kind="executable", mtime=T2024 + 400 * DAY),
        doc(NAS, "a/eve.txt", 100, kind="text"),
        doc(NAS, "a/Setup_100%.msi", 30_000_000),
        doc(NAS, "a/setup[1].msi", 1_000),
        doc(NAS, "a/my file.doc", 2_048),
        doc(NAS, "a/evening.exe", 7, kind="executable"),
        doc(NAS, "a/unreadable.exe", None, kind="executable", errors=[{"stage": "stat", "message": "denied"}]),
        doc(NAS, "a", 0, kind="dir"),
        doc(NAS, "setup-tools", 0, kind="dir"),
        doc(NAS, "cache/[CACHE]", 9_000_000, kind="rollup", probe={"rollup": {"tag": "[CACHE]", "matched": 2}}),
        doc(NAS, "[REDACTED]", 4_000, kind="rollup", probe={"rollup": {"tag": "[REDACTED]", "matched": 1}}),
        doc(OLD, "x/eve-old.exe", 300, kind="executable"),
        doc(LOCAL, "eve.local.exe", 300, kind="executable"),
    ]


def names(result):
    return sorted(r["rel_path"] for r in result["rows"])


def run(backend, text="", roots=None, scope=False, **params):
    """scope: with no root:/host: term, search only `roots` rather than every root (a shared
    server database holds other tests' records too)."""
    spec = search.with_params(search.parse_query(text), params)
    resolved = search.resolve_roots(spec, roots if roots is not None else backend.roots())
    if resolved is None and scope:
        resolved = list(roots)
    q = search.to_query(spec, resolved, **{k: v for k, v in params.items()
                                            if k in ("sort", "desc", "offset", "limit")})
    return backend.search_names(q) if resolved != [] else {"rows": [], "more": False}


# --- the parser and the translations -------------------------------------------------------
def test_terms_and_filters():
    s = search.parse_query('eve*.exe "my file" ext:exe;.DLL size:>10mb after:2024-01-01 kind:folder '
                           'root:homes host:nas-*')
    assert s["names"] == ["eve*.exe", "my file"]
    assert s["exts"] == ["exe", "dll"]
    assert s["min_size"] == 10 * 1024 ** 2 + 1 and s["max_size"] is None
    assert s["after"] == T2024 and s["kind"] == "dir"
    assert s["root_terms"] == ["homes"] and s["host_terms"] == ["nas-*"]


def test_a_drive_path_or_unknown_key_is_a_name_term():
    assert search.parse_query(r"c:\temp foo:bar")["names"] == [r"c:\temp", "foo:bar"]
    assert search.parse_query("ext:")["names"] == ["ext:"]      # no value: not a filter


@pytest.mark.parametrize("text,lo,hi", [
    ("size:1mb..2mb", 1024 ** 2, 2 * 1024 ** 2), ("size:<=1kb", None, 1024), ("size:<1kb", None, 1023),
    ("size:>=500", 500, None), ("size:=1.5kb", 1536, 1536), ("size:..10", None, 10),
    ("size:5gb..", 5 * 1024 ** 3, None)])
def test_size_filters(text, lo, hi):
    s = search.parse_query(text)
    assert (s["min_size"], s["max_size"]) == (lo, hi)


@pytest.mark.parametrize("text", ["size:big", "size:>10xb", "after:yesterday", "before:2024-13-45"])
def test_bad_values_are_errors(text):
    with pytest.raises(ValueError):
        search.parse_query(text)


def test_parameters_add_to_the_text():
    s = search.with_params(search.parse_query("eve ext:exe"), {"ext": "dll", "min_size": "1kb", "kind": "file"})
    assert s["exts"] == ["exe", "dll"] and s["min_size"] == 1024 and s["kind"] == "file"


@pytest.mark.parametrize("glob,hit,miss", [
    ("setup", ["Setup.exe", "mysetup", "SETUP"], ["set up"]),
    ("eve*.exe", ["eve.exe", "EVEREST.EXE", "eve.x.exe"], ["xeve.exe", "eve.exe.bak", "eve.txt"]),
    ("*setup*", ["a-setup-b"], ["stup"]),
    ("fil?.txt", ["file.txt", "FILE.TXT"], ["fil.txt", "files.txt"]),
    ("a.b", ["xa.bx"], ["axb"]),                      # a dot is a dot
    ("[CACHE]", ["[CACHE]"], ["C", "CACHE"]),
    ("100%", ["Setup_100%.msi"], ["1000"]),
    ("**x", ["abcx"], ["abcxd"]),
])
def test_name_patterns(glob, hit, miss):
    assert all(search.name_matches(n, glob) for n in hit)
    assert not any(search.name_matches(n, glob) for n in miss)


def test_like_patterns_escape_the_sql_wildcards():
    assert search.like_of("setup") == "%setup%"
    assert search.like_of("100%_x") == "%100!%!_x%"
    assert search.like_of("eve*.exe") == "eve%.exe"
    assert search.like_of("a?c") == "a_c"
    assert search.like_of("a!b*") == "a!!b%"
    assert search.like_of("[x]*", brackets=True) == "![x]%" and search.like_of("[x]*") == "[x]%"


def test_regex_translation_is_anchored_where_the_pattern_is():
    assert search.regex_of("eve*.exe") == r"^eve.*\.exe$"
    assert search.regex_of("*setup*") == "setup"
    assert search.regex_of("eve*") == "^eve"
    assert search.regex_of("setup") == "setup"
    re.compile(search.regex_of("a(b"))                  # specials are escaped


def test_roots_and_hosts():
    roots = [NAS, OLD, LOCAL, "//nas-main/other"]

    def resolve(text):
        return search.resolve_roots(search.parse_query(text), roots)

    assert resolve("eve") is None
    assert resolve("host:nas-main") == [NAS, "//nas-main/other"]
    assert resolve("host:nas-*") == [NAS, OLD, "//nas-main/other"]
    assert resolve("host:-") == [LOCAL]
    assert resolve("root:BACKUP") == [OLD]
    assert resolve(f'root:"{NAS}"') == [NAS]
    assert resolve("root:nope") == []
    assert resolve("root:homes host:nas-old") == []


def test_to_query_limits_and_defaults():
    q = search.to_query(search.parse_query("eve"), None, limit="99999", offset="-5", sort="bogus")
    assert q["limit"] == search.MAX_LIMIT and q["offset"] == 0 and q["sort"] == "name" and not q["desc"]
    assert search.to_query(search.parse_query("eve"), None, sort="size")["desc"] is True


# --- the backends --------------------------------------------------------------------------
def pytest_generate_tests(metafunc):
    if "backend_name" not in metafunc.fixturenames:
        return
    names_ = ["memory", "sqlite", "jsonl", "jsonl_dir"]
    for name, flag in (("postgres", "FILECAT_TEST_POSTGRES"), ("mysql", "FILECAT_TEST_MYSQL"),
                       ("mssql", "FILECAT_TEST_MSSQL"), ("mongodb", "FILECAT_TEST_MONGODB")):
        if os.environ.get(flag):
            names_.append(name)
    metafunc.parametrize("backend_name", names_)


def make_backend(name, d):
    if name == "memory":
        return MemoryBackend()
    if name == "sqlite":
        return SqliteBackend(str(d / "c.sqlite"))
    if name == "jsonl":
        return JsonlBackend(str(d / "c.jsonl"))
    if name == "jsonl_dir":
        return JsonlDirBackend(str(d / "c-dir"))
    if name == "postgres":
        from filecat.backends.postgres import PostgresBackend
        return PostgresBackend(os.environ["FILECAT_TEST_POSTGRES"])
    if name == "mysql":
        from filecat.backends.mysql import MysqlBackend
        return MysqlBackend(os.environ["FILECAT_TEST_MYSQL"])
    if name == "mssql":
        from filecat.backends.mssql import MssqlBackend
        return MssqlBackend(os.environ["FILECAT_TEST_MSSQL"])
    from filecat.backends.mongodb import MongoBackend
    return MongoBackend(os.environ["FILECAT_TEST_MONGODB"])


@pytest.fixture
def be(backend_name, fixture_dir):
    b = make_backend(backend_name, fixture_dir)
    shared = backend_name in ("postgres", "mysql", "mssql", "mongodb")

    def clear():
        for root in (NAS, OLD, LOCAL):
            for d in list(b.list(root=root)):
                b.delete(d["root"], d["rel_path"])
        b.flush()

    if shared:
        clear()
    for d in catalog_docs():
        b.put(d)
    b.flush()
    yield b
    if shared:
        clear()
    b.close()


def find(be, text="", **params):
    """The search over the three test roots (a server database may hold others)."""
    return run(be, text, roots=params.pop("roots", [NAS, OLD, LOCAL]), scope=True, **params)


def test_substring_and_case(be):
    assert names(find(be, "SETUP")) == ["a/Setup_100%.msi", "a/setup[1].msi", "setup-tools"]
    assert names(find(be, "setup", kind="file")) == ["a/Setup_100%.msi", "a/setup[1].msi"]


def test_wildcards_match_the_whole_name(be):
    assert names(find(be, "eve*.exe")) == ["a/Eve-Online.exe", "a/evening.exe", "a/everything.EXE",
                                            "eve.local.exe", "x/eve-old.exe"]
    assert names(find(be, "eve??ng.exe")) == ["a/evening.exe"]
    assert names(find(be, "*.msi")) == ["a/Setup_100%.msi", "a/setup[1].msi"]


def test_sql_wildcards_in_names_are_literal(be):
    assert names(find(be, "100%")) == ["a/Setup_100%.msi"]
    assert names(find(be, "t_p")) == []                # `_` is not a one-character wildcard
    assert names(find(be, "[1]")) == ["a/setup[1].msi"]
    assert names(find(be, "setup[1]*")) == ["a/setup[1].msi"]
    assert names(find(be, "t%")) == []
    assert names(find(be, '"my file"')) == ["a/my file.doc"]


def test_terms_are_anded(be):
    assert names(find(be, "eve exe")) == ["a/Eve-Online.exe", "a/evening.exe", "a/everything.EXE",
                                           "eve.local.exe", "x/eve-old.exe"]
    assert names(find(be, "eve online")) == ["a/Eve-Online.exe"]


def test_extension_size_and_date_filters(be):
    assert names(find(be, "eve ext:txt")) == ["a/eve.txt"]
    assert names(find(be, "ext:msi;doc")) == ["a/Setup_100%.msi", "a/my file.doc", "a/setup[1].msi"]
    assert names(find(be, "eve*.exe size:>1mb")) == ["a/Eve-Online.exe", "a/everything.EXE"]
    assert names(find(be, "ext:exe size:<=300")) == ["a/evening.exe", "eve.local.exe", "x/eve-old.exe"]
    assert names(find(be, "ext:exe after:2025-01-01")) == ["a/everything.EXE"]
    assert names(find(be, "ext:exe before:2024-06-01 eve")) == [
        "a/Eve-Online.exe", "a/evening.exe", "eve.local.exe", "x/eve-old.exe"]
    assert names(find(be, "unreadable")) == ["a/unreadable.exe"]      # no size, but still found
    assert names(find(be, "unreadable size:>0")) == []


def test_kinds(be):
    assert names(find(be, "kind:dir")) == ["a", "setup-tools"]
    assert names(find(be, "setup kind:dir")) == ["setup-tools"]
    assert names(find(be, "kind:text")) == ["a/eve.txt"]
    assert names(find(be, "e kind:file ext:doc")) == ["a/my file.doc"]


def test_root_and_host_filters(be):
    assert names(find(be, "eve*.exe host:nas-old")) == ["x/eve-old.exe"]
    assert names(find(be, "eve*.exe host:-")) == ["eve.local.exe"]
    assert names(find(be, "eve*.exe root:backup")) == ["x/eve-old.exe"]
    assert names(find(be, "eve*.exe root:homes")) == ["a/Eve-Online.exe", "a/evening.exe", "a/everything.EXE"]
    assert find(be, "eve*.exe root:nope")["rows"] == []


def test_a_rollup_is_found_by_its_own_name_only(be):
    assert names(find(be, "[CACHE]")) == ["cache/[CACHE]"]
    assert names(find(be, "REDACTED")) == ["[REDACTED]"]
    assert names(find(be, "cache")) == ["cache/[CACHE]"]          # the record's name, not the folder `cache`
    assert names(find(be, "kind:rollup")) == ["[REDACTED]", "cache/[CACHE]"]
    assert not any(r["kind"] == "rollup" for r in find(be, "ext:exe kind:file")["rows"])


def test_paging_sorting_and_more(be):
    first = find(be, "eve*.exe", limit=2)
    assert len(first["rows"]) == 2 and first["more"] is True
    pages, offset = [], 0
    while True:
        page = find(be, "eve*.exe", limit=2, offset=offset)
        pages += [r["rel_path"] for r in page["rows"]]
        offset += 2
        if not page["more"]:
            break
    assert sorted(pages) == names(find(be, "eve*.exe")) and len(set(pages)) == 5
    last = find(be, "eve*.exe", limit=5)
    assert last["more"] is False and len(last["rows"]) == 5
    sizes = [r["size"] for r in find(be, "eve*.exe", sort="size")["rows"]]
    assert sizes == sorted(sizes, reverse=True)


# --- the viewer ----------------------------------------------------------------------------
@pytest.fixture
def catalog(tmp_path):
    path = str(tmp_path / "c.sqlite")
    b = SqliteBackend(path)
    for d in catalog_docs():
        b.put(d)
    b.close()
    c = serve.Catalog(SimpleNamespace(backend="sqlite", out=path, dsn=None, quiet=True, no_save=False))
    yield c
    c.close()


def test_api_rows(catalog):
    res = catalog.search({"q": "eve*.exe host:nas-main", "limit": "2"})
    assert res["more"] is True and res["limit"] == 2 and res["elapsed_ms"] >= 0
    row = res["rows"][0]
    assert row["folder"] == "a" and row["root"] == NAS and row["host"] == "nas-main"
    assert {"name", "rel_path", "size", "mtime_ns", "kind"} <= set(row)
    assert res["query"]["host_terms"] == ["nas-main"]
    rollup = catalog.search({"q": "[CACHE]"})["rows"][0]
    assert rollup["kind"] == "rollup" and rollup["rollup"]["matched"] == 2


def test_api_needs_a_criterion_and_rejects_bad_values(catalog):
    for params in ({}, {"q": "   "}, {"q": "size:huge"}, {"q": "x", "after": "never"}):
        with pytest.raises(ValueError):
            catalog.search(params)
    assert catalog.search({"q": "x", "root": "nope"})["rows"] == []


# --- the name_lc column and index ----------------------------------------------------------
def test_sql_name_terms_match_the_lower_cased_column():
    from filecat.browse import MSSQL, MYSQL, POSTGRES, SQLITE, sql_where
    for d in (SQLITE, POSTGRES, MYSQL, MSSQL):
        where, params = sql_where({"names": ["EVE*.exe", "Setup"]}, d, None, name_lc=True)
        assert where.count(f"name_lc LIKE {d.ph} ESCAPE '!'") == 2 and "lower" not in where.lower()
        # a literal prefix and no leading wildcard: an index range; plain text stays `%x%`
        assert params == ["eve%.exe", "%setup%"]
    assert sql_where({"names": ["[x]*"]}, MSSQL, None, name_lc=True)[1] == ["![x]%"]
    assert sql_where({"names": ["100%"]}, SQLITE, None, name_lc=True)[1] == ["%100!%%"]
    # until every row has name_lc: the old predicate on `name`
    assert "name_lc" not in sql_where({"names": ["eve*"]}, SQLITE, None)[0]
    assert "lower(name)" in sql_where({"names": ["eve*"]}, MYSQL, None)[0].lower()


def test_mongo_name_terms_are_anchored_case_sensitive_regexes_on_name_lc():
    from filecat.backends.mongodb import MongoBackend
    q = {"names": ["EVE*.exe", "Setup"], "depth": 2}
    assert MongoBackend._browse_filter(q, True) == {"$and": [
        {"name_lc": {"$regex": r"^eve.*\.exe$", "$options": "s"}},
        {"name_lc": {"$regex": "setup", "$options": "s"}}]}
    assert MongoBackend._browse_filter(q)["$and"][0] == {"name": {"$regex": r"^EVE.*\.exe$", "$options": "is"}}


def test_reindex_names_is_a_no_op_on_a_filled_catalog_and_searches_stay_right(be):
    assert be.reindex_names() == 0
    assert names(find(be, "EVE*.EXE")) == ["a/Eve-Online.exe", "a/evening.exe", "a/everything.EXE",
                                            "eve.local.exe", "x/eve-old.exe"]
    assert names(find(be, "*SETUP*", kind="file")) == ["a/Setup_100%.msi", "a/setup[1].msi"]
    assert names(find(be, "100%")) == ["a/Setup_100%.msi"]


def test_sqlite_fills_name_lc_on_put(fixture_dir):
    b = SqliteBackend(str(fixture_dir / "c.sqlite"))
    b.put(doc(NAS, "a/Eve-Online.EXE"))
    b.put({k: v for k, v in doc(NAS, "a/x") .items() if k != "name"})      # no name at all
    b.put(doc(NAS, "a/\u00c4rger.txt"))
    b.flush()
    got = dict(b.conn.execute("SELECT rel_path, name_lc FROM files"))
    assert got == {"a/Eve-Online.EXE": "eve-online.exe", "a/x": "", "a/\u00c4rger.txt": "\u00e4rger.txt"}
    b.put(doc(NAS, "a/Eve-Online.EXE", 99))                                 # an update refreshes it
    assert b.search_names(search.to_query(search.parse_query("EVE-"), None))["rows"][0]["size"] == 99
    b.close()


def _old_catalog(path, rows):
    """A catalog as filecat 0.2.4 left it: no name_lc column, schema_version 1."""
    import json
    import sqlite3
    from filecat.backends import sqlite as sq
    conn = sqlite3.connect(path)
    conn.executescript(sq._SCHEMA.replace("    name_lc TEXT COLLATE NOCASE,\n", "")
                       .replace("    name_lc TEXT COLLATE NOCASE,\r\n", ""))
    conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', '1')")
    for d in rows:
        conn.execute("INSERT INTO files (root_id, root, rel_path, name, size, mtime_ns, kind, suffix, document) "
                     "VALUES (?,?,?,?,?,?,?,?,?)", (d["root_id"], d["root"], d["rel_path"], d["name"], d["size"],
                                                    d["mtime_ns"], d["kind"], d["suffix"], json.dumps(d)))
    assert "name_lc" not in {r[1] for r in conn.execute("PRAGMA table_info(files)")}
    conn.commit()
    conn.close()


def test_sqlite_adds_name_lc_to_an_old_catalog_and_reindex_fills_it(fixture_dir):
    path = str(fixture_dir / "old.sqlite")
    _old_catalog(path, catalog_docs()[:-1])
    b = SqliteBackend(path)
    cols = {r[1] for r in b.conn.execute("PRAGMA table_info(files)")}
    assert "name_lc" in cols
    assert b.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "2"
    assert b.conn.execute("SELECT 1 FROM sqlite_master WHERE name='idx_files_name_lc'").fetchone()
    assert b.conn.execute("SELECT COUNT(*) FROM files WHERE name_lc IS NULL").fetchone()[0] == 13

    everything = [NAS, OLD, LOCAL]
    want = ["a/Eve-Online.exe", "a/evening.exe", "a/everything.EXE", "x/eve-old.exe"]
    assert names(run(b, "EVE*.exe", roots=everything)) == want      # the old predicate, still right
    assert names(run(b, "100%", roots=everything)) == ["a/Setup_100%.msi"]
    assert not b._name_lc_ready()

    b.put(doc(LOCAL, "eve.local.exe", 300, kind="executable"))      # a new row has it, an old one not yet
    b.flush()
    assert b.conn.execute("SELECT COUNT(*) FROM files WHERE name_lc IS NULL").fetchone()[0] == 13
    assert names(run(b, "EVE*.exe", roots=everything)) == sorted(want + ["eve.local.exe"])

    seen = []
    assert b.reindex_names(seen.append, batch=5) == 13
    assert seen == [5, 10, 13]
    assert b.conn.execute("SELECT COUNT(*) FROM files WHERE name_lc IS NULL").fetchone()[0] == 0
    assert dict(b.conn.execute("SELECT rel_path, name_lc FROM files"))["a/Eve-Online.exe"] == "eve-online.exe"
    assert b._name_lc_ready()
    assert names(run(b, "EVE*.exe", roots=everything)) == sorted(want + ["eve.local.exe"])
    assert names(run(b, "setup[1]*", roots=everything)) == ["a/setup[1].msi"]
    assert b.reindex_names() == 0                                   # nothing left: safe to run again
    b.close()

    again = SqliteBackend(path)                                     # reopening a version 2 catalog
    assert again._name_lc_ready() and names(run(again, "my file", roots=everything)) == ["a/my file.doc"]
    again.close()


def test_sqlite_prefix_search_uses_the_name_lc_index(fixture_dir):
    from filecat.browse import SQLITE, sql_where
    b = SqliteBackend(str(fixture_dir / "c.sqlite"))
    for q, indexed in (({"names": ["eve*.exe"]}, True), ({"names": ["EVE*"]}, True),
                       ({"names": ["a!b*"]}, True), ({"names": ["setup"]}, False)):
        where, params = sql_where(q, SQLITE, None, name_lc=True)
        plan = " ".join(r[3] for r in b.conn.execute(f"EXPLAIN QUERY PLAN SELECT document FROM files{where}", params))
        assert ("idx_files_name_lc" in plan) is indexed, plan
    b.close()


def test_search_reindex_command(fixture_dir, capsys):
    from filecat import search_cmd
    path = str(fixture_dir / "old.sqlite")
    _old_catalog(path, catalog_docs()[:3])
    args = SimpleNamespace(backend="sqlite", out=path, dsn=None, batch=2, json=True)
    assert search_cmd.run(args) == 0
    assert '"filled": 3' in capsys.readouterr().out
    assert search_cmd.run(args) == 0
    assert '"filled": 0' in capsys.readouterr().out


def test_a_large_catalog_gets_its_name_index_from_reindex_not_from_connect(fixture_dir, monkeypatch, capsys):
    from filecat import search_cmd
    from filecat.backends import sqlite as sq
    path = str(fixture_dir / "old.sqlite")
    _old_catalog(path, catalog_docs()[:5])
    monkeypatch.setattr(sq, "INDEX_AT_CONNECT_MAX_ROWS", 0)         # five rows count as large
    b = SqliteBackend(path)
    has = lambda: bool(b.conn.execute("SELECT 1 FROM sqlite_master WHERE name='idx_files_name_lc'").fetchone())
    assert "name_lc" in {r[1] for r in b.conn.execute("PRAGMA table_info(files)")} and not has()
    assert names(run(b, "EVE*", roots=[NAS])) == ["a/Eve-Online.exe", "a/eve.txt", "a/everything.EXE"]  # before backfill
    said = []
    assert b.reindex_names(say=said.append) == 5
    assert has() and said == ["building index idx_files_name_lc"]
    assert names(run(b, "EVE*", roots=[NAS])) == ["a/Eve-Online.exe", "a/eve.txt", "a/everything.EXE"]
    said.clear()
    assert b.reindex_names(say=said.append) == 0 and said == []     # idempotent
    b.close()

    path = str(fixture_dir / "old2.sqlite")
    _old_catalog(path, catalog_docs()[:5])
    sq.SqliteBackend(path).close()                                  # connect only: no index
    args = SimpleNamespace(backend="sqlite", out=path, dsn=None, batch=2, json=False)
    assert search_cmd.run(args) == 0
    assert "building index idx_files_name_lc" in capsys.readouterr().err
