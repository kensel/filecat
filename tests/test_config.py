"""filecat.toml lookup, ${VAR} expansion, masking, CLI defaults and `filecat config`.

The server checks only run when FILECAT_TEST_<BACKEND> is set, like the
backend contract test.
"""
from __future__ import annotations

import argparse
import os
import tomllib

import pytest

from filecat import cli, config


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


def test_find_order(fixture_dir, monkeypatch):
    monkeypatch.chdir(fixture_dir)
    monkeypatch.setenv("APPDATA", str(fixture_dir / "appdata"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(fixture_dir / "appdata"))
    monkeypatch.delenv("FILECAT_CONFIG")
    assert config.find() is None
    user = config.user_path()
    user.parent.mkdir(parents=True)
    _write(user, 'backend = "jsonl"\n')
    assert config.find() == user
    local = _write(fixture_dir / "filecat.toml", 'backend = "sqlite"\n')
    assert config.find().resolve() == local.resolve()
    other = _write(fixture_dir / "other.toml", "")
    monkeypatch.setenv("FILECAT_CONFIG", str(other))
    assert config.find() == other
    assert config.find(str(local)) == local
    monkeypatch.setenv("FILECAT_CONFIG", "none")
    assert config.find() is None
    with pytest.raises(config.ConfigError):
        config.find(str(fixture_dir / "missing.toml"))


def test_load_rejects_unknown_backend(fixture_dir):
    with pytest.raises(config.ConfigError, match="oracle"):
        config.load(_write(fixture_dir / "c.toml", 'backend = "oracle"\n'))
    with pytest.raises(config.ConfigError):
        config.load(_write(fixture_dir / "bad.toml", "backend = \n"))


def test_expand_and_missing(monkeypatch):
    monkeypatch.setenv("FC_PW", "p@ss")
    monkeypatch.delenv("FC_NOPE", raising=False)
    assert config.expand("x:${FC_PW}@h") == "x:p@ss@h"
    assert config.expand("$FC_PW %FC_PW%") == "$FC_PW %FC_PW%"   # only ${NAME}
    with pytest.raises(config.ConfigError, match="FC_NOPE"):
        config.expand("${FC_NOPE}")
    assert config.expand("${FC_NOPE}", strict=False) == "${FC_NOPE}"
    assert config.missing_vars("a${FC_PW}b${FC_NOPE}") == ["FC_NOPE"]


@pytest.mark.parametrize("dsn, shown", [
    ("postgresql://u:secret@h:5432/db", "postgresql://u:***@h:5432/db"),
    ("postgresql://u:${PW}@h/db", "postgresql://u:${PW}@h/db"),
    ("mongodb://127.0.0.1:27017/filecat", "mongodb://127.0.0.1:27017/filecat"),
    ("host=h dbname=d user=u password=secret sslmode=require",
     "host=h dbname=d user=u password=*** sslmode=require"),
    ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=h;UID=u;PWD={a;b};DATABASE=d",
     "DRIVER={ODBC Driver 18 for SQL Server};SERVER=h;UID=u;PWD=***;DATABASE=d"),
])
def test_mask(dsn, shown):
    assert config.mask(dsn) == shown


def test_render_is_valid_toml():
    text = config.render(backend="mongodb", dsns={"mongodb": "mongodb://h/db"},
                         outs={"sqlite": r"D:\cat\x.sqlite"}, notes={"mongodb": "detected"})
    cfg = tomllib.loads(text)
    assert cfg["backend"] == "mongodb"
    assert cfg["mongodb"]["dsn"] == "mongodb://h/db"
    assert cfg["sqlite"]["out"] == r"D:\cat\x.sqlite"
    assert "postgres" not in cfg                      # written commented out
    assert "# dsn = \"postgresql://" in text
    assert cfg["ollama"]["model"] == config.DEFAULT_MODEL


def test_apply_precedence(monkeypatch):
    cfg = {"backend": "postgres", "postgres": {"dsn": "postgresql://h/${FC_DB}"},
           "sqlite": {"out": "x.sqlite"}, "ollama": {"model": "m1", "url": "http://o:1"}}
    monkeypatch.setenv("FC_DB", "cat")
    monkeypatch.delenv("FILECAT_DSN", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)

    args = argparse.Namespace(backend=None, out=None, dsn=None, model=None, ollama_url=None)
    config.apply(args, cfg)
    assert (args.backend, args.dsn, args.model, args.ollama_url) == \
        ("postgres", "postgresql://h/cat", "m1", "http://o:1")

    args = argparse.Namespace(backend="sqlite", out=None, dsn=None)
    config.apply(args, cfg)
    assert args.out == "x.sqlite"

    args = argparse.Namespace(backend=None, out=None, dsn="postgresql://flag/db")
    config.apply(args, cfg)
    assert args.dsn == "postgresql://flag/db"         # flag beats the file

    monkeypatch.setenv("FILECAT_DSN", "postgresql://env/db")
    args = argparse.Namespace(backend=None, out=None, dsn=None)
    config.apply(args, cfg)
    assert args.dsn is None                           # open_backend reads FILECAT_DSN

    args = argparse.Namespace(backend=None, out=None, dsn=None)
    config.apply(args, {})
    assert args.backend == "sqlite"


def test_apply_migrate(monkeypatch):
    monkeypatch.setenv("FILECAT_DSN", "mongodb://env/x")
    cfg = {"jsonl": {"out": "a.jsonl"}, "mongodb": {"dsn": "mongodb://cfg/x"}}
    args = argparse.Namespace(src_backend="mongodb", src_out=None, src_dsn=None,
                              dst_backend="jsonl", dst_out=None, dst_dsn=None)
    config.apply(args, cfg)
    assert args.src_dsn == "mongodb://cfg/x"          # FILECAT_DSN is the target's default only
    assert args.dst_out == "a.jsonl"


def test_cli_uses_config_backend_and_out(fixture_dir, monkeypatch, capsys):
    out = fixture_dir / "from-config.jsonl"
    cfg = _write(fixture_dir / "filecat.toml",
                 f'backend = "jsonl"\n[jsonl]\nout = {config._toml_str(str(out))}\n')
    tree = fixture_dir / "tree"
    tree.mkdir()
    (tree / "a.txt").write_text("hello", encoding="utf-8")
    assert cli.main(["--config", str(cfg), "scan", str(tree), "--workers", "1"]) == 0
    assert out.is_file() and "a.txt" in out.read_text(encoding="utf-8")


def test_cli_reports_unset_variable(fixture_dir, monkeypatch, capsys):
    monkeypatch.delenv("FC_UNSET_PW", raising=False)
    cfg = _write(fixture_dir / "c.toml",
                 'backend = "postgres"\n[postgres]\ndsn = "postgresql://u:${FC_UNSET_PW}@h/d"\n')
    assert cli.main(["--config", str(cfg), "summary"]) == 2
    assert "FC_UNSET_PW" in capsys.readouterr().err


def test_config_init(fixture_dir, monkeypatch, capsys):
    monkeypatch.setattr(config, "listening", lambda port, **kw: port == 27017)
    path = fixture_dir / "filecat.toml"
    assert cli.main(["config", "init", "--path", str(path)]) == 0
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
    assert cfg["backend"] == "sqlite"
    assert cfg["mongodb"]["dsn"] == "mongodb://127.0.0.1:27017/filecat"
    assert "postgres" not in cfg
    assert cli.main(["config", "init", "--path", str(path)]) == 1          # no overwrite
    assert cli.main(["config", "init", "--path", str(path), "--force", "--no-detect",
                     "--backend", "postgres", "--dsn", "postgresql://u@h/d"]) == 0
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
    assert cfg["backend"] == "postgres" and "mongodb" not in cfg
    assert cli.main(["config", "init", "--stdout", "--dsn", "x", "--no-detect"]) == 2  # dsn needs a server


def test_config_show_masks(fixture_dir, capsys):
    cfg = _write(fixture_dir / "c.toml", '[mysql]\ndsn = "mysql://u:hunter2@h/d"\n')
    assert cli.main(["--config", str(cfg), "config", "show"]) == 0
    out = capsys.readouterr().out
    assert "hunter2" not in out and "mysql://u:***@h/d" in out
    assert cli.main(["--config", str(cfg), "config", "show", "--reveal"]) == 0
    assert "hunter2" in capsys.readouterr().out


def test_config_test_file_backends(fixture_dir, capsys):
    from filecat.backends.sqlite import SqliteBackend
    from filecat.record import new_document
    db = fixture_dir / "c.sqlite"
    with SqliteBackend(str(db)) as be:
        be.put(new_document("R:", "a.txt", kind="text", size=1))
    cfg = _write(fixture_dir / "c.toml", f'[sqlite]\nout = {config._toml_str(str(db))}\n')
    assert cli.main(["--config", str(cfg), "config", "test"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("ok   sqlite") and "files_estimate=1" in out
    assert cli.main(["--config", str(cfg), "config", "test", "jsonl",
                     "--out", str(fixture_dir / "new.jsonl")]) == 0
    assert "does not exist yet" in capsys.readouterr().out
    assert cli.main(["--config", str(cfg), "config", "test", "jsonl",
                     "--out", str(fixture_dir / "no" / "dir" / "x.jsonl")]) == 1


def test_config_test_failures(fixture_dir, capsys):
    cfg = _write(fixture_dir / "c.toml", "")
    assert cli.main(["--config", str(cfg), "config", "test", "mongodb"]) == 1
    assert "no dsn" in capsys.readouterr().out
    assert cli.main(["--config", str(cfg), "config", "test", "oracle"]) == 2
    # nothing listens on port 9 (discard) on 127.0.0.1 in practice
    assert cli.main(["--config", str(cfg), "config", "test", "mongodb",
                     "--dsn", "mongodb://127.0.0.1:9/x", "--timeout", "0.5"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL mongodb") and "dsn=mongodb://127.0.0.1:9/x" in out


SERVER_ENV = {"postgres": "FILECAT_TEST_POSTGRES", "mysql": "FILECAT_TEST_MYSQL",
              "mssql": "FILECAT_TEST_MSSQL", "mongodb": "FILECAT_TEST_MONGODB"}


@pytest.mark.parametrize("name", sorted(SERVER_ENV))
def test_config_verify_server(name, fixture_dir, capsys):
    dsn = os.environ.get(SERVER_ENV[name])
    if not dsn:
        pytest.skip(f"{SERVER_ENV[name]} not set")
    cfg = _write(fixture_dir / "c.toml", "")
    assert cli.main(["--config", str(cfg), "config", "verify", name, "--dsn", dsn]) == 0, \
        capsys.readouterr().out
    out = capsys.readouterr().out
    assert out.startswith(f"ok   {name}") and "delete ok" in out
