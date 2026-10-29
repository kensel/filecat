"""Shared fixtures. Test fixtures are built under tests/_fixtures by the tests themselves.

A .env file at the repo root (gitignored; see .env.example) sets the
FILECAT_TEST_* variables that turn on the server-backend and SMB tests.
Variables already set in the environment win over the file.
"""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).parent / "_fixtures"


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


_load_dotenv(Path(__file__).resolve().parent.parent / ".env")


@pytest.fixture
def fixture_dir(request) -> Path:
    """A fresh directory under tests/_fixtures, removed after the test."""
    d = FIXTURE_ROOT / f"{request.node.name[:40]}-{uuid.uuid4().hex[:8]}"
    d.mkdir(parents=True)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(autouse=True)
def _no_user_config(monkeypatch):
    """A filecat.toml in the repo or the user profile must not steer the tests."""
    monkeypatch.setenv("FILECAT_CONFIG", "none")


def pytest_collection_modifyitems(config, items):
    """FILECAT_TEST_AGENT_BIN set: the agent tests run against the real binary
    (tests/_real_agent.py). These tests assert the fake's own constants or reach into the
    fake and cannot mean the same thing there."""
    if not os.environ.get("FILECAT_TEST_AGENT_BIN"):
        return
    from _real_agent import NOT_AGAINST_THE_REAL_AGENT
    for item in items:
        why = NOT_AGAINST_THE_REAL_AGENT.get(item.name)
        if why:
            item.add_marker(pytest.mark.skip(reason=f"real-agent run: {why}"))


@pytest.fixture(autouse=True)
def _redaction_key(monkeypatch, tmp_path):
    """The sticky-redaction key of a test is its own file, never the user's."""
    monkeypatch.setenv("FILECAT_REDACT_KEY_FILE", str(tmp_path / "redact.key"))
