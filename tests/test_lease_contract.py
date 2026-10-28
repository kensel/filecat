"""The server's atomic lease (Backend.claim_server_doc) on every backend the contract runs on.

CI's `backends` job sets FILECAT_TEST_POSTGRES / _MYSQL / _MSSQL / _MONGODB, so the conditional
UPDATE / upsert / duplicate-key paths of those backends run there (and only there); locally this
covers memory, sqlite and the JSONL files.
"""
from __future__ import annotations

import threading
import uuid

import pytest

# the contract's parametrisation and fixtures: one test body per available backend
from test_backend_contract import _make_backend, backend, pytest_generate_tests   # noqa: F401

T0, T1, T2 = ("2026-10-28T10:00:00.000+00:00", "2026-10-28T10:01:00.000+00:00", "2026-10-28T10:02:00.000+00:00")
STORE = "server_state"


def _lease(holder: str, expires: str, key: str) -> dict:
    return {"key": key, "host": "h-" + holder, "holder": holder, "pid": 1, "started_at": T0,
            "renewed_at": T0, "scanned_at": T0, "expires_at": expires}


def test_lease_claim_contract(backend, backend_name):
    key = f"lease-{uuid.uuid4().hex[:8]}"

    def doc():
        return next((d for d in backend.server_docs(STORE) if d["key"] == key), None)

    try:
        assert backend.claim_server_doc(STORE, _lease("A", T1, key), holder="A", now=T0)        # absent: taken
        assert doc()["holder"] == "A"
        assert not backend.claim_server_doc(STORE, _lease("B", T2, key), holder="B", now=T0)    # held and alive
        assert doc()["holder"] == "A"
        assert backend.claim_server_doc(STORE, _lease("A", T2, key), holder="A", now=T0)        # ours: renewed
        assert doc()["expires_at"] == T2
        # renewal is the holder's only: B cannot renew (takeover off), even past A's expiry
        assert not backend.claim_server_doc(STORE, _lease("B", T2, key), holder="B",
                                            now="2026-10-28T11:00:00.000+00:00", takeover=False)
        assert doc()["holder"] == "A"
        assert backend.claim_server_doc(STORE, _lease("B", T2, key), holder="B",
                                        now="2026-10-28T10:03:00.000+00:00")                    # expired: B takes over
        assert doc()["holder"] == "B"
        assert not backend.claim_server_doc(STORE, _lease("A", T2, key), holder="A", now=T0)    # A lost it
        assert doc()["holder"] == "B"
    finally:
        backend._topology_remove(STORE, key)


def test_lease_claim_race_has_one_winner(backend, backend_name, fixture_dir):
    """Four threads claim an absent lease at once, each on its own connection where the backend has
    connections: exactly one wins."""
    if backend_name in ("jsonl", "jsonl_dir"):
        pytest.skip("JSONL files: a best-effort read-check-write for a single host (docs/agent-server.md)")
    key = f"race-{uuid.uuid4().hex[:8]}"
    wins: list[str] = []
    gate = threading.Barrier(4)

    def attempt(who: str) -> None:
        mine = backend if backend_name == "memory" else _make_backend(backend_name, fixture_dir)
        try:
            gate.wait(10)
            if mine.claim_server_doc(STORE, _lease(who, "2099-01-01T00:00:00.000+00:00", key),
                                     holder=who, now=T0):
                wins.append(who)
        except Exception as exc:                # surfaced by the assert below
            wins.append(f"error: {exc!r}")
        finally:
            if mine is not backend:
                mine.close()

    threads = [threading.Thread(target=attempt, args=(w,)) for w in "ABCD"]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert len(wins) == 1 and not wins[0].startswith("error"), wins
        assert next(d for d in backend.server_docs(STORE) if d["key"] == key)["holder"] == wins[0]
    finally:
        backend._topology_remove(STORE, key)
