from __future__ import annotations

import io

from filecat import netaccount, preflight, record, rootinfo
from filecat.backends.sqlite import SqliteBackend
from filecat.options import ScanOptions
from filecat.scan import scan_roots

UNC = "\\\\nas-old\\Backup"


def test_server_of_and_clean():
    assert netaccount.server_of("\\\\NAS-VM\\home\\x") == "nas-vm"
    assert netaccount.server_of("//192.0.2.13/home") == "192.0.2.13"
    assert netaccount.server_of("C:\\") is None
    assert netaccount._clean("MicrosoftAccount\\admin") == "admin"
    assert netaccount._clean("MicrosoftAccount\\me@outlook.com") == "MicrosoftAccount\\me@outlook.com"
    assert netaccount.same_user({"user": "MicrosoftAccount\\Admin"}, {"user": "admin"})
    assert not netaccount.same_user({"user": "jdoe"}, {"user": "scanuser"})
    assert netaccount.same_user(None, {"user": "x"})


def test_account_order_connection_saved_logon(monkeypatch):
    netaccount._for_server.cache_clear()
    monkeypatch.setattr(netaccount, "logon_user", lambda: "winuser")
    monkeypatch.setattr(netaccount, "connections", lambda: {"192.0.2.13": "scanuser"})
    monkeypatch.setattr(netaccount, "saved_credential", lambda s: {"nas-old": "jdoe"}.get(s))
    monkeypatch.setattr(netaccount.sys, "platform", "win32")
    try:
        assert netaccount.account_for("\\\\192.0.2.13\\home") == {"user": "scanuser", "source": "connection"}
        assert netaccount.account_for("\\\\nas-old\\x") == {"user": "jdoe", "source": "saved credential"}
        assert netaccount.account_for("\\\\nas-zfs\\x") == {"user": "winuser", "source": "windows logon"}
        assert netaccount.account_for("D:\\") == {"user": "winuser", "source": "local"}
    finally:
        netaccount._for_server.cache_clear()


def test_default_connections_are_not_explicit(monkeypatch):
    monkeypatch.setattr(netaccount, "logon_user", lambda: "winuser")
    assert netaccount._is_default("WINUSER")
    assert netaccount._is_default("MicrosoftAccount\\me@outlook.com")
    assert not netaccount._is_default("MicrosoftAccount\\scanuser")


def _accounts(monkeypatch, table):
    monkeypatch.setattr(preflight.netaccount, "account_for",
                        lambda p: table.get(netaccount.server_of(p)))


def test_preflight_reports_unopenable_roots_and_account_changes(tmp_path, monkeypatch):
    backend = SqliteBackend(str(tmp_path / "c.sqlite"))
    good, gone = tmp_path / "share", tmp_path / "missing"
    good.mkdir()
    info = {"root_id": record.root_id(str(good)), "root": str(good),
            "last_scan": {"started_at": "2026-10-16T10:00:00+00:00",
                          "account": {"user": "jdoe", "source": "saved credential"}}}
    backend.put_root_info(info)
    _accounts(monkeypatch, {None: {"user": "scanuser", "source": "connection"}})
    checks = preflight.check([str(good), str(gone)], [str(good), str(gone)], backend, timeout=5)
    out = io.StringIO()
    assert preflight.report(checks, out) == 2
    text = out.getvalue()
    assert "preflight: 2 roots" in text
    assert "local    2 roots  as scanuser (connection)" in text
    assert f"! {gone}: cannot open:" in text
    assert f"! {good}: read as scanuser (connection); the last scan used jdoe (2026-10-16)" in text
    backend.close()


def test_scan_records_account_and_check_only_scans_nothing(tmp_path, monkeypatch, capsys):
    root = tmp_path / "data"
    root.mkdir()
    (root / "a.txt").write_text("x")
    _accounts(monkeypatch, {None: {"user": "winuser", "source": "local"}})
    backend = SqliteBackend(str(tmp_path / "c.sqlite"))
    resume = str(tmp_path / "r.json")

    assert scan_roots([str(root)], backend, ScanOptions(check_only=True), resume) == 0
    assert backend.get(str(root), "a.txt") is None and backend.get_root_info(str(root)) is None

    scan_roots([str(root)], backend, ScanOptions(identify="never"), resume)
    info = backend.get_root_info(str(root))
    assert info["last_scan"]["account"] == {"user": "winuser", "source": "local"}
    assert info["last_attempt"]["account"] == {"user": "winuser", "source": "local"}

    _accounts(monkeypatch, {None: {"user": "other", "source": "connection"}})
    capsys.readouterr()
    assert scan_roots([str(root)], backend, ScanOptions(check_only=True), resume) == 1
    assert "the last scan used winuser" in capsys.readouterr().err
    backend.close()


def test_rootinfo_begin_without_account_leaves_it_out(tmp_path):
    backend = SqliteBackend(str(tmp_path / "c.sqlite"))
    attempt = rootinfo.begin(backend, str(tmp_path))
    assert "account" not in attempt
    backend.close()
