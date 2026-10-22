from __future__ import annotations

import pytest

from filecat import cli, everything
from filecat.everything import ShareListError, drive_root, plan

SHARES = {"nas-vm": ["home", "ISOs"], "192.0.2.13": ["ActiveBackupforBusiness", "home"]}


def lister(server):
    if server == "down":
        raise ShareListError(53, "The network path was not found. (error 53)")
    if server == "locked":
        raise ShareListError(5, "Access is denied. (error 5)")
    return SHARES.get(server, [])


def test_drive_root():
    assert [drive_root(d) for d in ("c", "C:", "d:\\", "e:/")] == ["C:\\", "C:\\", "D:\\", "E:\\"]
    with pytest.raises(ValueError):
        drive_root("CD")


def test_plan_servers_then_drives_skipping_failures_and_excludes():
    roots, problems = plan(
        ["nas-vm", "\\\\192.0.2.13", "down", "empty"], ["c:", "I"], {},
        exclude=["\\\\nas-vm\\ISOs", "\\\\nas-main\\home\\"],          # matched as read or as recorded
        aliases={"\\\\192.0.2.13": "\\\\nas-main"}, lister=lister, login=lambda *a: False)
    assert roots == ["\\\\nas-vm\\home", "\\\\192.0.2.13\\ActiveBackupforBusiness", "C:\\", "I:\\"]
    assert problems == ["\\\\down: shares not listed: The network path was not found. (error 53)",
                        "\\\\empty: no disk shares"]


def test_plan_logs_in_on_access_denied_and_retries():
    calls = []

    def login(server, user):
        calls.append((server, user))
        SHARES["locked"] = ["data"]
        return True

    def lister2(server):
        if server == "locked" and not calls:
            raise ShareListError(5, "Access is denied. (error 5)")
        return SHARES.get(server, [])

    try:
        roots, problems = plan(["locked"], [], {"locked": "nas\\admin"}, [], {}, lister=lister2, login=login)
    finally:
        SHARES.pop("locked", None)
    assert calls == [("locked", "nas\\admin")]
    assert roots == ["\\\\locked\\data"] and problems == []


def test_plan_without_login_reports_access_denied():
    roots, problems = plan(["locked"], [], {}, [], {}, lister=lister, login=lambda *a: True)
    assert roots == [] and problems == ["\\\\locked: shares not listed: Access is denied. (error 5)"]


def test_scan_everything_list_uses_config(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "filecat.toml"
    cfg.write_text("""
[aliases]
'\\\\192.0.2.13' = '\\\\nas-main'

[everything]
servers = ["nas-vm", "192.0.2.13"]
drives = ["C:"]
exclude = ['\\\\nas-vm\\ISOs']
""", encoding="utf-8")
    monkeypatch.setattr(everything, "list_shares", lister)
    assert cli.main(["--config", str(cfg), "scan-everything", "--list"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "\\\\nas-vm\\home",
        "\\\\192.0.2.13\\ActiveBackupforBusiness  -> recorded as \\\\nas-main\\ActiveBackupforBusiness",
        "\\\\192.0.2.13\\home  -> recorded as \\\\nas-main\\home",
        "C:\\",
    ]
    # --server / --drive replace the configured set
    assert cli.main(["--config", str(cfg), "scan-everything", "--list", "--drive", "d"]) == 0
    assert capsys.readouterr().out.splitlines() == ["D:\\"]


def test_scan_everything_hands_roots_to_scan(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(everything, "list_shares", lister)

    def fake_scan(args):
        seen["roots"] = args.roots
        seen["measure_backups"] = args.measure_backups
        return 0

    from filecat import scan
    monkeypatch.setattr(scan, "run", fake_scan)
    code = cli.main(["scan-everything", "--server", "nas-vm", "--server", "down",
                     "--out", str(tmp_path / "c.sqlite")])
    assert code == 1                       # \\down could not be listed
    assert seen == {"roots": ["\\\\nas-vm\\home", "\\\\nas-vm\\ISOs"], "measure_backups": False}


def test_scan_everything_unfinished_skips_finished_roots(tmp_path, monkeypatch, capsys):
    import json

    from filecat import rootinfo, scan
    from filecat.backends.sqlite import SqliteBackend
    from filecat.record import root_id

    cfg = tmp_path / "filecat.toml"
    cfg.write_text("""
[aliases]
'\\\\192.0.2.13' = '\\\\nas-main'

[everything]
servers = ["nas-vm", "192.0.2.13"]
drives = ["C:", "D:"]
""", encoding="utf-8")
    out = tmp_path / "c.sqlite"
    backend = SqliteBackend(str(out))
    for root, status in (("\\\\nas-vm\\home", "errors"),      # a folder could not be listed
                         ("\\\\nas-vm\\ISOs", "ok"),
                         ("\\\\nas-main\\ActiveBackupforBusiness", "failed"),
                         ("D:\\", "running")):                  # another scan, heartbeat fresh
        backend.put_root_info({"root_id": root_id(root), "root": root, "last_attempt": {
            "status": status, "started_at": rootinfo.now(), "heartbeat_at": rootinfo.now()}})
    backend.close()
    (tmp_path / "c.sqlite.resume.json").write_text(json.dumps(
        {"version": 2, "roots": {"\\\\nas-vm\\home": {"x": {"mtime_ns": 1, "child_count": 0}}}}))
    monkeypatch.setattr(everything, "list_shares", lister)
    args = ["--config", str(cfg), "scan-everything", "--unfinished", "--out", str(out)]

    assert cli.main(args + ["--list"]) == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "\\\\nas-vm\\home  (stopped partway)",
        "\\\\192.0.2.13\\ActiveBackupforBusiness  -> recorded as "
        "\\\\nas-main\\ActiveBackupforBusiness  (failed)",
        "\\\\192.0.2.13\\home  -> recorded as \\\\nas-main\\home  (never scanned)",
        "C:\\  (never scanned)",
    ]
    assert "D:\\ is being scanned now" in captured.err
    assert "4 of 6 roots unfinished" in captured.err

    seen = {}

    def fake_scan(a):
        seen["roots"] = a.roots
        return 0

    monkeypatch.setattr(scan, "run", fake_scan)
    assert cli.main(args) == 0
    assert seen["roots"] == ["\\\\nas-vm\\home", "\\\\192.0.2.13\\ActiveBackupforBusiness",
                             "\\\\192.0.2.13\\home", "C:\\"]


def test_ctrl_c_exits_cleanly_with_a_hint(tmp_path, monkeypatch, capsys):
    from filecat import scan

    def interrupted(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(everything, "list_shares", lister)
    monkeypatch.setattr(scan, "run", interrupted)
    assert cli.main(["scan-everything", "--server", "nas-vm",
                     "--out", str(tmp_path / "c.sqlite")]) == 130
    err = capsys.readouterr().err
    assert "Ctrl+C pressed, scan-everything stopped" in err and "--unfinished" in err
    assert "Traceback" not in err


def test_scan_everything_unfinished_with_nothing_left(tmp_path, monkeypatch):
    from filecat import scan
    monkeypatch.setattr(everything, "list_shares", lister)
    monkeypatch.setattr(everything, "unfinished", lambda *a: ([], []))
    monkeypatch.setattr(scan, "run", lambda a: pytest.fail("nothing should be scanned"))
    assert cli.main(["scan-everything", "--unfinished", "--server", "nas-vm",
                     "--out", str(tmp_path / "c.sqlite")]) == 0
