"""The one filecat/agent version agrees in every file that carries it (scripts/version.py)."""
import shutil

from scripts import version


def test_every_place_agrees():
    assert version.check(None) == []


def test_set_rewrites_every_place_and_keeps_line_endings(tmp_path, monkeypatch):
    for rel, _ in version.PLACES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(version.ROOT / rel, tmp_path / rel)
    crlf = tmp_path / "src/filecat/__init__.py"
    crlf.write_bytes(crlf.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    monkeypatch.setattr(version, "ROOT", tmp_path)

    version.set_version("9.8.7")

    assert set(version.versions().values()) == {"9.8.7"}
    assert version.check("v9.8.7") == []
    assert version.check("v9.8.8") != []
    assert b"\r\n" in crlf.read_bytes() and b"\r\r" not in crlf.read_bytes()
