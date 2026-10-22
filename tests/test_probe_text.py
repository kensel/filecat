"""Encoding, newlines, sample, CSV/semicolon, XML-declared-encoding, scene-text,
lang.dat. See file-catalog-requirements.md 'Encoding and newlines' and the
fixture table.
"""
from __future__ import annotations

from pathlib import Path

from filecat.options import ScanOptions
from filecat.probe import probe_file


def _probe(fixture_dir: Path, filename: str, data: bytes, opts: ScanOptions | None = None):
    p = fixture_dir / filename
    p.write_bytes(data)
    return probe_file(str(p), filename, len(data), data[:8192], opts or ScanOptions())


def test_latin1_crlf(fixture_dir):
    # 0xE9 is not valid as a UTF-8 continuation byte on its own -> forces latin-1.
    data = "caf\xe9 au lait\r\nsecond line\r\n".encode("latin-1")
    r = _probe(fixture_dir, "latin1.txt", data)
    assert r.kind == "text"
    assert r.encoding["detected"] == "latin-1"
    assert r.newlines == "crlf"


def test_utf8_bom_lf(fixture_dir):
    data = b"\xef\xbb\xbfhello\nworld\n"
    r = _probe(fixture_dir, "bom.txt", data)
    assert r.kind == "text"
    assert r.encoding["bom"] == "utf-8"
    assert r.newlines == "lf"


def test_mixed_newlines(fixture_dir):
    data = b"one\r\ntwo\nthree\r\n"
    r = _probe(fixture_dir, "mixed.txt", data)
    assert r.newlines == "mixed"


def test_newlines_cr_only(fixture_dir):
    data = b"one\rtwo\rthree"
    r = _probe(fixture_dir, "cr.txt", data)
    assert r.newlines == "cr"


def test_newlines_none(fixture_dir):
    data = b"no line breaks at all"
    r = _probe(fixture_dir, "none.txt", data)
    assert r.newlines == "none"


def test_xml_declares_utf8_but_bytes_are_latin1(fixture_dir):
    data = b'<?xml version="1.0" encoding="UTF-8"?>\n<note>caf\xe9</note>\n'
    r = _probe(fixture_dir, "note.xml", data)
    assert r.kind == "text"
    assert r.encoding["detected"] == "latin-1"
    assert r.encoding["declared"] == "UTF-8"
    assert r.encoding["declared_matches"] is False


def test_xml_declared_encoding_matches(fixture_dir):
    data = '<?xml version="1.0" encoding="UTF-8"?>\n<note>plain ascii</note>\n'.encode("utf-8")
    r = _probe(fixture_dir, "ok.xml", data)
    assert r.encoding["declared"] == "UTF-8"
    assert r.encoding["declared_matches"] is True


def test_sample_truncated(fixture_dir):
    data = ("x" * 10_000).encode("utf-8")
    r = _probe(fixture_dir, "big.txt", data)
    assert r.kind == "text"
    assert r.sample_truncated is True
    assert len(r.sample.encode("utf-8")) <= 4096


def test_csv_detection(fixture_dir):
    data = b"a,b,c\n1,2,3\n4,5,6\n"
    r = _probe(fixture_dir, "table.csv", data)
    assert r.kind == "data"
    assert r.probe["format"] == "csv"
    assert r.probe["separator"] == "comma"
    assert r.probe["fields"] == 3
    assert r.probe["records"] == 2


def test_semicolon_table(fixture_dir):
    data = b"version;count;\n1;5;\n2;9;\n"
    r = _probe(fixture_dir, "table.dat.txt", data)
    assert r.kind == "data"
    assert r.probe["format"] == "semicolon"
    assert r.probe["separator"] == "semicolon"
    assert r.probe["records"] == 2


def test_semicolon_fields_count_header(fixture_dir):
    data = b"fields;count;\nx;1;\n"
    r = _probe(fixture_dir, "fields.txt", data)
    assert r.kind == "data"
    assert r.probe["format"] == "semicolon"


def test_scene_text(fixture_dir):
    data = b"VER:7\nsome scene content\n"
    r = _probe(fixture_dir, "scene.pbd", data)
    assert r.kind == "mesh"
    assert r.probe["format"] == "scene-text"
    assert r.probe["scene_version"] == 7


def test_lang_dat(fixture_dir):
    data = b"42\n"
    r = _probe(fixture_dir, "lang.dat", data)
    assert r.kind == "text"
    assert r.probe["language_id"] == 42


def test_plain_text_no_refinement(fixture_dir):
    data = b"just an ordinary line of text\nwith a second line\n"
    r = _probe(fixture_dir, "plain.txt", data)
    assert r.kind == "text"
    assert "format" not in r.probe


def test_unknown_mostly_printable_gets_sample(fixture_dir):
    import random
    from filecat.options import ScanOptions
    from filecat.probe import probe_file
    data = b"CFGv2\x00name=alpha\x00size=12\x00mode=fast\x00" * 20
    p = fixture_dir / "settings.zzq"
    p.write_bytes(data)
    r = probe_file(str(p), p.name, len(data), data[:8192], ScanOptions())
    assert r.kind == "unknown"
    assert r.probe["sample_basis"] == "printable"
    assert "name=alpha" in r.sample
    noise = random.Random(7).randbytes(2048)
    p2 = fixture_dir / "noise.bin"
    p2.write_bytes(noise)
    r2 = probe_file(str(p2), p2.name, len(noise), noise, ScanOptions())
    assert r2.kind == "unknown" and r2.sample is None


def test_x3_bodyfile_text_is_mesh(fixture_dir):
    from filecat.options import ScanOptions
    from filecat.probe import probe_file
    data = b"// EGOSOFT Bodyfile\r\n// exported\r\nMATERIAL5: 1; 2; 3;\r\n"
    p = fixture_dir / "ship.bod"
    p.write_bytes(data)
    r = probe_file(str(p), p.name, len(data), data, ScanOptions())
    assert r.kind == "mesh" and r.probe["format"] == "x3-bodyfile"
