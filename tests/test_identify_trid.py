"""Tests for filecat.identify.trid: the --trid-defs PATH loader."""
from __future__ import annotations

import zipfile

import pytest

from filecat.identify import trid
from filecat.identify import Identifier
from filecat.options import ScanOptions

TRID_XML = """<?xml version="1.0"?>
<FileType>
  <Info>
    <Ext>DOC</Ext>
    <FileTypeName>Microsoft Word document</FileTypeName>
  </Info>
</FileType>
"""


def test_tab_file(fixture_dir):
    p = fixture_dir / "defs.txt"
    p.write_text("# comment line\ndoc\tMicrosoft Word document\ntxt\tPlain text file\n",
                 encoding="utf-8")
    mapping = trid.load_defs(str(p))
    assert mapping["doc"] == "Microsoft Word document"
    assert mapping["txt"] == "Plain text file"


def test_trid_xml_single_file(fixture_dir):
    p = fixture_dir / "doc.trid.xml"
    p.write_text(TRID_XML, encoding="utf-8")
    mapping = trid.load_defs(str(p))
    assert mapping["doc"] == "Microsoft Word document"


def test_trid_xml_directory_package(fixture_dir):
    d = fixture_dir / "defs"
    d.mkdir()
    (d / "doc.trid.xml").write_text(TRID_XML, encoding="utf-8")
    mapping = trid.load_defs(str(d))
    assert mapping["doc"] == "Microsoft Word document"


def test_trid_xml_zip_package(fixture_dir):
    zpath = fixture_dir / "defs.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("doc.trid.xml", TRID_XML)
    mapping = trid.load_defs(str(zpath))
    assert mapping["doc"] == "Microsoft Word document"


def test_unrecognised_format_raises(fixture_dir):
    p = fixture_dir / "garbage.bin"
    p.write_bytes(b"\x00\x01\x02\x03 not a defs file")
    with pytest.raises(ValueError):
        trid.load_defs(str(p))


def test_identifier_stores_trid_desc(fixture_dir):
    p = fixture_dir / "defs.txt"
    p.write_text("doc\tMicrosoft Word document\n", encoding="utf-8")
    idf = Identifier(ScanOptions(trid_defs=str(p)))
    assert idf.scan_errors == []
    r = idf.identify(None, "report.doc", None, kind="document")
    assert r["probe"]["trid_desc"] == "Microsoft Word document"


def test_identifier_records_one_scan_error_for_bad_defs(fixture_dir):
    p = fixture_dir / "garbage.bin"
    p.write_bytes(b"\x00\x01 nonsense")
    idf = Identifier(ScanOptions(trid_defs=str(p)))
    assert len(idf.scan_errors) == 1
    assert idf.scan_errors[0]["stage"] == "trid"
    # Name layer is unaffected.
    assert idf.by_name("thing.txt")["mime_glob"] == "text/plain"
