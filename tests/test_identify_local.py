"""Local filecat-globs.tsv layered on the freedesktop globs."""
from __future__ import annotations

import time

from filecat.identify import Identifier
from filecat.identify.mimeglob import DATA_PATH, MimeDB, get_mime_db
from filecat.options import ScanOptions


def test_mpq_local_type_description_and_source():
    idf = Identifier(ScanOptions())
    p = idf.by_name("BroodWar.mpq")
    assert p["mime_glob"] == "application/x-mpq"
    assert "MPQ" in p["mime_glob_desc"]
    assert p["mime_glob_source"] == "filecat"
    assert "mime_glob_alternatives" not in p


def test_cat_local_overrides_freedesktop_but_keeps_it_visible():
    idf = Identifier(ScanOptions())
    p = idf.by_name("01.cat", probe_format="x3-cat")
    assert p["mime_glob"] == "application/x-x3-catalog"
    assert p["mime_glob_source"] == "filecat"
    assert "X3" in p["mime_glob_desc"]
    assert "application/vnd.ms-pki.seccat" in p["mime_glob_alternatives"]


def test_freedesktop_match_reports_freedesktop_source():
    p = Identifier(ScanOptions()).by_name("report.docx")
    assert p["mime_glob_source"] == "freedesktop"
    assert "mime_glob_alternatives" not in p


def test_pck_is_a_multi_meaning_entry():
    p = Identifier(ScanOptions()).by_name("PlayerStats.pck")
    assert p["mime_glob"] == "application/x-pck"
    desc = p["mime_glob_desc"]
    assert "X3" in desc and "Godot" in desc and "pickle" in desc and "others" in desc


def test_local_types_use_subclass_logic_and_comment():
    db = get_mime_db()
    assert db.comment("application/x-mpq")
    assert db.is_subclass("application/x-mpq", "application/octet-stream")
    assert db.is_subclass("application/x-w3x", "application/x-mpq")
    # With magic saying "mpq" the glob type agrees; with a ZIP it would not.
    idf = Identifier(ScanOptions())
    assert idf._resolve("application/x-w3x", "application/x-mpq") == ("application/x-w3x", "agree")


def test_equal_weight_tie_lists_both(tmp_path):
    tsv = tmp_path / "t.tsv"
    # fd has *.vhd at weight 50 (two types); a different local type at 50 joins the tie.
    tsv.write_text("*.vhd\tapplication/x-other-vhd\tOther VHD\t50\t\n", encoding="utf-8")
    idf = Identifier(ScanOptions(), local_tsv=str(tsv))
    p = idf.by_name("disk.vhd", size=10)
    assert "application/x-other-vhd" in p["mime_glob_alternatives"]
    assert "text/x-vhdl" in p["mime_glob_alternatives"]


def test_lower_local_weight_loses(tmp_path):
    tsv = tmp_path / "t.tsv"
    tsv.write_text("*.docx\tapplication/x-foo\tFoo\t10\t\n", encoding="utf-8")
    p = Identifier(ScanOptions(), local_tsv=str(tsv)).by_name("a.docx")
    assert p["mime_glob_source"] == "freedesktop"
    assert "mime_glob_alternatives" not in p


def test_malformed_lines_reported_once_and_skipped(tmp_path):
    tsv = tmp_path / "bad.tsv"
    tsv.write_text(
        "# comment\n"
        "\n"
        "*.good1\tapplication/x-good1\tGood one\t50\tnote\n"
        "only-two-columns\tapplication/x-x\n"
        "*.badweight\tapplication/x-bw\tBad\tfifty\t\n"
        "*.badmime\tnotamime\tBad\t50\t\n"
        "*.good2\tapplication/x-good2\tGood two\t50\t\n",
        encoding="utf-8")
    idf = Identifier(ScanOptions(), local_tsv=str(tsv))
    errs = [e for e in idf.scan_errors if e["stage"] == "mime_local"]
    assert len(errs) == 1
    assert "3 malformed" in errs[0]["message"]
    assert idf.by_name("x.good1")["mime_glob"] == "application/x-good1"
    assert idf.by_name("x.good2")["mime_glob"] == "application/x-good2"
    assert "mime_glob" not in idf.by_name("x.badweight")
    # a second lookup / identify does not add more errors
    idf.by_name("x.good1")
    assert len([e for e in idf.scan_errors if e["stage"] == "mime_local"]) == 1


def test_shipped_table_is_well_formed_and_load_is_fast():
    t0 = time.perf_counter()
    db = MimeDB(DATA_PATH)
    total = time.perf_counter() - t0
    assert db.local_errors == []
    assert db.local_entries >= 80
    t0 = time.perf_counter()
    db2 = MimeDB(DATA_PATH, local_tsv=None)
    base = time.perf_counter() - t0
    assert db2.local_entries == 0
    assert total - base < 0.25


def test_x3_catalog_needs_probe_confirmation():
    """A .cat is a Windows security catalog unless the probe decoded an X3 index."""
    from filecat.identify import Identifier
    from filecat.options import ScanOptions
    idf = Identifier(ScanOptions())
    plain = idf.by_name("Package~31bf3856ad364e35~amd64.cat")
    assert plain["mime_glob"] == "application/vnd.ms-pki.seccat"
    assert "application/x-x3-catalog" in plain["mime_glob_alternatives"]
    x3 = idf.by_name("01.cat", probe_format="x3-cat")
    assert x3["mime_glob"] == "application/x-x3-catalog"
    assert x3["mime_glob_source"] == "filecat"
