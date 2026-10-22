"""Tests for the vendored shared-mime-info parser: glob name lookup, the
alias/sub-class-of tables, and the byte-magic fallback matcher."""
from __future__ import annotations

import struct
import time

from filecat.identify.mimeglob import get_mime_db


def test_literal_name_beats_suffix():
    db = get_mime_db()
    # "core" is a literal glob (no extension); must not fall through to a
    # suffix/other pattern match.
    assert db.lookup_name("core") == "application/x-core"


def test_suffix_longest_match_wins():
    db = get_mime_db()
    assert db.lookup_name("archive.tar.gz") == "application/x-compressed-tar"
    assert db.lookup_name("plain.gz") == "application/gzip"


def test_docx_description_from_name_alone():
    db = get_mime_db()
    mime = db.lookup_name("report.docx")
    assert mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert "Word" in db.comment(mime)


def test_no_glob_match():
    db = get_mime_db()
    assert db.lookup_name("mystery.not-a-real-extension-xyz") is None


def test_alias_normalization():
    db = get_mime_db()
    assert db.canon("text/x-c") == "text/x-csrc"
    # A name with no alias entry resolves to itself.
    assert db.canon("application/pdf") == "application/pdf"


def test_subclass_rules_explicit_and_implicit():
    db = get_mime_db()
    # explicit sub-class-of in the XML
    assert db.is_subclass("application/msword", "application/x-ole-storage")
    assert db.is_subclass("image/svg+xml", "application/xml")
    # implicit: text/* is a subclass of text/plain
    assert db.is_subclass("text/x-python", "text/plain")
    assert not db.is_subclass("text/plain", "text/x-python")
    # implicit: everything is a subclass of application/octet-stream
    assert db.is_subclass("application/msword", "application/octet-stream")
    assert db.is_subclass("image/png", "application/octet-stream")
    assert not db.is_subclass("application/octet-stream", "image/png")


def _png_bytes() -> bytes:
    data = struct.pack(">II", 4, 4) + bytes([8, 2, 0, 0, 0])
    ihdr = struct.pack(">I", len(data)) + b"IHDR" + data + struct.pack(">I", 0)
    return bytes.fromhex("89504e470d0a1a0a") + ihdr


def test_guess_by_magic_png_and_zip():
    db = get_mime_db()
    assert db.guess_by_magic(_png_bytes())[0] == "image/png"
    zip_buf = b"PK\x03\x04" + b"\x00" * 64
    assert db.guess_by_magic(zip_buf)[0] == "application/zip"
    assert db.guess_by_magic(b"not a recognised header at all") is None


def test_magic_match_type_corroboration():
    db = get_mime_db()
    assert db.magic_match_type("image/png", _png_bytes())
    assert not db.magic_match_type("image/png", b"\x00" * 16)


def test_performance_construct_and_lookup():
    """Constructing the DB (parse once) plus 10k by_name lookups should be
    fast; this reports the timing rather than asserting a hard budget,
    since CI hardware varies."""
    t0 = time.perf_counter()
    db = get_mime_db()
    t1 = time.perf_counter()
    names = ["report.docx", "note.pdf", "archive.tar.gz", "script.py",
             "core", "unknown.xyzabc", "image.png", "Makefile"] * 1250
    assert len(names) == 10000
    for n in names:
        db.lookup_name(n)
    t2 = time.perf_counter()
    print(f"\nmimeglob: construct={t1 - t0:.4f}s, 10000 lookups={t2 - t1:.4f}s")
    # Generous ceiling: this should be a few hundredths of a second in
    # practice (see the printed timing above).
    assert (t2 - t1) < 5.0
