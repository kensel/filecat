"""Tests for filecat.identify.Identifier: the winner rule, identify_basis,
and the optional pronom / trid / magika identifiers.

These call Identifier directly (not through the probe/scan pipeline, which
other modules own in parallel); `kind` is supplied as the built-in probe
would have already decided it.
"""
from __future__ import annotations

import struct

import pytest

from filecat.identify import Identifier
from filecat.options import ScanOptions


def _png_bytes() -> bytes:
    data = struct.pack(">II", 4, 4) + bytes([8, 2, 0, 0, 0])
    ihdr = struct.pack(">I", len(data)) + b"IHDR" + data + struct.pack(">I", 0)
    return bytes.fromhex("89504e470d0a1a0a") + ihdr


def _ole_bytes() -> bytes:
    hdr = bytearray(512)
    hdr[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    hdr[24:26] = (0x003E).to_bytes(2, "little")
    hdr[26:28] = (0x0003).to_bytes(2, "little")
    hdr[28:30] = b"\xfe\xff"
    hdr[30:32] = (9).to_bytes(2, "little")
    hdr[32:34] = (6).to_bytes(2, "little")
    return bytes(hdr) + bytes(8192 - 512)


@pytest.fixture
def idf() -> Identifier:
    return Identifier(ScanOptions())


def test_note_pdf_with_png_bytes_disagrees(idf: Identifier):
    r = idf.identify(None, "note.pdf", _png_bytes(), kind="image")
    assert r["probe"]["mime_glob"] == "application/pdf"
    assert r["probe"]["mime_magic"] == "image/png"
    assert r["probe"]["identify_basis"] == "disagree"
    assert r["mime"] == "image/png"


def test_note_pdf_identify_never_uses_name_only(idf: Identifier):
    r = idf.identify(None, "note.pdf", None, kind="document")
    assert r["probe"]["identify_basis"] == "name"
    assert r["mime"] == "application/pdf"
    assert "mime_magic" not in r["probe"]


def test_docx_description_from_name_alone(idf: Identifier):
    r = idf.by_name("report.docx")
    assert r["mime_glob"] == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert "Word" in r["mime_glob_desc"]


def test_plain_text_agrees(idf: Identifier):
    r = idf.identify(None, "notes.txt", b"hello world\nsecond line\n", kind="text")
    assert r["probe"]["identify_basis"] == "agree"
    assert r["mime"] == "text/plain"


def test_no_glob_png_bytes_is_basis_bytes(idf: Identifier):
    r = idf.identify(None, "mystery.no-such-ext", _png_bytes(), kind="image")
    assert "mime_glob" not in r["probe"]
    assert r["probe"]["mime_magic"] == "image/png"
    assert r["probe"]["identify_basis"] == "bytes"
    assert r["mime"] == "image/png"


def test_ole_doc_stays_msword(idf: Identifier):
    r = idf.identify(None, "report.doc", _ole_bytes(), kind="document")
    assert r["mime"] == "application/msword"
    assert r["probe"]["identify_basis"] == "agree"
    # libmagic's raw "CDFV2" (or similar) must be normalised to the
    # shared-mime-info canonical OLE storage type for the subclass check
    # to apply at all.
    assert r["probe"]["mime_magic"] == "application/x-ole-storage"


def test_glob_more_specific_than_generic_text_plain_magic(idf: Identifier):
    # No shebang -> libmagic reports generic text/plain, but the glob
    # (text/x-python) is a subclass of text/plain, so it wins and the
    # basis is still "agree".
    r = idf.identify(None, "plain.py", b"x = 1\nprint(x)\n", kind="text")
    assert r["probe"]["mime_glob"] == "text/x-python"
    assert r["probe"]["mime_magic"] == "text/plain"
    assert r["probe"]["identify_basis"] == "agree"
    assert r["mime"] == "text/x-python"


def test_missing_sf_records_one_scan_error_name_layer_intact():
    idf2 = Identifier(ScanOptions(pronom=True))
    assert len(idf2.scan_errors) == 1
    assert idf2.scan_errors[0]["stage"] == "pronom"
    # Name layer still works.
    assert idf2.by_name("thing.txt") == {"mime_glob": "text/plain",
                                          "mime_glob_desc": "Plain text document",
                                              "mime_glob_source": "freedesktop"}
    # identify() still works end to end (pronom keys simply absent).
    r = idf2.identify(None, "thing.txt", b"hello\n", kind="text")
    assert r["mime"] == "text/plain"
    assert not any(k.startswith("pronom_") for k in r["probe"])


def test_magika_overrides_mime_only_with_no_other_result(fixture_dir):
    pytest.importorskip("magika")
    f = fixture_dir / "mystery.bin"
    payload = (b"\x00\x01\x02\x03binary junk here" * 20)
    f.write_bytes(payload)
    idf2 = Identifier(ScanOptions(magika=True))

    # head provided: the bytes layer already resolved a mime (bytes/weak
    # octet-stream), so Magika must not override it even at a high score.
    r = idf2.identify(str(f), f.name, payload[:8192], kind="unknown")
    assert "magika_label" in r["probe"]
    assert "magika_score" in r["probe"]

    # No name glob and no byte identification at all (head=None): Magika
    # is the only source of a mime, so a confident score may set it.
    r2 = idf2.identify(str(f), f.name, None, kind="unknown")
    assert "magika_label" in r2["probe"]
    if r2["probe"]["magika_score"] >= 0.5:
        assert r2["mime"] is not None
    else:
        assert r2["mime"] is None


def test_equal_weight_glob_tie_kept_and_broken_by_size():
    """'*.vhd' is both VHDL source and a VHD disk image at the same weight."""
    idf = Identifier(ScanOptions())
    small = idf.by_name("design.vhd", size=2_000)
    assert small["mime_glob"] == "text/x-vhdl"
    assert set(small["mime_glob_alternatives"]) == {"text/x-vhdl", "application/x-vhd-disk"}
    big = idf.by_name("disk.vhd", size=40 * 1024 ** 3)
    assert big["mime_glob"] == "application/x-vhd-disk"
    assert "mime_glob_alternatives" not in idf.by_name("report.docx")
