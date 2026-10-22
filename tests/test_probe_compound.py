"""Compound documents (data/compound_formats.toml): standard structure stays
out of members, anomalies are stored with a reason."""
from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from filecat.options import ScanOptions
from filecat.probe import compound, probe_file


def _zip(fixture_dir: Path, filename: str, entries: dict[str, bytes | str]) -> Path:
    p = fixture_dir / filename
    with zipfile.ZipFile(p, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return p


def _probe(p: Path, opts: ScanOptions | None = None):
    data = p.read_bytes()
    return probe_file(str(p), p.name, len(data), data[:8192], opts or ScanOptions())


DOCX = {
    "[Content_Types].xml": "<Types/>",
    "_rels/.rels": "<Relationships/>",
    "docProps/core.xml": "<cp:coreProperties/>",
    "docProps/app.xml": "<Properties/>",
    "word/document.xml": "<w:document/>",
    "word/styles.xml": "<w:styles/>",
    "word/_rels/document.xml.rels": "<Relationships/>",
    "word/media/image1.png": b"\x89PNG",
    "word/theme/theme1.xml": "<a:theme/>",
}


def test_shipped_config_loads_and_no_extension_is_claimed_twice():
    table = compound.rules()
    assert {"ooxml", "odf", "epub", "java", "x3_save"} <= {f.id for f in table.formats}
    seen: Counter[tuple[str, str]] = Counter()
    for f in table.formats:
        for ext in f.types:
            seen[(f.container, ext)] += 1
            assert ext not in table.archive_extensions, (f.id, ext)
    assert [k for k, n in seen.items() if n > 1] == []


@pytest.mark.parametrize("glob, path, hit", [
    ("word/**", "word/document.xml", True),
    ("word/**", "word/media/image1.png", True),
    ("word/**", "Word/Document.xml", True),           # case-insensitive
    ("**/vbaProject.bin", "vbaProject.bin", True),    # **/ matches no segment too
    ("**/vbaProject.bin", "xl/vbaProject.bin", True),
    ("*.kml", "doc.kml", True),
    ("*.kml", "files/doc.kml", False),                # * stays in one segment
    ("Object */**", "Object 1/content.xml", True),
    ("_rels/**", "word/_rels/x.rels", False),
])
def test_glob(glob, path, hit):
    assert bool(compound._glob_re(glob).match(path)) is hit


def test_standard_docx_stores_no_members(fixture_dir):
    r = _probe(_zip(fixture_dir, "Paper.docx", DOCX))
    assert r.kind == "document" and r.container == "zip"
    assert r.members == []
    c = r.probe["compound"]
    assert c["format"] == "ooxml" and c["entries"] == len(DOCX) and c["expected"] == len(DOCX)
    assert c["anomalies"] == 0 and "reasons" not in c and "marker_missing" not in c
    assert c["mime"].endswith("wordprocessingml.document")
    assert c["metadata_parts"] == ["docProps/core.xml", "docProps/app.xml"]
    assert r.probe["entry_count"] == len(DOCX) and r.probe["members_count"] == 0
    assert r.probe["entries"] == []


def test_docm_anomalies_are_stored_with_reasons(fixture_dir):
    entries = {**DOCX,
               "word/vbaProject.bin": b"\xd0\xcf\x11\xe0",
               "word/embeddings/oleObject1.bin": b"ole",
               "word/media/setup.exe": b"MZ",             # under an expected path, still an exe
               "payload/notes.txt": "hidden"}             # outside every expected path
    r = _probe(_zip(fixture_dir, "Report.docm", entries))
    reasons = {m["path"]: m["anomaly"] for m in r.members}
    assert reasons == {"word/vbaProject.bin": "macros",
                       "word/embeddings/oleObject1.bin": "embedded_object",
                       "word/media/setup.exe": "embedded_exe",
                       "payload/notes.txt": "unexpected"}
    c = r.probe["compound"]
    assert c["anomalies"] == 4 and c["expected"] == len(DOCX)
    assert c["reasons"] == {"macros": 1, "embedded_object": 1, "embedded_exe": 1, "unexpected": 1}
    assert r.probe["members_count"] == 4


def test_expand_compound_keeps_every_entry(fixture_dir):
    entries = {**DOCX, "word/vbaProject.bin": b"x"}
    r = _probe(_zip(fixture_dir, "Macro.docm", entries), ScanOptions(expand_compound=True))
    assert len(r.members) == len(entries)
    assert [m["path"] for m in r.members if "anomaly" in m] == ["word/vbaProject.bin"]


def test_zip_extension_always_expands(fixture_dir):
    r = _probe(_zip(fixture_dir, "unpacked-docx.zip", DOCX))
    assert r.kind == "archive" and "compound" not in r.probe
    assert len(r.members) == len(DOCX)


def test_markers_identify_a_renamed_file(fixture_dir):
    r = _probe(_zip(fixture_dir, "attachment.bin", DOCX))
    assert r.kind == "document" and r.probe["compound"]["format"] == "ooxml"
    assert "mime" not in r.probe["compound"]                  # .bin names no type
    model = {"[Content_Types].xml": "<Types/>", "_rels/.rels": "<R/>", "3D/3dmodel.model": "<model/>"}
    r = _probe(_zip(fixture_dir, "print.bin", model))
    assert r.probe["compound"]["format"] == "model_3mf" and r.kind == "mesh"


def test_extension_without_its_markers_is_flagged(fixture_dir):
    r = _probe(_zip(fixture_dir, "odd.docx", {"word/document.xml": "<w/>"}))
    assert r.probe["compound"]["marker_missing"] is True


def test_fat_jar_nested_jars_are_expected_but_an_exe_is_not(fixture_dir):
    r = _probe(_zip(fixture_dir, "app.jar", {
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
        "BOOT-INF/lib/dep.jar": b"PK",
        "com/example/Main.class": b"\xca\xfe\xba\xbe",
        "bin/helper.exe": b"MZ",
    }))
    assert r.kind == "archive"
    assert [(m["path"], m["anomaly"]) for m in r.members] == [("bin/helper.exe", "embedded_exe")]
    assert r.probe["compound"]["metadata_parts"] == ["META-INF/MANIFEST.MF"]


def test_odt_and_epub_are_documents(fixture_dir):
    odt = _probe(_zip(fixture_dir, "letter.odt", {
        "mimetype": "application/vnd.oasis.opendocument.text", "META-INF/manifest.xml": "<m/>",
        "content.xml": "<c/>", "meta.xml": "<m/>", "Basic/Standard/Module1.xml": "<s/>"}))
    assert odt.kind == "document"
    assert [(m["path"], m["anomaly"]) for m in odt.members] == [("Basic/Standard/Module1.xml", "macros")]
    epub = _probe(_zip(fixture_dir, "book.epub", {
        "mimetype": "application/epub+zip", "META-INF/container.xml": "<c/>",
        "OEBPS/content.opf": "<package/>", "OEBPS/ch1.xhtml": "<html/>"}))
    assert epub.kind == "document" and epub.members == []
    assert epub.probe["compound"]["metadata_parts"] == ["OEBPS/content.opf"]


def _tar_gz(p: Path) -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        info = tarfile.TarInfo("inner.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"hello"))
    p.write_bytes(gzip.compress(raw.getvalue()))


def test_gzip_compound_format_is_not_expanded(fixture_dir):
    p = fixture_dir / "game.sav"
    _tar_gz(p)
    r = _probe(p)
    assert r.members is None and r.probe["compound"]["format"] == "x3_save"
    plain = fixture_dir / "game.tgz"
    _tar_gz(plain)
    assert len(_probe(plain).members) == 1


def test_names_beat_the_archive_extension(fixture_dir):
    assert compound.for_file("level.dat", "gzip").id == "nbt"
    assert compound.for_file("level.dat", "zip") is None
    assert compound.for_file("01.dat", "gzip") is None


def test_by_mime():
    assert compound.rules().by_mime("application/EPUB+zip").id == "epub"
    assert compound.rules().by_mime("application/zip") is None


def test_parse_rejects_bad_config():
    with pytest.raises(ValueError, match="version"):
        compound.parse({"version": 2})
    with pytest.raises(ValueError, match="container"):
        compound.parse({"version": 1, "compound": {"x": {"container": "rar", "types": {"x": "a/b"}}}})
