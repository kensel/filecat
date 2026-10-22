"""ZIP listing, OOXML -> document, gzip and gzip_xored + inflate-and-classify.

See file-catalog-requirements.md 'Probe order' steps 5-6 and the fixture table.
"""
from __future__ import annotations

import gzip
import io
import struct
import zipfile
import zlib
from pathlib import Path

from filecat.options import ScanOptions
from filecat.probe import ProbeResult, archive, probe_file


def _probe(fixture_dir: Path, filename: str, data: bytes, opts: ScanOptions | None = None):
    p = fixture_dir / filename
    p.write_bytes(data)
    with open(p, "rb") as f:
        head = f.read(8192)
    return probe_file(str(p), filename, len(data), head, opts or ScanOptions())


def test_zip_two_entries(fixture_dir):
    zpath = fixture_dir / "two.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("alpha.txt", "hello")
        zf.writestr("beta.txt", "world")
    data = zpath.read_bytes()
    r = _probe(fixture_dir, "two.zip", data)
    assert r.kind == "archive"
    assert r.container == "zip"
    assert r.probe["entry_count"] == 2
    assert "alpha.txt" in r.probe["entries"]
    assert "beta.txt" in r.probe["entries"]


def test_zip_ooxml_is_document(fixture_dir):
    zpath = fixture_dir / "fake.docx"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<document/>")
    data = zpath.read_bytes()
    r = _probe(fixture_dir, "fake.docx", data)
    assert r.kind == "document"
    assert r.container == "zip"


def test_zip_list_cap(fixture_dir):
    zpath = fixture_dir / "many.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for i in range(5):
            zf.writestr(f"f{i}.txt", "x")
    data = zpath.read_bytes()
    r = _probe(fixture_dir, "many.zip", data, ScanOptions(list_zip_cap=2))
    assert len(r.probe["entries"]) == 2
    assert r.probe["members_count"] == 5      # members stay full; only the preview is capped
    assert len(r.members) == 5
    assert "members_truncated" not in r.probe


def test_zip_member_rows(fixture_dir):
    zpath = fixture_dir / "rich.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("a/", "")
        zf.writestr("a/plain.txt", "x" * 1000, compress_type=zipfile.ZIP_STORED)
        zf.writestr("a/packed.lua", "y" * 1000, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("a/héllo-日本.png", b"png")
    r = _probe(fixture_dir, "rich.zip", zpath.read_bytes())
    rows = {m["path"]: m for m in r.members}
    assert [m["index"] for m in r.members] == [0, 1, 2, 3]
    assert rows["a/"]["is_dir"] is True and "is_dir" not in rows["a/plain.txt"]
    assert rows["a/plain.txt"]["method"] == "stored" and rows["a/plain.txt"]["csize"] == 1000
    assert rows["a/packed.lua"]["method"] == "deflated" and rows["a/packed.lua"]["csize"] < 1000
    assert rows["a/packed.lua"]["role"] == "script"
    assert rows["a/plain.txt"]["crc32"] == zlib.crc32(b"x" * 1000)
    assert "a/héllo-日本.png" in rows
    assert all("mtime_ns" in m for m in r.members)
    assert r.probe["members_size"] == 2003


def test_zip64(fixture_dir):
    zpath = fixture_dir / "z64.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        with zf.open("big.bin", "w", force_zip64=True) as f:
            f.write(b"z" * 300)
        with zf.open("two.bin", "w", force_zip64=True) as f:
            f.write(b"q" * 5)
    r = _probe(fixture_dir, "z64.zip", zpath.read_bytes())
    assert r.kind == "archive"
    assert [(m["path"], m["size"]) for m in r.members] == [("big.bin", 300), ("two.bin", 5)]


def test_zip_max_members(fixture_dir):
    zpath = fixture_dir / "cut.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for i in range(5):
            zf.writestr(f"f{i}.txt", "x")
    r = _probe(fixture_dir, "cut.zip", zpath.read_bytes(), ScanOptions(max_members=2))
    assert len(r.members) == 2
    assert r.probe["members_truncated"] is True
    assert r.probe["entry_count"] == 5


def _raw_zip_with_ut(name: bytes, data: bytes, unix_mtime: int) -> bytes:
    crc = zlib.crc32(data)
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 33, crc, len(data), len(data), len(name), 0)
    local += name + data
    ut = struct.pack("<HHBi", 0x5455, 5, 1, unix_mtime)
    cd = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 33, crc, len(data), len(data),
                     len(name), len(ut), 0, 0, 0, 0, 0) + name + ut
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(cd), len(local), 0)
    return local + cd + eocd


def test_zip_extended_timestamp_preferred(fixture_dir):
    r = _probe(fixture_dir, "ut.zip", _raw_zip_with_ut(b"ts.txt", b"hello", 1_700_000_000))
    assert r.members[0]["mtime_ns"] == 1_700_000_000 * 10**9   # not the 1980 DOS date


def test_zip_reads_only_directory(fixture_dir, monkeypatch):
    zpath = fixture_dir / "big.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_STORED) as zf:
        for i in range(5000):
            zf.writestr(f"d/file_{i:05d}.dat", b"x" * 4000)
    size = zpath.stat().st_size
    assert size > 20_000_000
    counters = []
    real_open = io.open

    class Counting:
        def __init__(self, f):
            self._f, self.total = f, 0

        def read(self, *a):
            data = self._f.read(*a)
            self.total += len(data)
            return data

        def __getattr__(self, name):
            return getattr(self._f, name)

    def tracking(file, mode="r", *a, **k):
        f = real_open(file, mode, *a, **k)
        if str(file) == str(zpath):
            f = Counting(f)
            counters.append(f)
        return f

    monkeypatch.setattr(io, "open", tracking)
    r = ProbeResult()
    archive.probe_zip(str(zpath), ScanOptions(), r)
    monkeypatch.setattr(io, "open", real_open)
    read = sum(c.total for c in counters)
    assert len(r.members) == 5000
    assert read < 1_000_000 < size       # central directory (~400 KB) only, not the ~20 MB of data


def test_gzip(fixture_dir):
    payload = b"hello gzip world\n" * 50
    data = gzip.compress(payload, mtime=12345)
    r = _probe(fixture_dir, "log.gz", data)
    assert r.container == "gzip"
    assert r.probe["gzip"]["method"] == 8
    assert r.probe["gzip"]["mtime"] == 12345
    assert r.kind == "text"


def _xor_wrap(gzip_bytes: bytes, key: int = 0x55) -> bytes:
    byte0 = key ^ 0xC8
    return bytes([byte0]) + bytes(b ^ key for b in gzip_bytes)


def test_gzip_xored(fixture_dir):
    payload = b"xored gzip payload\n" * 20
    inner = gzip.compress(payload)
    data = _xor_wrap(inner, key=0xA3)
    r = _probe(fixture_dir, "weird.bin", data)
    assert r.container == "gzip_xored"
    assert r.kind == "text"
    assert "gzip world" not in str(r.sample)  # sanity: real payload decoded, not garbage


def test_gzip_xsa3_save(fixture_dir):
    inner = b"XSA3" + b"SYSB" + b"TIME" + b"STOR" + b"PADDING" + b"/XSA"
    data = gzip.compress(inner)
    r = _probe(fixture_dir, "game.sav", data)
    assert r.kind == "save"
    assert r.probe["format"] == "xsa3"
    assert r.probe["tag_order"] == ["XSA3", "SYSB", "TIME", "STOR", "/XSA"]


def test_gzip_probe_stops_after_first_member(fixture_dir, monkeypatch):
    """A file that only starts with a gzip member (e.g. an X3 .dat whose first
    entry is packed) must not be read to its end for classification."""
    import builtins
    import gzip as _gzip
    from filecat.probe import archive as archive_mod
    from filecat.probe import probe_file
    from filecat.options import ScanOptions
    data = _gzip.compress(b"hello world\n") + b"\x00" * (32 * 1024 * 1024)
    p = fixture_dir / "big.bin"
    p.write_bytes(data)
    read_total = 0
    real_open = builtins.open

    class Counting:
        def __init__(self, f):
            self._f = f
        def read(self, n=-1):
            nonlocal read_total
            b = self._f.read(n)
            read_total += len(b)
            return b
        def __getattr__(self, name):
            return getattr(self._f, name)
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self._f.close()

    monkeypatch.setattr(archive_mod, "open", lambda *a, **k: Counting(real_open(*a, **k)), raising=False)
    r = probe_file(str(p), p.name, len(data), data[:8192], ScanOptions())
    assert r.container == "gzip"
    assert read_total < 4 * 1024 * 1024
