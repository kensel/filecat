"""Plain tar, tar.gz / tar.bz2 / tar.xz member listing, xz index, gzip trailer."""
from __future__ import annotations

import gzip
import io
import lzma
import tarfile
from pathlib import Path

from filecat.options import ScanOptions
from filecat.probe import probe_file


def _probe(path: Path, opts: ScanOptions | None = None):
    with open(path, "rb") as f:
        head = f.read(8192)
    return probe_file(str(path), path.name, path.stat().st_size, head, opts or ScanOptions())


def _make_tar(path: Path, mode: str = "w", fmt=tarfile.GNU_FORMAT, n: int = 20):
    with tarfile.open(path, mode, format=fmt) as tf:
        d = tarfile.TarInfo("proj")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        for i in range(n):
            data = (b"line %d\n" % i) * 400
            ti = tarfile.TarInfo(f"proj/f{i:02d}.lua")
            ti.size = len(data)
            ti.mtime = 1_600_000_000
            tf.addfile(ti, io.BytesIO(data))
        ln = tarfile.TarInfo("proj/link")
        ln.type = tarfile.SYMTYPE
        ln.linkname = "f00.lua"
        tf.addfile(ln)


def test_plain_tar(fixture_dir):
    p = fixture_dir / "a.tar"
    _make_tar(p, fmt=tarfile.USTAR_FORMAT)
    r = _probe(p)
    assert (r.kind, r.container, r.probe["format"]) == ("archive", "plain", "tar")
    assert len(r.members) == 22
    assert r.members[0]["type"] == "dir"
    assert r.members[1] == {**r.members[1], "path": "proj/f00.lua", "size": 2800, "type": "file",
                            "role": "script", "mtime_ns": 1_600_000_000 * 10**9}
    assert r.members[-1]["type"] == "symlink" and r.members[-1]["link_target"] == "f00.lua"
    assert r.probe["members_count"] == 22 and "members_truncated" not in r.probe


def test_tar_gnu_longname_and_pax_path(fixture_dir):
    long = "d/" + "x" * 150 + "/file.txt"
    for fmt, name in ((tarfile.GNU_FORMAT, "g.tar"), (tarfile.PAX_FORMAT, "p.tar")):
        p = fixture_dir / name
        with tarfile.open(p, "w", format=fmt) as tf:
            ti = tarfile.TarInfo(long)
            ti.size = 3
            tf.addfile(ti, io.BytesIO(b"abc"))
            tj = tarfile.TarInfo("after.txt")
            tf.addfile(tj)
        r = _probe(p)
        assert [m["path"] for m in r.members] == [long, "after.txt"], name
        assert r.members[0]["size"] == 3


def test_tar_max_members(fixture_dir):
    p = fixture_dir / "m.tar"
    _make_tar(p)
    r = _probe(p, ScanOptions(max_members=5))
    assert len(r.members) == 5 and r.probe["members_truncated"] is True


def test_tar_reads_headers_only(fixture_dir, monkeypatch):
    p = fixture_dir / "big.tar"
    with tarfile.open(p, "w") as tf:
        for i in range(10):
            ti = tarfile.TarInfo(f"f{i}")
            ti.size = 2_000_000
            tf.addfile(ti, io.BytesIO(b"\0" * 2_000_000))
    read = [0]
    real = io.open

    class C:
        def __init__(self, f):
            self.f = f

        def read(self, n=-1):
            d = self.f.read(n)
            read[0] += len(d)
            return d

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.f.close()

        def __getattr__(self, k):
            return getattr(self.f, k)

    import builtins
    monkeypatch.setattr(builtins, "open", lambda f, m="r", *a, **k: C(real(f, m, *a, **k)) if str(f) == str(p) and "b" in m else real(f, m, *a, **k))
    r = _probe(p)
    monkeypatch.setattr(builtins, "open", real)
    assert len(r.members) == 10
    assert read[0] < 20_000   # 10 headers + end blocks, not 20 MB


def test_tar_gz_complete_truncated_deep(fixture_dir):
    p = fixture_dir / "a.tar.gz"
    _make_tar(p, "w:gz")
    r = _probe(p)
    assert (r.kind, r.container, r.probe["format"]) == ("archive", "gzip", "tar")
    assert len(r.members) == 22 and "members_truncated" not in r.probe
    assert r.probe["gzip"]["original_size"] == len(gzip.decompress(p.read_bytes()))

    small = _probe(p, ScanOptions(archive_scan_cap=10_000))
    assert small.probe["members_truncated"] is True
    assert 0 < len(small.members) < 22
    assert small.probe["scan_stopped_at"] >= 10_000

    deep = _probe(p, ScanOptions(archive_scan_cap=10_000, deep_archives=True))
    assert len(deep.members) == 22 and "members_truncated" not in deep.probe
    assert "scan_stopped_at" not in deep.probe


def test_tar_gz_concatenated_members(fixture_dir):
    raw = fixture_dir / "raw.tar"
    _make_tar(raw)
    data = raw.read_bytes()
    cut = 512 * 7
    p = fixture_dir / "cat.tar.gz"
    p.write_bytes(gzip.compress(data[:cut]) + gzip.compress(data[cut:]))
    r = _probe(p)
    assert len(r.members) == 22


def test_tar_bz2_and_xz(fixture_dir):
    for mode, name, container in (("w:bz2", "a.tar.bz2", "bzip2"), ("w:xz", "a.tar.xz", "xz")):
        p = fixture_dir / name
        _make_tar(p, mode)
        r = _probe(p)
        assert (r.kind, r.container, r.probe["format"]) == ("archive", container, "tar"), name
        assert len(r.members) == 22, name
        t = _probe(p, ScanOptions(archive_scan_cap=10_000))
        assert t.probe["members_truncated"] is True and t.probe["scan_stopped_at"] >= 10_000, name
        d = _probe(p, ScanOptions(archive_scan_cap=10_000, deep_archives=True))
        assert len(d.members) == 22, name


def test_xz_index_and_plain_content(fixture_dir):
    p = fixture_dir / "t.txt.xz"
    payload = b"hello xz\n" * 1000
    p.write_bytes(lzma.compress(payload))
    r = _probe(p)
    assert r.container == "xz" and r.kind == "text"
    assert r.probe["xz"] == {"uncompressed_size": len(payload), "block_count": 1}
    assert r.members is None


def test_bzip2_text(fixture_dir):
    import bz2
    p = fixture_dir / "t.txt.bz2"
    p.write_bytes(bz2.compress(b"hello bz\n" * 100))
    r = _probe(p)
    assert r.container == "bzip2" and r.kind == "text"


def test_gzip_original_name_and_size(fixture_dir):
    p = fixture_dir / "o.gz"
    payload = b"abc\n" * 100
    buf = io.BytesIO()
    with gzip.GzipFile(filename="orig-name.txt", fileobj=buf, mode="wb", mtime=1) as g:
        g.write(payload)
    p.write_bytes(buf.getvalue())
    r = _probe(p)
    assert r.probe["gzip"]["original_name"] == "orig-name.txt"
    assert r.probe["gzip"]["original_size"] == len(payload)


def _with_checksum(block: bytearray) -> bytes:
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\x00 " % sum(block)
    return bytes(block)


def test_v7_tar_detected_but_random_bytes_with_a_matching_checksum_are_not():
    from filecat.probe import tarball
    v7 = bytearray(512)
    v7[0:5] = b"a.txt"
    v7[100:108] = b"000644 \x00"
    v7[124:136] = b"00000000012\x00"
    v7[136:148] = b"14000000000\x00"
    assert tarball.detect(_with_checksum(v7) + bytes(512))
    # Binary junk whose checksum happens to add up (a damaged PNG on a NAS
    # was once listed as a tar member with an mtime of 3.9e37 ns).
    junk = bytearray((i * 37 + 11) % 256 for i in range(512))
    junk[257:265] = b"\x89PNG\r\n\x1a\n"
    junk = _with_checksum(junk)
    assert tarball._checksum_valid(junk) and not tarball.detect(junk + bytes(512))
