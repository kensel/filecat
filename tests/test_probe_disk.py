"""Disk-image probe: containers, partition tables, filesystems, ISO 9660.

Every fixture is built synthetically in the test's directory.
"""
from __future__ import annotations

import random
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

from filecat import cli
from filecat.identify import Identifier
from filecat.options import ScanOptions
from filecat.probe import probe_file

MiB = 1024 * 1024
SMALL = 1 * MiB       # bytes_read ceiling for header-only parses


def probe(path: Path, **opts):
    with open(path, "rb") as f:
        head = f.read(8192)
    return probe_file(str(path), path.name, path.stat().st_size, head, ScanOptions(**opts))


class Buf:
    def __init__(self, size: int = 0) -> None:
        self.b = bytearray(size)

    def put(self, off: int, data: bytes) -> "Buf":
        end = off + len(data)
        if end > len(self.b):
            self.b.extend(bytes(end - len(self.b)))
        self.b[off:end] = data
        return self

    def save(self, path: Path) -> Path:
        path.write_bytes(bytes(self.b))
        return path


# --- on-disk structure builders --------------------------------------

def mbr(*slots) -> bytes:
    s = bytearray(512)
    for i, (status, ptype, start, count) in enumerate(slots):
        s[446 + 16 * i:462 + 16 * i] = struct.pack("<B3sB3sII", status, b"\0\0\0", ptype, b"\0\0\0", start, count)
    s[510:512] = b"\x55\xaa"
    return bytes(s)


def ntfs_boot(total=2000, mft_cluster=4, serial=0x1122334455667788) -> bytes:
    s = bytearray(512)
    s[0:3] = b"\xeb\x52\x90"
    s[3:11] = b"NTFS    "
    struct.pack_into("<HB", s, 0x0B, 512, 8)
    struct.pack_into("<QQ", s, 0x28, total, mft_cluster)
    s[0x40] = 0xF6                                  # -10 -> 1024-byte records
    struct.pack_into("<Q", s, 0x48, serial)
    s[510:512] = b"\x55\xaa"
    return bytes(s)


def mft_record(parent: int, names, is_dir=False) -> bytes:
    """FILE record with one $FILE_NAME per (name, namespace), update-sequence fixups applied."""
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 0x30, 3)
    struct.pack_into("<HH", rec, 0x14, 0x38, 1 | (2 if is_dir else 0))
    pos = 0x38
    for name, ns in names:
        nm = name.encode("utf-16-le")
        val = bytearray(0x42 + len(nm))
        struct.pack_into("<Q", val, 0, parent | (1 << 48))      # sequence number in the high bits
        val[0x40], val[0x41] = len(name), ns
        val[0x42:] = nm
        alen = (24 + len(val) + 7) // 8 * 8
        struct.pack_into("<IIBBHHH", rec, pos, 0x30, alen, 0, 0, 0x18, 0, 0)
        struct.pack_into("<IH", rec, pos + 16, len(val), 24)
        rec[pos + 24:pos + 24 + len(val)] = val
        pos += alen
    rec[pos:pos + 4] = b"\xff\xff\xff\xff"
    rec[0x30:0x32] = b"\x01\x00"
    for i in (1, 2):
        rec[0x30 + 2 * i:0x32 + 2 * i] = rec[i * 512 - 2:i * 512]
        rec[i * 512 - 2:i * 512] = b"\x01\x00"
    return bytes(rec)


def windows_mft(buf: Buf, mft_off: int) -> None:
    recs = {
        5: mft_record(5, [(".", 1)], True),
        24: mft_record(5, [("Windows", 1)], True),
        25: mft_record(5, [("PROGRA~1", 2), ("Program Files", 1)], True),
        26: mft_record(5, [("Users", 1)], True),
        27: mft_record(26, [("alice", 1)], True),
        28: mft_record(26, [("Public", 1)], True),
        29: mft_record(26, [("desktop.ini", 1)], False),
        30: mft_record(5, [("pagefile.sys", 1)], False),
    }
    for n, rec in recs.items():
        buf.put(mft_off + n * 1024, rec)


def ext_sb(buf: Buf, off: int, label=b"data", incompat=0x40) -> None:
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x18, 2)             # s_log_block_size at 0x418 (relative to sb 0x400)
    struct.pack_into("<H", sb, 0x38, 0xEF53)
    struct.pack_into("<I", sb, 0x4C, 1)
    struct.pack_into("<II", sb, 0x5C, 0x4, incompat)
    sb[0x68:0x78] = uuid.UUID("11112222-3333-4444-5555-666677778888").bytes
    sb[0x78:0x78 + len(label)] = label
    buf.put(off + 0x400, bytes(sb))


def fat32_boot(label=b"MYDISK     ", serial=0xCAFEBABE) -> bytes:
    s = bytearray(512)
    s[0:3] = b"\xeb\x58\x90"
    s[3:11] = b"MSWIN4.1"
    struct.pack_into("<HB", s, 0x0B, 512, 1)
    struct.pack_into("<I", s, 0x43, serial)
    s[0x47:0x52] = label
    s[0x52:0x5A] = b"FAT32   "
    s[510:512] = b"\x55\xaa"
    return bytes(s)


# --- raw images -------------------------------------------------------

def test_raw_mbr_ntfs_windows(fixture_dir):
    buf = Buf().put(0, mbr((0x80, 0x07, 2048, 2000)))
    buf.put(MiB, ntfs_boot())
    windows_mft(buf, MiB + 4 * 4096)
    p = buf.save(fixture_dir / "win.img")
    r = probe(p)
    assert (r.kind, r.container) == ("disk", "plain")
    pr = r.probe
    assert pr["format"] == "raw" and pr["partition_table"] == "MBR" and pr["sparse"] is False
    assert pr["os_hint"] == "windows" and pr["volume_role"] == "system"
    summary = pr["volume_summaries"][0]
    assert summary["users"] == ["alice"] and summary["source"] == "mft"
    assert {"Windows/", "Program Files/", "Users/", "pagefile.sys"} <= set(summary["root_entries"])
    assert pr["filesystems"][0]["type"] == "ntfs" and pr["filesystems"][0]["volume_serial"] == "1122334455667788"
    assert r.members == [{"index": 0, "path": "partition1", "size": 2000 * 512, "offset": MiB,
                          "role": "volume", "format": "ntfs", "type_name": "NTFS/exFAT/HPFS",
                          "type_code": "0x07"}]
    assert pr["members_count"] == 1 and pr["member_roles"] == {"volume": 1}
    assert pr["bytes_read"] < 3 * MiB


def test_disk_scan_cap_zero_skips_content_scan(fixture_dir):
    buf = Buf().put(0, mbr((0x80, 0x07, 2048, 2000))).put(MiB, ntfs_boot())
    windows_mft(buf, MiB + 4 * 4096)
    r = probe(buf.save(fixture_dir / "win.img"), disk_scan_cap=0)
    assert "volume_summaries" not in r.probe and "os_hint" not in r.probe
    assert r.probe["bytes_read"] < 64 * 1024


def test_gpt_three_entries(fixture_dir):
    sector0 = bytearray(mbr((0, 0xEE, 1, 0xFFFFFFFF)))
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    buf = Buf().put(0, bytes(sector0)).put(512, bytes(hdr))
    for i, (guid, name, start) in enumerate((
            ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "EFI", 2048),
            ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Data", 4096),
            ("0FC63DAF-8483-4772-8E79-3D69D8477DE4", "root", 6144))):
        e = bytearray(128)
        e[0:16] = uuid.UUID(guid).bytes_le
        e[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQ", e, 32, start, start + 1999)
        e[56:56 + 2 * len(name)] = name.encode("utf-16-le")
        buf.put(1024 + 128 * i, bytes(e))
    buf.put(2048 * 512, fat32_boot())
    ext_sb(buf, 6144 * 512)
    buf.put(7000 * 512, b"\0")
    r = probe(buf.save(fixture_dir / "gpt.bin"))
    assert r.kind == "disk" and r.probe["partition_table"] == "GPT"
    rows = r.members
    assert [m["path"] for m in rows] == ["partition1", "partition2", "partition3"]
    assert [m["type_name"] for m in rows] == ["EFI System", "Microsoft Basic Data", "Linux filesystem"]
    assert [m["name"] for m in rows] == ["EFI", "Data", "root"]
    assert rows[0]["format"] == "fat32" and rows[0]["label"] == "MYDISK"
    assert rows[2]["format"] == "ext" and "format" not in rows[1]
    assert rows[0]["type_guid"] == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    assert rows[1]["offset"] == 4096 * 512 and rows[1]["size"] == 2000 * 512
    ext = [f for f in r.probe["filesystems"] if f["type"] == "ext"][0]
    assert ext["filesystem"] == "ext4" and ext["label"] == "data"


def test_extended_mbr_chain(fixture_dir):
    buf = Buf().put(0, mbr((0x80, 0x0B, 2048, 1000), (0, 0x05, 4096, 12000)))
    buf.put(4096 * 512, mbr((0, 0x83, 2048, 1000), (0, 0x05, 4096, 6000)))
    buf.put(8192 * 512, mbr((0, 0x07, 2048, 500)))
    buf.put(8192 * 512 + 512 * 2048 + 512, b"\0")
    r = probe(buf.save(fixture_dir / "ext.img"))
    assert [m["path"] for m in r.members] == ["partition1", "partition5", "partition6"]
    assert r.members[1]["offset"] == (4096 + 2048) * 512
    assert r.members[2]["offset"] == (8192 + 2048) * 512
    assert r.members[1]["type_name"] == "Linux"


def test_fat32_floppy_volume_at_offset_zero(fixture_dir):
    buf = Buf().put(0, fat32_boot()).put(64 * 1024 - 1, b"\0")
    r = probe(buf.save(fixture_dir / "floppy.ima"))
    assert r.kind == "disk" and "partition_table" not in r.probe and r.members is None
    fs = r.probe["filesystems"][0]
    assert (fs["location"], fs["type"], fs["label"], fs["volume_serial"]) == (
        "offset 0", "fat32", "MYDISK", "CAFEBABE")


def test_ext4_superblock_and_rejects_bad_superblock(fixture_dir):
    buf = Buf(64 * 1024)
    ext_sb(buf, 0)
    r = probe(buf.save(fixture_dir / "e.img"))
    assert r.probe["filesystems"][0]["filesystem"] == "ext4"
    assert r.probe["filesystems"][0]["uuid"] == "11112222-3333-4444-5555-666677778888"
    bad = Buf(64 * 1024)
    ext_sb(bad, 0)
    bad.put(0x400 + 0x18, struct.pack("<I", 9))     # s_log_block_size > 6: not ext
    assert probe(bad.save(fixture_dir / "bad.img")).kind != "disk"


def test_luks1_and_luks2(fixture_dir):
    l1 = Buf(4096).put(0, b"LUKS\xba\xbe" + struct.pack(">H", 1))
    l1.put(8, b"aes").put(40, b"xts-plain64").put(72, b"sha256").put(168, b"aaaaaaaa-0000-0000-0000-000000000001")
    r = probe(l1.save(fixture_dir / "l1.bin"))
    fs = r.probe["filesystems"][0]
    assert (fs["type"], fs["cipher"], fs["cipher_mode"]) == ("luks", "aes", "xts-plain64")
    assert fs["uuid"] == "aaaaaaaa-0000-0000-0000-000000000001"
    assert r.probe["encryption"]["encryption"] == "LUKS v1"
    assert r.probe["volume_summaries"] == [{"location": "offset 0",
                                            "note": "encrypted volume — content scan skipped"}]
    l2 = Buf(4096).put(0, b"LUKS\xba\xbe" + struct.pack(">H", 2)).put(24, b"vault").put(72, b"sha256")
    l2.put(168, b"bbbbbbbb-0000-0000-0000-000000000002")
    fs = probe(l2.save(fixture_dir / "l2.bin")).probe["filesystems"][0]
    assert (fs["label"], fs["checksum_alg"], fs["uuid"]) == ("vault", "sha256", "bbbbbbbb-0000-0000-0000-000000000002")


def test_bitlocker_metadata_and_scan_skipped(fixture_dir):
    boot = bytearray(512)
    boot[3:11] = b"-FVE-FS-"
    ident = uuid.UUID("4967d63b-2e29-4ad8-8399-f6a339e3d001")
    boot[160:176] = ident.bytes_le
    struct.pack_into("<QQQ", boot, 0xB0, 0x2000, 0x3000, 0)
    boot[510:512] = b"\x55\xaa"
    vol_guid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    blk = bytearray(256)
    blk[0:8] = b"-FVE-FS-"
    struct.pack_into("<H", blk, 10, 2)
    struct.pack_into("<IIII", blk, 64, 0x200, 2, 48, 0x100)
    blk[64 + 16:64 + 32] = vol_guid.bytes_le
    struct.pack_into("<H", blk, 64 + 36, 0x8005)
    ft = int((datetime(2023, 1, 2) - datetime(1601, 1, 1)).total_seconds()) * 10**7
    struct.pack_into("<Q", blk, 64 + 40, ft)
    buf = Buf().put(0, bytes(boot)).put(0x2000, bytes(blk)).put(0x4000, b"\0")
    r = probe(buf.save(fixture_dir / "bl.bin"))
    fs = r.probe["filesystems"][0]
    assert fs["type"] == "bitlocker"
    assert fs["identifier_guid"] == str(ident) and fs["volume_guid"] == str(vol_guid)
    assert fs["encryption_method"] == "AES-256-XTS" and fs["created"].startswith("2023-01-02")
    assert "volume_summaries" in r.probe and "note" in r.probe["volume_summaries"][0]
    assert "os_hint" not in r.probe


def test_bitlocker_bad_metadata_signature_is_not_trusted(fixture_dir):
    boot = bytearray(512)
    boot[3:11] = b"-FVE-FS-"
    struct.pack_into("<Q", boot, 0xB0, 0x2000)
    buf = Buf().put(0, bytes(boot)).put(0x2000, b"GARBAGE!" * 32)
    fs = probe(buf.save(fixture_dir / "bl2.bin")).probe["filesystems"][0]
    assert fs["type"] == "bitlocker" and "volume_guid" not in fs


def test_lvm_label(fixture_dir):
    lbl = bytearray(512)
    lbl[0:8] = b"LABELONE"
    lbl[24:32] = b"LVM2 001"
    lbl[32:64] = b"abcdef0123456789ABCDEF0123456789"
    r = probe(Buf(8192).put(512, bytes(lbl)).save(fixture_dir / "pv.img"))
    assert r.probe["lvm"]["pv_uuid"] == "abcdef-0123-4567-89AB-CDEF-0123-456789"
    assert r.probe["filesystems"][0]["type"] == "lvm"


# --- containers -------------------------------------------------------

def guest_disk(buf: Buf, base: int) -> None:
    """MBR with one ext partition at guest LBA 64 (32 KiB), as seen at file offset `base`."""
    buf.put(base, mbr((0x80, 0x83, 64, 1000)))
    ext_sb(buf, base + 64 * 512, label=b"guest")


def test_vhd_dynamic_maps_guest_through_bat(fixture_dir):
    block = 2 * MiB
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">Q", footer, 16, 512)         # data offset: dynamic header
    struct.pack_into(">QQ", footer, 40, 8 * MiB, 8 * MiB)
    struct.pack_into(">I", footer, 60, 3)
    footer[68:84] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes
    hdr = bytearray(1024)
    hdr[0:8] = b"cxsparse"
    struct.pack_into(">Q", hdr, 16, 1536)
    struct.pack_into(">II", hdr, 28, 4, block)
    buf = Buf().put(0, bytes(footer)).put(512, bytes(hdr))
    bat = struct.pack(">4I", 4, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)     # block 0 at sector 4
    buf.put(1536, bat)
    data = 4 * 512 + 512                             # + 512-byte sector bitmap
    guest_disk(buf, data)
    buf.put(data + block, bytes(footer))
    r = probe(buf.save(fixture_dir / "dyn.vhd"), disk_scan_cap=0)
    pr = r.probe
    assert (r.kind, pr["format"], pr["variant"], pr["virtual_size"], pr["sparse"]) == ("disk", "vhd", "dynamic", 8 * MiB, True)
    assert pr["unique_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" and pr["block_size"] == block
    assert pr["partition_table"] == "MBR" and r.members[0]["format"] == "ext"
    assert pr["bytes_read"] < SMALL


def test_vhd_fixed_is_raw_plus_footer(fixture_dir):
    buf = Buf().put(0, mbr((0x80, 0x0B, 64, 100))).put(64 * 512, fat32_boot())
    buf.put(256 * 1024 - 1, b"\0")
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">QQ", footer, 40, 256 * 1024, 256 * 1024)
    struct.pack_into(">I", footer, 60, 2)
    buf.put(256 * 1024, bytes(footer))
    r = probe(buf.save(fixture_dir / "fixed.vhd"))
    assert (r.probe["format"], r.probe["variant"], r.probe["virtual_size"], r.probe["sparse"]) == ("vhd", "fixed", 256 * 1024, False)
    assert r.members[0]["format"] == "fat32"


def vhdx_file(path: Path, flags: int) -> Path:
    buf = Buf().put(0, b"vhdxfile")
    guid = lambda s: uuid.UUID(s).bytes_le          # noqa: E731
    bat_guid, meta_guid = "2DC27766-F623-4200-9D64-115E9BFD4A08", "8B7CA206-4790-4B9A-B8FE-575F050F886E"
    for off in (0x30000, 0x40000):
        t = bytearray(16) + guid(bat_guid) + struct.pack("<QII", 0x200000, 0x10000, 1)
        t += guid(meta_guid) + struct.pack("<QII", 0x100000, 0x100000, 1)
        t[0:4] = b"regi"
        struct.pack_into("<I", t, 8, 2)
        buf.put(off, bytes(t))
    items = [("CAA16737-FA36-4D43-B3B6-33F0AA44E76B", 0x10000, 8),
             ("2FA54224-CD1B-4876-B211-5DBED83BF4B8", 0x10008, 8),
             ("8141BF1D-A96F-4709-BA47-F233A8FAAB5F", 0x10010, 4),
             ("CDA348C7-445D-4471-9CC9-E9885251C556", 0x10014, 4)]
    meta = bytearray(32 + 32 * len(items))
    meta[0:8] = b"metadata"
    struct.pack_into("<H", meta, 10, len(items))
    for i, (g, off, ln) in enumerate(items):
        meta[32 + 32 * i:64 + 32 * i] = guid(g) + struct.pack("<IIII", off, ln, 0, 0)
    buf.put(0x100000, bytes(meta))
    buf.put(0x100000 + 0x10000, struct.pack("<IIQII", MiB, flags, 16 * MiB, 512, 4096))
    buf.put(0x200000, struct.pack("<Q", (3 << 20) | 6))      # payload block 0 -> 3 MiB, fully present
    guest_disk(buf, 3 * MiB)
    return buf.save(path)


def test_vhdx_dynamic_and_fixed(fixture_dir):
    r = probe(vhdx_file(fixture_dir / "d.vhdx", 0), disk_scan_cap=0)
    pr = r.probe
    assert (pr["format"], pr["variant"], pr["virtual_size"], pr["block_size"]) == ("vhdx", "dynamic", 16 * MiB, MiB)
    assert pr["logical_sector_size"] == 512 and pr["physical_sector_size"] == 4096 and pr["sparse"] is True
    assert pr["partition_table"] == "MBR" and r.members[0]["format"] == "ext"
    assert pr["bytes_read"] < SMALL
    fixed = probe(vhdx_file(fixture_dir / "f.vhdx", 1)).probe
    assert fixed["variant"] == "fixed" and fixed["sparse"] is False
    diff = probe(vhdx_file(fixture_dir / "p.vhdx", 2))
    assert diff.probe["variant"] == "differencing" and "partition_table" not in diff.probe


def test_vdi_dynamic_block_map(fixture_dir):
    h = bytearray(0x1C8)
    h[0:0x28] = b"<<< Oracle VM VirtualBox Disk Image >>>\n"
    struct.pack_into("<III", h, 0x40, 0xBEDA107F, 0x00010001, 0x190)
    struct.pack_into("<I", h, 0x4C, 1)
    struct.pack_into("<II", h, 0x154, 0x200, 0x1000)
    struct.pack_into("<Q", h, 0x170, 4 * MiB)
    struct.pack_into("<IIII", h, 0x178, MiB, 0, 4, 1)
    h[0x188:0x198] = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef").bytes_le
    buf = Buf().put(0, bytes(h)).put(0x200, struct.pack("<4I", 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE))
    guest_disk(buf, 0x1000)
    r = probe(buf.save(fixture_dir / "d.vdi"), disk_scan_cap=0)
    pr = r.probe
    assert (pr["format"], pr["variant"], pr["virtual_size"], pr["allocated_size"]) == ("vdi", "dynamic", 4 * MiB, MiB)
    assert pr["unique_id"] == "01234567-89ab-cdef-0123-456789abcdef" and pr["version"] == "1.1"
    assert r.members[0]["format"] == "ext" and pr["bytes_read"] < SMALL


def qcow2_header(vsize, l1_size, l1_off, version=3, backing=None, crypt=0) -> bytearray:
    h = bytearray(112)
    struct.pack_into(">4sIQIIQIIQ", h, 0, b"QFI\xfb", version, 0, 0, 16, vsize, crypt, l1_size, l1_off)
    if backing:
        struct.pack_into(">QI", h, 8, 104, len(backing))
        h[104:104 + len(backing)] = backing
    return h


def test_qcow2_v3_maps_guest_cluster(fixture_dir):
    buf = Buf().put(0, bytes(qcow2_header(64 * MiB, 1, 65536)))
    buf.put(65536, struct.pack(">Q", 131072 | (1 << 63)))                  # L1[0] -> L2 table
    buf.put(131072, struct.pack(">Q", 196608 | (1 << 63)))                 # L2[0] -> data cluster
    guest_disk(buf, 196608)
    buf.put(196608 + 65535, b"\0")
    r = probe(buf.save(fixture_dir / "g.qcow2"), disk_scan_cap=0)
    pr = r.probe
    assert (pr["format"], pr["version"], pr["virtual_size"], pr["cluster_size"]) == ("qcow2", 3, 64 * MiB, 65536)
    assert pr["partition_table"] == "MBR" and r.members[0]["format"] == "ext"
    assert pr["bytes_read"] < SMALL


def test_qcow2_backing_file_and_luks(fixture_dir):
    buf = Buf().put(0, bytes(qcow2_header(MiB, 1, 65536, backing=b"base.qcow2"))).put(65536, bytes(8))
    r = probe(buf.save(fixture_dir / "child.qcow2"))
    assert r.probe["backing_file"] == "base.qcow2" and r.probe["variant"] == "differencing"
    assert r.members is None
    enc = Buf().put(0, bytes(qcow2_header(MiB, 1, 65536, crypt=2))).put(65536, bytes(8))
    r = probe(enc.save(fixture_dir / "enc.qcow2"))
    assert r.probe["encryption"] == {"type": "qcow2", "method": "LUKS"}


def test_huge_virtual_size_reads_stay_small(fixture_dir):
    tib = 1 << 40
    buf = Buf().put(0, bytes(qcow2_header(tib, 2048, 65536))).put(65536 + 2048 * 8, b"\0")
    r = probe(buf.save(fixture_dir / "huge.qcow2"))
    assert r.kind == "disk" and r.probe["virtual_size"] == tib and r.probe["sparse"] is True
    assert r.probe["bytes_read"] < 64 * 1024
    assert any("no partition table" in n for n in r.probe["notes"])


def vmdk_sparse(path: Path) -> Path:
    h = bytearray(512)
    h[0:4] = b"KDMV"
    struct.pack_into("<IIQQQQIQQQ", h, 4, 1, 3, 20480, 128, 1, 20, 512, 21, 22, 40)
    desc = (b'# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n'
            b'createType="monolithicSparse"\n\n# Extent description\n'
            b'RW 20480 SPARSE "disk.vmdk"\n')
    buf = Buf().put(0, bytes(h)).put(512, desc)
    buf.put(22 * 512, struct.pack("<I", 23))                  # GD[0] -> GT at sector 23
    buf.put(23 * 512, struct.pack("<I", 40))                  # GT[0] -> grain at sector 40
    guest_disk(buf, 40 * 512)
    buf.put(40 * 512 + 65535, b"\0")
    return buf.save(path)


def test_vmdk_sparse_capacity_at_offset_12(fixture_dir):
    r = probe(vmdk_sparse(fixture_dir / "s.vmdk"), disk_scan_cap=0)
    pr = r.probe
    assert (pr["format"], pr["variant"], pr["virtual_size"]) == ("vmdk", "sparse", 20480 * 512)
    assert pr["create_type"] == "monolithicSparse"
    assert pr["extents"] == [{"access": "RW", "sectors": 20480, "type": "SPARSE", "file": "disk.vmdk"}]
    assert r.members[0]["format"] == "ext" and pr["bytes_read"] < SMALL


def test_vmdk_text_descriptor(fixture_dir):
    text = ('# Disk DescriptorFile\nversion=1\ncreateType="twoGbMaxExtentSparse"\n'
            'parentFileNameHint="base.vmdk"\n'
            'RW 4192256 SPARSE "x-s001.vmdk"\nRW 1000 SPARSE "x-s002.vmdk"\n')
    p = fixture_dir / "x.vmdk"
    p.write_text(text)
    r = probe(p)
    pr = r.probe
    assert (r.kind, pr["format"], pr["variant"]) == ("disk", "vmdk", "descriptor")
    assert pr["virtual_size"] == (4192256 + 1000) * 512 and pr["parent"] == "base.vmdk"
    assert [e["file"] for e in pr["extents"]] == ["x-s001.vmdk", "x-s002.vmdk"]


# --- ISO 9660 ---------------------------------------------------------

def dirrec(name: bytes, lba: int, length: int, is_dir: bool, date=(124, 5, 17, 10, 30, 0, 0)) -> bytes:
    rl = 33 + len(name)
    rl += rl % 2
    r = bytearray(rl)
    r[0] = rl
    struct.pack_into("<I", r, 2, lba)
    struct.pack_into("<I", r, 10, length)
    r[18:25] = bytes(date)
    r[25] = 2 if is_dir else 0
    r[32] = len(name)
    r[33:33 + len(name)] = name
    return bytes(r)


def pad(b: bytes, n: int) -> bytes:
    return b.ljust(n, b" ")


def build_iso(path: Path, hybrid=False) -> Path:
    def j(s: str) -> bytes:
        return s.encode("utf-16-be")

    dot, dotdot = dirrec(b"\x00", 0, 2048, True), dirrec(b"\x01", 0, 2048, True)

    def sector(*recs: bytes) -> bytes:
        return b"".join(recs).ljust(2048, b"\0")

    buf = Buf(40 * 2048)
    if hybrid:
        buf.put(0, mbr((0x80, 0x17, 1, 100)))
    # 9660 tree: root 20-21, DOCS 24, DEEP 26.  Joliet tree: root 22-23, docs 25, deep 27.
    buf.put(20 * 2048, sector(dot, dotdot, dirrec(b"README.TXT;1", 28, 100, False),
                              dirrec(b"DOCS", 24, 2048, True)))
    buf.put(21 * 2048, sector(dirrec(b"LATE.TXT;1", 29, 5, False, date=(124, 0, 1, 0, 0, 0, 0))))
    buf.put(24 * 2048, sector(dot, dotdot, dirrec(b"MANUAL.PDF;1", 30, 4096, False), dirrec(b"DEEP", 26, 2048, True)))
    buf.put(26 * 2048, sector(dot, dotdot, dirrec(b"A.LUA;1", 31, 12, False)))
    buf.put(22 * 2048, sector(dot, dotdot, dirrec(j("README.txt"), 28, 100, False),
                              dirrec(j("docs"), 25, 2048, True)))
    buf.put(23 * 2048, sector(dirrec(j("late.txt"), 29, 5, False, date=(124, 0, 1, 0, 0, 0, 0))))
    buf.put(25 * 2048, sector(dot, dotdot, dirrec(j("Manual Final.pdf"), 30, 4096, False),
                              dirrec(j("deep"), 27, 2048, True)))
    buf.put(27 * 2048, sector(dot, dotdot, dirrec(j("a.lua"), 31, 12, False)))

    def vd(kind: int) -> bytearray:
        d = bytearray(2048)
        d[0], d[1:6], d[6] = kind, b"CD001", 1
        return d

    pvd = vd(1)
    pvd[8:40], pvd[40:72] = pad(b"LINUX", 32), pad(b"TESTVOL", 32)
    struct.pack_into("<I", pvd, 80, 40)
    struct.pack_into("<H", pvd, 128, 2048)
    pvd[156:190] = dirrec(b"\x00", 20, 4096, True)
    pvd[318:446] = pad(b"ACME", 128)
    pvd[813:830] = b"2024010112000000\0"
    boot = vd(0)
    boot[7:30] = b"EL TORITO SPECIFICATION"
    svd = vd(2)
    svd[88:91] = b"%/E"
    svd[156:190] = dirrec(b"\x00", 22, 4096, True)
    end = vd(255)
    for i, d in enumerate((pvd, boot, svd, end)):
        buf.put((16 + i) * 2048, bytes(d))
    return buf.save(path)


def test_iso_members_joliet_eltorito(fixture_dir):
    r = probe(build_iso(fixture_dir / "disc.iso"))
    assert (r.kind, r.container) == ("disk", "plain")
    pr = r.probe
    assert (pr["format"], pr["volume_id"], pr["publisher"], pr["virtual_size"]) == ("iso9660", "TESTVOL", "ACME", 40 * 2048)
    assert pr["joliet"] is True and pr["bootable"] is True and pr["created"] == "2024-01-01T12:00:00"
    assert "hybrid" not in pr and "udf" not in pr
    assert [m["path"] for m in r.members] == [
        "README.txt", "docs/", "late.txt", "docs/Manual Final.pdf", "docs/deep/", "docs/deep/a.lua"]
    by = {m["path"]: m for m in r.members}
    assert by["docs/Manual Final.pdf"]["size"] == 4096 and by["docs/Manual Final.pdf"]["offset"] == 30 * 2048
    assert by["docs/Manual Final.pdf"]["role"] == "document" and by["docs/"]["role"] == "dir"
    assert by["docs/deep/a.lua"]["role"] == "script" and by["README.txt"]["role"] == "text"
    assert by["README.txt"]["mtime_ns"] == int(datetime(2024, 5, 17, 10, 30, tzinfo=timezone.utc).timestamp()) * 10**9
    assert "mtime_ns" not in by["late.txt"]                  # month 0 is not a date
    assert pr["members_count"] == 6 and pr["member_roles"]["dir"] == 2


def test_iso_without_joliet_strips_versions_and_caps(fixture_dir):
    p = build_iso(fixture_dir / "plain.iso")
    data = bytearray(p.read_bytes())
    data[18 * 2048:19 * 2048] = bytes(2048)                    # drop the Joliet SVD
    data[18 * 2048 + 1:18 * 2048 + 6] = b"CD001"
    data[18 * 2048] = 255
    p.write_bytes(bytes(data))
    r = probe(p)
    assert [m["path"] for m in r.members][:2] == ["README.TXT", "DOCS/"] and "joliet" not in r.probe
    capped = probe(p, max_members=2)
    assert len(capped.members) == 2 and capped.probe["members_truncated"] is True
    tiny = probe(p, archive_scan_cap=2048)
    assert tiny.probe["members_truncated"] is True and tiny.probe["bytes_read"] < 64 * 1024


def test_iso_hybrid_mbr(fixture_dir):
    r = probe(build_iso(fixture_dir / "hyb.iso", hybrid=True))
    assert r.probe["format"] == "iso9660" and r.probe["hybrid"] is True
    assert r.probe["partition_table"] == "MBR" and len(r.members) == 6      # files, not partitions


# --- things that are not disks ---------------------------------------

def test_img_that_is_png_falls_through(fixture_dir):
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0) + bytes(20)
    p = fixture_dir / "pic.img"
    p.write_bytes(png)
    r = probe(p)
    assert r.kind == "image" and r.probe.get("format") != "raw"


def test_random_img_and_bin_are_not_disks(fixture_dir):
    rnd = random.Random(7)
    noise = bytearray(rnd.randbytes(64 * 1024))
    noise[510:512] = b"\x00\x00"
    p = fixture_dir / "noise.img"
    p.write_bytes(bytes(noise))
    assert probe(p).kind == "unknown"
    fake = bytearray(rnd.randbytes(64 * 1024))
    fake[510:512] = b"\x55\xaa"
    for i in range(4):
        fake[446 + 16 * i] = 0x55                              # invalid status byte
    for suffix in ("bin", "img"):
        q = fixture_dir / f"fake.{suffix}"
        q.write_bytes(bytes(fake))
        assert probe(q).kind == "unknown"


def test_iso_suffix_without_pvd_is_not_disk(fixture_dir):
    p = fixture_dir / "notes.iso"
    p.write_text("just some text that is not a disc image\n" * 20)
    assert probe(p).kind == "text"


def test_glob_table_names_raw_images():
    idf = Identifier(ScanOptions())
    for name in ("a.dd", "a.hdd", "a.ima", "a.img", "a.qcow"):
        assert idf.by_name(name).get("mime_glob"), name


# --- end to end -------------------------------------------------------

def test_scan_and_members_for_iso(fixture_dir, capsys):
    tree = fixture_dir / "tree"
    tree.mkdir()
    build_iso(tree / "disc.iso")
    db = fixture_dir / "cat.sqlite"
    assert cli.main(["scan", str(tree), "--backend", "sqlite", "--out", str(db), "--hash", "none",
                     "--identify", "never"]) == 0
    capsys.readouterr()
    assert cli.main(["members", "disc.iso", "--root", str(tree), "--backend", "sqlite", "--out", str(db)]) == 0
    out = capsys.readouterr().out
    assert "Manual Final.pdf" in out and "a.lua" in out
    assert cli.main(["show", "disc.iso", "--root", str(tree), "--backend", "sqlite", "--out", str(db)]) == 0
    shown = capsys.readouterr().out
    assert '"kind": "disk"' in shown and '"members_count": 6' in shown


def test_cli_disk_scan_cap_option():
    args = cli.build_parser().parse_args(["scan", "x", "--disk-scan-cap", "0.5"])
    assert ScanOptions.from_args(args).disk_scan_cap == 512 * 1024
    assert ScanOptions().disk_scan_cap == 8 * MiB


def test_ext_volume_with_grub_strings_is_not_windows():
    """GRUB scripts on a Linux /boot name bootmgr and ntldr; ext rules out Windows."""
    from filecat.probe.diskscan import scan_strings
    blob = (b"menuentry chainloader bootmgr NTLDR pagefile.sys Windows\\System32 "
            b"/etc/grub.d /etc/default /boot/grub")
    assert scan_strings(blob)["os_hint"] == "windows"
    assert scan_strings(blob, "ext")["os_hint"] == "linux"


# --- UDF -------------------------------------------------------------

UDF_SECTOR = 2048
UDF_PART = 300          # partition start sector


def udf_tag(tag_id: int, body: bytes, location: int = 0) -> bytes:
    """16-byte descriptor tag + body; checksum over tag bytes 0-3 and 5-15."""
    t = bytearray(struct.pack("<HHBBHHHI", tag_id, 2, 0, 0, 1, 0, 0, location))
    t[4] = (sum(t[0:4]) + sum(t[5:16])) & 0xFF
    return bytes(t) + body


def udf_fid(name: str, lbn: int, is_dir=False, parent=False, ref=0) -> bytes:
    raw = b"" if parent else b"\x08" + name.encode("latin-1")
    body = bytearray(22)
    struct.pack_into("<HBB", body, 0, 1, (2 if is_dir else 0) | (8 if parent else 0), len(raw))
    struct.pack_into("<IIH", body, 4, UDF_SECTOR, lbn, ref)
    struct.pack_into("<H", body, 20, 0)            # L_IU
    rec = udf_tag(257, bytes(body) + raw, lbn)
    return rec + bytes(-len(rec) % 4)


def udf_fe(file_type: int, size: int, ad: bytes, ad_type: int) -> bytes:
    fe = bytearray(176 - 16)
    fe[27 - 16] = file_type
    struct.pack_into("<H", fe, 34 - 16, ad_type)
    struct.pack_into("<Q", fe, 56 - 16, size)
    struct.pack_into("<HH5B", fe, 84 - 16, 0x1000, 2020, 5, 17, 12, 30, 0)   # mtime UTC
    struct.pack_into("<II", fe, 168 - 16, 0, len(ad))
    return udf_tag(261, bytes(fe) + ad)


def build_udf(buf: Buf, metadata=False) -> None:
    for i, ident in enumerate((b"BEA01", b"NSR02", b"TEA01")):
        buf.put(0x8000 + i * UDF_SECTOR, b"\x00" + ident + b"\x01")
    buf.put(256 * UDF_SECTOR, udf_tag(2, struct.pack("<II", 16 * UDF_SECTOR, 32)))
    pd = bytearray(512 - 16)
    struct.pack_into("<H", pd, 22 - 16, 0)
    struct.pack_into("<II", pd, 188 - 16, UDF_PART, 64)
    lvd = bytearray(512 - 16)
    vid = b"\x08MYUDF"
    lvd[84 - 16:84 - 16 + len(vid)] = vid
    lvd[211 - 16] = len(vid)
    struct.pack_into("<I", lvd, 212 - 16, UDF_SECTOR)
    struct.pack_into("<IIH", lvd, 248 - 16, UDF_SECTOR, 0, 1 if metadata else 0)   # FSD long_ad
    maps = bytes([1, 6]) + struct.pack("<HH", 1, 0)
    if metadata:
        m = bytearray(64)
        m[0], m[1] = 2, 64
        m[5:5 + 23] = b"*UDF Metadata Partition"
        struct.pack_into("<HHI", m, 36, 1, 0, 20)  # vol seq, partition 0, metadata file at lbn 20
        maps += bytes(m)
    struct.pack_into("<II", lvd, 264 - 16, len(maps), 2 if metadata else 1)
    lvd[440 - 16:440 - 16 + len(maps)] = maps
    buf.put(32 * UDF_SECTOR, udf_tag(5, bytes(pd), 32))
    buf.put(33 * UDF_SECTOR, udf_tag(6, bytes(lvd), 33))
    buf.put(34 * UDF_SECTOR, udf_tag(8, b"", 34))

    # Logical blocks, addressed in the partition that holds the tree. With a
    # metadata partition, the tree lives in metadata blocks 0.. which the
    # metadata file maps to physical lbn 40...
    base = 40 if metadata else 0
    ref = 1 if metadata else 0

    def put(lbn: int, data: bytes) -> None:
        buf.put((UDF_PART + base + lbn) * UDF_SECTOR, data)

    fsd = bytearray(512 - 16)
    struct.pack_into("<IIH", fsd, 400 - 16, UDF_SECTOR, 1, ref)
    put(0, udf_tag(256, bytes(fsd)))
    root = (udf_fid("", 1, True, parent=True, ref=ref) + udf_fid("sub", 2, True, ref=ref)
            + udf_fid("big.bin", 4, ref=ref))
    put(1, udf_fe(4, len(root), root, 3))
    sub = udf_fid("", 1, True, parent=True, ref=ref) + udf_fid("a.txt", 3, ref=ref)
    put(2, udf_fe(4, len(sub), sub, 3))
    put(3, udf_fe(5, 5, struct.pack("<II", 5, 10), 0))
    put(4, udf_fe(5, 5 * 1024**3, struct.pack("<II", 1 << 29, 11), 0))
    if metadata:
        # metadata file entry at physical lbn 20: one short_ad of 8 blocks at lbn 40
        buf.put((UDF_PART + 20) * UDF_SECTOR, udf_fe(250, 8 * UDF_SECTOR,
                                                    struct.pack("<II", 8 * UDF_SECTOR, 40), 0))
    buf.put((UDF_PART + 64) * UDF_SECTOR - 1, b"\x00")


def test_udf_only_image_is_listed(fixture_dir):
    buf = Buf()
    build_udf(buf)
    r = probe(buf.save(fixture_dir / "game.iso"))
    assert r.kind == "disk"
    assert r.probe["format"] == "udf" and r.probe["listing"] == "udf"
    assert r.probe["udf_volume_id"] == "MYUDF"
    rows = {m["path"]: m for m in r.members}
    assert set(rows) == {"sub/", "big.bin", "sub/a.txt"}
    assert rows["big.bin"]["size"] == 5 * 1024**3
    assert rows["sub/a.txt"]["size"] == 5
    assert rows["sub/a.txt"]["offset"] == (UDF_PART + 10) * UDF_SECTOR
    assert rows["sub/a.txt"]["mtime_ns"] == int(datetime(2020, 5, 17, 12, 30, tzinfo=timezone.utc).timestamp()) * 10**9
    assert r.probe["bytes_read"] < SMALL


def test_udf_metadata_partition_is_mapped(fixture_dir):
    buf = Buf()
    build_udf(buf, metadata=True)
    r = probe(buf.save(fixture_dir / "bd.iso"))
    assert r.probe["udf_partition_maps"] == ["metadata"]
    assert {m["path"] for m in r.members} == {"sub/", "big.bin", "sub/a.txt"}


def test_udf_bridge_prefers_the_larger_tree(fixture_dir):
    """Windows setup media: ISO 9660 holds a README, UDF holds the files."""
    buf = Buf()
    build_udf(buf)
    pvd = bytearray(UDF_SECTOR)
    pvd[0:7] = b"\x01CD001\x01"
    struct.pack_into("<I", pvd, 80, UDF_PART + 64)
    struct.pack_into("<H", pvd, 128, UDF_SECTOR)
    root = bytearray(34)
    root[0] = 34
    struct.pack_into("<II", root, 2, 290, 0)
    struct.pack_into("<II", root, 10, UDF_SECTOR, 0)
    root[25], root[32] = 2, 1
    pvd[156:190] = root
    readme = bytearray(34 + 10)
    readme[0] = len(readme)
    struct.pack_into("<I", readme, 2, 291)
    struct.pack_into("<I", readme, 10, 135)
    readme[32] = 10
    readme[33:43] = b"README.TXT"
    buf.put(0x8000, bytes(pvd))
    buf.put(0x8000 + UDF_SECTOR, b"\xffCD001\x01")
    buf.put(0x8000 + 2 * UDF_SECTOR, b"\x00BEA01\x01")
    buf.put(0x8000 + 3 * UDF_SECTOR, b"\x00NSR02\x01")
    buf.put(0x8000 + 4 * UDF_SECTOR, b"\x00TEA01\x01")
    buf.put(290 * UDF_SECTOR, bytes(root) + bytes(root) + bytes(readme))
    r = probe(buf.save(fixture_dir / "win.iso"))
    assert r.probe["format"] == "iso9660" and r.probe["udf"] is True
    assert r.probe["listing"] == "udf"
    assert "big.bin" in {m["path"] for m in r.members}


def test_squashfs_image(fixture_dir):
    sb = bytearray(4096)
    sb[0:4] = b"hsqs"
    struct.pack_into("<III", sb, 4, 3, 1526938290, 131072)
    struct.pack_into("<HH", sb, 20, 4, 17)
    struct.pack_into("<HH", sb, 28, 4, 0)
    struct.pack_into("<Q", sb, 40, 4096)
    path = fixture_dir / "squashfs.img"
    path.write_bytes(bytes(sb))
    r = probe(path)
    assert r.kind == "disk" and r.probe["format"] == "squashfs"
    fs = r.probe["filesystems"][0]
    assert fs["compression"] == "xz" and fs["block_size"] == 131072
