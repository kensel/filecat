"""Scan a real SMB share end to end. Runs only when FILECAT_TEST_SMB names a
writable share: a UNC path (\\\\host\\share) on Windows, or the mount point of
a CIFS mount elsewhere. CI mounts the samba container from compose.yaml.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from pathlib import Path

import pytest

from filecat import cli
from filecat.backends.sqlite import SqliteBackend

SMB = os.environ.get("FILECAT_TEST_SMB")
pytestmark = pytest.mark.skipif(not SMB, reason="FILECAT_TEST_SMB not set")


@pytest.fixture
def share_dir():
    d = Path(SMB) / f"filecat-test-{uuid.uuid4().hex[:8]}"
    d.mkdir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_scan_records_files_on_the_share(share_dir, fixture_dir):
    (share_dir / "hello.txt").write_bytes(b"hello smb")
    (share_dir / "sub").mkdir()
    payload = bytes(range(256)) * 64
    (share_dir / "sub" / "data.bin").write_bytes(payload)
    out = fixture_dir / "smb.sqlite"

    assert cli.main(["scan", str(share_dir), "--backend", "sqlite", "--out", str(out), "--workers", "2"]) == 0

    docs = {d["rel_path"]: d for d in SqliteBackend(str(out)).list()}
    assert docs["hello.txt"]["size"] == 9
    assert docs["hello.txt"]["sha256"] == hashlib.sha256(b"hello smb").hexdigest()
    assert docs["sub/data.bin"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert docs["sub"]["kind"] == "dir"
