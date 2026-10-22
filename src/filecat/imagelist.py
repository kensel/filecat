"""File listings of disk images, read from dissect's `target-query` command.

dissect (https://github.com/fox-it/dissect) is AGPL-3.0, so it is never
imported here: filecat starts `target-query -f walkfs --json IMAGE` as a
separate process, in its own virtualenv, and reads the JSON lines it prints.
Point --dissect at that executable (or set $FILECAT_DISSECT). The listing
comes from the image's own file system metadata (for NTFS the MFT); no file
contents are read.

Two images are compared by reading both listings in step and stopping, and
killing both processes, at the first entry that differs. Nothing is kept in
memory but the current entry. This relies on the walk order being the file
system's own directory order, which is the same for the same contents; if it
were not, the result is a false "differs", never a false "identical".
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from itertools import zip_longest
from typing import Any, Iterator

IMAGE_SUFFIXES = (".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow2", ".img", ".raw", ".dd")


class ListingError(Exception):
    pass


def walk(exe: str, image: str) -> Iterator[tuple[str, int, str]]:
    """(path, size, mtime) of every file in `image`, as target-query reports
    them. Closing the generator early kills the process."""
    proc = subprocess.Popen([exe, "-f", "walkfs", "--json", image], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, encoding="utf-8", errors="replace")
    seen = 0
    finished = False
    try:
        for line in proc.stdout:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("_type") != "record" or rec.get("type") == "dir":
                continue
            seen += 1
            yield rec.get("path") or "", int(rec.get("size") or 0), rec.get("mtime") or ""
        finished = True
    finally:
        if not finished:
            proc.kill()
        proc.stdout.close()
        code = proc.wait()
    if code != 0 or not seen:
        raise ListingError(f"{exe} listed {seen} files from {image} (exit {code})")


def compare_streams(exe: str, image_a: str, image_b: str) -> dict[str, Any]:
    """Walk both images in step. Identical: {"identical": True, "files": n,
    "digest": sha256 of the listing}. Otherwise {"identical": False,
    "compared": n entries that matched, "first_difference": [entry_a, entry_b]}
    where an entry is (path, size, mtime), or None past the end of the shorter."""
    digest = hashlib.sha256()
    n = 0
    a, b = walk(exe, image_a), walk(exe, image_b)
    try:
        for ea, eb in zip_longest(a, b):
            if ea != eb:
                return {"identical": False, "compared": n, "first_difference": [ea, eb]}
            n += 1
            digest.update(f"{ea[0]}\0{ea[1]}\0{ea[2]}\n".encode("utf-8", "replace"))
    finally:
        a.close()
        b.close()
    return {"identical": True, "files": n, "digest": digest.hexdigest()}
