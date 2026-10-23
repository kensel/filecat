"""Built-in content probe. Sets kind, container, probe measurements, encoding,
newlines and sample for a regular, non-empty file.

dir / link / empty are decided by the walker before this is called.
See file-catalog-requirements.md, "Probe order" and the sections after it.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from ..options import ScanOptions
from ..fsource import fopen
from ..record import suffix_of
from . import archive, disk, images, media, mpq, pck, pe, sevenzip, tarball, text, x3

_MESH_EXT_ONLY = {"obj", "stl", "glb"}


@dataclass
class ProbeResult:
    kind: str = "unknown"
    container: str = "plain"
    probe: dict[str, Any] = field(default_factory=dict)
    encoding: dict[str, Any] | None = None
    newlines: str | None = None
    sample: str | None = None
    sample_truncated: bool = False
    errors: list[dict[str, str]] = field(default_factory=list)   # [{stage, message}]
    # Archive member rows (see Backend.put_members). None = not an archive or
    # not listed; [] = listed and empty. The document keeps only a summary:
    # probe.members_count, probe.members_truncated, probe.member_roles, and
    # probe.entries (first options.list_zip_cap paths).
    members: list[dict[str, Any]] | None = None

    def apply(self, doc: dict[str, Any]) -> None:
        """Copy results onto a catalog document (omitting unmeasured fields)."""
        doc["kind"] = self.kind
        doc["container"] = self.container
        if self.probe:
            doc.setdefault("probe", {}).update(self.probe)
        if self.encoding is not None:
            doc["encoding"] = self.encoding
        if self.newlines is not None:
            doc["newlines"] = self.newlines
        if self.sample is not None:
            doc["sample"] = self.sample
            if self.sample_truncated:
                doc["sample_truncated"] = True
        if self.errors:
            doc.setdefault("errors", []).extend(self.errors)
        if self.members is not None:
            from ..record import MEMBERS_KEY
            doc[MEMBERS_KEY] = self.members


def probe_file(path: str, name: str, size: int, head: bytes,
               options: ScanOptions | None = None) -> ProbeResult:
    """Classify one regular file.

    path    -- absolute OS path; probes that need more than `head` may open it
               (PE via pefile, ZIP central dir, gzip inflate, CSV counts).
    name    -- final path component (for extension fallback, lang.dat, .cat/.dat).
    size    -- file size in bytes (> 0).
    head    -- the first min(size, 8 KiB) bytes, already read by the caller.
    Never raises for bad file content; failures go to ProbeResult.errors.
    """
    opts = options if options is not None else ScanOptions()
    result = ProbeResult()
    try:
        _probe(path, name, size, head, opts, result)
        # A .pck that was neither Godot nor X3 gzip: name what it is
        # (Python pickle, or unknown) without changing kind.
        if suffix_of(name) == "pck":
            pck.identify_other(name, head, result)
    except Exception as exc:  # last-resort safety net -- never raise out of here
        result.errors.append({"stage": "probe", "message": f"{type(exc).__name__}: {exc}"})
    return result


def _looks_like_pe(path: str, head: bytes) -> bool:
    """MZ plus a 'PE\\0\\0' signature at e_lfanew.

    e_lfanew is usually well inside `head`, but a handful of real images
    (signed Windows system binaries such as tcblaunch.exe) carry an unusually
    large DOS stub that pushes it past the 8 KiB head window. When that
    happens, seek to the one spot on disk that matters instead of guessing
    "not a PE" from a truncated buffer.
    """
    if len(head) < 0x40 or head[:2] != b"MZ":
        return False
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew + 4 <= len(head):
        return head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    try:
        with fopen(path, "rb") as f:
            f.seek(e_lfanew)
            sig = f.read(4)
    except OSError:
        return False
    return sig == b"PE\x00\x00"


def _probe(path: str, name: str, size: int, head: bytes,
           opts: ScanOptions, result: ProbeResult) -> None:
    # 4. exe
    if _looks_like_pe(path, head):
        try:
            pe.probe_pe(path, opts, result)
        except Exception as exc:
            result.errors.append({"stage": "pe", "message": f"{type(exc).__name__}: {exc}"})
            result.kind = "exe"
            result.container = "pe"
        return

    # 4b. disk images (containers, raw disks, ISO 9660 / UDF)
    if disk.probe_disk(path, name, size, head, opts, result):
        return

    # 5. zip (and OOXML -> document)
    if head[:4] == b"PK\x03\x04":
        try:
            archive.probe_zip(path, opts, result)
        except Exception as exc:
            result.errors.append({"stage": "archive", "message": f"{type(exc).__name__}: {exc}"})
            result.kind = "archive"
            result.container = "zip"
        return

    # 5b. other indexed or streamed archives: MPQ, Godot PCK, tar, bzip2, xz, 7z.
    # Each sniff is a few header bytes; the module owns the parse.
    for sniff, run, container, stage in (
        (mpq.detect, mpq.probe_mpq, "unknown", "mpq"),
        (pck.detect_godot, pck.probe_godot, "unknown", "pck"),
        (tarball.detect, tarball.probe_tar, "plain", "tar"),
        (archive.detect_bzip2, archive.probe_bzip2, "bzip2", "archive"),
        (archive.detect_xz, archive.probe_xz, "xz", "archive"),
        (sevenzip.detect, sevenzip.probe_7z, "7z", "7z"),
    ):
        if sniff(head):
            try:
                run(path, head, opts, result)
            except Exception as exc:
                result.errors.append({"stage": stage, "message": f"{type(exc).__name__}: {exc}"})
                result.kind = "archive"
                result.container = container
            return

    # 6. gzip / gzip_xored
    gz_container = archive.detect_gzip(head)
    # An X3 .dat whose first packed entry is itself gzip starts with a gzip
    # header; its sibling .cat decides that it is the catalogue payload.
    if gz_container is not None and suffix_of(name) == "dat":
        if x3.probe_dat_sibling(path, opts, result):
            return
    if gz_container is not None:
        try:
            archive.probe_gzip(path, gz_container, opts, result)
        except Exception as exc:
            result.errors.append({"stage": "archive", "message": f"{type(exc).__name__}: {exc}"})
            result.kind = "unknown"
            result.container = gz_container
        return

    # 7. texture / image
    hit = images.sniff(head)
    if hit is not None:
        result.kind = hit.pop("kind")
        result.container = "plain"
        result.probe.update(hit)
        return

    # 8. mesh (BOB1)
    if head[:4] == b"BOB1":
        full = head if size <= len(head) else _read_whole(path, head)
        hit = x3.sniff_bob1(full)
        if hit is not None:
            result.kind = hit.pop("kind")
            result.container = "plain"
            result.probe.update(hit)
            return

    # 9. audio / video
    hit = media.sniff(head)
    if hit is not None:
        result.kind = hit.pop("kind")
        result.container = "plain"
        result.probe.update(hit)
        return

    # 10. pdf
    if head[:4] == b"%PDF":
        result.kind = "document"
        result.container = "plain"
        version = text.probe_pdf_version(head)
        if version is not None:
            result.probe["pdf_version"] = version
        return

    suffix = suffix_of(name)

    # x3 refinements keyed on filename: .cat / .dat / lang.dat (steps 6, 8, 11)
    if suffix == "cat":
        if x3.probe_cat(path, result, opts):
            return
    if suffix == "dat":
        if x3.probe_dat_sibling(path, opts, result):
            return
        if name.lower() == "lang.dat":
            if _probe_lang_dat(head, result):
                return

    # other mesh filenames stay ext_only until a real header parser exists
    if suffix in _MESH_EXT_ONLY:
        result.kind = "mesh"
        result.container = "plain"
        result.probe["ext_only"] = True
        return

    # 11. text (+ CSV / semicolon / scene-text refinements)
    if text.is_text(head, size):
        _probe_text(path, head, size, opts, result)
        return

    # 12. unknown
    result.kind = "unknown"
    if suffix:
        result.probe["suffix"] = suffix
    # A mostly-printable head still gets a sample so a model can be asked
    # about it (Ollama selects unknown files with a non-empty sample).
    loose = text.printable_sample(head)
    if loose is not None:
        result.sample, result.sample_truncated = text.make_sample(loose)
        result.sample_truncated = result.sample_truncated or size > len(head)
        result.probe["sample_basis"] = "printable"


# A BOB1 chunk walk reads the body; models larger than this are walked
# only as far as the cap (the walk stops at a truncated chunk).
_BOB1_READ_CAP = 32 * 1024 * 1024


def _read_whole(path: str, head: bytes) -> bytes:
    try:
        with fopen(path, "rb") as f:
            return f.read(_BOB1_READ_CAP)
    except OSError:
        return head


def _probe_lang_dat(head: bytes, result: ProbeResult) -> bool:
    if not text.is_text(head, len(head)):
        return False
    enc, decoded = text.detect_encoding(head)
    language_id = text.detect_lang_dat(decoded)
    if language_id is None:
        return False
    result.kind = "text"
    result.container = "plain"
    result.encoding = enc
    result.newlines = text.classify_newlines(decoded)
    sample, truncated = text.make_sample(decoded)
    result.sample = sample
    result.sample_truncated = truncated
    result.probe["language_id"] = language_id
    return True


def _probe_text(path: str, head: bytes, size: int, opts: ScanOptions, result: ProbeResult) -> None:
    enc, decoded = text.detect_encoding(head)
    text.check_xml_declared_encoding(head, enc)
    newlines = text.classify_newlines(decoded)
    sample, truncated = text.make_sample(decoded)

    result.encoding = enc
    result.newlines = newlines
    result.sample = sample
    result.sample_truncated = truncated
    result.kind = "text"
    result.container = "plain"

    scene_version = text.detect_scene_text(decoded)
    if scene_version is not None:
        result.kind = "mesh"
        result.probe["format"] = "scene-text"
        result.probe["scene_version"] = scene_version
        return
    if text.is_x3_bodyfile(decoded):
        result.kind = "mesh"
        result.probe["format"] = "x3-bodyfile"
        return

    structured = text.detect_structured_text(decoded)
    if structured is not None:
        fmt, sep_name, fields = structured
        codec = enc.get("bom") or enc.get("detected") or "utf-8"
        records, truncated_records = text.count_records(path, codec)
        result.kind = "data"
        result.probe["format"] = fmt
        result.probe["separator"] = sep_name
        result.probe["fields"] = fields
        result.probe["records"] = records
        if truncated_records:
            result.probe["truncated"] = True
