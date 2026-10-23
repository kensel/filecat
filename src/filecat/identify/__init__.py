"""Type identification: freedesktop glob names for every file, libmagic on
bytes when asked, and the optional PRONOM / TrID / Magika identifiers.

See file-catalog-requirements.md, "Type identification".
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..fsource import fopen
from ..options import ScanOptions
from ..record import suffix_of
from . import trid
from .mimeglob import MimeDB, get_mime_db

# libmagic emits a few mime strings that are not in the freedesktop alias
# table at all (it is not shared-mime-info's own sniffer). Fold the ones we
# have seen onto their shared-mime-info equivalent before using the alias
# table for everything else normal (e.g. "text/x-c" -> "text/x-csrc").
_LIBMAGIC_OVERRIDES = {
    "application/cdfv2": "application/x-ole-storage",
    "application/cdfv2-corrupt": "application/x-ole-storage",
    "application/x-cdf": "application/x-ole-storage",
}


# Name-only types that the built-in probe must confirm before they win.
# ".cat" is far more often a Windows security catalog than an X3 index, so
# the X3 type wins only when probe.format says the bytes decoded as one.
PROBE_CONFIRMED = {"application/x-x3-catalog": "x3-cat"}

# Above this size an equal-weight glob tie prefers a non-text type.
_TEXT_TIE_MAX = 1024 * 1024


class Identifier:
    """One per scan. Loads the vendored tables once and checks optional tools.

    scan_errors: scan-level problems (e.g. `sf` not on PATH with --pronom),
    each {stage, message}; recorded once per scan, not once per file.
    """

    def __init__(self, options: ScanOptions | None = None,
                 local_tsv: str | None = None) -> None:
        self.options = options or ScanOptions()
        self.scan_errors: list[dict[str, str]] = []
        self._reported_stages: set[str] = set()
        self.db: MimeDB = get_mime_db(local_tsv=local_tsv)
        if self.db.local_errors:
            n = len(self.db.local_errors)
            self._scan_error_once(
                "mime_local",
                f"filecat-globs.tsv: {n} malformed line(s) skipped; first: {self.db.local_errors[0]}")

        # libmagic: initialised lazily on first byte-identification call,
        # so a scan that never reads bytes never reports a spurious error.
        self._magic_mime = None
        self._magic_desc = None
        self._magic_checked = False
        self._magic_available = False

        self._sf_path: str | None = None
        if self.options.pronom:
            self._init_pronom()

        self._trid_map: dict[str, str] = {}
        if self.options.trid_defs:
            self._init_trid(self.options.trid_defs)

        self._magika = None
        if self.options.magika:
            self._init_magika()

    # -- name layer ----------------------------------------------------

    def by_name(self, name: str, size: int | None = None,
                probe_format: str | None = None) -> dict[str, Any]:
        """Name layer only. Returns probe keys mime_glob, mime_glob_desc
        (omitted when no glob matches), and mime_glob_alternatives when
        several types tie on the name."""
        probe: dict[str, Any] = {}
        self._glob(name, size, None, probe, probe_format)
        return probe

    def _glob(self, name: str, size: int | None, magic_type: str | None,
              probe: dict[str, Any], probe_format: str | None = None) -> str | None:
        """Pick the glob type and fill mime_glob* keys on probe.

        Equal-weight ties (".vhd": VHDL source vs VHD disk image) are settled
        by the magic type when one of them matches it; otherwise a file over
        1 MiB prefers a non-text candidate, since multi-megabyte source files
        are rare and disk images, archives and media are not.
        """
        candidates, source_of, hidden = self.db.lookup_name_merged(name)
        if not candidates:
            return None
        chosen = candidates[0]
        if len(candidates) > 1 or hidden:
            # hidden: freedesktop types a higher-weight local entry overrode.
            probe["mime_glob_alternatives"] = candidates + hidden
        if len(candidates) > 1:
            matching = [c for c in candidates if magic_type is not None
                        and (c == magic_type or self.db.is_subclass(c, magic_type))]
            if matching:
                chosen = matching[0]
            elif size is not None and size > _TEXT_TIE_MAX:
                chosen = next((c for c in candidates if not c.startswith("text/")), chosen)
        needed = PROBE_CONFIRMED.get(chosen)
        if needed is not None and probe_format != needed:
            chosen = next((c for c in candidates + hidden if c not in PROBE_CONFIRMED), chosen)
        probe["mime_glob"] = chosen
        probe["mime_glob_source"] = source_of.get(chosen, "freedesktop")
        desc = self.db.comment(chosen)
        if desc:
            probe["mime_glob_desc"] = desc
        return chosen

    # -- full identification ---------------------------------------------

    def identify(self, path: str | None, name: str, head: bytes | None,
                 kind: str, size: int | None = None,
                 probe_format: str | None = None) -> dict[str, Any]:
        """Full identification for one file.

        head is None when byte identification is off for this root.
        kind is the built-in probe's result (Magika runs only for
        kind == 'unknown' or identify_basis == 'disagree').

        Returns {"mime": str | None, "probe": {...}} where probe holds
        mime_glob, mime_glob_desc, mime_magic, mime_magic_desc,
        identify_basis, and any pronom_* / trid_desc / magika_* keys.
        Never changes kind.
        """
        probe: dict[str, Any] = {}
        mime_magic = None
        if head is not None:
            mime_magic, magic_desc = self._run_magic(head)
            if mime_magic is not None:
                probe["mime_magic"] = mime_magic
                if magic_desc:
                    probe["mime_magic_desc"] = magic_desc
        mime_glob = self._glob(name, size, mime_magic, probe, probe_format)

        mime, basis = self._resolve(mime_glob, mime_magic)
        probe["identify_basis"] = basis
        result: dict[str, Any] = {"mime": mime, "probe": probe}

        if self.options.pronom:
            self._apply_pronom(path, probe)
        if self.options.trid_defs:
            self._apply_trid(name, probe)
        if self.options.magika and (basis == "disagree" or kind == "unknown"):
            self._apply_magika(path, head, probe, result)

        return result

    def close(self) -> None:
        """Release any helper process (e.g. a batched `sf` run)."""
        # Siegfried currently runs one subprocess per file; nothing to release.

    # -- winner / basis --------------------------------------------------

    def _resolve(self, glob_type: str | None, magic_type: str | None) -> tuple[str | None, str]:
        """shared-mime-info's resolution rule: a glob type that equals or is
        a subclass of the magic type wins; otherwise the magic type wins;
        otherwise (no magic ran) the glob type wins. See "Type identification"
        for the identify_basis table."""
        if magic_type is None:
            return glob_type, "name"
        if glob_type is None:
            return magic_type, "bytes"
        same_or_sub = glob_type == magic_type or self.db.is_subclass(glob_type, magic_type)
        agree = same_or_sub or self.db.is_subclass(magic_type, glob_type)
        winner = glob_type if same_or_sub else magic_type
        return winner, ("agree" if agree else "disagree")

    # -- bytes layer (libmagic, vendored magic fallback) ------------------

    def _ensure_magic(self) -> None:
        if self._magic_checked:
            return
        self._magic_checked = True
        try:
            import magic
        except ImportError as exc:
            self._scan_error_once("mime_magic", f"python-magic unavailable: {exc}")
            return
        try:
            self._magic_mime = magic.Magic(mime=True)
            self._magic_desc = magic.Magic(mime=False)
            self._magic_available = True
        except Exception as exc:
            self._scan_error_once("mime_magic", exc)

    def _run_magic(self, head: bytes) -> tuple[str | None, str | None]:
        self._ensure_magic()
        if self._magic_available:
            try:
                raw_mime = self._magic_mime.from_buffer(head)
                raw_desc = self._magic_desc.from_buffer(head)
            except Exception as exc:
                self._scan_error_once("mime_magic", exc)
            else:
                canon = self._normalize_libmagic_mime(raw_mime)
                desc = raw_desc
                if self.db.magic_match_type(canon, head):
                    better = self.db.comment(canon)
                    if better:
                        desc = better
                return canon, desc
        # libmagic unavailable: fall back to the vendored magic rules alone.
        guess = self.db.guess_by_magic(head)
        if guess is None:
            return None, None
        return guess

    def _normalize_libmagic_mime(self, raw_mime: str) -> str:
        lowered = raw_mime.strip().lower()
        return self.db.canon(_LIBMAGIC_OVERRIDES.get(lowered, lowered))

    # -- optional: PRONOM / Siegfried --------------------------------------

    def _init_pronom(self) -> None:
        sf = shutil.which("sf") or shutil.which("sf.exe")
        if not sf:
            from ..signatures import default_signatures_dir
            sig_dir = default_signatures_dir()
            for cand in (sig_dir / "sf.exe", sig_dir / "sf"):
                if cand.exists():
                    sf = str(cand)
                    break
        if not sf:
            self._scan_error_once(
                "pronom", "sf (Siegfried) not found on PATH or in the signatures directory")
            return
        self._sf_path = sf

    def _apply_pronom(self, path: str | None, probe: dict[str, Any]) -> None:
        if not self._sf_path or not path:
            return
        try:
            proc = subprocess.run([self._sf_path, "-json", path],
                                   capture_output=True, timeout=30, check=False)
            data = json.loads(proc.stdout.decode("utf-8", errors="replace"))
            files = data.get("files") or []
            if not files:
                return
            matches = files[0].get("matches") or []
            best = next((m for m in matches if m.get("id") and m["id"] != "UNKNOWN"),
                        matches[0] if matches else None)
            if not best:
                return
            if best.get("id"):
                probe["pronom_id"] = best["id"]
            if best.get("format"):
                probe["pronom_name"] = best["format"]
            if best.get("version"):
                probe["pronom_version"] = best["version"]
            if best.get("mime"):
                probe["pronom_mime"] = best["mime"]
            if best.get("basis"):
                probe["pronom_basis"] = best["basis"]
        except Exception as exc:
            self._scan_error_once("pronom", exc)

    # -- optional: TrID defs -----------------------------------------------

    def _init_trid(self, defs_path: str) -> None:
        try:
            self._trid_map = trid.load_defs(defs_path)
        except Exception as exc:
            self._scan_error_once("trid", exc)

    def _apply_trid(self, name: str, probe: dict[str, Any]) -> None:
        if not self._trid_map:
            return
        suf = suffix_of(name)
        if suf and suf in self._trid_map:
            probe["trid_desc"] = self._trid_map[suf]

    # -- optional: Magika ----------------------------------------------------

    def _init_magika(self) -> None:
        try:
            from magika import Magika
            self._magika = Magika()
        except Exception as exc:
            self._magika = None
            self._scan_error_once("magika", exc)

    def _apply_magika(self, path: str | None, head: bytes | None,
                       probe: dict[str, Any], result: dict[str, Any]) -> None:
        if self._magika is None:
            return
        try:
            if head is not None:
                buf = head
            elif path is not None:
                with fopen(path) as f:
                    buf = f.read(8192)
            else:
                return
            res = self._magika.identify_bytes(buf)
            out = res.prediction.output
            probe["magika_label"] = out.label
            probe["magika_score"] = res.prediction.score
            # Below 0.5 never changes mime (spec). At or above 0.5 we only
            # let Magika set mime when nothing else resolved one at all
            # (kind unknown, no glob, no magic) -- it never overrides an
            # existing glob/magic winner, agreeing or not.
            if res.prediction.score >= 0.5 and result.get("mime") is None and out.mime_type:
                result["mime"] = out.mime_type
        except Exception as exc:
            self._scan_error_once("magika", exc)

    # -- shared ------------------------------------------------------------

    def _scan_error_once(self, stage: str, message: Any) -> None:
        if stage in self._reported_stages:
            return
        self._reported_stages.add(stage)
        if isinstance(message, BaseException):
            message = f"{type(message).__name__}: {message}"
        self.scan_errors.append({"stage": stage, "message": str(message)})
