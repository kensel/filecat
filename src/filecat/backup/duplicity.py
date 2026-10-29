"""duplicity (and deja-dup, which writes the same files).

A target folder holds backup sets named by their UTC times::

    duplicity-full.20240101T020000Z.manifest[.gpg]
    duplicity-full.20240101T020000Z.vol1.difftar.gz[.gpg]   opaque
    duplicity-full-signatures.20240101T020000Z.sigtar.gz     opaque
    duplicity-inc.20240101T020000Z.to.20240102T020000Z.manifest
    duplicity-inc.20240101T020000Z.to.20240102T020000Z.vol1.difftar.gz
    duplicity-new-signatures.20240101T020000Z.to.20240102T020000Z.sigtar.gz

A chain is a full set plus the incremental sets that follow it, each
starting where the previous one ended. The manifest is written last, so a
set without one did not finish. An unencrypted manifest names the source
(Hostname, Localdir) and lists every volume::

    Hostname myhost
    Localdir /home/me
    Volume 1:
        StartingPath   .
        EndingPath     "docs/a file" 3
        Hash SHA1 4f0b...

Checks: every set has a manifest and its signatures; volumes run 1..N
(and match the manifest when it is readable); every incremental set
continues a chain. Encrypted (.gpg) manifests are not read.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .storefs import LOCAL, StoreFS

_NAME = re.compile(
    r"^duplicity-(full|inc|full-signatures|new-signatures)\."
    r"(\d{8}T\d{6}Z)(?:\.to\.(\d{8}T\d{6}Z))?\."
    r"(manifest|vol(\d+)\.difftar|sigtar)((?:\.[A-Za-z0-9]+)*)$")


def _parse(name: str) -> dict[str, Any] | None:
    m = _NAME.match(name)
    if not m:
        return None
    kind, t1, t2, part, vol, ext = m.groups()
    return {"kind": kind, "t1": t1, "t2": t2,
            "part": "volume" if vol else part, "vol": int(vol) if vol else None,
            "encrypted": ".gpg" in ext}


def _iso(stamp: str | None) -> str | None:
    if not stamp:
        return None
    return datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape")
    return value


def read_manifest(text: str) -> dict[str, Any]:
    """Hostname, Localdir and {volume number: sha1} from a plain manifest."""
    out: dict[str, Any] = {"volumes": {}}
    vol = None
    for line in text.splitlines():
        s = line.strip()
        if line.startswith("Hostname "):
            out["hostname"] = _unquote(line[len("Hostname "):])
        elif line.startswith("Localdir "):
            out["localdir"] = _unquote(line[len("Localdir "):])
        elif m := re.match(r"^Volume (\d+):", line):
            vol = int(m.group(1))
            out["volumes"][vol] = None
        elif vol is not None and (m := re.match(r"^Hash (\w+) (\w+)", s)):
            out["volumes"][vol] = f"{m.group(1).lower()}:{m.group(2)}"
        elif line.startswith("Filelist"):
            vol = None
    return out


class _Duplicity:
    name = "duplicity"

    def matches(self, dir_name: str, names: set[str]) -> bool:
        return any(n.startswith("duplicity-") and _NAME.match(n) for n in names)

    def opaque(self, inner: str) -> bool:
        info = "/" not in inner and _parse(inner)
        return bool(info) and info["part"] in ("volume", "sigtar")

    def summarize(self, path: str, names: set[str], fs: StoreFS = LOCAL) -> dict[str, Any]:
        sets: dict[tuple, dict[str, Any]] = {}
        sigs: set[tuple] = set()
        for name in names:
            info = _parse(name)
            if info is None:
                continue
            if info["kind"].endswith("signatures"):
                sigs.add(("full" if info["kind"] == "full-signatures" else "inc", info["t1"], info["t2"]))
                continue
            key = (info["kind"], info["t1"], info["t2"])
            s = sets.setdefault(key, {"type": info["kind"], "start": _iso(info["t1"]),
                                      "end": _iso(info["t2"] or info["t1"]), "volumes": {},
                                      "manifest": None, "encrypted": False})
            s["encrypted"] = s["encrypted"] or info["encrypted"]
            if info["part"] == "manifest":
                s["manifest"] = name
            else:
                try:
                    s["volumes"][info["vol"]] = fs.stat(fs.join(path, name)).st_size
                except OSError:
                    s["volumes"][info["vol"]] = None

        problems: list[str] = []
        hosts: set[str] = set()
        out_sets = []
        for key in sorted(sets, key=lambda k: (k[1], k[2] or "")):
            s = sets[key]
            label = f"{s['type']} {key[1]}" + (f" to {key[2]}" if key[2] else "")
            vols = s.pop("volumes")
            have = sorted(vols)
            s["volume_count"] = len(have)
            s["bytes"] = sum(v or 0 for v in vols.values())
            if not s["manifest"]:
                problems.append(f"{label}: no manifest (the set did not finish)")
            elif not s["manifest"].endswith(".gpg"):
                try:
                    with fs.open(fs.join(path, s["manifest"]), "r", encoding="utf-8",
                                 errors="replace") as f:
                        man = read_manifest(f.read(4 * 1024 * 1024))
                except OSError as e:
                    problems.append(f"{label}: manifest unreadable: {e}")
                else:
                    for k in ("hostname", "localdir"):
                        if man.get(k):
                            s[k] = man[k]
                    if man.get("hostname"):
                        hosts.add(man["hostname"])
                    listed = set(man["volumes"])
                    missing = sorted(listed - set(have))
                    extra = sorted(set(have) - listed)
                    if missing:
                        problems.append(f"{label}: volumes {_list(missing)} listed in the manifest are missing")
                    if extra:
                        problems.append(f"{label}: volumes {_list(extra)} are not in the manifest")
                    s["manifest_volumes"] = len(listed)
            if have:
                gaps = sorted(set(range(1, have[-1] + 1)) - set(have))
                if gaps and not any(f"volumes {_list(gaps)}" in p for p in problems):
                    problems.append(f"{label}: volumes {_list(gaps)} missing")
            elif s["manifest"]:
                problems.append(f"{label}: no volumes")
            sig_key = ("full", key[1], None) if s["type"] == "full" else ("inc", key[1], key[2])
            if sig_key not in sigs:
                problems.append(f"{label}: signatures missing")
            out_sets.append(s)

        # chains: a full, then incrementals each starting where the last ended
        chains: list[dict[str, Any]] = []
        ends: dict[str, dict[str, Any]] = {}
        for key in sorted(sets, key=lambda k: (k[1], k[0] != "full")):
            s = sets[key]
            if s["type"] == "full":
                chain = {"start": s["start"], "end": s["end"], "sets": 1}
                chains.append(chain)
                ends[key[1]] = chain
            else:
                chain = ends.pop(key[1], None)
                if chain is None:
                    problems.append(f"inc {key[1]} to {key[2]}: does not continue any chain")
                    continue
                chain["end"] = s["end"]
                chain["sets"] += 1
                ends[key[2]] = chain

        machines = sorted(hosts)
        return {
            "format": self.name, "machines": machines, "chains": chains, "sets": out_sets,
            "versions": len(out_sets),
            "latest": max((s["end"] for s in out_sets), default=None),
            "problems": problems,
            "copy_keys": [f"duplicity:{s.get('hostname', '')}:{k[0]}:{k[1]}:{k[2] or ''}"
                          for k, s in sorted(sets.items(), key=lambda kv: kv[0][1])],
            "machine_keys": [f"host:{h.lower()}" for h in machines],
        }


def _list(numbers: list[int]) -> str:
    return ", ".join(map(str, numbers[:20])) + (" ..." if len(numbers) > 20 else "")


FORMAT = _Duplicity()
