"""Show, check or set the filecat version in every file that carries it.

    uv run python scripts/version.py                  print each place and its version
    uv run python scripts/version.py --check          exit 1 unless every place agrees
    uv run python scripts/version.py --check v0.2.1   ... and they agree with this tag
    uv run python scripts/version.py set 0.2.2        write 0.2.2 everywhere

The Python package and the agent share one version, and a release tag vX.Y.Z
must match it (.github/workflows/release.yml runs --check with the tag). The
places are PLACES below; each file has a comment pointing here. The lock files
are edited in place (only the filecat / filecat-agent entry), so `set` needs
neither uv nor cargo. See docs/releasing.md.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"\d+\.\d+\.\d+")

# (file, regex whose group 2 is the version; groups 1 and 3 are kept as they are)
PLACES: list[tuple[str, re.Pattern[str]]] = [
    ("pyproject.toml", re.compile(r'(\[project\]\s*\nname = "filecat"\s*\nversion = ")([^"]+)(")')),
    ("src/filecat/__init__.py", re.compile(r'(^__version__ = ")([^"]+)(")', re.M)),
    ("uv.lock", re.compile(r'(\[\[package\]\]\s*\nname = "filecat"\s*\nversion = ")([^"]+)(")')),
    ("agent/Cargo.toml", re.compile(r'(\[package\]\s*\nname = "filecat-agent"\s*\nversion = ")([^"]+)(")')),
    ("agent/Cargo.lock", re.compile(r'(\[\[package\]\]\s*\nname = "filecat-agent"\s*\nversion = ")([^"]+)(")')),
]


def read(rel: str) -> str:
    with (ROOT / rel).open(encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def versions() -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for rel, rx in PLACES:
        m = rx.search(read(rel))
        out[rel] = m.group(2) if m else None
    return out


def check(tag: str | None) -> list[str]:
    """Problems found; empty when every place agrees (and with the tag, if given)."""
    found = versions()
    problems = [f"{rel}: version not found" for rel, v in found.items() if v is None]
    distinct = {v for v in found.values() if v is not None}
    if len(distinct) > 1:
        problems.append("versions differ: " + ", ".join(f"{rel}={v}" for rel, v in found.items()))
    if tag is not None:
        want = tag.removeprefix("refs/tags/").removeprefix("v")
        if distinct != {want}:
            problems.append(f"tag {tag} does not match the version {', '.join(sorted(distinct)) or '?'}")
    return problems


def set_version(new: str) -> None:
    if not SEMVER.fullmatch(new):
        raise SystemExit(f"not X.Y.Z: {new}")
    for rel, rx in PLACES:
        path = ROOT / rel
        raw = path.read_bytes().decode("utf-8")
        crlf = "\r\n" in raw
        text = raw.replace("\r\n", "\n")
        text, n = rx.subn(lambda m: m.group(1) + new + m.group(3), text, count=1)
        if n != 1:
            raise SystemExit(f"{rel}: version not found")
        path.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))
        print(f"{rel}: {new}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", nargs="?", const="", metavar="TAG",
                    help="exit 1 unless every place agrees (and matches TAG, e.g. v0.2.1)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("set", help="write a version everywhere").add_argument("version")
    args = ap.parse_args(argv)
    if args.cmd == "set":
        set_version(args.version.removeprefix("v"))
        return 0
    if args.check is not None:
        problems = check(args.check or None)
        for p in problems:
            print(p, file=sys.stderr)
        if not problems:
            print(f"ok: {next(iter(versions().values()))} everywhere")
        return 1 if problems else 0
    for rel, v in versions().items():
        print(f"{v or '?':10} {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
