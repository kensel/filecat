"""Replace internal names in the repo with the generic aliases from sanitize-aliases.local.toml.

    uv run python scripts/sanitize.py [--aliases FILE] [--check]

Rewrites every text file git would commit (tracked, or untracked and not
ignored) except the alias files themselves. Keys match whole words,
case-insensitively; the alias takes the match's case when that is all
caps or Title case. --check rewrites nothing and exits 1 if any key is
still present.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP = {"sanitize-aliases.local.toml", "sanitize-aliases.example.toml", "LICENSE"}


def load(path: Path) -> dict[str, str]:
    with path.open("rb") as f:
        return tomllib.load(f)["aliases"]


def pattern(aliases: dict[str, str]) -> re.Pattern[str]:
    keys = sorted(aliases, key=len, reverse=True)
    alt = "|".join(re.escape(k) for k in keys)
    return re.compile(rf"(?<![A-Za-z0-9])(?:{alt})(?![A-Za-z0-9])", re.IGNORECASE)


def targets() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / f for f in sorted(set(out.split("\0"))) if f and f not in SKIP]


def recase(word: str, alias: str) -> str:
    if not any(c.isalpha() for c in word):
        return alias
    if word.isupper():
        return alias.upper()
    if word[0].isupper() and word[1:].islower() and alias.islower():
        return alias.capitalize()
    return alias


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--aliases", type=Path, default=ROOT / "sanitize-aliases.local.toml")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    aliases = load(args.aliases)
    lookup = {k.lower(): v for k, v in aliases.items()}
    rx = pattern(aliases)

    found = 0
    for path in targets():
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits = rx.findall(text)
        if not hits:
            continue
        found += len(hits)
        rel = path.relative_to(ROOT).as_posix()
        if args.check:
            print(f"{rel}: {', '.join(sorted(set(hits)))}")
        else:
            new = rx.sub(lambda m: recase(m.group(0), lookup[m.group(0).lower()]), text)
            path.write_bytes(new.encode("utf-8"))
            print(f"{rel}: {len(hits)} replaced")
    return 1 if args.check and found else 0


if __name__ == "__main__":
    sys.exit(main())
