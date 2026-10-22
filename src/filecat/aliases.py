"""Root aliases: walk a tree through one path, record it under another.

    filecat scan \\\\192.0.2.13\\home --alias \\\\192.0.2.13=\\\\nas-main

reads the share through the IP (so Windows can hold a second connection to
the NAS with other credentials) and records it as root \\\\nas-main\\home.
An alias is a path prefix matched on whole components, case-insensitively;
the longest matching prefix wins. `enrich` applies the same table in
reverse, so records under \\\\nas-main\\... are read back through the IP.

filecat.toml holds the permanent ones (literal strings need no escaping):

    [aliases]
    '\\\\192.0.2.13' = '\\\\nas-main'
"""
from __future__ import annotations


def parse(items: list[str] | None, flag: str = "--alias") -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        src, sep, dst = item.partition("=")
        if not sep or not src or not dst:
            raise ValueError(f"{flag} wants PATH=ROOT, got {item!r}")
        out[src] = dst
    return out


def _norm(path: str) -> str:
    path = path.replace("/", "\\")
    return path if path.endswith(":\\") else path.rstrip("\\")


def _swap(path: str, table: list[tuple[str, str]]) -> str:
    norm = _norm(path)
    low = norm.lower()
    best: tuple[str, str] | None = None
    for prefix, repl in table:
        p = _norm(prefix).lower()
        if low == p or low.startswith(p if p.endswith("\\") else p + "\\"):
            if best is None or len(p) > len(best[0]):
                best = (p, repl)
    if best is None:
        return path
    prefix, repl = best
    rest = norm[len(prefix):].lstrip("\\")
    repl = _norm(repl)
    if not rest:
        return repl
    return repl + rest if repl.endswith("\\") else f"{repl}\\{rest}"


def recorded_root(path: str, aliases: dict[str, str]) -> str:
    """The root a scan of `path` is recorded under."""
    return _swap(path, list(aliases.items()))


def source_path(root: str, aliases: dict[str, str]) -> str:
    """Where a recorded root is read from (the reverse of recorded_root)."""
    return _swap(root, [(dst, src) for src, dst in aliases.items()])
