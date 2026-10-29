"""`filecat show`: print the stored record for one (root, rel_path)."""
from __future__ import annotations

import json
import sys
from typing import Any

from . import samples
from .backends import open_backend


def run(args: Any) -> int:
    rel_path = args.rel_path.replace("\\", "/")
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        doc = samples.attach_one(backend, backend.get(args.root, rel_path))
    finally:
        backend.close()
    if doc is None:
        print(f"filecat show: no record for root={args.root!r} rel_path={rel_path!r}",
              file=sys.stderr)
        return 1
    if doc.get("kind") == "rollup":
        info = (doc.get("probe") or {}).get("rollup") or {}
        from .summary import _human_bytes
        print(f"{info.get('tag', doc.get('name'))} rollup: {info.get('total_files', 0)} files in "
              f"{info.get('total_dirs', 0)} folders, {_human_bytes(doc.get('size') or 0)}, "
              f"{info.get('matched', 0)} folded in" + ("; a lower bound (some of it could not be read)"
                                                      if info.get("partial") else ""), file=sys.stderr)
    print(json.dumps(doc, indent=2, ensure_ascii=False))
    return 0
