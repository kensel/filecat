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
    print(json.dumps(doc, indent=2, ensure_ascii=False))
    return 0
