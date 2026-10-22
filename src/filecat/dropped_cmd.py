"""`filecat dropped`: records of files and folders that vanished from disk.

A scan moves such records to the dropped store (Backend.drop_many) instead
of deleting them, and purges entries older than --keep-dropped days (90)
at the end of every scan. This lists them, newest first, or purges now.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from itertools import islice
from typing import Any

from .backends import open_backend
from .backends.base import dropped_now
from .roots_cmd import _local
from .summary import _human_bytes


def run(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    try:
        if args.purge:
            # --days 0 removes everything, including entries dropped this second
            cutoff = ("9999" if args.days <= 0
                      else dropped_now(datetime.now(timezone.utc) - timedelta(days=args.days)))
            n = backend.purge_dropped(cutoff)
            print(f"purged {n} dropped records" + (f" older than {args.days} days" if args.days > 0 else ""),
                  file=sys.stderr)
            return 0
        if args.root:
            rows = (d for r in args.root for d in backend.list_dropped(r))
        else:
            rows = backend.list_dropped()
        if args.limit:
            rows = islice(rows, args.limit)
        shown = 0
        for d in rows:
            shown += 1
            if args.json:
                print(json.dumps(d, ensure_ascii=False))
                continue
            size = "dir" if d.get("kind") == "dir" else _human_bytes(d.get("size") or 0)
            print(f"{_local(d.get('dropped_at'))}  {d.get('drop_reason', '?'):8}  {size:>10}  "
                  f"{d.get('root')}  {d.get('rel_path')}")
        if not shown and not args.json:
            print("(no dropped records)")
    except NotImplementedError as e:
        print(f"filecat dropped: {e}", file=sys.stderr)
        return 1
    finally:
        backend.close()
    return 0
