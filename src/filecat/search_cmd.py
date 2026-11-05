"""`filecat search`: upkeep of the file-name search.

    filecat search reindex      fill files.name_lc (the lower-cased name that name
                                searches match, and index) for records stored before
                                the column existed,
                                then build the name indexes if they are missing

A catalog made by an older filecat gets the column and its index when it is first
opened, but no values: filling millions of rows at connect would stall every command.
Until the last row has one, name searches match on `name` the slow way and stay
correct. The command works in batches that each commit, so it can be stopped and run
again (it only touches rows that still lack the value), and prints its progress.

On a large catalog (more than about 200,000 records) opening it adds only the column,
because building an index of millions of names inside a connect would stall the first
command (and, on PostgreSQL, block writes). The name indexes are built here instead, after
the backfill, each announced on stderr ("building index ...") as it starts; until then name
searches scan. A small catalog gets its indexes when it is opened.
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from .backends import open_backend


def _reindex(args: Any) -> int:
    backend = open_backend(args.backend, args.out, args.dsn)
    started, shown = time.monotonic(), [0.0]

    def progress(done: int) -> None:
        if not args.json and time.monotonic() - shown[0] >= 1.0:
            shown[0] = time.monotonic()
            print(f"\r  {done:,} records", end="", file=sys.stderr, flush=True)

    def say(text: str) -> None:
        print(("\n" if shown[0] and not args.json else "") + f"filecat search: {text} ...",
              file=sys.stderr, flush=True)

    try:
        done = backend.reindex_names(progress, max(1, args.batch), say=say)
    finally:
        backend.close()
    seconds = round(time.monotonic() - started, 1)
    if args.json:
        print(json.dumps({"filled": done, "seconds": seconds}))
    else:
        print(f"\r  {done:,} records filled in {seconds}s" if done else "nothing to fill: every record has a lower-cased name (name indexes checked)",
              file=sys.stderr if done else sys.stdout)
    return 0


def run(args: Any) -> int:
    return _reindex(args)
