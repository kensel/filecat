"""Small filesystem helpers."""
from __future__ import annotations

import os
import time

_ATTEMPTS = 20


def replace(src: str | os.PathLike, dst: str | os.PathLike) -> None:
    """os.replace that rides out a brief Windows sharing violation.

    Antivirus scanners and the search indexer open freshly written files for
    a moment; replacing one then fails with WinError 5/32. Retry for about
    two seconds before giving up.
    """
    for attempt in range(_ATTEMPTS):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == _ATTEMPTS - 1:
                raise
            time.sleep(0.02 * (attempt + 1))
