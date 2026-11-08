"""The viewer's page (src/filecat/web/index.html) is one inline script: a syntax error there leaves
every view blank, and no Python test would notice. Node checks it when it is installed."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = Path(__file__).parent.parent / "src" / "filecat" / "web" / "index.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_page_script_parses(tmp_path):
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", PAGE.read_text(encoding="utf-8"), re.S)
    assert scripts
    for i, body in enumerate(scripts):
        path = tmp_path / f"page{i}.mjs"
        path.write_text(body, encoding="utf-8")
        done = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
