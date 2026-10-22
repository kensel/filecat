from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from filecat import ollama
from filecat.backends.memory import MemoryBackend
from filecat.options import ScanOptions
from filecat.record import root_id as root_id_of


class _Handler(BaseHTTPRequestHandler):
    reply_content = ""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps({"message": {"content": self.reply_content}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _start_server(reply_content: str):
    _Handler.reply_content = reply_content
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, t


def test_base_url_defaults_and_scheme():
    assert ollama.base_url(ScanOptions()) == ollama.DEFAULT_URL
    assert ollama.base_url(ScanOptions(ollama_url="localhost:1234")) == "http://localhost:1234"
    assert ollama.base_url(ScanOptions(ollama_url="https://x:1")) == "https://x:1"


def test_call_ollama_valid_reply():
    httpd, t = _start_server('{"summary": "a test file", "labels": ["test", "demo"], "unsure": false}')
    try:
        port = httpd.server_address[1]
        doc = {"root": "R", "root_id": "x", "rel_path": "f.txt", "kind": "unknown",
               "size": 10, "sample": "hi"}
        llm = ollama.call_ollama(f"http://127.0.0.1:{port}", "testmodel", doc, timeout=5)
        assert llm["summary"] == "a test file"
        assert llm["labels"] == ["test", "demo"]
        assert llm["unsure"] is False
        assert llm["model"] == "testmodel"
        assert llm["prompt_version"] == ollama.PROMPT_VERSION
        assert "error" not in llm
    finally:
        httpd.shutdown()
        t.join(timeout=2)


def test_call_ollama_fenced_reply():
    content = "```json\n" + '{"summary": "fenced", "labels": [], "unsure": true}' + "\n```"
    httpd, t = _start_server(content)
    try:
        port = httpd.server_address[1]
        doc = {"root": "R", "root_id": "x", "rel_path": "f.txt", "kind": "unknown",
               "size": 10, "sample": "hi"}
        llm = ollama.call_ollama(f"http://127.0.0.1:{port}", "testmodel", doc, timeout=5)
        assert llm["summary"] == "fenced"
        assert llm["unsure"] is True
        assert "error" not in llm
    finally:
        httpd.shutdown()
        t.join(timeout=2)


def test_call_ollama_non_json_reply_sets_raw_and_error():
    httpd, t = _start_server("not json at all, sorry")
    try:
        port = httpd.server_address[1]
        doc = {"root": "R", "root_id": "x", "rel_path": "f.txt", "kind": "unknown",
               "size": 10, "sample": "hi"}
        llm = ollama.call_ollama(f"http://127.0.0.1:{port}", "testmodel", doc, timeout=5)
        assert "error" in llm
        assert "raw" in llm
    finally:
        httpd.shutdown()
        t.join(timeout=2)


def test_annotate_backend_refused_port_keeps_measured_fields(fixture_dir):
    backend = MemoryBackend()
    doc = {
        "root_id": root_id_of("R"), "root": "R", "rel_path": "f.txt", "name": "f.txt",
        "size": 10, "kind": "unknown", "suffix": "txt", "sha256": "deadbeef",
        "sample": "hi there",
    }
    backend.put(doc)
    options = ScanOptions(ollama=True, model="testmodel", ollama_url="127.0.0.1:9",
                         ollama_kinds=["unknown"], ollama_max_size=1000, ollama_max_files=10)
    ollama.annotate_backend(backend, options)

    stored = backend.get("R", "f.txt")
    assert stored["kind"] == "unknown"
    assert stored["sha256"] == "deadbeef"
    assert stored["size"] == 10
    assert "error" in stored["llm"]
    assert stored["llm"]["model"] == "testmodel"


def test_select_candidates_respects_kind_size_sample_and_cap():
    backend = MemoryBackend()
    for i in range(5):
        backend.put({
            "root_id": root_id_of("R"), "root": "R", "rel_path": f"u{i}.bin", "name": f"u{i}.bin",
            "size": 10, "kind": "unknown", "suffix": "bin", "sample": "data",
        })
    backend.put({
        "root_id": root_id_of("R"), "root": "R", "rel_path": "big.bin", "name": "big.bin",
        "size": 10_000_000, "kind": "unknown", "suffix": "bin", "sample": "data",
    })
    backend.put({
        "root_id": root_id_of("R"), "root": "R", "rel_path": "nosample.bin", "name": "nosample.bin",
        "size": 10, "kind": "unknown", "suffix": "bin",
    })
    backend.put({
        "root_id": root_id_of("R"), "root": "R", "rel_path": "wrongkind.txt", "name": "wrongkind.txt",
        "size": 10, "kind": "text", "suffix": "txt", "sample": "data",
    })
    options = ScanOptions(ollama=True, model="m", ollama_kinds=["unknown"],
                         ollama_max_size=1000, ollama_max_files=3)
    candidates = ollama.select_candidates(backend, options)
    assert len(candidates) == 3
    assert all(c["kind"] == "unknown" and c["size"] <= 1000 and c.get("sample") for c in candidates)
