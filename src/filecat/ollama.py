"""Ollama summaries, added after the walk. See file-catalog-requirements.md,
"Ollama". Off unless options.ollama is set (scan.scan_roots only imports
this module when that flag is on).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .backends.base import Backend
from .options import ScanOptions

PROMPT_VERSION = "filecat-1"
DEFAULT_URL = "http://127.0.0.1:11434"
TIMEOUT = 60.0
MAX_RAW = 4000

SYSTEM_PROMPT = (
    "You are cataloguing files for a file inventory tool. You will be given "
    "one JSON object describing a single file's already-measured metadata "
    "and, when available, a short decoded text sample. Reply with ONLY a "
    "JSON object of exactly this shape, no prose, no markdown fences:\n"
    '{"summary": "one or two sentences", "labels": ["...", "..."], '
    '"unsure": true}\n'
    "`labels` holds at most 8 short strings. `unsure` is true when the "
    "sample is too thin to summarise confidently. Describe what the "
    "measurements and sample show; never contradict a measured field such "
    "as kind, size, or an offset, and never invent one that is not there."
)


def base_url(options: ScanOptions) -> str:
    url = options.ollama_url or os.environ.get("OLLAMA_HOST")
    if not url:
        return DEFAULT_URL
    if "://" not in url:
        url = "http://" + url
    return url.rstrip("/")


def _record_payload(doc: dict[str, Any]) -> dict[str, Any]:
    """The record as sent to the model: no llm/errors, sample already capped
    by the probe (at most 4 KiB) and never re-attached as a raw file."""
    return {k: v for k, v in doc.items() if k not in ("llm", "errors")}


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def _parse_reply(content: str) -> dict[str, Any]:
    data = json.loads(_strip_fences(content))
    if not isinstance(data, dict) or "summary" not in data or "labels" not in data:
        raise ValueError("reply is not the expected {summary, labels, unsure} object")
    labels = list(data.get("labels") or [])[:8]
    return {
        "summary": str(data["summary"]),
        "labels": [str(x) for x in labels],
        "unsure": bool(data.get("unsure", False)),
    }


def _is_terminal_error(message: str) -> bool:
    """Errors worth failing the rest of the batch fast for, instead of
    waiting out a 60s timeout on every remaining candidate: the server is
    unreachable, or this model name does not exist on it."""
    m = message.lower()
    return any(s in m for s in (
        "refused", "econnrefused", "timed out", "timeout",
        "name or service not known", "no route to host",
        "http 404", "not found",
    ))


def call_ollama(url: str, model: str, doc: dict[str, Any], timeout: float = TIMEOUT) -> dict[str, Any]:
    """One POST /api/chat call. Returns an `llm` dict: the parsed reply, or
    {"model", "prompt_version", "error"} / {... , "raw", "error"}."""
    payload = {
        "model": model,
        "stream": False,
        "options": {"temperature": 0},
        "format": "json",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(_record_payload(doc), default=str)},
        ],
    }
    req = urllib.request.Request(
        url.rstrip("/") + "/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    llm: dict[str, Any] = {"model": model, "prompt_version": PROMPT_VERSION}

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
            detail = json.loads(body).get("error", body)
        except Exception:
            detail = str(e)
        llm["error"] = f"HTTP {e.code}: {detail}"
        return llm
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        llm["error"] = f"{type(e).__name__}: {e}"
        return llm

    try:
        envelope = json.loads(raw)
        content = envelope["message"]["content"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        llm["raw"] = raw[:MAX_RAW]
        llm["error"] = f"unexpected response shape: {e}"
        return llm

    try:
        parsed = _parse_reply(content)
    except (ValueError, json.JSONDecodeError) as e:
        llm["raw"] = content[:MAX_RAW]
        llm["error"] = f"reply is not the expected JSON: {e}"
        return llm

    llm.update(parsed)
    return llm


def _current(llm: Any, options: ScanOptions) -> bool:
    """A result from this model and prompt version, not an error: not asked again."""
    return (isinstance(llm, dict) and "error" not in llm and llm.get("model") == options.model
            and llm.get("prompt_version") == PROMPT_VERSION)


def select_candidates(backend: Backend, options: ScanOptions) -> list[dict[str, Any]]:
    """kind in options.ollama_kinds, size <= options.ollama_max_size, a
    non-empty decoded sample and no current result, at most
    options.ollama_max_files. A sample in the samples store is one
    candidate however many records share it; candidates come back with the
    sample attached (samples.attach)."""
    from . import samples
    out: list[dict[str, Any]] = []
    stored: dict[str, tuple[str, str]] = {}   # sample_id -> the first record naming it
    for doc in backend.list():
        if len(out) >= options.ollama_max_files:
            break
        if doc.get("kind") not in options.ollama_kinds or (doc.get("probe") or {}).get("secret"):
            continue
        if doc.get("size", 0) > options.ollama_max_size:
            continue
        if doc.get("sample"):
            if not _current(doc.get("llm"), options):
                out.append(doc)
        elif doc.get("sample_id"):
            stored.setdefault(doc["sample_id"], (doc["root"], doc["rel_path"]))
    # Looked up only now: some servers allow no second statement while a
    # listing is still open on the connection.
    ids = list(stored)
    for i in range(0, len(ids), 500):
        if len(out) >= options.ollama_max_files:
            break
        found = backend.get_samples(ids[i:i + 500])
        for sid in ids[i:i + 500]:
            if len(out) >= options.ollama_max_files:
                break
            if sid not in found or _current(found[sid].get("llm"), options):
                continue
            doc = samples.attach_one(backend, backend.get(*stored[sid]))
            if doc is not None and doc.get("sample"):
                out.append(doc)
    return out


def annotate_backend(backend: Backend, options: ScanOptions) -> None:
    """Call Ollama for the bounded candidate set and store each `llm`: on
    the sample document when the sample is in the samples store (every copy
    of the file shares it), else on the record. Never raises: a down server
    or unknown model lands in `llm.error` and the rest of the scan's result
    (exit code, stored fields) is unaffected."""
    if not options.ollama or not options.model:
        return
    url = base_url(options)
    fast_fail: str | None = None
    for doc in select_candidates(backend, options):
        if fast_fail is not None:
            llm = {"model": options.model, "prompt_version": PROMPT_VERSION, "error": fast_fail}
        else:
            llm = call_ollama(url, options.model, doc)
            if "error" in llm and _is_terminal_error(llm["error"]):
                fast_fail = llm["error"]
        if doc.get("sample_id"):
            backend.set_sample_llm(doc["sample_id"], llm)   # the record itself is unchanged
        else:
            doc["llm"] = llm
            backend.put(doc)
