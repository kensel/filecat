"""Run the agent tests against the real Rust `filecat-agent` instead of the in-process fake.

    FILECAT_TEST_AGENT_BIN=/root/.cache/filecat-agent-target-conformance/x86_64-unknown-linux-musl/release/filecat-agent \\
        python -m pytest tests -q

`agent/build.sh conformance` builds that binary (the `test-root` feature: every request path is taken
below `FILECAT_AGENT_TEST_ROOT`, so a temp directory can be served as "/" exactly as the fake does).
`_fake_agent.py` swaps `FakeAgent` for `RealAgent` at import when the variable is set; no test changes.

On Windows the binary is a path inside WSL (distro `FILECAT_TEST_AGENT_WSL_DISTRO`, default
`ubuntu2`); the served directory is passed as /mnt/<drive>/..., and WSL2's localhost forwarding makes
the agent's 127.0.0.1 port reachable. Anywhere else the binary is started directly.

`RealAgent` keeps the fake's public surface where it can: `port`, `token`, `connections`, and
`requests` / `wire`, which a small relay in front of the agent records (the relay presents the test
certificate, so `cert_fingerprint()` still names what the client sees). What only the fake can do
(simulated Windows attributes, planted unreadable files, canned `run` output, recordings, forced
progress lines) skips the test with a message that names the hook.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

DATA = Path(__file__).parent / "data"
CERT = DATA / "agent.crt"
KEY = DATA / "agent.key"
DISTRO = os.environ.get("FILECAT_TEST_AGENT_WSL_DISTRO", "ubuntu2")
ON_WINDOWS = sys.platform == "win32"

# Hooks only the in-process fake has: writing one of these skips the test.
FAKE_ONLY = {
    "entry_errors": "forced list_dir entry errors", "extra_entries": "injected list_dir entries",
    "extras": "injected list_dir entries", "served_as": "non-UTF-8 names served from UTF-8 files",
    "unreadable": "planted unreadable names", "mounts": "folders pretending to be mounts",
    "sum_delay": "a slowed-down walk", "progress_always": "forced progress lines",
    "max_sums": "a lowered sum limit", "run_outputs": "canned `run` output",
    "unavailable": "missing allowlist binaries", "statfs_data": "canned statfs numbers",
    "subtree_overrides": "canned sum_subtree answers", "windows_attributes": "simulated Windows attributes",
    "attributes_after_list": "simulated Windows attributes",
}


# Tests that assert a constant of the fake or reach into it; skipped in a real-agent run (conftest.py).
FAKE_HELLO = "asserts the fake's hello constants (agent_version 0.2.0-test, hostname fake-nas)"
WRONG_POLICY_ID = "makes the fake answer a wrong policy id (monkeypatches _fake_agent.policy_id); the real agent's is right"
NOT_AGAINST_THE_REAL_AGENT = {
    "test_hello_and_auth": FAKE_HELLO,
    "test_from_config": FAKE_HELLO,
    "test_agents_test_ok": FAKE_HELLO,
    "test_a_policy_id_the_client_does_not_expect_refuses_the_connection": WRONG_POLICY_ID,
    "test_a_policy_id_mismatch_stops_the_scan_before_anything_is_listed": WRONG_POLICY_ID,
    "test_agent_scan_matches_local_scan": "lowers hashing.PARTIAL_HASH_CUTOFF in the client process to make a "
                                          "76 KB file partial; the real agent's cutoff is fixed at 64 MiB "
                                          "(the 64 MiB+ digests are checked by the cargo hash vectors)",
    "test_agent_records_carry_allocated_size_and_inode": "expects the fake's 4096-byte blocks; NTFS stores a tiny "
                                                         "file in the MFT, so st_blocks is 0 on /mnt/c",
}


def linux_path(path: Path | str) -> str:
    """The path as the (Linux) agent sees it."""
    p = str(Path(path).resolve()) if ON_WINDOWS else str(path)
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p)
    if ON_WINDOWS and m:
        return "/mnt/" + m.group(1).lower() + "/" + m.group(2).replace("\\", "/")
    return p.replace("\\", "/")


def _skip(what: str) -> None:
    pytest.skip(f"fake-agent hook, not available against the real agent: {what}")


class RealAgent:
    def __init__(self, root: Path, token: str = "s3cret", *, protocol: int = 1, cert: Path = CERT,
                 key: Path = KEY, allow_roots: list[str] | None = None) -> None:
        object.__setattr__(self, "_ready", False)
        self.root = root
        self.token = token
        self.protocol = protocol
        self.allow_roots = allow_roots
        self.requests: list[dict[str, Any]] = []
        self.wire: list[tuple[str, str]] = []
        self.connections = 0
        self._bin = os.environ["FILECAT_TEST_AGENT_BIN"]
        self._proc: subprocess.Popen | None = None
        self._pid: str | None = None
        self._agent_port = 0
        self._lock = threading.Lock()
        self._open: list[socket.socket] = []
        self._stop = False
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._client_ctx.check_hostname = False
        self._client_ctx.verify_mode = ssl.CERT_NONE
        self._start_agent()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
        object.__setattr__(self, "_ready", True)

    # --- the fake's hooks ---
    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_ready", False):
            if name in FAKE_ONLY:
                _skip(f"{name} ({FAKE_ONLY[name]})")
            if name == "allow_roots":                       # supported: restart the agent with the new roots
                object.__setattr__(self, name, value)
                self._start_agent()
                return
            if name == "allow_roots_source":
                _skip(name)
        object.__setattr__(self, name, value)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        _skip(f"{name} (state kept by the fake)")

    def load_recording(self, rec: Path) -> None:
        _skip("load_recording (canned `run`, statfs and sum_subtree answers)")

    def __enter__(self) -> "RealAgent":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # --- the agent process ---
    def _command(self) -> list[str]:
        env = {"FILECAT_AGENT_TOKEN": self.token, "FILECAT_AGENT_TEST_ROOT": linux_path(self.root),
               "FILECAT_AGENT_ALLOW_ROOTS": "/" if self.allow_roots is None else ":".join(self.allow_roots)}
        pairs = [f"{k}={v}" for k, v in env.items()]
        agent = [self._bin, "--listen", "127.0.0.1:0", "--cert", "/tmp/filecat-conformance.crt",
                 "--key", "/tmp/filecat-conformance.key", "--env-file", "/nonexistent/.env"]
        inner = ["sh", "-c", 'echo "pid $$"; exec "$@"', "sh", "env", *pairs, *agent]
        return ["wsl.exe", "-d", DISTRO, "--exec", *inner] if ON_WINDOWS else inner      # --exec: no shell in between

    def _start_agent(self) -> None:
        self._kill_agent()
        proc = subprocess.Popen(self._command(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self._proc = proc
        for _ in range(40):
            line = proc.stdout.readline()
            if not line:
                break
            if line.startswith("pid "):
                self._pid = line.split()[1]
            m = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
            if m:
                self._agent_port = int(m.group(1))
                threading.Thread(target=lambda: [None for _ in proc.stdout], daemon=True).start()   # drain
                return
        raise RuntimeError(f"the real agent did not start: {self._command()}")

    def _kill_agent(self) -> None:
        proc, pid = self._proc, self._pid
        self._proc = self._pid = None
        if proc is None:
            return
        proc.terminate()
        if ON_WINDOWS and pid:                              # killing wsl.exe alone leaves the Linux process
            subprocess.Popen(["wsl.exe", "-d", DISTRO, "--exec", "kill", pid], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        elif pid:
            try:
                os.kill(int(pid), 15)
            except OSError:
                pass

    # --- the recording relay ---
    def stop(self) -> None:
        self._stop = True
        try:
            self._listener.close()
        except OSError:
            pass
        self.drop_connections()
        self._kill_agent()

    def drop_connections(self) -> None:
        with self._lock:
            sockets, self._open = self._open, []
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def _accept(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._relay, args=(conn,), daemon=True).start()

    def _relay(self, raw: socket.socket) -> None:
        try:
            front = self._ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            return
        try:
            back = self._client_ctx.wrap_socket(socket.create_connection(("127.0.0.1", self._agent_port), timeout=30))
            back.settimeout(None)
        except OSError:
            front.close()
            return
        with self._lock:
            self._open += [front, back]
            self.connections += 1
        try:
            frfile, brfile = front.makefile("rb"), back.makefile("rb")
            while True:
                line = frfile.readline()
                if not line:
                    return
                with self._lock:
                    self.wire.append(("in", line.decode("utf-8", "replace").rstrip("\n")))
                    try:
                        req = json.loads(line)
                        if isinstance(req, dict):
                            self.requests.append(req)
                    except ValueError:
                        pass
                back.sendall(line)
                while True:
                    reply = brfile.readline()
                    if not reply:
                        return
                    obj = None
                    try:
                        obj = json.loads(reply)
                    except ValueError:
                        pass
                    if isinstance(obj, dict) and obj.get("protocol") is not None and self.protocol != 1:
                        obj["protocol"] = self.protocol         # a "newer agent": only hello carries it
                        reply = json.dumps(obj).encode() + b"\n"
                    with self._lock:
                        self.wire.append(("out", reply.decode("utf-8", "replace").rstrip("\n")))
                    front.sendall(reply)
                    if not (isinstance(obj, dict) and "ok" not in obj):     # a progress line has no `ok`
                        break
        except OSError:
            return
        finally:
            for s in (front, back):
                try:
                    s.close()
                except OSError:
                    pass
