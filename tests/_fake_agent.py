"""A filecat-agent speaking protocol 1 (docs/agent-protocol.md), in Python,
for the agent client's tests.

It serves a temp directory as "/": the agent path /volume1/Backup/a.zip is
<root>/volume1/Backup/a.zip. Digests come from filecat.hashing, the
reference the Rust agent must reproduce, fed the 100 ns-floored mtime the
protocol demands. TLS uses the self-signed pair in tests/data (generated
once with openssl, ed25519, valid to 2126; the key protects nothing).
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import socket
import ssl
import threading
from pathlib import Path
from typing import Any

from filecat.hashing import hash_file

DATA = Path(__file__).parent / "data"
CERT = DATA / "agent.crt"
KEY = DATA / "agent.key"
MAX_READ = 4 * 1024 * 1024


def cert_fingerprint(cert: Path = CERT) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()


def floor100(ns: int) -> int:
    return ns - ns % 100


class _Fail(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class FakeAgent:
    def __init__(self, root: Path, token: str = "s3cret", *, protocol: int = 1,
                 cert: Path = CERT, key: Path = KEY) -> None:
        self.root = root
        self.token = token
        self.protocol = protocol
        self.requests: list[dict[str, Any]] = []        # every request received, in order
        self.connections = 0
        self.entry_errors: set[str] = set()             # names list_dir reports with an error
        self.extra_entries: list[dict[str, Any]] = []   # raw entries appended to every list_dir
        self.extras: dict[str, list[dict[str, Any]]] = {}   # ... or only to list_dir of this path
        self.served_as: dict[str, bytes] = {}           # real name -> the (non-UTF-8) bytes it is listed as
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._open: list[socket.socket] = []
        self._lock = threading.Lock()
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def __enter__(self) -> "FakeAgent":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def stop(self) -> None:
        self._stop = True
        try:
            self._listener.close()
        except OSError:
            pass
        self.drop_connections()

    def drop_connections(self) -> None:
        """Close every open connection, as an agent restart or an idle timeout would."""
        with self._lock:
            sockets, self._open = self._open, []
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    # --- connections ---
    def _accept(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, raw: socket.socket) -> None:
        try:
            conn = self._ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            return
        with self._lock:
            self._open.append(conn)
            self.connections += 1
        authed = False
        policy: dict[str, Any] = {}
        try:
            rfile = conn.makefile("rb")
            while True:
                line = rfile.readline()
                if not line:
                    return
                close = False
                try:
                    req = json.loads(line)
                    if not isinstance(req, dict):
                        raise _Fail("bad_request", "not an object")
                    self.requests.append(req)
                    cmd = req.get("cmd")
                    if cmd == "hello":
                        resp = {"ok": True, "protocol": self.protocol, "agent_version": "0.2.0-test",
                                "hostname": "fake-nas", "os": "linux", "arch": "x86_64"}
                    elif cmd == "auth":
                        if req.get("token") != self.token:
                            close = True
                            raise _Fail("unauthorized", "invalid token")
                        authed, resp = True, {"ok": True}
                    elif not authed:
                        raise _Fail("unauthorized", "authenticate first")
                    elif cmd == "configure_policy":
                        policy = req.get("policy") or {}
                        resp = {"ok": True}
                    else:
                        resp = self._command(cmd, req, policy)
                except _Fail as exc:
                    resp = {"ok": False, "error": str(exc), "code": exc.code}
                except FileNotFoundError as exc:
                    resp = {"ok": False, "error": str(exc), "code": "not_found"}
                except PermissionError as exc:
                    resp = {"ok": False, "error": str(exc), "code": "permission_denied"}
                except json.JSONDecodeError:
                    resp = {"ok": False, "error": "bad json", "code": "bad_request"}
                except OSError as exc:
                    resp = {"ok": False, "error": str(exc), "code": "io"}
                conn.sendall(json.dumps(resp).encode() + b"\n")
                if close:
                    return
        except OSError:
            return
        finally:
            conn.close()

    # --- commands ---
    def real(self, req: dict[str, Any]) -> Path:
        if "path_b64" in req:
            raw = base64.b64decode(req["path_b64"])
            back = {v: k.encode() for k, v in self.served_as.items()}
            path = b"/".join(back.get(part, part) for part in raw.split(b"/")).decode("utf-8")
        else:
            path = req.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise _Fail("bad_request", "path must be absolute")
        real = self.root / path.lstrip("/")
        real.lstat()                    # FileNotFoundError -> not_found
        return real

    def _command(self, cmd: Any, req: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
        if cmd == "list_dir":
            return self._list_dir(req, policy)
        if cmd == "measure":
            return self._measure(req)
        if cmd == "read_range":
            return self._read_range(req)
        if cmd == "sum_subtree":
            return {"ok": True, "path": req.get("path"), **self._sum(self.real(req), policy)}
        if cmd == "storage_topology":
            return {"ok": True, "volumes": [{"mount_point": "/volume1", "device": "/dev/vg1/volume_1",
                                             "fs_type": "btrfs", "total_bytes": 10, "used_bytes": 4,
                                             "free_bytes": 6, "shares": ["Backup"],
                                             "block_devices": []}]}
        raise _Fail("bad_request", f"unknown cmd {cmd!r}")

    @staticmethod
    def _numbers(st: os.stat_result) -> dict[str, int]:
        return {"size": st.st_size, "allocated_size": -(-st.st_size // 4096) * 4096,
                "ino": st.st_ino, "dev": st.st_dev, "nlink": st.st_nlink,
                "mtime_ns": floor100(st.st_mtime_ns), "ctime_ns": floor100(st.st_ctime_ns)}

    def _list_dir(self, req: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
        path = self.real(req)
        if not path.is_dir():
            raise _Fail("bad_request", "not a directory")
        dst = path.stat()
        exclude = set(policy.get("exclude", []))
        groups = policy.get("rollup_groups", {})
        entries: list[dict[str, Any]] = []
        rollups: dict[str, dict[str, Any]] = {}
        for child in sorted(os.scandir(path), key=lambda e: e.name):
            if child.name in exclude:
                continue
            if child.name in self.entry_errors:
                entries.append({"name": child.name, "kind": "file",
                                "error": {"code": "permission_denied", "message": "denied"}})
                continue
            st = os.lstat(child.path)
            tag = next((t for t, pats in groups.items()
                        if any(fnmatch.fnmatchcase(child.name, p) for p in pats)), None)
            if tag is not None:
                acc = rollups.setdefault(tag, {"tag": tag, "matched": 0, "total_files": 0,
                                               "total_dirs": 0, "total_size": 0,
                                               "total_allocated_size": 0, "newest_mtime_ns": 0,
                                               "errors": 0})
                acc["matched"] += 1
                if child.is_dir(follow_symlinks=False):
                    acc["total_dirs"] += 1
                    sub = self._sum(Path(child.path), policy)
                    for key in ("total_files", "total_dirs", "total_size", "total_allocated_size", "errors"):
                        acc[key] += sub[key]
                    acc["newest_mtime_ns"] = max(acc["newest_mtime_ns"], sub["newest_mtime_ns"])
                else:
                    acc["total_files"] += 1
                    acc["total_size"] += st.st_size
                    acc["total_allocated_size"] += self._numbers(st)["allocated_size"]
                acc["newest_mtime_ns"] = max(acc["newest_mtime_ns"], floor100(st.st_mtime_ns))
                continue
            entry: dict[str, Any] = {"kind": "file", **self._numbers(st)}
            if child.is_symlink():
                entry.update(kind="link", link_target=os.readlink(child.path))
            elif child.is_dir(follow_symlinks=False):
                entry["kind"] = "dir"
            elif not child.is_file(follow_symlinks=False):
                entry["kind"] = "other"
            if child.name in self.served_as:
                raw = self.served_as[child.name]
                entry.update(name=raw.decode("utf-8", "replace"), name_b64=base64.b64encode(raw).decode())
            else:
                entry["name"] = child.name
            entries.append(entry)
        for tag, acc in rollups.items():
            entries.append({"name": tag, "kind": "rollup", "size": acc["total_size"],
                            "allocated_size": acc["total_allocated_size"], "ino": 0,
                            "dev": dst.st_dev, "nlink": 1, "mtime_ns": acc["newest_mtime_ns"],
                            "ctime_ns": acc["newest_mtime_ns"], "rollup": acc})
        entries += self.extra_entries + self.extras.get(req.get("path"), [])
        return {"ok": True, "path": req.get("path"), "dev": dst.st_dev,
                "mtime_ns": floor100(dst.st_mtime_ns), "ctime_ns": floor100(dst.st_ctime_ns),
                "entries": entries}

    def _measure(self, req: dict[str, Any]) -> dict[str, Any]:
        policy = req.get("hash", "auto")
        head_bytes = req.get("head_bytes", 8192)
        if policy not in ("auto", "full", "none") or not 0 <= head_bytes <= 1024 * 1024:
            raise _Fail("bad_request", "bad hash or head_bytes")
        path = self.real(req)
        if not path.is_file():
            raise _Fail("bad_request", "not a regular file")
        with open(path, "rb") as f:
            st = os.fstat(f.fileno())
            size, mtime_ns = st.st_size, floor100(st.st_mtime_ns)
            head = f.read(min(size, head_bytes))
        resp: dict[str, Any] = {"ok": True, "size": size, "mtime_ns": mtime_ns,
                                "head_b64": base64.b64encode(head).decode()}
        resp.update(hash_file(str(path), size, mtime_ns, policy))
        return resp

    def _read_range(self, req: dict[str, Any]) -> dict[str, Any]:
        offset, length = req.get("offset"), req.get("len")
        if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length < 0:
            raise _Fail("bad_request", "bad offset or len")
        if length > MAX_READ:
            raise _Fail("bad_request", f"len {length} is over the maximum {MAX_READ}")
        path = self.real(req)
        if not path.is_file():
            raise _Fail("bad_request", "not a regular file")
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
            eof = offset + len(data) >= os.fstat(f.fileno()).st_size
        return {"ok": True, "data_b64": base64.b64encode(data).decode(), "eof": eof}

    def _sum(self, top: Path, policy: dict[str, Any]) -> dict[str, int]:
        if not top.is_dir():
            raise _Fail("bad_request", "not a directory")
        exclude = set(policy.get("exclude", []))
        out = {"total_files": 0, "total_dirs": 0, "total_size": 0, "total_allocated_size": 0,
               "newest_mtime_ns": 0, "errors": 0}
        seen: set[tuple[int, int]] = set()
        for base, dirs, files in os.walk(top):
            dirs[:] = [d for d in dirs if d not in exclude]
            out["total_dirs"] += len(dirs)
            for name in files:
                if name in exclude:
                    continue
                st = os.lstat(os.path.join(base, name))
                out["total_files"] += 1
                out["newest_mtime_ns"] = max(out["newest_mtime_ns"], floor100(st.st_mtime_ns))
                if st.st_nlink <= 1 or (st.st_dev, st.st_ino) not in seen:
                    seen.add((st.st_dev, st.st_ino))
                    out["total_size"] += st.st_size
                    out["total_allocated_size"] += self._numbers(st)["allocated_size"]
        return out
