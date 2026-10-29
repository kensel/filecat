# 02 - Rust Scanning Agent Plan & Architecture

This document details the architecture, cross-compilation workflow, security model, and Python integration for filecat-agent—a static, zero-dependency Rust daemon designed to run as root on both modern x86_64 NAS systems (NAS-MAIN) and legacy 32-bit armv7l systems (NAS-OLD Synology DS2015xs running Annapurna Labs Alpine AL514 with 4 GB RAM).

## 1. Source Code Reference (rust-agent/ Subfolder)

All Rust source files are stored in the rust-agent subfolder inside this research directory:

- **rust-agent/Cargo.toml**: Crate manifest and static musl cross-compilation targets.
- **rust-agent/main.rs**: NDJSON-over-TLS RPC server, lstat directory walker, rollup group aggregator, byte-exact sha256 / sha256_partial hashing engine, and random-access read_range handler.
- **rust-agent/tls.rs**: Pure-Rust TLS certificate generator (rcgen + rustls) and SHA-256 fingerprint calculator.
- ~~rust-agent/synology_storage.rs~~ (deleted): the Synology topology parser moved to Python (`filecat.topology_collect`); the agent reads raw files and runs allowlisted commands only, see [agent-protocol.md](../agent-protocol.md) and [agent-allowlist.md](../agent-allowlist.md).

## 2. Why a Static Rust Agent Beats SMB Scanning

| Operation | Current SMB Scan from Windows | With filecat-agent (Local Rust Daemon) |
|---|---|---|
| **Full Hash (≤ 64 MiB)** | Transfers up to 64 MiB over LAN per file. | Hashed locally off SATA/NVMe backplane; only 32-byte digest crosses LAN. |
| **Partial Hash (> 64 MiB)** | Opens SMB handle, reads 1 MiB head + 1 MiB tail over network. | Reads head/tail locally and feeds 8-byte BE size + 8-byte BE signed mtime_ns into SHA-256 (matching hashing.py byte-for-byte). |
| **Sparse Files & Hardlinks** | Windows SMB hides Linux inode numbers and reports 512 GiB fake size on ROD files. | lstat captures st_ino, st_dev, st_nlink, and true physical disk usage via st_blocks * 512. |
| **Disk Image & Archive Probing** | Random SMB seeks across multi-terabyte files. | Python RemoteFileProxy issues bounded read_range RPC calls for MFT sectors and ZIP central directories. |

## 3. Security Model: Self-Generated TLS + TOFU Fingerprint Pinning

Instead of managing a full PKI CA hierarchy initially, filecat-agent uses pure-Rust rcgen and rustls (zero OpenSSL C dependencies):

- On first launch, tls.rs generates an Ed25519 certificate/key pair (agent.crt / agent.key) and prints the cert_sha256 fingerprint to stdout.
- You paste cert_sha256 and token into filecat.toml under [[agents]].
- Python connects over TLS, verifies hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest() == cert_sha256 (making IP vs. hostname connections work seamlessly without DNS SAN mismatches), and sends the bearer token.
- Future Consul / mDNS group discovery can swap the self-signed cert for a shared group CA without changing the wire protocol.

## 4. Cross-Compiling for NAS-MAIN (x86_64) and NAS-OLD (ARMv7)

```sh
# Install zig and cargo-zigbuild once on your workstation/WSL:
rustup target add x86_64-unknown-linux-musl armv7-unknown-linux-musleabihf
cargo install cargo-zigbuild

# Build static binary for NAS-MAIN (x86_64):
cargo zigbuild --release --target x86_64-unknown-linux-musl

# Build static binary for NAS-OLD (DS2015xs Annapurna Labs Alpine AL514 ARMv7):
cargo zigbuild --release --target armv7-unknown-linux-musleabihf
```

## 5. Python Client & RemoteFileProxy (src/filecat/agent_client.py)

The Python coordinator maps POSIX paths (/volume1/Backup/...) back to canonical UNC roots (\\nas-main\Backup\...) so existing MongoDB records and treemap pins line up seamlessly:

```python
import base64
import hashlib
import json
import socket
import ssl
import threading
from typing import Any

class AgentClient:
    def __init__(self, host: str, port: int, cert_sha256: str, token: str, alias: str, share_map: dict[str, str] | None = None):
        self.host = host
        self.port = port
        self.expected_fp = cert_sha256.lower().replace(":", "")
        self.token = token
        self.alias = alias.rstrip("\\")
        self.share_map = share_map or {}
        self._lock = threading.Lock()
        self._sock: ssl.SSLSocket | None = None
        self._rfile = None

    def connect(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw = socket.create_connection((self.host, self.port), timeout=30)
        self._sock = ctx.wrap_socket(raw, server_hostname=self.host)

        der_cert = self._sock.getpeercert(binary_form=True)
        actual_fp = hashlib.sha256(der_cert).hexdigest()
        if actual_fp != self.expected_fp:
            self._sock.close()
            raise PermissionError(f"Agent TLS fingerprint mismatch: expected {self.expected_fp}, got {actual_fp}")

        self._rfile = self._sock.makefile("rb")
        resp = self.rpc({"cmd": "auth", "token": self.token})
        if not resp.get("ok"):
            raise PermissionError(f"Agent auth failed: {resp}")

    def rpc(self, payload: dict[str, Any]) -> dict[str, Any]:
        line = (json.dumps(payload) + "\n").encode("utf-8")
        with self._lock:
            self._sock.sendall(line)
            raw_reply = self._rfile.readline()
        if not raw_reply:
            raise ConnectionError("Agent closed connection")
        return json.loads(raw_reply)

    def to_catalog_path(self, posix_path: str) -> str:
        for prefix, unc_root in self.share_map.items():
            if posix_path == prefix or posix_path.startswith(prefix + "/"):
                rel = posix_path[len(prefix):].lstrip("/").replace("/", "\\")
                return f"{unc_root}\\{rel}" if rel else unc_root

        parts = posix_path.strip("/").split("/", 2)
        if len(parts) >= 2 and parts[0].startswith("volume"):
            share = parts[1]
            rest = parts[2].replace("/", "\\") if len(parts) == 3 else ""
            return f"{self.alias}\\{share}\\{rest}" if rest else f"{self.alias}\\{share}"
        return f"{self.alias}\\$root\\" + posix_path.lstrip("/").replace("/", "\\")

    def open_remote(self, posix_path: str, size: int) -> "RemoteFileProxy":
        return RemoteFileProxy(self, posix_path, size)

class RemoteFileProxy:
    """Drop-in file-like object for disk_inspector, zipfile, and pefile over the agent RPC."""
    def __init__(self, client: AgentClient, path: str, size: int):
        self.client = client
        self.path = path
        self.size = size
        self.pos = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = self.size + offset
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def tell(self) -> int:
        return self.pos

    def read(self, n: int = -1) -> bytes:
        if self.pos >= self.size:
            return b""
        if n < 0 or self.pos + n > self.size:
            n = self.size - self.pos
        resp = self.client.rpc({
            "cmd": "read_range",
            "path": self.path,
            "offset": self.pos,
            "len": n,
        })
        if not resp.get("ok"):
            raise OSError(resp.get("error", "Remote read_range failed"))
        data = base64.b64decode(resp["data_b64"])
        self.pos += len(data)
        return data
```
