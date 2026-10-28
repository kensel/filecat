"""Password, login throttling and sessions for the viewer's "run now" (docs/agent-server.md "Run now").

Nothing here touches the network: `serve.py` calls it. All clocks are injected (a callable giving
seconds), so the windows and blocks are tested with a fake clock.

    scrypt$n$r$p$salt_b64$hash_b64     the stored hash (hashlib.scrypt, 16-byte salt, 32-byte key)
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import math
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

MIN_PASSWORD = 12
SCRYPT_N, SCRYPT_R, SCRYPT_P, SALT_BYTES, KEY_BYTES = 2 ** 14, 8, 1, 16, 32
COOKIE = "filecat_session"
DAY = 86400.0


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt if salt is not None else os.urandom(SALT_BYTES)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                         dklen=KEY_BYTES, maxmem=64 * 1024 * 1024)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(key)}"


def parse_hash(encoded: str | None) -> tuple[int, int, int, bytes, bytes] | None:
    try:
        scheme, n, r, p, salt, key = (encoded or "").strip().split("$")
        if scheme != "scrypt":
            return None
        n, r, p = int(n), int(r), int(p)
        if not (2 ** 10 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16):
            return None
        return n, r, p, base64.b64decode(salt, validate=True), base64.b64decode(key, validate=True)
    except (ValueError, TypeError):
        return None


def valid_hash(encoded: str | None) -> bool:
    return parse_hash(encoded) is not None


# a throw-away hash, so a malformed stored hash or request costs the same scrypt run
_DUMMY = (SCRYPT_N, SCRYPT_R, SCRYPT_P, b"\0" * SALT_BYTES, b"\0" * KEY_BYTES)


def verify_password(password: Any, encoded: str | None) -> bool:
    """Constant-time check. Always runs one scrypt, whatever `password` and `encoded` look like."""
    parsed = parse_hash(encoded)
    n, r, p, salt, want = parsed or _DUMMY
    text = password if isinstance(password, str) else ""
    key = hashlib.scrypt(text.encode("utf-8", "surrogatepass"), salt=salt, n=n, r=r, p=p, dklen=len(want) or KEY_BYTES,
                         maxmem=128 * 1024 * 1024)
    return hmac.compare_digest(key, want) and parsed is not None and isinstance(password, str)


# --- throttling --------------------------------------------------------------------------------
@dataclass
class _Ip:
    failures: list[float] = field(default_factory=list)
    blocked_until: float = 0.0
    block_len: float = 0.0
    touched: float = 0.0


class LoginGuard:
    """Per-IP and global failure blocking. In memory: a restart resets it."""

    def __init__(self, clock: Callable[[], float] = time.time, *, max_failures: int = 5, window: float = 900.0,
                 block: float = 900.0, global_max_failures: int = 20, max_block: float = DAY,
                 log: Callable[[str], None] = lambda m: None) -> None:
        self.clock, self.max_failures, self.window, self.block = clock, max_failures, window, block
        self.global_max, self.max_block, self.log = global_max_failures, max_block, log
        self._ips: dict[str, _Ip] = {}
        self._global: list[float] = []
        self._global_until = 0.0
        self._lock = threading.Lock()

    def retry_after(self, ip: str) -> int:
        """Seconds until `ip` may try again (0: it may now): its own block, or the global one."""
        with self._lock:
            now = self.clock()
            wait = max(self._ips.get(ip, _Ip()).blocked_until, self._global_until) - now
            return max(0, math.ceil(wait))

    def fail(self, ip: str) -> None:
        """Record one failed login (or an attempt made while blocked: that doubles the block)."""
        with self._lock:
            now = self.clock()
            self._forget(now)
            st = self._ips.setdefault(ip, _Ip())
            st.touched = now
            if st.blocked_until > now:
                st.block_len = min(max(st.block_len, self.block) * 2, self.max_block)
                st.blocked_until = now + st.block_len
                self.log(f"login from {ip} while blocked: blocked for {int(st.block_len)}s")
                return
            st.failures = [t for t in st.failures if now - t < self.window] + [now]
            self.log(f"failed login from {ip} ({len(st.failures)} of {self.max_failures})")
            if len(st.failures) >= self.max_failures:
                st.failures.clear()
                st.block_len = self.block
                st.blocked_until = now + self.block
                self.log(f"{ip} blocked for {int(self.block)}s after {self.max_failures} failed logins")
            self._global = [t for t in self._global if now - t < self.window] + [now]
            if len(self._global) >= self.global_max and self._global_until <= now:
                self._global.clear()
                self._global_until = now + self.block
                self.log(f"warning: {self.global_max} failed logins from all addresses within "
                         f"{int(self.window)}s: every login refused for {int(self.block)}s")

    def success(self, ip: str) -> None:
        """Clears this address's counter (not the global one)."""
        with self._lock:
            st = self._ips.get(ip)
            if st is not None:
                st.failures.clear()
                if st.blocked_until <= self.clock():
                    self._ips.pop(ip, None)

    def _forget(self, now: float) -> None:
        for key in [k for k, v in self._ips.items() if now - v.touched > self.max_block and v.blocked_until < now]:
            del self._ips[key]


# --- sessions ----------------------------------------------------------------------------------
class Sessions:
    """Server-side sessions: an idle timeout and an absolute one. In memory."""

    def __init__(self, clock: Callable[[], float] = time.time, idle: float = 1800.0, absolute: float = 43200.0) -> None:
        self.clock, self.idle, self.absolute = clock, idle, absolute
        self._s: dict[str, tuple[float, float]] = {}        # id -> (created, last seen)
        self._lock = threading.Lock()

    def create(self) -> str:
        sid = secrets.token_urlsafe(32)
        now = self.clock()
        with self._lock:
            self._s = {k: v for k, v in self._s.items() if self._alive(v, now)}
            self._s[sid] = (now, now)
        return sid

    def _alive(self, entry: tuple[float, float], now: float) -> bool:
        return now - entry[1] < self.idle and now - entry[0] < self.absolute

    def valid(self, sid: str | None) -> bool:
        if not sid:
            return False
        with self._lock:
            entry = self._s.get(sid)
            now = self.clock()
            if entry is None or not self._alive(entry, now):
                self._s.pop(sid, None)
                return False
            self._s[sid] = (entry[0], now)
            return True

    def drop(self, sid: str | None) -> None:
        with self._lock:
            self._s.pop(sid or "", None)


@dataclass
class ControlAuth:
    """What the viewer needs: the stored hash, the throttle, the sessions, the settings."""
    password_hash: str | None
    guard: LoginGuard
    sessions: Sessions
    login_required_for_view: bool = False
    fail_delay: float = 0.5

    @property
    def enabled(self) -> bool:
        return valid_hash(self.password_hash)


# --- `filecat server set-password` -------------------------------------------------------------
_HASH_LINE = re.compile(r"^\s*control_password_hash\s*=.*$", re.M)


def write_hash(path: Path, encoded: str) -> None:
    """Put `control_password_hash = "..."` in the [server] table of filecat.toml (replacing one)."""
    text = path.read_text(encoding="utf-8")
    line = f'control_password_hash = "{encoded}"'
    if _HASH_LINE.search(text):
        text = _HASH_LINE.sub(lambda m: line, text, count=1)
    elif re.search(r"^\[server\]\s*$", text, re.M):
        text = re.sub(r"^(\[server\][ \t]*\r?\n)", lambda m: m.group(1) + line + "\n", text, count=1, flags=re.M)
    else:
        text = text.rstrip("\n") + f"\n\n[server]\n{line}\n"
    path.write_text(text, encoding="utf-8")


def set_password(args: Any, ask: Callable[[str], str] = getpass.getpass) -> int:
    from . import config
    first = ask("New password for the viewer's \"run now\" (not echoed): ")
    if len(first) < MIN_PASSWORD:
        print(f"filecat server set-password: at least {MIN_PASSWORD} characters", file=sys.stderr)
        return 2
    if ask("Again: ") != first:
        print("filecat server set-password: the two entries differ", file=sys.stderr)
        return 2
    encoded = hash_password(first)
    if getattr(args, "write", False):
        path = config.find(getattr(args, "config", None))
        if path is None:
            print("filecat server set-password: no filecat.toml to write into (use --config)", file=sys.stderr)
            return 2
        write_hash(Path(path), encoded)
        print(f"written to {path}: [server] control_password_hash")
    else:
        print("Put this in the [server] table of filecat.toml:\n")
        print(f'control_password_hash = "{encoded}"\n')
        print("or keep it out of the file: set the environment variable and reference it:\n")
        print('control_password_hash = "${FILECAT_SERVER_PASSWORD_HASH}"')
        print(f"FILECAT_SERVER_PASSWORD_HASH={encoded}")
    return 0
