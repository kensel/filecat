"""What a filecat-agent built from this filecat version reports about its own rules.

`capabilities` carries `allowlist_sha256` (the compiled command table) and `deny_sha256` (the
compiled deny list). An agent built from other sources, older or modified, reports other values.
`data/agent_expected.json` holds the values this filecat expects, per protocol version:

    {"1": {"deny_sha256": "...", "allowlist_sha256": {"linux": "...", "windows": null}}}

The deny list is spelled out here (the executable specification the fake agent in the tests also
uses) and its hash computed, so a test can check the file; the allowlist hash comes from the Rust
build (`agent/build.sh hashes`; a cargo test fails when the Rust values and the file differ).
docs/agent-server.md says how to update it. A null (or missing) value means "not known": no
warning is given for it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

# Deny list compiled into the agent (docs/agent-protocol.md, "Allowed roots and the deny list").
DENY_POSIX = ("/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/sudoers",
              "/etc/sudoers.d", "/etc/ssh/ssh_host_*_key", "/etc/ssl/private", "/var/log", "/var/logs")
ENV_ALLOWED = (".env.example", ".env.sample", ".env.template")
DENY_WINDOWS = (r"%SystemRoot%\system32\config", r"%SystemRoot%\ntds")
# The private key signatures, one per line as secretfiles.SIGNATURES spells them (hash input only).
SIGNATURE_LINES = ("-----BEGIN *PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                   "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "PuTTY-User-Key-File-")

MISMATCH_WARNING = "agent built from a different allowlist/deny list (outdated or modified)"


def deny_sha256() -> str:
    """SHA-256 of DENY_POSIX, ENV_ALLOWED, DENY_WINDOWS and SIGNATURE_LINES, in that order,
    joined with newlines (no trailing newline): what the agent reports as `deny_sha256`."""
    text = "\n".join(DENY_POSIX + ENV_ALLOWED + DENY_WINDOWS + SIGNATURE_LINES)
    return hashlib.sha256(text.encode()).hexdigest()


def load() -> dict[str, Any]:
    return json.loads(resources.files("filecat").joinpath("data/agent_expected.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Expected:
    protocol: int
    deny_sha256: str | None
    allowlist_sha256: str | None        # for the platform asked about


def expected(protocol: int, platform: str, table: dict[str, Any] | None = None) -> Expected:
    """The hashes expected of an agent speaking `protocol` on `platform` ("linux", "windows")."""
    entry = (table if table is not None else load()).get(str(protocol)) or {}
    return Expected(protocol, entry.get("deny_sha256"), (entry.get("allowlist_sha256") or {}).get(platform))


def compare(protocol: int, platform: str, allowlist_sha256: str | None, deny: str | None,
            table: dict[str, Any] | None = None) -> tuple[bool | None, bool | None]:
    """(allowlist matches, deny list matches); None for a side that is not known (the agent did
    not report it, or no expected value is recorded)."""
    want = expected(protocol, platform, table)

    def side(have: str | None, wanted: str | None) -> bool | None:
        if not have or not wanted:
            return None
        return have.lower() == wanted.lower()
    return side(allowlist_sha256, want.allowlist_sha256), side(deny, want.deny_sha256)
