"""Files whose content is a secret: recorded from the directory entry, never read.

A scan reads a file's head (magic, probes, text sample) and hashes it. For a
private key that is the one thing a catalog must not do: the head would sit in
the record and the sample could reach an LLM. So a file is checked first and,
when it is a secret, recorded with name, size, times and the type its name
suggests, and nothing else: no sha256 or sha256_partial, no head, no sample,
no archive or other probe. The record says why with probe.secret:

    "private_key"  the head is a private key (below)
    "keystore"     the name is a binary, encrypted key container (below)
    "denied"       the filecat-agent refused to read it (its deny list: .env,
                   shadow, Windows hives; docs/agent-protocol.md)

Private key signatures, matched at the start of the file after an optional
UTF-8 byte order mark and leading ASCII whitespace, within the first
SIGNATURE_WINDOW bytes (the agent applies the same rule to its own reads):

    -----BEGIN <anything>PRIVATE KEY-----   PKCS#8, RSA, EC, DSA, ENCRYPTED, OPENSSH
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
    PuTTY-User-Key-File-                    PuTTY .ppk

A public key, a certificate or a CSR is not one and is hashed as usual. A
key that follows something else in the file (a certificate first, then the
key, as in a combined PEM) is not found: only the start is looked at.

Names: .pfx, .p12 (PKCS#12) and .kdbx (KeePass) have no text header. They are
encrypted, but filecat does not know with what, and their content says nothing
a catalog uses, so they are recorded as "keystore" without being opened. That
check is by name and made by the scan, before any read; the agent's own
read commands do not know it.
"""
from __future__ import annotations

from typing import Any

from . import record

SIGNATURE_WINDOW = 256
_BOM = b"\xef\xbb\xbf"
_LEADING = b" \t\r\n"
KEYSTORE_SUFFIXES = (".pfx", ".p12", ".kdbx")
_PGP = b"-----BEGIN PGP PRIVATE KEY BLOCK-----"
_SSH2 = b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
_PUTTY = b"PuTTY-User-Key-File-"
# What the agent's deny_sha256 covers besides its path rules, one per line.
SIGNATURES = ("-----BEGIN *PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
              "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "PuTTY-User-Key-File-")


def private_key_in(head: bytes) -> bool:
    """Whether the first bytes of a file are a private key's header."""
    h = head[:SIGNATURE_WINDOW]
    if h.startswith(_BOM):
        h = h[len(_BOM):]
    h = h.lstrip(_LEADING)
    if h.startswith((_PUTTY, _PGP, _SSH2)):
        return True
    if not h.startswith(b"-----BEGIN "):
        return False
    first = h.split(b"\n", 1)[0].rstrip(b"\r \t")
    return first.endswith(b"PRIVATE KEY-----")


def keystore_name(name: str) -> bool:
    return name.lower().endswith(KEYSTORE_SUFFIXES)


def listed(root: str, rel_path: str, name: str, size: int, mtime_ns: int, ctime_ns: int,
           probe: dict[str, Any], identifier: Any) -> dict[str, Any]:
    """The record of a file that is not opened: its directory entry and the type its
    name suggests (the name layer of the identifier only), `probe` saying why."""
    doc = record.new_document(root, rel_path, kind="unknown", size=size,
                              mtime_ns=mtime_ns, ctime_ns=ctime_ns, name=name)
    doc["probe"] = dict(probe)
    by_name = getattr(identifier, "by_name", None)
    if by_name is not None:
        try:
            result = by_name(name, size, None)
        except Exception as e:  # a broken glob table must not stop the scan
            record.add_error(doc, "identify", e)
        else:
            if result:
                doc["probe"].update(result)
                if result.get("mime_glob"):
                    doc["mime"] = result["mime_glob"]
                doc["probe"].setdefault("identify_basis", "name")
    return doc
