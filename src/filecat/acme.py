"""A small ACME v2 client (RFC 8555) that proves control of a name with DNS-01 only.

Nothing is exposed: no HTTP-01 listener, no TLS-ALPN. The CA looks up a TXT record that a DNS
provider hook publishes, so a LAN-only viewer can hold a publicly trusted certificate for a name
that resolves to a private address. Pieces:

    AcmeClient      account key (ES256, 0600), new-account, new-order, dns-01, finalize, chain
    CloudflareProvider  zone lookup by name, TXT create/delete through the v4 API (a scoped token)
    ExecProvider    `script add|remove <fqdn> <value>` for any other provider (lego/acme.sh hooks)
    dns_txt         one UDP TXT query, to wait until public resolvers see the record

Needs `cryptography` (the `tls` extra) for keys, the JWS and the CSR; HTTP is urllib. Tokens, the
account key and certificate keys are never logged or put in an error message.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

LETS_ENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"   # a module global so tests can point it elsewhere
DNS_PROVIDERS = ("cloudflare", "exec")


class AcmeError(Exception):
    """The CA, the DNS provider or the network refused; the message is safe to log."""


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _crypto() -> Any:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise AcmeError("ACME needs the 'cryptography' package (pip install 'filecat[tls]')") from None


@dataclass(frozen=True)
class AcmeConfig:
    """`[server.tls.acme]`, resolved (${VAR} expanded)."""
    dns: str                                    # "cloudflare" | "exec"
    email: str | None = None
    agree_tos: bool = False
    staging: bool = False
    directory: str | None = None                # overrides Let's Encrypt (other CAs, step-ca)
    ca_bundle: str | None = None                # PEM roots to trust for the CA's own HTTPS (a private step-ca)
    api_token: str = field(default="", repr=False)   # cloudflare
    zone: str | None = None                     # cloudflare: zone name or id; default: found from the name
    command: tuple[str, ...] = ()               # exec: argv of the hook
    propagation_delay: float = 30.0             # seconds to wait after publishing, unless resolvers are set
    propagation_timeout: float = 300.0          # with resolvers: how long to wait for them to see the record
    resolvers: tuple[str, ...] = ()             # public resolvers (IP or IP:PORT) polled for the TXT record

    @property
    def directory_url(self) -> str:
        return self.directory or (LETS_ENCRYPT_STAGING if self.staging else LETS_ENCRYPT)


class Http:
    """urllib with every HTTP status returned, not raised: (status, headers, body)."""

    def __init__(self, ca_bundle: str | None = None, timeout: float = 30.0) -> None:
        self.timeout = timeout
        handlers: list[Any] = []
        if ca_bundle:
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_bundle)))
        self._opener = urllib.request.build_opener(*handlers)

    def request(self, url: str, data: bytes | None = None, headers: dict[str, str] | None = None,
                method: str | None = None) -> tuple[int, Any, bytes]:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.headers, exc.read()
        except (urllib.error.URLError, OSError) as exc:
            raise AcmeError(f"{urllib.parse.urlsplit(url).netloc}: {getattr(exc, 'reason', exc)}") from None


# --- DNS providers ------------------------------------------------------------------------------
class DnsProvider(Protocol):
    def add(self, fqdn: str, value: str) -> None: ...
    def remove(self, fqdn: str, value: str) -> None: ...


class ExecProvider:
    """`command add|remove <fqdn> <value>`: exit 0 once the record is published (or gone)."""

    def __init__(self, command: tuple[str, ...], runner: Callable[..., Any] = subprocess.run,
                 timeout: float = 120.0) -> None:
        self.command, self._run, self.timeout = command, runner, timeout

    def _call(self, action: str, fqdn: str, value: str) -> None:
        argv = [*self.command, action, fqdn, value]
        try:
            done = self._run(argv, capture_output=True, text=True, timeout=self.timeout,
                             stdin=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise AcmeError(f"dns hook {self.command[0]} {action}: {type(exc).__name__}: {exc}") from None
        if done.returncode != 0:
            tail = (done.stderr or "").strip()[-200:]
            raise AcmeError(f"dns hook {self.command[0]} {action} {fqdn} exited {done.returncode}"
                            + (f": {tail}" if tail else ""))

    def add(self, fqdn: str, value: str) -> None:
        self._call("add", fqdn, value)

    def remove(self, fqdn: str, value: str) -> None:
        self._call("remove", fqdn, value)


class CloudflareProvider:
    """TXT records through the Cloudflare v4 API. The token needs Zone:Read and DNS:Edit on the zone."""

    def __init__(self, token: str, zone: str | None = None, http: Http | None = None) -> None:
        self._token, self._zone, self._http = token, zone, http or Http()
        self._zone_ids: dict[str, str] = {}

    def _call(self, method: str, path: str, body: Any = None, query: dict[str, str] | None = None) -> Any:
        url = CLOUDFLARE_API + path + ("?" + urllib.parse.urlencode(query) if query else "")
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        status, _, raw = self._http.request(url, json.dumps(body).encode() if body is not None else None,
                                            headers, method)
        try:
            doc = json.loads(raw)
        except ValueError:
            raise AcmeError(f"cloudflare {method} {path}: HTTP {status}, not JSON") from None
        if not isinstance(doc, dict) or not doc.get("success"):
            errors = "; ".join(str(e.get("message")) for e in (doc.get("errors") or []) if isinstance(e, dict)) \
                if isinstance(doc, dict) else ""
            raise AcmeError(f"cloudflare {method} {path}: HTTP {status}: {errors or 'request failed'}")
        return doc.get("result")

    def _zone_id(self, fqdn: str) -> str:
        if self._zone and re.fullmatch(r"[0-9a-fA-F]{32}", self._zone):
            return self._zone
        labels = fqdn.rstrip(".").split(".")
        candidates = [self._zone] if self._zone else [".".join(labels[i:]) for i in range(len(labels) - 1)]
        for name in candidates:
            if name in self._zone_ids:
                return self._zone_ids[name]
            found = self._call("GET", "/zones", query={"name": name})
            if found:
                self._zone_ids[name] = found[0]["id"]
                return found[0]["id"]
        raise AcmeError(f"cloudflare: no zone found for {fqdn} (tried {', '.join(candidates)}); "
                        "check the token's Zone:Read permission or set zone")

    def add(self, fqdn: str, value: str) -> None:
        self._call("POST", f"/zones/{self._zone_id(fqdn)}/dns_records",
                   {"type": "TXT", "name": fqdn, "content": value, "ttl": 60})

    def remove(self, fqdn: str, value: str) -> None:
        zone = self._zone_id(fqdn)
        for rec in self._call("GET", f"/zones/{zone}/dns_records", query={"type": "TXT", "name": fqdn}) or []:
            if str(rec.get("content", "")).strip('"') == value:
                self._call("DELETE", f"/zones/{zone}/dns_records/{rec['id']}")


def make_provider(cfg: AcmeConfig, http: Http | None = None) -> DnsProvider:
    if cfg.dns == "cloudflare":
        return CloudflareProvider(cfg.api_token, cfg.zone, http)
    if cfg.dns == "exec":
        return ExecProvider(cfg.command)
    raise AcmeError(f"dns = {cfg.dns!r}; choose from {', '.join(DNS_PROVIDERS)}")


def split_command(text: str) -> tuple[str, ...]:
    return tuple(shlex.split(text, posix=os.name != "nt"))


# --- waiting for DNS ----------------------------------------------------------------------------
def dns_txt(name: str, resolver: str, timeout: float = 5.0) -> list[str]:
    """The TXT strings of `name` according to `resolver` (IP or IP:PORT), by one UDP query."""
    host, port_n = (resolver.rpartition(":")[0], int(resolver.rpartition(":")[2])) if resolver.count(":") == 1 \
        else (resolver, 53)
    qid = os.urandom(2)
    question = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split(".")) + b"\0\0\x10\0\x01"
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(qid + b"\x01\0\0\x01\0\0\0\0\0\0" + question, (host, port_n))
        data, _ = sock.recvfrom(4096)
    if data[:2] != qid or len(data) < 12 or data[3] & 0x0F:
        return []

    def skip_name(pos: int) -> int:
        while data[pos]:
            if data[pos] & 0xC0 == 0xC0:
                return pos + 2
            pos += 1 + data[pos]
        return pos + 1

    pos = skip_name(12) + 4
    out: list[str] = []
    for _ in range(int.from_bytes(data[6:8], "big")):
        pos = skip_name(pos)
        rtype, rdlen = int.from_bytes(data[pos:pos + 2], "big"), int.from_bytes(data[pos + 8:pos + 10], "big")
        pos += 10
        if rtype == 16:
            end, chunks = pos + rdlen, []
            while pos < end:
                chunks.append(data[pos + 1:pos + 1 + data[pos]])
                pos += 1 + data[pos]
            out.append(b"".join(chunks).decode("utf-8", "replace"))
        pos += rdlen if rtype != 16 else 0
    return out


# --- the client ---------------------------------------------------------------------------------
def load_or_create_key(path: Path) -> Any:
    """The ECDSA P-256 key in `path` (PEM), made (0600) when it does not exist."""
    _crypto()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        return serialization.load_pem_private_key(path.read_bytes(), None)
    except FileNotFoundError:
        pass
    key = ec.generate_private_key(ec.SECP256R1())
    write_private(path, key_pem(key))
    return key


def key_pem(key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write `data` atomically with `mode` from the first byte (no window where it is world-readable)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


class AcmeClient:
    """One account at one CA. `sleep` and `txt_lookup` are injectable so tests need no waiting."""

    def __init__(self, cfg: AcmeConfig, account_key_path: Path, *, http: Http | None = None,
                 sleep: Callable[[float], None] = time.sleep, txt_lookup: Callable[..., list[str]] = dns_txt,
                 log: Callable[[str], None] = lambda m: None, polls: int = 150, poll_interval: float = 2.0) -> None:
        _crypto()
        self.cfg, self.http, self.sleep, self.txt_lookup, self.log = cfg, http or Http(cfg.ca_bundle), sleep, txt_lookup, log
        self.polls, self.poll_interval = polls, poll_interval
        self._key = load_or_create_key(account_key_path)
        self._dir: dict[str, Any] | None = None
        self._nonce_pool: list[str] = []
        self._kid: str | None = None
        nums = self._key.public_key().public_numbers()
        self.jwk = {"crv": "P-256", "kty": "EC", "x": b64u(nums.x.to_bytes(32, "big")),
                    "y": b64u(nums.y.to_bytes(32, "big"))}
        self.thumbprint = b64u(hashlib.sha256(json.dumps(self.jwk, sort_keys=True, separators=(",", ":")).encode()).digest())

    # -- protocol plumbing
    def directory(self) -> dict[str, Any]:
        if self._dir is None:
            status, _, body = self.http.request(self.cfg.directory_url)
            if status != 200:
                raise AcmeError(f"ACME directory {self.cfg.directory_url}: HTTP {status}")
            self._dir = json.loads(body)
        return self._dir

    def _fresh_nonce(self) -> str:
        if self._nonce_pool:
            return self._nonce_pool.pop()
        _, headers, _ = self.http.request(self.directory()["newNonce"], method="HEAD")
        nonce = headers.get("Replay-Nonce")
        if not nonce:
            raise AcmeError("ACME server sent no Replay-Nonce")
        return nonce

    def _sign(self, url: str, payload: Any, nonce: str) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        protected: dict[str, Any] = {"alg": "ES256", "nonce": nonce, "url": url}
        protected.update({"kid": self._kid} if self._kid else {"jwk": self.jwk})
        head = b64u(json.dumps(protected, separators=(",", ":")).encode())
        body = "" if payload is None else b64u(json.dumps(payload, separators=(",", ":")).encode())
        r, s = decode_dss_signature(self._key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        return json.dumps({"protected": head, "payload": body,
                           "signature": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}).encode()

    def post(self, url: str, payload: Any = None, accept: str | None = None) -> tuple[Any, bytes]:
        """A signed POST (payload None: POST-as-GET); (headers, body). badNonce is retried."""
        for attempt in range(3):
            headers = {"Content-Type": "application/jose+json"}
            if accept:
                headers["Accept"] = accept
            status, resp, body = self.http.request(url, self._sign(url, payload, self._fresh_nonce()), headers, "POST")
            nonce = resp.get("Replay-Nonce")
            if nonce:
                self._nonce_pool.append(nonce)
            if status < 400:
                return resp, body
            try:
                problem = json.loads(body)
            except ValueError:
                problem = {}
            kind = str(problem.get("type", "")).rpartition(":")[2]
            if kind == "badNonce" and attempt < 2:
                continue
            raise AcmeError(f"ACME {urllib.parse.urlsplit(url).path}: HTTP {status} {kind or 'error'}: "
                            f"{problem.get('detail', '')}".rstrip(": "))
        raise AcmeError("ACME: badNonce three times")           # pragma: no cover

    def account(self) -> str:
        if self._kid is None:
            if not self.cfg.agree_tos:
                raise AcmeError("agree_tos = true is required in [server.tls.acme] (the CA's terms of service)")
            payload: dict[str, Any] = {"termsOfServiceAgreed": True}
            if self.cfg.email:
                payload["contact"] = [f"mailto:{self.cfg.email}"]
            resp, _ = self.post(self.directory()["newAccount"], payload)
            self._kid = resp.get("Location")
            if not self._kid:
                raise AcmeError("ACME server sent no account Location")
        return self._kid

    # -- the order
    def _poll(self, url: str, done: tuple[str, ...], what: str) -> dict[str, Any]:
        doc: dict[str, Any] = {}
        for _ in range(self.polls):
            _, body = self.post(url)
            doc = json.loads(body)
            if doc.get("status") in done:
                return doc
            if doc.get("status") == "invalid":
                break
            self.sleep(self.poll_interval)
        if doc.get("status") == "invalid":
            err = doc.get("error") or next((c.get("error") for c in doc.get("challenges", []) if c.get("error")), {})
            raise AcmeError(f"ACME {what} invalid: {(err or {}).get('detail') or 'no detail'}")
        raise AcmeError(f"ACME {what} still {doc.get('status')!r} after waiting")

    def _wait_dns(self, records: list[tuple[str, str]]) -> None:
        if not self.cfg.resolvers:
            self.sleep(self.cfg.propagation_delay)
            return
        waited = 0.0
        while True:
            missing = [(r, f) for f, v in records for r in self.cfg.resolvers if not self._sees(r, f, v)]
            if not missing:
                return
            if waited >= self.cfg.propagation_timeout:
                self.log(f"acme: {missing[0][1]} not visible at {missing[0][0]} after {waited:.0f}s; asking the CA anyway")
                return
            self.sleep(10.0)
            waited += 10.0

    def _sees(self, resolver: str, fqdn: str, value: str) -> bool:
        try:
            return value in self.txt_lookup(fqdn, resolver)
        except (OSError, ValueError, IndexError):
            return False

    def obtain(self, names: list[str], provider: DnsProvider) -> tuple[str, bytes]:
        """Order a certificate for `names`; (chain PEM, new private key PEM). Wildcards (*.x) work.
        The TXT records are removed again whatever happens."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self.account()
        resp, body = self.post(self.directory()["newOrder"],
                               {"identifiers": [{"type": "dns", "value": n} for n in names]})
        order, order_url = json.loads(body), resp.get("Location")
        pending: list[tuple[str, str, str, str]] = []           # fqdn, value, challenge url, authz url
        for authz_url in order["authorizations"]:
            _, raw = self.post(authz_url)
            authz = json.loads(raw)
            if authz.get("status") == "valid":
                continue
            chal = next((c for c in authz.get("challenges", []) if c.get("type") == "dns-01"), None)
            if chal is None:
                raise AcmeError(f"the CA offers no dns-01 challenge for {authz['identifier']['value']}")
            key_auth = f"{chal['token']}.{self.thumbprint}"
            pending.append((f"_acme-challenge.{authz['identifier']['value']}",
                            b64u(hashlib.sha256(key_auth.encode()).digest()), chal["url"], authz_url))
        published: list[tuple[str, str]] = []
        try:
            for fqdn, value, _, _ in pending:
                provider.add(fqdn, value)
                published.append((fqdn, value))
            if pending:
                self._wait_dns(published)
            for _, _, chal_url, _ in pending:
                self.post(chal_url, {})
            for _, _, _, authz_url in pending:
                self._poll(authz_url, ("valid",), "authorization")
        finally:
            for fqdn, value in published:
                try:
                    provider.remove(fqdn, value)
                except AcmeError as exc:
                    self.log(f"acme: could not remove {fqdn}: {exc}")
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])]) if len(names[0]) <= 64 \
            else x509.Name([])
        csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
               .sign(key, hashes.SHA256()))
        self.post(order["finalize"], {"csr": b64u(csr.public_bytes(serialization.Encoding.DER))})
        done = self._poll(order_url, ("valid",), "order")
        _, chain = self.post(done["certificate"], accept="application/pem-certificate-chain")
        return chain.decode("ascii"), key_pem(key)
