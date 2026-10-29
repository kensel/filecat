"""HTTPS for the web viewer, served by filecat itself (docs/agent-server.md "TLS").

    [server.tls]                       # the table turns TLS on; flags: --tls MODE --tls-cert --tls-key
    mode  = "self-signed"              # "self-signed" | "acme" | "cert" | "off" (default: acme when
    cert  = "/etc/filecat/viewer.crt"  #   [server.tls.acme] exists, cert when cert is set, else self-signed)
    key   = "/etc/filecat/viewer.key"
    dir   = "D:/filecat/tls"           # generated certs, ACME account key (default: .filecat-tls next to the catalog)
    names = ["filecat.lan"]            # extra SANs (self-signed) / the certificate's names (acme)

TlsManager owns one live ssl.SSLContext (TLS 1.2 minimum). `cert` mode loads the files you give;
`self-signed` generates an ECDSA P-256 certificate (cryptography, else the openssl command), reuses it
and regenerates it when it is within 30 days of expiry or the SANs change; `acme` obtains one with
DNS-01 (acme.py), renews within 30 days, and keeps serving the previous certificate when the CA or the
DNS provider fails (a self-signed one, loudly, when there is none). check() renews and reloads the
certificate into the live context, so new connections get it without a restart; `filecat server` calls
it once a day, `filecat serve` only at start-up. The listening socket stays plain: each accepted
connection is wrapped and handshakes in its own handler thread, so a stalled client cannot block accept.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from . import acme
from .config import ConfigError, expand

MODES = ("off", "self-signed", "acme", "cert")
TLS_KEYS = ("mode", "cert", "key", "dir", "names", "acme")
ACME_KEYS = ("email", "agree_tos", "staging", "directory", "ca_bundle", "dns", "api_token", "zone", "command",
             "propagation_delay", "propagation_timeout", "resolvers")
RENEW_BEFORE = timedelta(days=30)
SELF_SIGNED_DAYS = 365
CHECK_EVERY = 86400.0           # filecat server: renewal check interval, seconds
HANDSHAKE_TIMEOUT = 60.0
NO_BACKEND = ("TLS needs the 'cryptography' package (pip install 'filecat[tls]') or the openssl command, "
              "and neither is available")


class TlsError(Exception):
    """TLS cannot be started: bad files, no way to make a certificate."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def default_log(message: str) -> None:
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} filecat tls: {message}", file=sys.stderr, flush=True)


# --- configuration ------------------------------------------------------------------------------
@dataclass(frozen=True)
class TlsConfig:
    mode: str = "self-signed"
    cert: str | None = None
    key: str | None = None
    dir: str | None = None
    names: tuple[str, ...] = ()
    acme: acme.AcmeConfig | None = None


def _text(table: dict[str, Any], key: str, label: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} {key} wants a non-empty string")
    return expand(value.strip())


def _seconds(table: dict[str, Any], key: str, default: float, label: str) -> float:
    if key not in table:
        return default
    from .server_cfg import parse_duration
    return parse_duration(table[key], f"{label} {key}").total_seconds()


def _parse_acme(table: Any, names: tuple[str, ...]) -> acme.AcmeConfig:
    label = "[server.tls.acme]"
    if not isinstance(table, dict):
        raise ConfigError(f"{label}: write a table with dns, agree_tos and (for cloudflare) api_token")
    unknown = [k for k in table if k not in ACME_KEYS]
    if unknown:
        raise ConfigError(f"{label}: unknown key {unknown[0]!r}; the keys are {', '.join(ACME_KEYS)}")
    if not names:
        raise ConfigError("[server.tls] mode = \"acme\" needs names = [...], the names the certificate is for")
    dns = table.get("dns")
    if dns not in acme.DNS_PROVIDERS:
        raise ConfigError(f"{label} dns = {dns!r}; choose from {', '.join(acme.DNS_PROVIDERS)} "
                          "(DNS-01 is the only challenge: nothing is exposed)")
    for key in ("agree_tos", "staging"):
        if not isinstance(table.get(key, False), bool):
            raise ConfigError(f"{label} {key} wants true or false")
    if table.get("agree_tos") is not True:
        raise ConfigError(f"{label} agree_tos = true is required: you accept the CA's terms of service")
    token, command = "", ()
    if dns == "cloudflare":
        token = _text(table, "api_token", label) or ""
        if not token:
            raise ConfigError(f'{label} api_token is required for cloudflare, e.g. "${{CLOUDFLARE_API_TOKEN}}"')
    else:
        raw = table.get("command")
        if isinstance(raw, list) and raw and all(isinstance(w, str) and w for w in raw):
            command = tuple(expand(w) for w in raw)             # type: ignore[misc]
        elif isinstance(raw, str) and raw.strip():
            command = acme.split_command(expand(raw))           # type: ignore[arg-type]
        else:
            raise ConfigError(f'{label} command is required for exec: a script (or ["script", "arg"]) called as '
                              "`script add|remove <fqdn> <value>`")
    resolvers = table.get("resolvers", [])
    if not isinstance(resolvers, list) or not all(isinstance(r, str) and r for r in resolvers):
        raise ConfigError(f'{label} resolvers wants a list of resolver addresses, e.g. ["1.1.1.1", "8.8.8.8"]')
    directory = _text(table, "directory", label)
    return acme.AcmeConfig(
        dns=dns, email=_text(table, "email", label), agree_tos=True, staging=bool(table.get("staging", False)),
        directory=directory, ca_bundle=_text(table, "ca_bundle", label), api_token=token,
        zone=_text(table, "zone", label), command=command,
        propagation_delay=_seconds(table, "propagation_delay", 30.0, label),
        propagation_timeout=_seconds(table, "propagation_timeout", 300.0, label), resolvers=tuple(resolvers))


def _validate(cfg: TlsConfig) -> None:
    if (cfg.cert is None) != (cfg.key is None):
        raise ConfigError("TLS: cert and key go together (--tls-cert with --tls-key)")
    if cfg.mode == "cert" and cfg.cert is None:
        raise ConfigError("TLS: mode = \"cert\" needs cert and key")
    if cfg.mode == "self-signed" and cfg.cert is not None:
        raise ConfigError("TLS: mode = \"self-signed\" generates its own certificate; drop cert/key, or use "
                          "mode = \"cert\"")
    if cfg.mode == "acme" and cfg.acme is None:
        raise ConfigError("TLS: mode = \"acme\" needs a [server.tls.acme] table")


def parse_table(section: Any) -> TlsConfig | None:
    """The validated `[server.tls]` table; None when there is none or mode = "off"."""
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ConfigError("[server.tls]: write a table (mode, cert, key, dir, names)")
    unknown = [k for k in section if k not in TLS_KEYS]
    if unknown:
        raise ConfigError(f"[server.tls]: unknown key {unknown[0]!r}; the keys are {', '.join(TLS_KEYS)}")
    cert, key = _text(section, "cert", "[server.tls]"), _text(section, "key", "[server.tls]")
    mode = section.get("mode") or ("acme" if "acme" in section else "cert" if cert else "self-signed")
    if mode not in MODES:
        raise ConfigError(f"[server.tls] mode = {mode!r}; choose from {', '.join(MODES)}")
    if mode == "off":
        return None
    names = section.get("names", [])
    if not isinstance(names, list) or not all(isinstance(n, str) and n.strip() for n in names):
        raise ConfigError('[server.tls] names wants a list of host names or addresses, e.g. ["filecat.lan"]')
    names_t = tuple(expand(n.strip()) for n in names)           # type: ignore[misc]
    cfg = TlsConfig(mode=mode, cert=cert, key=key, dir=_text(section, "dir", "[server.tls]"), names=names_t,
                    acme=_parse_acme(section.get("acme"), names_t) if mode == "acme" else None)
    _validate(cfg)
    return cfg


def effective(base: TlsConfig | None, args: Any, table: Any = None) -> TlsConfig | None:
    """`base` (from [server.tls]) with the command line applied: --tls MODE, --tls-cert/--tls-key.
    `table` is the raw [server.tls] table, read only when --tls acme turns on a table that said another mode."""
    mode, cert, key = (getattr(args, n, None) for n in ("tls_mode", "tls_cert", "tls_key"))
    if mode is None and cert is None and key is None:
        return base
    if mode == "off":
        return None
    if mode == "acme" and (base is None or base.acme is None) and isinstance(table, dict):
        base = parse_table({**table, "mode": "acme"})
    cfg = base or TlsConfig()
    if cert is not None or key is not None:
        cfg = replace(cfg, cert=cert if cert is not None else cfg.cert, key=key if key is not None else cfg.key)
        mode = mode or ("acme" if cfg.mode == "acme" else "cert")
    if mode:
        cfg = replace(cfg, mode=mode)
        if mode == "self-signed" and cert is None and key is None:
            cfg = replace(cfg, cert=None, key=None)
    _validate(cfg)
    return cfg


def default_dir(out: str | None) -> Path:
    """Where generated certificates and the ACME account key live: next to the catalog file."""
    return (Path(out).resolve().parent if out and "://" not in out else Path.cwd()) / ".filecat-tls"


# --- certificates -------------------------------------------------------------------------------
@dataclass(frozen=True)
class CertInfo:
    not_after: datetime
    sans: frozenset[str]


def _norm_san(name: str) -> str:
    name = name.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        return name


def _have_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise TlsError(NO_BACKEND)
    return path


def read_cert(path: Path) -> CertInfo:
    """Expiry and SANs of the first certificate in `path`. ValueError when it is not a certificate."""
    if _have_cryptography():
        from cryptography import x509
        try:
            cert = x509.load_pem_x509_certificate(path.read_bytes())
        except ValueError as exc:
            raise ValueError(f"{path}: not a PEM certificate") from exc
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            sans = {_norm_san(n) for n in ext.get_values_for_type(x509.DNSName)}
            sans |= {_norm_san(str(i)) for i in ext.get_values_for_type(x509.IPAddress)}
        except x509.ExtensionNotFound:
            sans = set()
        return CertInfo(cert.not_valid_after_utc, frozenset(sans))
    done = subprocess.run([_openssl(), "x509", "-in", str(path), "-noout", "-enddate", "-ext", "subjectAltName"],
                          capture_output=True, text=True, check=False)
    end = re.search(r"notAfter=(.+)", done.stdout)
    if done.returncode != 0 or not end:
        raise ValueError(f"{path}: not a PEM certificate")
    when = datetime.strptime(" ".join(end.group(1).split()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    sans = {_norm_san(m) for m in re.findall(r"(?:DNS:|IP Address:)([^,\s]+)", done.stdout)}
    return CertInfo(when, frozenset(sans))


def fingerprint(path: Path) -> str:
    """SHA-256 of the first certificate in `path`, as the browser shows it (AA:BB:...)."""
    pem = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", path.read_text("ascii"), re.S)
    if not pem:
        raise ValueError(f"{path}: no certificate")
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.group(0))).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def wanted_sans(host: str, names: tuple[str, ...] = ()) -> list[str]:
    """The bind host (unless it is a wildcard address), localhost, the loopback addresses, this machine's
    hostname and FQDN, then the configured names; normalised and without repeats."""
    out: list[str] = []

    def add(name: str) -> None:
        name = _norm_san(name)
        if name and name not in out:
            out.append(name)
    if host and host not in ("0.0.0.0", "::"):
        add(host)
    for fixed in ("localhost", "127.0.0.1", "::1"):
        add(fixed)
    for getter in (socket.gethostname, socket.getfqdn):
        try:
            add(getter())
        except OSError:
            pass
    for name in names:
        add(name)
    return out


def _idna(name: str) -> str:
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def generate_self_signed(cert: Path, key: Path, sans: list[str], now: datetime, days: int = SELF_SIGNED_DAYS) -> None:
    """A new ECDSA P-256 certificate (and key, mode 0600) for `sans`, replacing both files."""
    cn = next((s for s in sans if not _is_ip(s)), "filecat")[:64]
    if _have_cryptography():
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        priv = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
        general = [x509.IPAddress(ipaddress.ip_address(s)) if _is_ip(s) else x509.DNSName(_idna(s)) for s in sans]
        built = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(priv.public_key())
                 .serial_number(x509.random_serial_number())
                 .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=days))
                 .add_extension(x509.SubjectAlternativeName(general), critical=False)
                 .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                 .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                              data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                              crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                 .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                 .add_extension(x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False)
                 .sign(priv, hashes.SHA256()))
        acme.write_private(key, acme.key_pem(priv))
        acme.write_private(cert, built.public_bytes(serialization.Encoding.PEM), 0o644)
        return
    exe = _openssl()
    tmp_cert, tmp_key = (cert.with_name(f".{p.name}.tmp") for p in (cert, key))
    cert.parent.mkdir(parents=True, exist_ok=True)
    alt = ",".join(("IP:" if _is_ip(s) else "DNS:") + _idna(s) for s in sans)
    try:
        done = subprocess.run(
            [exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", str(days),
             "-keyout", str(tmp_key), "-out", str(tmp_cert), "-subj", f"/CN={cn}", "-addext", f"subjectAltName={alt}",
             "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"],
            capture_output=True, text=True, check=False)
        if done.returncode != 0:
            raise TlsError(f"openssl could not make a certificate: {done.stderr.strip()[-200:]}")
        os.chmod(tmp_key, 0o600)
        os.replace(tmp_key, key)
        os.replace(tmp_cert, cert)
    finally:
        tmp_cert.unlink(missing_ok=True)
        tmp_key.unlink(missing_ok=True)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# --- the manager --------------------------------------------------------------------------------
class TlsManager:
    """The live server SSLContext and the policy that keeps its certificate fresh."""

    def __init__(self, cfg: TlsConfig, host: str, base_dir: Path | None = None, *,
                 clock: Callable[[], datetime] = utcnow, log: Callable[[str], None] = default_log,
                 sleep: Callable[[float], None] | None = None, http: acme.Http | None = None) -> None:
        self.cfg, self.host, self.clock, self.log = cfg, host, clock, log
        self.dir = Path(cfg.dir) if cfg.dir else (base_dir or default_dir(None))
        self._sleep, self._http = sleep, http
        self._lock = threading.Lock()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.source = ""                    # "cert" | "self-signed" | "acme" | "self-signed-fallback"
        self.cert_path: Path | None = None
        self.fingerprint = ""
        self._stamp: tuple[float, float] | None = None

    # -- file locations
    def _self_signed_paths(self) -> tuple[Path, Path]:
        return self.dir / "selfsigned.crt", self.dir / "selfsigned.key"

    def _acme_paths(self) -> tuple[Path, Path]:
        return (Path(self.cfg.cert) if self.cfg.cert else self.dir / "acme.crt",
                Path(self.cfg.key) if self.cfg.key else self.dir / "acme.key")

    # -- loading
    def _load(self, cert: Path, key: Path, source: str) -> None:
        """Put the pair into the live context. A throwaway context checks it first: load_cert_chain on a
        mismatched pair would otherwise leave the live one half-replaced."""
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key)
            self.context.load_cert_chain(cert, key)
            self.fingerprint = fingerprint(cert)
        except (ssl.SSLError, OSError, ValueError) as exc:
            raise TlsError(f"cannot load the certificate {cert} with key {key}: {exc}") from None
        self.source, self.cert_path = source, cert
        self._stamp = (cert.stat().st_mtime, key.stat().st_mtime)

    def start(self) -> None:
        """Make or find the certificate and load it. TlsError when TLS cannot be offered."""
        with self._lock:
            mode = self.cfg.mode
            if mode == "cert":
                self._load(Path(self.cfg.cert), Path(self.cfg.key), "cert")      # type: ignore[arg-type]
            elif mode == "self-signed":
                self._ensure_self_signed()
                self._load(*self._self_signed_paths(), "self-signed")
            else:
                self._start_acme()

    def banner(self) -> list[str]:
        what = {"cert": "configured certificate", "self-signed": "self-signed certificate",
                "acme": "ACME certificate", "self-signed-fallback": "SELF-SIGNED FALLBACK certificate (ACME failed)"}
        lines = [f"TLS: {what.get(self.source, self.source)} {self.cert_path}",
                 f"TLS: SHA-256 fingerprint {self.fingerprint}"]
        if self.source.startswith("self-signed"):
            lines.append("TLS: self-signed: your browser will warn; compare this fingerprint with the one it shows")
        return lines

    # -- self-signed
    def _ensure_self_signed(self) -> bool:
        """Generate unless a current certificate with the right SANs exists; True when generated."""
        cert, key = self._self_signed_paths()
        want = wanted_sans(self.host, self.cfg.names)
        reason = "no certificate yet"
        try:
            info = read_cert(cert)
            if not key.exists():
                reason = "its key is missing"
            elif info.not_after - self.clock() < RENEW_BEFORE:
                reason = f"it expires {info.not_after:%Y-%m-%d}"
            elif info.sans != {_norm_san(s) for s in want}:
                reason = "its names changed"
            else:
                return False
        except (OSError, ValueError):
            pass
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            self.dir.chmod(0o700)
        except OSError:
            pass
        generate_self_signed(cert, key, want, self.clock())
        self.log(f"generated a self-signed certificate for {', '.join(want)} ({reason})")
        return True

    # -- ACME
    def _acme_due(self) -> tuple[bool, str]:
        cert, key = self._acme_paths()
        try:
            info = read_cert(cert)
        except (OSError, ValueError):
            return True, "no certificate yet"
        if not key.exists():
            return True, "its key is missing"
        if info.not_after - self.clock() < RENEW_BEFORE:
            return True, f"it expires {info.not_after:%Y-%m-%d}"
        if info.sans != {_norm_san(n) for n in self.cfg.names}:
            return True, "its names changed"
        return False, ""

    def _acme_issue(self, reason: str) -> bool:
        """Order a new certificate; False (logged, never raised) when anything fails."""
        a = self.cfg.acme
        assert a is not None
        self.log(f"ACME: ordering a certificate for {', '.join(self.cfg.names)} from {a.directory_url} "
                 f"({reason}; dns-01 via {a.dns})")
        digest = hashlib.sha256(a.directory_url.encode()).hexdigest()[:8]
        try:
            kwargs: dict[str, Any] = {"log": self.log}
            if self._sleep:
                kwargs["sleep"] = self._sleep
            client = acme.AcmeClient(a, self.dir / f"acme-account-{digest}.key", http=self._http, **kwargs)
            chain, key_pem = client.obtain(list(self.cfg.names), acme.make_provider(a, self._http))
            cert, key = self._acme_paths()
            acme.write_private(key, key_pem)
            acme.write_private(cert, chain.encode("ascii"), 0o644)
        except Exception as exc:          # the CA, DNS, the network, the disk: never take the viewer down
            self.log(f"ACME failed: {type(exc).__name__}: {exc}")
            return False
        self.log(f"ACME: certificate issued for {', '.join(self.cfg.names)}")
        return True

    def _start_acme(self) -> None:
        cert, key = self._acme_paths()
        due, reason = self._acme_due()
        if due:
            self._acme_issue(reason)
        try:
            self._load(cert, key, "acme")
            return
        except TlsError as exc:
            if cert.exists():
                self.log(f"ACME: cannot use the existing certificate: {exc}")
        self.log("WARNING: no usable ACME certificate; serving a SELF-SIGNED one until ACME succeeds "
                 "(retried daily). Browsers will warn.")
        self._ensure_self_signed()
        self._load(*self._self_signed_paths(), "self-signed-fallback")

    # -- renewal
    def check(self) -> bool:
        """Renew if due and reload into the live context; True when the served certificate changed."""
        with self._lock:
            mode = self.cfg.mode
            try:
                if mode == "cert":
                    cert, key = Path(self.cfg.cert), Path(self.cfg.key)           # type: ignore[arg-type]
                    if (cert.stat().st_mtime, key.stat().st_mtime) == self._stamp:
                        return False
                    self._load(cert, key, "cert")
                    self.log("reloaded the changed certificate files")
                    return True
                if mode == "self-signed":
                    if not self._ensure_self_signed():
                        return False
                    self._load(*self._self_signed_paths(), "self-signed")
                    return True
                due, reason = self._acme_due()
                if self.source == "self-signed-fallback" and not due:
                    due, reason = True, "serving the self-signed fallback"
                if not due:
                    return False
                if not self._acme_issue(reason):
                    return False
                self._load(*self._acme_paths(), "acme")
                self.log(f"now serving the new certificate ({self.fingerprint})")
                return True
            except (TlsError, OSError, ValueError) as exc:
                self.log(f"renewal check failed: {exc}; keeping the current certificate")
                return False


def start_renewal(manager: TlsManager, stop: threading.Event, interval: float = CHECK_EVERY) -> threading.Thread:
    """A daemon thread that runs manager.check() every `interval` seconds until `stop` is set."""
    def loop() -> None:
        while not stop.wait(interval):
            try:
                manager.check()
            except Exception as exc:
                manager.log(f"renewal check crashed: {type(exc).__name__}: {exc}")
    thread = threading.Thread(target=loop, name="filecat-tls-renewal", daemon=True)
    thread.start()
    return thread


class TlsHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer whose accepted connections are TLS (the manager's live context)."""

    def __init__(self, address: tuple[str, int], handler: Any, manager: TlsManager) -> None:
        self.tls = manager
        super().__init__(address, handler)

    def get_request(self) -> tuple[Any, Any]:
        sock, addr = super().get_request()
        sock.settimeout(HANDSHAKE_TIMEOUT)
        try:                                # the handshake runs on the handler's first read, in its own thread
            return self.tls.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr
        except Exception:
            sock.close()
            raise

    def handle_error(self, request: Any, client_address: Any) -> None:
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError)):
            return                          # a scanner, a plain-HTTP client, a browser that distrusts the cert
        super().handle_error(request, client_address)
