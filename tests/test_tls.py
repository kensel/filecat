"""TLS for the viewer: self-signed certificates, HTTPS serving, the Secure cookie, an ACME client against an
in-process fake CA (DNS-01 through the exec hook and a fake Cloudflare API), renewal and live reload.
Nothing here touches the network: every server listens on 127.0.0.1."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import stat
import sys
import threading
import urllib.parse
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

from filecat import acme, cli, config, control_auth, serve, server_cfg, tls  # noqa: E402
from filecat.backends.sqlite import SqliteBackend  # noqa: E402
from filecat.record import new_document  # noqa: E402

POSIX = os.name != "nt"


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    """urllib would send 127.0.0.1 through the sandbox's proxy."""
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "*")
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


class Clock:
    def __init__(self, now: datetime | None = None) -> None:
        self.now = now or datetime.now(timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


def manager(tmp_path, cfg=None, host="127.0.0.1", clock=None, logs=None, **kw):
    return tls.TlsManager(cfg or tls.TlsConfig(), host, tmp_path / "tls", clock=clock or Clock(),
                          log=(logs if logs is not None else []).append, **kw)


def served_cert(host: str, port: int) -> str:
    """The SHA-256 (AA:BB:..) of the certificate a server presents, trusting nothing."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as raw, ctx.wrap_socket(raw) as conn:
        digest = hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


# --- self-signed --------------------------------------------------------------------------------
def test_self_signed_is_generated_with_the_sans_a_p256_key_and_a_private_key_file(tmp_path):
    m = manager(tmp_path, tls.TlsConfig(names=("filecat.lan", "10.1.2.3")), host="192.168.5.9")
    m.start()
    cert, key = m._self_signed_paths()
    info = tls.read_cert(cert)
    assert {"192.168.5.9", "localhost", "127.0.0.1", "::1", "filecat.lan", "10.1.2.3",
            socket.gethostname().lower()} <= info.sans
    parsed = x509.load_pem_x509_certificate(cert.read_bytes())
    assert isinstance(parsed.public_key(), ec.EllipticCurvePublicKey) and parsed.public_key().curve.name == "secp256r1"
    assert parsed.not_valid_after_utc - parsed.not_valid_before_utc > timedelta(days=300)
    if POSIX:
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert m.fingerprint == tls.fingerprint(cert) and m.fingerprint.count(":") == 31
    assert any(m.fingerprint in line for line in m.banner())
    assert m.context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_a_wildcard_bind_adds_no_wildcard_san():
    sans = tls.wanted_sans("0.0.0.0", ("a.lan",))
    assert "0.0.0.0" not in sans and sans[:3] == ["localhost", "127.0.0.1", "::1"] and sans[-1] == "a.lan"


def test_self_signed_is_reused_then_regenerated_on_expiry_or_changed_names(tmp_path):
    clock, logs = Clock(), []
    first = manager(tmp_path, clock=clock, logs=logs)
    first.start()
    cert = first._self_signed_paths()[0]
    stamp = cert.stat().st_mtime_ns
    again = manager(tmp_path, clock=clock, logs=logs)
    again.start()
    assert again.fingerprint == first.fingerprint and cert.stat().st_mtime_ns == stamp      # reused
    clock.advance(days=334)                                     # 31 days left: still fine
    assert not manager(tmp_path, clock=clock, logs=logs)._ensure_self_signed()
    clock.advance(days=2)                                       # 29 days left: renewed
    soon = manager(tmp_path, clock=clock, logs=logs)
    soon.start()
    assert soon.fingerprint != first.fingerprint and any("expires" in line for line in logs)
    named = manager(tmp_path, tls.TlsConfig(names=("other.lan",)), clock=clock, logs=logs)
    named.start()
    assert named.fingerprint != soon.fingerprint and "other.lan" in tls.read_cert(cert).sans
    assert any("names changed" in line for line in logs)
    cert.write_text("not a certificate")                        # garbage on disk: replaced, not fatal
    manager(tmp_path, tls.TlsConfig(names=("other.lan",)), clock=clock, logs=logs).start()
    assert tls.read_cert(cert).sans


@pytest.mark.skipif(shutil.which("openssl") is None, reason="no openssl command")
def test_openssl_fallback_makes_and_reads_the_same_kind_of_certificate(tmp_path, monkeypatch):
    monkeypatch.setattr(tls, "_have_cryptography", lambda: False)
    m = manager(tmp_path, tls.TlsConfig(names=("filecat.lan",)))
    m.start()
    cert, key = m._self_signed_paths()
    info = tls.read_cert(cert)
    assert {"localhost", "127.0.0.1", "::1", "filecat.lan"} <= info.sans
    assert info.not_after - datetime.now(timezone.utc) > timedelta(days=300)
    assert x509.load_pem_x509_certificate(cert.read_bytes()).public_key().curve.name == "secp256r1"
    if POSIX:
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
    again = manager(tmp_path, tls.TlsConfig(names=("filecat.lan",)))
    again.start()
    assert again.fingerprint == m.fingerprint                   # reused after reading it with openssl too


def test_neither_cryptography_nor_openssl_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr(tls, "_have_cryptography", lambda: False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(tls.TlsError, match="cryptography.*openssl"):
        manager(tmp_path).start()


def test_a_configured_cert_is_loaded_and_reloaded_when_the_files_change(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    for d in (first, second):
        tls.generate_self_signed(d / "c.crt", d / "c.key", ["localhost", "127.0.0.1"], datetime.now(timezone.utc))
    cfg = tls.TlsConfig(mode="cert", cert=str(first / "c.crt"), key=str(first / "c.key"))
    m = manager(tmp_path, cfg)
    m.start()
    assert m.source == "cert" and not m.check()
    fp = m.fingerprint
    shutil.copy(second / "c.crt", first / "c.crt")
    shutil.copy(second / "c.key", first / "c.key")
    os.utime(first / "c.crt", (1, 1))                           # a different mtime whatever the clock resolution
    assert m.check() and m.fingerprint == tls.fingerprint(second / "c.crt") != fp


def test_a_mismatched_pair_is_refused_and_leaves_the_live_context_alone(tmp_path):
    for d in ("a", "b"):
        tls.generate_self_signed(tmp_path / d / "c.crt", tmp_path / d / "c.key", ["localhost"], datetime.now(timezone.utc))
    cfg = tls.TlsConfig(mode="cert", cert=str(tmp_path / "a/c.crt"), key=str(tmp_path / "b/c.key"))
    with pytest.raises(tls.TlsError, match="cannot load"):
        manager(tmp_path, cfg).start()


# --- configuration ------------------------------------------------------------------------------
def test_parse_table_modes_and_errors(monkeypatch):
    monkeypatch.setenv("CRT_DIR", "/etc/filecat")
    assert tls.parse_table(None) is None and tls.parse_table({"mode": "off"}) is None
    assert tls.parse_table({}).mode == "self-signed"
    cfg = tls.parse_table({"cert": "${CRT_DIR}/v.crt", "key": "${CRT_DIR}/v.key", "names": ["a.lan"]})
    assert (cfg.mode, cfg.cert, cfg.key, cfg.names) == ("cert", "/etc/filecat/v.crt", "/etc/filecat/v.key", ("a.lan",))
    for bad, text in [({"cert": "x"}, "go together"), ({"mode": "tls13"}, "choose from"), ({"mode": "cert"}, "needs cert"),
                      ({"mode": "self-signed", "cert": "a", "key": "b"}, "generates its own"),
                      ({"colour": 1}, "unknown key"), ({"mode": "acme"}, "acme"), ({"names": "a"}, "names wants")]:
        with pytest.raises(config.ConfigError, match=text):
            tls.parse_table(bad)
    with pytest.raises(config.ConfigError, match="NOPE"):
        tls.parse_table({"cert": "${NOPE}/c", "key": "k"})


def acme_table(**over):
    return {"names": ["filecat.example.test"], "acme": {"dns": "exec", "command": "hook.sh --x", "agree_tos": True, **over}}


def test_parse_acme_table(monkeypatch):
    monkeypatch.setenv("CF_TOKEN", "s3cret-token")
    cfg = tls.parse_table(acme_table(email="me@example.test", staging=True, resolvers=["1.1.1.1"]))
    assert cfg.mode == "acme" and cfg.acme.command == ("hook.sh", "--x") and cfg.acme.staging
    assert cfg.acme.directory_url == acme.LETS_ENCRYPT_STAGING and cfg.acme.resolvers == ("1.1.1.1",)
    assert tls.parse_table(acme_table()).acme.directory_url == acme.LETS_ENCRYPT
    assert tls.parse_table(acme_table(directory="https://ca.lan/dir")).acme.directory_url == "https://ca.lan/dir"
    cf = tls.parse_table({"names": ["a.test"], "acme": {"dns": "cloudflare", "api_token": "${CF_TOKEN}", "agree_tos": True,
                                                         "propagation_delay": "45s"}})
    assert cf.acme.api_token == "s3cret-token" and cf.acme.propagation_delay == 45 and "s3cret" not in repr(cf)
    for table, text in [({**acme_table(), "names": []}, "needs names"), (acme_table(agree_tos=False), "agree_tos"),
                        (acme_table(dns="route53"), "choose from"), (acme_table(command=""), "command is required"),
                        (acme_table(challenge="http-01"), "unknown key"),
                        ({"names": ["a"], "acme": {"dns": "cloudflare", "agree_tos": True}}, "api_token")]:
        with pytest.raises(config.ConfigError, match=text):
            tls.parse_table(table)


def test_server_table_carries_tls_and_flags_override_it():
    cfg = server_cfg.load_server({"server": {"tls": {"names": ["a.lan"]}}}, [])
    assert cfg.tls.mode == "self-signed" and server_cfg.load_server({}, []).tls is None
    ns = lambda **kw: Namespace(**{"tls_mode": None, "tls_cert": None, "tls_key": None, **kw})   # noqa: E731
    assert tls.effective(cfg.tls, ns()) is cfg.tls
    assert tls.effective(cfg.tls, ns(tls_mode="off")) is None
    assert tls.effective(None, ns(tls_mode="self-signed")).mode == "self-signed"
    flagged = tls.effective(None, ns(tls_cert="c.pem", tls_key="k.pem"))
    assert (flagged.mode, flagged.cert, flagged.key) == ("cert", "c.pem", "k.pem")
    assert tls.effective(flagged, ns(tls_mode="self-signed")).cert is None
    with pytest.raises(config.ConfigError, match="go together"):
        tls.effective(None, ns(tls_cert="c.pem"))
    with pytest.raises(config.ConfigError, match="acme"):
        tls.effective(None, ns(tls_mode="acme"))
    table = {"mode": "off", **acme_table()}
    assert tls.effective(None, ns(tls_mode="acme"), table).mode == "acme"
    parser = cli.build_parser()
    for command in ("serve", "server"):
        got = parser.parse_args([command, "--tls", "acme", "--tls-cert", "c", "--tls-key", "k"])
        assert (got.tls_mode, got.tls_cert, got.tls_key) == ("acme", "c", "k")


# --- serving ------------------------------------------------------------------------------------
GOOD = "correct horse battery"


@pytest.fixture
def catalog_path(tmp_path):
    out = str(tmp_path / "c.sqlite")
    with SqliteBackend(out) as b:
        b.put(new_document(r"\nas\share", "", kind="dir"))
    return out


def start_viewer(out, tls_cfg, coordinator=None, auth=None):
    args = SimpleNamespace(backend="sqlite", out=out, dsn=None, host="127.0.0.1", port=0, quiet=True, no_save=False,
                           graph_max_age=120, open=False, control_auth=auth, tls=tls_cfg)
    return serve.start_viewer(args, coordinator)


def https(viewer, cafile):
    ctx = ssl.create_default_context(cafile=str(cafile))
    return http.client.HTTPSConnection("127.0.0.1", viewer.httpd.server_address[1], context=ctx, timeout=10)


def test_the_viewer_answers_over_https_with_its_own_certificate(catalog_path, tmp_path):
    viewer = start_viewer(catalog_path, tls.TlsConfig())
    try:
        assert viewer.url.startswith("https://127.0.0.1:")
        cert = tmp_path / ".filecat-tls" / "selfsigned.crt"           # next to the catalog
        assert cert.exists()
        conn = https(viewer, cert)                                    # verified against the generated cert
        conn.connect()
        version = conn.sock.version()
        conn.request("GET", "/api/info")
        res = conn.getresponse()
        assert res.status == 200 and json.loads(res.read())["backend"] == "sqlite"
        assert version in ("TLSv1.2", "TLSv1.3")
        conn.close()
        assert served_cert("127.0.0.1", viewer.httpd.server_address[1]) == tls.fingerprint(cert)
        pinned = ssl.create_default_context(cafile=str(cert))          # a TLS 1.2-only client still connects
        pinned.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("127.0.0.1", viewer.httpd.server_address[1]), timeout=10) as raw, \
                pinned.wrap_socket(raw, server_hostname="127.0.0.1") as tls12:
            assert tls12.version() == "TLSv1.2"
        plain = http.client.HTTPConnection("127.0.0.1", viewer.httpd.server_address[1], timeout=10)
        with pytest.raises((http.client.HTTPException, OSError)):     # plain HTTP to the TLS port gets nothing
            plain.request("GET", "/")
            plain.getresponse().read()
    finally:
        viewer.stop()


def test_a_stalled_client_does_not_block_other_connections(catalog_path, tmp_path):
    viewer = start_viewer(catalog_path, tls.TlsConfig())
    try:
        port = viewer.httpd.server_address[1]
        idle = socket.create_connection(("127.0.0.1", port))          # connects, never sends a ClientHello
        conn = https(viewer, tmp_path / ".filecat-tls" / "selfsigned.crt")
        conn.request("GET", "/api/info")
        assert conn.getresponse().status == 200
        idle.close()
    finally:
        viewer.stop()


def test_the_session_cookie_is_secure_over_tls_and_csrf_checks_https_origins(catalog_path, tmp_path):
    auth = control_auth.ControlAuth(control_auth.hash_password(GOOD), control_auth.LoginGuard(), control_auth.Sessions(),
                                    False, fail_delay=0.0)
    viewer = start_viewer(catalog_path, tls.TlsConfig(), coordinator=object(), auth=auth)
    try:
        port = viewer.httpd.server_address[1]
        cafile = tmp_path / ".filecat-tls" / "selfsigned.crt"

        def login(origin):
            conn = https(viewer, cafile)
            headers = {"Content-Type": "application/json", "X-Filecat-Control": "run"}
            if origin:
                headers["Origin"] = origin
            conn.request("POST", "/api/login", json.dumps({"password": GOOD}), headers)
            res = conn.getresponse()
            res.read()
            conn.close()
            return res.status, res.getheader("Set-Cookie") or ""

        for origin in (f"https://127.0.0.1:{port}", None):             # an Origin-less request is still TLS
            status, cookie = login(origin)
            assert status == 200 and "; Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
        assert login(f"https://evil.example:{port}")[0] == 403         # cross-origin
        assert login(f"http://127.0.0.1:{port}")[0] == 403             # an http origin cannot be same-origin over TLS
    finally:
        viewer.stop()


def test_the_cookie_stays_non_secure_over_plain_http(catalog_path):
    auth = control_auth.ControlAuth(control_auth.hash_password(GOOD), control_auth.LoginGuard(), control_auth.Sessions(),
                                    False, fail_delay=0.0)
    viewer = start_viewer(catalog_path, None, coordinator=object(), auth=auth)
    try:
        port = viewer.httpd.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/api/login", json.dumps({"password": GOOD}),
                     {"Content-Type": "application/json", "X-Filecat-Control": "run", "Origin": f"http://127.0.0.1:{port}"})
        res = conn.getresponse()
        res.read()
        assert viewer.url.startswith("http://") and res.status == 200 and "Secure" not in res.getheader("Set-Cookie")
    finally:
        viewer.stop()


def test_serve_run_refuses_a_missing_cert_file(catalog_path, tmp_path, capsys):
    (tmp_path / "f.toml").write_text("")
    args = Namespace(backend="sqlite", out=catalog_path, dsn=None, host="127.0.0.1", port=0, quiet=True, no_save=False,
                     graph_max_age=120, open=False, config=str(tmp_path / "f.toml"), tls_mode=None,
                     tls_cert=str(tmp_path / "no.crt"), tls_key=str(tmp_path / "no.key"))
    assert serve.run(args) == 2
    assert "cannot load the certificate" in capsys.readouterr().err


# --- the fake CA --------------------------------------------------------------------------------
def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeAcme:
    """RFC 8555 from the server's side: directory, nonces, JWS verification, account, order, authz, dns-01
    challenge (checks the TXT through `txt`), finalize (signs the CSR with a throwaway CA), certificate."""

    def __init__(self, txt, validity_days=90, fail_validation=False):
        self.txt, self.validity, self.fail_validation = txt, validity_days, fail_validation
        self.now = lambda: datetime.now(timezone.utc)      # the CA's clock (a test may share its fake one)
        self.nonces: set[str] = set()
        self.accounts: dict[str, dict] = {}
        self.account_payloads: list[dict] = []
        self.orders: dict[str, dict] = {}
        self.authz: dict[str, dict] = {}
        self.bad_nonces = 0                  # answer this many POSTs with badNonce first
        self.issued: list[x509.Certificate] = []
        self.requests: list[str] = []
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Fake CA")])
        now = datetime.now(timezone.utc)
        self.ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                        .public_key(self.ca_key.public_key()).serial_number(1).not_valid_before(now - timedelta(days=1))
                        .not_valid_after(now + timedelta(days=3650))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                        .sign(self.ca_key, hashes.SHA256()))
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, doc=None, headers=None, raw=None, ctype="application/json"):
                body = raw if raw is not None else json.dumps(doc or {}).encode()
                nonce = b64e(os.urandom(12))
                fake.nonces.add(nonce)
                self.send_response(status)
                self.send_header("Replay-Nonce", nonce)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self):
                if self.path == "/directory":
                    base = fake.base
                    return self._send(200, {"newNonce": base + "/nonce", "newAccount": base + "/acct",
                                            "newOrder": base + "/order", "meta": {"termsOfService": base + "/tos"}})
                self._send(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "no GET here"})

            def do_HEAD(self):
                self._send(200)

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                url = fake.base + self.path
                fake.requests.append(self.path)
                try:
                    payload, kid = fake._verify(body, url)
                except ValueError as exc:
                    kind = "badNonce" if "nonce" in str(exc) else "malformed"
                    return self._send(400, {"type": f"urn:ietf:params:acme:error:{kind}", "detail": str(exc)})
                status, doc, headers, raw, ctype = fake.route(self.path, payload, kid)
                self._send(status, doc, headers, raw, ctype or "application/json")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def directory(self) -> str:
        return self.base + "/directory"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    @staticmethod
    def thumbprint(jwk) -> str:
        canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, sort_keys=True, separators=(",", ":"))
        return b64e(hashlib.sha256(canon.encode()).digest())

    def _verify(self, body: bytes, url: str):
        doc = json.loads(body)
        protected = json.loads(b64d(doc["protected"]))
        if self.bad_nonces:
            self.bad_nonces -= 1
            raise ValueError("bad nonce (injected)")
        if protected["nonce"] not in self.nonces:
            raise ValueError("bad nonce")
        self.nonces.discard(protected["nonce"])
        if protected["url"] != url or protected["alg"] != "ES256":
            raise ValueError("url or alg mismatch")
        jwk = protected.get("jwk") or self.accounts[protected["kid"]]
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64d(jwk["x"]), "big"), int.from_bytes(b64d(jwk["y"]), "big"),
                                            ec.SECP256R1()).public_key()
        sig = b64d(doc["signature"])
        assert len(sig) == 64
        try:
            pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                       f"{doc['protected']}.{doc['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise ValueError("bad signature") from None
        payload = json.loads(b64d(doc["payload"])) if doc["payload"] else None
        return payload, (protected.get("kid") or jwk)

    def route(self, path, payload, kid):
        base = self.base
        if path == "/acct":
            self.account_payloads.append(payload)
            ident = f"{base}/acct/{len(self.accounts) + 1}"
            self.accounts[ident] = kid
            return 201, {"status": "valid"}, {"Location": ident}, None, None
        if not isinstance(kid, str) or kid not in self.accounts:
            return 401, {"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "use kid"}, {}, None, None
        jwk = self.accounts[kid]
        if path == "/order":
            names = [i["value"] for i in payload["identifiers"]]
            oid = f"o{len(self.orders) + 1}"
            ids = []
            for n in names:
                aid = f"a{len(self.authz) + 1}"
                bare = n[2:] if n.startswith("*.") else n
                self.authz[aid] = {"name": bare, "wild": n.startswith("*."), "status": "pending", "token": b64e(os.urandom(16)),
                                   "jwk": jwk, "error": None}
                ids.append(aid)
            self.orders[oid] = {"names": names, "authz": ids, "status": "pending", "cert": None}
            return 201, self._order(oid), {"Location": f"{base}/order/{oid}"}, None, None
        if path.startswith("/order/"):
            return 200, self._order(path.rpartition("/")[2]), {}, None, None
        if path.startswith("/authz/"):
            return 200, self._authz(path.rpartition("/")[2]), {}, None, None
        if path.startswith("/chal/"):
            aid = path.rpartition("/")[2]
            az = self.authz[aid]
            want = b64e(hashlib.sha256(f"{az['token']}.{self.thumbprint(jwk)}".encode()).digest())
            seen = self.txt(f"_acme-challenge.{az['name']}")
            if not self.fail_validation and want in seen:
                az["status"] = "valid"
            else:
                az["status"], az["error"] = "invalid", {"type": "urn:ietf:params:acme:error:unauthorized",
                                                        "detail": f"no TXT {want} found at _acme-challenge.{az['name']}"}
            return 200, {"type": "dns-01", "status": az["status"], "url": f"{base}/chal/{aid}", "token": az["token"]}, {}, None, None
        if path.startswith("/finalize/"):
            oid = path.rpartition("/")[2]
            order = self.orders[oid]
            if any(self.authz[a]["status"] != "valid" for a in order["authz"]):
                return 403, {"type": "urn:ietf:params:acme:error:orderNotReady", "detail": "authorizations not valid"}, {}, None, None
            csr = x509.load_der_x509_csr(b64d(payload["csr"]))
            assert csr.is_signature_valid
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            assert sorted(san.get_values_for_type(x509.DNSName)) == sorted(order["names"])
            now = self.now()
            leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.ca_cert.subject)
                    .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=self.validity))
                    .add_extension(san, critical=False).sign(self.ca_key, hashes.SHA256()))
            self.issued.append(leaf)
            order["cert"], order["status"] = leaf.public_bytes(serialization.Encoding.PEM) + \
                self.ca_cert.public_bytes(serialization.Encoding.PEM), "valid"
            return 200, self._order(oid), {}, None, None
        if path.startswith("/cert/"):
            return 200, None, {}, self.orders[path.rpartition("/")[2]]["cert"], "application/pem-certificate-chain"
        return 404, {"type": "urn:ietf:params:acme:error:malformed", "detail": path}, {}, None, None

    def _order(self, oid):
        o = self.orders[oid]
        if o["status"] == "pending" and all(self.authz[a]["status"] == "valid" for a in o["authz"]):
            o["status"] = "ready"
        doc = {"status": o["status"], "identifiers": [{"type": "dns", "value": n} for n in o["names"]],
               "authorizations": [f"{self.base}/authz/{a}" for a in o["authz"]], "finalize": f"{self.base}/finalize/{oid}"}
        if o["cert"]:
            doc["certificate"] = f"{self.base}/cert/{oid}"
        return doc

    def _authz(self, aid):
        az = self.authz[aid]
        chal = {"type": "dns-01", "status": az["status"], "url": f"{self.base}/chal/{aid}", "token": az["token"]}
        if az["error"]:
            chal["error"] = az["error"]
        return {"status": az["status"], "identifier": {"type": "dns", "value": az["name"]}, "wildcard": az["wild"],
                "challenges": [{"type": "http-01", "status": "pending", "url": f"{self.base}/nope", "token": "x"}, chal]}


HOOK = """import pathlib, sys
action, fqdn, value = sys.argv[1:4]
here = pathlib.Path(__file__).parent
records = here / "records"
records.mkdir(exist_ok=True)
with open(here / "hook.log", "a") as fh:
    fh.write(f"{action} {fqdn} {value}\\n")
record = records / f"{fqdn}.{value}"
if action == "add":
    record.write_text(value)
else:
    record.unlink()
"""


@pytest.fixture
def hook(tmp_path):
    d = tmp_path / "hook"
    d.mkdir()
    (d / "dns.py").write_text(HOOK)

    def txt(fqdn):
        return [p.read_text() for p in (d / "records").glob(f"{fqdn}.*")] if (d / "records").exists() else []
    txt.dir, txt.log = d, lambda: (d / "hook.log").read_text().splitlines() if (d / "hook.log").exists() else []
    txt.command = (sys.executable, str(d / "dns.py"))
    return txt


def acme_cfg(fake, hook, **over):
    return acme.AcmeConfig(dns="exec", email="admin@example.test", agree_tos=True, directory=fake.directory,
                           command=hook.command, propagation_delay=0.0, **over)


NAMES = ("filecat.example.test", "viewer.example.test")


def acme_manager(tmp_path, fake, hook, clock=None, logs=None, **over):
    cfg = tls.TlsConfig(mode="acme", names=NAMES, acme=acme_cfg(fake, hook, **over))
    return manager(tmp_path, cfg, clock=clock, logs=logs, sleep=lambda s: None)


@pytest.fixture
def fake(hook):
    f = FakeAcme(hook)
    yield f
    f.close()


# --- ACME ---------------------------------------------------------------------------------------
def test_acme_issues_through_the_exec_hook_and_serves_the_chain(tmp_path, fake, hook):
    logs = []
    m = acme_manager(tmp_path, fake, hook, logs=logs)
    m.start()
    cert, key = m._acme_paths()
    assert m.source == "acme" and tls.read_cert(cert).sans == set(NAMES)
    assert cert.read_text().count("BEGIN CERTIFICATE") == 2                      # leaf + the CA's
    assert fake.issued and fake.account_payloads == [{"termsOfServiceAgreed": True, "contact": ["mailto:admin@example.test"]}]
    adds = [line for line in hook.log() if line.startswith("add")]
    assert sorted(a.split()[1] for a in adds) == [f"_acme-challenge.{n}" for n in sorted(NAMES)]
    assert [line.split()[0] for line in hook.log()] == ["add", "add", "remove", "remove"]      # all published first
    assert not list((hook.dir / "records").iterdir())                          # cleaned up
    accounts = list((tmp_path / "tls").glob("acme-account-*.key"))
    assert len(accounts) == 1
    if POSIX:
        assert stat.S_IMODE(key.stat().st_mode) == 0o600 and stat.S_IMODE(accounts[0].stat().st_mode) == 0o600
    assert not any("PRIVATE" in line for line in logs)
    # the key matches the chain and the live context serves it
    srv = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    srv.socket = m.context.wrap_socket(srv.socket, server_side=True)
    assert m.fingerprint == tls.fingerprint(cert)
    srv.server_close()


def test_acme_uses_staging_and_directory_defaults():
    assert acme.AcmeConfig(dns="exec", staging=True).directory_url == acme.LETS_ENCRYPT_STAGING
    assert acme.AcmeConfig(dns="exec").directory_url == acme.LETS_ENCRYPT
    assert acme.AcmeConfig(dns="exec", staging=True, directory="https://x/d").directory_url == "https://x/d"


def test_acme_retries_a_bad_nonce_and_refuses_without_tos(tmp_path, fake, hook):
    fake.bad_nonces = 1
    m = acme_manager(tmp_path, fake, hook)
    m.start()
    assert m.source == "acme"
    with pytest.raises(acme.AcmeError, match="agree_tos"):
        acme.AcmeClient(acme.AcmeConfig(dns="exec", directory=fake.directory), tmp_path / "k.key").account()


def test_acme_is_not_repeated_while_the_certificate_is_fresh(tmp_path, fake, hook):
    acme_manager(tmp_path, fake, hook).start()
    n = len(fake.issued)
    again = acme_manager(tmp_path, fake, hook)
    again.start()
    assert len(fake.issued) == n and again.source == "acme" and not again.check()


def test_a_failed_acme_keeps_the_previous_certificate(tmp_path, fake, hook):
    clock, logs = Clock(), []
    m = acme_manager(tmp_path, fake, hook, clock=clock, logs=logs)
    m.start()
    before = m.fingerprint
    clock.advance(days=70)                                      # 20 days left: due
    fake.fail_validation = True
    again = acme_manager(tmp_path, fake, hook, clock=clock, logs=logs)
    again.start()
    assert again.source == "acme" and again.fingerprint == before             # still the old one
    assert any("ACME failed" in line and "no TXT" in line for line in logs)
    assert not list((hook.dir / "records").iterdir())                         # records removed after the failure too
    assert not again.check() and again.fingerprint == before


def test_acme_failure_with_no_certificate_falls_back_to_self_signed_loudly_then_recovers(tmp_path, fake, hook):
    logs = []
    fake.fail_validation = True
    m = acme_manager(tmp_path, fake, hook, logs=logs)
    m.start()
    assert m.source == "self-signed-fallback" and any("WARNING" in line and "SELF-SIGNED" in line for line in logs)
    assert any("FALLBACK" in line for line in m.banner())
    fallback = m.fingerprint
    fake.fail_validation = False                                # the daily retry succeeds
    assert m.check() and m.source == "acme" and m.fingerprint != fallback


def test_acme_unreachable_ca_is_a_logged_failure_not_a_crash(tmp_path, hook):
    logs = []
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()
    cfg = tls.TlsConfig(mode="acme", names=NAMES, acme=acme.AcmeConfig(
        dns="exec", agree_tos=True, directory=f"http://127.0.0.1:{port}/directory", command=hook.command))
    m = manager(tmp_path, cfg, logs=logs)
    m.start()
    assert m.source == "self-signed-fallback" and any("ACME failed" in line for line in logs)


def test_wildcard_names_validate_the_base_name(tmp_path, fake, hook):
    cfg = tls.TlsConfig(mode="acme", names=("*.example.test", "example.test"), acme=acme_cfg(fake, hook))
    m = manager(tmp_path, cfg, sleep=lambda s: None)
    m.start()
    assert m.source == "acme"
    adds = [line.split()[1:] for line in hook.log() if line.startswith("add")]
    assert [a[0] for a in adds] == ["_acme-challenge.example.test"] * 2 and adds[0][1] != adds[1][1]


# --- the fake Cloudflare ------------------------------------------------------------------------
class FakeCloudflare:
    def __init__(self, token="cf-secret-token-123"):
        self.token, self.zones, self.records, self.calls = token, {"example.test": "z1"}, {}, []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, result, status=200, ok=True):
                body = json.dumps({"success": ok, "result": result,
                                   "errors": [] if ok else [{"code": 1, "message": "denied"}]}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self):
                url = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(url.query))
                fake.calls.append((self.command, url.path))
                if self.headers.get("Authorization") != f"Bearer {fake.token}":
                    return self._reply(None, 403, False)
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                parts = url.path.removeprefix("/client/v4").strip("/").split("/")
                if parts == ["zones"]:
                    return self._reply([{"id": fake.zones[q["name"]], "name": q["name"]}] if q.get("name") in fake.zones else [])
                zone = parts[1]
                if len(parts) == 3 and self.command == "POST":
                    rid = f"r{len(fake.records) + 1}"
                    fake.records[rid] = {"id": rid, "zone": zone, "type": "TXT", **{k: body[k] for k in ("name", "content")}}
                    return self._reply(fake.records[rid])
                if len(parts) == 3:
                    return self._reply([r for r in fake.records.values() if r["name"] == q["name"] and r["zone"] == zone])
                fake.records.pop(parts[3])
                return self._reply({"id": parts[3]})

            do_GET = do_POST = do_DELETE = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/client/v4"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def txt(self, fqdn):
        return [r["content"] for r in self.records.values() if r["name"] == fqdn]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def cloudflare(monkeypatch):
    cf = FakeCloudflare()
    monkeypatch.setattr(acme, "CLOUDFLARE_API", cf.url)
    yield cf
    cf.close()


def test_acme_with_cloudflare_creates_and_deletes_the_txt_records_and_never_logs_the_token(tmp_path, cloudflare):
    fake = FakeAcme(cloudflare.txt)
    logs = []
    try:
        cfg = tls.TlsConfig(mode="acme", names=NAMES, acme=acme.AcmeConfig(
            dns="cloudflare", agree_tos=True, directory=fake.directory, api_token=cloudflare.token, propagation_delay=0.0))
        m = manager(tmp_path, cfg, logs=logs, sleep=lambda s: None)
        m.start()
        assert m.source == "acme" and not cloudflare.records                     # created, validated, deleted
        calls = cloudflare.calls
        assert ("GET", "/client/v4/zones") in calls                              # found by name (filecat.example.test -> example.test)
        assert sum(c == ("POST", "/client/v4/zones/z1/dns_records") for c in calls) == 2
        assert sum(c[0] == "DELETE" for c in calls) == 2
        text = "\n".join(logs) + repr(cfg) + repr(m.cfg)
        assert cloudflare.token not in text
        for p in (tmp_path / "tls").rglob("*"):
            if p.is_file() and p.suffix == ".log":
                assert cloudflare.token not in p.read_text()
    finally:
        fake.close()


def test_cloudflare_errors_are_reported_without_the_token(cloudflare):
    p = acme.CloudflareProvider("wrong-token-xyz")
    with pytest.raises(acme.AcmeError) as err:
        p.add("_acme-challenge.a.example.test", "v")
    assert "denied" in str(err.value) and "wrong-token-xyz" not in str(err.value)
    with pytest.raises(acme.AcmeError, match="no zone found"):
        acme.CloudflareProvider(cloudflare.token).add("_acme-challenge.a.other.test", "v")
    assert acme.CloudflareProvider(cloudflare.token, zone="example.test")._zone_id("x.y.example.test") == "z1"
    assert acme.CloudflareProvider(cloudflare.token, zone="0" * 32)._zone_id("x.example.test") == "0" * 32


def test_exec_hook_failures_name_the_script_and_exit_code(tmp_path):
    script = tmp_path / "bad.py"
    script.write_text("import sys; sys.stderr.write('boom'); sys.exit(3)")
    p = acme.ExecProvider((sys.executable, str(script)))
    with pytest.raises(acme.AcmeError, match=r"exited 3: boom"):
        p.add("_acme-challenge.a.test", "v")
    with pytest.raises(acme.AcmeError, match="FileNotFoundError|No such|cannot find"):
        acme.ExecProvider((str(tmp_path / "missing-hook"),)).add("a", "b")


def test_waiting_for_resolvers_polls_until_they_see_the_record(tmp_path, fake, hook):
    seen = {"calls": 0}

    def lookup(fqdn, resolver, timeout=5.0):
        seen["calls"] += 1
        return hook(fqdn) if seen["calls"] > 4 else []           # invisible for the first rounds
    waits = []
    cfg = acme_cfg(fake, hook, resolvers=("203.0.113.1", "203.0.113.2"))
    client = acme.AcmeClient(cfg, tmp_path / "k.key", sleep=waits.append, txt_lookup=lookup)
    client.obtain(["filecat.example.test"], acme.ExecProvider(hook.command))
    assert seen["calls"] > 4 and 10.0 in waits and 0.0 not in waits           # polled, not the fixed delay


def test_dns_txt_parses_a_udp_answer():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def answer():
        data, addr = srv.recvfrom(512)
        name_end = data.index(b"\0", 12) + 1
        question = data[12:name_end + 4]
        rdata = bytes([5]) + b"hello" + bytes([3]) + b"abc"
        rr = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
        srv.sendto(data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + rr, addr)
    t = threading.Thread(target=answer)
    t.start()
    try:
        assert acme.dns_txt("_acme-challenge.a.test", f"127.0.0.1:{port}", timeout=5) == ["helloabc"]
    finally:
        t.join()
        srv.close()


# --- renewal and live reload --------------------------------------------------------------------
def test_renewal_within_30_days_reloads_the_live_context(tmp_path, fake, hook):
    clock, logs = Clock(), []
    fake.now = clock
    m = acme_manager(tmp_path, fake, hook, clock=clock, logs=logs)
    m.start()
    srv = tls.TlsHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler, m)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        first = served_cert("127.0.0.1", port)
        assert first == m.fingerprint
        clock.advance(days=59)                                  # 31 days left
        assert not m.check() and served_cert("127.0.0.1", port) == first and len(fake.issued) == 1
        clock.advance(days=2)                                   # 29 days left: renew
        assert m.check()
        second = served_cert("127.0.0.1", port)                 # new connections, same listening socket
        assert second != first and second == m.fingerprint and len(fake.issued) == 2
        assert any("now serving the new certificate" in line for line in logs)
        assert not m.check()                                    # the new one has 90 days
    finally:
        srv.shutdown()
        srv.server_close()


def test_renewal_failure_keeps_serving_the_current_certificate(tmp_path, fake, hook):
    clock, logs = Clock(), []
    m = acme_manager(tmp_path, fake, hook, clock=clock, logs=logs)
    m.start()
    first = m.fingerprint
    clock.advance(days=80)
    fake.fail_validation = True
    assert not m.check() and m.fingerprint == first and m.source == "acme"
    assert any("ACME failed" in line for line in logs)


def test_self_signed_renewal_reloads_too(tmp_path):
    clock = Clock()
    m = manager(tmp_path, clock=clock)
    m.start()
    first = m.fingerprint
    assert not m.check()
    clock.advance(days=340)
    assert m.check() and m.fingerprint != first


def test_the_renewal_thread_checks_on_its_interval_and_survives_errors():
    calls, errors = [], []

    class Fake:
        log = staticmethod(errors.append)

        def check(self):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return False
    stop = threading.Event()
    thread = tls.start_renewal(Fake(), stop, interval=0.01)
    deadline = datetime.now() + timedelta(seconds=10)
    while len(calls) < 3 and datetime.now() < deadline:
        stop.wait(0.01)
    stop.set()
    thread.join(5)
    assert len(calls) >= 3 and any("boom" in e for e in errors) and not thread.is_alive()


def test_viewer_stop_ends_the_renewal_thread(catalog_path):
    viewer = start_viewer(catalog_path, tls.TlsConfig())
    viewer.stop()
    assert viewer._stop.is_set()


def test_the_files_are_writable_only_by_the_owner_from_the_first_byte(tmp_path):
    target = tmp_path / "d" / "secret.key"
    acme.write_private(target, b"k")
    acme.write_private(target, b"k2")                           # replacing keeps the mode
    assert target.read_bytes() == b"k2" and not list(target.parent.glob(".*.tmp"))
    if POSIX:
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
