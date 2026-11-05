"""VaultTlsOptions: PEM and PKCS#12 trust and client keys, against a mutual-TLS server on loopback."""

from __future__ import annotations

import datetime
import ipaddress
import os
import shutil
import ssl
import subprocess
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from hkdfguard.abstractions import DataProtector, KeyWrapper, WritableBuffer
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.integration.hashicorpvault import VaultTlsOptions, _tls
from hkdfguard.integration.hashicorpvault._http import VaultConnector

PASSWORD = "store-password"

# --- Certificates and stores ----------------------------------------------------------------------


@dataclass
class Issued:
    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate

    @property
    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def issue(name: str, issuer: Issued | None = None, *, ca: bool = False, dns: str | None = None) -> Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.certificate.subject if issuer else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               # Python 3.13's strict verification (VERIFY_X509_STRICT) requires both identifiers.
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer.key if issuer else key).public_key()), critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                                      key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False,
                                                      decipher_only=False), critical=True)
    if dns is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                                                                    if dns == "localhost" else [x509.DNSName(dns)]), critical=False)
    return Issued(key, builder.sign(issuer.key if issuer else key, hashes.SHA256()))


@dataclass
class Pki:
    ca: Issued
    server: Issued
    named_server: Issued
    client: Issued
    directory: Path

    def write(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path

    def key_store(self, name: str = "vault-client", password: str = PASSWORD) -> Path:
        data = pkcs12.serialize_key_and_certificates(name.encode(), self.client.key, self.client.certificate, [self.ca.certificate],
                                                     serialization.BestAvailableEncryption(password.encode()))
        return self.write(f"client-{name}.p12", data)

    def trust_store(self, password: str = PASSWORD) -> Path:
        cas = [pkcs12.PKCS12Certificate(self.ca.certificate, b"ca")]
        data = pkcs12.serialize_java_truststore(cas, serialization.BestAvailableEncryption(password.encode())) if hasattr(
            pkcs12, "serialize_java_truststore") else pkcs12.serialize_key_and_certificates(None, None, None, cas,
                                                                                           serialization.BestAvailableEncryption(password.encode()))
        return self.write("trust.p12", data)


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    ca = issue("Test CA", ca=True)
    return Pki(ca, issue("localhost", ca, dns="localhost"), issue("vault.test", ca, dns="vault.test"), issue("vault-client", ca),
               tmp_path_factory.mktemp("pki"))


class FixedKeyWrapper(KeyWrapper):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def wrap(self, plaintext: Any, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Any, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


@pytest.fixture
def protector() -> Iterator[DataProtector]:
    ring = DefaultKeyRing(DefaultFormatProvider())
    ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
    yield ring.create_protector(VaultTlsOptions.PASSWORD_PURPOSE)
    ring.close()


# --- A mutual-TLS server ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        peer = self.connection.getpeercert() if isinstance(self.connection, ssl.SSLSocket) else None
        subject: dict[str, Any] = {name: value for rdn in peer["subject"] for name, value in rdn} if peer else {}  # type: ignore[str-unpack]  # typeshed types a subject loosely
        body = str(subject.get("commonName", "anonymous")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class TlsServer:
    def __init__(self, pki: Pki, certificate: Issued, *, require_client: bool) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_file = pki.write(f"server-{certificate.certificate.serial_number}.pem", certificate.certificate_pem + certificate.key_pem)
        context.load_cert_chain(cert_file)
        if require_client:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cadata=pki.ca.certificate_pem.decode())
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def servers(pki: Pki) -> Iterator[Callable[..., TlsServer]]:
    started: list[TlsServer] = []

    def start(certificate: Issued | None = None, *, require_client: bool = True) -> TlsServer:
        server = TlsServer(pki, certificate or pki.server, require_client=require_client)
        started.append(server)
        return server

    yield start
    for server in started:
        server.close()


def get(server: TlsServer, tls: VaultTlsOptions, host: str = "127.0.0.1") -> str:
    connection = VaultConnector(True, host, server.port, timedelta(seconds=5), tls=tls).connect()
    try:
        connection.request("GET", "/v1/sys/health")
        return connection.getresponse().read().decode()
    finally:
        connection.close()


def chain(error: BaseException) -> list[BaseException]:
    found: list[BaseException] = []
    current: BaseException | None = error
    while current is not None:
        found.append(current)
        current = current.__cause__ or current.__context__
    return found


# --- Tests ------------------------------------------------------------------------------------------


def test_nothing_set_is_empty_and_is_the_systems_defaults() -> None:
    options = VaultTlsOptions()
    assert options.is_empty
    context = options.create_ssl_context()
    assert context.check_hostname
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize("field", ["server_certificate_file", "server_certificate_directory", "client_certificate_file", "client_certificate_key_file",
                                   "trust_store_file", "client_key_store_file"])
def test_any_file_makes_it_not_empty(field: str) -> None:
    assert not VaultTlsOptions(**{field: "x"}).is_empty  # type: ignore[arg-type]


def test_pem_ca_and_client_certificate_authenticate_both_ways(pki: Pki, servers: Callable[..., TlsServer]) -> None:
    server = servers()
    tls = VaultTlsOptions(server_certificate_file=pki.write("ca.pem", pki.ca.certificate_pem),
                          client_certificate_file=pki.write("client.pem", pki.client.certificate_pem),
                          client_certificate_key_file=pki.write("client.key", pki.client.key_pem))
    assert get(server, tls) == "vault-client"


def test_pem_in_memory_authenticates_both_ways(pki: Pki, servers: Callable[..., TlsServer]) -> None:
    server = servers()
    tls = VaultTlsOptions(server_certificate_pem=pki.ca.certificate_pem, client_certificate_pem=pki.client.certificate_pem,
                          client_certificate_key_pem=bytearray(pki.client.key_pem))
    assert get(server, tls) == "vault-client"


def test_a_ca_directory_is_read(pki: Pki, servers: Callable[..., TlsServer], tmp_path: Path) -> None:
    (tmp_path / "ca.pem").write_bytes(pki.ca.certificate_pem)
    assert get(servers(require_client=False), VaultTlsOptions(server_certificate_directory=tmp_path)) == "anonymous"


def test_pkcs12_stores_authenticate_both_ways(pki: Pki, servers: Callable[..., TlsServer], protector: DataProtector) -> None:
    server = servers()
    password = VaultTlsOptions.protect_password(protector, PASSWORD)
    tls = VaultTlsOptions(trust_store_file=pki.trust_store(), trust_store_password=password, client_key_store_file=pki.key_store(),
                          client_key_store_password=password, password_protector=protector)
    assert get(server, tls) == "vault-client"


def test_the_client_key_store_alias_is_matched_ignoring_case(pki: Pki, servers: Callable[..., TlsServer], protector: DataProtector) -> None:
    server = servers()
    password = VaultTlsOptions.protect_password(protector, PASSWORD)
    tls = VaultTlsOptions(server_certificate_pem=pki.ca.certificate_pem, client_key_store_file=pki.key_store("Vault-Client"),
                          client_key_store_password=password, client_key_store_alias="vault-CLIENT", password_protector=protector)
    assert get(server, tls) == "vault-client"


def test_an_alias_the_store_doesnt_hold_is_refused(pki: Pki, protector: DataProtector) -> None:
    tls = VaultTlsOptions(client_key_store_file=pki.key_store(), client_key_store_password=VaultTlsOptions.protect_password(protector, PASSWORD),
                          client_key_store_alias="other", password_protector=protector)
    with pytest.raises(ValueError, match="no private key named 'other'"):
        tls.create_ssl_context()


@pytest.mark.skipif(shutil.which("keytool") is None, reason="keytool makes the store of two keys cryptography can't")
def test_a_store_of_several_keys_needs_an_alias_and_presents_the_one_it_names(protector: DataProtector, tmp_path: Path,
                                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    store = tmp_path / "two.p12"
    keytool = shutil.which("keytool")
    assert keytool is not None
    for alias in ("first", "second"):
        subprocess.run([keytool, "-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", f"CN={alias}",
                        "-storetype", "PKCS12", "-keystore", str(store), "-storepass", PASSWORD, "-validity", "2"], check=True, capture_output=True)
    password = VaultTlsOptions.protect_password(protector, PASSWORD)
    with pytest.raises(ValueError, match="more than one private key"):
        VaultTlsOptions(client_key_store_file=store, client_key_store_password=password, password_protector=protector).create_ssl_context()

    presented: list[str] = []
    real = _tls._load_client_key
    def recording(context: ssl.SSLContext, key: Any, chain: list[x509.Certificate]) -> None:
        presented.append(chain[0].subject.rfc4514_string())
        real(context, key, chain)

    monkeypatch.setattr(_tls, "_load_client_key", recording)
    VaultTlsOptions(client_key_store_file=store, client_key_store_password=password, client_key_store_alias="SECOND",
                    password_protector=protector).create_ssl_context()
    assert presented == ["CN=second"]


def test_a_store_without_its_password_or_protector_is_refused(pki: Pki, protector: DataProtector) -> None:
    with pytest.raises(ValueError, match="needs its password"):
        VaultTlsOptions(client_key_store_file=pki.key_store(), password_protector=protector).create_ssl_context()
    with pytest.raises(ValueError, match="set password_protector"):
        VaultTlsOptions(trust_store_file=pki.trust_store(), trust_store_password="protected").create_ssl_context()


def test_an_unprotected_password_is_refused_without_quoting_or_chaining(pki: Pki, protector: DataProtector) -> None:
    tls = VaultTlsOptions(client_key_store_file=pki.key_store(), client_key_store_password=PASSWORD, password_protector=protector)
    with pytest.raises(ValueError, match="isn't protected") as raised:
        tls.create_ssl_context()
    assert PASSWORD not in str(raised.value)
    assert chain(raised.value) == [raised.value]


def test_a_password_protected_for_another_purpose_is_refused(pki: Pki, protector: DataProtector) -> None:
    ring = DefaultKeyRing(DefaultFormatProvider())
    ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
    try:
        other = ring.create_protector("another purpose").encrypt(PASSWORD)
    finally:
        ring.close()
    with pytest.raises(ValueError, match="isn't protected"):
        VaultTlsOptions(client_key_store_file=pki.key_store(), client_key_store_password=other, password_protector=protector).create_ssl_context()


def test_a_wrong_password_is_refused(pki: Pki, protector: DataProtector) -> None:
    tls = VaultTlsOptions(client_key_store_file=pki.key_store(), client_key_store_password=VaultTlsOptions.protect_password(protector, "wrong"),
                          password_protector=protector)
    with pytest.raises(ValueError, match="Could not read the client key store"):
        tls.create_ssl_context()


def test_a_password_is_decrypted_only_while_the_store_is_read_and_zeroed(pki: Pki, protector: DataProtector, monkeypatch: pytest.MonkeyPatch) -> None:
    decrypted: list[bytearray] = []
    original = pkcs12.load_pkcs12

    def recording(data: bytes, password: Any, *args: Any) -> Any:
        decrypted.append(password)
        assert bytes(password) == PASSWORD.encode()
        return original(data, password, *args)

    monkeypatch.setattr(pkcs12, "load_pkcs12", recording)
    VaultTlsOptions(client_key_store_file=pki.key_store(), client_key_store_password=VaultTlsOptions.protect_password(protector, PASSWORD),
                    password_protector=protector).create_ssl_context()
    assert decrypted
    assert all(isinstance(p, bytearray) and not any(p) for p in decrypted)


def test_the_client_key_reaches_ssl_only_encrypted_and_its_file_is_deleted(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    removed: dict[str, bytes] = {}
    real_remove = os.remove

    def remove(path: str) -> None:
        removed[path] = Path(path).read_bytes()
        real_remove(path)

    monkeypatch.setattr(os, "remove", remove)
    VaultTlsOptions(client_certificate_pem=pki.client.certificate_pem, client_certificate_key_pem=pki.client.key_pem).create_ssl_context()
    assert len(removed) == 1
    path, content = next(iter(removed.items()))
    assert not Path(path).exists()
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in content
    assert pki.client.key_pem not in content


def test_a_jks_store_is_refused_with_how_to_convert_it(pki: Pki, protector: DataProtector) -> None:
    store = pki.write("store.jks", b"\xfe\xed\xfe\xed" + bytes(60))
    tls = VaultTlsOptions(trust_store_file=store, trust_store_password=VaultTlsOptions.protect_password(protector, PASSWORD), password_protector=protector)
    with pytest.raises(ValueError, match=r"JKS or JCEKS.*-deststoretype PKCS12"):
        tls.create_ssl_context()


def test_a_trust_store_holding_a_key_is_refused(pki: Pki, protector: DataProtector) -> None:
    tls = VaultTlsOptions(trust_store_file=pki.key_store(), trust_store_password=VaultTlsOptions.protect_password(protector, PASSWORD),
                          password_protector=protector)
    with pytest.raises(ValueError, match="holds a private key"):
        tls.create_ssl_context()


@pytest.mark.parametrize(("make", "match"), [
    (lambda p, s: VaultTlsOptions(trust_store_file=s, server_certificate_pem=p.ca.certificate_pem), "trust store and PEM"),
    (lambda p, s: VaultTlsOptions(client_key_store_file=s, client_certificate_pem=p.client.certificate_pem), "client key store and a PEM"),
    (lambda p, s: VaultTlsOptions(client_certificate_pem=p.client.certificate_pem), "must be given together"),
    (lambda p, s: VaultTlsOptions(client_certificate_key_pem=p.client.key_pem), "must be given together"),
    (lambda p, s: VaultTlsOptions(server_certificate_pem=b"not a certificate"), "no PEM-encoded certificate"),
    (lambda p, s: VaultTlsOptions(server_certificate_file=s.parent / "missing.pem"), "Could not read"),
])
def test_conflicting_or_unreadable_settings_are_refused(pki: Pki, make: Callable[[Pki, Path], VaultTlsOptions], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        make(pki, pki.key_store()).create_ssl_context()


def test_an_encrypted_or_missing_client_key_is_refused_without_quoting_it(pki: Pki) -> None:
    encrypted = pki.client.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))
    with pytest.raises(ValueError, match="encrypted"):
        VaultTlsOptions(client_certificate_pem=pki.client.certificate_pem, client_certificate_key_pem=encrypted).create_ssl_context()
    with pytest.raises(ValueError, match="no private key") as raised:
        VaultTlsOptions(client_certificate_pem=pki.client.certificate_pem, client_certificate_key_pem=b"garbage").create_ssl_context()
    assert raised.value.__cause__ is None


def test_options_of_the_wrong_type_are_refused() -> None:
    with pytest.raises(TypeError, match="server_certificate_file"):
        VaultTlsOptions(server_certificate_file=1).create_ssl_context()  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="server_certificate_pem"):
        VaultTlsOptions(server_certificate_pem="pem").create_ssl_context()  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="password_protector"):
        VaultTlsOptions(password_protector="p").create_ssl_context()  # type: ignore[arg-type]


def test_an_untrusted_server_is_refused(pki: Pki, servers: Callable[..., TlsServer]) -> None:
    server = servers(require_client=False)
    with pytest.raises(ssl.SSLCertVerificationError):
        get(server, VaultTlsOptions(server_certificate_pem=issue("Other CA", ca=True).certificate_pem))


def test_the_server_name_replaces_the_host_for_verification(pki: Pki, servers: Callable[..., TlsServer]) -> None:
    server = servers(pki.named_server, require_client=False)
    with pytest.raises(ssl.SSLCertVerificationError):
        get(server, VaultTlsOptions(server_certificate_pem=pki.ca.certificate_pem))
    assert get(server, VaultTlsOptions(server_certificate_pem=pki.ca.certificate_pem, server_name="vault.test")) == "anonymous"


def test_insecure_skip_verify_trusts_any_certificate(servers: Callable[..., TlsServer]) -> None:
    server = servers(require_client=False)
    assert get(server, VaultTlsOptions(insecure_skip_verify=True)) == "anonymous"


def test_protect_password_refuses_nothing_to_protect(protector: DataProtector) -> None:
    with pytest.raises(ValueError, match="empty"):
        VaultTlsOptions.protect_password(protector, "")
    with pytest.raises(TypeError):
        VaultTlsOptions.protect_password(None, PASSWORD)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        VaultTlsOptions.protect_password(protector, None)  # type: ignore[arg-type]
    assert VaultTlsOptions.protect_password(protector, PASSWORD) != PASSWORD


def test_the_repr_holds_no_password_or_key(pki: Pki) -> None:
    text = repr(VaultTlsOptions(client_key_store_password="protected-value", client_certificate_key_pem=pki.client.key_pem))
    assert "protected-value" not in text
    assert "PRIVATE KEY" not in text
