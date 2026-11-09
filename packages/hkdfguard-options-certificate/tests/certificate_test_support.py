"""What hkdfguard-options-certificate's tests share: certificates and keys they make, a store and a
password source they hand the loader, the fixtures other tools wrote, and a TLS handshake over
memory BIOs."""

from __future__ import annotations

import ssl
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID
from hkdfguard.abstractions import ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.options.certificate import (
    CertificateFileFormat,
    CertificateFileOptions,
    CertificateOptions,
    CertificateOptionsLoader,
    CertificateOptionsValidator,
    StoreLocation,
    StoreName,
)
from hkdfguard.options.certificate._keys import RsaDecryption, RsaSignature

TESTDATA = Path(__file__).parent / "testdata"
SUBJECT = "CN=api.example.com, O=Contoso"
PASSWORD = "pässwörd-123"
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)

type PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


@cache
def rsa_key(index: int = 0) -> rsa.RSAPrivateKey:
    """An RSA key, made once per index: generating one per certificate would make the suite slow."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@cache
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def name_of(subject: str) -> x509.Name:
    """A subject written as configuration writes it, most specific first, as a certificate encodes it."""
    oids = {"CN": NameOID.COMMON_NAME, "O": NameOID.ORGANIZATION_NAME, "OU": NameOID.ORGANIZATIONAL_UNIT_NAME, "C": NameOID.COUNTRY_NAME,
            "DC": NameOID.DOMAIN_COMPONENT, "E": NameOID.EMAIL_ADDRESS}
    rdns = []
    for part in subject.split(","):
        keyword, _, value = part.strip().partition("=")
        rdns.append(x509.RelativeDistinguishedName([x509.NameAttribute(oids[keyword], value)]))
    return x509.Name(list(reversed(rdns)))


def self_signed(key: PrivateKey, subject: str | x509.Name = SUBJECT, not_before_days: float = -1, not_after_days: float = 30,
                *, now: datetime = NOW) -> x509.Certificate:
    """A self-signed certificate for ``key``, valid from ``not_before_days`` to ``not_after_days``
    after ``now``, usable as its own TLS trust anchor - for api.example.com."""
    name = name_of(subject) if isinstance(subject, str) else subject
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + timedelta(days=not_before_days)).not_valid_after(now + timedelta(days=not_after_days))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.example.com")]), critical=False))
    return builder.sign(key, hashes.SHA256())


def pem(*certificates: x509.Certificate) -> bytes:
    return b"".join(certificate.public_bytes(serialization.Encoding.PEM) for certificate in certificates)


def fixture(name: str) -> Path:
    return TESTDATA / name


def fixture_certificate(name: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(fixture(name).read_bytes())


class FakePasswords(ProtectedReadOnlyCache):
    """A password source holding plaintext passwords, recording every buffer it decrypts into so a
    test can check the loader zeroes it."""

    def __init__(self, passwords: dict[str, str] | None = None) -> None:
        self.passwords = {name: value.encode("utf-8") for name, value in (passwords or {"tls-password": PASSWORD}).items()}
        self.buffers: list[WritableBuffer] = []
        self.failure: Exception | None = None

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        if self.failure is not None:
            raise self.failure
        value = self.passwords.get(name)
        if value is None:
            return 0
        self.buffers.append(result)
        memoryview(result).cast("B")[:len(value)] = value
        return len(value)

    def find_max_decrypted_length(self, name: str) -> int | None:
        if self.failure is not None:
            raise self.failure
        value = self.passwords.get(name)
        return None if value is None else len(value) + 7  # an upper bound, as a real cache's is


class FakeKey:
    """A store's key, as an OsKey: signs and decrypts with a cryptography key, from the digest and
    scheme the loader's OsKeySource resolved, as CNG and the keychain are handed them."""

    def __init__(self, key: PrivateKey) -> None:
        self.key = key
        self.closed = False

    def sign_digest(self, digest: bytes, algorithm: hashes.HashAlgorithm, scheme: RsaSignature | None) -> bytes:
        assert not self.closed
        if isinstance(self.key, ec.EllipticCurvePrivateKey):
            assert scheme is None
            return self.key.sign(digest, ec.ECDSA(Prehashed(algorithm)))
        assert scheme is not None
        chosen: padding.AsymmetricPadding = padding.PKCS1v15() if scheme.scheme == "pkcs1" else padding.PSS(padding.MGF1(algorithm), scheme.salt_length)
        return self.key.sign(digest, chosen, Prehashed(algorithm))

    def decrypt(self, ciphertext: bytes, scheme: RsaDecryption) -> bytearray:
        assert isinstance(self.key, rsa.RSAPrivateKey)
        if scheme.scheme == "pkcs1":
            return bytearray(self.key.decrypt(ciphertext, padding.PKCS1v15()))
        assert scheme.hash is not None
        return bytearray(self.key.decrypt(ciphertext, padding.OAEP(padding.MGF1(scheme.hash), scheme.hash, scheme.label or None)))

    def close(self) -> None:
        self.closed = True


class FakeStoreCertificate:
    """One certificate in a FakeStore."""

    def __init__(self, certificate: x509.Certificate, key: PrivateKey | None, *, key_fails: Exception | None = None) -> None:
        self.certificate = certificate
        self.der = certificate.public_bytes(serialization.Encoding.DER)
        self.has_private_key = key is not None
        self._key = key
        self.key_fails = key_fails
        self.closed = False
        self.opened: FakeKey | None = None

    def open_private_key(self) -> FakeKey:
        if self.key_fails is not None:
            raise self.key_fails
        assert self._key is not None
        self.opened = FakeKey(self._key)
        return self.opened

    def close(self) -> None:
        self.closed = True


class FakeStore:
    """A store the loader reads instead of the operating system's: its certificates, by location and name."""

    def __init__(self, *certificates: FakeStoreCertificate, failure: Exception | None = None) -> None:
        self.certificates = list(certificates)
        self.failure = failure
        self.reads: list[tuple[StoreLocation, StoreName]] = []

    def read(self, location: StoreLocation, name: StoreName) -> Sequence[FakeStoreCertificate]:
        self.reads.append((location, name))
        if self.failure is not None:
            raise self.failure
        return list(self.certificates)


def entry(not_before_days: float, not_after_days: float, *, with_key: bool = True, subject: str = SUBJECT,
          key: PrivateKey | None = None) -> FakeStoreCertificate:
    chosen = key or rsa_key()
    return FakeStoreCertificate(self_signed(chosen, subject, not_before_days, not_after_days), chosen if with_key else None)


def loader(passwords: ProtectedReadOnlyCache | None = None, platform: str = "windows", store: FakeStore | None = None,
           now: datetime = NOW) -> CertificateOptionsLoader:
    return CertificateOptionsLoader(passwords, lambda: now, validator=CertificateOptionsValidator(platform),
                                    store_reader=store.read if store is not None else None)


def pfx_options(path: Path | str, password_secret_name: str | None = "tls-password", *, allow_unprotected: bool = False,
                require_private_key: bool = True) -> CertificateOptions:
    return CertificateOptions(file=CertificateFileOptions(path=str(path), password_secret_name=password_secret_name,
                                                          allow_unprotected_private_key=allow_unprotected),
                              require_private_key=require_private_key)


def pem_options(path: Path | str, key_path: Path | str | None, password_secret_name: str | None = "tls-password", *,
                allow_unprotected: bool = False, require_private_key: bool = True) -> CertificateOptions:
    return CertificateOptions(file=CertificateFileOptions(path=str(path), format=CertificateFileFormat.PEM,
                                                          key_path=None if key_path is None else str(key_path),
                                                          password_secret_name=password_secret_name,
                                                          allow_unprotected_private_key=allow_unprotected),
                              require_private_key=require_private_key)


def handshake(server: ssl.SSLContext, client: ssl.SSLContext, hostname: str | None = "api.example.com") -> bytes:
    """A TLS handshake between the two contexts over memory BIOs, and a message from server to
    client through it; returns the DER of the certificate the client was shown."""
    server_in, server_out, client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    server_side = server.wrap_bio(server_in, server_out, server_side=True)
    client_side = client.wrap_bio(client_in, client_out, server_hostname=hostname)
    done = {"client": False, "server": False}
    for _ in range(20):
        for name, side in (("client", client_side), ("server", server_side)):
            if not done[name]:
                try:
                    side.do_handshake()
                    done[name] = True
                except ssl.SSLWantReadError:
                    pass
            server_in.write(client_out.read())
            client_in.write(server_out.read())
        if all(done.values()):
            break
    assert all(done.values()), "the handshake didn't finish"
    server_side.write(b"hello")
    client_in.write(server_out.read())
    assert client_side.read(5) == b"hello"
    peer = client_side.getpeercert(binary_form=True)
    assert peer is not None
    return peer
