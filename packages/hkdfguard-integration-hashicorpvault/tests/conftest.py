"""The fixtures VaultClient's tests share: real key rings, a fake Vault, clients over it, and TLS."""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hkdfguard.abstractions import DataProtector
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.integration.hashicorpvault import StaticVaultToken, VaultClient, VaultClientOptions, VaultRetryOptions
from vault_client_test_support import TOKEN, FakeVault, FixedKeyWrapper, MakeClient, Tls


@pytest.fixture
def make_ring() -> Iterator[Callable[[], DefaultKeyRing]]:
    rings: list[DefaultKeyRing] = []

    def make() -> DefaultKeyRing:
        ring = DefaultKeyRing(DefaultFormatProvider())
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
        rings.append(ring)
        return ring

    yield make
    for ring in rings:
        ring.close()


@pytest.fixture
def protector(make_ring: Callable[[], DefaultKeyRing]) -> DataProtector:
    """A protector for VaultClient.TOKEN_PURPOSE on a fresh ring."""
    return make_ring().create_protector(VaultClient.TOKEN_PURPOSE)


@pytest.fixture
def vault() -> Iterator[FakeVault]:
    fake = FakeVault()
    yield fake
    fake.close()


@pytest.fixture
def make_client(vault: FakeVault, protector: DataProtector) -> Iterator[MakeClient]:
    """A client of the fake, with the fake's token protected and set, and no waits between retries -
    so tests that meet a 5xx stay quick; keyword arguments replace options."""
    clients: list[VaultClient] = []

    def make(*, with_token: bool = True, logger: Any = None, **changes: Any) -> VaultClient:
        options = VaultClientOptions(address=vault.address, retry=VaultRetryOptions(retry_wait_min=timedelta(0), retry_wait_max=timedelta(0)),
                                     token=StaticVaultToken.protect(protector, TOKEN) if with_token else None)
        client = VaultClient(protector, replace(options, **changes), logger)
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.close()


@pytest.fixture(scope="session")
def tls(tmp_path_factory: pytest.TempPathFactory) -> Tls:
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(ca_name)
              .public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                             critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
              .sign(ca_key, hashes.SHA256()))
    path: Path = tmp_path_factory.mktemp("tls") / "server.pem"
    path.write_bytes(server.public_bytes(serialization.Encoding.PEM)
                     + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(path)
    return Tls(ca.public_bytes(serialization.Encoding.PEM), context)
