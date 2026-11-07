"""The Windows certificate store itself: read-only always, and - with
HKDFGUARD_TEST_WINDOWS_CERT_STORE=1 - a round trip through throwaway self-signed certificates
New-SelfSignedCertificate makes in CurrentUser\\My with non-exportable CNG keys, removed with their
keys afterwards."""

from __future__ import annotations

import hashlib
import os
import secrets
import ssl
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from hkdfguard.abstractions import ObjectClosedError
from hkdfguard.options.certificate import (
    CertificateNotFoundError,
    CertificateOptions,
    CertificateOptionsLoader,
    CertificateStoreOptions,
    NativeProviderRequiredError,
    StoreLocation,
    StoreName,
)
from hkdfguard.options.certificate._dn import describe

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the Windows certificate store")


def _powershell(script: str) -> str:
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, check=False, timeout=120)
    if result.returncode != 0:
        raise AssertionError(f"PowerShell failed: {result.stderr or result.stdout}")
    return result.stdout.strip()


def _current_user_options(subject: str, require_private_key: bool = True) -> CertificateOptions:
    return CertificateOptions(windows=CertificateStoreOptions(StoreLocation.CURRENT_USER, StoreName.MY, subject),
                              require_private_key=require_private_key)


def test_the_real_store_is_opened_read_only() -> None:
    subject = f"CN=hkdfguard-python-test-{secrets.token_hex(8)}"
    with pytest.raises(CertificateNotFoundError, match="holds no certificate"):
        CertificateOptionsLoader().load(_current_user_options(subject))


def test_every_store_name_is_a_windows_system_store() -> None:
    from hkdfguard.options.certificate import _windows_store

    for name in StoreName:
        for certificate in _windows_store.read_store(StoreLocation.CURRENT_USER, name):
            certificate.close()
    assert _windows_store.windows_store_name(StoreName.CERTIFICATE_AUTHORITY) == "CA"
    assert _windows_store.windows_store_name(StoreName.MY) == "My"
    # A store that doesn't exist reads as empty, as .NET's does.
    assert _windows_store.read_store(StoreLocation.CURRENT_USER, f"hkdfguard-no-such-store-{secrets.token_hex(4)}") == []  # type: ignore[arg-type]


def test_a_root_certificate_loads_for_trust_without_a_key() -> None:
    from hkdfguard.options.certificate import _windows_store

    now = datetime.now(UTC)
    roots = _windows_store.read_store(StoreLocation.LOCAL_MACHINE, StoreName.ROOT)
    try:
        valid = [root.certificate for root in roots if root.certificate.not_valid_before_utc <= now <= root.certificate.not_valid_after_utc]
    finally:
        for root in roots:
            root.close()
    if not valid:
        pytest.skip("LocalMachine Root holds no root valid now")
    options = CertificateOptions(windows=CertificateStoreOptions(StoreLocation.LOCAL_MACHINE, StoreName.ROOT, describe(valid[0].subject)),
                                 require_private_key=False)
    with CertificateOptionsLoader().load(options) as loaded:
        assert not loaded.has_private_key
        context = loaded.create_ssl_context(ssl.Purpose.SERVER_AUTH)
        assert context.get_ca_certs(binary_form=True)


@pytest.fixture
def opted_in() -> None:
    if os.environ.get("HKDFGUARD_TEST_WINDOWS_CERT_STORE") != "1":
        pytest.skip("makes and removes certificates in CurrentUser\\My: set HKDFGUARD_TEST_WINDOWS_CERT_STORE=1")


def _throwaway(key_algorithm: str) -> Iterator[str]:
    """A self-signed certificate in CurrentUser\\My with a non-exportable key of ``key_algorithm`` in
    the Microsoft Software Key Storage Provider, removed with its key afterwards; yields its subject."""
    subject = f"CN=hkdfguard-python-test-{secrets.token_hex(8)}"
    thumbprint = _powershell(
        "$ErrorActionPreference = 'Stop'; "
        f"$c = New-SelfSignedCertificate -Subject '{subject}' -CertStoreLocation Cert:\\CurrentUser\\My -KeyAlgorithm {key_algorithm} "
        "-KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' -KeyUsage DigitalSignature,KeyEncipherment "
        "-NotAfter (Get-Date).AddDays(2); $c.Thumbprint")
    try:
        yield subject
    finally:
        _powershell(f"Remove-Item -Path Cert:\\CurrentUser\\My\\{thumbprint} -DeleteKey -ErrorAction Stop")
        assert _powershell(f"Test-Path Cert:\\CurrentUser\\My\\{thumbprint}") == "False"


@pytest.fixture
def rsa_certificate(opted_in: None) -> Iterator[str]:
    yield from _throwaway("RSA -KeyLength 2048")


@pytest.fixture
def ecdsa_certificate(opted_in: None) -> Iterator[str]:
    yield from _throwaway("ECDSA_nistP256")


def test_a_non_exportable_rsa_key_signs_and_decrypts_through_cng(rsa_certificate: str) -> None:
    loaded = CertificateOptionsLoader().load(_current_user_options(rsa_certificate))
    with loaded:
        assert loaded.key_location == "the Windows certificate store"
        public = loaded.public_key()
        assert isinstance(public, rsa.RSAPublicKey)
        data = b"to sign"
        for algorithm in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512(), hashes.SHA1()):
            public.verify(loaded.sign(data, algorithm, padding.PKCS1v15()), data, padding.PKCS1v15(), algorithm)
            for salt in (padding.PSS.DIGEST_LENGTH, padding.PSS.MAX_LENGTH, 20):
                signature = loaded.sign(data, algorithm, padding.PSS(padding.MGF1(algorithm), salt))
                public.verify(signature, data, padding.PSS(padding.MGF1(algorithm), padding.PSS.AUTO), algorithm)
        assert loaded.decrypt(public.encrypt(b"secret", padding.PKCS1v15()), padding.PKCS1v15()) == bytearray(b"secret")
        oaep = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), b"label")
        assert loaded.decrypt(public.encrypt(b"secret", oaep), oaep) == bytearray(b"secret")
        with pytest.raises(NativeProviderRequiredError):
            loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH)
    with pytest.raises(ObjectClosedError):
        loaded.sign(data, hashes.SHA256(), padding.PKCS1v15())


def test_a_non_exportable_ecdsa_key_signs_in_der_through_cng(ecdsa_certificate: str) -> None:
    with CertificateOptionsLoader().load(_current_user_options(ecdsa_certificate)) as loaded:
        public = loaded.public_key()
        assert isinstance(public, ec.EllipticCurvePublicKey)
        for algorithm in (hashes.SHA256(), hashes.SHA384()):
            public.verify(loaded.sign(b"to sign", algorithm), b"to sign", ec.ECDSA(algorithm))


def test_a_certificate_with_an_unknown_version_in_the_store_doesnt_stop_another_loading(rsa_certificate: str, tmp_path: Path) -> None:
    # Anyone running as the user can add a certificate to CurrentUser\My. One claiming X.509 version 9
    # makes cryptography raise InvalidVersion - not a ValueError - and is passed over like any other
    # certificate that can't be read, rather than failing every load from the store.
    from hkdfguard.options.certificate import _windows_store
    from test_certificate_pkcs12 import version_9

    with CertificateOptionsLoader().load(_current_user_options(rsa_certificate, require_private_key=False)) as loaded:
        bad = version_9(loaded.certificate)
    path = tmp_path / "bad.cer"
    path.write_bytes(bad)
    thumbprint = hashlib.sha1(bad).hexdigest().upper()  # the store's own name for it
    _powershell(f"certutil -user -f -addstore My '{path}' | Out-Null; if ($LASTEXITCODE) {{ throw 'certutil failed' }}")
    try:
        read = _windows_store.read_store(StoreLocation.CURRENT_USER, StoreName.MY)
        try:
            assert not any(c.der == bad for c in read)  # passed over, not raised
        finally:
            for certificate in read:
                certificate.close()
        with CertificateOptionsLoader().load(_current_user_options(rsa_certificate)) as loaded:
            assert loaded.has_private_key
    finally:
        _powershell(f"Remove-Item -Path Cert:\\CurrentUser\\My\\{thumbprint} -ErrorAction Stop")


def test_the_certificate_alone_loads_without_opening_its_key(rsa_certificate: str) -> None:
    with CertificateOptionsLoader().load(_current_user_options(rsa_certificate, require_private_key=False)) as loaded:
        assert not loaded.has_private_key
        loaded.create_ssl_context(ssl.Purpose.SERVER_AUTH)
