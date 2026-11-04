"""The macOS keychains themselves: read-only always, and - with HKDFGUARD_TEST_MACOS_KEYCHAIN=1 - a
round trip through a throwaway identity imported into the login keychain, deleted afterwards.

Not yet run on a Mac: written to the Go port's test of the same, which was."""

from __future__ import annotations

import os
import secrets
import ssl
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from certificate_test_support import ec_key, rsa_key, self_signed
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from hkdfguard.options.certificate import (
    CertificateNotFoundError,
    CertificateOptions,
    CertificateOptionsLoader,
    CertificateStoreOptions,
    NativeProviderRequiredError,
    StoreLocation,
    StoreName,
    UnsupportedCertificateError,
)

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="the macOS keychains")


def test_the_real_keychains_are_opened_read_only() -> None:
    for location in (StoreLocation.CURRENT_USER, StoreLocation.LOCAL_MACHINE):
        options = CertificateOptions(mac_os=CertificateStoreOptions(location, subject=f"CN=hkdfguard-python-test-{secrets.token_hex(8)}"))
        with pytest.raises(CertificateNotFoundError, match="holds no certificate"):
            CertificateOptionsLoader().load(options)


def test_only_the_my_store_is_a_keychain() -> None:
    from hkdfguard.options.certificate import _macos_keychain

    with pytest.raises(UnsupportedCertificateError):
        _macos_keychain.read_store(StoreLocation.CURRENT_USER, StoreName.ROOT)


@pytest.fixture(params=["RSA", "ECDSA"])
def identity(request: pytest.FixtureRequest) -> Iterator[str]:
    """A self-signed identity imported into the login keychain, open to every application (-A) so
    no dialog asks, deleted when the test ends; yields its subject."""
    if os.environ.get("HKDFGUARD_TEST_MACOS_KEYCHAIN") != "1":
        pytest.skip("imports and deletes an identity in the login keychain: set HKDFGUARD_TEST_MACOS_KEYCHAIN=1")
    key = rsa_key() if request.param == "RSA" else ec_key()
    subject = f"CN=hkdfguard-python-test-{secrets.token_hex(8)}"
    certificate = self_signed(key, subject)
    # 3DES and a SHA-1 MAC: what every macOS release's security import reads.
    encryption = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(2048)
                  .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(b"test"))
    import pwd  # Unix only

    keychain = os.path.join(pwd.getpwuid(os.geteuid()).pw_dir,  # type: ignore[attr-defined,unused-ignore]
                             "Library", "Keychains", "login.keychain-db")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "identity.p12"
        path.write_bytes(pkcs12.serialize_key_and_certificates(b"test", key, certificate, None, encryption))
        subprocess.run(["/usr/bin/security", "import", str(path), "-k", keychain, "-P", "test", "-A"], check=True, capture_output=True)
    sha1 = certificate.fingerprint(hashes.SHA1()).hex().upper()
    try:
        yield subject
    finally:
        subprocess.run(["/usr/bin/security", "delete-identity", "-Z", sha1, keychain], check=True, capture_output=True)


def test_an_identity_signs_and_decrypts_through_the_security_framework(identity: str) -> None:
    options = CertificateOptions(mac_os=CertificateStoreOptions(StoreLocation.CURRENT_USER, subject=identity))
    with CertificateOptionsLoader().load(options) as loaded:
        assert loaded.key_location == "the macOS keychain"
        public = loaded.public_key()
        data = b"to sign"
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(loaded.sign(data, hashes.SHA256(), padding.PKCS1v15()), data, padding.PKCS1v15(), hashes.SHA256())
            pss = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)
            public.verify(loaded.sign(data, hashes.SHA256(), pss), data, pss, hashes.SHA256())
            with pytest.raises(UnsupportedCertificateError):
                loaded.sign(data, hashes.SHA256(), padding.PSS(padding.MGF1(hashes.SHA256()), 5))
            assert loaded.decrypt(public.encrypt(b"secret", padding.PKCS1v15()), padding.PKCS1v15()) == bytearray(b"secret")
            oaep = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            assert loaded.decrypt(public.encrypt(b"secret", oaep), oaep) == bytearray(b"secret")
        else:
            assert isinstance(public, ec.EllipticCurvePublicKey)
            public.verify(loaded.sign(data, hashes.SHA256()), data, ec.ECDSA(hashes.SHA256()))
        with pytest.raises(NativeProviderRequiredError):
            loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH)
