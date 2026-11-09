"""A Linux OpenSSL provider key: the key file Python's ssl module reads through the provider's
decoder, and - with HKDFGUARD_TEST_OPENSSL_PROVIDER=<provider>, HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI
and HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE set - a real TLS handshake through it, signed by the
TPM or the token. Run under a Python linked against the system's OpenSSL 3, with the provider's own
configuration (TPM2OPENSSL_TCTI, PKCS11_PROVIDER_MODULE...) in the environment."""

from __future__ import annotations

import base64
import os
import ssl
from pathlib import Path

import pytest
from certificate_test_support import ec_key, handshake, loader, pem, self_signed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from hkdfguard.options.certificate import (
    CertificateOptions,
    CertificateOptionsLoader,
    LinuxOpenSslProviderOptions,
    UnsupportedCertificateError,
    _der,
)
from hkdfguard.options.certificate._openssl_provider import pkcs11_uri_pem


def test_a_pkcs11_uri_is_written_as_pkcs11_providers_uri_pem() -> None:
    text = pkcs11_uri_pem("pkcs11:token=hkdfguard;object=tls;type=private").decode("ascii")
    assert text.startswith("-----BEGIN PKCS#11 PROVIDER URI-----\n")
    assert text.endswith("-----END PKCS#11 PROVIDER URI-----\n")
    body = base64.b64decode("".join(text.splitlines()[1:-1]))
    description, uri = _der.sequence(_der.read(body), "uri", 2, 2)
    assert (description.tag, bytes(description.contents)) == (0x1A, b"PKCS#11 Provider URI v1.0")
    assert (uri.tag, bytes(uri.contents)) == (_der.UTF8_STRING, b"pkcs11:token=hkdfguard;object=tls;type=private")


def test_a_provider_key_this_python_cant_reach_is_refused_at_load_time(tmp_path: Path) -> None:
    # On Windows and macOS there is no /proc/self/maps; a Linux Python with OpenSSL built in (as
    # python-build-standalone's is) has no shared libcrypto; a system Python without the provider, or
    # with this garbage key file, can't decode it: each is refused when the certificate is loaded.
    certificate = tmp_path / "tls.crt"
    certificate.write_bytes(pem(self_signed(ec_key())))
    key = tmp_path / "tls.key"
    key.write_bytes(b"-----BEGIN TSS2 PRIVATE KEY-----\nAAAA\n-----END TSS2 PRIVATE KEY-----\n")
    options = CertificateOptions(linux=LinuxOpenSslProviderOptions("tpm2", str(key), str(certificate)))
    with pytest.raises(UnsupportedCertificateError):
        loader(platform="linux").load(options)


def _real_options(require_private_key: bool = True) -> CertificateOptions:
    provider = os.environ.get("HKDFGUARD_TEST_OPENSSL_PROVIDER")
    if not provider:
        pytest.skip("set HKDFGUARD_TEST_OPENSSL_PROVIDER, HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI and "
                    "HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE to reach a real provider key")
    return CertificateOptions(linux=LinuxOpenSslProviderOptions(provider, os.environ["HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI"],
                                                                os.environ["HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE"]),
                              require_private_key=require_private_key)


def test_a_real_provider_key_serves_a_tls_handshake() -> None:
    with CertificateOptionsLoader().load(_real_options()) as loaded:
        assert loaded.has_private_key
        assert loaded.key_location == f"the OpenSSL provider '{os.environ['HKDFGUARD_TEST_OPENSSL_PROVIDER']}'"
        with CertificateOptionsLoader().load(_real_options(require_private_key=False)) as trusted:
            client = trusted.create_ssl_context(ssl.Purpose.SERVER_AUTH)
        client.check_hostname = False  # the test certificate names whatever the provisioning script gave it
        for _ in range(2):  # each context opens the key through the provider again
            assert handshake(loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH), client, None) == loaded.der
        with pytest.raises(UnsupportedCertificateError, match="create_ssl_context"):
            loaded.sign(b"x", hashes.SHA256(), padding.PKCS1v15())
