"""CertificateOptionsLoader and LoadedCertificate: choosing a store's certificate, reading files with
their password, and what the loaded certificate does with its key."""

from __future__ import annotations

import asyncio
import ssl
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from certificate_test_support import (
    NOW,
    PASSWORD,
    SUBJECT,
    FakePasswords,
    FakeStore,
    FakeStoreCertificate,
    ec_key,
    entry,
    fixture,
    fixture_certificate,
    handshake,
    loader,
    pem,
    pem_options,
    pfx_options,
    rsa_key,
    self_signed,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import pkcs12
from hkdfguard.abstractions import KeyNotFoundError, ObjectClosedError
from hkdfguard.options.certificate import (
    CertificateError,
    CertificateNotFoundError,
    CertificateNotValidNowError,
    CertificateOptions,
    CertificateOptionsValidationError,
    CertificateStoreOptions,
    InvalidCertificateFileError,
    LinuxOpenSslProviderOptions,
    LoadedCertificate,
    NativeProviderRequiredError,
    NoPasswordSourceError,
    NoPrivateKeyError,
    PasswordNotFoundError,
    StoreLocation,
    StoreName,
    UnsupportedCertificateError,
    WrongPasswordError,
)
from hkdfguard.options.certificate._private_files import leftover_directories


def windows(subject: str = SUBJECT, **kwargs: object) -> CertificateOptions:
    return CertificateOptions(windows=CertificateStoreOptions(subject=subject), **kwargs)  # type: ignore[arg-type]


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def pfx(tmp_path: Path, key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, certificate: x509.Certificate,
        chain: list[x509.Certificate] | None = None, secret: str | None = PASSWORD, name: str = "tls.pfx") -> Path:
    encryption = serialization.BestAvailableEncryption(secret.encode()) if secret else serialization.NoEncryption()
    return write(tmp_path, name, pkcs12.serialize_key_and_certificates(b"tls", key, certificate, chain, encryption))


def encrypted_key(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, secret: str = PASSWORD) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(secret.encode()))


def plain_key(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, form: serialization.PrivateFormat = serialization.PrivateFormat.PKCS8) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, form, serialization.NoEncryption())


def assert_signs(loaded: LoadedCertificate) -> None:
    """Signs every way the key's type does, and checks each signature with the certificate's public key."""
    public = loaded.public_key()
    data = b"to sign"
    if isinstance(public, rsa.RSAPublicKey):
        for algorithm in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512(), hashes.SHA1()):
            signature = loaded.sign(data, algorithm, padding.PKCS1v15())
            public.verify(signature, data, padding.PKCS1v15(), algorithm)
            for salt in (padding.PSS.DIGEST_LENGTH, padding.PSS.MAX_LENGTH, 20):
                pss = padding.PSS(padding.MGF1(algorithm), salt)
                public.verify(loaded.sign(data, algorithm, pss), data, padding.PSS(padding.MGF1(algorithm), padding.PSS.AUTO), algorithm)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        signature = loaded.sign(digest.finalize(), Prehashed(hashes.SHA256()), padding.PKCS1v15())
        public.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        ciphertext = public.encrypt(b"secret", padding.PKCS1v15())
        assert loaded.decrypt(ciphertext, padding.PKCS1v15()) == bytearray(b"secret")
        oaep = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), b"label")
        assert loaded.decrypt(public.encrypt(b"secret", oaep), oaep) == bytearray(b"secret")
        with pytest.raises(TypeError):
            loaded.sign(data, hashes.SHA256())
    else:
        for algorithm in (hashes.SHA256(), hashes.SHA384()):
            public.verify(loaded.sign(data, algorithm), data, ec.ECDSA(algorithm))
        with pytest.raises(TypeError):
            loaded.sign(data, hashes.SHA256(), padding.PKCS1v15())
        with pytest.raises(UnsupportedCertificateError):
            loaded.decrypt(b"x", padding.PKCS1v15())


# --- Stores ------------------------------------------------------------------------------------


def test_a_store_gives_the_certificate_valid_now_with_its_key_that_expires_last() -> None:
    expired = entry(-30, -1)
    not_yet = entry(1, 90)
    keyless_latest = entry(-1, 120, with_key=False)
    older = entry(-10, 30)
    chosen = entry(-5, 60)
    other_subject = entry(-1, 365, subject="CN=api.example.com, O=Fabrikam")
    store = FakeStore(expired, not_yet, keyless_latest, older, chosen, other_subject)

    loaded = loader(store=store).load(windows())
    assert loaded.certificate == chosen.certificate
    assert loaded.has_private_key
    assert loaded.chain == ()
    assert store.reads == [(StoreLocation.LOCAL_MACHINE, StoreName.MY)]
    assert all(c.closed for c in (expired, not_yet, keyless_latest, older, other_subject))
    assert not chosen.closed
    assert_signs(loaded)
    loaded.close()
    assert chosen.closed
    assert chosen.opened is not None and chosen.opened.closed
    with pytest.raises(ObjectClosedError):
        loaded.sign(b"x", hashes.SHA256(), padding.PKCS1v15())
    loaded.close()  # again


def test_a_store_ecdsa_key_signs_in_der() -> None:
    store = FakeStore(entry(-1, 30, key=ec_key()))
    with loader(store=store).load(windows()) as loaded:
        assert_signs(loaded)


def test_a_store_without_a_key_required_gives_the_newest_valid_one_and_trusts_it() -> None:
    keyless = entry(-1, 120, with_key=False)
    store = FakeStore(entry(-5, 60), keyless)
    loaded = loader(store=store).load(windows(require_private_key=False))
    assert loaded.certificate == keyless.certificate
    assert not loaded.has_private_key
    with pytest.raises(NoPrivateKeyError):
        loaded.sign(b"x", hashes.SHA256(), padding.PKCS1v15())
    context = loaded.create_ssl_context(ssl.Purpose.SERVER_AUTH)
    assert context.get_ca_certs(binary_form=True) == [keyless.der]


def test_a_stores_subject_is_compared_whole_ignoring_case() -> None:
    store = FakeStore(entry(-1, 30, subject="CN=api.example.com, O=Contoso"))
    assert loader(store=store).load(windows("cn=API.example.com; o=CONTOSO")).has_private_key
    with pytest.raises(CertificateNotFoundError, match="holds no certificate whose subject is 'CN=api'"):
        loader(store=store).load(windows("CN=api"))


def test_a_store_without_a_certificate_to_give_says_why() -> None:
    with pytest.raises(CertificateNotFoundError) as none:
        loader(store=FakeStore()).load(windows())
    assert str(none.value) == f"The LocalMachine My store holds no certificate whose subject is '{SUBJECT}'."
    store = FakeStore(entry(-30, -1), entry(-1, 30, with_key=False))
    with pytest.raises(CertificateNotFoundError) as unusable:
        loader(store=store).load(windows())
    assert str(unusable.value) == (f"The LocalMachine My store's 2 certificate(s) whose subject is '{SUBJECT}' are all expired, not yet valid, "
                                   "or without a private key.")
    with pytest.raises(CertificateNotFoundError, match="are all expired or not yet valid"):
        loader(store=FakeStore(entry(-30, -1))).load(windows(require_private_key=False))
    assert isinstance(unusable.value, LookupError)


def test_a_macos_keychain_is_read_as_a_store() -> None:
    store = FakeStore(entry(-1, 30))
    options = CertificateOptions(mac_os=CertificateStoreOptions(StoreLocation.CURRENT_USER, subject=SUBJECT))
    loaded = loader(platform="macos", store=store).load(options)
    assert store.reads == [(StoreLocation.CURRENT_USER, StoreName.MY)]
    assert loaded.key_location == "the macOS keychain"


def test_a_store_key_that_wont_open_is_reported_naming_the_certificate() -> None:
    failing = FakeStoreCertificate(self_signed(rsa_key()), rsa_key(), key_fails=NoPrivateKeyError("CNG says no."))
    with pytest.raises(NoPrivateKeyError, match=r"The certificate 'CN=api.example.com, O=Contoso' in the LocalMachine My store: CNG says no\."):
        loader(store=FakeStore(failing)).load(windows())
    assert failing.closed


def test_a_store_that_fails_to_read_is_reported() -> None:
    with pytest.raises(CertificateError, match="store is broken"):
        loader(store=FakeStore(failure=CertificateError("The store is broken."))).load(windows())


def test_a_store_key_cant_make_a_tls_context_without_the_native_provider() -> None:
    with loader(store=FakeStore(entry(-1, 30))).load(windows()) as loaded:
        with pytest.raises(NativeProviderRequiredError, match="native provider") as raised:
            loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH)
        assert isinstance(raised.value, UnsupportedCertificateError)


def test_close_waits_for_a_use_in_flight() -> None:
    started, release = threading.Event(), threading.Event()
    store_entry = entry(-1, 30)
    loaded = loader(store=FakeStore(store_entry)).load(windows())
    assert store_entry.opened is not None
    original = store_entry.opened.sign_digest

    def slow(*args: object) -> bytes:
        started.set()
        release.wait(5)
        return original(*args)  # type: ignore[arg-type]

    store_entry.opened.sign_digest = slow  # type: ignore[method-assign,assignment]
    signer = threading.Thread(target=loaded.sign, args=(b"x", hashes.SHA256(), padding.PKCS1v15()))
    signer.start()
    assert started.wait(5)
    closer = threading.Thread(target=loaded.close)
    closer.start()
    closer.join(0.2)
    assert closer.is_alive(), "close didn't wait for the signature in flight"
    release.set()
    signer.join(5)
    closer.join(5)
    assert loaded.closed and store_entry.opened.closed


# --- PKCS#12 -----------------------------------------------------------------------------------


def test_a_pfx_is_opened_with_its_password_from_the_password_source_and_serves_tls(tmp_path: Path) -> None:
    certificate = self_signed(rsa_key())
    passwords = FakePasswords()
    with loader(passwords).load(pfx_options(pfx(tmp_path, rsa_key(), certificate))) as loaded:
        assert loaded.certificate == certificate
        assert loaded.der == certificate.public_bytes(serialization.Encoding.DER)
        assert loaded.key_location == "a key file"
        assert_signs(loaded)
        server = loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH)
        client = ssl.create_default_context(cadata=pem(certificate).decode())
        assert handshake(server, client) == loaded.der
    assert leftover_directories() == []


def test_the_password_is_zeroed_once_the_key_is_read(tmp_path: Path) -> None:
    passwords = FakePasswords()
    loader(passwords).load(pfx_options(pfx(tmp_path, rsa_key(), self_signed(rsa_key())))).close()
    assert len(passwords.buffers) == 1
    assert not any(passwords.buffers[0])


def test_an_openssl_and_a_dotnet_pfx_load_through_the_loader_and_serve_tls() -> None:
    leaf = fixture_certificate("rsa.crt")
    now = leaf.not_valid_before_utc + timedelta(hours=1)
    for name in ("openssl-aes.pfx", "openssl-3des.pfx", "dotnet-default.pfx", "dotnet-aes.pfx"):
        with loader(FakePasswords(), now=now).load(pfx_options(fixture(name))) as loaded:
            assert loaded.certificate == leaf
            assert_signs(loaded)
            client = ssl.create_default_context(cadata=pem(leaf).decode())
            client.check_hostname = False  # the fixtures name no DNS name
            handshake(loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH), client)


def test_a_wrong_password_is_refused(tmp_path: Path) -> None:
    path = pfx(tmp_path, rsa_key(), self_signed(rsa_key()))
    with pytest.raises(WrongPasswordError):
        loader(FakePasswords({"tls-password": "wrong"})).load(pfx_options(path))


def test_a_missing_password_or_no_password_source_is_refused(tmp_path: Path) -> None:
    path = pfx(tmp_path, rsa_key(), self_signed(rsa_key()))
    with pytest.raises(PasswordNotFoundError, match="no secret named 'other'") as missing:
        loader(FakePasswords()).load(pfx_options(path, "other"))
    assert isinstance(missing.value, KeyNotFoundError)
    with pytest.raises(NoPasswordSourceError):
        loader(None).load(pfx_options(path))


def test_a_password_source_failure_is_reported(tmp_path: Path) -> None:
    passwords = FakePasswords()
    passwords.failure = ConnectionError("the vault is down")
    with pytest.raises(ConnectionError, match="the vault is down"):
        loader(passwords).load(pfx_options(pfx(tmp_path, rsa_key(), self_signed(rsa_key()))))


def test_an_unprotected_pfx_is_opened_when_allowed() -> None:
    leaf = fixture_certificate("rsa.crt")
    now = leaf.not_valid_before_utc + timedelta(hours=1)
    for name in ("openssl-nopass.pfx", "dotnet-nopassword.pfx"):
        with loader(None, now=now).load(pfx_options(fixture(name), None, allow_unprotected=True)) as loaded:
            assert loaded.has_private_key
            assert_signs(loaded)


def test_a_pfx_needs_its_password_even_for_the_certificate_alone(tmp_path: Path) -> None:
    path = pfx(tmp_path, rsa_key(), self_signed(rsa_key()))
    passwords = FakePasswords()
    with loader(passwords).load(pfx_options(path, require_private_key=False)) as loaded:
        assert loaded.certificate is not None
    assert len(passwords.buffers) == 1


def test_a_pfx_chain_keeps_its_other_certificates_after_the_one_with_the_key(tmp_path: Path) -> None:
    leaf = self_signed(rsa_key(), "CN=api.example.com")
    issuer = self_signed(rsa_key(1), "CN=Contoso CA")
    with loader(FakePasswords()).load(pfx_options(pfx(tmp_path, rsa_key(), leaf, [issuer]))) as loaded:
        assert loaded.certificate == leaf
        assert loaded.chain == (issuer,)


def test_a_legacy_rc2_pfx_is_refused_through_the_loader() -> None:
    now = fixture_certificate("rsa.crt").not_valid_before_utc + timedelta(hours=1)
    with pytest.raises(UnsupportedCertificateError, match="re-export it with AES"):
        loader(FakePasswords(), now=now).load(pfx_options(fixture("openssl-rc2.pfx")))


# --- PEM ---------------------------------------------------------------------------------------


def test_a_pem_certificate_with_an_encrypted_key_is_opened_with_its_password(tmp_path: Path) -> None:
    for key in (rsa_key(), ec_key()):
        certificate = self_signed(key)
        issuer = self_signed(rsa_key(1), "CN=Contoso CA")
        # The certificate is the one whose key it is, wherever it is in the file.
        cert_path = write(tmp_path, "tls.crt", pem(issuer, certificate))
        key_path = write(tmp_path, "tls.key", encrypted_key(key))
        passwords = FakePasswords()
        with loader(passwords).load(pem_options(cert_path, key_path)) as loaded:
            assert loaded.certificate == certificate
            assert loaded.chain == (issuer,)
            assert_signs(loaded)
            client = ssl.create_default_context(cadata=pem(certificate).decode())
            handshake(loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH), client)
        assert not any(passwords.buffers[0])


def test_the_fixtures_encrypted_pkcs8_keys_load_beside_their_certificates() -> None:
    for key, certificate in (("rsa-encrypted.key", "rsa.crt"), ("ec-encrypted.key", "ec.crt"), ("dotnet-encrypted.key", "rsa.crt")):
        leaf = fixture_certificate(certificate)
        with loader(FakePasswords(), now=leaf.not_valid_before_utc + timedelta(hours=1)).load(
                pem_options(fixture(certificate), fixture(key))) as loaded:
            assert loaded.certificate == leaf
            assert_signs(loaded)


def test_a_pem_key_encrypted_or_not_must_be_what_the_password_says(tmp_path: Path) -> None:
    cert_path = write(tmp_path, "tls.crt", pem(self_signed(rsa_key())))
    plain = write(tmp_path, "plain.key", plain_key(rsa_key()))
    encrypted = write(tmp_path, "encrypted.key", encrypted_key(rsa_key()))
    with pytest.raises(InvalidCertificateFileError, match="isn't encrypted"):
        loader(FakePasswords()).load(pem_options(cert_path, plain))
    with pytest.raises(InvalidCertificateFileError, match="is encrypted"):
        loader(None).load(pem_options(cert_path, encrypted, None, allow_unprotected=True))
    with pytest.raises(WrongPasswordError):
        loader(FakePasswords({"tls-password": "wrong"})).load(pem_options(cert_path, encrypted))


def test_a_pem_certificate_with_a_plain_key_is_opened_when_allowed(tmp_path: Path) -> None:
    forms: list[tuple[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, serialization.PrivateFormat]] = [
        (rsa_key(), serialization.PrivateFormat.PKCS8), (rsa_key(), serialization.PrivateFormat.TraditionalOpenSSL),
             (ec_key(), serialization.PrivateFormat.TraditionalOpenSSL)]
    for key, form in forms:
        certificate = self_signed(key)
        cert_path = write(tmp_path, "tls.crt", pem(certificate))
        key_path = write(tmp_path, "tls.key", plain_key(key, form))
        with loader(None).load(pem_options(cert_path, key_path, None, allow_unprotected=True)) as loaded:
            assert loaded.key_location == "an unprotected key file"
            assert_signs(loaded)
            handshake(loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH), ssl.create_default_context(cadata=pem(certificate).decode()))


def test_a_plain_key_file_replaced_after_loading_changes_nothing(tmp_path: Path) -> None:
    # Read once and checked against the certificate when loaded, then held: a file swapped in afterwards
    # never becomes the key the certificate signs with.
    key, other = rsa_key(0), rsa_key(1)
    certificate = self_signed(key)
    cert_path = write(tmp_path, "tls.crt", pem(certificate))
    key_path = write(tmp_path, "tls.key", plain_key(key))
    with loader(None).load(pem_options(cert_path, key_path, None, allow_unprotected=True)) as loaded:
        key_path.write_bytes(plain_key(other))
        signature = loaded.sign(b"to sign", hashes.SHA256(), padding.PKCS1v15())
        key.public_key().verify(signature, b"to sign", padding.PKCS1v15(), hashes.SHA256())  # the certificate's key, not the swapped one
        handshake(loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH), ssl.create_default_context(cadata=pem(certificate).decode()))


def test_a_pem_key_for_no_certificate_in_the_file_is_refused(tmp_path: Path) -> None:
    cert_path = write(tmp_path, "tls.crt", pem(self_signed(rsa_key())))
    key_path = write(tmp_path, "other.key", encrypted_key(rsa_key(1)))
    with pytest.raises(InvalidCertificateFileError, match="is the key's"):
        loader(FakePasswords()).load(pem_options(cert_path, key_path))
    plain = write(tmp_path, "other-plain.key", plain_key(rsa_key(1)))
    with pytest.raises(InvalidCertificateFileError, match="is the key's"):
        loader(None).load(pem_options(cert_path, plain, None, allow_unprotected=True))


def test_a_pem_or_der_certificate_alone_needs_no_key_or_password(tmp_path: Path) -> None:
    certificate = self_signed(ec_key())
    for data in (pem(certificate), certificate.public_bytes(serialization.Encoding.DER)):
        path = write(tmp_path, "alone.crt", data)
        passwords = FakePasswords()
        with loader(passwords).load(pem_options(path, None, None, require_private_key=False)) as loaded:
            assert loaded.certificate == certificate
            assert not loaded.has_private_key
        assert passwords.buffers == []


def test_a_file_certificate_not_valid_now_or_without_its_key_is_refused(tmp_path: Path) -> None:
    expired = self_signed(rsa_key(), not_before_days=-30, not_after_days=-1)
    with pytest.raises(CertificateNotValidNowError, match=r"is valid from 2026-10-04 12:00:00Z to 2026-11-02 12:00:00Z, not now"):
        loader(FakePasswords()).load(pfx_options(pfx(tmp_path, rsa_key(), expired)))
    keyless = write(tmp_path, "keyless.pfx", pkcs12.serialize_key_and_certificates(
        b"x", None, None, [self_signed(rsa_key())], serialization.BestAvailableEncryption(PASSWORD.encode())))
    with pytest.raises(NoPrivateKeyError, match="has no private key"):
        loader(FakePasswords()).load(pfx_options(keyless))
    assert leftover_directories() == []


def test_a_missing_or_broken_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        loader(FakePasswords()).load(pfx_options(tmp_path / "missing.pfx"))
    with pytest.raises(InvalidCertificateFileError):
        loader(FakePasswords()).load(pfx_options(write(tmp_path, "broken.pfx", b"\x30\x03\x02\x01\x03")))
    with pytest.raises(InvalidCertificateFileError, match="holds no CERTIFICATE"):
        loader(None).load(pem_options(write(tmp_path, "none.crt", b"-----BEGIN JUNK-----\nAAAA\n-----END JUNK-----\n"), None, None,
                                      require_private_key=False))


# --- Linux, and options ------------------------------------------------------------------------


def test_a_linux_certificate_alone_is_read_from_its_file(tmp_path: Path) -> None:
    certificate = self_signed(ec_key())
    path = write(tmp_path, "tls.crt", pem(certificate))
    options = CertificateOptions(linux=LinuxOpenSslProviderOptions(certificate_file=str(path)), require_private_key=False)
    with loader(platform="linux").load(options) as loaded:
        assert loaded.certificate == certificate
        assert not loaded.has_private_key


def test_invalid_options_are_refused_before_anything_is_opened() -> None:
    store = FakeStore(entry(-1, 30))
    with pytest.raises(CertificateOptionsValidationError) as raised:
        loader(store=store, platform="linux").load(windows(), "tls")
    assert raised.value.name == "tls"
    assert store.reads == []


def test_load_async_reads_the_password_without_blocking(tmp_path: Path) -> None:
    passwords = FakePasswords()
    path = pfx(tmp_path, rsa_key(), self_signed(rsa_key()))
    loaded = asyncio.run(loader(passwords).load_async(pfx_options(path)))
    with loaded:
        assert loaded.has_private_key
    assert not any(passwords.buffers[0])
    with pytest.raises(PasswordNotFoundError):
        asyncio.run(loader(passwords).load_async(pfx_options(path, "other")))


def test_a_closed_file_key_is_wiped_and_refuses_every_use(tmp_path: Path) -> None:
    loaded = loader(FakePasswords()).load(pfx_options(pfx(tmp_path, rsa_key(), self_signed(rsa_key()))))
    source = loaded._key
    loaded.close()
    assert source is not None
    assert not any(source._password) and not any(source._encrypted)  # type: ignore[attr-defined]
    for use in (lambda: loaded.sign(b"x", hashes.SHA256(), padding.PKCS1v15()), lambda: loaded.decrypt(b"x", padding.PKCS1v15()),
                lambda: loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH)):
        with pytest.raises(ObjectClosedError):
            use()
    assert repr(loaded) == "LoadedCertificate(subject='CN=api.example.com, O=Contoso', has_private_key=True)"
    assert NOW.tzinfo is not None


def test_the_private_directory_is_the_accounts_alone_and_is_removed() -> None:
    import os
    import stat
    import subprocess
    import sys

    from hkdfguard.options.certificate._private_files import private_directory

    with private_directory() as directory:
        path = directory.write("key.pem", b"ciphertext")
        if sys.platform == "win32":
            from hkdfguard.options.certificate._win32 import current_user_sid

            listing = subprocess.run(["icacls", directory.path], capture_output=True, text=True, check=True).stdout
            entries = [line.strip() for line in listing.splitlines()[:-1] if line.strip()]
            # One entry, not inherited: the account itself, full control, inherited by what is made in it.
            assert len(entries) == 1, listing
            assert "(OI)(CI)(F)" in entries[0] and "(I)" not in entries[0], listing
            assert current_user_sid().startswith("S-1-5-")
            file_listing = subprocess.run(["icacls", path], capture_output=True, text=True, check=True).stdout
            assert len([line for line in file_listing.splitlines()[:-1] if line.strip()]) == 1, file_listing
        else:
            assert stat.S_IMODE(os.stat(directory.path).st_mode) == 0o700
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert not os.path.exists(directory.path)
    assert leftover_directories() == []
