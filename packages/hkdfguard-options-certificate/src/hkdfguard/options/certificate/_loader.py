"""CertificateOptionsLoader: opens the certificate a validated CertificateOptions describes."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from hkdfguard.abstractions import ArrayUtility, ProtectedReadOnlyCache
from hkdfguard.options.certificate import _files, _pbe, _pkcs12
from hkdfguard.options.certificate._dn import DistinguishedName, describe
from hkdfguard.options.certificate._errors import (
    CertificateError,
    CertificateNotFoundError,
    CertificateNotValidNowError,
    CertificateOptionsValidationError,
    InvalidCertificateFileError,
    NoPasswordSourceError,
    NoPrivateKeyError,
    PasswordNotFoundError,
)
from hkdfguard.options.certificate._keys import OsKey
from hkdfguard.options.certificate._loaded import (
    EncryptedKeySource,
    LoadedCertificate,
    OsKeySource,
    PlainKeyFileSource,
    ProviderKeySource,
    _KeySource,
)
from hkdfguard.options.certificate._openssl_provider import pkcs11_uri_pem
from hkdfguard.options.certificate._options import (
    CertificateFileFormat,
    CertificateFileOptions,
    CertificateOptions,
    CertificateStoreOptions,
    LinuxOpenSslProviderOptions,
    StoreLocation,
    StoreName,
)
from hkdfguard.options.certificate._validator import CertificateOptionsValidator


class StoreCertificate(Protocol):
    """One certificate a store read gave, holding whatever native handle reaches it until closed."""

    certificate: x509.Certificate
    der: bytes
    has_private_key: bool

    def open_private_key(self) -> OsKey:
        """Opens the certificate's private key where the store keeps it; it is never exported."""
        ...

    def close(self) -> None:
        """Releases the native handle to the certificate."""
        ...


type StoreReader = Callable[[StoreLocation, StoreName], Sequence[StoreCertificate]]
"""Reads every certificate in a store, read-only; a store that doesn't exist reads as empty."""


def read_store(location: StoreLocation, name: StoreName) -> Sequence[StoreCertificate]:
    """The operating system's own store: Windows' certificate stores, or macOS' keychains."""
    if sys.platform == "win32":
        from hkdfguard.options.certificate import _windows_store  # noqa: PLC0415

        return _windows_store.read_store(location, name)
    if sys.platform == "darwin":
        from hkdfguard.options.certificate import _macos_keychain  # noqa: PLC0415

        return _macos_keychain.read_store(location, name)
    from hkdfguard.options.certificate._errors import UnsupportedCertificateError  # noqa: PLC0415

    raise UnsupportedCertificateError(f"There is no certificate store to read on {sys.platform}.")


class CertificateOptionsLoader:
    """Opens the certificate a validated :class:`CertificateOptions` describes, as a
    :class:`LoadedCertificate` the caller owns, and closes.

    * A store (:attr:`~CertificateOptions.windows`, :attr:`~CertificateOptions.mac_os`) is opened
      read-only, and of the certificates whose subject is the one named, the one valid now - with its
      private key, when one is required - that expires last is returned; every other is released.
      The key stays where the store keeps it, and every use of it is a call into the store.
    * A Linux OpenSSL provider key (:attr:`~CertificateOptions.linux`) is checked by loading it
      through the provider into a TLS context once, and then reached the same way by each
      :meth:`LoadedCertificate.create_ssl_context`; it never enters the process.
    * A file (:attr:`~CertificateOptions.file`) is read with its password, which is decrypted from
      the password source into a ``bytearray`` only while the key is read, and zeroed at once; it is
      never a ``str``. The key is decrypted into a buffer of its own, re-encrypted under a random
      throwaway password at once, and that buffer zeroed: it is held encrypted from then on.

    Whatever the source, a certificate that isn't valid now, or that has no private key when one is
    required, is refused. Safe for concurrent use.
    """

    def __init__(self, passwords: ProtectedReadOnlyCache | None = None, now: Callable[[], datetime] | None = None, *,
                 validator: CertificateOptionsValidator | None = None, store_reader: StoreReader | None = None) -> None:
        """
        :param passwords: where a file's password is read from, by
            :attr:`CertificateFileOptions.password_secret_name` - a ``FilePerSecretCache``, a remote
            secret cache, protected configuration. Needed only for a file with a password.
        :param now: the clock a certificate's validity is judged by (timezone-aware); ``None`` for
            the system's
        :param validator: the validator, for tests; ``None`` for this platform's
        :param store_reader: reads a store's certificates, for tests; ``None`` for the operating
            system's own
        """
        self._passwords = passwords
        self._now = now or (lambda: datetime.now(UTC))
        self._validator = validator or CertificateOptionsValidator()
        self._read_store: StoreReader = store_reader or read_store

    def load(self, options: CertificateOptions, name: str | None = None) -> LoadedCertificate:
        """Opens the certificate ``options`` describes, reading a file's password synchronously -
        blocking, for a remote password source, until it answers.

        :param options: describes the certificate to open; validated before anything is opened
        :param name: the options' name, for named options; only reported in a validation failure
        :raises CertificateOptionsValidationError: the options aren't valid on this operating system
        :raises CertificateNotFoundError: a store holds no certificate valid now (with its key, when required)
        :raises CertificateNotValidNowError: a file's certificate isn't valid now
        :raises NoPrivateKeyError: the certificate has no private key, or it can't be opened, and one is required
        :raises NoPasswordSourceError: a password is needed and the loader has no password source
        :raises PasswordNotFoundError: the password source holds no secret by the name given
        :raises InvalidCertificateFileError: a file isn't a certificate or key
        :raises WrongPasswordError: the password doesn't open the key file
        :raises UnsupportedCertificateError: what this port can't open
        :raises OSError: a file can't be read
        """
        self._validate(options, name)
        password_name = self._password_name(options)
        if password_name is None:
            return self._open(options, None)
        passwords = self._password_source()
        length = passwords.find_max_decrypted_length(password_name)
        if not length:
            raise PasswordNotFoundError(f"The password source holds no secret named '{password_name}'.")
        password = bytearray(length)
        try:
            written = passwords.decrypt(password_name, password)
            return self._open_with(options, password, written, password_name)
        finally:
            ArrayUtility.zero_memory(password)

    async def load_async(self, options: CertificateOptions, name: str | None = None) -> LoadedCertificate:
        """As :meth:`load`, reading a file's password without blocking the event loop. Reading the
        files themselves and decrypting the key happen on the calling thread, as in .NET."""
        self._validate(options, name)
        password_name = self._password_name(options)
        if password_name is None:
            return self._open(options, None)
        passwords = self._password_source()
        length = await passwords.find_max_decrypted_length_async(password_name)
        if not length:
            raise PasswordNotFoundError(f"The password source holds no secret named '{password_name}'.")
        password = bytearray(length)
        try:
            written = await passwords.decrypt_async(password_name, password)
            return self._open_with(options, password, written, password_name)
        finally:
            ArrayUtility.zero_memory(password)

    def _validate(self, options: CertificateOptions, name: str | None) -> None:
        failures = self._validator.validate(options)
        if failures:
            raise CertificateOptionsValidationError(failures, name)

    @staticmethod
    def _password_name(options: CertificateOptions) -> str | None:
        # A PKCS#12 file needs its password even for the certificate alone; a PEM certificate without
        # its key needs none.
        file = options.file
        if file is None or (file.format != CertificateFileFormat.PKCS12 and not options.require_private_key):
            return None
        return file.password_secret_name

    def _password_source(self) -> ProtectedReadOnlyCache:
        if self._passwords is None:
            raise NoPasswordSourceError("The certificate's key file has a password, but the loader was given no password source to read it from.")
        return self._passwords

    def _open_with(self, options: CertificateOptions, password: bytearray, written: int, password_name: str) -> LoadedCertificate:
        if written == 0:
            raise PasswordNotFoundError(f"The password source holds no secret named '{password_name}'.")
        if written == len(password):
            return self._open(options, password)
        # A view would do, but the readers take a bytearray: copy the password into one of its own length, wiped too.
        exact = bytearray(written)
        try:
            exact[:] = memoryview(password)[:written]
            return self._open(options, exact)
        finally:
            ArrayUtility.zero_memory(exact)

    def _open(self, options: CertificateOptions, password: bytearray | None) -> LoadedCertificate:
        if options.windows is not None:
            loaded = self._from_store(options.windows, options.require_private_key, "the Windows certificate store")
        elif options.mac_os is not None:
            loaded = self._from_store(options.mac_os, options.require_private_key, "the macOS keychain")
        elif options.linux is not None:
            loaded = self._from_provider(options.linux, options.require_private_key)
        else:
            assert options.file is not None
            loaded = self._from_file(options.file, options.require_private_key, password)
        try:
            subject = describe(loaded.certificate.subject)
            if options.require_private_key and not loaded.has_private_key:
                raise NoPrivateKeyError(f"The certificate '{subject}' has no private key.")
            if not self._is_valid_now(loaded.certificate):
                raise CertificateNotValidNowError(f"The certificate '{subject}' is valid from {_universal(loaded.certificate.not_valid_before_utc)} "
                                                  f"to {_universal(loaded.certificate.not_valid_after_utc)}, not now.")
            return loaded
        except BaseException:
            loaded.close()
            raise

    def _is_valid_now(self, certificate: x509.Certificate) -> bool:
        now = self._now()
        return certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc

    def _from_store(self, store: CertificateStoreOptions, require_private_key: bool, description: str) -> LoadedCertificate:
        location = StoreLocation(store.store_location)
        store_name = StoreName(store.store_name)
        assert store.subject is not None
        subject = DistinguishedName.parse(store.subject)
        found = list(self._read_store(location, store_name))
        chosen: StoreCertificate | None = None
        kept: StoreCertificate | None = None  # the one returned: every other is released
        try:
            # Compared decoded, as each certificate states its subject, so how either side spells its
            # string types doesn't matter; ignoring case, as distinguished names compare.
            named = 0
            for candidate in found:
                try:
                    if not DistinguishedName.of(candidate.certificate.subject).matches(subject):
                        continue
                except ValueError:
                    continue  # a subject that can't be decoded can't be the one named
                named += 1
                if not self._is_valid_now(candidate.certificate) or (require_private_key and not candidate.has_private_key):
                    continue
                if chosen is None or candidate.certificate.not_valid_after_utc > chosen.certificate.not_valid_after_utc:
                    chosen = candidate
            if chosen is None:
                if named == 0:
                    raise CertificateNotFoundError(f"The {location} {store_name} store holds no certificate whose subject is '{store.subject}'.")
                unusable = "expired, not yet valid, or without a private key" if require_private_key else "expired or not yet valid"
                raise CertificateNotFoundError(f"The {location} {store_name} store's {named} certificate(s) whose subject is '{store.subject}' "
                                               f"are all {unusable}.")

            key = None
            if require_private_key:
                try:
                    key = OsKeySource(chosen.open_private_key(), description)
                except CertificateError as error:
                    raise type(error)(f"The certificate '{describe(chosen.certificate.subject)}' in the {location} {store_name} store: {error}") from error
            kept = chosen
            return LoadedCertificate([chosen.certificate], key, [chosen])
        finally:
            for candidate in found:
                if candidate is not kept:
                    candidate.close()

    @staticmethod
    def _from_provider(linux: LinuxOpenSslProviderOptions, require_private_key: bool) -> LoadedCertificate:
        assert linux.certificate_file is not None
        certificates = _read_certificates(linux.certificate_file)
        if not require_private_key:
            return LoadedCertificate(certificates, None)
        assert linux.key_uri is not None
        if linux.key_uri.startswith("pkcs11:"):
            source = ProviderKeySource(linux.provider, None, pkcs11_uri_pem(linux.key_uri))
        else:
            source = ProviderKeySource(linux.provider, linux.key_uri.removeprefix("file:"), None)
        loaded = LoadedCertificate(certificates, source)
        try:
            # Opens the key through the provider once, now, so a key that isn't there - or isn't the
            # certificate's - is reported at load time, not at the first handshake.
            import ssl  # noqa: PLC0415

            loaded.create_ssl_context(ssl.Purpose.CLIENT_AUTH)
            return loaded
        except BaseException:
            loaded.close()
            raise

    @staticmethod
    def _from_file(file: CertificateFileOptions, require_private_key: bool, password: bytearray | None) -> LoadedCertificate:
        assert file.path is not None
        if file.format == CertificateFileFormat.PKCS12:
            return _from_pkcs12(file.path, password)
        certificates = _read_certificates(file.path)
        if not require_private_key:
            return LoadedCertificate(certificates, None)
        assert file.key_path is not None
        key_data = _files.read_file(file.key_path)
        try:
            if password is None:
                # Read once and held encrypted, as a protected key is. The PKCS#8 cryptography writes is
                # an immutable bytes no one can zero; an unprotected key file is for development only.
                key = _files.plain_pem_key(key_data, file.key_path)
                private_key_info = bytearray(key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))
                source: Callable[[bytearray], _KeySource] = PlainKeyFileSource
            else:
                private_key_info = _files.decrypt_pem_key(key_data, password, file.key_path)
                source = EncryptedKeySource
        finally:
            ArrayUtility.zero_memory(key_data)
        try:
            return _with_key(certificates, private_key_info, f"No certificate in '{file.path}' is the key's.", source)
        finally:
            ArrayUtility.zero_memory(private_key_info)


def _with_key(certificates: list[x509.Certificate], private_key_info: bytearray, mismatch: str,
              source: Callable[[bytearray], _KeySource] = EncryptedKeySource) -> LoadedCertificate:
    """The certificates, the key's first, with the key re-encrypted under a throwaway password."""
    public_key = _files.private_key_of(private_key_info).public_key()
    ordered = _files.leaf_first(certificates, public_key)
    if ordered is None:
        raise InvalidCertificateFileError(mismatch)
    return LoadedCertificate(ordered, source(private_key_info))


def _from_pkcs12(path: str, password: bytearray | None) -> LoadedCertificate:
    data = _files.read_file(path)
    try:
        contents = _pkcs12.decode(data, password)
    except BaseException:
        # The whole file: a key in the clear, if it holds one.
        _pbe.wipe(data)
        raise
    try:
        if not contents.certificates:
            raise InvalidCertificateFileError(f"The PKCS#12 file '{path}' holds no certificate.")
        # The certificate is the first that has its key, as .NET chooses it, or else the first; the
        # rest are its chain. Any other key is wiped.
        for key in contents.keys:
            try:
                public_key = _files.private_key_of(key).public_key()
            except InvalidCertificateFileError:
                continue
            ordered = _files.leaf_first(contents.certificates, public_key)
            if ordered is not None:
                return LoadedCertificate(ordered, EncryptedKeySource(key))
        return LoadedCertificate(contents.certificates, None)
    finally:
        contents.wipe()
        _pbe.wipe(data)


def _read_certificates(path: str) -> list[x509.Certificate]:
    data = _files.read_file(path)
    try:
        return _files.parse_certificates(data, path)
    finally:
        _pbe.wipe(data)


def _universal(moment: datetime) -> str:
    # .NET's "u" format, as its messages give a validity period.
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
