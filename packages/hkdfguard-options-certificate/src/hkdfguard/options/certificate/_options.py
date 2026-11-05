"""Where one certificate is opened from, as plain data: the .NET port's CertificateOptions, read
from the same configuration keys."""

from __future__ import annotations

import enum
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Self

_INTEGER: re.Pattern[str] = re.compile(r"[+-]?\d+")


class StoreLocation(enum.StrEnum):
    """Which certificate store location a :class:`CertificateStoreOptions` opens, as .NET names them."""

    CURRENT_USER = "CurrentUser"
    """The store of the account the process runs as: on macOS, its login keychain."""

    LOCAL_MACHINE = "LocalMachine"
    """The machine's store, the default: on macOS, the System keychain."""


class StoreName(enum.StrEnum):
    """Which store at a :class:`StoreLocation` a :class:`CertificateStoreOptions` opens - every name
    of .NET's ``StoreName``, so the same configuration binds."""

    ADDRESS_BOOK = "AddressBook"
    """Other users' certificates."""

    AUTH_ROOT = "AuthRoot"
    """Third-party certification authorities."""

    CERTIFICATE_AUTHORITY = "CertificateAuthority"
    """Intermediate certification authorities (the Windows system store "CA")."""

    DISALLOWED = "Disallowed"
    """Revoked certificates."""

    MY = "My"
    """Personal certificates, with their private keys; the default."""

    ROOT = "Root"
    """Trusted root certification authorities."""

    TRUSTED_PEOPLE = "TrustedPeople"
    """Directly trusted people and resources."""

    TRUSTED_PUBLISHER = "TrustedPublisher"
    """Directly trusted publishers."""


class CertificateFileFormat(enum.StrEnum):
    """The format of a certificate file."""

    PKCS12 = "Pkcs12"
    """A PKCS#12 (.pfx/.p12) file holding the certificate and its key; the default."""

    PEM = "Pem"
    """A PEM certificate, with its key in :attr:`CertificateFileOptions.key_path` as encrypted PKCS#8."""


# .NET's enum values, as configuration may give them by number.
_STORE_LOCATION_NUMBERS: dict[int, StoreLocation] = {1: StoreLocation.CURRENT_USER, 2: StoreLocation.LOCAL_MACHINE}
_STORE_NAME_NUMBERS: dict[int, StoreName] = {number: name for number, name in enumerate(StoreName, start=1)}
_FORMAT_NUMBERS: dict[int, CertificateFileFormat] = {0: CertificateFileFormat.PKCS12, 1: CertificateFileFormat.PEM}


@dataclass
class CertificateStoreOptions:
    """A certificate in an operating system certificate store, found by its subject, so a renewed
    certificate an administrator adds under the same subject is picked up with no change to
    configuration. Of the certificates with that subject, the one opened is the one valid now - and
    with its private key, when one is required - that expires last; an expired or not-yet-valid one
    is never chosen. Its private key stays in the store: CNG (or the TPM) on Windows, the keychain on
    macOS, where CurrentUser is the login keychain and LocalMachine the System keychain.

    Matching by subject trusts whoever can add a certificate to the store to choose it: keep it to a
    store only administrators can write, such as LocalMachine's My.
    """

    store_location: StoreLocation | str = StoreLocation.LOCAL_MACHINE
    """Which store location to open. A string that isn't a location is kept as it is, for the
    validator to refuse."""

    store_name: StoreName | str = StoreName.MY
    """Which store to open; My (Personal) by default. On macOS only My - the keychain itself - can be
    read."""

    subject: str | None = None
    """The certificate's subject distinguished name, as the certificate states it:
    ``"CN=api.example.com, O=Contoso"``. Compared to each certificate's whole subject, decoded,
    ignoring case - never as a substring, so ``"CN=api"`` doesn't match ``"CN=api.example.com"``."""


@dataclass
class LinuxOpenSslProviderOptions:
    """A certificate on Linux whose private key is opened through an OpenSSL 3 provider - ``tpm2``
    for a key in the TPM, or ``pkcs11`` for a hardware token - so the key never leaves it, beside
    the certificate itself as a PEM file, which holds nothing secret.

    Python's ``ssl`` module reads the key through the provider's own decoder, which takes a key
    file, not a URI: :attr:`key_uri` is a ``pkcs11:`` URI (written for the provider into a private
    temporary file as a ``PKCS#11 PROVIDER URI`` PEM) or the absolute path of a PEM key file the
    provider decodes - a ``TSS2 PRIVATE KEY`` for tpm2. A persistent TPM handle
    (``handle:0x81000001``) has no such file, and is refused.
    """

    provider: str = "tpm2"
    """The OpenSSL provider that holds the key: ``"tpm2"`` (the default) or ``"pkcs11"``."""

    key_uri: str | None = None
    """The key, as the provider names it: a ``pkcs11:`` URI, or the path to a TPM key blob."""

    certificate_file: str | None = None
    """The certificate, PEM- or DER-encoded, without its key; absolute."""


@dataclass
class CertificateFileOptions:
    """A certificate and its key read from files, by absolute paths. The key must be protected by a
    password - a password-protected PKCS#12 file, or an encrypted PKCS#8 PEM key - and the password
    comes from the secret :attr:`password_secret_name` names, never from configuration. An
    unprotected key file is refused unless :attr:`allow_unprotected_private_key` is set."""

    path: str | None = None
    """The certificate file - PKCS#12, or a PEM certificate."""

    format: CertificateFileFormat | str = CertificateFileFormat.PKCS12
    """The file's format; PKCS#12 by default."""

    key_path: str | None = None
    """The PEM private key file, for :attr:`CertificateFileFormat.PEM`; ignored for PKCS#12."""

    password_secret_name: str | None = None
    """The name of the secret holding the key's password, as a protected secret source - a
    ``FilePerSecretCache``, a remote secret cache, protected configuration - is asked for it. The
    password is decrypted only while the key is read, into a buffer zeroed straight after."""

    allow_unprotected_private_key: bool = False
    """Accepts a key file with no password - a PKCS#12 file without one, or a plain PEM key - whose
    private key is then plaintext on disk, protected only by file permissions. Set it only for
    development."""


@dataclass
class CertificateOptions:
    """Plain-data description of where one certificate - with its private key - is opened from:
    exactly one of the operating system's own protected key storage (:attr:`windows`,
    :attr:`mac_os`, :attr:`linux`) or a key file on the filesystem (:attr:`file`). It carries no
    behavior and never a password: a file's password is named here, and read at load time from a
    protected secret source, so it is never plaintext on disk or in configuration.

    The configuration keys are the .NET port's, so the same ``appsettings.json`` section binds::

        "Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
        "Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } }
        "Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=t;object=k", "CertificateFile": "/etc/myapp/tls.crt" } }
        "Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }

    Validate it with :meth:`validate` or :class:`CertificateOptionsValidator`;
    :meth:`CertificateOptionsLoader.load` validates it too.
    """

    windows: CertificateStoreOptions | None = None
    """A certificate in a Windows certificate store, its key held by CNG."""

    mac_os: CertificateStoreOptions | None = None
    """A certificate in a macOS keychain, its key held by the keychain."""

    linux: LinuxOpenSslProviderOptions | None = None
    """A certificate whose key an OpenSSL 3 provider holds on Linux - the TPM, say."""

    file: CertificateFileOptions | None = None
    """A certificate and key read from files, the key protected by a password."""

    require_private_key: bool = True
    """Whether the certificate must come with its private key: true (the default) for one presented
    as a TLS server or client certificate, or used to sign; false for one only to be trusted."""

    @classmethod
    def from_mapping(cls, settings: Mapping[str, object]) -> Self:
        """Reads options from a parsed configuration section - a dict from JSON, TOML or YAML.

        Keys match a field ignoring case and underscores, so a .NET ``appsettings.json`` section
        (``"MacOS"``, ``"StoreLocation"``, ``"KeyUri"``, ``"PasswordSecretName"``) and snake_case
        (``"mac_os"``, ``"key_uri"``) both read. An enum is matched ignoring case, or by .NET's
        number for it; one that is neither is kept as given for the validator to report. Booleans may
        be given as strings, as an INI file or environment variable supplies them. A ``None`` value
        leaves its field unset. The result is not validated: call :meth:`validate` or
        :meth:`require_valid`, or let the loader do it.

        :raises TypeError: ``settings`` or a section in it is not a mapping
        :raises ValueError: an unknown key (a likely typo, never silently ignored), a key given
            twice, or a value of the wrong type
        """
        reader = _Reader(settings, "settings", ("windows", "mac_os", "linux", "file", "require_private_key"))
        require_private_key = reader.read("require_private_key", _boolean)
        return cls(
            windows=reader.read("windows", _store),
            mac_os=reader.read("mac_os", _store),
            linux=reader.read("linux", _linux),
            file=reader.read("file", _file),
            require_private_key=True if require_private_key is None else require_private_key,
        )

    def validate(self) -> list[str]:
        """Checks these options for the operating system the process runs on, as
        :class:`CertificateOptionsValidator` does.

        :returns: every failure, or an empty list if these options are valid
        """
        from hkdfguard.options.certificate._validator import CertificateOptionsValidator  # noqa: PLC0415  (the validator imports this module)

        return CertificateOptionsValidator().validate(self)

    def require_valid(self, name: str | None = None) -> Self:
        """:returns: these same options
        :raises CertificateOptionsValidationError: any rule is broken; it lists every failure
        """
        from hkdfguard.options.certificate._errors import CertificateOptionsValidationError  # noqa: PLC0415

        failures = self.validate()
        if failures:
            raise CertificateOptionsValidationError(failures, name)
        return self


# --- Reading configuration -------------------------------------------------------------------


def _normalize(key: str) -> str:
    return key.replace("_", "").casefold()


class _Reader:
    """A configuration section's values by field name, matched ignoring case and underscores."""

    def __init__(self, settings: object, where: str, fields: tuple[str, ...]) -> None:
        if not isinstance(settings, Mapping):
            raise TypeError(f"{where} must be a mapping; it is {type(settings).__name__}.")
        known = {_normalize(name): name for name in fields}
        self._values: dict[str, object] = {}
        self._where = where
        for key, value in settings.items():
            if not isinstance(key, str):
                raise ValueError(f"{where} has a key that is not a string: {key!r}.")
            name = known.get(_normalize(key))
            if name is None:
                raise ValueError(f"{where} has an unknown key '{key}'. Known keys: {', '.join(fields)}.")
            if name in self._values:
                raise ValueError(f"{where} gives '{name}' more than once.")
            self._values[name] = value

    def read[T](self, name: str, convert: Callable[[object, str], T]) -> T | None:
        value = self._values.get(name)
        return None if value is None else convert(value, f"{self._where}.{name}")


def _string(value: object, where: str) -> str:
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str):
        raise ValueError(f"{where} must be a string; it is {type(value).__name__}.")
    return value


def _boolean(value: object, where: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().casefold() in ("true", "false"):
        return value.strip().casefold() == "true"
    raise ValueError(f"{where} must be true or false; it is {value!r}.")


def _enum[E: enum.StrEnum](kind: type[E], numbers: Mapping[int, E]) -> Callable[[object, str], E | str]:
    def convert(value: object, where: str) -> E | str:
        if isinstance(value, kind):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return numbers.get(value, str(value))
        if not isinstance(value, str):
            raise ValueError(f"{where} must be a string; it is {type(value).__name__}.")
        text = value.strip()
        if _INTEGER.fullmatch(text):
            return numbers.get(int(text), value)
        for member in kind:
            if member.value.casefold() == text.casefold():
                return member
        return value  # not one: the validator says so, with every other failure

    return convert


def _store(value: object, where: str) -> CertificateStoreOptions:
    if isinstance(value, CertificateStoreOptions):
        return value
    reader = _Reader(value, where, ("store_location", "store_name", "subject"))
    return CertificateStoreOptions(
        store_location=reader.read("store_location", _enum(StoreLocation, _STORE_LOCATION_NUMBERS)) or StoreLocation.LOCAL_MACHINE,
        store_name=reader.read("store_name", _enum(StoreName, _STORE_NAME_NUMBERS)) or StoreName.MY,
        subject=reader.read("subject", _string),
    )


def _linux(value: object, where: str) -> LinuxOpenSslProviderOptions:
    if isinstance(value, LinuxOpenSslProviderOptions):
        return value
    reader = _Reader(value, where, ("provider", "key_uri", "certificate_file"))
    provider = reader.read("provider", _string)
    return LinuxOpenSslProviderOptions(
        provider="tpm2" if provider is None else provider,
        key_uri=reader.read("key_uri", _string),
        certificate_file=reader.read("certificate_file", _string),
    )


def _file(value: object, where: str) -> CertificateFileOptions:
    if isinstance(value, CertificateFileOptions):
        return value
    reader = _Reader(value, where, ("path", "format", "key_path", "password_secret_name", "allow_unprotected_private_key"))
    return CertificateFileOptions(
        path=reader.read("path", _string),
        format=reader.read("format", _enum(CertificateFileFormat, _FORMAT_NUMBERS)) or CertificateFileFormat.PKCS12,
        key_path=reader.read("key_path", _string),
        password_secret_name=reader.read("password_secret_name", _string),
        allow_unprotected_private_key=reader.read("allow_unprotected_private_key", _boolean) or False,
    )
