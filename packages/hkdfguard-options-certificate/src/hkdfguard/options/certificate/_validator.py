"""CertificateOptionsValidator: the .NET validator's rules, for the platform the process runs on."""

from __future__ import annotations

import os
import sys
from typing import Final

from hkdfguard.options.certificate._dn import DistinguishedName
from hkdfguard.options.certificate._errors import CertificateOptionsValidationError
from hkdfguard.options.certificate._options import (
    CertificateFileFormat,
    CertificateFileOptions,
    CertificateOptions,
    CertificateStoreOptions,
    LinuxOpenSslProviderOptions,
    StoreLocation,
    StoreName,
)

WINDOWS: Final = "windows"
MACOS: Final = "macos"
LINUX: Final = "linux"


def current_platform() -> str:
    """The platform the process runs on, as the validator names it: ``"windows"``, ``"macos"``,
    ``"linux"``, or ``sys.platform`` for any other (which has no native source)."""
    if sys.platform == "win32":
        return WINDOWS
    if sys.platform == "darwin":
        return MACOS
    if sys.platform.startswith("linux"):
        return LINUX
    return sys.platform


def _describe(platform: str) -> str:
    return {WINDOWS: "Windows", MACOS: "macOS", LINUX: "Linux"}.get(platform, platform)


class CertificateOptionsValidator:
    """Checks a :class:`CertificateOptions` before anything is opened: exactly one source set, and one
    this operating system has - the Windows store on Windows, a keychain on macOS, an OpenSSL
    provider on Linux, a file anywhere - with a store, subject, provider, key or path that is one. A
    file holding a private key must be protected by a password, named by its secret, unless an
    unprotected key is explicitly allowed.

    Beyond .NET's rules, it refuses what this port can't open on the platform it runs on, where the
    source is otherwise usable: a macOS store other than My, and a Linux provider key that is neither
    a ``pkcs11:`` URI nor the absolute path of a key file (a ``handle:`` TPM handle).
    """

    def __init__(self, platform: str | None = None) -> None:
        """:param platform: the platform to judge for - ``"windows"``, ``"macos"``, ``"linux"`` or
            another ``sys.platform`` - for tests; ``None`` for the one the process runs on"""
        self._platform = current_platform() if platform is None else platform

    @property
    def platform(self) -> str:
        """The platform this validator judges for."""
        return self._platform

    def validate(self, options: CertificateOptions) -> list[str]:
        """:returns: every failure, or an empty list if ``options`` is valid
        :raises TypeError: ``options`` isn't a :class:`CertificateOptions`
        """
        if not isinstance(options, CertificateOptions):
            raise TypeError(f"options must be CertificateOptions; it is {type(options).__name__}.")
        failures: list[str] = []
        sources = (("Windows", options.windows, WINDOWS), ("MacOS", options.mac_os, MACOS), ("Linux", options.linux, LINUX),
                   ("File", options.file, None))
        chosen = [name for name, value, _ in sources if value is not None]
        if not chosen:
            failures.append("One certificate source is required: Windows, MacOS, Linux or File.")
        elif len(chosen) > 1:
            failures.append(f"Only one certificate source can be set, but {', '.join(chosen)} are.")
        for name, value, platform in sources:
            if value is not None and platform is not None and platform != self._platform:
                failures.append(f"The {name} certificate source can only be used on {name}; this is {_describe(self._platform)}.")

        if options.windows is not None:
            self._validate_store("Windows", options.windows, failures)
        if options.mac_os is not None:
            self._validate_store("MacOS", options.mac_os, failures)
            # Only where the source is otherwise usable: elsewhere the platform failure says enough.
            if self._platform == MACOS and options.mac_os.store_name in StoreName and options.mac_os.store_name != StoreName.MY:
                failures.append(f"MacOS.StoreName must be My - the keychain itself, the only store this port reads on macOS - "
                                f"not {options.mac_os.store_name}.")
        if options.linux is not None:
            self._validate_linux(options.linux, options.require_private_key, failures)
        if options.file is not None:
            self._validate_file(options.file, options.require_private_key, failures)
        return failures

    def require_valid(self, options: CertificateOptions, name: str | None = None) -> CertificateOptions:
        """:returns: ``options``
        :raises CertificateOptionsValidationError: any rule is broken; it lists every failure and ``name``
        """
        failures = self.validate(options)
        if failures:
            raise CertificateOptionsValidationError(failures, name)
        return options

    @staticmethod
    def _validate_store(source: str, store: CertificateStoreOptions, failures: list[str]) -> None:
        if store.store_location not in StoreLocation:
            failures.append(f"{source}.StoreLocation must be CurrentUser or LocalMachine, not {store.store_location}.")
        if store.store_name not in StoreName:
            failures.append(f"{source}.StoreName must be a store's name - My, Root, CertificateAuthority, TrustedPeople... - not {store.store_name}.")
        if store.subject is None or not store.subject.strip():
            failures.append(f'{source}.Subject is required: the certificate\'s subject distinguished name, e.g. "CN=api.example.com".')
            return
        try:
            DistinguishedName.parse(store.subject)
        except ValueError:
            failures.append(f"{source}.Subject must be a distinguished name, e.g. \"CN=api.example.com, O=Contoso\", not '{store.subject}'.")

    def _validate_linux(self, linux: LinuxOpenSslProviderOptions, require_private_key: bool, failures: list[str]) -> None:
        provider = linux.provider
        if not provider or not all(c.isascii() and (c.isalnum() or c in "-_") for c in provider):
            failures.append(f"Linux.Provider must be an OpenSSL provider's name - \"tpm2\" or \"pkcs11\" - not '{provider}'.")
        if require_private_key:
            if linux.key_uri is None or not linux.key_uri.strip():
                failures.append('Linux.KeyUri is required: the key as the provider names it, e.g. "pkcs11:token=...;object=...".')
            elif self._platform == LINUX and (problem := provider_key_problem(linux.key_uri)) is not None:
                failures.append(problem)
        _validate_path("Linux.CertificateFile", linux.certificate_file, failures)

    @staticmethod
    def _validate_file(file: CertificateFileOptions, require_private_key: bool, failures: list[str]) -> None:
        _validate_path("File.Path", file.path, failures)
        if file.format not in CertificateFileFormat:
            failures.append(f"File.Format must be Pkcs12 or Pem, not {file.format}.")
        elif file.format == CertificateFileFormat.PEM and require_private_key:
            _validate_path("File.KeyPath", file.key_path, failures)

        if file.password_secret_name is not None and not file.password_secret_name.strip():
            failures.append("File.PasswordSecretName can't be empty: name the secret holding the key's password, or leave it unset.")
        elif require_private_key and file.password_secret_name is None and not file.allow_unprotected_private_key:
            failures.append("File.PasswordSecretName is required: a private key file must be protected by a password, read from a protected "
                            "secret. Set File.AllowUnprotectedPrivateKey to accept a plaintext key, for development only.")


def provider_key_problem(key_uri: str) -> str | None:
    """Why a Linux ``KeyUri`` can't be given to Python's ``ssl`` module through a provider's decoder;
    ``None`` for one that can: a ``pkcs11:`` URI, or an absolute path (optionally ``file:``-prefixed)."""
    if key_uri.startswith("pkcs11:"):
        return None
    if key_uri.startswith("handle:"):
        return (f"Linux.KeyUri '{key_uri}' is a persistent TPM handle, which Python's ssl module can't open: it reads a key only from a "
                "file, through the provider's decoder. Give the path of the key's TSS2 PRIVATE KEY PEM file instead (tpm2-openssl writes "
                "one with 'openssl genpkey -provider tpm2 ... -out key.pem').")
    path = key_uri[len("file:"):] if key_uri.startswith("file:") else key_uri
    if not os.path.isabs(path):
        return (f"Linux.KeyUri must be a \"pkcs11:\" URI or the absolute path of a key file the provider decodes (a TSS2 PRIVATE KEY PEM, "
                f"for tpm2), not '{key_uri}'.")
    return None


def _validate_path(what: str, path: str | None, failures: list[str]) -> None:
    if path is None or not path.strip():
        failures.append(f"{what} is required.")
    elif not os.path.isabs(path):
        failures.append(f"{what} must be an absolute path, not '{path}'.")
