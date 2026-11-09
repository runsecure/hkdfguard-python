"""The exceptions the certificate loader raises: one class for each way a load fails, as the Go port
has one sentinel error each, so callers can tell them apart without reading messages."""

from __future__ import annotations

from collections.abc import Sequence

from hkdfguard.abstractions import CryptographicError, KeyNotFoundError
from hkdfguard.options import OptionsValidationError


class CertificateOptionsValidationError(OptionsValidationError):
    """:class:`~hkdfguard.options.certificate.CertificateOptions` the validator refuses - .NET's
    ``OptionsValidationException``. :attr:`failures` lists every failure, so they can all be fixed
    at once; :attr:`name` is the options' name, for named options (``None`` for the default)."""

    def __init__(self, failures: Sequence[str], name: str | None = None) -> None:
        # Not OptionsValidationError's own message, which names the key ring options.
        self.failures: tuple[str, ...] = tuple(failures)
        self.name: str | None = name
        prefix = f"The certificate options '{name}' are invalid: " if name else "The certificate options are invalid: "
        ValueError.__init__(self, prefix + " ".join(self.failures))


class CertificateError(Exception):
    """The base of every failure to open a certificate, but invalid options
    (:class:`CertificateOptionsValidationError`) and the operating system's own ``OSError`` for a
    file that can't be read."""


class CertificateNotFoundError(CertificateError, LookupError):
    """A store holds no certificate with the subject named that is valid now (and has its private
    key, when one is required) - .NET's ``InvalidOperationException`` from a store."""


class CertificateNotValidNowError(CertificateError):
    """The certificate is expired or not yet valid."""


class NoPrivateKeyError(CertificateError):
    """The certificate has no private key, or the store won't open it, and one is required."""


class NoPasswordSourceError(CertificateError):
    """A key file has a password to read, but the loader was given no password source."""


class PasswordNotFoundError(CertificateError, KeyNotFoundError):
    """The password source holds no secret by the name ``PasswordSecretName`` gives - .NET's
    ``KeyNotFoundException``, so it is a :class:`~hkdfguard.abstractions.KeyNotFoundError` too."""


class InvalidCertificateFileError(CertificateError, CryptographicError):
    """A file isn't a certificate or key in the format named - .NET's ``CryptographicException``."""


class WrongPasswordError(CertificateError, CryptographicError):
    """A key file the password doesn't open: a PKCS#12 file whose integrity check fails, or a key
    that doesn't decrypt - .NET's ``CryptographicException``."""


class UnsupportedCertificateError(CertificateError):
    """What this port can't open or do: a legacy RC2 or RC4 PKCS#12 file, a store or key the
    platform has no way to reach, an algorithm the key or the store doesn't support."""


class NativeProviderRequiredError(UnsupportedCertificateError):
    """A TLS context was asked for a certificate whose private key an operating system store holds
    (Windows, macOS): Python's ``ssl`` module can only take a key from a file, and the store's key
    is never exported to make one. Use :meth:`LoadedCertificate.sign` and
    :meth:`LoadedCertificate.decrypt`, which call the store, or a File or Linux source for TLS."""
