"""One X.509 certificate, and its private key, opened from where configuration says it is - the
Python port of the .NET HkdfGuard.Options.Certificate: :class:`CertificateOptions` names exactly one
source (a Windows certificate store, a macOS keychain, an OpenSSL 3 provider on Linux, or a
password-protected PKCS#12 or PEM file), :class:`CertificateOptionsValidator` checks it, and
:class:`CertificateOptionsLoader` opens it as a :class:`LoadedCertificate`. A key an operating system
store holds is never exported: every signature and decryption is a call into the store."""

from hkdfguard.options.certificate._dn import DistinguishedName
from hkdfguard.options.certificate._errors import (
    CertificateError,
    CertificateNotFoundError,
    CertificateNotValidNowError,
    CertificateOptionsValidationError,
    InvalidCertificateFileError,
    NativeProviderRequiredError,
    NoPasswordSourceError,
    NoPrivateKeyError,
    PasswordNotFoundError,
    UnsupportedCertificateError,
    WrongPasswordError,
)
from hkdfguard.options.certificate._loaded import LoadedCertificate
from hkdfguard.options.certificate._loader import CertificateOptionsLoader, StoreCertificate, StoreReader
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

__all__ = [
    "CertificateError",
    "CertificateFileFormat",
    "CertificateFileOptions",
    "CertificateNotFoundError",
    "CertificateNotValidNowError",
    "CertificateOptions",
    "CertificateOptionsLoader",
    "CertificateOptionsValidationError",
    "CertificateOptionsValidator",
    "CertificateStoreOptions",
    "DistinguishedName",
    "InvalidCertificateFileError",
    "LinuxOpenSslProviderOptions",
    "LoadedCertificate",
    "NativeProviderRequiredError",
    "NoPasswordSourceError",
    "NoPrivateKeyError",
    "PasswordNotFoundError",
    "StoreCertificate",
    "StoreLocation",
    "StoreName",
    "StoreReader",
    "UnsupportedCertificateError",
    "WrongPasswordError",
]
