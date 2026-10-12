"""The interfaces every HkdfGuard component is written against, the rules every port shares
(service names, configuration purposes, cache AADs), and the protected-cache base class."""

from hkdfguard.abstractions._buffers import ArrayUtility, Utf8, WritableBuffer
from hkdfguard.abstractions._errors import (
    AuthenticationTagMismatchError,
    CryptographicError,
    EncryptedFormatError,
    KeyNotFoundError,
    ObjectClosedError,
)
from hkdfguard.abstractions._interfaces import (
    CryptoProvider,
    CryptoProviderFactory,
    DataEncryptionKey,
    DataProtector,
    EncryptedFormatProvider,
    KeyRing,
    KeyTrackingValue,
    KeyWrapper,
    PipelineDataProtector,
    ProtectedCache,
    ProtectedReadOnlyCache,
    VersionedKey,
)
from hkdfguard.abstractions._protected_cache_base import ProtectedCacheBase
from hkdfguard.abstractions._rules import (
    KeyVersions,
    ProtectedConfigurationPurpose,
    RefreshFailurePolicy,
    ServiceNames,
    WrappedKeyLimits,
    ascii_upper,
)

__all__ = [
    "ArrayUtility",
    "AuthenticationTagMismatchError",
    "CryptoProvider",
    "CryptoProviderFactory",
    "CryptographicError",
    "DataEncryptionKey",
    "DataProtector",
    "EncryptedFormatError",
    "EncryptedFormatProvider",
    "KeyNotFoundError",
    "KeyRing",
    "KeyTrackingValue",
    "KeyVersions",
    "KeyWrapper",
    "ObjectClosedError",
    "PipelineDataProtector",
    "ProtectedCache",
    "ProtectedCacheBase",
    "ProtectedConfigurationPurpose",
    "ProtectedReadOnlyCache",
    "RefreshFailurePolicy",
    "ServiceNames",
    "Utf8",
    "VersionedKey",
    "WrappedKeyLimits",
    "WritableBuffer",
    "ascii_upper",
]
