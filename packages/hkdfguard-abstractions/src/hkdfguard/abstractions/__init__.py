"""The interfaces every HkdfGuard component is written against, the rules every port shares
(service names, configuration purposes, cache AADs), the protected-cache base class, and the strict
JSON reader the remote caches and key wrappers parse secrets with."""

from hkdfguard.abstractions._buffers import ArrayUtility, Utf8, WritableBuffer
from hkdfguard.abstractions._errors import (
    AuthenticationTagMismatchError,
    CryptographicError,
    EncryptedFormatError,
    InvalidKeyFileError,
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
from hkdfguard.abstractions._json_reader import JsonReader, JsonToken, MalformedJsonError
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
    "InvalidKeyFileError",
    "JsonReader",
    "JsonToken",
    "KeyNotFoundError",
    "KeyRing",
    "KeyTrackingValue",
    "KeyVersions",
    "KeyWrapper",
    "MalformedJsonError",
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
