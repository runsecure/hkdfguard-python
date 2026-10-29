"""Concurrent name-to-encrypted-value caches: :class:`ProtectedCache` encrypts every value under a
key ring's current key, bound to its name, :class:`ProtectedCacheCollection` reads through several
caches in order, and :class:`RemoteSecretCache` is the base of the caches over a remote secret
store, with :class:`SecretJsonBody` to take a secret out of a JSON response body before an SDK can
turn it into a ``str``."""

from pkgutil import extend_path

# The hkdfguard-cache-* provider distributions install subpackages of hkdfguard.cache
# (hkdfguard.cache.awssecretsmanager, ...). Installed wheels share one directory, but editable
# installs keep each distribution's src separate, so every one of them is searched.
__path__ = extend_path(__path__, __name__)

from hkdfguard.cache._body import ReadableBody, ResponseBody
from hkdfguard.cache._cache import ProtectedCache, ProtectedCacheCollection
from hkdfguard.cache._error_response_body import ErrorResponseBody
from hkdfguard.cache._errors import InvalidSecretDataError
from hkdfguard.cache._remote_secret_cache import RemoteSecretCache, SecretNameMatching, SecretValueSink
from hkdfguard.cache._secret_json_body import SecretJsonBody

__all__ = [
    "ErrorResponseBody",
    "InvalidSecretDataError",
    "ProtectedCache",
    "ProtectedCacheCollection",
    "ReadableBody",
    "RemoteSecretCache",
    "ResponseBody",
    "SecretJsonBody",
    "SecretNameMatching",
    "SecretValueSink",
]
