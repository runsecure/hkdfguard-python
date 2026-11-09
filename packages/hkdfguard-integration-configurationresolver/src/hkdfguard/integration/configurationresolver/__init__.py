"""Resolves the ``${name}`` items in a template - a connection string, a configuration file - with
secrets from HkdfGuard's protected caches: the port of HkdfGuard.Integration.ConfigurationResolver,
together with the parts of ConfigurationResolver it uses.

* :class:`ProtectedCacheValueProvider` - a :class:`ValueProvider` over any
  ``ProtectedReadOnlyCache``; :meth:`ConfigurationResolverBuilder.add_protected_cache` adds one.
* :class:`ResolvingProtectedCacheCollection` - a ``ProtectedReadOnlyCache`` over several sources
  that resolves a value holding items on its first lookup, and caches the result encrypted.
* The resolver: :class:`ConfigurationItemTokenBase` and :class:`DefaultToken`,
  :class:`ConfigurationItemReader`, :class:`ConfigurationItemResolver` and
  :class:`ConfigurationResolverBuilder`, :class:`ValueProviderBase` and
  :class:`CompositeValueProvider`, and the errors they raise.

Values are UTF-8 bytes, written into the caller's ``bytearray`` and never made into a ``str``
unless a caller opts in.
"""

from hkdfguard.integration.configurationresolver._builder import ConfigurationResolverBuilder
from hkdfguard.integration.configurationresolver._errors import ConfigurationKeyError, ConfigurationKeyErrorCode, DestinationTooSmallError
from hkdfguard.integration.configurationresolver._protected_cache_value_provider import ProtectedCacheValueProvider
from hkdfguard.integration.configurationresolver._reader import ConfigurationItemReader, KeyReader
from hkdfguard.integration.configurationresolver._resolver import ConfigurationItemResolver, ConfigurationResolver
from hkdfguard.integration.configurationresolver._resolving_collection import ResolvingProtectedCacheCollection
from hkdfguard.integration.configurationresolver._tokens import ConfigurationItemTokenBase, DefaultToken
from hkdfguard.integration.configurationresolver._value_providers import CompositeValueProvider, ValueProvider, ValueProviderBase, ValueStatus

__all__ = [
    "CompositeValueProvider",
    "ConfigurationItemReader",
    "ConfigurationItemResolver",
    "ConfigurationItemTokenBase",
    "ConfigurationKeyError",
    "ConfigurationKeyErrorCode",
    "ConfigurationResolver",
    "ConfigurationResolverBuilder",
    "DefaultToken",
    "DestinationTooSmallError",
    "KeyReader",
    "ProtectedCacheValueProvider",
    "ResolvingProtectedCacheCollection",
    "ValueProvider",
    "ValueProviderBase",
    "ValueStatus",
]
