"""Builds a resolver from a token, a reader, and value providers."""

from __future__ import annotations

from typing import Self

from hkdfguard.abstractions import ProtectedReadOnlyCache
from hkdfguard.integration.configurationresolver._protected_cache_value_provider import ProtectedCacheValueProvider
from hkdfguard.integration.configurationresolver._reader import KeyReader
from hkdfguard.integration.configurationresolver._resolver import ConfigurationItemResolver
from hkdfguard.integration.configurationresolver._tokens import ConfigurationItemTokenBase, DefaultToken
from hkdfguard.integration.configurationresolver._value_providers import ValueProvider


class ConfigurationResolverBuilder:
    """Builds a :class:`ConfigurationItemResolver` from a token, a reader, and one or more value
    providers: the port of ConfigurationResolverBuilder, with .NET's AddProtectedCache extension
    method as a method of its own.

    The token defaults to :class:`DefaultToken`. A reader and at least one value provider are
    required. The reader is not created for you, because only you can read the keys of your trusted
    template into it; create it with the same token. Each :meth:`build` returns a new resolver that
    shares the reader and the value providers::

        token = DefaultToken()
        reader = ConfigurationItemReader(token)
        reader.read_keys(template)

        resolver = (ConfigurationResolverBuilder()
                    .with_token(token)
                    .with_reader(reader)
                    .add_protected_cache(secrets)
                    .build())
    """

    def __init__(self) -> None:
        self._value_providers: list[ValueProvider] = []
        self._token: ConfigurationItemTokenBase = DefaultToken()
        self._reader: KeyReader | None = None
        self._ignore_unresolvable_placeholders = False
        self._max_resolution_depth = 1

    def with_token(self, token: ConfigurationItemTokenBase) -> Self:
        """Sets the token that defines the start, end, and escape sequences of a configuration
        item. Use the same token as the reader.

        :raises TypeError: ``token`` is ``None``
        """
        if token is None:
            raise TypeError("token must not be None.")
        self._token = token
        return self

    def with_reader(self, reader: KeyReader) -> Self:
        """Sets the reader whose keys are the only keys the resolver may resolve.

        :raises TypeError: ``reader`` is ``None``
        """
        if reader is None:
            raise TypeError("reader must not be None.")
        self._reader = reader
        return self

    def add_value_provider(self, value_provider: ValueProvider) -> Self:
        """Adds a value provider, after any added already. Providers added earlier have higher priority.

        :raises TypeError: ``value_provider`` is ``None``
        """
        if value_provider is None:
            raise TypeError("value_provider must not be None.")
        self._value_providers.append(value_provider)
        return self

    def add_protected_cache(self, cache: ProtectedReadOnlyCache) -> Self:
        """Adds a :class:`ProtectedCacheValueProvider` over ``cache``, after any value provider
        added already.

        :raises TypeError: ``cache`` is ``None``
        """
        return self.add_value_provider(ProtectedCacheValueProvider(cache))

    def ignore_unresolvable_placeholders(self, ignore: bool = True) -> Self:
        """Sets whether an allowed key that no value provider has is copied unchanged instead of raising."""
        self._ignore_unresolvable_placeholders = ignore
        return self

    def with_max_resolution_depth(self, max_resolution_depth: int) -> Self:
        """Sets the number of levels of configuration items that are resolved; 1 inserts values as they are.

        :raises ValueError: ``max_resolution_depth`` is less than 1
        """
        if max_resolution_depth < 1:
            raise ValueError(f"max_resolution_depth must be at least 1, not {max_resolution_depth}.")
        self._max_resolution_depth = max_resolution_depth
        return self

    def build(self) -> ConfigurationItemResolver:
        """A new resolver from the builder's settings.

        :raises RuntimeError: no reader has been set, or no value provider has been added
        """
        if self._reader is None:
            raise RuntimeError("A reader is required. Call with_reader before build.")
        if not self._value_providers:
            raise RuntimeError("At least one value provider is required. Call add_value_provider before build.")
        return ConfigurationItemResolver(
            self._token,
            self._reader,
            *self._value_providers,
            ignore_unresolvable_placeholders=self._ignore_unresolvable_placeholders,
            max_resolution_depth=self._max_resolution_depth,
        )
