"""A cache collection that resolves the templates its sources hold."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from enum import Enum, auto
from typing import Final, Self

from hkdfguard.abstractions import ArrayUtility, KeyRing, ProtectedCacheBase, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.diagnostics import AttributeNames, HkdfGuardTelemetry, SpanNames
from hkdfguard.integration.configurationresolver._errors import DestinationTooSmallError
from hkdfguard.integration.configurationresolver._protected_cache_value_provider import ProtectedCacheValueProvider
from hkdfguard.integration.configurationresolver._reader import ConfigurationItemReader
from hkdfguard.integration.configurationresolver._resolver import ConfigurationItemResolver
from hkdfguard.integration.configurationresolver._tokens import ConfigurationItemTokenBase, DefaultToken
from hkdfguard.integration.configurationresolver._value_providers import ValueProvider


class _Location(Enum):
    MISSING = auto()
    """No source holds the name, or its template resolved to nothing."""

    SOURCE = auto()
    """A source holds the name, and its value has no items: that source answers."""

    RESOLVED = auto()
    """The name's template was resolved: look in the resolved store again. If an invalidate or
    clear kept the result out of it, the lookup resolves it again."""


class ResolvingProtectedCacheCollection(ProtectedReadOnlyCache):
    """``ProtectedCacheCollection`` with templates: aggregates :class:`ProtectedReadOnlyCache`
    sources, checked in the order they were added, and resolves a value holding configuration items
    - ``"Host=db;Password=${db-password}"`` - on its first lookup, from those same sources (then any
    value providers added with :meth:`add_value_provider`). The resolved value is encrypted under
    the ring's current key, bound to its name as every :class:`ProtectedCacheBase` entry is, and
    cached, so later lookups only decrypt it. A value without items is answered by its source,
    unchanged. The port of ResolvingProtectedCacheCollection.

    **Templates are trusted.** A template's items may name any value in any source, so every source
    must be as trusted as the secrets it can reach: a template comes from whichever source holds its
    name, and nothing marks one source as templates only. Items are resolved one level deep: an item
    whose value is itself a template inserts that template's text unresolved. A value that is a
    template but names a value no source or provider has raises :class:`ConfigurationKeyError` on
    lookup, rather than reporting the name missing. One that resolves to nothing is reported
    missing, as an empty value can't be cached.

    **Resolved values are kept until invalidated.** When a value a template uses changes - a
    ``ProtectedCache.add_or_update``, a rotated remote secret - call :meth:`invalidate` for the
    template's name, or :meth:`clear`; the next lookup resolves it again. A resolution already under
    way when either is called doesn't cache its result. Which source holds a value without items is
    remembered too, and forgotten the same way. Add every source and provider before the first
    lookup.

    A source that raises fails the lookup, as in ``ProtectedCacheCollection``, and the same advice
    holds: add local sources before remote ones. decrypt_async and find_max_decrypted_length_async
    find the value and every value its template names with each source's async members, so a remote
    source doesn't block the event loop; the synchronous members block on a remote fetch.
    """

    DEFAULT_MAX_RESOLVED_LENGTH: Final = 1 << 20
    """The default :attr:`max_resolved_length`: 1 MiB."""

    def __init__(
        self,
        key_ring: KeyRing,
        *,
        token: ConfigurationItemTokenBase | None = None,
        max_resolved_length: int = DEFAULT_MAX_RESOLVED_LENGTH,
    ) -> None:
        """:param key_ring: encrypts each resolved value under its current key, and decrypts it
            under the version it recorded; owned by the caller
        :param token: the token that marks an item; :class:`DefaultToken` by default
        :param max_resolved_length: the most UTF-8 bytes a resolved value may hold; a template that
            resolves to more raises ``RuntimeError`` on lookup
        :raises TypeError: ``key_ring`` is ``None``
        :raises ValueError: ``max_resolved_length`` is less than 1
        """
        if key_ring is None:
            raise TypeError("key_ring must not be None.")
        if max_resolved_length < 1:
            raise ValueError(f"max_resolved_length must be at least 1, not {max_resolved_length}.")
        self._resolved = _ResolvedStore(key_ring)
        self._token = DefaultToken() if token is None else token
        self._max_resolved_length = max_resolved_length
        self._sources: tuple[ProtectedReadOnlyCache, ...] = ()
        self._value_providers: tuple[ValueProvider, ...] = ()
        self._plain: dict[str, ProtectedReadOnlyCache] = {}
        self._gate = threading.Lock()
        self._generation = 0

    @property
    def token(self) -> ConfigurationItemTokenBase:
        """The token that marks an item."""
        return self._token

    @property
    def max_resolved_length(self) -> int:
        """The most UTF-8 bytes a resolved value may hold."""
        return self._max_resolved_length

    def add(self, source: ProtectedReadOnlyCache) -> Self:
        """Registers ``source`` as an additional lookup source, checked after every source already
        added - for names and for the items in templates alike.

        :returns: this same collection, for fluent chaining
        :raises TypeError: ``source`` is ``None``
        """
        if source is None:
            raise TypeError("source must not be None.")
        with self._gate:
            self._sources = (*self._sources, source)
        return self

    def add_value_provider(self, value_provider: ValueProvider) -> Self:
        """Registers a value provider for the items in templates only, asked after every source and
        every provider already added. Its values are never answered by name on their own. A provider
        that holds its values as strings is no place for secrets.

        :returns: this same collection, for fluent chaining
        :raises TypeError: ``value_provider`` is ``None``
        """
        if value_provider is None:
            raise TypeError("value_provider must not be None.")
        with self._gate:
            self._value_providers = (*self._value_providers, value_provider)
        return self

    def invalidate(self, name: str) -> bool:
        """Forgets ``name``'s resolved value, or which source holds it, so the next lookup reads it again.

        :returns: ``True`` if anything was remembered for ``name``
        :raises TypeError: ``name`` is ``None``
        """
        key = _store_key(name)
        with self._gate:
            self._generation += 1
            resolved = self._resolved.remove(key)
            plain = self._plain.pop(name, None) is not None
            return plain or resolved

    def clear(self) -> None:
        """Forgets every resolved value, and every source a value was found in."""
        with self._gate:
            self._generation += 1
            self._resolved.clear()
            self._plain.clear()

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """:raises ConfigurationKeyError: ``name``'s value is a template naming a value nothing has
        :raises RuntimeError: ``name``'s value resolves to more than :attr:`max_resolved_length` bytes
        """
        with self._decrypt_span(name):
            key = _store_key(name)
            while True:
                written = self._resolved.decrypt(key, result)
                if written > 0:
                    return written

                location, source = self._locate(name)
                if location is not _Location.RESOLVED:
                    return 0 if source is None else source.decrypt(name, result)

    def find_max_decrypted_length(self, name: str) -> int | None:
        """:raises ConfigurationKeyError: ``name``'s value is a template naming a value nothing has
        :raises RuntimeError: ``name``'s value resolves to more than :attr:`max_resolved_length` bytes
        """
        key = _store_key(name)
        while True:
            max_length = self._resolved.find_max_decrypted_length(key)
            if max_length is not None:
                return max_length

            location, source = self._locate(name)
            if location is not _Location.RESOLVED:
                return None if source is None else source.find_max_decrypted_length(name)

    async def decrypt_async(self, name: str, result: WritableBuffer) -> int:
        """:raises ConfigurationKeyError: ``name``'s value is a template naming a value nothing has
        :raises RuntimeError: ``name``'s value resolves to more than :attr:`max_resolved_length` bytes
        """
        with self._decrypt_span(name):
            key = _store_key(name)
            while True:
                written = self._resolved.decrypt(key, result)
                if written > 0:
                    return written

                location, source = await self._locate_async(name)
                if location is not _Location.RESOLVED:
                    return 0 if source is None else await source.decrypt_async(name, result)

    async def find_max_decrypted_length_async(self, name: str) -> int | None:
        """:raises ConfigurationKeyError: ``name``'s value is a template naming a value nothing has
        :raises RuntimeError: ``name``'s value resolves to more than :attr:`max_resolved_length` bytes
        """
        key = _store_key(name)
        while True:
            max_length = self._resolved.find_max_decrypted_length(key)
            if max_length is not None:
                return max_length

            location, source = await self._locate_async(name)
            if location is not _Location.RESOLVED:
                return None if source is None else await source.find_max_decrypted_length_async(name)

    def _locate(self, name: str) -> tuple[_Location, ProtectedReadOnlyCache | None]:
        """Finds ``name``'s value outside the resolved store, resolving and caching it on the way
        when it is a template."""
        source = self._plain.get(name)
        if source is not None:
            return _Location.SOURCE, source

        generation = self._generation
        sources, value_providers = self._sources, self._value_providers
        source, max_length = self._find_source(sources, name)
        if source is None:
            return _Location.MISSING, None

        template, reader = self._read_template(source, name, max_length)
        if template is None or reader is None:
            return self._remember(name, source, generation), source

        try:
            keys = reader.keys()
            bound = len(template) + sum(self._find_source(sources, key)[1] for key in keys)
            return self._resolve(name, template, reader, bound=bound, generation=generation, sources=sources, value_providers=value_providers), None
        finally:
            ArrayUtility.zero_memory(template)

    async def _locate_async(self, name: str) -> tuple[_Location, ProtectedReadOnlyCache | None]:
        source = self._plain.get(name)
        if source is not None:
            return _Location.SOURCE, source

        generation = self._generation
        sources, value_providers = self._sources, self._value_providers
        source, max_length = await self._find_source_async(sources, name)
        if source is None:
            return _Location.MISSING, None

        # The source has the value in hand now, so reading it doesn't fetch.
        template, reader = self._read_template(source, name, max_length)
        if template is None or reader is None:
            return self._remember(name, source, generation), source

        try:
            bound = len(template)
            keys = reader.keys()
            for key in keys:
                bound += (await self._find_source_async(sources, key))[1]
            return self._resolve(name, template, reader, bound=bound, generation=generation, sources=sources, value_providers=value_providers), None
        finally:
            ArrayUtility.zero_memory(template)

    @staticmethod
    def _find_source(sources: tuple[ProtectedReadOnlyCache, ...], name: str) -> tuple[ProtectedReadOnlyCache | None, int]:
        """The first source holding ``name``, as ``ProtectedCacheCollection`` finds it, with its bound."""
        for source in sources:
            max_length = source.find_max_decrypted_length(name)
            if max_length is not None:
                return source, max_length
        return None, 0

    @staticmethod
    async def _find_source_async(sources: tuple[ProtectedReadOnlyCache, ...], name: str) -> tuple[ProtectedReadOnlyCache | None, int]:
        for source in sources:
            max_length = await source.find_max_decrypted_length_async(name)
            if max_length is not None:
                return source, max_length
        return None, 0

    def _read_template(self, source: ProtectedReadOnlyCache, name: str, max_length: int) -> tuple[bytearray | None, ConfigurationItemReader | None]:
        """Reads ``name``'s value from ``source``, returning it, exactly sized, with a reader that
        has read its items - or ``None``, the value already zeroed, when it holds none."""
        value = bytearray(max_length)
        try:
            length = source.decrypt(name, value)
            reader = ConfigurationItemReader(self._token)
            with memoryview(value) as view:
                if not reader.read_keys(view[:length]):
                    return None, None
                template = bytearray(view[:length])
            return template, reader
        finally:
            ArrayUtility.zero_memory(value)

    def _remember(self, name: str, source: ProtectedReadOnlyCache, generation: int) -> _Location:
        with self._gate:
            if generation == self._generation:
                self._plain[name] = source
        return _Location.SOURCE

    def _resolve(
        self,
        name: str,
        template: bytearray,
        reader: ConfigurationItemReader,
        *,
        bound: int,
        generation: int,
        sources: tuple[ProtectedReadOnlyCache, ...],
        value_providers: tuple[ValueProvider, ...],
    ) -> _Location:
        """Resolves ``template`` and caches the result under ``name`` - unless invalidate or clear
        was called since ``generation`` was read, when the result is dropped for the lookup to
        resolve again."""
        resolver = ConfigurationItemResolver(self._token, reader, *(ProtectedCacheValueProvider(source) for source in sources), *value_providers)

        # The sources' bounds cover their values; a value provider's can't be known up front, so a
        # value from one may need a larger buffer.
        capacity = min(max(bound, 1), self._max_resolved_length)
        while True:
            resolved = bytearray(capacity)
            try:
                try:
                    written = resolver.resolve(template, resolved)
                except DestinationTooSmallError as error:
                    if capacity >= self._max_resolved_length:
                        raise RuntimeError(f"The value resolves to more than max_resolved_length ({self._max_resolved_length}) bytes.") from error
                    capacity = min(2 * capacity, self._max_resolved_length)
                    continue

                if written == 0:
                    return _Location.MISSING

                with self._gate:
                    if generation == self._generation:
                        with memoryview(resolved) as view:
                            self._resolved.set(_store_key(name), view[:written])
                    return _Location.RESOLVED
            finally:
                ArrayUtility.zero_memory(resolved)

    @contextmanager
    def _decrypt_span(self, name: str) -> Iterator[None]:
        # Current across an await too: OpenTelemetry's context lives in contextvars, which follow the task.
        telemetry = HkdfGuardTelemetry.CACHE
        with telemetry.start_span(SpanNames.Cache.DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.Cache.DECRYPT, {AttributeNames.NAME: str(name)})
            yield


def _store_key(name: str) -> str:
    """``name``'s key in the resolved store. The store matches names ignoring ASCII case, as every
    :class:`ProtectedCacheBase` does; this collection matches them exactly, as its sources may. So
    each name is stored under a spelling with no upper-case ASCII - ``!`` becomes ``!!``, and an
    upper-case letter ``!`` and its lower-case form - whose AAD no other name shares."""
    if name is None:
        raise TypeError("name must not be None.")
    if not any(c == "!" or "A" <= c <= "Z" for c in name):
        return name
    return "".join("!!" if c == "!" else "!" + c.lower() if "A" <= c <= "Z" else c for c in name)


class _ResolvedStore(ProtectedCacheBase):
    """The resolved values, encrypted and bound to their (store-key) names."""

    def set(self, key: str, plaintext: memoryview) -> None:
        """Encrypts ``plaintext`` under ``key``, replacing any value there; ``plaintext`` is zeroed."""
        self._put_entry(key, self._encrypt(key, plaintext))

    def remove(self, key: str) -> bool:
        return self._remove_entry(key)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
