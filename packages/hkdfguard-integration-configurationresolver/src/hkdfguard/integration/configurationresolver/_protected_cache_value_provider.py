"""A value provider over HkdfGuard's protected caches."""

from __future__ import annotations

from collections.abc import Iterable

from hkdfguard.abstractions import ArrayUtility, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.integration.configurationresolver._reader import KeyReader
from hkdfguard.integration.configurationresolver._value_providers import ValueProviderBase, ValueStatus


class ProtectedCacheValueProvider(ValueProviderBase):
    """A value provider over a :class:`ProtectedReadOnlyCache`, so the items in a template -
    ``"Password=${db-password}"`` - resolve from HkdfGuard's protected caches: a ``ProtectedCache``,
    a ``ProtectedCacheCollection``, a ``FilePerSecretCache``, or a remote secret store's cache (AWS
    Secrets Manager, Azure Key Vault, Google Secret Manager, HashiCorp Vault). A template's key is
    the cache's name as it is, so a remote cache's ``"app-config#api-key"`` form works unchanged.

    Each value is decrypted straight into the resolver's destination when the cache's upper bound
    on its length fits there, and otherwise into a ``bytearray`` that is zeroed once the value has
    been copied out. It is never a ``str``: :meth:`try_get_value`, the one member that returns one,
    raises unless ``allow_string_values`` is set. The resolver itself never calls it.

    Value providers are synchronous, so a remote cache fetches a value it hasn't cached yet by
    blocking the resolving thread. Await :meth:`prefetch_async` with the template's reader first:
    the cache keeps what it fetches, so resolve then reads only from memory.
    """

    def __init__(self, cache: ProtectedReadOnlyCache, *, allow_string_values: bool = False) -> None:
        """:param cache: the cache values are read from
        :param allow_string_values: whether :meth:`try_get_value` may return a value as a ``str``,
            which can't be zeroed; ``False`` by default, when it raises ``RuntimeError`` instead
        :raises TypeError: ``cache`` is ``None``
        """
        if cache is None:
            raise TypeError("cache must not be None.")
        self._cache = cache
        self._allow_string_values = allow_string_values

    @property
    def cache(self) -> ProtectedReadOnlyCache:
        """The cache values are read from."""
        return self._cache

    @property
    def allow_string_values(self) -> bool:
        """Whether :meth:`try_get_value` may return a value as a ``str``, which can't be zeroed."""
        return self._allow_string_values

    async def prefetch_async(self, keys: KeyReader | Iterable[str]) -> None:
        """Fetches each key - every key a reader has read, or each of ``keys`` - one at a time and
        without blocking the event loop, so a later resolve doesn't fetch. A key listed twice is
        fetched once; a key the cache doesn't have is skipped, and resolve reports it.

        :param keys: the reader the resolver was given, after it has read the template; or the keys
        :raises TypeError: ``keys`` is ``None``, or a single ``str``
        """
        if keys is None:
            raise TypeError("keys must not be None.")
        if isinstance(keys, str):
            raise TypeError("keys must be a reader or several keys, not one str.")
        names = keys.keys() if isinstance(keys, KeyReader) else keys
        for key in dict.fromkeys(names):
            await self._cache.find_max_decrypted_length_async(key)

    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        if key is None:
            raise TypeError("key must not be None.")
        max_length = self._cache.find_max_decrypted_length(key)
        if max_length is None:
            return ValueStatus.NOT_FOUND, 0

        with memoryview(destination) as view:
            room = view.cast("B")
            if max_length <= len(room):
                written = self._cache.decrypt(key, room)
                return (ValueStatus.FOUND, written) if written else (ValueStatus.NOT_FOUND, 0)

            # The bound is above the room left, but the value itself may still fit.
            plaintext = bytearray(max_length)
            try:
                length = self._cache.decrypt(key, plaintext)
                if length == 0:
                    return ValueStatus.NOT_FOUND, 0
                if length > len(room):
                    return ValueStatus.DESTINATION_TOO_SMALL, 0
                with memoryview(plaintext) as value:
                    room[:length] = value[:length]
                return ValueStatus.FOUND, length
            finally:
                ArrayUtility.zero_memory(plaintext)

    def try_get_value(self, key: str) -> tuple[ValueStatus, str | None]:
        """:raises RuntimeError: ``allow_string_values`` isn't set"""
        if not self._allow_string_values:
            raise RuntimeError("ProtectedCacheValueProvider doesn't return values as strings unless allow_string_values is set.")
        return super().try_get_value(key)

    def _find_byte_count(self, key: str) -> int | None:
        return self._cache.find_max_decrypted_length(key)
