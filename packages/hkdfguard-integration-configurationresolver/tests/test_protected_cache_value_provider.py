from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from configurationresolver_test_support import FakeRemoteSecretCache, SettingsProvider, new_cache, new_ring
from hkdfguard.abstractions import ArrayUtility, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.dataencryptionkey import KeyRing
from hkdfguard.integration.configurationresolver import (
    ConfigurationItemReader,
    ConfigurationItemResolver,
    ConfigurationKeyError,
    ConfigurationKeyErrorCode,
    ConfigurationResolver,
    ConfigurationResolverBuilder,
    DefaultToken,
    DestinationTooSmallError,
    ProtectedCacheValueProvider,
    ValueStatus,
)


@pytest.fixture
def ring() -> Iterator[KeyRing]:
    with new_ring() as ring:
        yield ring


def create_resolver(template: str, cache: ProtectedReadOnlyCache) -> ConfigurationResolver:
    token = DefaultToken()
    reader = ConfigurationItemReader(token)
    reader.read_keys(template)
    return ConfigurationItemResolver(token, reader, ProtectedCacheValueProvider(cache))


def test_resolve_replaces_items_with_cached_values(ring: KeyRing) -> None:
    cache = new_cache(ring, **{"db-user": "app", "db-password": "pässword"})
    template = "User=${db-user};Password=${db-password}"

    destination = bytearray(256)
    written = create_resolver(template, cache).resolve(template, destination)

    assert destination[:written].decode() == "User=app;Password=pässword"


def test_resolve_utf8_source_replaces_items_with_cached_values(ring: KeyRing) -> None:
    cache = new_cache(ring, **{"db-password": "pässword"})

    destination = bytearray(256)
    written = create_resolver("Password=${db-password}", cache).resolve(b"Password=${db-password}", destination)

    assert destination[:written].decode() == "Password=pässword"


def test_resolve_missing_name_raises_not_found(ring: KeyRing) -> None:
    cache = new_cache(ring, present="value")

    with pytest.raises(ConfigurationKeyError) as raised:
        create_resolver("${absent}", cache).resolve("${absent}", bytearray(64))

    assert raised.value.error is ConfigurationKeyErrorCode.NOT_FOUND


# The cache's bound is the ciphertext's length, so a destination with exactly the value's room is
# below it: the value goes through a scratch buffer.
@pytest.mark.parametrize("value_length", [5, 612])
def test_resolve_destination_below_bound_but_value_fits_resolves(ring: KeyRing, value_length: int) -> None:
    value = "v" * value_length
    cache = new_cache(ring, item=value)

    destination = bytearray(value_length)
    written = create_resolver("${item}", cache).resolve("${item}", destination)

    assert destination[:written].decode() == value


def test_resolve_value_larger_than_destination_raises_and_zeroes_destination(ring: KeyRing) -> None:
    cache = new_cache(ring, item="too long a value")
    destination = bytearray(b"XXXX")

    with pytest.raises(DestinationTooSmallError):
        create_resolver("${item}", cache).resolve("${item}", destination)

    assert destination == bytearray(4)


def test_try_get_bytes_value_larger_than_the_room_is_too_small_and_writes_nothing(ring: KeyRing) -> None:
    provider = ProtectedCacheValueProvider(new_cache(ring, item="value"))
    destination = bytearray(4)

    assert provider.try_get_bytes("item", destination) == (ValueStatus.DESTINATION_TOO_SMALL, 0)
    assert destination == bytearray(4)


def test_try_get_bytes_writes_into_a_memoryview_slice(ring: KeyRing) -> None:
    provider = ProtectedCacheValueProvider(new_cache(ring, item="value"))
    destination = bytearray(b"--" + bytes(62))

    assert provider.try_get_bytes("item", memoryview(destination)[2:]) == (ValueStatus.FOUND, 5)
    assert destination[:7] == b"--value"


def test_try_get_bytes_a_cache_error_propagates_and_resolve_zeroes(ring: KeyRing) -> None:
    class RefusingCache(ProtectedReadOnlyCache):
        def decrypt(self, name: str, result: WritableBuffer) -> int:
            raise PermissionError("access denied")

        def find_max_decrypted_length(self, name: str) -> int | None:
            raise PermissionError("access denied")

    destination = bytearray(b"X" * 16)

    with pytest.raises(PermissionError):
        create_resolver("a${item}", RefusingCache()).resolve("a${item}", destination)

    assert ArrayUtility.is_null_or_empty(destination)


def test_try_get_value_by_default_raises(ring: KeyRing) -> None:
    provider = ProtectedCacheValueProvider(new_cache(ring, item="value"))

    assert not provider.allow_string_values
    with pytest.raises(RuntimeError):
        provider.try_get_value("item")


def test_try_get_value_when_allowed_returns_the_value_as_a_str(ring: KeyRing) -> None:
    provider = ProtectedCacheValueProvider(new_cache(ring, item="value"), allow_string_values=True)

    assert provider.try_get_value("item") == (ValueStatus.FOUND, "value")
    assert provider.try_get_value("absent") == (ValueStatus.NOT_FOUND, None)


def test_composite_value_provider_falls_through_to_the_next_provider_for_missing_names(ring: KeyRing) -> None:
    cache = new_cache(ring, **{"db-password": "s3cret"})
    template = "Host=${db-host};Password=${db-password}"
    token = DefaultToken()
    reader = ConfigurationItemReader(token)
    reader.read_keys(template)
    resolver = ConfigurationItemResolver(token, reader, ProtectedCacheValueProvider(cache), SettingsProvider(**{"db-host": "db.internal"}))

    destination = bytearray(256)
    written = resolver.resolve(template, destination)

    assert destination[:written].decode() == "Host=db.internal;Password=s3cret"


def test_add_protected_cache_adds_a_provider_over_the_cache(ring: KeyRing) -> None:
    cache = new_cache(ring, **{"db-password": "s3cret"})
    template = "Password=${db-password}"
    token = DefaultToken()
    reader = ConfigurationItemReader(token)
    reader.read_keys(template)

    resolver = ConfigurationResolverBuilder().with_token(token).with_reader(reader).add_protected_cache(cache).build()

    destination = bytearray(64)
    written = resolver.resolve(template, destination)
    assert destination[:written].decode() == "Password=s3cret"


def test_prefetch_async_fetches_each_secret_once_without_blocking_so_resolve_does_not_fetch(ring: KeyRing) -> None:
    cache = FakeRemoteSecretCache(ring, **{"app-config": '{"user":"app","password":"s3cret"}'})
    template = "User=${app-config#user};Password=${app-config#password};Again=${app-config#user}"
    token = DefaultToken()
    reader = ConfigurationItemReader(token)
    reader.read_keys(template)
    provider = ProtectedCacheValueProvider(cache)

    asyncio.run(provider.prefetch_async(reader))

    destination = bytearray(256)
    written = ConfigurationItemResolver(token, reader, provider).resolve(template, destination)

    assert destination[:written].decode() == "User=app;Password=s3cret;Again=app"
    assert cache.async_fetches == ["app-config"]
    assert cache.fetches == []


def test_prefetch_async_skips_keys_the_cache_does_not_have(ring: KeyRing) -> None:
    cache = FakeRemoteSecretCache(ring, present="value")
    provider = ProtectedCacheValueProvider(cache)

    asyncio.run(provider.prefetch_async(["present", "absent", "absent"]))

    assert cache.async_fetches == ["present", "absent"]
    assert provider.try_get_bytes("absent", bytearray(16)) == (ValueStatus.NOT_FOUND, 0)


def test_prefetch_async_cancelled_raises(ring: KeyRing) -> None:
    async def cancelled() -> None:
        task = asyncio.ensure_future(ProtectedCacheValueProvider(FakeRemoteSecretCache(ring)).prefetch_async(["item"]))
        task.cancel()
        await task

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancelled())


def test_members_reject_none_arguments(ring: KeyRing) -> None:
    cache = new_cache(ring)
    provider = ProtectedCacheValueProvider(cache)

    assert provider.cache is cache
    with pytest.raises(TypeError):
        ProtectedCacheValueProvider(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        provider.try_get_bytes(None, bytearray(1))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        asyncio.run(provider.prefetch_async(None))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        asyncio.run(provider.prefetch_async("item"))
    with pytest.raises(TypeError):
        ConfigurationResolverBuilder().add_protected_cache(None)  # type: ignore[arg-type]
