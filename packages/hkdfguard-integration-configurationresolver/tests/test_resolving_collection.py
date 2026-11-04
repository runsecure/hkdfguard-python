from __future__ import annotations

import asyncio
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from configurationresolver_test_support import FakeRemoteSecretCache, PlainSource, SettingsProvider, decrypt_text, decrypt_text_async, new_ring
from hkdfguard.abstractions import ProtectedCacheBase
from hkdfguard.dataencryptionkey import KeyRing
from hkdfguard.diagnostics import AttributeNames, HkdfGuardTelemetry, SpanNames
from hkdfguard.integration.configurationresolver import (
    ConfigurationItemTokenBase,
    ConfigurationKeyError,
    ConfigurationKeyErrorCode,
    DefaultToken,
    DestinationTooSmallError,
    ResolvingProtectedCacheCollection,
)
from hkdfguard.integration.configurationresolver._resolving_collection import _store_key
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

CONN = "Host=db.internal;Password=s3cret"


@pytest.fixture
def ring() -> Iterator[KeyRing]:
    with new_ring() as ring:
        yield ring


def create(ring: KeyRing) -> tuple[ResolvingProtectedCacheCollection, PlainSource]:
    source = PlainSource(conn="Host=${host};Password=${password}", host="db.internal", password="s3cret")
    return ResolvingProtectedCacheCollection(ring).add(source), source


def test_template_is_resolved_from_the_sources_and_cached(ring: KeyRing) -> None:
    collection, source = create(ring)

    assert decrypt_text(collection, "conn") == CONN
    assert decrypt_text(collection, "conn") == CONN

    # Read and resolved once; every later lookup decrypts the cached result.
    assert source.decrypt_count("conn") == 1
    assert source.decrypt_count("password") == 1


def test_template_is_resolved_by_a_first_decrypt_without_sizing_first(ring: KeyRing) -> None:
    collection, _ = create(ring)
    async_collection, _ = create(ring)

    result = bytearray(64)
    assert result[: collection.decrypt("conn", result)].decode() == CONN
    result = bytearray(64)
    assert result[: asyncio.run(async_collection.decrypt_async("conn", result))].decode() == CONN


def test_resolved_value_is_cached_encrypted_not_as_the_sources_values(ring: KeyRing) -> None:
    collection, _ = create(ring)

    max_length = collection.find_max_decrypted_length("conn")

    # An AEAD bound: longer than the 32-byte resolved value it encloses.
    assert max_length is not None
    assert max_length > len(CONN)


def test_value_without_items_is_answered_by_its_source_which_is_remembered(ring: KeyRing) -> None:
    collection, source = create(ring)

    assert decrypt_text(collection, "password") == "s3cret"
    assert decrypt_text(collection, "password") == "s3cret"

    # One search through the sources, then only the lookups the remembered source answers.
    assert source.length_lookup_count("password") == 3
    assert source.decrypt_count("password") == 3


def test_missing_name_is_reported_missing(ring: KeyRing) -> None:
    collection, _ = create(ring)

    assert collection.decrypt("absent", bytearray(16)) == 0
    assert collection.find_max_decrypted_length("absent") is None
    assert asyncio.run(collection.decrypt_async("absent", bytearray(16))) == 0
    assert asyncio.run(collection.find_max_decrypted_length_async("absent")) is None


def test_sources_are_checked_in_order_for_names_and_items(ring: KeyRing) -> None:
    first = PlainSource(conn="${password}", password="first")
    second = PlainSource(conn="ignored", password="second", **{"only-second": "${password}"})
    collection = ResolvingProtectedCacheCollection(ring).add(first).add(second)

    assert decrypt_text(collection, "conn") == "first"
    assert decrypt_text(collection, "only-second") == "first"
    assert second.decrypt_count("conn") == 0


def test_value_providers_supply_items_after_the_sources_growing_the_buffer_when_needed(ring: KeyRing) -> None:
    large = "x" * 5000
    source = PlainSource(conn="Host=${host};Blob=${blob}", host="from-source")
    collection = ResolvingProtectedCacheCollection(ring).add(source).add_value_provider(SettingsProvider(host="ignored", blob=large))

    assert decrypt_text(collection, "conn") == f"Host=from-source;Blob={large}"


def test_value_providers_are_not_answered_by_name_on_their_own(ring: KeyRing) -> None:
    collection = ResolvingProtectedCacheCollection(ring).add_value_provider(SettingsProvider(host="db"))

    assert collection.find_max_decrypted_length("host") is None


def test_resolved_value_longer_than_max_resolved_length_raises(ring: KeyRing) -> None:
    collection = (
        ResolvingProtectedCacheCollection(ring, max_resolved_length=16).add(PlainSource(conn="${blob}")).add_value_provider(SettingsProvider(blob="x" * 17))
    )

    with pytest.raises(RuntimeError) as raised:
        collection.decrypt("conn", bytearray(64))

    assert isinstance(raised.value.__cause__, DestinationTooSmallError)


def test_max_resolved_length_and_token_default_and_reject_invalid_values(ring: KeyRing) -> None:
    collection = ResolvingProtectedCacheCollection(ring)

    assert collection.max_resolved_length == ResolvingProtectedCacheCollection.DEFAULT_MAX_RESOLVED_LENGTH
    assert isinstance(collection.token, DefaultToken)
    with pytest.raises(ValueError):
        ResolvingProtectedCacheCollection(ring, max_resolved_length=0)


def test_custom_token_marks_items(ring: KeyRing) -> None:
    source = PlainSource(conn="Host={{host}};Literal=${host}", host="db")
    collection = ResolvingProtectedCacheCollection(ring, token=ConfigurationItemTokenBase("{{", "}}")).add(source)

    assert decrypt_text(collection, "conn") == "Host=db;Literal=${host}"


def test_template_naming_a_missing_value_raises(ring: KeyRing) -> None:
    collection = ResolvingProtectedCacheCollection(ring).add(PlainSource(conn="${absent}"))

    with pytest.raises(ConfigurationKeyError) as raised:
        collection.decrypt("conn", bytearray(64))
    assert raised.value.error is ConfigurationKeyErrorCode.NOT_FOUND
    with pytest.raises(ConfigurationKeyError):
        collection.find_max_decrypted_length("conn")
    with pytest.raises(ConfigurationKeyError):
        asyncio.run(collection.decrypt_async("conn", bytearray(64)))
    with pytest.raises(ConfigurationKeyError):
        asyncio.run(collection.find_max_decrypted_length_async("conn"))


def test_template_resolving_to_nothing_is_reported_missing(ring: KeyRing) -> None:
    collection = ResolvingProtectedCacheCollection(ring).add(PlainSource(conn="${empty}")).add_value_provider(SettingsProvider(empty=""))

    assert collection.find_max_decrypted_length("conn") is None
    assert collection.decrypt("conn", bytearray(16)) == 0


def test_a_source_that_raises_fails_the_lookup(ring: KeyRing) -> None:
    class Refusing(PlainSource):
        def find_max_decrypted_length(self, name: str) -> int | None:
            raise PermissionError("access denied")

    collection = ResolvingProtectedCacheCollection(ring).add(PlainSource(conn="${remote}")).add(Refusing())

    with pytest.raises(PermissionError):
        collection.decrypt("conn", bytearray(64))
    with pytest.raises(PermissionError):
        collection.find_max_decrypted_length("absent")


def test_resolved_value_is_kept_until_invalidated(ring: KeyRing) -> None:
    collection, source = create(ring)
    assert decrypt_text(collection, "conn") == CONN

    source["password"] = "rotated"
    assert decrypt_text(collection, "conn") == CONN

    assert collection.invalidate("conn")
    assert decrypt_text(collection, "conn") == "Host=db.internal;Password=rotated"
    assert not collection.invalidate("never-looked-up")


def test_invalidate_forgets_which_source_holds_a_plain_value(ring: KeyRing) -> None:
    first = PlainSource()
    second = PlainSource(password="second")
    collection = ResolvingProtectedCacheCollection(ring).add(first).add(second)
    assert decrypt_text(collection, "password") == "second"

    first["password"] = "first"
    assert decrypt_text(collection, "password") == "second"

    assert collection.invalidate("password")
    assert decrypt_text(collection, "password") == "first"


def test_clear_forgets_everything(ring: KeyRing) -> None:
    collection, source = create(ring)
    decrypt_text(collection, "conn")
    decrypt_text(collection, "host")

    source["host"] = "db2"
    source["password"] = "rotated"
    collection.clear()

    assert decrypt_text(collection, "conn") == "Host=db2;Password=rotated"
    assert decrypt_text(collection, "host") == "db2"


def test_invalidate_during_a_resolve_keeps_its_result_out_of_the_cache(ring: KeyRing) -> None:
    collection, source = create(ring)

    def rotate() -> None:
        source["password"] = "rotated"
        collection.invalidate("conn")

    source.on_first_decrypt = ("password", rotate)

    # The first resolution read the old value's length, so it is dropped and the lookup resolves again.
    result = bytearray(64)
    assert result[: collection.decrypt("conn", result)].decode() == "Host=db.internal;Password=rotated"
    assert source.decrypt_count("conn") == 2

    assert result[: collection.decrypt("conn", result)].decode() == "Host=db.internal;Password=rotated"
    assert source.decrypt_count("conn") == 2


def test_clear_during_a_plain_lookup_does_not_remember_the_source(ring: KeyRing) -> None:
    collection, source = create(ring)
    source.on_first_decrypt = ("host", collection.clear)

    assert decrypt_text(collection, "host") == "db.internal"
    lookups = source.length_lookup_count("host")

    assert decrypt_text(collection, "host") == "db.internal"
    assert source.length_lookup_count("host") == lookups + 1


def test_names_match_exactly_even_where_the_resolved_store_ignores_case(ring: KeyRing) -> None:
    source = PlainSource(
        Db="upper ${value}",
        db="lower ${value}",
        aB="camel ${value}",
        value="v",
        **{"a!b": "bang ${value}", "a!!b": "double ${value}", "app/Db-1": "path ${value}"},
    )
    collection = ResolvingProtectedCacheCollection(ring).add(source)

    assert decrypt_text(collection, "Db") == "upper v"
    assert decrypt_text(collection, "db") == "lower v"
    assert decrypt_text(collection, "a!b") == "bang v"
    assert decrypt_text(collection, "aB") == "camel v"
    assert decrypt_text(collection, "a!!b") == "double v"
    assert decrypt_text(collection, "app/Db-1") == "path v"
    assert decrypt_text(collection, "Db") == "upper v"


def test_store_key_has_no_upper_case_ascii_and_no_two_names_share_an_aad() -> None:
    names = ["", "db", "Db", "DB", "dB", "!", "!!", "!d", "!D", "a!b", "aB", "a!!b", "a!Bb", "app/Db-1", "café", "CAFÉ"]
    aads: dict[bytes, str] = {}
    for name in names:
        key = _store_key(name)
        assert not any("A" <= c <= "Z" for c in key), (name, key)
        aad = ProtectedCacheBase.aad_for(key)
        assert aad not in aads, (name, aads.get(aad))
        aads[aad] = name


def test_async_lookups_resolve_from_a_remote_source_without_blocking_fetches(ring: KeyRing) -> None:
    remote = FakeRemoteSecretCache(ring, conn="Host=${host};Password=${password}", host="db.internal", password="s3cret")
    collection = ResolvingProtectedCacheCollection(ring).add(remote)

    async def lookups() -> None:
        max_length = await collection.find_max_decrypted_length_async("conn")
        assert max_length is not None
        result = bytearray(max_length)
        assert result[: await collection.decrypt_async("conn", result)].decode() == CONN
        assert await collection.find_max_decrypted_length_async("conn") == max_length

        # A plain value, found and then remembered.
        assert (await collection.find_max_decrypted_length_async("host") or 0) > 0
        assert await decrypt_text_async(collection, "password") == "s3cret"

    asyncio.run(lookups())

    assert remote.fetches == []
    assert sorted(remote.async_fetches) == ["conn", "host", "password"]


def test_async_lookup_after_the_template_was_invalidated_resolves_again(ring: KeyRing) -> None:
    collection, source = create(ring)
    assert (asyncio.run(collection.find_max_decrypted_length_async("conn")) or 0) > 0

    source["password"] = "rotated"
    collection.invalidate("conn")

    result = bytearray(64)
    assert result[: asyncio.run(collection.decrypt_async("conn", result))].decode() == "Host=db.internal;Password=rotated"


def test_concurrent_lookups_all_see_the_resolved_value(ring: KeyRing) -> None:
    collection, _ = create(ring)

    def lookup(index: int) -> str:
        if index % 8 == 0:
            collection.invalidate("conn")
        result = bytearray(64)
        return result[: collection.decrypt("conn", result)].decode()

    with ThreadPoolExecutor(8) as pool:
        assert set(pool.map(lookup, range(64))) == {CONN}


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    original_logging = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.set_tracer_provider(provider)
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    try:
        yield exporter
    finally:
        HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original_logging
        HkdfGuardTelemetry.set_tracer_provider(None)


def test_sensitive_logging_records_the_name(ring: KeyRing, spans: InMemorySpanExporter) -> None:
    collection, _ = create(ring)

    assert decrypt_text(collection, "password") == "s3cret"

    names = [
        event.attributes.get(AttributeNames.NAME)
        for span in spans.get_finished_spans()
        if span.name == SpanNames.Cache.DECRYPT
        for event in span.events
        if event.attributes is not None
    ]
    assert "password" in names


def test_members_reject_none_arguments(ring: KeyRing) -> None:
    collection = ResolvingProtectedCacheCollection(ring)

    with pytest.raises(TypeError):
        ResolvingProtectedCacheCollection(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        collection.add(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        collection.add_value_provider(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        collection.invalidate(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        collection.decrypt(None, bytearray(1))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        collection.find_max_decrypted_length(None)  # type: ignore[arg-type]
