from __future__ import annotations

import logging
import os
from collections.abc import Buffer, Callable, Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from hkdfguard.abstractions import (
    AuthenticationTagMismatchError,
    KeyRing,
    KeyTrackingValue,
    KeyWrapper,
    ProtectedCacheBase,
    ProtectedReadOnlyCache,
    WritableBuffer,
)
from hkdfguard.cache import ProtectedCache, ProtectedCacheCollection
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.diagnostics import AttributeNames, HkdfGuardLog, HkdfGuardTelemetry, MetricNames, SpanNames
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader, NumberDataPoint
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

# --- Helpers ----------------------------------------------------------------------------------


class FixedKeyWrapper(KeyWrapper):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError


def new_key() -> DataEncryptionKey:
    return DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60))


@pytest.fixture
def ring() -> Iterator[DefaultKeyRing]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, new_key())
        yield ring


second_ring = ring


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def recording_logger() -> tuple[logging.Logger, RecordingHandler]:
    logger = logging.Logger("recording", logging.DEBUG)
    handler = RecordingHandler()
    logger.addHandler(handler)
    return logger, handler


def read(cache: ProtectedReadOnlyCache, name: str, size: int = 64) -> str:
    result = bytearray(size)
    return result[: cache.decrypt(name, result)].decode()


class PopulatingCache(ProtectedCacheBase):
    """A minimal ProtectedCacheBase subclass whose _try_populate is driven directly by the test, with
    ways to tamper with its entries as a populate bug or an attacker would."""

    def __init__(self, ring: KeyRing) -> None:
        super().__init__(ring)
        self.try_populate_calls = 0
        self.on_try_populate: Callable[[str], bool] | None = None

    def seed(self, name: str, plaintext: str) -> None:
        self._put_entry(name, self._encrypt_text(name, plaintext))

    def copy_entry(self, source: str, target: str) -> None:
        entry = self._get_entry(source)
        assert entry is not None
        self._put_entry(target, entry)

    def version_of(self, name: str) -> int:
        entry = self._get_entry(name)
        assert entry is not None
        return entry.key_version

    def relabel_version(self, name: str, version: int) -> None:
        entry = self._get_entry(name)
        assert entry is not None
        self._put_entry(name, KeyTrackingValue(version, entry.value))

    def _try_populate(self, name: str) -> bool:
        self.try_populate_calls += 1
        return self.on_try_populate is not None and self.on_try_populate(name)


class ThrowingReadOnlyCache(ProtectedReadOnlyCache):
    def decrypt(self, name: str, result: WritableBuffer) -> int:
        raise RuntimeError("boom")

    def decrypt_to_str(self, name: str) -> str | None:
        raise RuntimeError("boom")

    def find_max_decrypted_length(self, name: str) -> int | None:
        raise RuntimeError("boom")


# --- ProtectedCache ---------------------------------------------------------------------------


def test_bytes_round_trip_and_the_plaintext_is_zeroed(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    plaintext = bytearray(b"top secret bytes")
    cache.add("item", plaintext)

    assert plaintext == bytearray(16)
    result = bytearray(16)
    assert cache.decrypt("item", result) == 16 and result == b"top secret bytes"

    view = memoryview(bytearray(b"via a view"))
    cache.add("view", view)
    assert view.tobytes() == bytes(10) and cache.decrypt_to_str("view") == "via a view"


@pytest.mark.parametrize("value", ["top secret chars", "héllo wörld 日本語", "😀 astral"])
def test_text_round_trips_including_multi_byte_utf8(ring: DefaultKeyRing, value: str) -> None:
    cache = ProtectedCache(ring)
    cache.add("item", value)
    assert cache.decrypt_to_str("item") == value
    assert read(cache, "item") == value


def test_immutable_bytes_are_refused_because_they_cannot_be_zeroed(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    with pytest.raises(TypeError):
        cache.add("item", b"immutable")  # type: ignore[arg-type]
    assert cache.find_max_decrypted_length("item") is None


def test_adding_a_name_twice_is_refused_whatever_the_ascii_case_and_keeps_the_first(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    cache.add("Item", bytearray(b"original"))

    with pytest.raises(ValueError, match="already been added"):
        cache.add("item", bytearray(b"second"))
    with pytest.raises(ValueError, match="already been added"):
        cache.add("ITEM", "second")
    assert read(cache, "item") == "original"


def test_add_or_update_replaces_the_value_whatever_the_ascii_case(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    cache.add("Item-Name", bytearray(b"first"))
    cache.add_or_update("ITEM-name", bytearray(b"second-value"))
    cache.add_or_update("item-NAME", "third-value")

    max_length = cache.find_max_decrypted_length("item-name")
    assert max_length is not None
    assert read(cache, "item-name", max_length) == "third-value"


def test_an_unknown_name_reads_as_nothing(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    assert cache.decrypt("missing", bytearray(16)) == 0
    assert cache.decrypt_to_str("missing") is None
    assert cache.find_max_decrypted_length("missing") is None


def test_find_max_decrypted_length_is_a_safe_upper_bound(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    cache.add("item", bytearray(b"some plaintext value"))
    max_length = cache.find_max_decrypted_length("item")
    assert max_length is not None
    result = bytearray(max_length)
    written = cache.decrypt("item", result)
    assert max_length >= written and result[:written] == b"some plaintext value"


def test_every_operation_round_trips_with_sensitive_logging(ring: DefaultKeyRing, sensitive: None) -> None:
    cache = ProtectedCache(ring)
    cache.add("a", bytearray(b"top secret"))
    cache.add("b", "top secret")
    cache.add_or_update("c", bytearray(b"top secret"))
    cache.add_or_update("d", "top secret")
    for name in "abcd":
        assert read(cache, name) == "top secret"
        assert cache.decrypt_to_str(name) == "top secret"
    assert cache.decrypt("missing", bytearray(16)) == 0


def test_decrypting_into_a_too_small_buffer_is_refused(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    cache.add("item", bytearray(b"top secret"))
    with pytest.raises(ValueError):
        cache.decrypt("item", bytearray(1))


def test_a_none_name_is_refused_by_every_write_and_the_plaintext_is_still_zeroed(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    for write in (cache.add, cache.add_or_update):
        plaintext = bytearray(b"value")
        with pytest.raises(TypeError):
            write(None, plaintext)  # type: ignore[arg-type]
        assert plaintext == bytearray(5)
        with pytest.raises(TypeError):
            write(None, "value")  # type: ignore[arg-type]


def test_an_empty_value_is_refused_by_every_write_and_nothing_is_stored(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    for write in (cache.add, cache.add_or_update):
        for empty in (bytearray(), ""):
            with pytest.raises(ValueError, match="empty"):
                write("item", empty)
    assert cache.find_max_decrypted_length("item") is None


def test_an_invalid_name_is_refused_and_the_plaintext_is_zeroed(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    plaintext = bytearray(b"value")
    with pytest.raises(ValueError):
        cache.add("bad\ud800name", plaintext)
    assert plaintext == bytearray(5)


def test_concurrent_adds_and_decrypts_across_many_names_all_round_trip(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda i: cache.add(f"item-{i}", bytearray(f"value-{i}".encode())), range(200)))
        assert list(pool.map(lambda i: cache.decrypt_to_str(f"item-{i}"), range(200))) == [f"value-{i}" for i in range(200)]


def test_concurrent_adds_of_one_name_exactly_one_succeeds(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)

    def attempt(i: int) -> bool:
        try:
            cache.add("shared-name", bytearray(f"value-{i}".encode()))
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(8) as pool:
        assert sum(pool.map(attempt, range(50))) == 1


@pytest.mark.parametrize("kind", range(4))
def test_with_sensitive_logging_each_write_logs_one_debug_entry_naming_the_item(ring: DefaultKeyRing, sensitive: None, kind: int) -> None:
    logger, handler = recording_logger()
    cache = ProtectedCache(ring, logger)
    write = cache.add if kind < 2 else cache.add_or_update
    write("item", bytearray(b"value") if kind % 2 == 0 else "value")

    (entry,) = handler.records
    assert entry.levelno == logging.DEBUG
    assert getattr(entry, HkdfGuardLog.EVENT_ID_KEY) == HkdfGuardLog.SENSITIVE_OPERATION_LOGGED
    assert "item" in entry.getMessage()


def test_without_sensitive_logging_a_write_logs_nothing(ring: DefaultKeyRing) -> None:
    logger, handler = recording_logger()
    ProtectedCache(ring, logger).add("item", "value")
    assert handler.records == []


def test_a_failed_write_logs_operation_failed_with_the_exception(ring: DefaultKeyRing) -> None:
    logger, handler = recording_logger()
    cache = ProtectedCache(ring, logger)
    cache.add("item", bytearray(b"first"))

    with pytest.raises(ValueError):
        cache.add("item", bytearray(b"second"))
    with pytest.raises(ValueError):
        cache.add("item", "second")
    with pytest.raises(ValueError):
        cache.add_or_update("other", bytearray())
    with pytest.raises(ValueError):
        cache.add_or_update("other", "")

    errors = [r for r in handler.records if r.levelno == logging.ERROR]
    assert len(errors) == 4
    for error in errors:
        assert getattr(error, HkdfGuardLog.EVENT_ID_KEY) == HkdfGuardLog.OPERATION_FAILED
        assert error.exc_info is not None and isinstance(error.exc_info[1], ValueError)


def test_writes_count_toward_the_operations_counter_tagged_with_operation_and_result(ring: DefaultKeyRing) -> None:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    HkdfGuardTelemetry.set_meter_provider(provider)
    try:
        cache = ProtectedCache(ring)
        cache.add("item", bytearray(b"value"))
        with pytest.raises(ValueError):
            cache.add("item", bytearray(b"value"))
        cache.add_or_update("item", "value")

        data = reader.get_metrics_data()
        assert data is not None
        points = [(dict(p.attributes or {}), p.value) for rm in data.resource_metrics for sm in rm.scope_metrics
                  for m in sm.metrics if m.name == MetricNames.Cache.OPERATIONS for p in m.data.data_points if isinstance(p, NumberDataPoint)]
        for operation, result in ((SpanNames.Cache.ADD, "success"), (SpanNames.Cache.ADD, "error"), (SpanNames.Cache.ADD_OR_UPDATE, "success")):
            assert ({AttributeNames.OPERATION_NAME: operation, AttributeNames.RESULT: result}, 1) in points
    finally:
        HkdfGuardTelemetry.set_meter_provider(None)
        provider.shutdown()


def test_a_failed_write_marks_its_span_as_errored(ring: DefaultKeyRing, sensitive: None) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    HkdfGuardTelemetry.set_tracer_provider(provider)
    try:
        cache = ProtectedCache(ring)
        cache.add("item", "value")
        with pytest.raises(ValueError):
            cache.add("item", "value")

        ok, failed = [s for s in exporter.get_finished_spans() if s.name == SpanNames.Cache.ADD]
        assert ok.status.status_code != StatusCode.ERROR
        assert failed.status.status_code == StatusCode.ERROR and failed.events[-1].name == "exception"
        assert any(e.attributes and e.attributes.get(AttributeNames.NAME) == "item" for e in ok.events)
    finally:
        HkdfGuardTelemetry.set_tracer_provider(None)


@pytest.mark.parametrize("value", ["é-秘密-" * 1500, "x" * 4096, "x" * (1024 * 1024)], ids=["mixed-15000", "ascii-4096", "ascii-1mib"])
def test_large_values_round_trip_and_the_callers_buffer_is_zeroed(ring: DefaultKeyRing, value: str) -> None:
    cache = ProtectedCache(ring)
    encoded = bytearray(value.encode())
    cache.add_or_update("big", encoded)
    assert encoded == bytearray(len(encoded))
    assert cache.decrypt_to_str("big") == value
    cache.add_or_update("big-text", value)
    assert cache.decrypt_to_str("big-text") == value


def test_ascii_case_variants_share_an_entry_and_non_ascii_case_variants_do_not(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    cache.add("Café", bytearray(b"value"))

    assert cache.decrypt("CAFé", bytearray(16)) == 5
    assert cache.decrypt("CAFÉ", bytearray(16)) == 0

    cache.add("CAFÉ", bytearray(b"other"))
    assert read(cache, "cafÉ") == "other"
    assert read(cache, "café") == "value"


# --- Populate on miss, rotation, name binding -------------------------------------------------


def test_a_miss_calls_try_populate_and_returns_the_populated_value(ring: DefaultKeyRing) -> None:
    cache = PopulatingCache(ring)

    def populate(name: str) -> bool:
        cache.seed(name, "populated value")
        return True

    cache.on_try_populate = populate
    assert read(cache, "item") == "populated value"
    assert cache.try_populate_calls == 1
    assert cache.decrypt_to_str("item") == "populated value" and cache.try_populate_calls == 1


def test_a_cached_value_never_calls_try_populate(ring: DefaultKeyRing) -> None:
    cache = PopulatingCache(ring)
    cache.seed("item", "already cached")

    def fail(name: str) -> bool:
        raise AssertionError("should not be called")

    cache.on_try_populate = fail
    assert read(cache, "item") == "already cached"
    assert cache.try_populate_calls == 0


def test_a_try_populate_that_fails_or_lies_reads_as_nothing(ring: DefaultKeyRing) -> None:
    cache = PopulatingCache(ring)
    cache.on_try_populate = lambda name: False
    assert cache.decrypt("item", bytearray(32)) == 0
    assert cache.try_populate_calls == 1

    cache.on_try_populate = lambda name: True  # claims success, stores nothing
    assert cache.decrypt("item", bytearray(32)) == 0
    assert cache.decrypt_to_str("item") is None

    cache.on_try_populate = None
    assert cache.decrypt("item", bytearray(32)) == 0


def test_find_max_decrypted_length_on_a_miss_calls_try_populate(ring: DefaultKeyRing) -> None:
    cache = PopulatingCache(ring)

    def populate(name: str) -> bool:
        cache.seed(name, "populated value")
        return True

    cache.on_try_populate = populate
    assert (cache.find_max_decrypted_length("item") or 0) > 0
    assert cache.try_populate_calls == 1


def test_values_stored_before_and_after_a_rotation_use_their_own_keys(ring: DefaultKeyRing) -> None:
    cache = PopulatingCache(ring)
    cache.seed("before", "stored under v1")
    ring.add(2, new_key())  # what scheduled ephemeral rotation does
    cache.seed("after", "stored under v2")

    assert (cache.version_of("before"), cache.version_of("after")) == (1, 2)
    assert read(cache, "before") == "stored under v1"
    assert read(cache, "after") == "stored under v2"


def test_add_or_update_after_a_rotation_re_encrypts_under_the_new_key(ring: DefaultKeyRing) -> None:
    cache = ProtectedCache(ring)
    cache.add_or_update("item", bytearray(b"first"))
    ring.add(2, new_key())
    cache.add_or_update("item", bytearray(b"second"))
    assert read(cache, "item") == "second"


def test_an_entry_whose_version_was_swapped_fails_authentication(ring: DefaultKeyRing) -> None:
    ring.add(2, new_key())
    cache = PopulatingCache(ring)
    cache.seed("item", "value")
    cache.relabel_version("item", 1)  # claims v1, but was encrypted under v2

    with pytest.raises(AuthenticationTagMismatchError):
        cache.decrypt("item", bytearray(16))


def test_a_ciphertext_copied_under_another_name_fails_authentication(ring: DefaultKeyRing) -> None:
    cache = PopulatingCache(ring)
    cache.seed("ConnectionStrings:Admin", "admin-password")
    cache.seed("ConnectionStrings:Reporting", "reporting-password")
    cache.copy_entry("ConnectionStrings:Admin", "ConnectionStrings:Reporting")

    with pytest.raises(AuthenticationTagMismatchError):
        cache.decrypt("ConnectionStrings:Reporting", bytearray(64))
    with pytest.raises(AuthenticationTagMismatchError):
        cache.decrypt_to_str("ConnectionStrings:Reporting")
    # The original entry still decrypts, under any ASCII-case spelling.
    assert read(cache, "connectionstrings:ADMIN") == "admin-password"


# --- ProtectedCacheCollection -----------------------------------------------------------------


def test_add_returns_the_same_collection_and_refuses_none(ring: DefaultKeyRing) -> None:
    collection = ProtectedCacheCollection()
    assert collection.add(ProtectedCache(ring)) is collection
    with pytest.raises(TypeError):
        collection.add(None)  # type: ignore[arg-type]


def test_with_no_sources_every_lookup_misses() -> None:
    collection = ProtectedCacheCollection()
    assert collection.decrypt("item", bytearray(16)) == 0
    assert collection.decrypt_to_str("item") is None
    assert collection.find_max_decrypted_length("item") is None


def test_lookups_return_from_the_first_source_that_has_the_name(ring: DefaultKeyRing, second_ring: DefaultKeyRing) -> None:
    first, second = ProtectedCache(ring), ProtectedCache(second_ring)
    first.add("item", bytearray(b"from-first"))
    second.add("item", bytearray(b"a much longer value from the second source"))
    collection = ProtectedCacheCollection().add(first).add(second)

    assert read(collection, "item") == "from-first"
    assert collection.decrypt_to_str("item") == "from-first"
    assert collection.find_max_decrypted_length("item") == first.find_max_decrypted_length("item")


def test_lookups_fall_through_to_a_later_source(ring: DefaultKeyRing, second_ring: DefaultKeyRing) -> None:
    first, second = ProtectedCache(ring), ProtectedCache(second_ring)
    second.add("item", "from-second")
    collection = ProtectedCacheCollection().add(first).add(second)

    assert read(collection, "item") == "from-second"
    assert collection.decrypt_to_str("item") == "from-second"
    assert (collection.find_max_decrypted_length("item") or 0) > 0
    assert collection.decrypt("missing", bytearray(16)) == 0
    assert collection.decrypt_to_str("missing") is None
    assert collection.find_max_decrypted_length("missing") is None


def test_collection_decrypt_round_trips_with_sensitive_logging(ring: DefaultKeyRing, sensitive: None) -> None:
    first = ProtectedCache(ring)
    first.add("item", bytearray(b"top secret"))
    collection = ProtectedCacheCollection().add(first)
    assert read(collection, "item") == "top secret"
    assert collection.decrypt_to_str("item") == "top secret"


def test_a_source_that_raises_propagates() -> None:
    collection = ProtectedCacheCollection().add(ThrowingReadOnlyCache())
    with pytest.raises(RuntimeError, match="boom"):
        collection.decrypt("item", bytearray(16))
    with pytest.raises(RuntimeError, match="boom"):
        collection.decrypt_to_str("item")
    with pytest.raises(RuntimeError, match="boom"):
        collection.find_max_decrypted_length("item")
