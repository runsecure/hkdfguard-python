from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections.abc import Awaitable, Buffer, Callable, Coroutine, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from hkdfguard.abstractions import KeyRing, KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache import InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection, RemoteSecretCache, SecretNameMatching, SecretValueSink
from hkdfguard.cache._secret_names import entry_name, secret_name
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.diagnostics import AttributeNames, HkdfGuardEventId, HkdfGuardLog, HkdfGuardTelemetry, MetricNames, SpanNames
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

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


@pytest.fixture
def ring() -> Iterator[DefaultKeyRing]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
        yield ring


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


class FakeRemoteSecretCache(RemoteSecretCache):
    """A RemoteSecretCache over an in-memory dict, matched as ``matching`` says. Names are valid
    unless they are empty or hold a ':'. Every fetch is recorded, and on_fetch or on_fetch_async can
    replace one."""

    def __init__(self, ring: KeyRing, matching: SecretNameMatching = SecretNameMatching.EXACT, logger: logging.Logger | None = None) -> None:
        super().__init__(ring, matching, logger)
        self.matching = matching
        self.secrets: dict[str, str] = {}
        # Every name _fetch was called with, in order.
        self.fetches: list[str] = []
        # Every name _fetch_async was called with, in order - whether or not it went on to call _fetch.
        self.async_fetches: list[str] = []
        self.on_fetch: Callable[[str, SecretValueSink], None] | None = None
        self.on_fetch_async: Callable[[str, SecretValueSink], Awaitable[None]] | None = None
        self.default_key_to_read: str | None = None

    def set(self, name: str, value: str) -> None:
        self.secrets[self._key(name)] = value

    def _key(self, name: str) -> str:
        return name if self.matching is SecretNameMatching.EXACT else name.lower()

    def _default_key(self) -> str | None:
        return self.default_key_to_read

    def _is_valid_name(self, name: str) -> bool:
        return bool(name) and ":" not in name

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        self.fetches.append(name)
        if self.on_fetch is not None:
            self.on_fetch(name, value)
            return
        secret = self.secrets.get(self._key(name))
        if secret is not None:
            value.set_text(secret)

    async def _fetch_async(self, name: str, value: SecretValueSink) -> None:
        self.async_fetches.append(name)
        if self.on_fetch_async is not None:
            await self.on_fetch_async(name, value)
        else:
            await super()._fetch_async(name, value)


class UnreachableError(Exception):
    """Raised by a fetch, as a client's failure would be."""


class Fatal(BaseException):
    """Raised by a fetch: not an Exception, as Java's Error isn't a RuntimeException."""


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def recording_logger() -> tuple[logging.Logger, list[logging.LogRecord]]:
    logger = logging.Logger("recording", logging.DEBUG)
    handler = RecordingHandler()
    logger.addHandler(handler)
    return logger, handler.records


def decrypt_string(cache: ProtectedReadOnlyCache, name: str, size: int = 64) -> str:
    result = bytearray(size)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_string_async(cache: ProtectedReadOnlyCache, name: str, size: int = 64) -> str:
    result = bytearray(size)
    return result[: await cache.decrypt_async(name, result)].decode()


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Runs a test's coroutine, with a timeout so a hang fails instead of stalling the run."""

    async def bounded() -> T:
        return await asyncio.wait_for(coroutine, 10)

    return asyncio.run(bounded())


def utf8(text: str) -> bytearray:
    return bytearray(text.encode())


class Gate:
    """An on_fetch_async that waits for release, then hands over a value; started is set once it is running."""

    def __init__(self, cache: FakeRemoteSecretCache, value: str) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = False
        self.value = value
        cache.on_fetch_async = self._fetch

    async def _fetch(self, name: str, sink: SecretValueSink) -> None:
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        sink.set_text(self.value)


# --- Fetch on miss, name matching, SecretValueSink --------------------------------------------


def test_a_miss_fetches_once_then_every_lookup_is_served_from_the_cache(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.set("item", "value")

    assert (cache.find_max_decrypted_length("item") or 0) >= 5
    assert decrypt_string(cache, "item") == "value"
    assert decrypt_string(cache, "item") == "value"
    assert cache.fetches == ["item"]


def test_ignore_ascii_case_spellings_differing_in_case_share_one_entry_and_one_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring, SecretNameMatching.IGNORE_ASCII_CASE)
    cache.set("Db-Password", "value")

    assert decrypt_string(cache, "db-password") == "value"
    assert decrypt_string(cache, "DB-PASSWORD") == "value"
    assert cache.fetches == ["db-password"]


def test_exact_spellings_differing_in_case_are_separate_entries_fetched_by_their_own_spelling(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.set("prod/Db", "upper")
    cache.set("prod/db", "lower")

    assert decrypt_string(cache, "prod/Db") == "upper"
    assert decrypt_string(cache, "prod/db") == "lower"
    assert cache.decrypt("PROD/DB", bytearray(16)) == 0
    assert decrypt_string(cache, "prod/Db") == "upper"
    assert cache.fetches == ["prod/Db", "prod/db", "PROD/DB"]


def test_exact_a_name_holding_the_case_marker_is_missing_without_a_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    assert cache.decrypt("prod/!db", bytearray(16)) == 0
    assert cache.fetches == []


def test_ignore_ascii_case_a_name_holding_the_case_marker_is_fetched_like_any_other(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring, SecretNameMatching.IGNORE_ASCII_CASE)
    cache.set("bang!", "value")

    assert decrypt_string(cache, "bang!") == "value"


@pytest.mark.parametrize("name", ["prod/Db", "ALLCAPS", "a/B_c+D=e.F@g-H", "nocaps"])
def test_entry_name_round_trips_and_holds_no_upper_case(name: str) -> None:
    escaped = entry_name(name)

    assert not any("A" <= c <= "Z" for c in escaped)
    assert secret_name(escaped) == name


def test_an_invalid_name_is_missing_without_a_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    assert cache.decrypt("Connection:Strings", bytearray(16)) == 0
    assert cache.find_max_decrypted_length("Connection:Strings") is None
    assert cache.fetches == []


def test_a_none_name_is_refused(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    with pytest.raises(TypeError):
        cache.decrypt(None, bytearray(16))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        cache.find_max_decrypted_length(None)  # type: ignore[arg-type]


def test_a_fetch_that_sets_nothing_is_missing_and_is_fetched_again_next_time(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    assert cache.decrypt("later", bytearray(16)) == 0
    cache.set("later", "now here")
    assert decrypt_string(cache, "later") == "now here"
    assert len(cache.fetches) == 2


def test_an_empty_value_is_missing(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = lambda name, sink: sink.set_bytes(bytearray())
    assert cache.decrypt("empty", bytearray(16)) == 0

    cache.on_fetch = lambda name, sink: sink.set_text("")
    assert cache.decrypt("empty", bytearray(16)) == 0


def test_set_bytes_stores_the_bytes_and_zeroes_them(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    given = bytearray(b"\x01\x02\x03")
    cache.on_fetch = lambda name, sink: sink.set_bytes(given)

    result = bytearray(16)
    assert result[: cache.decrypt("binary", result)] == b"\x01\x02\x03"
    assert given == bytearray(3)


def test_set_bytes_takes_a_view_of_part_of_a_buffer_and_zeroes_only_that_part(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    buffer = bytearray(b"xxsecretyy")
    cache.on_fetch = lambda name, sink: sink.set_bytes(memoryview(buffer)[2:8])

    assert decrypt_string(cache, "item") == "secret"
    assert buffer == b"xx\0\0\0\0\0\0yy"


def test_immutable_bytes_are_refused_by_every_setter_because_they_cannot_be_zeroed(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    def fetch(name: str, sink: SecretValueSink) -> None:
        with pytest.raises(TypeError, match="can't be zeroed"):
            sink.set_bytes(b"immutable")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="can't be zeroed"):
            sink.set_key_bytes("k", b"immutable")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="can't be zeroed"):
            sink.set_bytes_with_json_keys(memoryview(b"{}"))
        sink.set_text("fine")

    cache.on_fetch = fetch
    assert decrypt_string(cache, "item") == "fine"


def test_set_text_of_a_large_value_round_trips(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    large = "é-秘密-" * 1500
    cache.set("large", large)

    assert decrypt_string(cache, "large", cache.find_max_decrypted_length("large") or 0) == large


def test_setting_a_second_value_raises_and_nothing_is_cached(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    def fetch(name: str, sink: SecretValueSink) -> None:
        sink.set_text("first")
        sink.set_text("second")

    cache.on_fetch = fetch
    with pytest.raises(RuntimeError, match="already been set"):
        cache.decrypt("item", bytearray(16))

    cache.on_fetch = None
    assert cache.decrypt("item", bytearray(16)) == 0


def test_a_sink_kept_past_its_fetch_refuses_every_value(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    kept: list[SecretValueSink] = []
    cache.on_fetch = lambda name, sink: kept.append(sink)
    assert cache.decrypt("item", bytearray(16)) == 0

    given = bytearray(b"\x09")
    with pytest.raises(RuntimeError, match="already returned"):
        kept[0].set_bytes(given)
    assert given == bytearray(1)
    with pytest.raises(RuntimeError, match="already returned"):
        kept[0].set_text("late")

    def failing(name: str, sink: SecretValueSink) -> None:
        kept.append(sink)
        raise UnreachableError("unreachable")

    cache.on_fetch = failing
    with pytest.raises(UnreachableError):
        cache.decrypt("item", bytearray(16))
    with pytest.raises(RuntimeError, match="already returned"):
        kept[-1].set_text("late")


def test_a_fetch_failure_propagates_and_is_retried_on_the_next_lookup(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    def failing(name: str, sink: SecretValueSink) -> None:
        raise UnreachableError("unreachable")

    cache.on_fetch = failing
    with pytest.raises(UnreachableError):
        cache.decrypt("item", bytearray(16))

    cache.on_fetch = None
    cache.set("item", "value")
    assert decrypt_string(cache, "item") == "value"
    assert len(cache.fetches) == 2


def test_a_fetch_raising_a_base_exception_propagates_it(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    def fatal(name: str, sink: SecretValueSink) -> None:
        raise Fatal

    cache.on_fetch = fatal
    with pytest.raises(Fatal):
        cache.decrypt("item", bytearray(16))
    cache.on_fetch = None
    assert cache.decrypt("item", bytearray(16)) == 0


def test_concurrent_misses_on_one_name_share_one_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    release = threading.Event()

    def fetch(name: str, sink: SecretValueSink) -> None:
        assert release.wait(10)
        sink.set_text("value")

    cache.on_fetch = fetch
    with ThreadPoolExecutor(8) as pool:
        lookups = [pool.submit(decrypt_string, cache, "shared") for _ in range(8)]
        time.sleep(0.2)
        release.set()
        assert [lookup.result(10) for lookup in lookups] == ["value"] * 8
    assert len(cache.fetches) == 1


def test_a_waiter_on_a_failed_fetch_gets_the_same_failure(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    started = threading.Event()
    release = threading.Event()

    def fetch(name: str, sink: SecretValueSink) -> None:
        started.set()
        assert release.wait(10)
        raise UnreachableError("shared failure")

    cache.on_fetch = fetch
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(decrypt_string, cache, "shared")
        assert started.wait(10)
        second = pool.submit(decrypt_string, cache, "shared")
        time.sleep(0.1)
        release.set()

        first_failure, second_failure = first.exception(10), second.exception(10)
    assert isinstance(first_failure, UnreachableError) and first_failure is second_failure
    assert len(cache.fetches) == 1


def test_with_sensitive_logging_a_fetch_logs_the_secrets_own_name_and_a_failure_logs_an_error(ring: DefaultKeyRing, sensitive: None) -> None:
    logger, records = recording_logger()
    cache = FakeRemoteSecretCache(ring, SecretNameMatching.EXACT, logger)
    cache.set("prod/Item", "never-logged")

    assert decrypt_string(cache, "prod/Item") == "never-logged"

    def failing(name: str, sink: SecretValueSink) -> None:
        raise UnreachableError("boom")

    cache.on_fetch = failing
    with pytest.raises(UnreachableError):
        cache.decrypt("other", bytearray(16))

    # The secret's own spelling, not its escaped entry name.
    assert any(r.levelno == logging.DEBUG and getattr(r, HkdfGuardLog.EVENT_ID_KEY) == HkdfGuardEventId.SENSITIVE_OPERATION_LOGGED
               and "prod/Item" in r.getMessage() for r in records)
    assert any(r.levelno == logging.ERROR and r.exc_info is not None and isinstance(r.exc_info[1], UnreachableError) for r in records)
    assert not any("never-logged" in r.getMessage() for r in records)


def test_without_sensitive_logging_only_failures_are_logged(ring: DefaultKeyRing) -> None:
    logger, records = recording_logger()
    cache = FakeRemoteSecretCache(ring, SecretNameMatching.EXACT, logger)
    cache.set("item", "value")

    assert decrypt_string(cache, "item") == "value"
    assert records == []


def test_with_the_default_logger_fetches_and_failures_still_work_with_sensitive_logging(ring: DefaultKeyRing, sensitive: None) -> None:
    cache = FakeRemoteSecretCache(ring, SecretNameMatching.IGNORE_ASCII_CASE)
    cache.set("item", "value")
    assert decrypt_string(cache, "item") == "value"

    def failing(name: str, sink: SecretValueSink) -> None:
        raise UnreachableError("boom")

    cache.on_fetch = failing
    with pytest.raises(UnreachableError):
        cache.decrypt("other", bytearray(16))


def test_the_constructor_refuses_a_none_ring_or_matching(ring: DefaultKeyRing) -> None:
    with pytest.raises(TypeError):
        FakeRemoteSecretCache(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FakeRemoteSecretCache(ring, None)  # type: ignore[arg-type]


def test_a_stored_value_is_bound_to_its_entry_name(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = lambda name, sink: sink.set_bytes(utf8("secret"))

    assert decrypt_string(cache, "a") == "secret"
    assert cache.find_max_decrypted_length("b#k") is None


def test_each_fetch_is_a_populate_span_counted_as_success_not_found_or_error(ring: DefaultKeyRing, sensitive: None) -> None:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    HkdfGuardTelemetry.set_tracer_provider(tracer_provider)
    HkdfGuardTelemetry.set_meter_provider(meter_provider)
    try:
        cache = FakeRemoteSecretCache(ring)
        cache.set("Found", "value")
        assert decrypt_string(cache, "Found") == "value"
        assert cache.decrypt("missing", bytearray(16)) == 0

        def failing(name: str, sink: SecretValueSink) -> None:
            raise UnreachableError("boom")

        cache.on_fetch = failing
        with pytest.raises(UnreachableError):
            cache.decrypt("failing", bytearray(16))

        found, missing, failed = [s for s in exporter.get_finished_spans() if s.name == SpanNames.Cache.POPULATE]
        assert found.instrumentation_scope is not None and found.instrumentation_scope.name == HkdfGuardTelemetry.CACHE.source_name
        assert any(e.attributes and e.attributes.get(AttributeNames.NAME) == "Found" for e in found.events)
        assert found.status.status_code != StatusCode.ERROR and missing.status.status_code != StatusCode.ERROR
        assert failed.status.status_code == StatusCode.ERROR
        assert [e.name for e in failed.events].count("exception") == 1

        data = reader.get_metrics_data()
        assert data is not None
        points = [(dict(p.attributes or {}), p.value) for rm in data.resource_metrics for sm in rm.scope_metrics
                  for m in sm.metrics if m.name == MetricNames.Cache.OPERATIONS for p in m.data.data_points if isinstance(p, NumberDataPoint)]
        for result in ("success", "not_found", "error"):
            assert ({AttributeNames.OPERATION_NAME: SpanNames.Cache.POPULATE, AttributeNames.RESULT: result}, 1) in points
    finally:
        HkdfGuardTelemetry.set_tracer_provider(None)
        HkdfGuardTelemetry.set_meter_provider(None)
        meter_provider.shutdown()


# --- Names holding a key ----------------------------------------------------------------------

# A key/value secret as AWS Secrets Manager's console stores one.
KEY_VALUE_SECRET = """{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential"
}"""


def set_json(json: str) -> Callable[[str, SecretValueSink], None]:
    return lambda name, sink: sink.set_bytes_with_json_keys(utf8(json))


def test_one_fetch_caches_the_whole_value_and_every_key(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = set_json(KEY_VALUE_SECRET)

    assert decrypt_string(cache, "creds#api-credential-21", 512) == "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q=="
    assert decrypt_string(cache, "creds#test-credential-1", 512) == "This is my first credential"
    assert decrypt_string(cache, "creds#service-credential-3", 512) == "This is my third credential"
    assert decrypt_string(cache, "creds#domain-credential-17", 512) == "fakedomain/thiscredential"
    assert decrypt_string(cache, "creds", 512) == KEY_VALUE_SECRET
    assert cache.fetches == ["creds"]


def test_concurrent_misses_on_different_keys_share_one_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    release = threading.Event()
    json = '{"a":"1","b":"2","c":"3"}'

    def fetch(name: str, sink: SecretValueSink) -> None:
        assert release.wait(10)
        sink.set_bytes_with_json_keys(utf8(json))

    cache.on_fetch = fetch
    names = ["s#a", "s#b", "s#c", "s"]
    with ThreadPoolExecutor(4) as pool:
        lookups = [pool.submit(decrypt_string, cache, name) for name in names]
        time.sleep(0.2)
        release.set()
        assert [lookup.result(10) for lookup in lookups] == ["1", "2", "3", json]
    assert len(cache.fetches) == 1


def test_a_key_the_secret_doesnt_hold_is_missing_and_fetches_again_without_replacing_what_is_cached(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = set_json('{"a":"first"}')
    assert decrypt_string(cache, "s#a") == "first"

    assert cache.decrypt("s#b", bytearray(16)) == 0

    cache.on_fetch = set_json('{"a":"second","b":"added"}')
    assert decrypt_string(cache, "s#b") == "added"
    assert decrypt_string(cache, "s#a") == "first"
    assert len(cache.fetches) == 3


def test_keys_are_matched_exactly_even_where_secret_names_ignore_case(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring, SecretNameMatching.IGNORE_ASCII_CASE)
    cache.on_fetch = set_json('{"Key":"upper","key":"lower"}')

    assert decrypt_string(cache, "Db#Key") == "upper"
    assert decrypt_string(cache, "DB#key") == "lower"
    assert decrypt_string(cache, "db#Key") == "upper"
    assert cache.decrypt("db#KEY", bytearray(16)) == 0
    assert cache.fetches == ["Db", "db"]


def test_under_exact_matching_secret_names_and_keys_are_both_exact(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = lambda name, sink: sink.set_bytes_with_json_keys(utf8('{"Pass":"' + name + '"}'))

    assert decrypt_string(cache, "Prod/Db#Pass") == "Prod/Db"
    assert decrypt_string(cache, "prod/db#Pass") == "prod/db"
    assert cache.decrypt("prod/db#pass", bytearray(16)) == 0


@pytest.mark.parametrize("name", ["s#", "s#a#b", "s#a b", "s#bang!", "s#café", "#key", "in:valid#key"])
def test_a_name_whose_secret_or_key_isnt_one_is_missing_without_a_fetch(ring: DefaultKeyRing, name: str) -> None:
    cache = FakeRemoteSecretCache(ring)

    assert cache.decrypt(name, bytearray(16)) == 0
    assert cache.find_max_decrypted_length(name) is None
    assert cache.fetches == []


def test_is_valid_key_accepts_printable_ascii_but_space_bang_and_hash_up_to_the_limit() -> None:
    assert RemoteSecretCache.is_valid_key("a")
    assert RemoteSecretCache.is_valid_key("ConnectionStrings:Admin")
    assert RemoteSecretCache.is_valid_key("\"$%&'()*+,-./0-9;<=>?@A-Z[\\]^_`a-z{|}~")
    assert RemoteSecretCache.is_valid_key("k" * RemoteSecretCache.MAX_KEY_LENGTH)
    assert not RemoteSecretCache.is_valid_key("k" * (RemoteSecretCache.MAX_KEY_LENGTH + 1))
    assert not RemoteSecretCache.is_valid_key(None)
    assert not RemoteSecretCache.is_valid_key("")
    assert not RemoteSecretCache.is_valid_key("a b")
    assert not RemoteSecretCache.is_valid_key("a!")
    assert not RemoteSecretCache.is_valid_key("a#")
    assert not RemoteSecretCache.is_valid_key("tab\t")
    assert not RemoteSecretCache.is_valid_key("del\x7f")
    assert (RemoteSecretCache.KEY_SEPARATOR, RemoteSecretCache.MAX_KEY_LENGTH) == ("#", 256)


def test_with_a_default_key_a_name_without_one_reads_that_key_not_the_whole_value(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.default_key_to_read = "value"

    def fetch(name: str, sink: SecretValueSink) -> None:
        sink.set_text("the whole value")
        sink.set_key_bytes("value", utf8("the default key"))
        sink.set_key_bytes("other", utf8("another key"))

    cache.on_fetch = fetch
    assert decrypt_string(cache, "s") == "the default key"
    assert decrypt_string(cache, "s#value") == "the default key"
    assert decrypt_string(cache, "s#other") == "another key"
    assert len(cache.fetches) == 1


def test_set_key_bytes_zeroes_what_its_given_and_refuses_an_invalid_key(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    given = bytearray(b"\x01\x02\x03")
    refused = bytearray(b"\x04\x05\x06")

    def fetch(name: str, sink: SecretValueSink) -> None:
        with pytest.raises(ValueError, match="isn't a key"):
            sink.set_key_bytes("not a key", refused)
        with pytest.raises(ValueError, match="isn't a key"):
            sink.set_key_bytes(None, refused)  # type: ignore[arg-type]
        sink.set_key_bytes("k", given)

    cache.on_fetch = fetch
    result = bytearray(16)
    assert result[: cache.decrypt("s#k", result)] == b"\x01\x02\x03"
    assert given == bytearray(3)
    assert refused == bytearray(3)


def test_setting_a_key_twice_raises_and_nothing_is_cached(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    def fetch(name: str, sink: SecretValueSink) -> None:
        sink.set_key_bytes("k", utf8("first"))
        sink.set_text("whole")
        sink.set_key_bytes("k", utf8("second"))

    cache.on_fetch = fetch
    with pytest.raises(RuntimeError, match="already been set"):
        cache.decrypt("s#k", bytearray(16))

    cache.on_fetch = None
    assert cache.decrypt("s", bytearray(16)) == 0
    assert cache.decrypt("s#k", bytearray(16)) == 0


def test_an_empty_key_is_missing_and_can_still_be_set_afterwards(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    def fetch(name: str, sink: SecretValueSink) -> None:
        sink.set_key_bytes("k", bytearray())
        sink.set_key_bytes("k", utf8("set"))

    cache.on_fetch = fetch
    assert decrypt_string(cache, "s#k") == "set"


def test_a_sink_kept_past_its_fetch_refuses_keys(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    kept: list[SecretValueSink] = []
    cache.on_fetch = lambda name, sink: kept.append(sink)
    assert cache.decrypt("s#k", bytearray(16)) == 0

    given = bytearray(b"\x09")
    with pytest.raises(RuntimeError):
        kept[0].set_key_bytes("k", given)
    assert given == bytearray(1)
    json = utf8('{"k":"v"}')
    with pytest.raises(RuntimeError):
        kept[0].set_bytes_with_json_keys(json)
    assert json == bytearray(len(json))


def test_json_members_are_cached_as_their_text_or_left_out(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = set_json('{"text":"a\\"b\\\\cé\\n","int":3306,"real":-1.5e3,"yes":true,"no":false,\n'
                              ' "null":null,"object":{"x":"y"},"array":["z"],"empty":"","bad key":"x","bang!":"x","Ascaped":"name"}\n')

    assert decrypt_string(cache, "s#text") == 'a"b\\cé\n'
    assert decrypt_string(cache, "s#int") == "3306"
    assert decrypt_string(cache, "s#real") == "-1.5e3"
    assert decrypt_string(cache, "s#yes") == "true"
    assert decrypt_string(cache, "s#no") == "false"
    assert decrypt_string(cache, "s#Ascaped") == "name"
    for key in ("null", "object", "array", "empty", "x"):
        assert cache.decrypt("s#" + key, bytearray(16)) == 0


@pytest.mark.parametrize("value", [
    "plain text",
    '["a","b"]',
    '"a json string"',
    "42",
    '{"k":"unterminated',
    '{"k":"v"} trailing',
    '{"k":"v"}{"k":"w"}',
    '{"k":"v", // a comment\n"j":"w"}',
    '{"k":"\\ud800"}',
])
def test_a_value_that_isnt_one_json_object_is_cached_whole_only(ring: DefaultKeyRing, value: str) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = set_json(value)

    assert decrypt_string(cache, "s") == value
    assert cache.decrypt("s#k", bytearray(16)) == 0
    assert cache.decrypt("s#a", bytearray(16)) == 0


def test_a_json_object_with_whitespace_around_is_split(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = set_json('  \r\n{"k":"v"}\n  ')

    assert decrypt_string(cache, "s#k") == "v"


def test_a_duplicated_key_is_refused_without_naming_it_and_nothing_is_cached(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = set_json('{"dup-key-name":"a","other":"b","dup-key-name":"c"}')

    # The key is part of a name, which is logged only with sensitive logging on; an error log carries the message.
    with pytest.raises(InvalidSecretDataError) as error:
        cache.decrypt("s#other", bytearray(16))
    assert "dup-key-name" not in str(error.value)

    cache.on_fetch = None
    assert cache.decrypt("s", bytearray(16)) == 0


def test_set_bytes_with_json_keys_zeroes_what_its_given(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    given = utf8('{"k":"v"}')
    cache.on_fetch = lambda name, sink: sink.set_bytes_with_json_keys(given)

    assert decrypt_string(cache, "s#k") == "v"
    assert given == bytearray(len(given))


def test_an_empty_value_with_json_keys_is_missing(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.on_fetch = lambda name, sink: sink.set_bytes_with_json_keys(bytearray())

    assert cache.decrypt("s", bytearray(16)) == 0


# --- Asynchronous lookups ---------------------------------------------------------------------


def test_async_a_miss_fetches_through_fetch_async_then_every_lookup_is_served_from_the_cache(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    cache.set("item", "value")

    async def scenario() -> None:
        assert (await cache.find_max_decrypted_length_async("item") or 0) >= 5
        assert await decrypt_string_async(cache, "item") == "value"

    run(scenario())
    assert decrypt_string(cache, "item") == "value"
    # _fetch_async's default calls _fetch.
    assert cache.async_fetches == ["item"]
    assert cache.fetches == ["item"]


def test_the_default_fetch_async_runs_fetch_in_a_worker_thread(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    threads: list[threading.Thread] = []

    def fetch(name: str, sink: SecretValueSink) -> None:
        threads.append(threading.current_thread())
        sink.set_text("value")

    cache.on_fetch = fetch
    assert run(decrypt_string_async(cache, "item")) == "value"
    assert threads[0] is not threading.current_thread()


def test_cancelling_a_lookup_leaves_the_default_fetchs_thread_running_but_refuses_what_it_hands_over(ring: DefaultKeyRing) -> None:
    # Java interrupts the fetch's virtual thread; Python can't interrupt a thread, so the fetch runs on
    # and the closed sink refuses its value.
    cache = FakeRemoteSecretCache(ring)
    started, release, done = threading.Event(), threading.Event(), threading.Event()
    refused: list[RuntimeError] = []

    def fetch(name: str, sink: SecretValueSink) -> None:
        started.set()
        release.wait(10)
        try:
            sink.set_text("late")
        except RuntimeError as error:
            refused.append(error)
        done.set()

    cache.on_fetch = fetch

    async def scenario() -> None:
        lookup = asyncio.create_task(decrypt_string_async(cache, "item"))
        assert await asyncio.to_thread(started.wait, 10)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup
        release.set()
        assert await asyncio.to_thread(done.wait, 10)

    run(scenario())
    assert len(refused) == 1
    cache.on_fetch = None
    assert cache.decrypt("item", bytearray(16)) == 0


def test_an_overridden_fetch_async_is_used_and_fetch_is_not(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def fetch(name: str, sink: SecretValueSink) -> None:
        await asyncio.sleep(0)
        sink.set_text("async " + name)

    cache.on_fetch_async = fetch
    assert run(decrypt_string_async(cache, "item")) == "async item"
    assert cache.fetches == []


def test_keys_handed_over_asynchronously_are_cached_from_one_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def fetch(name: str, sink: SecretValueSink) -> None:
        await asyncio.sleep(0)
        sink.set_bytes_with_json_keys(utf8('{"user":"app","pass":"s3cret"}'))

    cache.on_fetch_async = fetch

    async def scenario() -> None:
        assert await decrypt_string_async(cache, "db#pass") == "s3cret"
        assert await decrypt_string_async(cache, "db#user") == "app"

    run(scenario())
    assert len(cache.async_fetches) == 1


def test_async_a_missing_secret_returns_zero_and_is_fetched_again(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def scenario() -> None:
        assert await cache.decrypt_async("later", bytearray(16)) == 0
        assert await cache.find_max_decrypted_length_async("later") is None
        cache.set("later", "now here")
        assert await decrypt_string_async(cache, "later") == "now here"

    run(scenario())
    assert len(cache.async_fetches) == 3


@pytest.mark.parametrize("name", ["in:valid", "s#bad key", "#key"])
def test_async_an_invalid_name_is_missing_without_a_fetch(ring: DefaultKeyRing, name: str) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def scenario() -> None:
        assert await cache.decrypt_async(name, bytearray(16)) == 0
        assert await cache.find_max_decrypted_length_async(name) is None

    run(scenario())
    assert cache.async_fetches == []


def test_async_a_none_name_is_refused(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    with pytest.raises(TypeError):
        run(cache.decrypt_async(None, bytearray(16)))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        run(cache.find_max_decrypted_length_async(None))  # type: ignore[arg-type]


def test_async_a_fetch_failure_propagates_and_is_retried_on_the_next_lookup(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def failing(name: str, sink: SecretValueSink) -> None:
        await asyncio.sleep(0)
        raise UnreachableError("unreachable")

    cache.on_fetch_async = failing
    with pytest.raises(UnreachableError):
        run(decrypt_string_async(cache, "item"))

    cache.on_fetch_async = None
    cache.set("item", "value")
    assert run(decrypt_string_async(cache, "item")) == "value"


def test_a_fetch_async_that_raises_before_awaiting_fails_the_lookup(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def failing(name: str, sink: SecretValueSink) -> None:
        raise UnreachableError("raised")

    cache.on_fetch_async = failing
    with pytest.raises(UnreachableError):
        run(decrypt_string_async(cache, "item"))


def test_a_fetchs_own_cancellation_is_a_failure_not_the_callers_cancellation(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def cancelled(name: str, sink: SecretValueSink) -> None:
        raise asyncio.CancelledError("A timeout inside the fetch.")

    cache.on_fetch_async = cancelled

    async def scenario() -> None:
        lookup = asyncio.create_task(decrypt_string_async(cache, "item"))
        with pytest.raises(RuntimeError) as error:
            await lookup
        assert isinstance(error.value.__cause__, asyncio.CancelledError)
        assert str(error.value.__cause__) == "A timeout inside the fetch."
        assert not lookup.cancelled()

    run(scenario())


def test_a_synchronous_waiter_on_a_fetch_cancelling_itself_gets_that_failure(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def scenario() -> None:
        started, gate = asyncio.Event(), asyncio.Event()

        async def fetch(name: str, sink: SecretValueSink) -> None:
            started.set()
            await gate.wait()
            raise asyncio.CancelledError("A timeout inside the fetch.")

        cache.on_fetch_async = fetch
        owner = asyncio.create_task(decrypt_string_async(cache, "shared"))
        await started.wait()
        waiter = asyncio.create_task(asyncio.to_thread(decrypt_string, cache, "shared"))
        await asyncio.sleep(0.1)
        gate.set()

        with pytest.raises(RuntimeError):
            await owner
        with pytest.raises(RuntimeError):
            await waiter

    run(scenario())
    assert len(cache.async_fetches) == 1


def test_concurrent_sync_and_async_lookups_share_one_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def scenario() -> None:
        gate = Gate(cache, "value")
        first = asyncio.create_task(decrypt_string_async(cache, "shared"))
        await gate.started.wait()
        second = asyncio.create_task(decrypt_string_async(cache, "shared"))
        third = asyncio.create_task(asyncio.to_thread(decrypt_string, cache, "shared"))
        fourth = asyncio.create_task(asyncio.to_thread(decrypt_string, cache, "shared"))
        await asyncio.sleep(0.1)
        gate.release.set()

        assert list(await asyncio.gather(first, second, third, fourth)) == ["value"] * 4

    run(scenario())
    assert len(cache.async_fetches) == 1
    assert cache.fetches == []


def test_a_sync_lookup_starting_the_fetch_is_joined_by_async_ones(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    release = threading.Event()

    def fetch(name: str, sink: SecretValueSink) -> None:
        assert release.wait(10)
        sink.set_text("value")

    cache.on_fetch = fetch

    async def scenario() -> None:
        sync = asyncio.create_task(asyncio.to_thread(decrypt_string, cache, "shared"))
        while not cache.fetches:
            await asyncio.sleep(0.01)
        asynchronous = asyncio.create_task(decrypt_string_async(cache, "shared"))
        await asyncio.sleep(0.1)
        release.set()

        assert list(await asyncio.gather(sync, asynchronous)) == ["value", "value"]

    run(scenario())
    assert len(cache.fetches) == 1
    assert cache.async_fetches == []


def test_lookups_on_different_event_loops_share_one_fetch(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    release = threading.Event()

    def fetch(name: str, sink: SecretValueSink) -> None:
        assert release.wait(10)
        sink.set_text("value")

    cache.on_fetch = fetch
    with ThreadPoolExecutor(3) as pool:
        lookups = [pool.submit(run, decrypt_string_async(cache, "shared")) for _ in range(2)]
        lookups.append(pool.submit(decrypt_string, cache, "shared"))
        time.sleep(0.2)
        release.set()
        assert [lookup.result(10) for lookup in lookups] == ["value"] * 3
    assert len(cache.fetches) == 1


def test_an_async_joiner_of_a_failed_fetch_gets_the_failure(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def scenario() -> None:
        gate = asyncio.Event()

        async def fetch(name: str, sink: SecretValueSink) -> None:
            await gate.wait()
            raise UnreachableError("shared failure")

        cache.on_fetch_async = fetch
        owner = asyncio.create_task(decrypt_string_async(cache, "shared"))
        joiner = asyncio.create_task(decrypt_string_async(cache, "shared"))
        await asyncio.sleep(0)
        gate.set()

        results = await asyncio.gather(owner, joiner, return_exceptions=True)
        assert all(isinstance(result, UnreachableError) for result in results)

    run(scenario())
    assert len(cache.async_fetches) == 1


def test_a_joiner_cancelling_its_wait_leaves_the_fetch_running_for_the_others(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def scenario() -> None:
        gate = Gate(cache, "value")
        owner = asyncio.create_task(decrypt_string_async(cache, "shared"))
        await gate.started.wait()
        joiner = asyncio.create_task(decrypt_string_async(cache, "shared"))
        await asyncio.sleep(0.05)
        joiner.cancel()

        with pytest.raises(asyncio.CancelledError):
            await joiner
        gate.release.set()
        assert await owner == "value"
        assert not gate.cancelled

    run(scenario())
    assert len(cache.async_fetches) == 1


@pytest.mark.parametrize("synchronous_joiner", [False, True])
def test_when_the_lookup_that_started_a_fetch_cancels_it_a_joiner_fetches_again(ring: DefaultKeyRing, synchronous_joiner: bool) -> None:
    cache = FakeRemoteSecretCache(ring)

    async def scenario() -> None:
        gate = Gate(cache, "never")
        owner = asyncio.create_task(decrypt_string_async(cache, "shared"))
        await gate.started.wait()
        joiner = asyncio.create_task(asyncio.to_thread(decrypt_string, cache, "shared") if synchronous_joiner
                                     else decrypt_string_async(cache, "shared"))
        await asyncio.sleep(0.1)

        # The fetch the joiner starts once the first is cancelled answers at once.
        async def second(name: str, sink: SecretValueSink) -> None:
            sink.set_text("second fetch")

        cache.on_fetch_async = second
        cache.on_fetch = lambda name, sink: sink.set_text("second fetch")
        owner.cancel()

        with pytest.raises(asyncio.CancelledError):
            await owner
        assert gate.cancelled
        assert await joiner == "second fetch"

    run(scenario())


def test_a_sink_used_after_its_fetch_was_cancelled_refuses_the_value(ring: DefaultKeyRing) -> None:
    cache = FakeRemoteSecretCache(ring)
    kept: list[SecretValueSink] = []

    async def fetch(name: str, sink: SecretValueSink) -> None:
        kept.append(sink)
        await asyncio.Event().wait()

    cache.on_fetch_async = fetch

    async def scenario() -> None:
        lookup = asyncio.create_task(decrypt_string_async(cache, "item"))
        while not kept:
            await asyncio.sleep(0)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup

        with pytest.raises(RuntimeError):
            kept[0].set_text("late")
        cache.on_fetch_async = None
        assert await cache.decrypt_async("item", bytearray(16)) == 0

    run(scenario())


def test_in_a_collection_a_remote_source_is_asked_asynchronously(ring: DefaultKeyRing) -> None:
    remote = FakeRemoteSecretCache(ring)

    async def fetch(name: str, sink: SecretValueSink) -> None:
        await asyncio.sleep(0)
        sink.set_text("remote value")

    remote.on_fetch_async = fetch
    local = ProtectedCache(ring)
    local.add("local", "local value")
    collection = ProtectedCacheCollection().add(local).add(remote)

    async def scenario() -> None:
        assert await decrypt_string_async(collection, "local") == "local value"
        assert await decrypt_string_async(collection, "remote") == "remote value"
        assert (await collection.find_max_decrypted_length_async("remote") or 0) >= len("remote value")
        assert (await collection.find_max_decrypted_length_async("local") or 0) >= len("local value")
        assert await collection.find_max_decrypted_length_async("in:valid") is None

    run(scenario())
    assert remote.async_fetches == ["remote"]
    assert remote.fetches == []


def test_in_a_collection_cancelling_a_lookup_cancels_the_remote_fetch(ring: DefaultKeyRing) -> None:
    remote = FakeRemoteSecretCache(ring)
    collection = ProtectedCacheCollection().add(remote)

    async def scenario() -> None:
        gate = Gate(remote, "value")
        lookup = asyncio.create_task(collection.decrypt_async("item", bytearray(16)))
        await gate.started.wait()
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup
        assert gate.cancelled

    run(scenario())


# --- ProtectedCacheCollection's asynchronous lookups ------------------------------------------


class AsyncOnlyCache(ProtectedReadOnlyCache):
    """A source whose decrypt_async waits until released, recording a cancellation, or raises."""

    def __init__(self, raised: Exception | None = None) -> None:
        self.raised = raised
        self.cancelled = False
        self.asked = 0

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        raise NotImplementedError

    def find_max_decrypted_length(self, name: str) -> int | None:
        raise NotImplementedError

    async def decrypt_async(self, name: str, result: WritableBuffer) -> int:
        self.asked += 1
        if self.raised is not None:
            raise self.raised
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return 0


def test_collection_decrypt_async_returns_from_the_first_source_that_has_it(ring: DefaultKeyRing) -> None:
    first, second = ProtectedCache(ring), ProtectedCache(ring)
    first.add("item", "from-first")
    second.add("item", "from-second")
    second.add("only-second", "second")
    collection = ProtectedCacheCollection().add(first).add(second)

    async def scenario() -> None:
        assert await decrypt_string_async(collection, "item") == "from-first"
        assert await decrypt_string_async(collection, "only-second") == "second"
        assert (await collection.find_max_decrypted_length_async("only-second") or 0) >= 6

    run(scenario())


def test_collection_decrypt_async_with_no_source_holding_it_returns_zero(ring: DefaultKeyRing) -> None:
    collection = ProtectedCacheCollection().add(ProtectedCache(ring))

    async def scenario() -> None:
        assert await collection.decrypt_async("missing", bytearray(16)) == 0
        assert await collection.find_max_decrypted_length_async("missing") is None
        assert await ProtectedCacheCollection().decrypt_async("missing", bytearray(16)) == 0

    run(scenario())


def test_collection_decrypt_async_when_a_source_fails_fails_for_every_member() -> None:
    class Throwing(ProtectedReadOnlyCache):
        def decrypt(self, name: str, result: WritableBuffer) -> int:
            raise RuntimeError("boom")

        def find_max_decrypted_length(self, name: str) -> int | None:
            raise RuntimeError("boom")

    collection = ProtectedCacheCollection().add(Throwing())
    with pytest.raises(RuntimeError, match="boom"):
        run(collection.decrypt_async("item", bytearray(16)))
    with pytest.raises(RuntimeError, match="boom"):
        run(collection.find_max_decrypted_length_async("item"))
    with pytest.raises(LookupError, match="raised"):
        run(ProtectedCacheCollection().add(AsyncOnlyCache(LookupError("raised"))).decrypt_async("item", bytearray(16)))


def test_collection_cancelling_a_lookup_cancels_the_source_being_asked_and_asks_no_more(ring: DefaultKeyRing) -> None:
    pending = AsyncOnlyCache()
    later = AsyncOnlyCache()
    collection = ProtectedCacheCollection().add(pending).add(later)

    async def scenario() -> None:
        lookup = asyncio.create_task(collection.decrypt_async("item", bytearray(16)))
        while not pending.asked:
            await asyncio.sleep(0)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup

    run(scenario())
    assert pending.cancelled
    assert later.asked == 0


def test_collection_decrypt_async_with_sensitive_logging_still_works(ring: DefaultKeyRing, sensitive: None) -> None:
    cache = ProtectedCache(ring)
    cache.add("item", "value")
    collection = ProtectedCacheCollection().add(cache)

    assert run(collection.decrypt_async("item", bytearray(16))) == 5
