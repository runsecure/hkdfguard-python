"""GoogleSecretManagerSecretCache against a fake Secret Manager - a gRPC server on the loopback
address - through a real SecretManagerServiceClient."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
import time
from collections.abc import Buffer, Callable, Coroutine, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import grpc
import pytest
from google.api_core import exceptions as core_exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud.secretmanager_v1 import AccessSecretVersionRequest, AccessSecretVersionResponse, SecretManagerServiceClient, SecretPayload
from google.cloud.secretmanager_v1.services.secret_manager_service.transports import SecretManagerServiceGrpcTransport
from hkdfguard.abstractions import CryptographicError, KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache import ProtectedCache, ProtectedCacheCollection
from hkdfguard.cache.googlesecretmanager import GoogleSecretManagerSecretCache
from hkdfguard.cache.googlesecretmanager import _cache as cache_module
from hkdfguard.cache.googlesecretmanager._capture import AccessedSecretVersion, ResponseCapture, crc32c
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

PROJECT_ID = "hkdfguard-test"
# Google answers with the project's number, not the ID it was asked with.
PROJECT_NUMBER = "123456789012"

# A key/value secret as AWS Secrets Manager's console stores one.
KEY_VALUE_SECRET = """{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}"""

_VERSION_NAME = re.compile(r"projects/([^/]+)/secrets/([^/]+)/versions/([^/]+)")


# --- Test doubles ---------------------------------------------------------------------------------


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


def new_key() -> DataEncryptionKey:
    return DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60))


class FakeSecretManager:
    """A stand-in for Secret Manager: a gRPC server on the loopback address implementing only
    AccessSecretVersion (any other call is recorded and answered UNIMPLEMENTED), reached through a
    real ``SecretManagerServiceClient``, so the client's channel, error mapping and metadata are as
    they would be against Google. Secret IDs are matched exactly, as Google matches them, and
    responses name the project by its number and carry a CRC32C, as Google's do for payloads added
    with one. Every call's resource name and metadata are recorded."""

    SERVICE = "google.cloud.secretmanager.v1.SecretManagerService"

    def __init__(self) -> None:
        self.secrets: dict[str, bytes] = {}
        self.accesses: list[str] = []
        self.metadata: list[dict[str, str]] = []
        self.unexpected_calls: list[str] = []
        # When set, every AccessSecretVersion fails with this status instead of answering.
        self.failure: tuple[grpc.StatusCode, str] | None = None
        # Statuses the next calls fail with, one each, before failure and the secrets are consulted.
        self.next_failures: list[grpc.StatusCode] = []
        # Runs inside every AccessSecretVersion before it answers, e.g. to hold it open.
        self.on_get: Callable[[], None] | None = None
        # Rewrites a response before it is sent.
        self.tamper: Callable[[AccessSecretVersionResponse], AccessSecretVersionResponse] | None = None
        # Sent as the response's bytes instead, when set.
        self.raw: bytes | None = None
        # Never answer, until the client cancels the call (or release is set).
        self.hang = False
        self.release = threading.Event()
        self.received = threading.Event()
        self.cancelled = threading.Event()

        fake = self

        class Handler(grpc.GenericRpcHandler):  # type: ignore[misc]
            def service(self, handler_call_details: Any) -> Any:
                if handler_call_details.method == f"/{FakeSecretManager.SERVICE}/AccessSecretVersion":
                    return grpc.unary_unary_rpc_method_handler(fake._access, request_deserializer=AccessSecretVersionRequest.deserialize,
                                                               response_serializer=lambda raw: raw)
                fake.unexpected_calls.append(handler_call_details.method)
                return None

        self._server = grpc.server(ThreadPoolExecutor(max_workers=16))
        self._server.add_generic_rpc_handlers((Handler(),))
        self.port = self._server.add_insecure_port("127.0.0.1:0")
        self._server.start()
        self._channel = grpc.insecure_channel(f"127.0.0.1:{self.port}")
        self.client = SecretManagerServiceClient(transport=SecretManagerServiceGrpcTransport(channel=self._channel))

    def close(self) -> None:
        self.release.set()
        self._channel.close()
        self._server.stop(None)

    def set(self, secret_id: str, value: str | bytes) -> None:
        self.secrets[secret_id] = value.encode() if isinstance(value, str) else value

    def gets(self) -> list[str]:
        """The secret ID of every access, in order."""
        return [m.group(2) for m in (_VERSION_NAME.fullmatch(a) for a in self.accesses) if m]

    def _access(self, request: AccessSecretVersionRequest, context: grpc.ServicerContext) -> bytes:
        self.accesses.append(request.name)
        self.metadata.append(dict(context.invocation_metadata()))
        self.received.set()
        if self.hang:
            while context.is_active() and not self.release.wait(0.02):
                pass
            if not context.is_active():
                self.cancelled.set()
                return b""

        if self.on_get is not None:
            self.on_get()
        if self.next_failures:
            context.abort(self.next_failures.pop(0), "Failing once in a test.")
        if self.failure is not None:
            context.abort(*self.failure)

        name = _VERSION_NAME.fullmatch(request.name)
        if name is None or name.group(1) != PROJECT_ID or name.group(3) != "latest":
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Unexpected resource name {request.name}.")
        assert name is not None
        value = self.secrets.get(name.group(2))
        if value is None:
            context.abort(grpc.StatusCode.NOT_FOUND, f"Secret [projects/{PROJECT_NUMBER}/secrets/{name.group(2)}] not found or has no versions.")
        assert value is not None

        response = AccessSecretVersionResponse(name=f"projects/{PROJECT_NUMBER}/secrets/{name.group(2)}/versions/1",
                                               payload=SecretPayload(data=value, data_crc32c=crc32c(value)))
        if self.tamper is not None:
            response = self.tamper(response)
        return self.raw if self.raw is not None else AccessSecretVersionResponse.serialize(response)


# --- Fixtures and helpers -------------------------------------------------------------------------


@pytest.fixture
def ring() -> Iterator[DefaultKeyRing]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, new_key())
        yield ring


@pytest.fixture
def google() -> Iterator[FakeSecretManager]:
    fake = FakeSecretManager()
    yield fake
    fake.close()


@pytest.fixture
def cache(google: FakeSecretManager, ring: DefaultKeyRing) -> GoogleSecretManagerSecretCache:
    return GoogleSecretManagerSecretCache(google.client, PROJECT_ID, ring)


@pytest.fixture
def parsed(monkeypatch: pytest.MonkeyPatch) -> list[AccessedSecretVersion]:
    """Every response the cache's deserializer parsed, to check its payload was zeroed."""
    versions: list[AccessedSecretVersion] = []
    original = ResponseCapture.deserialize

    def recording(self: ResponseCapture, raw: bytes) -> AccessedSecretVersion:
        version = original(self, raw)
        versions.append(version)
        return version

    monkeypatch.setattr(ResponseCapture, "deserialize", recording)
    return versions


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


@pytest.fixture
def fast_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cache_module, "_INITIAL_RETRY_DELAY", 0.01)


def decrypt_string(cache: ProtectedReadOnlyCache, name: str, size: int = 512) -> str:
    result = bytearray(size)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_string_async(cache: ProtectedReadOnlyCache, name: str, size: int = 512) -> str:
    result = bytearray(size)
    return result[: await cache.decrypt_async(name, result)].decode()


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Runs a test's coroutine, with a timeout so a hang fails instead of stalling the run."""

    async def bounded() -> T:
        return await asyncio.wait_for(coroutine, 10)

    return asyncio.run(bounded())


def assert_the_one_response_was_zeroed(parsed: list[AccessedSecretVersion]) -> None:
    assert len(parsed) == 1
    assert type(parsed[0].data) is bytearray
    assert not any(parsed[0].data)


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


# --- Fetching -------------------------------------------------------------------------------------


def test_decrypt_on_miss_fetches_the_one_secrets_latest_version_then_serves_it_from_the_cache(google: FakeSecretManager,
                                                                                               cache: GoogleSecretManagerSecretCache) -> None:
    google.set("Db-Password", "s3cret")

    assert decrypt_string(cache, "Db-Password") == "s3cret"
    assert decrypt_string(cache, "Db-Password") == "s3cret"

    assert google.accesses == ["projects/hkdfguard-test/secrets/Db-Password/versions/latest"]


def test_the_parsed_payload_is_zeroed_once_encrypted(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                     parsed: list[AccessedSecretVersion]) -> None:
    google.set("item", "value")

    assert decrypt_string(cache, "item") == "value"

    assert_the_one_response_was_zeroed(parsed)
    assert len(parsed[0].data) == 5
    assert google.unexpected_calls == []


def test_the_clients_own_message_is_never_built(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache, monkeypatch: pytest.MonkeyPatch) -> None:
    # The proto-plus (and so protobuf) response, which would hold the payload in bytes.
    def never(*args: object, **kwargs: object) -> None:
        raise AssertionError("The client's AccessSecretVersionResponse was deserialized.")

    monkeypatch.setattr(AccessSecretVersionResponse, "deserialize", never)
    monkeypatch.setattr(SecretPayload, "deserialize", never)
    # And the client's own call, whose stub deserializes with the original.
    monkeypatch.setattr(SecretManagerServiceClient, "access_secret_version", never)
    google.set("a", "value")
    google.set("b", "value")

    assert decrypt_string(cache, "a") == "value"
    assert run(decrypt_string_async(cache, "b")) == "value"


def test_the_clients_debug_logging_never_sees_the_payload(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    handler = RecordingHandler()
    logger = logging.getLogger("google")
    original_level, original_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    base64 = "bmV2ZXItbG9nZ2Vk"  # the payload's base64, as the client's JSON logging writes it
    try:
        google.set("item", "never-logged")
        assert decrypt_string(cache, "item") == "never-logged"
        assert run(decrypt_string_async(cache, "item#absent")) == ""
        ours = list(handler.records)

        # The client's own call, through its logging interceptor, would have logged it.
        google.client.access_secret_version(name="projects/hkdfguard-test/secrets/item/versions/latest")
        theirs = handler.records[len(ours):]
    finally:
        logger.removeHandler(handler)
        logger.setLevel(original_level)
        logger.propagate = original_propagate

    for record in ours:
        assert "never-logged" not in str(record.__dict__)
        assert base64 not in str(record.__dict__)
    assert any(base64 in str(record.__dict__) for record in theirs)


def test_each_call_carries_the_routing_header_and_the_clients_api_header(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("item", "value")

    assert decrypt_string(cache, "item") == "value"
    assert run(cache.decrypt_async("absent", bytearray(16))) == 0

    for metadata in google.metadata:
        assert metadata["x-goog-request-params"].startswith("name=projects")
        assert "hkdfguard-test" in metadata["x-goog-request-params"]
        assert "gapic/" in metadata["x-goog-api-client"]


def test_a_json_payload_is_cached_whole_and_by_key_from_one_call_and_is_zeroed(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                              parsed: list[AccessedSecretVersion]) -> None:
    google.set("App-Credentials", KEY_VALUE_SECRET)

    assert decrypt_string(cache, "App-Credentials#api-credential-21") == \
        "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q=="
    assert decrypt_string(cache, "App-Credentials#service-credential-3") == "This is my third credential"
    assert decrypt_string(cache, "App-Credentials#port") == "5432"
    assert decrypt_string(cache, "App-Credentials") == KEY_VALUE_SECRET

    assert google.gets() == ["App-Credentials"]
    assert_the_one_response_was_zeroed(parsed)


def test_decrypt_async_fetches_through_a_future_on_the_channel_and_zeroes_the_payload(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                                     parsed: list[AccessedSecretVersion],
                                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    # RemoteSecretCache's default _fetch_async would have run _fetch in a worker thread.
    def blocking(name: str, value: object) -> None:
        raise AssertionError("_fetch was called.")

    monkeypatch.setattr(cache, "_fetch", blocking)
    google.set("App-Credentials", KEY_VALUE_SECRET)

    async def scenario() -> None:
        assert await decrypt_string_async(cache, "App-Credentials#service-credential-3") == "This is my third credential"
        assert await decrypt_string_async(cache, "App-Credentials") == KEY_VALUE_SECRET
        assert await cache.decrypt_async("Missing", bytearray(16)) == 0

    run(scenario())
    assert_the_one_response_was_zeroed(parsed)
    assert google.unexpected_calls == []


def test_decrypt_async_works_from_one_event_loop_after_another(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("a", "first")
    google.set("b", "second")

    assert run(decrypt_string_async(cache, "a")) == "first"
    assert run(decrypt_string_async(cache, "b")) == "second"


def test_decrypt_async_propagates_a_google_failure(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("item", "value")
    google.failure = (grpc.StatusCode.PERMISSION_DENIED, "Denied in a test.")

    with pytest.raises(core_exceptions.PermissionDenied) as raised:
        run(cache.decrypt_async("item", bytearray(16)))
    assert raised.value.grpc_status_code == grpc.StatusCode.PERMISSION_DENIED


def test_decrypt_async_refuses_a_payload_that_does_not_match_its_checksum_and_zeroes_it(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                                       parsed: list[AccessedSecretVersion]) -> None:
    google.set("item", "value")
    google.tamper = lambda r: AccessSecretVersionResponse(name=r.name, payload=SecretPayload(data=r.payload.data,
                                                                                             data_crc32c=r.payload.data_crc32c ^ 1))

    with pytest.raises(CryptographicError):
        run(cache.decrypt_async("item", bytearray(16)))
    assert_the_one_response_was_zeroed(parsed)


def test_cancelling_the_lookup_that_started_a_fetch_cancels_the_call_and_a_later_lookup_fetches_again(google: FakeSecretManager,
                                                                                                      cache: GoogleSecretManagerSecretCache) -> None:
    google.set("item", "value")
    google.hang = True

    async def scenario() -> None:
        lookup = asyncio.ensure_future(cache.decrypt_async("item", bytearray(16)))
        assert await asyncio.to_thread(google.received.wait, 10)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup

    run(scenario())
    assert google.cancelled.wait(10), "The Secret Manager call was not cancelled."

    google.hang = False
    assert decrypt_string(cache, "item") == "value"
    assert len(google.accesses) == 2


def test_find_max_decrypted_length_on_miss_fetches_the_secret(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("api-key", "value")

    assert (cache.find_max_decrypted_length("api-key") or 0) >= 5
    assert decrypt_string(cache, "api-key") == "value"
    assert len(google.accesses) == 1


def test_find_max_decrypted_length_async_on_miss_fetches_the_secret(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("api-key", "value")

    assert (run(cache.find_max_decrypted_length_async("api-key")) or 0) >= 5
    assert run(cache.find_max_decrypted_length_async("absent")) is None
    assert len(google.accesses) == 2


def test_names_differing_only_in_case_are_different_secrets_and_different_entries(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("Db", "upper")
    google.set("db", "lower")

    assert decrypt_string(cache, "Db") == "upper"
    assert decrypt_string(cache, "db") == "lower"
    assert cache.decrypt("DB", bytearray(16)) == 0
    assert decrypt_string(cache, "Db") == "upper"

    assert google.gets() == ["Db", "db", "DB"]


def test_a_missing_secret_returns_zero_and_is_looked_up_again_until_it_exists(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    assert cache.decrypt("later", bytearray(16)) == 0
    assert cache.find_max_decrypted_length("later") is None

    google.set("later", "now here")
    assert decrypt_string(cache, "later") == "now here"
    assert len(google.accesses) == 3


def test_an_empty_or_absent_payload_is_reported_missing(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("empty", b"")

    assert cache.decrypt("empty", bytearray(16)) == 0

    google.tamper = lambda r: AccessSecretVersionResponse(name=r.name)
    google.set("no-payload", "value")
    assert cache.decrypt("no-payload", bytearray(16)) == 0


def test_a_binary_secret_is_cached_as_its_bytes(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("binary", bytes([0, 1, 254, 255]))

    result = bytearray(16)
    written = cache.decrypt("binary", result)

    assert result[:written] == bytes([0, 1, 254, 255])


def test_a_payload_without_a_checksum_is_accepted(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("item", "value")
    google.tamper = lambda r: AccessSecretVersionResponse(name=r.name, payload=SecretPayload(data=r.payload.data))

    assert decrypt_string(cache, "item") == "value"


def test_a_payload_that_does_not_match_its_checksum_is_refused_and_zeroed(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                         parsed: list[AccessedSecretVersion]) -> None:
    google.set("item", "value")
    google.tamper = lambda r: AccessSecretVersionResponse(name=r.name, payload=SecretPayload(data=r.payload.data,
                                                                                             data_crc32c=r.payload.data_crc32c ^ 1))

    with pytest.raises(CryptographicError) as raised:
        cache.decrypt("item", bytearray(16))

    assert "value" not in str(raised.value)
    assert_the_one_response_was_zeroed(parsed)
    # Nothing was cached: the next lookup asks again.
    google.tamper = None
    assert decrypt_string(cache, "item") == "value"


@pytest.mark.parametrize("reported_name", ["projects/123456789012/secrets/other/versions/1", "not a resource name", "",
                                           "projects/123456789012/secrets/item", "projects/123456789012/secrets/item/versions/1/extra"])
def test_a_response_for_another_secret_is_refused_and_zeroed(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                             parsed: list[AccessedSecretVersion], reported_name: str) -> None:
    google.set("item", "value")
    google.tamper = lambda r: AccessSecretVersionResponse(name=reported_name, payload=r.payload)

    with pytest.raises(CryptographicError):
        cache.decrypt("item", bytearray(16))
    assert_the_one_response_was_zeroed(parsed)


def test_a_response_from_a_regional_secret_of_the_same_name_is_accepted(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("item", "value")
    google.tamper = lambda r: AccessSecretVersionResponse(name="projects/123456789012/locations/us-east1/secrets/item/versions/3", payload=r.payload)

    assert decrypt_string(cache, "item") == "value"


def test_a_malformed_response_fails_as_internal_and_nothing_is_cached(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("item", "value")
    google.raw = bytes([0x0A, 0x7F, 1, 2, 3])

    with pytest.raises(core_exceptions.InternalServerError):
        cache.decrypt("item", bytearray(16))
    with pytest.raises(core_exceptions.InternalServerError):
        run(cache.decrypt_async("item", bytearray(16)))

    google.raw = None
    assert decrypt_string(cache, "item") == "value"


@pytest.mark.parametrize("name", ["", "ConnectionStrings:Admin", "prod/db", "db.password", "has space", "café", "bang!", "x" * 256])
def test_a_name_secret_manager_cant_hold_is_missing_without_calling_google(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                           name: str) -> None:
    assert cache.decrypt(name, bytearray(16)) == 0
    assert cache.find_max_decrypted_length(name) is None
    assert run(cache.decrypt_async(name, bytearray(16))) == 0
    assert run(cache.find_max_decrypted_length_async(name)) is None
    assert google.accesses == []


def test_is_valid_secret_name_accepts_letters_digits_hyphens_and_underscores_up_to_255() -> None:
    assert GoogleSecretManagerSecretCache.is_valid_secret_name("a")
    assert GoogleSecretManagerSecretCache.is_valid_secret_name("Db_Password-2")
    assert GoogleSecretManagerSecretCache.is_valid_secret_name("x" * GoogleSecretManagerSecretCache.MAX_SECRET_NAME_LENGTH)
    assert not GoogleSecretManagerSecretCache.is_valid_secret_name("x" * (GoogleSecretManagerSecretCache.MAX_SECRET_NAME_LENGTH + 1))
    assert not GoogleSecretManagerSecretCache.is_valid_secret_name(None)
    assert not GoogleSecretManagerSecretCache.is_valid_secret_name("")
    assert not GoogleSecretManagerSecretCache.is_valid_secret_name("１２")  # fullwidth digits aren't ASCII


# Codes the client doesn't retry: FAILED_PRECONDITION is a disabled or destroyed latest version.
@pytest.mark.parametrize(("status", "error"), [(grpc.StatusCode.PERMISSION_DENIED, core_exceptions.PermissionDenied),
                                               (grpc.StatusCode.FAILED_PRECONDITION, core_exceptions.FailedPrecondition),
                                               (grpc.StatusCode.INTERNAL, core_exceptions.InternalServerError),
                                               (grpc.StatusCode.UNAUTHENTICATED, core_exceptions.Unauthenticated)])
def test_a_google_failure_propagates_and_is_retried_on_the_next_lookup(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                       status: grpc.StatusCode, error: type[Exception]) -> None:
    google.set("item", "value")
    google.failure = (status, "refused")

    with pytest.raises(error) as raised:
        cache.decrypt("item", bytearray(16))
    assert isinstance(raised.value, core_exceptions.GoogleAPICallError) and raised.value.grpc_status_code == status

    google.failure = None
    assert decrypt_string(cache, "item") == "value"
    assert len(google.accesses) == 2


@pytest.mark.parametrize("status", [grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.RESOURCE_EXHAUSTED])
def test_unavailable_and_resource_exhausted_are_retried_as_the_client_retries_them(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                                   fast_retries: None, status: grpc.StatusCode) -> None:
    google.set("a", "first")
    google.set("b", "second")

    google.next_failures = [status, status]
    assert decrypt_string(cache, "a") == "first"
    google.next_failures = [status]
    assert run(decrypt_string_async(cache, "b")) == "second"

    assert google.gets() == ["a", "a", "a", "b", "b"]


def test_a_fetch_that_outlasts_the_timeout_fails_as_deadline_exceeded(google: FakeSecretManager, ring: DefaultKeyRing) -> None:
    cache = GoogleSecretManagerSecretCache(google.client, PROJECT_ID, ring, timeout=0.3)
    google.set("item", "value")
    google.hang = True

    with pytest.raises(core_exceptions.DeadlineExceeded):
        cache.decrypt("item", bytearray(16))
    with pytest.raises(core_exceptions.DeadlineExceeded):
        run(cache.decrypt_async("item", bytearray(16)))


def test_concurrent_misses_on_one_name_share_one_fetch(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache) -> None:
    google.set("shared", "value")
    release = threading.Event()

    def hold() -> None:
        release.wait(10)

    google.on_get = hold

    with ThreadPoolExecutor(8) as executor:
        lookups = [executor.submit(decrypt_string, cache, "shared") for _ in range(8)]
        time.sleep(0.2)
        release.set()

        assert [lookup.result(10) for lookup in lookups] == ["value"] * 8
    assert len(google.accesses) == 1


def test_a_large_secret_round_trips(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache, parsed: list[AccessedSecretVersion]) -> None:
    large = "é-秘密-" * 1500
    assert len(large.encode()) > 4096
    google.set("large", large)

    result = bytearray(cache.find_max_decrypted_length("large") or 0)
    assert result[: cache.decrypt("large", result)].decode() == large
    assert_the_one_response_was_zeroed(parsed)


def test_a_cached_secret_still_decrypts_after_the_ring_rotates(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                               ring: DefaultKeyRing) -> None:
    google.set("before", "v1 value")
    google.set("after", "v2 value")

    assert decrypt_string(cache, "before") == "v1 value"
    ring.add(2, new_key())

    assert decrypt_string(cache, "after") == "v2 value"
    assert decrypt_string(cache, "before") == "v1 value"


def test_in_a_collection_only_names_the_earlier_sources_miss_reach_google(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                          ring: DefaultKeyRing) -> None:
    google.set("from-google", "google value")
    local = ProtectedCache(ring)
    local.add("ConnectionStrings:Admin", "local value")
    collection = ProtectedCacheCollection().add(local).add(cache)

    assert decrypt_string(collection, "ConnectionStrings:Admin") == "local value"
    assert decrypt_string(collection, "from-google") == "google value"
    assert run(decrypt_string_async(collection, "from-google")) == "google value"
    assert google.gets() == ["from-google"]


# --- Telemetry and logging ------------------------------------------------------------------------


def test_with_sensitive_logging_a_fetch_logs_the_name_only_and_a_failure_logs_an_error(google: FakeSecretManager, ring: DefaultKeyRing,
                                                                                       sensitive: None) -> None:
    google.set("Item", "never-logged")
    logger = logging.Logger("recording", logging.DEBUG)
    handler = RecordingHandler()
    logger.addHandler(handler)
    cache = GoogleSecretManagerSecretCache(google.client, PROJECT_ID, ring, logger)

    assert decrypt_string(cache, "Item") == "never-logged"
    google.failure = (grpc.StatusCode.INTERNAL, "boom")
    with pytest.raises(core_exceptions.InternalServerError):
        cache.decrypt("other", bytearray(16))

    # The secret's own name, not its escaped entry name.
    records = handler.records
    assert any(r.levelno == logging.DEBUG and getattr(r, HkdfGuardLog.EVENT_ID_KEY) == HkdfGuardEventId.SENSITIVE_OPERATION_LOGGED
               and "Item" in r.getMessage() for r in records)
    assert any(r.levelno == logging.ERROR and r.exc_info is not None and isinstance(r.exc_info[1], core_exceptions.GoogleAPICallError) for r in records)
    assert not any("never-logged" in r.getMessage() for r in records)


@pytest.mark.parametrize("sensitive_logging", [False, True])
def test_without_a_logger_fetches_and_failures_still_work_with_or_without_sensitive_logging(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                                            sensitive_logging: bool) -> None:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = sensitive_logging
    try:
        google.set("item", "value")
        assert decrypt_string(cache, "item") == "value"
        google.failure = (grpc.StatusCode.PERMISSION_DENIED, "refused")
        with pytest.raises(core_exceptions.PermissionDenied):
            cache.decrypt("other", bytearray(16))
    finally:
        HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


def test_each_fetch_is_a_populate_span_counted_as_success_not_found_or_error(google: FakeSecretManager, cache: GoogleSecretManagerSecretCache,
                                                                             sensitive: None) -> None:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    HkdfGuardTelemetry.set_tracer_provider(tracer_provider)
    HkdfGuardTelemetry.set_meter_provider(meter_provider)
    try:
        google.set("Found", "value")
        assert decrypt_string(cache, "Found") == "value"
        assert cache.decrypt("missing", bytearray(16)) == 0
        google.failure = (grpc.StatusCode.PERMISSION_DENIED, "refused")
        with pytest.raises(core_exceptions.PermissionDenied):
            cache.decrypt("failing", bytearray(16))

        found, missing, failed = [s for s in exporter.get_finished_spans() if s.name == SpanNames.Cache.POPULATE]
        assert any(e.attributes and e.attributes.get(AttributeNames.NAME) == "Found" for e in found.events)
        assert found.status.status_code != StatusCode.ERROR and missing.status.status_code != StatusCode.ERROR
        assert failed.status.status_code == StatusCode.ERROR

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


# --- Construction and closing ---------------------------------------------------------------------


def test_close_leaves_a_callers_own_client_open(google: FakeSecretManager, ring: DefaultKeyRing) -> None:
    google.set("item", "value")
    with GoogleSecretManagerSecretCache(google.client, PROJECT_ID, ring) as first:
        assert decrypt_string(first, "item") == "value"
    first.close()

    assert decrypt_string(GoogleSecretManagerSecretCache(google.client, PROJECT_ID, ring), "item") == "value"


def test_the_constructor_rejects_nones_and_project_ids_that_could_change_the_resource_path(google: FakeSecretManager, ring: DefaultKeyRing) -> None:
    client = google.client

    with pytest.raises(TypeError):
        GoogleSecretManagerSecretCache(None, "p", ring)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GoogleSecretManagerSecretCache(client, None, ring)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GoogleSecretManagerSecretCache(client, "p", None)  # type: ignore[arg-type]
    for project_id in ["", "p/secrets/other", "my project", "projé", "p?x", "p#x"]:
        with pytest.raises(ValueError):
            GoogleSecretManagerSecretCache(client, project_id, ring)
    for timeout in [0, -1, float("nan"), True]:
        with pytest.raises(ValueError):
            GoogleSecretManagerSecretCache(client, "p", ring, timeout=timeout)

    # A project number, and a legacy domain-scoped ID, are both fine.
    GoogleSecretManagerSecretCache(client, "123456789012", ring)
    GoogleSecretManagerSecretCache(client, "example.com:my-project", ring)


def test_create_rejects_an_invalid_project_before_creating_a_client(ring: DefaultKeyRing) -> None:
    # No credentials are looked up: the arguments are checked first.
    with pytest.raises(ValueError):
        GoogleSecretManagerSecretCache.create("p/x", ring)
    with pytest.raises(TypeError):
        GoogleSecretManagerSecretCache.create(None, ring)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GoogleSecretManagerSecretCache.create("p", None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        GoogleSecretManagerSecretCache.create("p", ring, timeout=0)


def test_a_rest_client_is_refused(ring: DefaultKeyRing) -> None:
    client = SecretManagerServiceClient(transport="rest", credentials=AnonymousCredentials())  # type: ignore[no-untyped-call]

    with pytest.raises(ValueError, match="gRPC"):
        GoogleSecretManagerSecretCache(client, PROJECT_ID, ring)


def test_create_makes_its_own_client_without_calling_google_until_a_secret_is_requested_and_close_closes_it(ring: DefaultKeyRing) -> None:
    with GoogleSecretManagerSecretCache.create(PROJECT_ID, ring, credentials=AnonymousCredentials(),  # type: ignore[no-untyped-call]
                                               client_options={"api_endpoint": "127.0.0.1:1"}) as cache:
        # An invalid name never reaches the channel, so this needs no network.
        assert cache.decrypt("not:a:secret", bytearray(16)) == 0

    # The channel is closed, so a real lookup fails at once.
    with pytest.raises(ValueError, match="closed channel"):
        cache.decrypt("valid", bytearray(16))
