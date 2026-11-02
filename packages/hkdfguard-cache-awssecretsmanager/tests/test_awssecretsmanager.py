"""The cache through a real botocore Secrets Manager client - its serializer, event system, capture and
parser included - answered by :class:`FakeSecretsManager` instead of the network."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import threading
import time
import uuid
from collections.abc import Buffer, Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import botocore.session
import pytest
from botocore.awsrequest import AWSPreparedRequest, AWSResponse, HeadersDict
from botocore.config import Config
from botocore.credentials import CredentialResolver
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.stub import Stubber
from hkdfguard.abstractions import KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache import InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection, SecretJsonBody
from hkdfguard.cache.awssecretsmanager import AwsSecretsManagerSecretCache, SecretsManagerClient
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.diagnostics import AttributeNames, HkdfGuardEventId, HkdfGuardLog, HkdfGuardTelemetry, MetricNames, SpanNames
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader, NumberDataPoint
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

# A key/value secret as AWS Secrets Manager's console stores one.
KEY_VALUE_SECRET = """{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}"""


# --- Test doubles ---------------------------------------------------------------------------------


class FakeSecretsManager:
    """Secrets Manager's JSON 1.1 endpoint, under a real botocore client - no network: a
    ``before-send`` handler answers each request as the HTTP layer would (which botocore lets a
    handler do). A GetSecretValue is answered with the secret (names matched exactly, as AWS matches
    them) or ResourceNotFoundException; any other operation - ListSecrets and BatchGetSecretValue
    among them - is recorded in :attr:`unexpected_operations` and refused. Each body is sent in small
    chunks, as urllib3 streams one."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._lock = threading.Lock()
        # Every SecretId GetSecretValue was called with, in order.
        self.gets: list[str] = []
        # Every other operation called.
        self.unexpected_operations: list[str] = []
        # When set, GetSecretValue fails with this AWS error type and HTTP status.
        self.fail_with: tuple[str, int] | None = None
        # When set, GetSecretValue is answered with this body as it is.
        self.raw_body: bytes | None = None
        # Runs inside every GetSecretValue before it answers, e.g. to hold it open; given the SecretId.
        self.on_get: Callable[[str], object] | None = None
        self.chunk_length = 7

    def set_string(self, name: str, value: str) -> None:
        self._secrets[name] = '"SecretString":' + json.dumps(value) + ","

    def set_binary(self, name: str, value: bytes) -> None:
        self._secrets[name] = '"SecretBinary":"' + base64.b64encode(value).decode("ascii") + '",'

    def set_empty(self, name: str) -> None:
        self._secrets[name] = ""

    def client(self, session: botocore.session.Session | None = None, credentials: bool = True) -> Any:
        """A client sending every request here, without retries. Creating one reads the service model
        from botocore's own files and makes no request."""
        session = session if session is not None else botocore.session.get_session()
        keys = {"aws_access_key_id": "testing", "aws_secret_access_key": "testing"} if credentials else {}
        client = session.create_client("secretsmanager", region_name="us-east-1", config=Config(retries={"total_max_attempts": 1}), **keys)
        client.meta.events.register("before-send.secrets-manager", self._answer)
        return client

    def _answer(self, request: AWSPreparedRequest, **_: Any) -> AWSResponse:
        operation = _text(request.headers.get("X-Amz-Target", ""))
        if operation != "secretsmanager.GetSecretValue":
            with self._lock:
                self.unexpected_operations.append(operation)
            return self._error(request, "AccessDeniedException", 400)

        assert request.method == "POST"
        assert _text(request.headers.get("Content-Type", "")).startswith("application/x-amz-json-1.1")
        body = json.loads(bytes(request.body or b""))
        assert set(body) == {"SecretId"}, body  # no VersionId or VersionStage: AWSCURRENT
        name = body["SecretId"]

        with self._lock:
            self.gets.append(name)
        hold = self.on_get
        if hold is not None:
            hold(name)

        if self.fail_with is not None:
            return self._error(request, *self.fail_with)
        if self.raw_body is not None:
            return self._respond(request, 200, self.raw_body)
        value = self._secrets.get(name)
        if value is None:
            return self._error(request, "ResourceNotFoundException", 400)

        response = ('{"ARN":' + json.dumps(f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{name}-AbCdEf")
                    + ',"Name":' + json.dumps(name) + "," + value
                    + '"VersionId":"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111","VersionStages":["AWSCURRENT"],"CreatedDate":1700000000.0}')
        return self._respond(request, 200, response.encode())

    def _error(self, request: AWSPreparedRequest, error_type: str, status: int) -> AWSResponse:
        body = json.dumps({"__type": error_type, "Message": f"{error_type} in a test."}).encode()
        return self._respond(request, status, body, {"x-amzn-ErrorType": error_type})

    def _respond(self, request: AWSPreparedRequest, status: int, body: bytes, extra: dict[str, str] | None = None) -> AWSResponse:
        headers = HeadersDict({"Content-Type": "application/x-amz-json-1.1", "Content-Length": str(len(body)), "x-amzn-RequestId": "request-1",
                               **(extra or {})})
        chunks = [body[i:i + self.chunk_length] for i in range(0, len(body), self.chunk_length)]
        return AWSResponse(request.url, status, headers, _ChunkedRaw(chunks))


class _ChunkedRaw:
    """The raw stream AWSResponse reads its content from, in chunks, as urllib3's response is."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def stream(self, amt: int | None = None, decode_content: bool | None = None) -> Iterator[bytes]:
        yield from self._chunks


def _text(value: str | bytes) -> str:
    return value.decode() if isinstance(value, bytes) else value


class Recorded:
    """What every GetSecretValue response held as botocore handled it: the body a ``before-parse``
    handler registered by the application saw, and the dict the parser produced (``after-call``)."""

    def __init__(self, client: Any) -> None:
        self.bodies: list[bytes] = []
        self.responses: list[dict[str, Any]] = []
        client.meta.events.register("before-parse.secrets-manager.GetSecretValue", self._before_parse)
        client.meta.events.register("after-call.secrets-manager.GetSecretValue", self._after_call)

    def _before_parse(self, response_dict: dict[str, Any], **_: Any) -> None:
        if response_dict["status_code"] < 300:
            self.bodies.append(bytes(response_dict["body"]))

    def _after_call(self, parsed: dict[str, Any], **_: Any) -> None:
        if "Error" not in parsed:
            self.responses.append(parsed)


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


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


# --- Fixtures and helpers -------------------------------------------------------------------------


@pytest.fixture
def ring() -> Iterator[DefaultKeyRing]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, new_key())
        yield ring


@pytest.fixture
def aws() -> FakeSecretsManager:
    return FakeSecretsManager()


@pytest.fixture
def client(aws: FakeSecretsManager) -> Iterator[Any]:
    created = aws.client()
    try:
        yield created
    finally:
        created.close()


@pytest.fixture
def recorded(client: Any) -> Recorded:
    return Recorded(client)


@pytest.fixture
def cache(client: Any, ring: DefaultKeyRing, recorded: Recorded) -> AwsSecretsManagerSecretCache:
    # Created after the application's own before-parse handler (recorded), as an application would.
    return AwsSecretsManagerSecretCache(client, ring)


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


def decrypt_string(cache: ProtectedReadOnlyCache, name: str, size: int = 512) -> str:
    result = bytearray(size)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_string_async(cache: ProtectedReadOnlyCache, name: str, size: int = 512) -> str:
    result = bytearray(size)
    return result[: await cache.decrypt_async(name, result)].decode()


def error_code(error: ClientError) -> str:
    return str(error.response["Error"]["Code"])


def eventually(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 10
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("The condition never held.")
        time.sleep(0.01)


# --- Fetching -------------------------------------------------------------------------------------


def test_decrypt_on_miss_fetches_the_one_secret_then_serves_it_from_the_cache(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_string("prod/Db-Password", "s3cret")

    assert decrypt_string(cache, "prod/Db-Password") == "s3cret"
    assert decrypt_string(cache, "prod/Db-Password") == "s3cret"

    assert aws.gets == ["prod/Db-Password"]
    assert aws.unexpected_operations == []


def test_the_parsed_response_holds_the_value_blanked(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache, recorded: Recorded) -> None:
    aws.set_string("text", "s3cret")
    aws.set_binary("binary", bytes([1, 2, 3]))

    assert decrypt_string(cache, "text") == "s3cret"
    assert cache.decrypt("binary", bytearray(16)) == 3

    assert len(recorded.responses) == 2
    for response in recorded.responses:
        assert response.get("SecretString", "") == ""
        assert response.get("SecretBinary", b"") == b""
        assert response["ARN"].startswith("arn:aws:secretsmanager:")
        assert response["VersionStages"] == ["AWSCURRENT"]


def test_every_later_handler_and_botocores_debug_log_see_only_the_redacted_body(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache,
                                                                                recorded: Recorded) -> None:
    aws.set_string("text", "s3cret-value-spanning-several-chunks")
    aws.set_binary("binary", b"binary-value-spanning-several-chunks")
    handler = RecordingHandler()
    botocore_logger = logging.getLogger("botocore")
    original_level = botocore_logger.level
    botocore_logger.addHandler(handler)
    botocore_logger.setLevel(logging.DEBUG)
    try:
        assert decrypt_string(cache, "text") == "s3cret-value-spanning-several-chunks"
        assert cache.decrypt("binary", bytearray(64)) > 0
    finally:
        botocore_logger.removeHandler(handler)
        botocore_logger.setLevel(original_level)

    # The application's handler was registered before the cache's, yet runs after it.
    assert len(recorded.bodies) == 2
    for body in recorded.bodies:
        parsed = json.loads(body)
        assert parsed.get("SecretString", "") == "" and parsed.get("SecretBinary", "") == ""
        assert b"spanning" not in body
    encoded = base64.b64encode(b"binary-value-spanning-several-chunks").decode()
    assert any("Response body" in r.getMessage() for r in handler.records)
    assert not any("s3cret" in r.getMessage() or encoded in r.getMessage() for r in handler.records)


def test_the_applications_own_calls_on_the_client_are_left_as_they_are(aws: FakeSecretsManager, client: Any, cache: AwsSecretsManagerSecretCache,
                                                                      ring: DefaultKeyRing) -> None:
    aws.set_string("a", "1")
    aws.set_string("b", "2")

    assert decrypt_string(cache, "a") == "1"
    # The capture acts only on the cache's own calls: the application's are parsed as usual.
    assert client.get_secret_value(SecretId="b")["SecretString"] == "2"

    # A second cache on the same client shares the one handler, and both still capture.
    other = AwsSecretsManagerSecretCache(client, ring)
    assert decrypt_string(other, "b") == "2"
    assert decrypt_string(cache, "b") == "2"
    assert client.get_secret_value(SecretId="a")["SecretString"] == "1"


def test_concurrent_fetches_on_one_shared_client_each_capture_only_their_own_response(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache,
                                                                                     client: Any) -> None:
    count = 12
    for i in range(count):
        aws.set_string(f"secret-{i}", f"value-{i}")
    aws.set_string("plain", "the application's")
    # Every call - the cache's twelve and the application's own - is in flight at once before any answers.
    barrier = threading.Barrier(count + 1, timeout=10)
    aws.on_get = lambda name: barrier.wait()

    def application_call() -> str:
        return str(client.get_secret_value(SecretId="plain")["SecretString"])

    with ThreadPoolExecutor(count + 1) as pool:
        lookups = [pool.submit(decrypt_string, cache, f"secret-{i}") for i in range(count)]
        plain = pool.submit(application_call)
        assert [lookup.result(timeout=20) for lookup in lookups] == [f"value-{i}" for i in range(count)]
        assert plain.result(timeout=20) == "the application's"


def test_a_value_with_json_escapes_is_unescaped_exactly(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    secret = 'p"a\\ss/wörd\n\u0001秘密'
    aws.set_string("escaped", secret)

    assert decrypt_string(cache, "escaped") == secret


def test_a_binary_secret_is_cached_as_its_bytes(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_binary("binary", bytes([0, 1, 254, 255]))

    result = bytearray(16)
    written = cache.decrypt("binary", result)

    assert result[:written] == bytes([0, 1, 254, 255])


def test_a_key_value_secret_is_cached_whole_and_by_key_from_one_call_and_botocore_never_sees_it(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache,
                                                                                               recorded: Recorded) -> None:
    aws.set_string("prod/App", KEY_VALUE_SECRET)

    assert decrypt_string(cache, "prod/App#api-credential-21") == "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q=="
    assert decrypt_string(cache, "prod/App#test-credential-1") == "This is my first credential"
    assert decrypt_string(cache, "prod/App#service-credential-3") == "This is my third credential"
    assert decrypt_string(cache, "prod/App#domain-credential-17") == "fakedomain/thiscredential"
    assert decrypt_string(cache, "prod/App#port") == "5432"
    assert decrypt_string(cache, "prod/App") == KEY_VALUE_SECRET
    assert cache.decrypt("prod/app#port", bytearray(16)) == 0

    assert aws.gets == ["prod/App", "prod/app"]
    assert recorded.responses[0]["SecretString"] == ""


def test_a_binary_secret_holding_json_is_not_split(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_binary("binary", b'{"k":"v"}')

    assert decrypt_string(cache, "binary") == '{"k":"v"}'
    assert cache.decrypt("binary#k", bytearray(16)) == 0


def test_decrypt_async_fetches_without_blocking_and_botocore_never_sees_the_value(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache,
                                                                                 recorded: Recorded) -> None:
    aws.set_string("prod/App", KEY_VALUE_SECRET)

    async def run() -> None:
        assert await decrypt_string_async(cache, "prod/App#test-credential-1") == "This is my first credential"
        assert await decrypt_string_async(cache, "prod/App") == KEY_VALUE_SECRET
        length = await cache.find_max_decrypted_length_async("prod/App#port")
        assert length is not None and length >= 4
        assert await cache.decrypt_async("missing", bytearray(16)) == 0

    asyncio.run(run())

    assert aws.gets == ["prod/App", "missing"]
    assert recorded.responses[0]["SecretString"] == ""


def test_decrypt_async_propagates_an_aws_failure(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.fail_with = ("InvalidRequestException", 400)
    with pytest.raises(ClientError) as raised:
        asyncio.run(cache.decrypt_async("item", bytearray(16)))
    assert error_code(raised.value) == "InvalidRequestException"

    aws.fail_with = None
    aws.set_string("item", "value")
    assert asyncio.run(cache.decrypt_async("item", bytearray(16))) == 5


def test_cancelling_decrypt_async_stops_the_lookup_and_the_next_lookup_fetches_again(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_string("item", "value")
    release = threading.Event()
    aws.on_get = lambda name: release.wait(10)

    async def run() -> None:
        lookup = asyncio.create_task(cache.decrypt_async("item", bytearray(16)))
        await asyncio.to_thread(eventually, lambda: len(aws.gets) == 1)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup

        # botocore can't be interrupted: the first call runs on once released, and what it reads is refused.
        aws.on_get = None
        release.set()
        assert await cache.decrypt_async("item", bytearray(16)) == 5

    asyncio.run(run())
    assert len(aws.gets) == 2


def test_find_max_decrypted_length_on_miss_fetches_the_secret(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_string("api-key", "value")

    length = cache.find_max_decrypted_length("api-key")
    assert length is not None and length >= 5
    assert decrypt_string(cache, "api-key") == "value"
    assert len(aws.gets) == 1


def test_names_differing_only_in_case_are_different_secrets_and_different_entries(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_string("prod/Db", "upper")
    aws.set_string("prod/db", "lower")

    assert decrypt_string(cache, "prod/Db") == "upper"
    assert decrypt_string(cache, "prod/db") == "lower"
    assert cache.decrypt("PROD/DB", bytearray(16)) == 0
    assert decrypt_string(cache, "prod/Db") == "upper"

    assert aws.gets == ["prod/Db", "prod/db", "PROD/DB"]


def test_a_missing_secret_returns_zero_and_is_looked_up_again_until_it_exists(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    assert cache.decrypt("later", bytearray(16)) == 0
    assert cache.find_max_decrypted_length("later") is None

    aws.set_string("later", "now here")
    assert decrypt_string(cache, "later") == "now here"
    assert len(aws.gets) == 3


def test_an_empty_secret_is_reported_missing(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_empty("none")
    aws.set_string("empty-string", "")
    aws.set_binary("empty-binary", b"")

    assert cache.decrypt("none", bytearray(16)) == 0
    assert cache.decrypt("empty-string", bytearray(16)) == 0
    assert cache.decrypt("empty-binary", bytearray(16)) == 0


@pytest.mark.parametrize("body", ['{"SecretString":"a","SecretBinary":"Yg=="}', '{"SecretBinary":"not base64!"}', "not json"])
def test_a_response_that_cant_be_trusted_is_refused(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache, recorded: Recorded, body: str) -> None:
    aws.raw_body = body.encode()

    with pytest.raises(InvalidSecretDataError) as raised:
        cache.decrypt("item", bytearray(16))
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    with pytest.raises(InvalidSecretDataError):
        asyncio.run(cache.decrypt_async("item", bytearray(16)))
    # Refused before botocore parsed it, so nothing after the capture saw it.
    assert recorded.bodies == [] and recorded.responses == []


def test_a_response_body_over_the_limit_is_refused(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache, recorded: Recorded) -> None:
    # botocore has read the whole body by the time any hook runs, so - unlike the Java port - it can't
    # be refused part-way; it is refused before botocore parses it.
    prefix = b'{"SecretString":"'
    aws.chunk_length = 64 * 1024
    aws.raw_body = prefix + b"a" * (SecretJsonBody.MAX_BODY_LENGTH + 64 * 1024 - len(prefix))

    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item", bytearray(16))
    assert recorded.responses == []


# --- Names ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["", "ConnectionStrings:Admin", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf", "has space",
                                  "café", "bang!", "prod/Db!x"])
def test_a_name_secrets_manager_cant_hold_is_missing_without_calling_aws(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache, name: str) -> None:
    assert cache.decrypt(name, bytearray(16)) == 0
    assert cache.find_max_decrypted_length(name) is None
    assert asyncio.run(cache.decrypt_async(name, bytearray(16))) == 0
    assert asyncio.run(cache.find_max_decrypted_length_async(name)) is None
    assert aws.gets == []
    assert aws.unexpected_operations == []


def test_is_valid_secret_name_accepts_the_secrets_manager_character_set_up_to_512() -> None:
    assert AwsSecretsManagerSecretCache.is_valid_secret_name("a")
    assert AwsSecretsManagerSecretCache.is_valid_secret_name("prod/app_1+x=y.z@w-v")
    assert AwsSecretsManagerSecretCache.is_valid_secret_name("AZaz09")
    assert AwsSecretsManagerSecretCache.is_valid_secret_name("x" * AwsSecretsManagerSecretCache.MAX_SECRET_NAME_LENGTH)
    assert not AwsSecretsManagerSecretCache.is_valid_secret_name("x" * (AwsSecretsManagerSecretCache.MAX_SECRET_NAME_LENGTH + 1))
    assert not AwsSecretsManagerSecretCache.is_valid_secret_name("")
    assert not AwsSecretsManagerSecretCache.is_valid_secret_name(None)
    assert not AwsSecretsManagerSecretCache.is_valid_secret_name("prod#key")
    assert not AwsSecretsManagerSecretCache.is_valid_secret_name("ｆｕｌｌ")  # full-width letters aren't ASCII


def test_a_key_after_the_name_is_read_from_the_named_secret(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_string("prod/app", '{"user":"admin"}')

    assert decrypt_string(cache, "prod/app#user") == "admin"
    assert cache.decrypt("prod/app#bad key", bytearray(16)) == 0
    assert aws.gets == ["prod/app"]


# --- Failures -------------------------------------------------------------------------------------


def test_an_aws_failure_propagates_and_is_retried_on_the_next_lookup(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_string("item", "value")
    aws.fail_with = ("InvalidRequestException", 400)

    with pytest.raises(ClientError) as raised:
        cache.decrypt("item", bytearray(16))
    assert error_code(raised.value) == "InvalidRequestException"

    aws.fail_with = None
    assert decrypt_string(cache, "item") == "value"
    assert len(aws.gets) == 2


@pytest.mark.parametrize(("error_type", "status", "modeled"), [("AccessDeniedException", 400, None),
                                                               ("InvalidRequestException", 400, "InvalidRequestException"),
                                                               ("DecryptionFailure", 400, "DecryptionFailure"),
                                                               ("InvalidParameterException", 400, "InvalidParameterException"),
                                                               ("InternalServiceError", 500, "InternalServiceError")])
def test_every_error_but_not_found_raises_botocores_exception(aws: FakeSecretsManager, client: Any, cache: AwsSecretsManagerSecretCache,
                                                              error_type: str, status: int, modeled: str | None) -> None:
    aws.fail_with = (error_type, status)

    with pytest.raises(ClientError) as raised:
        cache.decrypt("item", bytearray(16))

    assert error_code(raised.value) == error_type
    assert raised.value.response["ResponseMetadata"]["HTTPStatusCode"] == status
    if modeled is not None:
        assert isinstance(raised.value, getattr(client.exceptions, modeled))


def test_resource_not_found_is_missing_not_an_error(aws: FakeSecretsManager, client: Any, cache: AwsSecretsManagerSecretCache) -> None:
    with pytest.raises(client.exceptions.ResourceNotFoundException):
        client.get_secret_value(SecretId="missing")

    assert cache.decrypt("missing", bytearray(16)) == 0
    assert asyncio.run(cache.decrypt_async("missing", bytearray(16))) == 0


def test_a_credential_failure_propagates(aws: FakeSecretsManager, ring: DefaultKeyRing) -> None:
    session = botocore.session.Session()
    session.register_component("credential_provider", CredentialResolver(providers=[]))
    failing = aws.client(session, credentials=False)
    try:
        cache = AwsSecretsManagerSecretCache(failing, ring)

        with pytest.raises(NoCredentialsError):
            cache.decrypt("item", bytearray(16))
        with pytest.raises(NoCredentialsError):
            asyncio.run(cache.decrypt_async("item", bytearray(16)))
        assert aws.gets == []
    finally:
        failing.close()


def test_a_response_that_never_passed_through_the_capture_is_refused(ring: DefaultKeyRing) -> None:
    # A Stubber answers before the endpoint runs, so no before-parse event: the value would be a str.
    client = botocore.session.get_session().create_client("secretsmanager", region_name="us-east-1", aws_access_key_id="testing",
                                                          aws_secret_access_key="testing")
    try:
        cache = AwsSecretsManagerSecretCache(client, ring)
        with Stubber(client) as stubber:
            stubber.add_response("get_secret_value", {"ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:item-AbCdEf", "Name": "item",
                                                      "SecretString": "s3cret"}, {"SecretId": "item"})
            with pytest.raises(RuntimeError, match="wasn't captured"):
                cache.decrypt("item", bytearray(16))
    finally:
        client.close()


# --- The cache ------------------------------------------------------------------------------------


def test_concurrent_misses_on_one_name_share_one_fetch(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    aws.set_string("shared", "value")
    release = threading.Event()
    aws.on_get = lambda name: release.wait(10)

    async def lookup_async() -> str:
        return await decrypt_string_async(cache, "shared")

    with ThreadPoolExecutor(9) as pool:
        lookups = [pool.submit(decrypt_string, cache, "shared") for _ in range(8)]
        lookups.append(pool.submit(asyncio.run, lookup_async()))
        eventually(lambda: len(aws.gets) == 1)
        time.sleep(0.2)
        release.set()
        assert [lookup.result(timeout=20) for lookup in lookups] == ["value"] * 9
    assert len(aws.gets) == 1


def test_a_large_secret_round_trips(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache) -> None:
    large = "é-秘密-" * 3000
    assert len(large.encode()) > 16 * 1024
    aws.set_string("large", large)

    length = cache.find_max_decrypted_length("large")
    assert length is not None
    assert decrypt_string(cache, "large", length) == large


def test_a_cached_secret_still_decrypts_after_the_ring_rotates(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache, ring: DefaultKeyRing) -> None:
    aws.set_string("before", "v1 value")
    aws.set_string("after", "v2 value")

    assert decrypt_string(cache, "before") == "v1 value"
    ring.add(2, new_key())

    assert decrypt_string(cache, "after") == "v2 value"
    assert decrypt_string(cache, "before") == "v1 value"


def test_in_a_collection_only_names_the_earlier_sources_miss_reach_aws(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache,
                                                                       ring: DefaultKeyRing) -> None:
    aws.set_string("from-aws", "aws value")
    local = ProtectedCache(ring)
    local.add("ConnectionStrings:Admin", bytearray(b"local value"))
    collection = ProtectedCacheCollection().add(local).add(cache)

    assert decrypt_string(collection, "ConnectionStrings:Admin") == "local value"
    assert decrypt_string(collection, "from-aws") == "aws value"
    assert aws.gets == ["from-aws"]


def test_with_sensitive_logging_a_fetch_logs_the_name_only_and_a_failure_logs_an_error(aws: FakeSecretsManager, client: Any, ring: DefaultKeyRing,
                                                                                       sensitive: None) -> None:
    logger = logging.Logger(f"recording-{uuid.uuid4().hex}", logging.DEBUG)
    handler = RecordingHandler()
    logger.addHandler(handler)
    cache = AwsSecretsManagerSecretCache(client, ring, logger)
    aws.set_string("prod/Item", "never-logged")

    assert decrypt_string(cache, "prod/Item") == "never-logged"
    aws.fail_with = ("InternalServiceError", 500)
    with pytest.raises(client.exceptions.InternalServiceError):
        cache.decrypt("other", bytearray(16))

    # The secret's own name, not its escaped entry name.
    records = handler.records
    assert any(r.levelno == logging.DEBUG and getattr(r, HkdfGuardLog.EVENT_ID_KEY) == HkdfGuardEventId.SENSITIVE_OPERATION_LOGGED
               and "prod/Item" in r.getMessage() for r in records)
    assert any(r.levelno == logging.ERROR and r.exc_info is not None and isinstance(r.exc_info[1], client.exceptions.InternalServiceError)
               for r in records)
    assert not any("never-logged" in r.getMessage() for r in records)


def test_each_fetch_is_a_populate_span_counted_as_success_not_found_or_error(aws: FakeSecretsManager, cache: AwsSecretsManagerSecretCache,
                                                                             sensitive: None) -> None:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    HkdfGuardTelemetry.set_tracer_provider(tracer_provider)
    HkdfGuardTelemetry.set_meter_provider(meter_provider)
    try:
        aws.set_string("Found", "value")
        assert decrypt_string(cache, "Found") == "value"
        assert cache.decrypt("missing", bytearray(16)) == 0
        aws.fail_with = ("AccessDeniedException", 400)
        with pytest.raises(ClientError):
            cache.decrypt("denied", bytearray(16))

        found, missing, failed = [s for s in exporter.get_finished_spans() if s.name == SpanNames.Cache.POPULATE]
        assert any(e.attributes and e.attributes.get(AttributeNames.NAME) == "Found" for e in found.events)
        assert failed.status.status_code.name == "ERROR" and missing.status.status_code.name != "ERROR"

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


def test_constructing_makes_no_call_until_a_secret_is_requested(aws: FakeSecretsManager, client: Any, ring: DefaultKeyRing) -> None:
    AwsSecretsManagerSecretCache(client, ring)
    assert aws.gets == [] and aws.unexpected_operations == []


def test_the_constructor_refuses_a_none_client_or_ring_or_a_client_without_an_event_system(client: Any, ring: DefaultKeyRing) -> None:
    with pytest.raises(TypeError):
        AwsSecretsManagerSecretCache(None, ring)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AwsSecretsManagerSecretCache(client, None)  # type: ignore[arg-type]

    class NotBotocore:
        meta = None

        def get_secret_value(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"SecretString": "a str already"}

    not_botocore: SecretsManagerClient = NotBotocore()
    with pytest.raises(TypeError, match="botocore client"):
        AwsSecretsManagerSecretCache(not_botocore, ring)
    assert AwsSecretsManagerSecretCache(client, ring, None).decrypt("missing", bytearray(16)) == 0
