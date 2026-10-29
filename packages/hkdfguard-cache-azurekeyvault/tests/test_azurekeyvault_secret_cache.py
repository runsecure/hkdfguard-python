"""A real SecretClient, with the cache's own pipeline policy, over a stub Key Vault HTTP endpoint."""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import logging
import os
import re
import threading
import time
from collections.abc import Buffer, Callable, Coroutine, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests
import urllib3
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.core.pipeline import Pipeline, PipelineRequest, PipelineResponse
from azure.core.pipeline.policies import RetryPolicy, SansIOHTTPPolicy
from azure.core.pipeline.transport import RequestsTransport
from azure.core.rest import HttpRequest, HttpResponse
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import KeyVaultSecret, SecretClient
from hkdfguard.abstractions import KeyRing, KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache import InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection, RemoteSecretCache, SecretNameMatching, SecretValueSink
from hkdfguard.cache.azurekeyvault import AzureKeyVaultSecretCache
from hkdfguard.cache.azurekeyvault._capture import CAPTURE_OPTION, Capture, SecretCapturePolicy
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
from requests.adapters import BaseAdapter

VAULT = "https://hkdfguard-test.vault.azure.net"
TOKEN = "stub-token"

# A key/value secret as AWS Secrets Manager's console stores one.
KEY_VALUE_SECRET = """{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}"""


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


@pytest.fixture
def ring() -> Iterator[DefaultKeyRing]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, new_key())
        yield ring


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


class Credential:
    """A TokenCredential that hands out the stub's token, or fails as one that can't get a token does."""

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        if self.error is not None:
            raise self.error
        return AccessToken(TOKEN, int(time.time()) + 3600)


class SecretsHttpStub(BaseAdapter):
    """Key Vault's secrets endpoint over HTTP, as the Azure SDK's requests transport reaches it, behind
    a real SecretClient with no network: a request without a bearer token gets Key Vault's 401
    challenge, and an authorized Get Secret is answered with the secret's JSON (names compared
    ignoring case, as Key Vault does) or a 404. Any other request - listing secrets or versions among
    them - is recorded in ``unexpected_requests`` and refused.

    Like requests itself, it hands a body over unread only when the request asks to stream, unless
    ``always_buffer`` is set. :meth:`client_options` also installs a policy recording every 200 body
    SecretClient was given to deserialize, so a test can check the secret never reached it."""

    CHALLENGE = 'Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="https://vault.azure.net"'
    GET_SECRET = re.compile(r"/secrets/([^/]+)/?")

    def __init__(self) -> None:
        super().__init__()
        self.secrets: dict[str, str] = {}
        # The name of every authorized Get Secret, in order.
        self.gets: list[str] = []
        # Whether each authorized Get Secret asked for its body unread.
        self.streams: list[bool] = []
        # Every other request, as "METHOD path".
        self.unexpected_requests: list[str] = []
        # Every 200 body SecretClient deserialized.
        self.bodies_seen_by_secret_client: list[str] = []
        # When set, an authorized Get Secret is answered with this status and an error body -
        # failures_left times, or every time while that is None.
        self.fail_with: int | None = None
        self.failures_left: int | None = None
        # When set, an authorized Get Secret is answered with this body as it is.
        self.raw_body: str | None = None
        # Runs inside every authorized Get Secret before it answers, e.g. to hold it open.
        self.on_get: Callable[[str], None] | None = None
        # Hands every body over already read, whatever the request asks.
        self.always_buffer = False
        # Compresses every 200 body with gzip, when the request accepts it.
        self.gzip = False
        # How many bodies were compressed.
        self.compressed = 0
        self._lock = threading.Lock()

    def set(self, name: str, value: str) -> None:
        self.secrets[name.lower()] = value

    def send(self, request: requests.PreparedRequest, stream: bool = False, *args: Any, **kwargs: Any) -> requests.Response:
        assert request.url is not None
        parts = urlsplit(request.url)
        authorization = request.headers.get("Authorization")
        if authorization is None:
            return self.respond(request, 401, b"", stream, {"WWW-Authenticate": self.CHALLENGE})
        if authorization != f"Bearer {TOKEN}":
            return self.error(request, 401, "Unauthorized", stream)

        path = self.GET_SECRET.fullmatch(parts.path)
        if request.method != "GET" or f"https://{parts.netloc}" != VAULT or path is None:
            with self._lock:
                self.unexpected_requests.append(f"{request.method} {parts.path}")
            return self.error(request, 403, "Forbidden", stream)

        name = path.group(1)
        with self._lock:
            self.gets.append(name)
            self.streams.append(stream)
        if self.on_get is not None:
            self.on_get(name)

        if self.fail_with is not None and (self.failures_left is None or self.failures_left > 0):
            if self.failures_left is not None:
                self.failures_left -= 1
            return self.error(request, self.fail_with, "Forbidden" if self.fail_with == 403 else "InternalServerError", stream)

        if self.raw_body is not None:
            return self.ok(request, self.raw_body, stream)

        value = self.secrets.get(name.lower())
        if value is None:
            return self.error(request, 404, "SecretNotFound", stream)

        return self.ok(request, json.dumps({
            "value": value,
            "id": f"{VAULT}/secrets/{name}/0123456789abcdef0123456789abcdef",
            "attributes": {"enabled": True, "created": 1700000000, "updated": 1700000000, "recoveryLevel": "Recoverable+Purgeable"},
            "tags": {"value": "a tag, not the secret"},
        }, ensure_ascii=False), stream)

    def ok(self, request: requests.PreparedRequest, body: str, stream: bool) -> requests.Response:
        content = body.encode()
        headers: dict[str, str] = {}
        if self.gzip and "gzip" in request.headers.get("Accept-Encoding", ""):
            content = gzip.compress(content)
            self.compressed += 1
            headers["Content-Encoding"] = "gzip"
        return self.respond(request, 200, content, stream, headers)

    def error(self, request: requests.PreparedRequest, status: int, code: str, stream: bool) -> requests.Response:
        body = json.dumps({"error": {"code": code, "message": f"{code} from the stub vault."}}).encode()
        return self.respond(request, status, body, stream)

    def respond(self, request: requests.PreparedRequest, status: int, content: bytes, stream: bool,
                headers: dict[str, str] | None = None) -> requests.Response:
        all_headers = {"Content-Type": "application/json; charset=utf-8", "Content-Length": str(len(content)), **(headers or {})}
        response = requests.Response()
        response.request = request
        response.url = request.url or ""
        response.status_code = status
        response.reason = "Stub"
        response.headers.update(all_headers)
        response.raw = urllib3.HTTPResponse(body=io.BytesIO(content), headers=all_headers, status=status, preload_content=False, decode_content=False)
        if not stream or self.always_buffer:
            # As requests does without stream: the body read (and decompressed) into content.
            response._content = response.raw.read(decode_content=True)
            response._content_consumed = True
        return response

    def close(self) -> None:
        pass

    def client_options(self, **extra: Any) -> dict[str, Any]:
        """SecretClient options that send every request here, never retry, and record the bodies SecretClient sees."""
        session = requests.Session()
        session.mount("https://", self)
        return {"transport": RequestsTransport(session=session, session_owner=False), "retry_total": 0,
                "per_call_policies": [BodyRecorder(self)], **extra}


class BodyRecorder(SansIOHTTPPolicy[HttpRequest, HttpResponse]):
    """Outermost, so it sees each response exactly as SecretClient will deserialize it."""

    def __init__(self, stub: SecretsHttpStub) -> None:
        self.stub = stub

    def on_response(self, request: PipelineRequest[HttpRequest], response: PipelineResponse[HttpRequest, HttpResponse]) -> None:
        if response.http_response.status_code == 200:
            self.stub.bodies_seen_by_secret_client.append(response.http_response.read().decode())


class SinkProbeCache(RemoteSecretCache):
    """A RemoteSecretCache whose fetch is a test's: the way to get a real SecretValueSink, which only a
    cache creates, into a request made through SecretCapturePolicy directly."""

    def __init__(self, ring: KeyRing, fetch: Callable[[str, SecretValueSink], None]) -> None:
        super().__init__(ring, SecretNameMatching.IGNORE_ASCII_CASE)
        self._probe = fetch

    def _is_valid_name(self, name: str) -> bool:
        return AzureKeyVaultSecretCache.is_valid_secret_name(name)

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        self._probe(name, value)


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


@pytest.fixture
def vault() -> SecretsHttpStub:
    return SecretsHttpStub()


def create(vault: SecretsHttpStub, ring: KeyRing, logger: logging.Logger | None = None, **options: Any) -> AzureKeyVaultSecretCache:
    return AzureKeyVaultSecretCache(VAULT, Credential(), ring, logger, client_options=vault.client_options(**options))


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


# --- Fetching and caching -------------------------------------------------------------------------


def test_decrypt_on_miss_fetches_the_one_secret_then_serves_it_from_the_cache(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("Db-Password", "s3cret")

    assert decrypt_string(cache, "Db-Password") == "s3cret"
    assert decrypt_string(cache, "Db-Password") == "s3cret"

    assert vault.gets == ["Db-Password"]
    assert vault.unexpected_requests == []


def test_a_json_secret_is_cached_whole_and_by_key_from_one_call_and_secret_client_never_sees_it(vault: SecretsHttpStub,
                                                                                                ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("App-Credentials", KEY_VALUE_SECRET)

    assert decrypt_string(cache, "App-Credentials#api-credential-21") == \
        "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q=="
    assert decrypt_string(cache, "app-credentials#test-credential-1") == "This is my first credential"
    assert decrypt_string(cache, "APP-CREDENTIALS#domain-credential-17") == "fakedomain/thiscredential"
    assert decrypt_string(cache, "App-Credentials#port") == "5432"
    assert decrypt_string(cache, "App-Credentials") == KEY_VALUE_SECRET

    # Secret names ignore case; keys don't - a key the secret doesn't hold costs a fetch.
    assert cache.decrypt("App-Credentials#PORT", bytearray(16)) == 0

    assert vault.gets == ["App-Credentials", "App-Credentials"]
    assert vault.bodies_seen_by_secret_client
    assert not any("credential" in body for body in vault.bodies_seen_by_secret_client)


def test_decrypt_async_fetches_and_secret_client_never_sees_the_value(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("App-Credentials", KEY_VALUE_SECRET)

    async def scenario() -> None:
        assert await decrypt_string_async(cache, "App-Credentials#domain-credential-17") == "fakedomain/thiscredential"
        assert await decrypt_string_async(cache, "app-credentials") == KEY_VALUE_SECRET
        assert await cache.decrypt_async("Missing", bytearray(16)) == 0
        assert await cache.find_max_decrypted_length_async("Not:Valid") is None

    run(scenario())
    assert vault.gets == ["App-Credentials", "Missing"]
    assert vault.bodies_seen_by_secret_client
    assert not any("credential" in body for body in vault.bodies_seen_by_secret_client)


def test_decrypt_async_propagates_a_key_vault_failure(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("Item", "value")
    vault.fail_with = 403

    with pytest.raises(HttpResponseError) as raised:
        run(cache.decrypt_async("Item", bytearray(16)))
    assert raised.value.status_code == 403


def test_cancelling_an_async_lookup_leaves_the_request_running_refuses_its_value_and_the_next_lookup_fetches_again(
        vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    # Java interrupts the fetch's virtual thread; Python can't interrupt a thread, so the request runs
    # on in the worker thread and the closed sink refuses the value it captures.
    cache = create(vault, ring)
    vault.set("slow", "value")
    entered, release = threading.Event(), threading.Event()

    def hold(name: str) -> None:
        entered.set()
        release.wait(10)

    vault.on_get = hold

    async def scenario() -> None:
        lookup = asyncio.create_task(cache.decrypt_async("slow", bytearray(16)))
        assert await asyncio.to_thread(entered.wait, 10)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup
        release.set()

    run(scenario())
    vault.on_get = None
    # The abandoned request's value wasn't cached: this lookup fetches the secret again.
    assert decrypt_string(cache, "slow") == "value"
    assert vault.gets == ["slow", "slow"]


def test_the_callers_client_options_are_left_alone_and_another_client_built_from_them_reads_secrets_as_usual(vault: SecretsHttpStub,
                                                                                                             ring: DefaultKeyRing) -> None:
    per_retry: list[Any] = []
    options = vault.client_options(per_retry_policies=per_retry)
    snapshot = dict(options)
    cache = AzureKeyVaultSecretCache(VAULT, Credential(), ring, client_options=options)
    vault.set("Db-Password", "s3cret")

    assert decrypt_string(cache, "Db-Password") == "s3cret"
    assert options == snapshot and per_retry == []
    assert SecretClient(VAULT, Credential(), **options).get_secret("Db-Password").value == "s3cret"


def test_secret_client_is_only_ever_given_the_body_with_the_value_blanked(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("Db-Password", "s3cret")

    assert decrypt_string(cache, "Db-Password") == "s3cret"

    [body] = vault.bodies_seen_by_secret_client
    assert "s3cret" not in body
    assert '"value": ""' in body
    # Only the top-level value is taken: a nested property of the same name is left alone.
    assert "a tag, not the secret" in body


def test_the_caches_fetches_ask_for_the_body_unread(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("Db-Password", "s3cret")

    assert decrypt_string(cache, "Db-Password") == "s3cret"
    assert vault.streams == [True]


def test_a_body_the_transport_read_anyway_is_still_captured_and_redacted(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    # Java zeroes the array the HTTP client buffered; Python's is an immutable bytes, read in place.
    cache = create(vault, ring)
    vault.set("Db-Password", "s3cret")
    vault.always_buffer = True

    assert decrypt_string(cache, "Db-Password") == "s3cret"
    [body] = vault.bodies_seen_by_secret_client
    assert "s3cret" not in body and '"value": ""' in body


def test_a_compressed_body_is_decompressed_before_it_is_captured(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("Db-Password", "s3cret")
    vault.gzip = True

    assert decrypt_string(cache, "Db-Password") == "s3cret"
    assert vault.compressed == 1
    [body] = vault.bodies_seen_by_secret_client
    assert "s3cret" not in body and '"value": ""' in body


def test_a_value_with_json_escapes_is_unescaped_exactly(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    secret = 'p"a\\ss/wörd\n\u0001秘密'
    vault.set("escaped", secret)

    assert decrypt_string(cache, "escaped") == secret
    assert "wörd" not in vault.bodies_seen_by_secret_client[0]


def test_find_max_decrypted_length_on_miss_fetches_the_secret(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("api-key", "value")

    length = cache.find_max_decrypted_length("api-key")
    assert length is not None and length >= 5
    assert decrypt_string(cache, "api-key") == "value"
    assert len(vault.gets) == 1


def test_names_differing_in_case_are_one_entry_and_one_fetch(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("Db-Password", "s3cret")

    assert decrypt_string(cache, "db-password") == "s3cret"
    assert decrypt_string(cache, "DB-PASSWORD") == "s3cret"
    assert vault.gets == ["db-password"]


def test_a_missing_secret_returns_zero_and_is_looked_up_again_until_it_exists(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)

    assert cache.decrypt("later", bytearray(16)) == 0
    assert cache.find_max_decrypted_length("later") is None

    vault.set("later", "now here")
    assert decrypt_string(cache, "later") == "now here"
    assert len(vault.gets) == 3


def test_an_empty_secret_is_reported_missing(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("empty", "")

    assert cache.decrypt("empty", bytearray(16)) == 0
    assert len(vault.gets) == 1


@pytest.mark.parametrize("name", ["", "ConnectionStrings:Admin", "db_password", "../keys/other", "name/version", "name?api-version=1", "café",
                                  "has space", "x" * 128, "١٢٣"])
def test_a_name_key_vault_cant_hold_is_missing_without_calling_the_vault(vault: SecretsHttpStub, ring: DefaultKeyRing, name: str) -> None:
    cache = create(vault, ring)

    assert cache.decrypt(name, bytearray(16)) == 0
    assert cache.find_max_decrypted_length(name) is None
    assert run(cache.decrypt_async(name, bytearray(16))) == 0
    assert run(cache.find_max_decrypted_length_async(name)) is None
    assert vault.gets == []
    assert vault.unexpected_requests == []


def test_is_valid_secret_name_accepts_ascii_letters_digits_and_hyphens_up_to_127() -> None:
    assert AzureKeyVaultSecretCache.is_valid_secret_name("a")
    assert AzureKeyVaultSecretCache.is_valid_secret_name("Db-Password-2")
    assert AzureKeyVaultSecretCache.is_valid_secret_name("x" * AzureKeyVaultSecretCache.MAX_SECRET_NAME_LENGTH)
    assert not AzureKeyVaultSecretCache.is_valid_secret_name("x" * (AzureKeyVaultSecretCache.MAX_SECRET_NAME_LENGTH + 1))
    assert not AzureKeyVaultSecretCache.is_valid_secret_name("")
    assert not AzureKeyVaultSecretCache.is_valid_secret_name(None)
    # str.isalnum would accept these; Key Vault doesn't.
    assert not AzureKeyVaultSecretCache.is_valid_secret_name("café")
    assert not AzureKeyVaultSecretCache.is_valid_secret_name("x١")


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_a_vault_failure_propagates_and_is_retried_on_the_next_lookup(vault: SecretsHttpStub, ring: DefaultKeyRing, status: int) -> None:
    cache = create(vault, ring)
    vault.set("item", "value")
    vault.fail_with = status

    with pytest.raises(HttpResponseError) as raised:
        cache.decrypt("item", bytearray(16))
    assert raised.value.status_code == status

    vault.fail_with = None
    assert decrypt_string(cache, "item") == "value"
    assert len(vault.gets) == 2


def test_a_retried_attempt_is_captured_once_it_succeeds(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    # The policy runs per attempt: the 503 is read for the retry policy, and the 200 that follows is captured.
    cache = create(vault, ring, retry_total=2, retry_backoff_factor=0)
    vault.set("item", "value")
    vault.fail_with, vault.failures_left = 503, 1

    assert decrypt_string(cache, "item") == "value"
    assert vault.gets == ["item", "item"]
    assert vault.streams == [True, True]
    [body] = vault.bodies_seen_by_secret_client
    assert '"value": ""' in body


def test_a_response_that_is_not_json_is_refused(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.raw_body = "not json"

    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item", bytearray(16))


def test_a_credential_failure_propagates(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    failure = ClientAuthenticationError("no token")
    cache = AzureKeyVaultSecretCache(VAULT, Credential(failure), ring, client_options=vault.client_options())

    with pytest.raises(ClientAuthenticationError) as raised:
        cache.decrypt("item", bytearray(16))
    assert raised.value is failure
    assert vault.gets == []


def test_concurrent_misses_on_one_name_share_one_fetch(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("shared", "value")
    release = threading.Event()

    def hold(name: str) -> None:
        release.wait(10)

    vault.on_get = hold

    with ThreadPoolExecutor(8) as pool:
        lookups = [pool.submit(decrypt_string, cache, "shared") for _ in range(8)]
        time.sleep(0.2)
        release.set()
        assert [lookup.result(10) for lookup in lookups] == ["value"] * 8
    assert len(vault.gets) == 1


def test_concurrent_fetches_of_different_secrets_through_the_one_client_each_capture_their_own_value(vault: SecretsHttpStub,
                                                                                                     ring: DefaultKeyRing) -> None:
    # Every request in flight at once, so each response must reach its own fetch's sink.
    names = [f"secret-{i}" for i in range(6)]
    for name in names:
        vault.set(name, f"value of {name}")
    barrier = threading.Barrier(len(names), timeout=10)

    def together(name: str) -> None:
        barrier.wait()

    vault.on_get = together
    cache = create(vault, ring)

    with ThreadPoolExecutor(len(names)) as pool:
        results = list(pool.map(lambda name: decrypt_string(cache, name), names))

    assert results == [f"value of {name}" for name in names]
    assert sorted(vault.gets) == names


def test_a_large_secret_round_trips(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    large = "é-秘密-" * 3000
    assert len(large.encode()) > 16 * 1024
    vault.set("large", large)

    length = cache.find_max_decrypted_length("large")
    assert length is not None
    assert decrypt_string(cache, "large", length) == large


def test_a_cached_secret_still_decrypts_after_the_ring_rotates(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    cache = create(vault, ring)
    vault.set("before", "v1 value")
    vault.set("after", "v2 value")

    assert decrypt_string(cache, "before") == "v1 value"
    ring.add(2, new_key())

    assert decrypt_string(cache, "after") == "v2 value"
    assert decrypt_string(cache, "before") == "v1 value"


def test_in_a_collection_only_names_the_earlier_sources_miss_reach_the_vault(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    vault_cache = create(vault, ring)
    vault.set("from-vault", "vault value")
    local = ProtectedCache(ring)
    local.add("ConnectionStrings:Admin", bytearray(b"local value"))
    collection = ProtectedCacheCollection().add(local).add(vault_cache)

    assert decrypt_string(collection, "ConnectionStrings:Admin") == "local value"
    assert decrypt_string(collection, "from-vault") == "vault value"
    assert vault.gets == ["from-vault"]


# --- Logging and telemetry ------------------------------------------------------------------------


def test_with_sensitive_logging_a_fetch_logs_the_name_only_and_a_failure_logs_an_error(vault: SecretsHttpStub, ring: DefaultKeyRing,
                                                                                       sensitive: None) -> None:
    logger, records = recording_logger()
    cache = create(vault, ring, logger)
    vault.set("item", "never-logged")

    assert decrypt_string(cache, "item") == "never-logged"
    vault.fail_with = 500
    with pytest.raises(HttpResponseError):
        cache.decrypt("other", bytearray(16))

    assert any(r.levelno == logging.DEBUG and getattr(r, HkdfGuardLog.EVENT_ID_KEY) == HkdfGuardEventId.SENSITIVE_OPERATION_LOGGED
               and "item" in r.getMessage() for r in records)
    assert any(r.levelno == logging.ERROR and r.exc_info is not None and isinstance(r.exc_info[1], HttpResponseError) for r in records)
    assert not any("never-logged" in r.getMessage() for r in records)


def test_each_fetch_is_a_populate_span_counted_as_success_not_found_or_error(vault: SecretsHttpStub, ring: DefaultKeyRing, sensitive: None) -> None:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    HkdfGuardTelemetry.set_tracer_provider(tracer_provider)
    HkdfGuardTelemetry.set_meter_provider(meter_provider)
    try:
        cache = create(vault, ring)
        vault.set("Found", "value")
        assert decrypt_string(cache, "Found") == "value"
        assert cache.decrypt("missing", bytearray(16)) == 0
        vault.fail_with = 500
        with pytest.raises(HttpResponseError):
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


def test_with_azure_sdk_logging_enabled_no_response_is_logged_with_the_secret(vault: SecretsHttpStub, ring: DefaultKeyRing,
                                                                              caplog: pytest.LogCaptureFixture) -> None:
    # Java replaces the caller's HTTP log options, .NET refuses content logging; in Python, a captured
    # request streams, and azure-core's NetworkTraceLoggingPolicy doesn't log a streamed body.
    vault.set("item", "never-logged")
    caplog.set_level(logging.DEBUG)

    # The control: a client of the caller's own, with logging_enable, logs the body with the secret in it.
    SecretClient(VAULT, Credential(), **vault.client_options(logging_enable=True)).get_secret("item")
    assert any("never-logged" in record.getMessage() for record in caplog.records)

    caplog.clear()
    cache = create(vault, ring, logging_enable=True)
    assert decrypt_string(cache, "item") == "never-logged"
    assert any("Body is streamable" in record.getMessage() for record in caplog.records)
    assert not any("never-logged" in record.getMessage() for record in caplog.records)


# --- Construction ---------------------------------------------------------------------------------


@pytest.mark.parametrize("option", ["policies", "generated_client", "authentication_policy", "custom_hook_policy", "raw_response_hook",
                                    "logging_policy", "http_logging_policy", "vault_url", "credential"])
def test_client_options_that_would_reach_a_body_before_the_capture_or_bypass_it_are_refused(vault: SecretsHttpStub, ring: DefaultKeyRing,
                                                                                           option: str) -> None:
    with pytest.raises(ValueError, match=f"must not set {option}"):
        AzureKeyVaultSecretCache(VAULT, Credential(), ring, client_options=vault.client_options(**{option: object()}))


def test_a_per_retry_policy_of_the_applications_sees_only_the_redacted_body(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    seen: list[str] = []

    class Peek(SansIOHTTPPolicy[HttpRequest, HttpResponse]):
        def on_response(self, request: PipelineRequest[HttpRequest], response: PipelineResponse[HttpRequest, HttpResponse]) -> None:
            seen.append(response.http_response.read().decode())

    cache = create(vault, ring, per_retry_policies=Peek())
    vault.set("item", "s3cret")

    assert decrypt_string(cache, "item") == "s3cret"
    [body] = seen
    assert "s3cret" not in body and '"value": ""' in body


def test_the_public_constructor_makes_no_call_until_a_secret_is_requested(ring: DefaultKeyRing) -> None:
    with AzureKeyVaultSecretCache("https://example.vault.azure.net/", DefaultAzureCredential(), ring) as cache:
        # An invalid name never reaches the client, so this needs no network or credential.
        assert cache.decrypt("not:a:secret", bytearray(16)) == 0


def test_the_constructor_refuses_nones_and_an_empty_vault_url(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    none: Any = None
    not_a_mapping: Any = [("retry_total", 0)]
    with pytest.raises(TypeError):
        AzureKeyVaultSecretCache(none, Credential(), ring)
    with pytest.raises(TypeError):
        AzureKeyVaultSecretCache(VAULT, none, ring)
    with pytest.raises(TypeError):
        AzureKeyVaultSecretCache(VAULT, Credential(), none)
    with pytest.raises(TypeError):
        AzureKeyVaultSecretCache(VAULT, Credential(), ring, client_options=not_a_mapping)
    with pytest.raises(ValueError):
        AzureKeyVaultSecretCache("", Credential(), ring)


def test_close_closes_the_client_and_cached_values_stay_readable(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    vault.set("item", "value")
    with create(vault, ring) as cache:
        assert decrypt_string(cache, "item") == "value"
    assert decrypt_string(cache, "item") == "value"
    assert vault.gets == ["item"]


# --- The capture policy on its own ----------------------------------------------------------------


def get_secret(name: str) -> HttpRequest:
    # The stub's own token, so the request needs no authentication policy.
    return HttpRequest("GET", f"{VAULT}/secrets/{name}/", headers={"Authorization": f"Bearer {TOKEN}"})


def pipeline(vault: SecretsHttpStub, *policies: Any) -> Pipeline[HttpRequest, HttpResponse]:
    session = requests.Session()
    session.mount("https://", vault)
    return Pipeline(RequestsTransport(session=session, session_owner=False), [*policies, SecretCapturePolicy()])


def send(run_pipeline: Pipeline[HttpRequest, HttpResponse], name: str, sink: SecretValueSink) -> None:
    run_pipeline.run(get_secret(name), **{CAPTURE_OPTION: Capture(sink)})


def test_the_key_vault_secret_secret_client_returns_holds_an_empty_value(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    client = SecretClient(VAULT, Credential(), per_retry_policies=[SecretCapturePolicy()], **vault.client_options())
    vault.set("Db-Password", "s3cret")
    returned: list[KeyVaultSecret] = []

    def fetch(name: str, sink: SecretValueSink) -> None:
        options: dict[str, Any] = {CAPTURE_OPTION: Capture(sink)}
        returned.append(client.get_secret(name, **options))

    cache = SinkProbeCache(ring, fetch)

    assert decrypt_string(cache, "Db-Password") == "s3cret"

    [secret] = returned
    assert secret.value == ""
    assert secret.properties.tags == {"value": "a tag, not the secret"}
    assert secret.name == "Db-Password"


def test_the_policy_captures_the_value_and_hands_on_the_body_with_it_blanked(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    run_pipeline = pipeline(vault)
    vault.set("Db-Password", "s3cret")
    bodies: list[str] = []
    captures: list[Capture] = []

    def fetch(name: str, sink: SecretValueSink) -> None:
        capture = Capture(sink)
        captures.append(capture)
        bodies.append(run_pipeline.run(get_secret(name), **{CAPTURE_OPTION: capture}).http_response.text())

    assert decrypt_string(SinkProbeCache(ring, fetch), "Db-Password") == "s3cret"

    assert captures[0].captured
    assert '"value": ""' in bodies[0] and "s3cret" not in bodies[0]
    assert vault.streams == [True]


def test_the_policy_leaves_an_error_read_for_the_client(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    run_pipeline = pipeline(vault)
    seen: list[tuple[int, str, bool]] = []

    def fetch(name: str, sink: SecretValueSink) -> None:
        capture = Capture(sink)
        response = run_pipeline.run(get_secret(name), **{CAPTURE_OPTION: capture}).http_response
        # Already read: content doesn't raise ResponseNotReadError.
        seen.append((response.status_code, response.content.decode(), capture.captured))

    assert SinkProbeCache(ring, fetch).decrypt("missing", bytearray(16)) == 0

    [(status, body, captured)] = seen
    assert status == 404 and "SecretNotFound" in body and not captured


def test_the_policy_refuses_a_body_that_is_not_json(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    run_pipeline = pipeline(vault)
    vault.raw_body = "not json"
    cache = SinkProbeCache(ring, lambda name, sink: send(run_pipeline, name, sink))

    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item", bytearray(16))


def test_a_request_without_a_capture_passes_through_untouched(vault: SecretsHttpStub) -> None:
    vault.set("item", "value")

    response = pipeline(vault).run(get_secret("item")).http_response

    assert '"value": "value"' in response.text()
    assert vault.streams == [False]


def test_a_capture_option_that_is_not_a_capture_is_refused_before_any_request(vault: SecretsHttpStub) -> None:
    with pytest.raises(TypeError, match="must be a Capture"):
        pipeline(vault).run(get_secret("item"), **{CAPTURE_OPTION: "not a capture"})
    assert vault.gets == []


def test_the_capture_option_never_reaches_the_transport_even_on_a_retry(vault: SecretsHttpStub, ring: DefaultKeyRing) -> None:
    # requests would refuse an unknown keyword; a retry must find the capture in the context again.
    run_pipeline = pipeline(vault, RetryPolicy(retry_total=1, retry_backoff_factor=0))
    vault.set("item", "value")
    vault.fail_with, vault.failures_left = 500, 1
    cache = SinkProbeCache(ring, lambda name, sink: send(run_pipeline, name, sink))

    assert decrypt_string(cache, "item") == "value"
    assert vault.streams == [True, True]
