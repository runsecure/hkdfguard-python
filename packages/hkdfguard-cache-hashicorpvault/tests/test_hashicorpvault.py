"""The cache's real http.client against a fake Vault on loopback."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import ssl
import threading
import time
from collections.abc import Buffer, Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import pytest
from hkdfguard.abstractions import DataProtector, KeyWrapper, ObjectClosedError, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache import InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection
from hkdfguard.cache.hashicorpvault import (
    HashiCorpVaultSecretCache,
    HashiCorpVaultSecretCacheOptions,
    StaticVaultToken,
    VaultKvVersion,
    VaultRequestError,
    VaultTokenProvider,
)
from hkdfguard.cache.hashicorpvault._cache import _retry_delay
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

TOKEN_PURPOSE = HashiCorpVaultSecretCache.TOKEN_PURPOSE
Options = HashiCorpVaultSecretCacheOptions

# --- A fake Vault -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Answer:
    """An answer given as it is: a status, a body ("" for none) and any extra headers."""

    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, vault: FakeVault) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.vault = vault

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A hook that raises drops the connection, as intended; nothing to report.
        pass


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        self.server.vault.handle(self)

    do_LIST = do_POST = do_PUT = do_DELETE = do_GET  # noqa: N815 - BaseHTTPRequestHandler's names


class FakeVault:
    """A KV secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which the
    cache allows on loopback): a GET of a secret's read path with the expected token is answered as
    Vault answers it - the secret, or 404 with an empty error list - for KV version 2 (the default)
    or 1. A request without that token is refused with 403, as Vault refuses it. Any other request -
    a LIST, a query, another path - is recorded in :attr:`unexpected_requests` and refused. Paths are
    matched exactly, as Vault matches them."""

    TOKEN = "hvs.CAESIFakeTokenForTests"

    def __init__(self, mount_path: str = "secret", kv_version: VaultKvVersion = VaultKvVersion.V2, path_prefix: str = "") -> None:
        self.mount_path = mount_path
        self.kv_version = kv_version
        self.path_prefix = path_prefix
        self.secrets: dict[str, dict[str, Any]] = {}
        self.deleted: set[str] = set()
        self._lock = threading.Lock()
        self._reads: list[str] = []
        self._tokens: list[str] = []
        self._namespaces: list[str] = []
        self._vault_request_headers: list[str] = []
        self._unexpected: list[str] = []
        # When set, a read with the right token is answered with this.
        self.answer: Answer | None = None
        # When set, runs inside every read before it answers: may hold it open, write to it, or raise
        # to drop the connection.
        self.on_read: Callable[[_Handler], object] | None = None
        # Set on close, so hooks holding a read open let go.
        self.stopping = threading.Event()
        self._server = _Server(self)
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def address(self) -> str:
        """Vault's address, with the path prefix if any, as VAULT_ADDR would hold it."""
        return f"http://127.0.0.1:{self.port}{self.path_prefix}/"

    def read_url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{self._read_prefix()}{path}"

    def set_data(self, path: str, data: dict[str, Any]) -> None:
        self.secrets[path] = data

    def set(self, path: str, value: str) -> None:
        self.set_data(path, {"value": value})

    def set_deleted(self, path: str) -> None:
        """A KV version 2 secret whose latest version is deleted: Vault answers 404 with its metadata."""
        self.deleted.add(path)

    @property
    def reads(self) -> list[str]:
        with self._lock:
            return list(self._reads)

    @property
    def tokens(self) -> list[str]:
        with self._lock:
            return list(self._tokens)

    @property
    def namespaces(self) -> list[str]:
        with self._lock:
            return list(self._namespaces)

    @property
    def vault_request_headers(self) -> list[str]:
        with self._lock:
            return list(self._vault_request_headers)

    @property
    def unexpected_requests(self) -> list[str]:
        with self._lock:
            return list(self._unexpected)

    def close(self) -> None:
        self.stopping.set()
        self._server.shutdown()
        self._server.server_close()

    def _read_prefix(self) -> str:
        return f"{self.path_prefix}/v1/{self.mount_path}/" + ("data/" if self.kv_version is VaultKvVersion.V2 else "")

    def handle(self, handler: _Handler) -> None:
        parts = urlsplit(handler.path)
        prefix = self._read_prefix()
        if handler.command != "GET" or parts.query or not parts.path.startswith(prefix):
            with self._lock:
                self._unexpected.append(f"{handler.command} {handler.path}")
            respond(handler, Answer(405, '{"errors":["1 error occurred:\\n\\t* unsupported operation\\n\\n"]}'))
            return

        token = handler.headers.get("X-Vault-Token")
        path = parts.path[len(prefix):]
        with self._lock:
            self._tokens.append(token or "")
            self._namespaces.append(handler.headers.get("X-Vault-Namespace") or "(none)")
            self._vault_request_headers.append(handler.headers.get("X-Vault-Request") or "(none)")
            self._reads.append(path)

        hook = self.on_read
        if hook is not None:
            hook(handler)

        given = self.answer
        if token != self.TOKEN:
            respond(handler, Answer(403, '{"errors":["permission denied"]}'))
        elif given is not None:
            respond(handler, given)
        elif path in self.deleted:
            respond(handler, Answer(404, envelope({"data": None, "metadata": metadata(deleted=True)}, 0)))
        elif path not in self.secrets:
            respond(handler, Answer(404, '{"errors":[]}'))
        elif self.kv_version is VaultKvVersion.V2:
            respond(handler, Answer(200, envelope({"data": self.secrets[path], "metadata": metadata(deleted=False)}, 0)))
        else:
            respond(handler, Answer(200, envelope(self.secrets[path], 2764800)))


def metadata(*, deleted: bool) -> dict[str, Any]:
    return {"created_time": "2026-10-28T12:00:00.000000Z", "custom_metadata": None,
            "deletion_time": "2026-10-28T13:00:00.000000Z" if deleted else "", "destroyed": False, "version": 3}


def envelope(data: Any, lease_duration: int) -> str:
    return json.dumps({"request_id": "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a", "lease_id": "", "renewable": False,
                       "lease_duration": lease_duration, "data": data, "wrap_info": None, "warnings": None, "auth": None,
                       "mount_type": "kv"})


def respond(handler: _Handler, answer: Answer) -> None:
    body = answer.body.encode()
    handler.send_response(answer.status)
    handler.send_header("Content-Type", "application/json")
    for name, value in answer.headers.items():
        handler.send_header(name, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class FakeTokenProvider(VaultTokenProvider):
    """A token provider that counts its calls, and can hand out any token, fail or hang. Each token
    :attr:`next` gives is protected by :attr:`protector`, as a real provider's is, unless the provider
    is unprotected."""

    def __init__(self, *, unprotected: bool = False) -> None:
        self.unprotected = unprotected
        self.calls = 0
        # Gives the token for call number n (from 1); may raise.
        self.next: Callable[[int], str | None] = lambda call: FakeVault.TOKEN
        # Protects every token handed out; set to the cache's own token protector.
        self.protector: DataProtector | None = None
        # When set, get_token blocks until released, and get_token_async never returns.
        self.hang = False
        self.release = threading.Event()
        self.async_cancelled = threading.Event()

    @staticmethod
    def giving(token: str) -> FakeTokenProvider:
        provider = FakeTokenProvider()
        provider.next = lambda call: token
        return provider

    def _give(self) -> str:
        self.calls += 1
        token = self.next(self.calls)
        return token if self.unprotected or self.protector is None or token is None else self.protector.encrypt(token)  # type: ignore[return-value]

    def get_token(self) -> str:
        if self.hang:
            self.release.wait(10)
        return self._give()

    async def get_token_async(self) -> str:
        if self.hang:
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                self.async_cancelled.set()
                raise
        return self._give()


# --- Rings and caches -------------------------------------------------------------------------


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
def make_ring() -> Iterator[Callable[..., DefaultKeyRing]]:
    rings: list[DefaultKeyRing] = []

    def make(version: int = 1) -> DefaultKeyRing:
        ring = DefaultKeyRing(DefaultFormatProvider())
        ring.add(version, new_key())
        rings.append(ring)
        return ring

    yield make
    for ring in rings:
        ring.close()


@pytest.fixture
def vaults() -> Iterator[Callable[..., FakeVault]]:
    started: list[FakeVault] = []

    def start(*args: Any) -> FakeVault:
        vault = FakeVault(*args)
        started.append(vault)
        return vault

    yield start
    for vault in started:
        vault.close()


@pytest.fixture
def vault(vaults: Callable[..., FakeVault]) -> FakeVault:
    return vaults()


Create = Callable[..., HashiCorpVaultSecretCache]


@pytest.fixture
def create(vault: FakeVault, make_ring: Callable[..., DefaultKeyRing]) -> Iterator[Create]:
    """A cache on a ring of its own, given the fake's token protected for it. No backoff, only each
    retry's 0-100 ms of jitter, so a test that meets a 5xx stays quick."""
    caches: list[HashiCorpVaultSecretCache] = []

    def make(*, on: FakeVault | None = None, address: str | None = None, tokens: VaultTokenProvider | None = None,
             logger: logging.Logger | None = None, ring: DefaultKeyRing | None = None, **options: Any) -> HashiCorpVaultSecretCache:
        target = on or vault
        options.setdefault("retry_delay", timedelta(0))
        ring = ring or make_ring()
        protector = ring.create_protector(TOKEN_PURPOSE)
        if isinstance(tokens, FakeTokenProvider) and tokens.protector is None and not tokens.unprotected:
            tokens.protector = protector
        provider = tokens if tokens is not None else StaticVaultToken.protect(protector, FakeVault.TOKEN)
        cache = HashiCorpVaultSecretCache(address or target.address, provider, protector, ring, options=Options(**options), logger=logger)
        caches.append(cache)
        return cache

    yield make
    for cache in caches:
        cache.close()


def new_cache(make_ring: Callable[..., DefaultKeyRing], address: str = "https://vault.example.com:8200", options: Options | None = None,
              ring: DefaultKeyRing | None = None) -> HashiCorpVaultSecretCache:
    ring = ring or make_ring()
    protector = ring.create_protector(TOKEN_PURPOSE)
    return HashiCorpVaultSecretCache(address, StaticVaultToken.protect(protector, FakeVault.TOKEN), protector, ring, options=options)


def decrypt_string(cache: ProtectedReadOnlyCache, name: str, size: int = 64) -> str:
    result = bytearray(size)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_string_async(cache: ProtectedReadOnlyCache, name: str, size: int = 64) -> str:
    result = bytearray(size)
    return result[: await cache.decrypt_async(name, result)].decode()


def recording_logger() -> tuple[logging.Logger, list[logging.LogRecord]]:
    records: list[logging.LogRecord] = []

    class Recording(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.Logger("recording", logging.DEBUG)
    logger.addHandler(Recording(logging.DEBUG))
    return logger, records


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def eventually(condition: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + 5
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    return True


def chain(error: BaseException) -> list[BaseException]:
    # The exception and everything chained to it.
    found: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and current not in found:
        found.append(current)
        current = current.__cause__ or current.__context__
    return found


# --- Reading ----------------------------------------------------------------------------------


def test_decrypt_on_miss_reads_the_one_secret_then_serves_it_from_the_cache(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set("myapp/Db", "s3cret")

    assert decrypt_string(cache, "myapp/Db") == "s3cret"
    assert decrypt_string(cache, "myapp/Db") == "s3cret"

    assert vault.reads == ["myapp/Db"]
    assert vault.vault_request_headers == ["true"]
    assert vault.unexpected_requests == []


def test_one_read_caches_every_key_the_secret_holds(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set_data("myapp/db", {"username": "app", "password": "s3cret", "value": "default", "Mixed-Case.key:1": "mixed"})

    assert decrypt_string(cache, "myapp/db#password") == "s3cret"
    assert decrypt_string(cache, "myapp/db#username") == "app"
    assert decrypt_string(cache, "myapp/db") == "default"
    assert decrypt_string(cache, "myapp/db#value") == "default"
    assert decrypt_string(cache, "myapp/db#Mixed-Case.key:1") == "mixed"

    assert vault.reads == ["myapp/db"]


def test_concurrent_misses_on_different_keys_share_one_read(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set_data("shared", {"a": "1", "b": "2", "value": "3"})
    release = threading.Event()
    vault.on_read = lambda handler: release.wait(10)

    with ThreadPoolExecutor(3) as pool:
        results = [pool.submit(decrypt_string, cache, name) for name in ("shared#a", "shared#b", "shared")]
        time.sleep(0.2)
        release.set()

        assert [r.result(10) for r in results] == ["1", "2", "3"]
    assert len(vault.reads) == 1


def test_concurrent_misses_on_one_name_share_one_fetch(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set("shared", "value")
    release = threading.Event()
    vault.on_read = lambda handler: release.wait(10)

    with ThreadPoolExecutor(8) as pool:
        results = [pool.submit(decrypt_string, cache, "shared") for _ in range(8)]
        time.sleep(0.2)
        release.set()

        assert all(r.result(10) == "value" for r in results)
    assert len(vault.reads) == 1


def test_decrypt_async_reads_without_blocking(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set_data("myapp/db", {"password": "s3cret", "value": "default"})

    async def main() -> None:
        assert await decrypt_string_async(cache, "myapp/db#password") == "s3cret"
        assert await decrypt_string_async(cache, "myapp/db") == "default"
        assert await cache.decrypt_async("missing", bytearray(16)) == 0
        assert await cache.find_max_decrypted_length_async("missing") is None

    asyncio.run(main())
    assert vault.reads == ["myapp/db", "missing", "missing"]


def test_cancelling_an_async_lookup_while_the_provider_is_awaited_cancels_the_providers_coroutine(vault: FakeVault, create: Create) -> None:
    tokens = FakeTokenProvider(unprotected=True)
    tokens.hang = True
    cache = create(tokens=tokens)

    async def main() -> None:
        lookup = asyncio.create_task(cache.decrypt_async("item", bytearray(16)))
        await asyncio.sleep(0.1)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup

    asyncio.run(main())
    assert tokens.async_cancelled.is_set()
    assert vault.reads == []


def test_cancelling_an_async_lookup_while_vault_is_answering_abandons_the_request_and_is_not_retried(vault: FakeVault, create: Create) -> None:
    cache = create()
    # Transient, so a read that wasn't abandoned would be retried once Vault answers.
    vault.answer = Answer(503, '{"errors":["Vault is sealed"]}')
    arrived = threading.Event()

    def hold(handler: _Handler) -> None:
        arrived.set()
        vault.stopping.wait(1)

    vault.on_read = hold

    async def main() -> None:
        lookup = asyncio.create_task(cache.decrypt_async("item", bytearray(16)))
        assert await asyncio.to_thread(arrived.wait, 10)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup

    # asyncio.run waits for the worker thread making the request, so it has ended - its socket shut
    # down, or (on Windows, where that doesn't wake a blocked read) once Vault answered - by now.
    asyncio.run(main())
    time.sleep(0.3)
    assert len(vault.reads) == 1


def test_the_default_key_is_configurable(vault: FakeVault, create: Create) -> None:
    cache = create(default_key="secret_value")
    vault.set_data("item", {"value": "wrong", "secret_value": "right"})

    assert decrypt_string(cache, "item") == "right"


def test_kv_version_1_is_read_at_the_mounts_own_path(vaults: Callable[..., FakeVault], create: Create) -> None:
    v1 = vaults("kv", VaultKvVersion.V1, "")
    cache = create(on=v1, kv_version=VaultKvVersion.V1, mount_path="kv")
    v1.set_data("myapp/db", {"password": "v1 value"})

    assert decrypt_string(cache, "myapp/db#password") == "v1 value"
    assert cache.decrypt("missing", bytearray(16)) == 0
    assert v1.unexpected_requests == []


def test_a_nested_mount_path_and_an_address_prefix_are_kept(vaults: Callable[..., FakeVault], create: Create) -> None:
    prefixed = vaults("kv/team-a", VaultKvVersion.V2, "/vault")
    cache = create(on=prefixed, mount_path="kv/team-a")
    prefixed.set("item", "prefixed")

    assert decrypt_string(cache, "item") == "prefixed"
    assert prefixed.unexpected_requests == []


def test_an_address_without_a_trailing_slash_is_read_the_same(vaults: Callable[..., FakeVault], create: Create) -> None:
    prefixed = vaults("secret", VaultKvVersion.V2, "/vault")
    cache = create(on=prefixed, address=prefixed.address.rstrip("/"))
    prefixed.set("item", "prefixed")

    assert decrypt_string(cache, "item") == "prefixed"


def test_the_namespace_is_sent_only_when_set(vault: FakeVault, create: Create) -> None:
    with_namespace = create(namespace="team-a/prod")
    without = create()
    vault.set("item", "value")

    decrypt_string(with_namespace, "item")
    decrypt_string(without, "item")

    assert vault.namespaces == ["team-a/prod", "(none)"]


# --- The token --------------------------------------------------------------------------------


def test_every_fetch_asks_the_provider_for_the_token(vault: FakeVault, create: Create) -> None:
    tokens = FakeTokenProvider()
    cache = create(tokens=tokens)
    vault.set("a", "1")
    vault.set("b", "2")

    decrypt_string(cache, "a")
    decrypt_string(cache, "a")
    decrypt_string(cache, "b")

    assert tokens.calls == 2
    assert vault.tokens == [FakeVault.TOKEN, FakeVault.TOKEN]


def test_a_refused_token_raises_403_and_a_new_token_is_used_next_time(vault: FakeVault, create: Create) -> None:
    tokens = FakeTokenProvider()
    tokens.next = lambda call: "hvs.expired" if call == 1 else FakeVault.TOKEN
    cache = create(tokens=tokens)
    vault.set("item", "value")

    with pytest.raises(VaultRequestError) as raised:
        cache.decrypt("item", bytearray(16))
    assert raised.value.status_code == 403
    assert "permission denied" in str(raised.value)
    assert "hvs." not in str(raised.value)

    assert decrypt_string(cache, "item") == "value"


@pytest.mark.parametrize("token", ["has space", "tab\tinside", "café"])
def test_a_token_that_cant_be_sent_is_refused_without_calling_vault(vault: FakeVault, create: Create, token: str) -> None:
    cache = create(tokens=FakeTokenProvider.giving(token))

    with pytest.raises(RuntimeError):
        cache.decrypt("item", bytearray(16))
    assert vault.reads == []


@pytest.mark.parametrize("handed_over", ["", FakeVault.TOKEN, "enc::v1::not base64!", "enc::v1"])
def test_an_unprotected_token_is_refused_without_calling_vault_or_quoting_it(vault: FakeVault, create: Create, handed_over: str) -> None:
    tokens = FakeTokenProvider(unprotected=True)
    tokens.next = lambda call: handed_over
    cache = create(tokens=tokens)

    with pytest.raises(RuntimeError) as raised:
        cache.decrypt("item", bytearray(16))

    assert raised.value.__cause__ is None and raised.value.__context__ is None
    if handed_over:
        assert handed_over not in str(raised.value)
    assert vault.reads == []


@pytest.mark.parametrize("handed_over", [None, 42])
def test_a_provider_returning_no_token_is_refused_without_calling_vault(vault: FakeVault, create: Create, handed_over: Any) -> None:
    tokens = FakeTokenProvider(unprotected=True)
    tokens.next = lambda call: handed_over
    cache = create(tokens=tokens)

    with pytest.raises(RuntimeError, match="no token"):
        cache.decrypt("item", bytearray(16))
    with pytest.raises(RuntimeError, match="no token"):
        asyncio.run(cache.decrypt_async("item", bytearray(16)))
    assert vault.reads == []


@pytest.mark.parametrize("how", ["another purpose", "another ring", "a version not on the ring"])
def test_a_token_protected_with_another_key_or_purpose_is_refused_without_calling_vault(vault: FakeVault, make_ring: Callable[..., DefaultKeyRing],
                                                                                       how: str) -> None:
    ring = make_ring()
    protector = ring.create_protector(TOKEN_PURPOSE)
    foreign = {
        "another purpose": lambda: ring.create_protector("Some.Other.Purpose"),
        "another ring": lambda: make_ring().create_protector(TOKEN_PURPOSE),
        "a version not on the ring": lambda: make_ring(7).create_protector(TOKEN_PURPOSE),
    }[how]()
    with HashiCorpVaultSecretCache(vault.address, StaticVaultToken(foreign.encrypt(FakeVault.TOKEN)), protector, ring) as cache:
        with pytest.raises(RuntimeError) as raised:
            cache.decrypt("item", bytearray(16))

        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert vault.reads == []


def test_the_token_is_decrypted_for_each_request_and_reaches_vault_intact(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set("a", "1")
    vault.set("b", "2")

    assert decrypt_string(cache, "a") == "1"
    assert decrypt_string(cache, "b") == "2"

    assert vault.tokens == [FakeVault.TOKEN, FakeVault.TOKEN]


def test_a_long_token_is_sent_whole(vault: FakeVault, create: Create) -> None:
    long_token = "hvs." + "x" * 2000
    cache = create(tokens=FakeTokenProvider.giving(long_token))

    # Not the fake's token, so Vault refuses it - after receiving it intact.
    with pytest.raises(VaultRequestError):
        cache.decrypt("item", bytearray(16))

    assert vault.tokens == [long_token]


def test_a_token_provider_failure_is_not_retried_and_propagates_as_it_is(vault: FakeVault, create: Create) -> None:
    tokens = FakeTokenProvider()
    failure = RuntimeError("The login endpoint is unreachable.")

    def fail(call: int) -> str:
        raise failure

    tokens.next = fail
    cache = create(tokens=tokens)

    with pytest.raises(RuntimeError) as raised:
        cache.decrypt("item", bytearray(16))
    assert raised.value is failure
    assert tokens.calls == 1

    with pytest.raises(RuntimeError) as raised:
        asyncio.run(cache.decrypt_async("item", bytearray(16)))
    assert raised.value is failure
    assert tokens.calls == 2
    assert vault.reads == []


def test_a_token_providers_os_error_propagates_as_it_is_and_is_not_retried(vault: FakeVault, create: Create) -> None:
    tokens = FakeTokenProvider()

    def fail(call: int) -> str:
        raise FileNotFoundError("The token file can't be read.")

    tokens.next = fail
    cache = create(tokens=tokens)

    with pytest.raises(FileNotFoundError, match="token file"):
        cache.decrypt("item", bytearray(16))
    assert tokens.calls == 1
    assert vault.reads == []


def test_a_provider_slower_than_the_timeout_times_out(vault: FakeVault, create: Create) -> None:
    tokens = FakeTokenProvider(unprotected=True)
    tokens.hang = True
    cache = create(tokens=tokens, timeout=timedelta(milliseconds=100))
    try:
        with pytest.raises(TimeoutError, match="no token within"):
            cache.decrypt("item", bytearray(16))
        with pytest.raises(TimeoutError, match="no token within"):
            asyncio.run(cache.decrypt_async("item", bytearray(16)))

        assert tokens.async_cancelled.is_set()
        assert vault.reads == []
    finally:
        tokens.release.set()


# --- Retries ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "body"), [
    (503, '{"errors":["Vault is sealed"]}'),
    (429, '{"errors":["request path \\"secret/data/item\\": rate limit quota exceeded"]}'),
    (500, '{"errors":["internal error"]}'),
    (502, "<html>Bad Gateway</html>"),
    (504, ""),
])
def test_a_transient_answer_is_retried_until_vault_answers(vault: FakeVault, create: Create, status: int, body: str) -> None:
    tokens = FakeTokenProvider()
    cache = create(tokens=tokens)
    vault.set("item", "value")
    vault.answer = Answer(status, body)

    def recover(handler: _Handler) -> None:
        if len(vault.reads) == 3:
            vault.answer = None

    vault.on_read = recover

    assert decrypt_string(cache, "item") == "value"

    assert len(vault.reads) == 3
    assert tokens.calls == 1


@pytest.mark.parametrize("retry_count", [Options.MIN_RETRY_COUNT, Options.MAX_RETRY_COUNT])
def test_a_transient_answer_is_retried_retry_count_times_then_propagates(vault: FakeVault, create: Create, retry_count: int) -> None:
    cache = create(retry_count=retry_count)
    vault.answer = Answer(503, '{"errors":["Vault is sealed"]}')

    with pytest.raises(VaultRequestError) as raised:
        cache.decrypt("item", bytearray(16))

    assert raised.value.status_code == 503
    assert raised.value.is_transient
    assert len(vault.reads) == 1 + retry_count


@pytest.mark.parametrize(("status", "body"), [
    (403, '{"errors":["permission denied"]}'),
    (404, '{"errors":["no handler for route"]}'),
    (400, '{"errors":["bad request"]}'),
    (501, '{"errors":["unsupported operation"]}'),
    (307, ""),
])
def test_an_answer_that_would_repeat_is_not_retried(vault: FakeVault, create: Create, status: int, body: str) -> None:
    cache = create()
    vault.answer = Answer(status, body)

    with pytest.raises(VaultRequestError) as raised:
        cache.decrypt("item", bytearray(16))

    assert not raised.value.is_transient
    assert len(vault.reads) == 1


@pytest.mark.parametrize("how", ["no answer", "dropped mid-response", "attempt timed out"])
def test_a_lost_connection_is_retried(vault: FakeVault, create: Create, how: str) -> None:
    cache = create(timeout=timedelta(milliseconds=300))
    vault.set("item", "value")

    def lose(handler: _Handler) -> None:
        if len(vault.reads) > 2:
            return
        if how == "no answer":
            raise ConnectionAbortedError("The connection is dropped without an answer.")
        if how == "dropped mid-response":
            handler.send_response(200)
            handler.send_header("Content-Length", "200")
            handler.end_headers()
            handler.wfile.write(b'{"data":{"data":{"value":"val')
            handler.wfile.flush()
            raise ConnectionAbortedError("The connection is dropped mid-response.")
        vault.stopping.wait(1)

    vault.on_read = lose

    assert decrypt_string(cache, "item") == "value"
    assert len(vault.reads) == 3


def test_a_body_that_stalls_times_out_within_the_attempts_timeout_and_is_retried(vault: FakeVault, create: Create) -> None:
    cache = create(timeout=timedelta(milliseconds=300))

    def stall(handler: _Handler) -> None:
        handler.send_response(200)
        handler.end_headers()
        handler.wfile.write(b'{"data":{"data":{"value":"val')
        handler.wfile.flush()
        vault.stopping.wait(5)
        raise ConnectionAbortedError("Never finished.")

    vault.on_read = stall

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="took longer than"):
        cache.decrypt("item", bytearray(16))
    elapsed = time.monotonic() - started

    assert len(vault.reads) == 1 + Options.MIN_RETRY_COUNT
    # Four attempts of 300 ms and three waits of at most 100 ms, far short of one stalled body.
    assert elapsed < 4, elapsed


def test_an_unreachable_vault_is_retried_then_raises_the_os_error(create: Create) -> None:
    cache = create(address=f"http://127.0.0.1:{free_port()}/")

    with pytest.raises(OSError):
        cache.decrypt("item", bytearray(16))


@pytest.mark.parametrize(("base", "retry", "jitter", "expected"), [
    (200, 0, 0, 200), (200, 1, 0, 400), (200, 2, 0, 800), (200, 5, 0, 6400), (200, 6, 0, 10000), (200, 9, 0, 10000),
    (200, 0, 100, 300), (200, 9, 100, 10100), (0, 3, 37, 37), (10000, 0, 0, 10000), (10000, 40, 0, 10000),
])
def test_retry_delay_doubles_up_to_the_maximum_plus_the_jitter(base: int, retry: int, jitter: int, expected: int) -> None:
    assert _retry_delay(timedelta(milliseconds=base), retry, jitter) == timedelta(milliseconds=expected)


def test_the_retry_options_are_checked(make_ring: Callable[..., DefaultKeyRing]) -> None:
    for invalid in (Options(retry_count=Options.MIN_RETRY_COUNT - 1), Options(retry_count=Options.MAX_RETRY_COUNT + 1),
                    Options(retry_delay=timedelta(milliseconds=-1)), Options(retry_delay=Options.MAX_RETRY_DELAY + timedelta(microseconds=1))):
        with pytest.raises(ValueError, match="retry"):
            new_cache(make_ring, options=invalid)

    new_cache(make_ring, options=Options(retry_count=Options.MIN_RETRY_COUNT, retry_delay=timedelta(0)))
    new_cache(make_ring, options=Options(retry_count=Options.MAX_RETRY_COUNT, retry_delay=Options.MAX_RETRY_DELAY))


# --- What Vault answers -----------------------------------------------------------------------


def test_a_value_with_json_escapes_is_unescaped_exactly(vault: FakeVault, create: Create) -> None:
    cache = create()
    secret = 'p"a\\ss/wörd\n\u0001秘密'
    vault.set("escaped", secret)

    assert decrypt_string(cache, "escaped") == secret


def test_a_large_secret_round_trips(vault: FakeVault, create: Create) -> None:
    cache = create()
    large = "é-秘密-" * 1500
    vault.set("large", large)

    maximum = cache.find_max_decrypted_length("large")
    assert maximum is not None
    assert decrypt_string(cache, "large", maximum) == large


def test_paths_differing_only_in_case_are_different_secrets_and_different_entries(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set("myapp/Db", "upper")
    vault.set("myapp/db", "lower")

    assert decrypt_string(cache, "myapp/Db") == "upper"
    assert decrypt_string(cache, "myapp/db") == "lower"
    assert cache.decrypt("MYAPP/DB", bytearray(16)) == 0
    assert decrypt_string(cache, "myapp/Db") == "upper"

    assert vault.reads == ["myapp/Db", "myapp/db", "MYAPP/DB"]


def test_a_missing_secret_returns_zero_and_is_looked_up_again_until_it_exists(vault: FakeVault, create: Create) -> None:
    cache = create()

    assert cache.decrypt("later", bytearray(16)) == 0
    assert cache.find_max_decrypted_length("later") is None

    vault.set("later", "now here")
    assert decrypt_string(cache, "later") == "now here"
    assert len(vault.reads) == 3


def test_a_deleted_latest_version_is_reported_missing(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set_deleted("gone")

    assert cache.decrypt("gone", bytearray(16)) == 0


def test_numbers_and_booleans_are_cached_as_their_text_and_other_values_are_missing(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set_data("item", {"number": 5432, "flag": True, "empty": "", "object": {"value": "nested"}, "array": ["x"], "null": None})

    assert decrypt_string(cache, "item#number") == "5432"
    assert decrypt_string(cache, "item#flag") == "true"
    for key in ("absent", "empty", "object", "array", "null", "value"):
        assert cache.decrypt(f"item#{key}", bytearray(16)) == 0, key


def test_a_duplicated_key_is_refused(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.answer = Answer(200, '{"data":{"data":{"k":"a","k":"b"}}}')

    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item#k", bytearray(16))


@pytest.mark.parametrize("body", ["not json", '["value"]', '{"data":{"data":{"value":"a","value":"b"}}}', ""])
def test_a_response_that_cant_be_trusted_is_refused_and_not_retried(vault: FakeVault, create: Create, body: str) -> None:
    cache = create()
    vault.answer = Answer(200, body)

    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item", bytearray(16))
    assert len(vault.reads) == 1


@pytest.mark.parametrize(("status", "body", "expected"), [
    (404, '{"errors":["no handler for route \\"nope/data/item\\". route entry not found."]}', "no handler for route"),
    (404, "<html>Not Found</html>", "HTTP 404"),
    (503, '{"errors":["Vault is sealed"]}', "Vault is sealed"),
    (500, '["internal"]', "HTTP 500"),
    (500, '{"errors":"internal"}', "HTTP 500"),
    (307, "", "HTTP 307"),
    (502, '{"request_id":"x"}', "HTTP 502"),
])
def test_any_other_answer_raises_with_vaults_status_and_errors(vault: FakeVault, create: Create, status: int, body: str, expected: str) -> None:
    cache = create()
    vault.answer = Answer(status, body)

    with pytest.raises(VaultRequestError) as raised:
        cache.decrypt("item", bytearray(16))
    assert raised.value.status_code == status
    assert expected in str(raised.value)
    assert "'item'" in str(raised.value)
    assert FakeVault.TOKEN not in str(raised.value)

    vault.answer = None
    vault.set("item", "value")
    assert decrypt_string(cache, "item") == "value"


def test_a_redirect_is_not_followed(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set("elsewhere", "value")
    vault.answer = Answer(307, "", {"Location": vault.read_url("elsewhere")})

    with pytest.raises(VaultRequestError) as raised:
        cache.decrypt("item", bytearray(16))

    assert raised.value.status_code == 307
    assert vault.reads == ["item"]


# --- Names ------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "", "ConnectionStrings:Admin", "../sys/seal-status", "myapp/../other", "myapp/./db", "..", "/leading", "trailing/",
    "double//slash", "has space", "café", "bang!", "query?list=true", "percent%2F", "item#", "#key", "item#a#b", "item#a b",
    "item#bang!", "x" * (HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH + 1),
])
def test_a_name_that_isnt_a_path_and_key_is_missing_without_calling_vault(vault: FakeVault, create: Create, name: str) -> None:
    cache = create()

    assert cache.decrypt(name, bytearray(16)) == 0
    assert cache.find_max_decrypted_length(name) is None
    assert asyncio.run(cache.decrypt_async(name, bytearray(16))) == 0
    assert vault.reads == []
    assert vault.unexpected_requests == []


def test_is_valid_secret_name_accepts_paths_up_to_the_limit() -> None:
    limit = HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH
    assert HashiCorpVaultSecretCache.is_valid_secret_name("a")
    assert HashiCorpVaultSecretCache.is_valid_secret_name("team-a/my_app/db.v2")
    assert HashiCorpVaultSecretCache.is_valid_secret_name("...x/x..")
    assert not HashiCorpVaultSecretCache.is_valid_secret_name("myapp/db#password")
    assert HashiCorpVaultSecretCache.is_valid_secret_name("x" * limit)
    assert not HashiCorpVaultSecretCache.is_valid_secret_name("x" * (limit + 1))
    assert not HashiCorpVaultSecretCache.is_valid_secret_name("ünïcode")
    assert not HashiCorpVaultSecretCache.is_valid_secret_name(None)


# --- The cache --------------------------------------------------------------------------------


def test_a_cached_secret_still_decrypts_after_the_ring_rotates(vault: FakeVault, create: Create, make_ring: Callable[..., DefaultKeyRing]) -> None:
    ring = make_ring()
    cache = create(ring=ring)
    vault.set("before", "v1 value")
    vault.set("after", "v2 value")

    assert decrypt_string(cache, "before") == "v1 value"
    ring.add(2, new_key())

    assert decrypt_string(cache, "after") == "v2 value"
    assert decrypt_string(cache, "before") == "v1 value"


def test_in_a_collection_only_names_the_earlier_sources_miss_reach_vault(vault: FakeVault, create: Create,
                                                                         make_ring: Callable[..., DefaultKeyRing]) -> None:
    vault_cache = create()
    vault.set("from-vault", "vault value")
    local = ProtectedCache(make_ring())
    local.add("ConnectionStrings:Admin", bytearray(b"local value"))
    collection = ProtectedCacheCollection().add(local).add(vault_cache)

    assert decrypt_string(collection, "ConnectionStrings:Admin") == "local value"
    assert decrypt_string(collection, "from-vault") == "vault value"
    assert vault.reads == ["from-vault"]


def test_with_sensitive_logging_a_fetch_logs_the_name_only_and_a_failure_logs_an_error(vault: FakeVault, create: Create, sensitive: None) -> None:
    logger, records = recording_logger()
    cache = create(logger=logger)
    vault.set("myapp/Item", "never-logged")

    assert decrypt_string(cache, "myapp/Item") == "never-logged"
    vault.answer = Answer(503, '{"errors":["Vault is sealed"]}')
    with pytest.raises(VaultRequestError):
        cache.decrypt("other", bytearray(16))

    # The secret's own name, not its escaped entry name.
    assert any(r.levelno == logging.DEBUG and getattr(r, HkdfGuardLog.EVENT_ID_KEY, None) == HkdfGuardEventId.SENSITIVE_OPERATION_LOGGED
               and "myapp/Item" in r.getMessage() for r in records)
    assert any(r.levelno == logging.ERROR and r.exc_info is not None and isinstance(r.exc_info[1], VaultRequestError) for r in records)
    assert not any("never-logged" in r.getMessage() or FakeVault.TOKEN in r.getMessage() for r in records)


def test_each_fetch_is_a_populate_span_counted_and_the_token_is_nowhere_in_it(vault: FakeVault, create: Create, sensitive: None) -> None:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    HkdfGuardTelemetry.set_tracer_provider(tracer_provider)
    HkdfGuardTelemetry.set_meter_provider(meter_provider)
    try:
        cache = create()
        vault.set("found", "never-traced")
        assert decrypt_string(cache, "found") == "never-traced"
        assert cache.decrypt("missing", bytearray(16)) == 0
        vault.answer = Answer(403, '{"errors":["permission denied"]}')
        with pytest.raises(VaultRequestError):
            cache.decrypt("refused", bytearray(16))

        found, missing, failed = [s for s in exporter.get_finished_spans() if s.name == SpanNames.Cache.POPULATE]
        assert any(e.attributes and e.attributes.get(AttributeNames.NAME) == "found" for e in found.events)
        assert found.status.status_code != StatusCode.ERROR and missing.status.status_code != StatusCode.ERROR
        assert failed.status.status_code == StatusCode.ERROR
        everything = repr([(s.attributes, [(e.name, e.attributes) for e in s.events], s.status.description) for s in exporter.get_finished_spans()])
        assert FakeVault.TOKEN not in everything and "never-traced" not in everything

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


def test_no_failure_quotes_the_token(vault: FakeVault, create: Create) -> None:
    failures: list[BaseException] = []
    for status in (403, 404, 503):
        vault.answer = Answer(status, json.dumps({"errors": ["denied"]}))
        cache = create()
        with pytest.raises(VaultRequestError) as raised:
            cache.decrypt("item", bytearray(16))
        failures.append(raised.value)
    cache = create(address=f"http://127.0.0.1:{free_port()}/")
    with pytest.raises(OSError) as unreachable:
        cache.decrypt("item", bytearray(16))
    failures.append(unreachable.value)

    for failure in failures:
        for linked in chain(failure):
            assert FakeVault.TOKEN not in repr(linked) and FakeVault.TOKEN not in str(linked.args)


def test_after_close_cached_secrets_are_served_but_nothing_is_read(vault: FakeVault, create: Create) -> None:
    cache = create()
    vault.set("item", "value")
    vault.set("other", "value")
    assert decrypt_string(cache, "item") == "value"

    cache.close()
    cache.close()

    assert decrypt_string(cache, "item") == "value"
    with pytest.raises(ObjectClosedError):
        cache.decrypt("other", bytearray(16))
    with pytest.raises(ObjectClosedError):
        asyncio.run(cache.decrypt_async("other", bytearray(16)))
    assert vault.reads == ["item"]


def test_the_cache_is_a_context_manager_that_closes(vault: FakeVault, make_ring: Callable[..., DefaultKeyRing]) -> None:
    vault.set("item", "value")
    with new_cache(make_ring, vault.address) as cache:
        assert decrypt_string(cache, "item") == "value"

    with pytest.raises(ObjectClosedError):
        cache.decrypt("other", bytearray(16))


# --- Construction -----------------------------------------------------------------------------


def test_the_defaults_make_no_call_until_a_secret_is_requested(make_ring: Callable[..., DefaultKeyRing]) -> None:
    cache = new_cache(make_ring)

    assert cache.decrypt("not:a:path", bytearray(16)) == 0


def test_the_defaults_are_vaults_own() -> None:
    defaults = Options()

    assert defaults.mount_path == "secret"
    assert defaults.kv_version is VaultKvVersion.V2
    assert defaults.default_key == "value"
    assert defaults.namespace is None
    assert defaults.timeout == timedelta(seconds=30)
    assert defaults.retry_count == 3
    assert defaults.retry_delay == timedelta(milliseconds=200)
    assert defaults.ssl_context is None

    changed = replace(defaults, namespace="team-a")
    assert changed.namespace == "team-a"
    assert changed.mount_path == "secret"


@pytest.mark.parametrize("address", ["http://localhost:8200", "http://LOCALHOST", "http://127.0.0.1:8200", "http://127.1.2.3", "http://[::1]:8200",
                                     "https://vault.example.com:8200", "HTTPS://vault.example.com/prefix/"])
def test_the_constructor_accepts_https_and_http_only_on_loopback(make_ring: Callable[..., DefaultKeyRing], address: str) -> None:
    new_cache(make_ring, address)


@pytest.mark.parametrize("address", [
    "relative/path", "vault.test:8200", "http://vault.example.com:8200", "http://10.0.0.1:8200", "http://[::2]", "http://127.0.0.1.example.com",
    "http://localhost.example.com", "ftp://127.0.0.1", "https://user:pass@vault.example.com", "https://vault.example.com/?x=1",
    "https://vault.example.com/?", "https://vault.example.com/#frag", "https:///no-host", "",
])
def test_the_constructor_rejects_an_address_that_would_expose_the_token(make_ring: Callable[..., DefaultKeyRing], address: str) -> None:
    with pytest.raises(ValueError, match="address"):
        new_cache(make_ring, address)


def test_the_constructor_rejects_invalid_options(vault: FakeVault, make_ring: Callable[..., DefaultKeyRing]) -> None:
    ring = make_ring()
    protector = ring.create_protector(TOKEN_PURPOSE)
    token = StaticVaultToken.protect(protector, FakeVault.TOKEN)
    address = vault.address
    none: Any = None
    wrong_type: Any = 2

    with pytest.raises(TypeError):
        HashiCorpVaultSecretCache(none, token, protector, ring)
    with pytest.raises(TypeError):
        HashiCorpVaultSecretCache(address, none, protector, ring)
    with pytest.raises(TypeError):
        HashiCorpVaultSecretCache(address, token, none, ring)
    with pytest.raises(TypeError):
        HashiCorpVaultSecretCache(address, token, protector, none)

    for invalid in (Options(mount_path=""), Options(mount_path="../sys"), Options(mount_path=none), Options(default_key=""),
                    Options(default_key="a b"), Options(default_key="a#b"), Options(default_key=none), Options(namespace="team a"),
                    Options(namespace=""), Options(timeout=timedelta(0)), Options(timeout=timedelta(milliseconds=-1))):
        with pytest.raises(ValueError):
            new_cache(make_ring, address, invalid)
    for wrong in (Options(kv_version=none), Options(kv_version=wrong_type), Options(timeout=none), Options(timeout=wrong_type), Options(retry_delay=none),
                  Options(retry_count=True), Options(retry_count=3.0), Options(ssl_context="tls")):  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            new_cache(make_ring, address, wrong)
    with pytest.raises(TypeError):
        new_cache(make_ring, address, "options")  # type: ignore[arg-type]


def test_an_ssl_context_given_is_the_one_every_https_request_uses(vault: FakeVault, create: Create) -> None:
    wrapped: list[str | None] = []

    class Recording(ssl.SSLContext):
        def wrap_socket(self, *args: Any, **kwargs: Any) -> ssl.SSLSocket:
            wrapped.append(kwargs.get("server_hostname"))
            return super().wrap_socket(*args, **kwargs)

    context = Recording(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    # The fake speaks plain http, so the handshake fails - after the context was asked to make it.
    cache = create(address=f"https://127.0.0.1:{vault.port}/", ssl_context=context)

    with pytest.raises(OSError):
        cache.decrypt("item", bytearray(16))

    assert wrapped == ["127.0.0.1"] * (1 + Options.MIN_RETRY_COUNT)


# --- StaticVaultToken -------------------------------------------------------------------------


@pytest.mark.parametrize("token", ["", "hvs.with space", "hvs.line\nbreak", "café"])
def test_static_vault_token_protect_rejects_a_token_that_cant_be_sent(make_ring: Callable[..., DefaultKeyRing], token: str) -> None:
    protector = make_ring().create_protector(TOKEN_PURPOSE)

    with pytest.raises(ValueError, match="printable ASCII"):
        StaticVaultToken.protect(protector, token)


def test_static_vault_token_protect_rejects_nones(make_ring: Callable[..., DefaultKeyRing]) -> None:
    protector = make_ring().create_protector(TOKEN_PURPOSE)
    none: Any = None

    with pytest.raises(TypeError):
        StaticVaultToken.protect(none, FakeVault.TOKEN)
    with pytest.raises(TypeError):
        StaticVaultToken.protect(protector, none)


@pytest.mark.parametrize("protected_token", ["", " "])
def test_static_vault_token_rejects_an_empty_protected_token(protected_token: str) -> None:
    none: Any = None
    with pytest.raises(ValueError, match="empty"):
        StaticVaultToken(protected_token)
    with pytest.raises(TypeError):
        StaticVaultToken(none)


def test_static_vault_token_protect_holds_only_the_protected_token(make_ring: Callable[..., DefaultKeyRing]) -> None:
    protector = make_ring().create_protector(TOKEN_PURPOSE)
    static = StaticVaultToken.protect(protector, FakeVault.TOKEN)

    held = static.get_token()
    assert held == asyncio.run(static.get_token_async())
    assert FakeVault.TOKEN not in held
    revealed = bytearray(protector.get_max_decrypted_length(held))
    assert revealed[: protector.decrypt(held, revealed)].decode() == FakeVault.TOKEN
