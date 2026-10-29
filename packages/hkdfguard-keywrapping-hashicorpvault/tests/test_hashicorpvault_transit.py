"""The wrapper's real http.client against a fake transit engine on loopback."""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hkdfguard.abstractions import CryptographicError, KeyWrapper, ObjectClosedError, WrappedKeyLimits
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.keywrapping.hashicorpvault import (
    HashiCorpVaultTransitKeyWrapper,
    HashiCorpVaultTransitKeyWrapperOptions,
    KeyFileTrust,
    StaticVaultTokenSource,
    VaultRequestError,
    VaultTokenSource,
)
from hkdfguard.keywrapping.hashicorpvault._wrapper import _decode_base64, _encode_base64, _retry_delay, is_vault_ciphertext
from hkdfguard_test_support import long_path

Wrapper = HashiCorpVaultTransitKeyWrapper
Options = HashiCorpVaultTransitKeyWrapperOptions

TOKEN = "hvs.CAESIFakeTokenForTests"
KEY_NAME = "myapp-kek"
CONTEXT = "hkdfguard.test"
CONTEXT_BASE64 = base64.b64encode(CONTEXT.encode()).decode()

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only.")


# --- A fake transit engine --------------------------------------------------------------------


@dataclass(frozen=True)
class Answer:
    """An answer given as it is: a status, a body ("" for none) and any extra headers."""

    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class TransitRequest:
    """One transit request as it arrived: its operation, key, body and headers."""

    operation: str
    key: str
    body: bytes
    token: str
    namespace: str | None
    content_type: str | None
    vault_request: str | None

    @property
    def json(self) -> dict[str, Any]:
        parsed: dict[str, Any] = json.loads(self.body)
        return parsed

    def field(self, name: str) -> Any:
        return self.json.get(name)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, transit: FakeTransit) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.transit = transit

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A hook that raises drops the connection, as intended; nothing to report.
        pass


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        self.server.transit.handle(self)

    do_GET = do_PUT = do_DELETE = do_LIST = do_POST  # noqa: N815 - BaseHTTPRequestHandler's names


class FakeTransit:
    """A transit secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which
    the wrapper allows on loopback). A POST to encrypt, decrypt or datakey/wrapped for a key it holds,
    with the expected token, is answered as Vault answers it: ciphertext is "vault:v{version}:" and
    base64 of AES-GCM under that key version's own local key, with associated_data as the AAD, so
    decrypt fails unless the key, its version and the context all match. A key can be rotated, and
    given a min_decryption_version. datakey/wrapped ignores associated_data and says so in its
    warnings, as Vault does. A request without the token is refused with 403. Any other request is
    recorded in :attr:`unexpected_requests` and refused."""

    def __init__(self, mount_path: str = "transit", path_prefix: str = "") -> None:
        self.mount_path = mount_path
        self.path_prefix = path_prefix
        self._keys: dict[str, list[bytes]] = {}
        self._min_version: dict[str, int] = {}
        self._lock = threading.Lock()
        self._requests: list[TransitRequest] = []
        self._unexpected: list[str] = []
        # When set, answers a request in place of the engine - given the request and how many have
        # arrived, this one included - or returns None to let the engine answer.
        self.answer: Callable[[TransitRequest, int], Answer | None] | None = None
        # When set, runs inside every request before it answers: may hold it open, write to it, or
        # raise to drop the connection. Given the handler and how many requests have arrived.
        self.on_request: Callable[[_Handler, int], object] | None = None
        # Answers as a Vault too old for associated_data would: ignoring it, with a warning.
        self.ignores_associated_data = False
        # Set on close, so hooks holding a request open let go.
        self.stopping = threading.Event()
        self.add_key(KEY_NAME)
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

    def add_key(self, name: str) -> None:
        with self._lock:
            self._keys[name] = [AESGCM.generate_key(256)]

    def rotate(self, name: str) -> None:
        """Adds a version to the key, as transit/keys/{name}/rotate does."""
        with self._lock:
            self._keys[name].append(AESGCM.generate_key(256))

    def set_min_decryption_version(self, name: str, version: int) -> None:
        """Refuses ciphertexts made under an earlier version, as min_decryption_version does."""
        with self._lock:
            self._min_version[name] = version

    @property
    def requests(self) -> list[TransitRequest]:
        with self._lock:
            return list(self._requests)

    @property
    def unexpected_requests(self) -> list[str]:
        with self._lock:
            return list(self._unexpected)

    def close(self) -> None:
        self.stopping.set()
        self._server.shutdown()
        self._server.server_close()

    def handle(self, handler: _Handler) -> None:
        parts = urlsplit(handler.path)
        prefix = f"{self.path_prefix}/v1/{self.mount_path}/"
        route = parts.path[len(prefix):] if parts.path.startswith(prefix) else ""
        operation, key = "", ""
        for name, route_prefix in (("encrypt", "encrypt/"), ("decrypt", "decrypt/"), ("datakey", "datakey/wrapped/")):
            if route.startswith(route_prefix):
                operation, key = name, route[len(route_prefix):]
        if handler.command != "POST" or not operation or "/" in key or parts.query:
            with self._lock:
                self._unexpected.append(f"{handler.command} {handler.path}")
            respond(handler, Answer(405, '{"errors":["1 error occurred:\\n\\t* unsupported operation\\n\\n"]}'))
            return

        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length)
        token = handler.headers.get("X-Vault-Token") or ""
        recorded = TransitRequest(operation, key, body, token, handler.headers.get("X-Vault-Namespace"), handler.headers.get("Content-Type"),
                                  handler.headers.get("X-Vault-Request"))
        with self._lock:
            self._requests.append(recorded)
            count = len(self._requests)

        hook = self.on_request
        if hook is not None:
            hook(handler, count)

        if token != TOKEN:
            respond(handler, Answer(403, '{"errors":["1 error occurred:\\n\\t* permission denied\\n\\n"]}'))
            return
        given = self.answer(recorded, count) if self.answer is not None else None
        if given is not None:
            respond(handler, given)
            return
        with self._lock:
            versions = list(self._keys.get(key, []))
            min_version = self._min_version.get(key, 1)
        if not versions:
            respond(handler, Answer(400, '{"errors":["encryption key not found"]}'))
            return

        request = json.loads(body)
        known = {"encrypt": {"plaintext", "associated_data"}, "decrypt": {"ciphertext", "associated_data"}, "datakey": {"bits"}}[operation]
        if self.ignores_associated_data:
            known = known - {"associated_data"}
        ignored = [name for name in request if name not in known]
        aad = b"" if "associated_data" in ignored or "associated_data" not in request else base64.b64decode(request["associated_data"])
        warnings = [f"Endpoint ignored these unrecognized parameters: [{' '.join(ignored)}]"] if ignored else None
        latest = len(versions)

        if operation == "encrypt":
            ciphertext = seal(versions[-1], latest, base64.b64decode(request["plaintext"]), aad)
            respond(handler, Answer(200, envelope({"ciphertext": ciphertext, "key_version": latest}, warnings)))
        elif operation == "datakey":
            ciphertext = seal(versions[-1], latest, os.urandom(request["bits"] // 8), aad)
            respond(handler, Answer(200, envelope({"ciphertext": ciphertext, "key_version": latest}, warnings)))
        else:
            _, version_text, sealed = str(request["ciphertext"]).split(":", 2)
            version = int(version_text[1:])
            if version < min_version:
                respond(handler, Answer(400, '{"errors":["ciphertext or signature version is disallowed by policy (too old)"]}'))
            elif not 1 <= version <= latest:
                respond(handler, Answer(400, '{"errors":["invalid key version"]}'))
            else:
                plaintext = open_sealed(versions[version - 1], base64.b64decode(sealed), aad)
                if plaintext is None:
                    respond(handler, Answer(400, '{"errors":["cipher: message authentication failed"]}'))
                else:
                    respond(handler, Answer(200, envelope({"plaintext": base64.b64encode(plaintext).decode()}, warnings)))


def envelope(data: Any, warnings: list[Any] | None = None) -> str:
    """A body shaped as Vault shapes a successful answer."""
    return json.dumps({"request_id": "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a", "lease_id": "", "renewable": False, "lease_duration": 0,
                       "data": data, "wrap_info": None, "warnings": warnings, "auth": None, "mount_type": "transit"}, separators=(",", ":"))


def seal(key: bytes, version: int, plaintext: bytes, aad: bytes) -> str:
    nonce = os.urandom(12)
    return f"vault:v{version}:" + base64.b64encode(nonce + AESGCM(key).encrypt(nonce, plaintext, aad or None)).decode()


def open_sealed(key: bytes, sealed: bytes, aad: bytes) -> bytes | None:
    if len(sealed) < 28:
        return None
    try:
        return AESGCM(key).decrypt(sealed[:12], sealed[12:], aad or None)
    except InvalidTag:
        return None


def respond(handler: _Handler, answer: Answer) -> None:
    body = answer.body.encode()
    handler.send_response(answer.status)
    handler.send_header("Content-Type", "application/json")
    for name, value in answer.headers.items():
        handler.send_header(name, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class FakeTokenSource(VaultTokenSource):
    """A token source that counts its calls, and can hand out any token, fail or hang."""

    def __init__(self) -> None:
        self.calls = 0
        # Gives the token for call number n (from 1); may raise.
        self.next: Callable[[int], str] = lambda call: TOKEN
        # When set, copy_token blocks until released.
        self.hang = False
        self.release = threading.Event()

    @staticmethod
    def giving(token: str) -> FakeTokenSource:
        source = FakeTokenSource()
        source.next = lambda call: token
        return source

    def copy_token(self, destination: memoryview) -> int:
        if self.hang:
            self.release.wait(10)
        self.calls += 1
        token = self.next(self.calls).encode()
        destination[:min(len(token), len(destination))] = token[:len(destination)]
        return len(token)


@dataclass
class Sent:
    """What the wrapper handed http.client: each request body, and each X-Vault-Token value, as the
    very objects it passed - so a test can see what became of them once the call returned."""

    bodies: list[Any] = field(default_factory=list)
    tokens: list[Any] = field(default_factory=list)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    record = Sent()
    putheader = http.client.HTTPConnection.putheader
    endheaders = http.client.HTTPConnection.endheaders

    def put(self: http.client.HTTPConnection, header: str, *values: Any) -> None:
        if header == "X-Vault-Token":
            record.tokens.extend(values)
        putheader(self, header, *values)

    def end(self: http.client.HTTPConnection, message_body: Any = None, **kwargs: Any) -> None:
        if message_body is not None:
            record.bodies.append(message_body)
        endheaders(self, message_body, **kwargs)

    monkeypatch.setattr(http.client.HTTPConnection, "putheader", put)
    monkeypatch.setattr(http.client.HTTPConnection, "endheaders", end)
    return record


@pytest.fixture
def transits() -> Iterator[Callable[..., FakeTransit]]:
    started: list[FakeTransit] = []

    def start(*args: Any) -> FakeTransit:
        transit = FakeTransit(*args)
        started.append(transit)
        return transit

    yield start
    for transit in started:
        transit.close()


@pytest.fixture
def vault(transits: Callable[..., FakeTransit]) -> FakeTransit:
    return transits()


Create = Callable[..., Wrapper]
_DEFAULT: Any = object()


@pytest.fixture
def create(vault: FakeTransit) -> Create:
    """A wrapper over the fake's key with the context. No backoff, only each retry's 0-100 ms of
    jitter, so a test that meets a 5xx stays quick."""

    def make(*, on: FakeTransit | None = None, address: str | None = None, key_name: str = KEY_NAME, context: str | None = _DEFAULT,
             tokens: VaultTokenSource | None = None, key_file_trust: KeyFileTrust | None = None, **options: Any) -> Wrapper:
        target = on or vault
        options.setdefault("retry_delay", timedelta(0))
        return Wrapper(address or target.address, key_name, tokens or FakeTokenSource(), CONTEXT if context is _DEFAULT else context,
                       key_file_trust=key_file_trust, options=Options(**options))

    return make


def wrap_new(wrapper: Wrapper, dek: bytes | bytearray | None = None) -> bytes:
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(bytearray(dek if dek is not None else os.urandom(32)), wrapped)
    return bytes(wrapped[:length])


def generate(wrapper: Wrapper) -> bytes:
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    return bytes(wrapped[:wrapper.generate_and_wrap(wrapped)])


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def is_zero(buffer: Any) -> bool:
    return not any(memoryview(buffer).cast("B"))


# --- Construction -----------------------------------------------------------------------------


def test_the_wrapper_is_a_key_wrapper_and_makes_no_call_until_used(vault: FakeTransit, create: Create) -> None:
    assert isinstance(create(), KeyWrapper)
    assert vault.requests == []


def test_the_defaults_are_vaults_own() -> None:
    defaults = Options()

    assert defaults.mount_path == "transit"
    assert defaults.namespace is None
    assert defaults.timeout == timedelta(seconds=30)
    assert defaults.retry_count == 3
    assert defaults.retry_delay == timedelta(milliseconds=200)
    assert defaults.ssl_context is None
    assert replace(defaults, namespace="team-a").mount_path == "transit"


def test_the_constants_are_the_dotnet_wrappers() -> None:
    assert (Wrapper.GENERATED_KEY_LENGTH, Wrapper.MAX_PLAINTEXT_LENGTH, Wrapper.MAX_CONTEXT_LENGTH, Wrapper.MAX_KEY_NAME_LENGTH,
            Wrapper.MAX_TOKEN_LENGTH, Wrapper.MAX_RESPONSE_LENGTH) == (32, 256, 1024, 128, 2048, 16 * 1024)


def test_constructor_rejects_missing_arguments() -> None:
    tokens = FakeTokenSource()
    none: Any = None

    with pytest.raises(TypeError):
        Wrapper(none, KEY_NAME, tokens)
    with pytest.raises(TypeError):
        Wrapper("https://vault.test:8200", none, tokens)
    with pytest.raises(TypeError):
        Wrapper("https://vault.test:8200", KEY_NAME, none)
    with pytest.raises(TypeError):
        Wrapper("https://vault.test:8200", KEY_NAME, TOKEN)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Wrapper("https://vault.test:8200", KEY_NAME, tokens, 7)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Wrapper("https://vault.test:8200", KEY_NAME, tokens, key_file_trust="admins")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Wrapper("https://vault.test:8200", KEY_NAME, tokens, options="options")  # type: ignore[arg-type]


@pytest.mark.parametrize("key_name", ["", ".", "..", "team/kek", "my kek", "kek?x=1", "kék", "k" * (Wrapper.MAX_KEY_NAME_LENGTH + 1)])
def test_constructor_rejects_a_key_name_that_is_not_one(key_name: str) -> None:
    with pytest.raises(ValueError, match="key name"):
        Wrapper("https://vault.test:8200", key_name, FakeTokenSource())


def test_constructor_accepts_the_longest_key_name() -> None:
    Wrapper("https://vault.test:8200", "k" * Wrapper.MAX_KEY_NAME_LENGTH, FakeTokenSource())


@pytest.mark.parametrize("address", ["http://localhost:8200", "http://LOCALHOST", "http://127.0.0.1:8200", "http://127.1.2.3", "http://[::1]:8200",
                                     "https://vault.example.com:8200", "HTTPS://vault.example.com/prefix/"])
def test_constructor_accepts_https_and_http_only_on_loopback(address: str) -> None:
    Wrapper(address, KEY_NAME, FakeTokenSource())


@pytest.mark.parametrize("address", [
    "relative/path", "vault.test:8200", "http://vault.example.com:8200", "http://10.0.0.1:8200", "http://[::2]", "http://127.0.0.1.example.com",
    "http://localhost.example.com", "ftp://vault.example.com", "https://user:pass@vault.example.com:8200", "https://vault.example.com:8200/?x=1",
    "https://vault.example.com/?", "https://vault.example.com:8200/#f", "https:///no-host", "",
])
def test_constructor_rejects_an_address_that_would_expose_the_token_or_deks(address: str) -> None:
    with pytest.raises(ValueError, match="address"):
        Wrapper(address, KEY_NAME, FakeTokenSource())


def test_constructor_rejects_a_context_over_the_limit_or_not_text_and_accepts_the_longest() -> None:
    with pytest.raises(ValueError, match="context"):
        Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), "c" * (Wrapper.MAX_CONTEXT_LENGTH + 1))
    with pytest.raises(ValueError, match="context"):
        Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), "é" * (Wrapper.MAX_CONTEXT_LENGTH // 2 + 1))
    with pytest.raises(ValueError, match="surrogate"):
        Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), "\ud800")
    Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), "c" * Wrapper.MAX_CONTEXT_LENGTH)


@pytest.mark.parametrize("options", [
    Options(mount_path=""), Options(mount_path="transit/../sys"), Options(mount_path="/transit"), Options(mount_path="transit/"),
    Options(namespace="team a"), Options(namespace=""), Options(timeout=timedelta(0)), Options(timeout=timedelta(milliseconds=-1)),
    Options(retry_count=Options.MIN_RETRY_COUNT - 1), Options(retry_count=Options.MAX_RETRY_COUNT + 1), Options(retry_delay=timedelta(milliseconds=-1)),
    Options(retry_delay=Options.MAX_RETRY_DELAY + timedelta(microseconds=1)),
])
def test_constructor_rejects_options_that_are_not_ones(options: Options) -> None:
    with pytest.raises(ValueError):
        Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), options=options)


def test_constructor_rejects_options_of_the_wrong_type() -> None:
    wrong: Any = "x"
    none: Any = None
    for options in (Options(timeout=wrong), Options(timeout=none), Options(retry_delay=none), Options(retry_count=True), Options(retry_count=wrong),
                    Options(ssl_context=wrong)):
        with pytest.raises(TypeError):
            Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), options=options)
    with pytest.raises(ValueError, match="mount path"):
        Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), options=Options(mount_path=none))


def test_the_retry_limits_are_accepted() -> None:
    Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(), options=Options(retry_count=Options.MIN_RETRY_COUNT, retry_delay=timedelta(0)))
    Wrapper("https://vault.test:8200", KEY_NAME, FakeTokenSource(),
            options=Options(retry_count=Options.MAX_RETRY_COUNT, retry_delay=Options.MAX_RETRY_DELAY))


# --- Wrap and unwrap --------------------------------------------------------------------------


def test_wrap_then_unwrap_round_trips_the_dek(create: Create) -> None:
    wrapper = create()
    dek = os.urandom(32)

    wrapped = wrap_new(wrapper, dek)
    revealed = bytearray(32)

    assert wrapped.startswith(b"vault:v1:")
    assert wrapper.unwrap(wrapped, revealed) == 32
    assert revealed == dek


@pytest.mark.parametrize("kind", [bytes, bytearray, memoryview])
def test_wrap_and_unwrap_take_any_buffer(create: Create, kind: Callable[[bytes], Any]) -> None:
    wrapper = create()
    dek = os.urandom(32)
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)

    length = wrapper.wrap(kind(dek), memoryview(wrapped))
    revealed = bytearray(32)

    assert wrapper.unwrap(kind(bytes(wrapped[:length])), memoryview(revealed)) == 32
    assert revealed == dek


def test_wrap_encrypts_under_the_key_with_the_context_sending_exactly_the_dotnet_body_and_zeroes_what_it_sent(vault: FakeTransit, create: Create,
                                                                                                                 sent: Sent) -> None:
    wrapper = create()
    dek = bytearray(os.urandom(32))
    expected = bytes(dek)

    wrap_new(wrapper, dek)

    [request] = vault.requests
    assert (request.operation, request.key) == ("encrypt", KEY_NAME)
    assert request.body == b'{"plaintext":"' + base64.b64encode(expected) + b'","associated_data":"' + CONTEXT_BASE64.encode() + b'"}'
    assert (request.token, request.namespace, request.content_type, request.vault_request) == (TOKEN, None, "application/json", "true")
    # The body and the token went to http.client as views of the wrapper's own bytearrays, now zeroed.
    [body] = sent.bodies
    [token] = sent.tokens
    assert isinstance(body, memoryview) and isinstance(token, memoryview)
    assert len(body) == len(request.body) and is_zero(body)
    assert len(token) == len(TOKEN) and is_zero(token)
    assert dek == expected
    assert vault.unexpected_requests == []


def test_unwrap_decrypts_under_the_key_with_the_context_sending_exactly_the_dotnet_body(vault: FakeTransit, create: Create, sent: Sent) -> None:
    wrapper = create()
    wrapped = wrap_new(wrapper)

    wrapper.unwrap(wrapped, bytearray(32))

    request = vault.requests[-1]
    assert (request.operation, request.key) == ("decrypt", KEY_NAME)
    assert request.body == b'{"ciphertext":"' + wrapped + b'","associated_data":"' + CONTEXT_BASE64.encode() + b'"}'
    assert all(is_zero(token) for token in sent.tokens)


def test_generate_and_wrap_with_no_context_has_vault_generate_a_wrapped_aes_256_key_only(vault: FakeTransit, create: Create) -> None:
    wrapper = create(context=None)

    wrapped = generate(wrapper)
    revealed = bytearray(32)
    revealed_length = wrapper.unwrap(wrapped, revealed)

    first, second = vault.requests
    assert (first.operation, first.key, first.body) == ("datakey", KEY_NAME, b'{"bits":256}')
    assert second.body == b'{"ciphertext":"' + wrapped + b'"}'
    assert revealed_length == Wrapper.GENERATED_KEY_LENGTH
    assert not is_zero(revealed)


def test_with_an_empty_context_sends_none_and_generates_in_vault(vault: FakeTransit, create: Create) -> None:
    wrapper = create(context="")

    wrapper.unwrap(wrap_new(wrapper), bytearray(32))
    generate(wrapper)

    assert all(r.field("associated_data") is None for r in vault.requests)
    assert vault.requests[-1].operation == "datakey"


def test_generate_and_wrap_with_a_context_generates_here_and_encrypts_with_it(vault: FakeTransit, create: Create, sent: Sent) -> None:
    # datakey/wrapped ignores associated_data, so it can't bind a context.
    wrapper = create()

    wrapped = generate(wrapper)
    revealed = bytearray(32)
    wrapper.unwrap(wrapped, revealed)

    request = vault.requests[0]
    assert request.operation == "encrypt"
    assert request.field("associated_data") == CONTEXT_BASE64
    assert base64.b64decode(request.field("plaintext")) == revealed
    assert not is_zero(revealed)
    assert is_zero(sent.bodies[0])


def test_the_context_is_bound_as_utf_8(vault: FakeTransit, create: Create) -> None:
    wrapper = create(context="contexte-é-秘密")

    wrap_new(wrapper)

    assert vault.requests[0].field("associated_data") == base64.b64encode("contexte-é-秘密".encode()).decode()


def test_key_files_made_before_the_key_rotated_still_unwrap_until_their_version_is_too_old(vault: FakeTransit, create: Create) -> None:
    wrapper = create()
    old_dek = os.urandom(32)
    old = wrap_new(wrapper, old_dek)

    vault.rotate(KEY_NAME)
    new_dek = os.urandom(32)
    new = wrap_new(wrapper, new_dek)
    revealed = bytearray(32)

    assert old.startswith(b"vault:v1:") and new.startswith(b"vault:v2:")
    wrapper.unwrap(old, revealed)
    assert revealed == old_dek
    wrapper.unwrap(new, revealed)
    assert revealed == new_dek

    vault.set_min_decryption_version(KEY_NAME, 2)
    with pytest.raises(CryptographicError, match="too old"):
        wrapper.unwrap(old, revealed)
    assert is_zero(revealed)
    wrapper.unwrap(new, revealed)
    assert revealed == new_dek


def test_unwrap_under_another_key_fails_naming_vaults_answer_and_zeroes_the_result(vault: FakeTransit, create: Create) -> None:
    vault.add_key("other-kek")
    wrapped = wrap_new(create(key_name="other-kek"))
    wrapper = create()
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(CryptographicError) as raised:
        wrapper.unwrap(wrapped, result)

    assert str(raised.value) == f"Vault transit unwrap failed for key '{KEY_NAME}': Vault answered 400 Bad Request: cipher: message authentication failed"
    cause = raised.value.__cause__
    assert isinstance(cause, VaultRequestError) and cause.status_code == 400 and not cause.is_transient
    assert is_zero(result)
    assert len(vault.requests) == 2


def test_unwrap_under_another_context_or_none_fails(create: Create) -> None:
    wrapped = wrap_new(create())

    with pytest.raises(CryptographicError):
        create(context="other").unwrap(wrapped, bytearray(32))
    with pytest.raises(CryptographicError):
        create(context=None).unwrap(wrapped, bytearray(32))


def test_unwrap_when_tampered_fails(create: Create) -> None:
    wrapper = create()
    wrapped = bytearray(wrap_new(wrapper))
    # Another base64 character, so it still reaches Vault and fails there.
    wrapped[12] = ord("B") if wrapped[12] == ord("A") else ord("A")

    with pytest.raises(CryptographicError, match="400"):
        wrapper.unwrap(wrapped, bytearray(32))


@pytest.mark.parametrize("wrapped", ["", "vault:v1:", "vault:v:AAAA", "vault:x1:AAAA", "vault:v12345678901:AAAA", 'vault:v1:AA"},"x":"AA',
                                     "vault:v1:AA AA", "VAULT:v1:AAAA", "vault:v1:AAAA\n"])
def test_unwrap_of_something_that_is_not_a_ciphertext_fails_without_calling_vault_and_zeroes_the_result(vault: FakeTransit, create: Create,
                                                                                                        wrapped: str) -> None:
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(CryptographicError):
        create().unwrap(wrapped.encode(), result)

    assert is_zero(result)
    assert vault.requests == []


def test_unwrap_over_the_key_file_limit_fails_without_calling_vault(vault: FakeTransit, create: Create) -> None:
    with pytest.raises(CryptographicError, match="1-512 bytes"):
        create().unwrap(b"vault:v1:" + b"A" * WrappedKeyLimits.MAX_BYTES, bytearray(32))

    assert vault.requests == []


def test_unwrap_when_the_key_does_not_fit_fails_and_zeroes_the_result(create: Create) -> None:
    wrapper = create()
    wrapped = wrap_new(wrapper)
    result = bytearray(b"\xaa" * 16)

    with pytest.raises(ValueError, match="result holds 16"):
        wrapper.unwrap(wrapped, result)

    assert is_zero(result)


def test_unwrap_writes_into_the_start_of_a_larger_result(create: Create) -> None:
    wrapper = create()
    dek = os.urandom(32)
    result = bytearray(b"\xaa" * 48)

    assert wrapper.unwrap(wrap_new(wrapper, dek), result) == 32

    assert result[:32] == dek
    assert result[32:] == b"\xaa" * 16


@pytest.mark.parametrize("size", [0, Wrapper.MAX_PLAINTEXT_LENGTH + 1])
def test_wrap_rejects_a_plaintext_out_of_bounds_without_calling_vault(vault: FakeTransit, create: Create, size: int) -> None:
    with pytest.raises(ValueError, match="1-256 bytes"):
        create().wrap(bytearray(size), bytearray(WrappedKeyLimits.MAX_BYTES))

    assert vault.requests == []


def test_wrap_of_the_largest_plaintext_fits_the_key_file_limit(create: Create) -> None:
    wrapper = create()
    dek = os.urandom(Wrapper.MAX_PLAINTEXT_LENGTH)

    wrapped = wrap_new(wrapper, dek)
    revealed = bytearray(len(dek))

    assert len(wrapped) <= WrappedKeyLimits.MAX_BYTES
    assert wrapper.unwrap(wrapped, revealed) == len(dek)
    assert revealed == dek


def test_wrap_when_the_result_is_too_small_fails(create: Create) -> None:
    with pytest.raises(ValueError, match="result holds 8"):
        create().wrap(bytearray(32), bytearray(8))
    with pytest.raises(ValueError, match="result holds 8"):
        create(context=None).generate_and_wrap(bytearray(8))


def test_wrap_writes_into_the_start_of_a_larger_result(create: Create) -> None:
    wrapper = create()
    result = bytearray(b"\xaa" * WrappedKeyLimits.MAX_BYTES)

    length = wrapper.wrap(bytearray(32), result)

    assert result[:length].startswith(b"vault:v1:")
    assert result[length:] == b"\xaa" * (WrappedKeyLimits.MAX_BYTES - length)


def test_the_wrapper_is_safe_for_concurrent_use(create: Create) -> None:
    wrapper = create()

    def round_trip(_: int) -> bool:
        dek = os.urandom(32)
        revealed = bytearray(32)
        wrapper.unwrap(wrap_new(wrapper, dek), revealed)
        return revealed == dek

    with ThreadPoolExecutor(8) as pool:
        assert all(pool.map(round_trip, range(16)))


# --- What Vault answers -----------------------------------------------------------------------


@pytest.mark.parametrize(("because", "body"), [
    ("not JSON", "<html>proxy</html>"),
    ("not an object", "[]"),
    ("no data", envelope(None)),
    ("data not an object", '{"data":"x"}'),
    ("no ciphertext", envelope({"key_version": 1})),
    ("ciphertext not a string", envelope({"ciphertext": 7})),
    ("ciphertext empty", envelope({"ciphertext": ""})),
    ("ciphertext twice", '{"data":{"ciphertext":"vault:v1:AAAA","ciphertext":"vault:v1:BBBB"}}'),
    ("not a ciphertext", envelope({"ciphertext": "AAAA"})),
    ("over the key file limit", envelope({"ciphertext": "vault:v1:" + "A" * WrappedKeyLimits.MAX_BYTES})),
    ("a parameter ignored", envelope({"ciphertext": "vault:v1:AAAA"}, ["Endpoint ignored these unrecognized parameters: [associated_data]"])),
    ("something after the object", '{"data":{"ciphertext":"vault:v1:AAAA"}} {}'),
    ("empty", ""),
])
def test_wrap_refuses_an_answer_that_is_not_a_ciphertext(vault: FakeTransit, create: Create, because: str, body: str) -> None:
    vault.answer = lambda request, count: Answer(200, body)

    with pytest.raises(CryptographicError, match=f"Vault transit wrap for key '{KEY_NAME}'"):
        create().wrap(bytearray(32), bytearray(2 * WrappedKeyLimits.MAX_BYTES))

    assert len(vault.requests) == 1, because


def test_an_escaped_answer_is_unescaped(vault: FakeTransit, create: Create) -> None:
    # vault:v1:AB+/ with '+' as a \u escape and '/' as \/, as a proxy re-encoding the answer might write it.
    vault.answer = lambda request, count: Answer(200, '{"data":{"ciphertext":"vault:v1:AB\\u002B\\/"}}')

    assert wrap_new(create(), bytes(32)) == b"vault:v1:AB+/"


def test_an_answer_with_other_warnings_is_accepted(vault: FakeTransit, create: Create) -> None:
    vault.answer = lambda request, count: Answer(
        200, '{"data":{"ciphertext":"vault:v1:AAAA"},"warnings":[7,{"unrecognized parameters":1},"some other warning"]}')

    assert wrap_new(create(), bytes(32)) == b"vault:v1:AAAA"


@pytest.mark.parametrize("operation", ["wrap", "unwrap", "generate"])
def test_a_vault_that_ignores_the_context_is_refused_rather_than_wrapping_unbound(vault: FakeTransit, create: Create, operation: str) -> None:
    wrapper = create()
    wrapped = wrap_new(wrapper)
    vault.ignores_associated_data = True

    with pytest.raises(CryptographicError, match="ignored a parameter"):
        if operation == "wrap":
            wrap_new(wrapper)
        elif operation == "generate":
            generate(wrapper)
        else:
            # Vault would fail to authenticate it without the AAD; a fake ignoring it but answering shows the warning wins.
            vault.answer = lambda request, count: Answer(200, envelope({"plaintext": base64.b64encode(bytes(32)).decode()},
                                                                       ["Endpoint ignored these unrecognized parameters: [associated_data]"]))
            wrapper.unwrap(wrapped, bytearray(32))


@pytest.mark.parametrize("body", ['{"data":{"plaintext":"not base64!"}}', '{"data":{"plaintext":"AAA"}}', '{"data":{"plaintext":"A==="}}',
                                  '{"data":{"plaintext":"AA=A"}}', '{"data":{"plaintext":""}}', '{"data":{}}', '{"data":{"plaintext":"AAAA"}} x'])
def test_unwrap_refuses_an_answer_that_is_not_a_plaintext_and_zeroes_the_result(vault: FakeTransit, create: Create, body: str) -> None:
    vault.answer = lambda request, count: Answer(200, body)
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(CryptographicError):
        create().unwrap(b"vault:v1:AAAA", result)

    assert is_zero(result)


def test_an_answer_over_the_response_limit_is_refused(vault: FakeTransit, create: Create) -> None:
    huge = envelope({"ciphertext": "vault:v1:AAAA", "padding": "x" * Wrapper.MAX_RESPONSE_LENGTH})
    vault.answer = lambda request, count: Answer(200, huge)

    with pytest.raises(CryptographicError, match="over 16384 bytes"):
        wrap_new(create(), bytes(32))

    assert len(vault.requests) == 1


def test_an_answer_of_exactly_the_response_limit_is_read(vault: FakeTransit, create: Create) -> None:
    body = envelope({"ciphertext": "vault:v1:AAAA", "padding": ""})
    body = body.replace('"padding":""', '"padding":"' + "x" * (Wrapper.MAX_RESPONSE_LENGTH - len(body)) + '"')
    assert len(body) == Wrapper.MAX_RESPONSE_LENGTH
    vault.answer = lambda request, count: Answer(200, body)

    assert wrap_new(create(), bytes(32)) == b"vault:v1:AAAA"


def test_a_vault_refusal_becomes_a_cryptographic_error_naming_vaults_errors_and_is_not_retried(vault: FakeTransit, create: Create) -> None:
    wrapper = create(tokens=FakeTokenSource.giving("hvs.revoked"))

    with pytest.raises(CryptographicError) as raised:
        wrap_new(wrapper, bytes(32))

    assert str(raised.value) == (f"Vault transit wrap failed for key '{KEY_NAME}': Vault answered 403 Forbidden: 1 error occurred:\n\t* permission "
                                 "denied\n\n")
    assert isinstance(raised.value.__cause__, VaultRequestError) and raised.value.__cause__.status_code == 403
    assert len(vault.requests) == 1


def test_several_errors_are_joined(vault: FakeTransit, create: Create) -> None:
    vault.answer = lambda request, count: Answer(400, '{"errors":["first","second",7]}')

    with pytest.raises(CryptographicError, match=r"Vault answered 400 Bad Request: first; second; 7$"):
        generate(create())


@pytest.mark.parametrize("body", ["<html>bad gateway</html>", '{"errors":"x"}', "[]", "{}", '{"errors":[]}', ""])
def test_a_refusal_that_is_not_vaults_json_is_reported_by_its_status(vault: FakeTransit, create: Create, body: str) -> None:
    vault.answer = lambda request, count: Answer(404, body)

    with pytest.raises(CryptographicError) as raised:
        generate(create())

    assert str(raised.value).endswith("Vault answered 404 Not Found")


@pytest.mark.parametrize(("status", "body"), [(503, '{"errors":["Vault is sealed"]}'), (500, '{"errors":["internal error"]}'),
                                              (429, '{"errors":["rate limit quota exceeded"]}'), (502, "<html>Bad Gateway</html>"), (504, "")])
def test_a_transient_failure_is_retried_asking_for_the_token_once(vault: FakeTransit, create: Create, sent: Sent, status: int, body: str) -> None:
    vault.answer = lambda request, count: Answer(status, body) if count <= 2 else None
    tokens = FakeTokenSource()
    wrapper = create(tokens=tokens)
    dek = os.urandom(32)

    wrapped = wrap_new(wrapper, dek)

    assert len(vault.requests) == 3
    assert tokens.calls == 1
    assert len(sent.tokens) == 3 and all(is_zero(token) for token in sent.tokens)
    assert len(sent.bodies) == 3 and all(is_zero(body) for body in sent.bodies)
    revealed = bytearray(32)
    wrapper.unwrap(wrapped, revealed)
    assert revealed == dek


def test_a_transient_failure_that_outlasts_the_retries_becomes_a_cryptographic_error(vault: FakeTransit, create: Create) -> None:
    vault.answer = lambda request, count: Answer(503, '{"errors":["Vault is sealed"]}')

    with pytest.raises(CryptographicError) as raised:
        generate(create(context=None, retry_count=4))

    assert len(vault.requests) == 5
    assert str(raised.value).endswith("Vault answered 503 Service Unavailable: Vault is sealed")
    assert isinstance(raised.value.__cause__, VaultRequestError) and raised.value.__cause__.is_transient


@pytest.mark.parametrize("status", [400, 403, 404, 501])
def test_an_answer_that_would_repeat_is_not_retried(vault: FakeTransit, create: Create, status: int) -> None:
    vault.answer = lambda request, count: Answer(status, '{"errors":[]}')

    with pytest.raises(CryptographicError):
        generate(create())

    assert len(vault.requests) == 1


@pytest.mark.parametrize("how", ["no answer", "dropped mid-response", "attempt timed out"])
def test_a_lost_connection_is_retried(vault: FakeTransit, create: Create, how: str) -> None:
    def lose(handler: _Handler, count: int) -> None:
        if count > 1:
            return
        if how == "no answer":
            raise ConnectionAbortedError("The connection is dropped without an answer.")
        if how == "dropped mid-response":
            handler.send_response(200)
            handler.send_header("Content-Length", "200")
            handler.end_headers()
            handler.wfile.write(b'{"data":{"ciphertext":"vault:v1:AA')
            handler.wfile.flush()
            raise ConnectionAbortedError("The connection is dropped mid-response.")
        vault.stopping.wait(1)

    vault.on_request = lose

    generate(create(timeout=timedelta(milliseconds=300)))

    assert len(vault.requests) == 2


def test_an_attempt_that_times_out_is_retried_then_reported_as_no_answer(vault: FakeTransit, create: Create) -> None:
    def stall(handler: _Handler, count: int) -> None:
        handler.send_response(200)
        handler.end_headers()
        handler.wfile.write(b'{"data":{"ciphertext":"vault:v1:AA')
        handler.wfile.flush()
        vault.stopping.wait(5)
        raise ConnectionAbortedError("Never finished.")

    vault.on_request = stall

    started = time.monotonic()
    with pytest.raises(CryptographicError, match=re.escape("no answer within 0:00:00.300000")) as raised:
        generate(create(timeout=timedelta(milliseconds=300)))
    elapsed = time.monotonic() - started

    assert len(vault.requests) == 1 + Options.MIN_RETRY_COUNT
    assert isinstance(raised.value.__cause__, TimeoutError)
    # Four attempts of 300 ms and three waits of at most 100 ms, far short of one stalled body.
    assert elapsed < 4, elapsed


def test_an_unreachable_vault_is_retried_then_raises_a_cryptographic_error_with_the_os_error(create: Create) -> None:
    with pytest.raises(CryptographicError, match=f"Vault transit generate-and-wrap failed for key '{KEY_NAME}'") as raised:
        generate(create(context=None, address=f"http://127.0.0.1:{free_port()}/"))

    assert isinstance(raised.value.__cause__, OSError)


def test_a_redirect_is_not_followed(vault: FakeTransit, create: Create) -> None:
    vault.answer = lambda request, count: Answer(307, "", {"Location": f"http://127.0.0.1:{vault.port}/v1/transit/encrypt/elsewhere"})

    with pytest.raises(CryptographicError, match="Vault answered 307 Temporary Redirect") as raised:
        wrap_new(create(), bytes(32))

    assert isinstance(raised.value.__cause__, VaultRequestError) and raised.value.__cause__.status_code == 307
    assert [r.key for r in vault.requests] == [KEY_NAME]


@pytest.mark.parametrize(("base", "retry", "jitter", "expected"), [
    (200, 0, 0, 200), (200, 1, 0, 400), (200, 2, 50, 850), (200, 5, 0, 6400), (200, 6, 0, 10000), (200, 20, 0, 10000), (200, 20, 100, 10100),
    (0, 3, 37, 37), (10000, 0, 0, 10000), (10000, 40, 0, 10000),
])
def test_retry_delay_doubles_up_to_the_maximum_plus_the_jitter(base: int, retry: int, jitter: int, expected: int) -> None:
    assert _retry_delay(timedelta(milliseconds=base), retry, jitter) == timedelta(milliseconds=expected)


def test_an_ssl_context_given_is_the_one_every_https_request_uses(vault: FakeTransit, create: Create) -> None:
    wrapped: list[str | None] = []

    class Recording(ssl.SSLContext):
        def wrap_socket(self, *args: Any, **kwargs: Any) -> ssl.SSLSocket:
            wrapped.append(kwargs.get("server_hostname"))
            return super().wrap_socket(*args, **kwargs)

    context = Recording(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    # The fake speaks plain http, so the handshake fails - after the context was asked to make it.
    wrapper = create(address=f"https://127.0.0.1:{vault.port}/", ssl_context=context)

    with pytest.raises(CryptographicError) as raised:
        generate(wrapper)

    assert isinstance(raised.value.__cause__, OSError)
    assert wrapped == ["127.0.0.1"] * (1 + Options.MIN_RETRY_COUNT)


def test_the_namespace_mount_and_path_prefix_are_used(transits: Callable[..., FakeTransit], create: Create) -> None:
    prefixed = transits("transit/team-a", "/vault")

    generate(create(on=prefixed, mount_path="transit/team-a", namespace="team-a/prod"))

    assert [r.namespace for r in prefixed.requests] == ["team-a/prod"]
    assert prefixed.unexpected_requests == []


def test_an_address_without_a_trailing_slash_is_used_the_same(vault: FakeTransit, create: Create) -> None:
    generate(create(address=f"http://127.0.0.1:{vault.port}"))

    assert vault.unexpected_requests == []


def test_after_close_no_call_is_made(vault: FakeTransit, create: Create) -> None:
    wrapper = create()
    wrapped = wrap_new(wrapper)
    result = bytearray(b"\xaa" * 32)

    with wrapper:
        pass

    with pytest.raises(ObjectClosedError):
        wrapper.unwrap(wrapped, result)
    with pytest.raises(ObjectClosedError):
        generate(wrapper)
    assert is_zero(result)
    assert len(vault.requests) == 1


@pytest.mark.parametrize(("value", "expected"), [
    ("vault:v1:AAAA", True), ("vault:v1234567890:AB+/=", True), ("vault:v1:", False), ("vault:v:AAAA", False), ("vault:v1AAAA", False),
    ("vault:v12345678901:AAAA", False), ("vault:v1:AA-A", False), ("vault:", False), ("", False), ("vault:v١:AAAA", False),
])
def test_is_vault_ciphertext_accepts_only_vaults_format(value: str, expected: bool) -> None:
    assert is_vault_ciphertext(value.encode()) is expected


@pytest.mark.parametrize("length", range(1, 40))
def test_base64_is_written_and_read_as_the_standard_library_does(length: int) -> None:
    data = os.urandom(length)
    encoded = bytearray((length + 2) // 3 * 4 + 2)

    written = _encode_base64(memoryview(data), encoded, 1)
    decoded = bytearray(written // 4 * 3)

    assert encoded[1:1 + written] == base64.b64encode(data)
    assert decoded[:_decode_base64(memoryview(encoded)[1:1 + written], decoded)] == data


# --- The token --------------------------------------------------------------------------------


@pytest.mark.parametrize("token", ["", "hvs.with space", "hvs.é", "hvs.\n", "t" * (Wrapper.MAX_TOKEN_LENGTH + 1)])
def test_a_token_that_is_not_one_fails_without_a_request(vault: FakeTransit, create: Create, token: str) -> None:
    with pytest.raises(RuntimeError, match="token source"):
        generate(create(tokens=FakeTokenSource.giving(token)))

    assert vault.requests == []


def test_a_token_source_returning_no_count_fails_without_a_request(vault: FakeTransit, create: Create) -> None:
    class Broken(VaultTokenSource):
        def copy_token(self, destination: memoryview) -> int:
            destination[:len(TOKEN)] = TOKEN.encode()
            return None  # type: ignore[return-value]

    with pytest.raises(RuntimeError, match="token source"):
        generate(create(tokens=Broken()))

    assert vault.requests == []


@pytest.mark.parametrize("failure", [TimeoutError("login failed"), PermissionError("approle refused"), KeyError("role_id")])
def test_a_token_sources_failure_propagates_as_it_is_and_is_not_retried(vault: FakeTransit, create: Create, failure: Exception) -> None:
    tokens = FakeTokenSource()

    def fail(call: int) -> str:
        raise failure

    tokens.next = fail

    with pytest.raises(type(failure)) as raised:
        generate(create(tokens=tokens))

    assert raised.value is failure
    assert tokens.calls == 1
    assert vault.requests == []


def test_a_token_source_slower_than_the_timeout_times_out_and_its_late_token_is_not_used(vault: FakeTransit, create: Create) -> None:
    tokens = FakeTokenSource()
    tokens.hang = True

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="token source"):
        generate(create(tokens=tokens, timeout=timedelta(milliseconds=200)))

    assert time.monotonic() - started < 2
    tokens.release.set()
    time.sleep(0.1)
    assert vault.requests == []


def test_every_call_asks_the_source_for_the_token_and_follows_a_token_it_replaces(vault: FakeTransit, create: Create) -> None:
    tokens = FakeTokenSource()
    tokens.next = lambda call: TOKEN if call != 2 else "hvs.expired"
    wrapper = create(tokens=tokens)

    wrapped = generate(wrapper)
    with pytest.raises(CryptographicError, match="403"):
        wrapper.unwrap(wrapped, bytearray(32))
    wrapper.unwrap(wrapped, bytearray(32))

    assert tokens.calls == 3
    assert [r.token for r in vault.requests] == [TOKEN, "hvs.expired", TOKEN]


def test_no_failure_quotes_the_token(vault: FakeTransit, create: Create) -> None:
    for answer in (Answer(403, '{"errors":["permission denied"]}'), Answer(500, "boom"), Answer(200, "<html>")):
        vault.answer = lambda request, count, given=answer: given
        with pytest.raises(CryptographicError) as raised:
            generate(create())
        for error in (raised.value, raised.value.__cause__):
            assert TOKEN not in str(error)


def test_static_vault_token_source_supplies_its_token_until_closed(vault: FakeTransit, create: Create) -> None:
    tokens = StaticVaultTokenSource(TOKEN)
    wrapper = create(tokens=tokens)

    generate(wrapper)
    with tokens:
        pass

    with pytest.raises(RuntimeError, match="token source"):
        generate(wrapper)
    assert len(vault.requests) == 1


def test_static_vault_token_source_takes_a_buffer_and_copies_it(vault: FakeTransit, create: Create) -> None:
    given = bytearray(TOKEN.encode())
    tokens = StaticVaultTokenSource(given)
    given[:] = bytes(len(given))

    generate(create(tokens=tokens))

    assert [r.token for r in vault.requests] == [TOKEN]


@pytest.mark.parametrize("token", ["", "hvs.with space", "hvs.é", "hvs.\n", b"hvs.\x00", "t" * (Wrapper.MAX_TOKEN_LENGTH + 1)])
def test_static_vault_token_source_rejects_a_token_that_is_not_one(token: str | bytes) -> None:
    with pytest.raises(ValueError, match="printable ASCII"):
        StaticVaultTokenSource(token)


def test_static_vault_token_source_rejects_none_and_a_destination_too_small() -> None:
    none: Any = None
    with pytest.raises(TypeError):
        StaticVaultTokenSource(none)
    with pytest.raises(TypeError):
        StaticVaultTokenSource(7)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="destination holds 4"):
        StaticVaultTokenSource(TOKEN).copy_token(memoryview(bytearray(4)))


# --- Crypto provider --------------------------------------------------------------------------


@pytest.mark.parametrize("context", [None, CONTEXT])
def test_a_crypto_provider_generates_and_reveals_its_dek_through_vault(vault: FakeTransit, create: Create, context: str | None) -> None:
    with AesGcmCryptoProviderFactory().create_ephemeral(create(context=context), 60) as provider:
        expected = b"hello, vault"
        # Encrypt zeroes the plaintext it is given, so it gets a copy.
        plaintext = bytearray(expected)
        encrypted = bytearray(provider.get_encrypted_allocation_length(len(plaintext)))
        encrypted_length = provider.encrypt(plaintext, encrypted)
        decrypted = bytearray(provider.get_decrypted_allocation_length(encrypted_length))
        decrypted_length = provider.decrypt(encrypted[:encrypted_length], decrypted)

        assert decrypted[:decrypted_length] == expected
    assert vault.requests[0].operation == ("datakey" if context is None else "encrypt")


# --- Key files --------------------------------------------------------------------------------


@pytest.fixture
def user_writable_key_file() -> Iterator[Path]:
    """A key file in a folder the user running the tests could replace: under the user's temp folder
    (Windows) or the shared /tmp (Linux and macOS) - neither somewhere only administrators can write."""
    root = long_path(Path(tempfile.gettempdir())) if sys.platform == "win32" else Path("/tmp")
    directory = root / f"hkdfguard-keys-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        path = directory / "v1.key"
        path.write_bytes(b"vault:v1:" + base64.b64encode(os.urandom(60)))
        yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_read_key_file_by_default_refuses_a_file_the_current_user_could_have_replaced(create: Create, user_writable_key_file: Path) -> None:
    with pytest.raises(PermissionError, match="not trusted"):
        create().read_key_file(user_writable_key_file)


def test_read_key_file_with_no_trust_given_trusts_administrators_only(vault: FakeTransit, user_writable_key_file: Path) -> None:
    # The same refusal as the default: None is ADMINISTRATORS_ONLY, never "anyone".
    with pytest.raises(PermissionError, match="not trusted"):
        Wrapper(vault.address, KEY_NAME, FakeTokenSource(), CONTEXT, key_file_trust=None).read_key_file(user_writable_key_file)


@pytest.mark.parametrize(("path", "expected"), [(None, TypeError), ("", ValueError)])
def test_read_key_file_refuses_a_missing_path(create: Create, path: object, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        create().read_key_file(path)  # type: ignore[arg-type]


def current_user_sid() -> str:
    whoami = os.path.join(os.environ["SYSTEMROOT"], "System32", "whoami.exe")
    output = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout.strip()
    return output.rsplit(",", 1)[1].strip('"')  # "DOMAIN\name","S-1-5-21-..."


@windows_only
def test_read_key_file_with_the_writers_account_trusted_reads_the_file_and_it_reveals(create: Create, user_writable_key_file: Path) -> None:
    wrapper = create(key_file_trust=KeyFileTrust(windows_principals=[current_user_sid()]))
    wrapped = generate(wrapper)
    user_writable_key_file.write_bytes(wrapped)

    read = wrapper.read_key_file(user_writable_key_file)

    assert read == wrapped
    assert wrapper.unwrap(read, bytearray(32)) == 32


@windows_only
def test_read_key_file_trusting_everyone_is_refused(create: Create, user_writable_key_file: Path) -> None:
    wrapper = create(key_file_trust=KeyFileTrust(windows_principals=["S-1-1-0"]))

    with pytest.raises(ValueError, match="every account"):
        wrapper.read_key_file(user_writable_key_file)
