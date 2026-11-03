"""What the transit key wrapper, the secret cache and the client share to send a request and read
Vault's answer: one attempt, its body read within the deadline, a refusal's errors, abandoning a
cancelled call, the token provider waited for, the address and the options."""

from __future__ import annotations

import asyncio
import dataclasses
import http.server
import socket
import threading
import time
from collections.abc import Callable, Iterator
from datetime import timedelta
from typing import Any, ClassVar

import pytest
from hkdfguard.integration.hashicorpvault import (
    MAX_RETRY_COUNT,
    MIN_RETRY_COUNT,
    VaultConnectionOptions,
    VaultTlsOptions,
    VaultTokenProvider,
    check_connection_options,
)
from hkdfguard.integration.hashicorpvault._connection import is_loopback, parse_address
from hkdfguard.integration.hashicorpvault._errors import MAX_ERROR_BODY_LENGTH, describe_status, read_errors, reason_phrase
from hkdfguard.integration.hashicorpvault._http import Abandon, VaultConnector, exchange, read_body
from hkdfguard.integration.hashicorpvault._token_provider import get_token_within, get_token_within_async

TIMEOUT = timedelta(seconds=5)

# --- read_errors, describe_status ----------------------------------------------------------------


@pytest.mark.parametrize(("body", "expected"), [
    ('{"errors":["permission denied"]}', ["permission denied"]),
    ('{"errors":["first","second"]}', ["first", "second"]),
    ('{"errors":["first",7,{"a":1},null]}', ["first", "7", '{"a":1}', "null"]),
    ('{"errors":[]}', []),
    ("{}", []),
    ('{"request_id":"x","data":{"a":1}}', []),
    ('{"error":"bad"}', ["bad"]),
    ('{"errors":[],"error":"bad"}', ["bad"]),
    ('{"errors":["listed"],"error":"bad"}', ["listed"]),
    ('{"error":7}', []),
    (' {"errors":["spaced"]} ', ["spaced"]),
])
def test_read_errors_lists_the_errors_vault_gave(body: str, expected: list[str]) -> None:
    assert read_errors(memoryview(body.encode())) == expected


@pytest.mark.parametrize("body", ["", "<html>Bad Gateway</html>", "[]", '"errors"', '{"errors":"x"}', '{"errors":{}}', '{"errors":["a"]} trailing',
                                  '{"errors":["a"]', "\xff"])
def test_read_errors_is_none_for_a_body_that_isnt_vaults_json(body: str) -> None:
    assert read_errors(memoryview(body.encode("latin1"))) is None


@pytest.mark.parametrize(("status", "expected"), [(404, " Not Found"), (503, " Service Unavailable"), (472, ""), (999, "")])
def test_reason_phrase_is_the_statuss_reason_or_nothing(status: int, expected: str) -> None:
    assert reason_phrase(status) == expected


def test_describe_status_names_the_status_and_joins_the_errors() -> None:
    assert describe_status(403, ["permission denied"]) == "403 Forbidden: permission denied"
    assert describe_status(400, ["a", "b"]) == "400 Bad Request: a; b"
    assert describe_status(400, ["a", "b"], ", ") == "400 Bad Request: a, b"
    assert describe_status(404, []) == "404 Not Found"
    assert describe_status(404, None) == "404 Not Found"
    assert describe_status(472, ["dr secondary"]) == "472: dr secondary"


# --- exchange, DeadlineBody, read_body -------------------------------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    # What the server answers with: given the handler, it writes the whole response.
    respond: ClassVar[Callable[[_Handler], None]]
    requests: ClassVar[list[tuple[str, str, dict[str, str], bytes]]] = []

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        _Handler.requests.append((self.command, self.path, dict(self.headers.items()), self.rfile.read(length)))
        _Handler.respond(self)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def _answer(status: int, body: bytes, *, length: int | None = None, delay: float = 0) -> Callable[[_Handler], None]:
    def respond(handler: _Handler) -> None:
        handler.send_response(status)
        handler.send_header("Content-Length", str(len(body) if length is None else length))
        handler.end_headers()
        if delay:
            handler.wfile.flush()
            time.sleep(delay)
        handler.wfile.write(body)
        handler.wfile.flush()
        handler.close_connection = True

    return respond


@pytest.fixture
def server() -> Iterator[VaultConnector]:
    _Handler.requests = []
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield VaultConnector(False, "127.0.0.1", httpd.server_address[1], TIMEOUT)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_exchange_sends_the_request_with_its_headers_and_body_and_yields_the_answer(server: VaultConnector) -> None:
    _Handler.respond = _answer(200, b'{"data":{"a":1}}')

    def headers(connection: Any) -> None:
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "2")

    with exchange(server, "POST", "/v1/transit/encrypt/k", "team-a", TIMEOUT, headers=headers, body=memoryview(b"{}")) as (status, body):
        buffer = bytearray(64)
        length = read_body(body, buffer)
    assert status == 200
    assert bytes(buffer[:length]) == b'{"data":{"a":1}}'
    method, path, sent, content = _Handler.requests[0]
    assert (method, path, content) == ("POST", "/v1/transit/encrypt/k", b"{}")
    assert sent["X-Vault-Request"] == "true"
    assert sent["X-Vault-Namespace"] == "team-a"


def test_read_body_stops_once_the_buffer_is_full(server: VaultConnector) -> None:
    _Handler.respond = _answer(200, b"x" * 100)
    with exchange(server, "GET", "/v1/a", None, TIMEOUT) as (_, body):
        buffer = bytearray(11)
        assert read_body(body, buffer) == 11
        # Read to its end, it reads nothing more.
        assert read_body(body, bytearray(200)) == 89
        assert read_body(body, bytearray(200)) == 0


def test_a_body_cut_short_of_its_content_length_is_a_lost_connection(server: VaultConnector) -> None:
    _Handler.respond = _answer(200, b"partial", length=100)
    with exchange(server, "GET", "/v1/a", None, TIMEOUT, description="the read of 'a'") as (_, body), \
            pytest.raises(ConnectionError, match="lost during Vault's response to the read of 'a'") as raised:
        read_body(body, bytearray(200))
    # Its partial bytes may hold a secret: neither kept nor chained.
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ or raised.value.__context__ is None


def test_a_body_that_takes_longer_than_the_timeout_times_out(server: VaultConnector) -> None:
    _Handler.respond = _answer(200, b"late", delay=1.5)
    with exchange(server, "GET", "/v1/a", None, timedelta(milliseconds=300)) as (_, body), \
            pytest.raises(TimeoutError, match=r"^Vault's response took longer than 0:00:00.300000\.$"):
        read_body(body, bytearray(16))


def test_an_abandoned_read_fails_with_the_abandons_error(server: VaultConnector) -> None:
    _Handler.respond = _answer(200, b"late", delay=2)
    abandon = Abandon("cancelled here")
    threading.Timer(0.3, abandon.abandon).start()
    started = time.monotonic()
    with exchange(server, "GET", "/v1/a", None, TIMEOUT, abandon=abandon) as (_, body), pytest.raises(ConnectionAbortedError, match="cancelled here"):
        read_body(body, bytearray(16))
    # Shut down, the socket doesn't wait for Vault - except on Windows, where that doesn't wake a
    # blocked read, which runs on to Vault's answer.
    assert time.monotonic() - started < 3


def test_an_abandoned_call_sends_no_request() -> None:
    abandon = Abandon("cancelled here")
    abandon.abandon()
    with pytest.raises(ConnectionAbortedError, match="cancelled here"):
        abandon.track(socket.socket())
    assert abandon.abandoned
    assert abandon.wait(10)


def test_an_abandon_shuts_down_the_socket_it_tracks() -> None:
    left, right = socket.socketpair()
    try:
        abandon = Abandon("x")
        abandon.track(left)
        abandon.abandon()
        # Shut down both ways: the peer reads its end.
        right.settimeout(5)
        assert right.recv(1) == b""
        abandon.track(None)
        # Nothing tracked, nothing to shut down.
        abandon.abandon()
    finally:
        left.close()
        right.close()


def test_the_error_body_limit_is_64_kib() -> None:
    assert MAX_ERROR_BODY_LENGTH == 64 * 1024


# --- get_token_within ------------------------------------------------------------------------------


class _Provider(VaultTokenProvider):
    def __init__(self, token: object, delay: float = 0) -> None:
        self.token = token
        self.delay = delay

    def get_token(self) -> str:
        time.sleep(self.delay)
        if isinstance(self.token, BaseException):
            raise self.token
        return self.token  # type: ignore[return-value]  # a provider that isn't, on purpose

    async def get_token_async(self) -> str:
        await asyncio.sleep(self.delay)
        if isinstance(self.token, BaseException):
            raise self.token
        return self.token  # type: ignore[return-value]


def test_get_token_within_returns_the_providers_token() -> None:
    assert get_token_within(_Provider("protected"), TIMEOUT) == "protected"
    assert asyncio.run(get_token_within_async(_Provider("protected"), TIMEOUT)) == "protected"


@pytest.mark.parametrize("token", [None, "", 7])
def test_get_token_within_refuses_no_token(token: object) -> None:
    with pytest.raises(RuntimeError, match="returned no token"):
        get_token_within(_Provider(token), TIMEOUT)
    with pytest.raises(RuntimeError, match="returned no token"):
        asyncio.run(get_token_within_async(_Provider(token), TIMEOUT))


def test_get_token_within_raises_the_providers_failure_as_it_is() -> None:
    failure = PermissionError("login refused")
    with pytest.raises(PermissionError) as raised:
        get_token_within(_Provider(failure), TIMEOUT)
    assert raised.value is failure
    # The provider's own TimeoutError isn't the wait's.
    own = TimeoutError("the login timed out")
    with pytest.raises(TimeoutError) as timed_out:
        asyncio.run(get_token_within_async(_Provider(own), TIMEOUT))
    assert timed_out.value is own


def test_get_token_within_times_out_a_provider_that_takes_too_long() -> None:
    with pytest.raises(TimeoutError, match=r"returned no token within 0:00:00.100000"):
        get_token_within(_Provider("late", delay=2), timedelta(milliseconds=100))
    with pytest.raises(TimeoutError, match=r"returned no token within 0:00:00.100000"):
        asyncio.run(get_token_within_async(_Provider("late", delay=2), timedelta(milliseconds=100)))


# --- parse_address, is_loopback --------------------------------------------------------------------


@pytest.mark.parametrize(("address", "expected"), [
    ("https://vault.example.com:8200", (True, "vault.example.com", 8200, "")),
    ("https://vault.example.com/proxy/vault/", (True, "vault.example.com", None, "/proxy/vault")),
    ("http://127.0.0.1:8200", (False, "127.0.0.1", 8200, "")),
])
def test_parse_address_gives_the_path_prefix(address: str, expected: tuple[bool, str, int | None, str]) -> None:
    assert parse_address(address) == expected


def test_parse_address_allows_http_anywhere_only_when_asked() -> None:
    assert parse_address("http://vault.example.com:8200", allow_unencrypted_http=True) == (False, "vault.example.com", 8200, "")
    with pytest.raises(ValueError, match=r"must be https.*or with allow_unencrypted_http"):
        parse_address("http://vault.example.com:8200", allow_unencrypted_http=False)
    # A caller with no such option isn't told of it.
    with pytest.raises(ValueError, match="must be https") as raised:
        parse_address("http://vault.example.com:8200")
    assert "allow_unencrypted_http" not in str(raised.value)


@pytest.mark.parametrize(("address", "message"), [
    ("unix:///var/run/vault.sock", "unix socket"),
    ("https://vault.example.com:notaport", "isn't absolute"),
    ("https://vault.example.com?x=1", "credentials, a query or a fragment"),
])
def test_parse_address_refuses_what_it_cant_connect_to(address: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_address(address)


@pytest.mark.parametrize(("host", "expected"), [("localhost", True), ("LOCALHOST", True), ("127.0.0.1", True), ("127.255.0.9", True), ("::1", True),
                                                ("10.0.0.1", False), ("127.0.0.1.example.com", False), ("::ffff:10.0.0.1", False), ("vault", False)])
def test_is_loopback_parses_only_literals(host: str, expected: bool) -> None:
    assert is_loopback(host) is expected


# --- VaultConnectionOptions ------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class _EngineOptions(VaultConnectionOptions):
    mount_path: str = "engine"
    extra: int = 1


def test_an_integrations_options_inherit_the_shared_ones_and_their_limits() -> None:
    options = _EngineOptions(namespace="team-a", extra=2)
    assert (options.mount_path, options.namespace, options.extra) == ("engine", "team-a", 2)
    assert (options.timeout, options.retry_count, options.retry_delay) == (timedelta(seconds=30), MIN_RETRY_COUNT, timedelta(milliseconds=200))
    assert (_EngineOptions.MIN_RETRY_COUNT, _EngineOptions.MAX_RETRY_COUNT) == (MIN_RETRY_COUNT, MAX_RETRY_COUNT)
    check_connection_options(options)
    assert dataclasses.replace(options, mount_path="other").mount_path == "other"
    with pytest.raises(TypeError):
        _EngineOptions("positional")  # type: ignore[call-arg]  # keyword-only
    with pytest.raises(dataclasses.FrozenInstanceError):
        options.namespace = "x"  # type: ignore[misc]


def test_check_connection_options_refuses_other_types_and_both_tls_settings() -> None:
    with pytest.raises(TypeError, match="must be VaultConnectionOptions"):
        check_connection_options(object())  # type: ignore[arg-type]
    import ssl
    with pytest.raises(ValueError, match="can't be given together"):
        check_connection_options(_EngineOptions(ssl_context=ssl.create_default_context(), tls=VaultTlsOptions(server_name="vault")))
    with pytest.raises(TypeError, match="tls must be VaultTlsOptions"):
        check_connection_options(_EngineOptions(tls="tls"))  # type: ignore[arg-type]
