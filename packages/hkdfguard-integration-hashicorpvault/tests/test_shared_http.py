"""The helpers the transit key wrapper and the secret cache share to make a request."""

from __future__ import annotations

import http.client
import os
import ssl
import threading
import time
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from hkdfguard.abstractions import DataProtector, KeyWrapper, WritableBuffer
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.integration.hashicorpvault import VaultRequestError, VaultTlsOptions
from hkdfguard.integration.hashicorpvault._http import (
    NAMESPACE_HEADER,
    REQUEST_HEADER,
    VaultConnector,
    _NamedHttpsConnection,
    decrypt_token,
    put_protected_token,
    put_request,
    run_within,
    set_remaining,
    with_retries,
)
from hkdfguard.integration.hashicorpvault._tls import check_tls_options

TOKEN = "hvs.example-token"


class FixedKeyWrapper(KeyWrapper):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def wrap(self, plaintext: Any, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Any, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


@pytest.fixture
def protector() -> Iterator[DataProtector]:
    ring = DefaultKeyRing(DefaultFormatProvider())
    ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
    yield ring.create_protector("HkdfGuard.Integration.HashiCorpVault.Token")
    ring.close()


class RecordingConnection:
    """Records the request line and headers http.client would send."""

    def __init__(self) -> None:
        self.request: tuple[str, str] | None = None
        self.headers: list[tuple[str, bytes]] = []
        self.token_buffers: list[Any] = []

    def putrequest(self, method: str, path: str) -> None:
        self.request = (method, path)

    def putheader(self, name: str, value: Any) -> None:
        if isinstance(value, memoryview):
            self.token_buffers.append(value.obj)
            self.headers.append((name, bytes(value)))
        else:
            self.headers.append((name, str(value).encode()))


# --- Headers and tokens ---------------------------------------------------------------------------


def test_every_request_is_marked_and_the_namespace_sent_only_when_set() -> None:
    connection = RecordingConnection()
    put_request(connection, "GET", "/v1/secret/data/a", None)  # type: ignore[arg-type]
    assert connection.request == ("GET", "/v1/secret/data/a")
    assert connection.headers == [(REQUEST_HEADER, b"true")]

    connection = RecordingConnection()
    put_request(connection, "POST", "/v1/transit/encrypt/k", "team-a/prod")  # type: ignore[arg-type]
    assert connection.headers == [(REQUEST_HEADER, b"true"), (NAMESPACE_HEADER, b"team-a/prod")]


def test_a_protected_token_is_sent_decrypted_from_a_buffer_then_zeroed(protector: DataProtector) -> None:
    connection = RecordingConnection()
    put_protected_token(connection, protector, protector.encrypt(TOKEN))  # type: ignore[arg-type]
    assert connection.headers == [("X-Vault-Token", TOKEN.encode())]
    assert len(connection.token_buffers) == 1
    assert not any(connection.token_buffers[0])


@pytest.mark.parametrize("handed_over", [TOKEN, "", "vault:v9:AAAA"])
def test_a_token_the_protector_didnt_protect_is_refused_without_quoting_or_chaining(protector: DataProtector, handed_over: str) -> None:
    with pytest.raises(RuntimeError, match="isn't protected by the token protector") as raised:
        decrypt_token(protector, handed_over)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ or raised.value.__context__ is None
    assert TOKEN not in str(raised.value)


def test_a_protected_value_that_isnt_a_token_is_refused(protector: DataProtector) -> None:
    with pytest.raises(RuntimeError, match="isn't a token"):
        decrypt_token(protector, protector.encrypt("has a space"))


def test_decrypt_token_returns_the_token_and_its_length(protector: DataProtector) -> None:
    token, length = decrypt_token(protector, protector.encrypt(TOKEN))
    assert bytes(token[:length]) == TOKEN.encode()


# --- Retries ---------------------------------------------------------------------------------------


class Attempts:
    def __init__(self, *failures: BaseException) -> None:
        self.failures = list(failures)
        self.count = 0

    def __call__(self) -> str:
        self.count += 1
        if self.failures:
            raise self.failures.pop(0)
        return "answer"


NO_DELAY = timedelta(0)


@pytest.mark.parametrize("failure", [VaultRequestError("sealed", 503), VaultRequestError("slow down", 429), ConnectionResetError(),
                                     TimeoutError(), http.client.RemoteDisconnected("closed")])
def test_a_transient_failure_is_retried(failure: BaseException) -> None:
    attempt = Attempts(failure, failure)
    assert with_retries(attempt, 3, NO_DELAY, wait=lambda _: False) == "answer"
    assert attempt.count == 3


@pytest.mark.parametrize("failure", [VaultRequestError("denied", 403), VaultRequestError("not implemented", 501),
                                     ssl.SSLCertVerificationError(1, "certificate verify failed"), ValueError("not transient")])
def test_anything_else_is_raised_at_once(failure: BaseException) -> None:
    attempt = Attempts(failure)
    with pytest.raises(type(failure)) as raised:
        with_retries(attempt, 3, NO_DELAY, wait=lambda _: False)
    assert raised.value is failure
    assert attempt.count == 1


def test_the_last_failure_is_raised_once_the_retries_are_spent() -> None:
    failures = [VaultRequestError(f"sealed {i}", 503) for i in range(5)]
    attempt = Attempts(*failures)
    with pytest.raises(VaultRequestError) as raised:
        with_retries(attempt, 3, NO_DELAY, wait=lambda _: False)
    assert raised.value is failures[3]
    assert attempt.count == 4


def test_the_waits_double_from_the_base_delay_with_jitter() -> None:
    waits: list[float] = []
    with pytest.raises(ConnectionResetError):
        with_retries(Attempts(*[ConnectionResetError()] * 4), 3, timedelta(milliseconds=200), wait=lambda s: waits.append(s) or False)  # type: ignore[func-returns-value]
    assert [round(w, 1) for w in waits] in ([0.2, 0.4, 0.8], [0.3, 0.4, 0.8], [0.2, 0.5, 0.8], [0.3, 0.5, 0.9], [0.2, 0.4, 0.9],
                                             [0.3, 0.4, 0.9], [0.2, 0.5, 0.9], [0.3, 0.5, 0.8])
    for wait, base in zip(waits, (0.2, 0.4, 0.8), strict=True):
        assert base <= wait <= base + 0.1


def test_stopped_or_a_wait_that_gives_up_raises_the_last_failure() -> None:
    attempt = Attempts(ConnectionResetError(), ConnectionResetError())
    with pytest.raises(ConnectionResetError):
        with_retries(attempt, 3, NO_DELAY, stopped=lambda: True)
    assert attempt.count == 1

    attempt = Attempts(ConnectionResetError(), ConnectionResetError())
    with pytest.raises(ConnectionResetError):
        with_retries(attempt, 3, NO_DELAY, wait=lambda _: True)
    assert attempt.count == 1


def test_without_a_wait_it_sleeps() -> None:
    started = time.monotonic()
    assert with_retries(Attempts(ConnectionResetError()), 3, timedelta(milliseconds=50)) == "answer"
    assert time.monotonic() - started >= 0.05


# --- Running within a timeout ----------------------------------------------------------------------


def test_run_within_returns_the_result_or_raises_the_failure_as_it_is() -> None:
    assert run_within(lambda: 42, timedelta(seconds=5), thread_name="t", timeout_message="late") == 42
    failure = KeyError("source")

    def fail() -> None:
        raise failure

    with pytest.raises(KeyError) as raised:
        run_within(fail, timedelta(seconds=5), thread_name="t", timeout_message="late")
    assert raised.value is failure


def test_a_late_result_times_out_and_is_handed_to_abandoned() -> None:
    release = threading.Event()
    abandoned: list[bytearray] = []
    done = threading.Event()
    late = bytearray(b"secret")

    def slow() -> bytearray:
        release.wait(5)
        return late

    def dispose(result: bytearray) -> None:
        abandoned.append(result)
        done.set()

    with pytest.raises(TimeoutError, match="no token within"):
        run_within(slow, timedelta(milliseconds=50), thread_name="hkdfguard-test", timeout_message="no token within 50 ms", abandoned=dispose)
    release.set()
    assert done.wait(5)
    assert abandoned == [late]


def test_the_action_runs_on_a_named_daemon_thread() -> None:
    thread = run_within(threading.current_thread, timedelta(seconds=5), thread_name="hkdfguard-vault-token", timeout_message="late")
    assert thread.name == "hkdfguard-vault-token"
    assert thread.daemon


def test_set_remaining_raises_once_the_deadline_has_passed() -> None:
    class Sock:
        timeout: float | None = None

        def settimeout(self, value: float) -> None:
            self.timeout = value

    sock = Sock()
    set_remaining(sock, time.monotonic() + 10, lambda: TimeoutError("late"))  # type: ignore[arg-type]
    assert sock.timeout is not None and 9 < sock.timeout <= 10
    with pytest.raises(TimeoutError, match="late"):
        set_remaining(sock, time.monotonic() - 1, lambda: TimeoutError("late"))  # type: ignore[arg-type]


# --- Connections -----------------------------------------------------------------------------------


def test_an_http_address_connects_in_the_clear_and_https_over_the_default_context() -> None:
    plain = VaultConnector(False, "127.0.0.1", 8200, timedelta(seconds=3))
    connection = plain.connect()
    assert type(connection) is http.client.HTTPConnection
    assert connection.timeout == 3
    assert plain.ssl_context is None

    secure = VaultConnector(True, "vault.example.com", None, timedelta(seconds=3))
    assert type(secure.connect()) is http.client.HTTPSConnection
    assert secure.ssl_context is not None and secure.ssl_context.check_hostname


def test_an_ssl_context_given_is_used_as_it_is() -> None:
    context = ssl.create_default_context()
    connector = VaultConnector(True, "vault.example.com", 8200, timedelta(seconds=3), context)
    assert connector.ssl_context is context
    assert connector.connect()._context is context  # type: ignore[attr-defined]


def test_tls_options_are_read_once_and_a_server_name_is_verified_in_place_of_the_host() -> None:
    connector = VaultConnector(True, "10.0.0.5", 8200, timedelta(seconds=3), tls=VaultTlsOptions(server_name="vault.internal"))
    connection = connector.connect()
    assert isinstance(connection, _NamedHttpsConnection)
    assert connection._server_name == "vault.internal"
    assert connector.ssl_context is not None and connector.ssl_context.minimum_version is ssl.TLSVersion.TLSv1_2


def test_tls_options_are_unused_for_an_http_address() -> None:
    connector = VaultConnector(False, "127.0.0.1", 8200, timedelta(seconds=3), tls=VaultTlsOptions(server_certificate_file="missing.pem"))
    assert connector.ssl_context is None


def test_unreadable_tls_options_fail_when_the_connector_is_made() -> None:
    with pytest.raises(ValueError, match="Could not read"):
        VaultConnector(True, "vault.example.com", 8200, timedelta(seconds=3), tls=VaultTlsOptions(server_certificate_file="missing.pem"))


def test_an_ssl_context_and_tls_options_are_refused_together_or_of_the_wrong_type() -> None:
    with pytest.raises(ValueError, match="can't be given together"):
        check_tls_options(ssl.create_default_context(), VaultTlsOptions())
    with pytest.raises(TypeError, match="ssl_context"):
        check_tls_options("context", None)
    with pytest.raises(TypeError, match="tls"):
        check_tls_options(None, {"server_name": "x"})
    check_tls_options(None, None)
