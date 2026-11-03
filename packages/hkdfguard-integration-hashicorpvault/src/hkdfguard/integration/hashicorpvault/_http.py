"""What the Vault integrations share to make a request: the connection, the headers every request
carries, the token's header, the retries, and running a caller's code within a timeout."""

from __future__ import annotations

import http.client
import itertools
import secrets
import socket
import ssl
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Final

from hkdfguard.abstractions import ArrayUtility, CryptographicError, DataProtector
from hkdfguard.integration.hashicorpvault._connection import TOKEN_HEADER, is_valid_token, retry_delay
from hkdfguard.integration.hashicorpvault._errors import VaultRequestError
from hkdfguard.integration.hashicorpvault._tls import VaultTlsOptions

REQUEST_HEADER: Final = "X-Vault-Request"
"""Marks every request as Vault's own clients do, so Vault answers an unauthenticated one 403 rather
than redirecting it to the UI."""

NAMESPACE_HEADER: Final = "X-Vault-Namespace"
"""The header a request's Vault Enterprise namespace is sent in."""


def check_tls_options(ssl_context: object, tls: object) -> None:
    """Refuses an ``ssl_context`` or ``tls`` of the wrong type, or both together: each says how to
    connect, so one would silently override the other.

    :raises TypeError: ``ssl_context`` isn't an ``ssl.SSLContext`` or ``tls`` a :class:`VaultTlsOptions`
    :raises ValueError: both are given
    """
    if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
        raise TypeError("ssl_context must be an ssl.SSLContext.")
    if tls is not None and not isinstance(tls, VaultTlsOptions):
        raise TypeError("tls must be VaultTlsOptions.")
    if ssl_context is not None and tls is not None:
        raise ValueError("ssl_context and tls can't be given together: set the TLS settings with one or the other.")


class VaultConnector:
    """Opens a connection of its own to Vault for each request - no proxy, no redirect followed -
    over TLS for an https address: with ``ssl_context`` if given, else ``tls``'s context (its files
    read here, once), else ``ssl.create_default_context()``."""

    __slots__ = ("_context", "_host", "_https", "_port", "_server_name", "_timeout_seconds")

    def __init__(self, https: bool, host: str, port: int | None, timeout: timedelta, ssl_context: ssl.SSLContext | None = None,  # noqa: PLR0917 - api_base's tuple, as it comes
                 tls: VaultTlsOptions | None = None) -> None:
        """:raises TypeError: see :func:`check_tls_options`
        :raises ValueError: see :func:`check_tls_options` and :meth:`VaultTlsOptions.create_ssl_context`
        """
        check_tls_options(ssl_context, tls)
        self._https = https
        self._host = host
        self._port = port
        self._timeout_seconds = timeout.total_seconds()
        self._server_name = tls.server_name if tls is not None else None
        if not https:
            self._context: ssl.SSLContext | None = None
        elif ssl_context is not None:
            self._context = ssl_context
        elif tls is not None and not tls.is_empty:
            self._context = tls.create_ssl_context()
        else:
            self._context = ssl.create_default_context()

    @property
    def ssl_context(self) -> ssl.SSLContext | None:
        """The context https connections are made with; ``None`` for an http address."""
        return self._context

    def connect(self) -> http.client.HTTPConnection:
        """A new, not yet connected, connection to Vault."""
        if self._context is None:
            return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout_seconds)
        if self._server_name is not None:
            return _NamedHttpsConnection(self._host, self._port, self._timeout_seconds, self._context, self._server_name)
        return http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout_seconds, context=self._context)


class _NamedHttpsConnection(http.client.HTTPSConnection):
    # Verifies Vault's certificate against, and sends as SNI, server_name rather than the host.

    def __init__(self, host: str, port: int | None, timeout: float, context: ssl.SSLContext, server_name: str) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._vault_context = context
        self._server_name = server_name

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)
        self.sock = self._vault_context.wrap_socket(self.sock, server_hostname=self._server_name)


def put_request(connection: http.client.HTTPConnection, method: str, path: str, namespace: str | None) -> None:
    """Starts ``method`` ``path`` with the headers every Vault request carries: X-Vault-Request, and
    X-Vault-Namespace when ``namespace`` isn't ``None``."""
    connection.putrequest(method, path)
    connection.putheader(REQUEST_HEADER, "true")
    if namespace is not None:
        connection.putheader(NAMESPACE_HEADER, namespace)


def put_token(connection: http.client.HTTPConnection, token: memoryview) -> None:
    """Adds ``token`` as X-Vault-Token, as it is: checked printable ASCII, so nothing to escape.
    ``http.client`` copies it into the header line; zeroing ``token`` stays the caller's."""
    connection.putheader(TOKEN_HEADER, token)


def put_protected_token(connection: http.client.HTTPConnection, protector: DataProtector, protected_token: str) -> None:
    """Adds the token ``protected_token`` holds as X-Vault-Token, decrypted into a bytearray zeroed
    once ``http.client`` has copied it.

    :raises RuntimeError: see :func:`decrypt_token`
    """
    token, length = decrypt_token(protector, protected_token)
    try:
        with memoryview(token) as view, view[:length] as header:
            put_token(connection, header)
    finally:
        ArrayUtility.zero_memory(token)


def decrypt_token(protector: DataProtector, protected_token: str) -> tuple[bytearray, int]:
    """The token ``protected_token`` holds, decrypted into a bytearray the caller zeroes, and its
    length. Refused unless ``protector`` protected it - it parses, its key version is on the ring, and
    it authenticates under the protector's purpose - and it is a token. Raised outside the
    protector's exceptions, so nothing is chained: a parser handed an unprotected token could quote it.

    :raises RuntimeError: ``protected_token`` isn't protected by ``protector``, or isn't a token
    """
    token: bytearray | None = None
    length = -1
    try:
        max_length = protector.get_max_decrypted_length(protected_token)
        if max_length >= 0:
            token = bytearray(max_length)
            length = protector.decrypt(protected_token, token)
    except (ValueError, LookupError, CryptographicError):
        length = -1
    if token is None or length < 0:
        ArrayUtility.zero_memory(token)
        raise RuntimeError("The Vault token isn't protected by the token protector: hand over token_protector.encrypt(token), "
                           "never the token itself.")

    if not is_valid_token(memoryview(token)[:length]):
        ArrayUtility.zero_memory(token)
        raise RuntimeError("The protected Vault token isn't a token: printable ASCII, with no spaces.")
    return token, length


def with_retries[T](attempt: Callable[[], T], retry_count: int, base_delay: timedelta, *, stopped: Callable[[], bool] | None = None,
                    wait: Callable[[float], bool] | None = None) -> T:
    """``attempt``'s result, retrying it up to ``retry_count`` times while it fails transiently: a
    :class:`VaultRequestError` that :attr:`~VaultRequestError.is_transient`, or an ``OSError`` or
    ``http.client.HTTPException`` (no answer, a lost connection, a timeout). Vault's certificate
    being refused isn't retried - retrying can't change it - nor is anything else. Waits
    :func:`retry_delay` before each retry, with a random 0-100 ms. The last failure is raised as it is.

    :param stopped: checked before each wait; ``True`` raises the last failure (the caller closed)
    :param wait: waits the seconds given, returning ``True`` to give up and raise the last failure;
        ``None`` for ``time.sleep``
    """
    for retry in itertools.count():
        try:
            return attempt()
        except VaultRequestError as error:
            if not error.is_transient:
                raise
            failure: Exception = error
        except ssl.SSLCertVerificationError:
            raise
        except (OSError, http.client.HTTPException) as error:
            failure = error

        if retry >= retry_count or (stopped is not None and stopped()):
            raise failure
        seconds = retry_delay(base_delay, retry, secrets.randbelow(101)).total_seconds()
        if wait is None:
            time.sleep(seconds)
        elif wait(seconds):
            raise failure
    raise AssertionError("unreachable")  # pragma: no cover


def run_within[T](action: Callable[[], T], timeout: timedelta, *, thread_name: str, timeout_message: str,
                  abandoned: Callable[[T], None] | None = None) -> T:
    """``action``'s result, run on a daemon thread of its own and waited for at most ``timeout`` -
    for code the caller supplies (a token source or provider), which may block for as long as it
    likes. Its failure is re-raised as it is.

    :param abandoned: given the result of an action that returns after the wait was given up, on
        its thread, to dispose of (zero) it
    :raises TimeoutError: ``action`` didn't return within ``timeout``, with ``timeout_message``
    """
    done = threading.Event()
    lock = threading.Lock()
    given_up = False
    outcome: list[tuple[T | None, BaseException | None]] = []

    def run() -> None:
        try:
            result = action()
        except BaseException as error:  # re-raised on the waiting thread
            outcome.append((None, error))
            done.set()
            return
        with lock:
            late = given_up
            if not late:
                outcome.append((result, None))
        if late and abandoned is not None:
            abandoned(result)
        done.set()

    threading.Thread(target=run, name=thread_name, daemon=True).start()
    if not done.wait(timeout.total_seconds()):
        with lock:
            if not outcome:
                given_up = True
        if given_up:
            raise TimeoutError(timeout_message)
    result, error = outcome[0]
    if error is not None:
        raise error
    return result  # type: ignore[return-value]


def set_remaining(sock: socket.socket, deadline: float, timed_out: Callable[[], BaseException]) -> None:
    """Lets the next read or write on ``sock`` wait at most until ``deadline`` (``time.monotonic``);
    raises ``timed_out()`` if it has passed."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise timed_out()
    sock.settimeout(remaining)
