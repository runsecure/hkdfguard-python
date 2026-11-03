"""What the Vault integrations share to make a request: the connection, the headers every request
carries, the token's header, one attempt within its deadline and its body read within it, the
retries, abandoning a cancelled request, and running a caller's code within a timeout."""

from __future__ import annotations

import contextlib
import http.client
import itertools
import secrets
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from datetime import timedelta
from typing import Final, Protocol

from hkdfguard.abstractions import ArrayUtility, CryptographicError, DataProtector
from hkdfguard.integration.hashicorpvault._connection import TOKEN_HEADER, is_valid_token, retry_delay
from hkdfguard.integration.hashicorpvault._errors import VaultRequestError
from hkdfguard.integration.hashicorpvault._tls import VaultTlsOptions, check_tls_options

REQUEST_HEADER: Final = "X-Vault-Request"
"""Marks every request as Vault's own clients do, so Vault answers an unauthenticated one 403 rather
than redirecting it to the UI."""

NAMESPACE_HEADER: Final = "X-Vault-Namespace"
"""The header a request's Vault Enterprise namespace is sent in."""


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
    """Lets the next read or write on ``sock`` wait at most until ``deadline`` (``time.monotonic``;
    infinity for no deadline); raises ``timed_out()`` if it has passed."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise timed_out()
    sock.settimeout(None if remaining == float("inf") else remaining)


class Abandon:
    """Abandons a request whose asynchronous call was cancelled: shuts down the socket of the request
    in flight, so a read blocked on it ends, and stops the waits between retries. Shared by the
    threads of one call: the one making the request, and the one cancelling it."""

    __slots__ = ("_event", "_lock", "_message", "_sock")

    def __init__(self, message: str) -> None:
        """:param message: what :meth:`error` says, naming what was cancelled"""
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._message = message

    @property
    def abandoned(self) -> bool:
        """Whether :meth:`abandon` has been called."""
        return self._event.is_set()

    def error(self) -> ConnectionAbortedError:
        """The error an abandoned request fails with."""
        return ConnectionAbortedError(self._message)

    def wait(self, seconds: float) -> bool:
        """Waits ``seconds``, or until the request is abandoned; ``True`` if it was."""
        return self._event.wait(seconds)

    def track(self, sock: socket.socket | None) -> None:
        """The socket of the request in flight, if any. Raises :meth:`error` if the request was
        abandoned meanwhile."""
        with self._lock:
            self._sock = sock
        if sock is not None and self.abandoned:
            raise self.error()

    def abandon(self) -> None:
        """Abandons the request: no retry follows, and the socket in flight is shut down."""
        self._event.set()
        with self._lock:
            sock = self._sock
            if sock is not None:
                # Already closed, the read it would end fails anyway.
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)


class Readable(Protocol):
    """A response body, read as a buffered stream is: ``readinto`` returns 0 at its end."""

    def readinto(self, buffer: memoryview, /) -> int: ...


class DeadlineBody:
    """A response body read within the attempt's deadline: each read waits at most the time left,
    and a body shorter than its Content-Length is a lost connection, not the end. Its bytes go only
    into the buffers it is given - never kept, nor quoted in an error - so it can be read straight
    into a bytearray that is zeroed."""

    __slots__ = ("_abandon", "_deadline", "_expected", "_lost_message", "_read", "_response", "_sock", "_timed_out")

    def __init__(self, response: http.client.HTTPResponse, sock: socket.socket, deadline: float, timed_out: Callable[[], BaseException], *,
                 lost_message: str, abandon: Abandon | None = None) -> None:
        """:param sock: the socket the response arrives on (``http.client`` drops its connection's
            reference once a response that closes it is read, so it is taken before)
        :param deadline: when the attempt's time is up (``time.monotonic``; infinity for no deadline)
        :param timed_out: the error a read that would pass the deadline raises
        :param lost_message: the ``ConnectionError``'s message for a connection lost mid-body
        :param abandon: the call's :class:`Abandon`; a read once it is abandoned raises its error
        """
        self._response = response
        self._sock = sock
        self._deadline = deadline
        self._timed_out = timed_out
        self._lost_message = lost_message
        self._abandon = abandon
        self._expected = response.length
        self._read = 0

    def readinto(self, buffer: memoryview, /) -> int:
        """Reads what has arrived of the body into ``buffer``; 0 at its end.

        :raises ConnectionError: the connection was lost before the body's end
        :raises ConnectionAbortedError: the call was abandoned
        :raises OSError: reading failed otherwise
        """
        if self._response.isclosed():
            # Read to its end: http.client has closed the socket.
            return 0
        set_remaining(self._sock, self._deadline, self._timed_out)
        lost = False
        timed_out = False
        read = 0
        try:
            read = self._response.readinto(buffer)
        except http.client.IncompleteRead:
            # Its partial bytes may hold a secret: neither kept nor chained.
            lost = True
        except TimeoutError:
            timed_out = True
        except OSError:
            if self._abandon is not None and self._abandon.abandoned:
                raise self._abandon.error() from None
            raise
        if self._abandon is not None and self._abandon.abandoned:
            raise self._abandon.error()
        if timed_out:
            raise self._timed_out()
        if lost or (read == 0 and len(buffer) > 0 and self._expected is not None and self._read < self._expected):
            raise ConnectionError(self._lost_message)
        self._read += read
        return read


def read_body(body: Readable, buffer: bytearray) -> int:
    """Reads ``body`` into ``buffer`` until it ends or ``buffer`` is full, and returns how much it
    read. Give ``buffer`` a byte more than the most that may be read, to tell a body that doesn't fit
    from one that just fits."""
    length = 0
    with memoryview(buffer) as view:
        while length < len(buffer):
            with view[length:] as rest:
                read = body.readinto(rest)
            if not read:
                break
            length += read
    return length


@contextlib.contextmanager
def exchange(connector: VaultConnector, method: str, path: str, namespace: str | None, timeout: timedelta, *,
             headers: Callable[[http.client.HTTPConnection], None] | None = None, body: memoryview | None = None,
             abandon: Abandon | None = None, description: str | None = None) -> Iterator[tuple[int, DeadlineBody]]:
    """One attempt, within ``timeout``: a connection of its own, the request - with the headers every
    Vault request carries (:func:`put_request`), those ``headers`` adds (the token, a body's), and
    ``body`` - and Vault's status and body (a :class:`DeadlineBody`), both closed as the block exits.

    :param abandon: the call's :class:`Abandon`, given the socket in flight
    :param description: what the request is, e.g. ``"the read of 'myapp/db'"``, for the errors of
        one that times out or loses its connection
    :raises TimeoutError: the attempt took longer than ``timeout``
    :raises ConnectionError: the connection was lost
    :raises OSError: or ``http.client.HTTPException``: Vault couldn't be reached, or answered with
        something that isn't HTTP
    """
    deadline = time.monotonic() + timeout.total_seconds()
    to = f" to {description}" if description else ""

    def timed_out() -> TimeoutError:
        return TimeoutError(f"Vault's response{to} took longer than {timeout}.")

    connection = connector.connect()
    try:
        put_request(connection, method, path, namespace)
        if headers is not None:
            headers(connection)
        # Sent from body itself, not a copy: http.client hands a buffer straight to the socket.
        connection.endheaders(body)
        sock = connection.sock
        if sock is None:
            raise ConnectionError("The connection to Vault was closed before its answer.")
        if abandon is not None:
            abandon.track(sock)
        set_remaining(sock, deadline, timed_out)
        response = connection.getresponse()
        try:
            yield response.status, DeadlineBody(response, sock, deadline, timed_out, lost_message=f"The connection was lost during Vault's response{to}.",
                                                abandon=abandon)
        finally:
            response.close()
    finally:
        if abandon is not None:
            abandon.track(None)
        connection.close()
