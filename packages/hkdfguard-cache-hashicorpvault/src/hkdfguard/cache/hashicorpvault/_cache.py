"""A protected read-only cache over the secrets in one HashiCorp Vault KV secrets engine."""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import ipaddress
import itertools
import logging
import re
import secrets
import socket
import ssl
import threading
import time
from datetime import timedelta
from types import TracebackType
from typing import ClassVar, Final, Self
from urllib.parse import urlsplit

from hkdfguard.abstractions import ArrayUtility, CryptographicError, DataProtector, KeyRing, ObjectClosedError
from hkdfguard.cache import ErrorResponseBody, RemoteSecretCache, SecretJsonBody, SecretNameMatching, SecretValueSink
from hkdfguard.cache.hashicorpvault._errors import VaultRequestError
from hkdfguard.cache.hashicorpvault._options import HashiCorpVaultSecretCacheOptions, VaultKvVersion
from hkdfguard.cache.hashicorpvault._token import VaultTokenProvider, is_valid_token

_TOKEN_HEADER: Final = "X-Vault-Token"  # noqa: S105 - a header name
_IPV4_LITERAL: Final = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_PATH_SEGMENT: Final = re.compile(r"[A-Za-z0-9._-]+")


class HashiCorpVaultSecretCache(RemoteSecretCache):
    """A protected read-only cache over the secrets in one HashiCorp Vault KV secrets engine. The
    first lookup of a name that isn't cached yet reads that one secret (GET on its path; for KV
    version 2, its latest version); fetching, encryption, caching and telemetry are
    :class:`RemoteSecretCache`'s. This class never lists secrets, so the token's policy needs only
    ``read`` on the paths it reads, never ``list``.

    A name is a secret's path within the engine, with the key to read after ``#``:
    ``"myapp/db#password"`` reads the password key of the secret at myapp/db, and ``"myapp/db"``
    reads its :attr:`~HashiCorpVaultSecretCacheOptions.default_key`. One read caches every key the
    secret holds, so the first lookup of any of them reads the secret once and the rest are already
    cached. A string is cached as its UTF-8 bytes; a number, true or false as its JSON text; a null,
    object or array value isn't cached. Paths are matched exactly, as Vault matches them, and so are
    keys. A path that isn't one - segments of ASCII letters, digits, ``-``, ``_`` and ``.``, no
    segment ``.`` or ``..``, at most :attr:`MAX_SECRET_NAME_LENGTH` characters, such as the
    configuration path ``ConnectionStrings:Admin`` - is reported missing without a call.

    A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
    deleted or destroyed, or that has no such key, or whose value there is empty or isn't cached, is
    reported missing. Any other answer (403 for a token that is invalid or not allowed to read the
    path, a 404 naming an error such as a mount that doesn't exist, a redirect, Vault sealed) raises
    :class:`VaultRequestError` carrying Vault's status and errors. A request that fails transiently -
    no answer, a connection lost mid-response, a timed-out attempt, 429 or a 5xx other than 501 - is
    first retried :attr:`~HashiCorpVaultSecretCacheOptions.retry_count` times (3-10), waiting
    :attr:`~HashiCorpVaultSecretCacheOptions.retry_delay` and doubling, up to 10 seconds, plus a
    random 0-100 ms each time so clients reconnecting together spread out. Once the retries are spent,
    a failure without an answer raises its ``OSError`` (``TimeoutError`` for a timed-out attempt), or
    the ``http.client.HTTPException`` of an answer that isn't HTTP.

    Authentication isn't the cache's: every fetch asks its :class:`VaultTokenProvider` for a token,
    once, so a provider can log in, renew and replace tokens however it likes. A provider's failure
    propagates as it is, and isn't retried; a provider that hasn't answered within the timeout fails
    the fetch with ``TimeoutError``. The token is handed over protected - encrypted by the cache's
    token protector, a protector on the key ring (``key_ring.create_protector(TOKEN_PURPOSE)``) - and
    a fetch given one that isn't fails with ``RuntimeError``, quoting and chaining nothing. It is
    decrypted only as each request is built, into a bytearray that is zeroed once the request's
    headers are sent; the token never becomes a ``str``. ``http.client`` copies each header into
    ``bytes`` of its own, though, which Python can't zero: each request's token is one such header
    line, referenced by nothing once it has been sent, which stays in memory until it is reused. So
    do the socket's and, over TLS, OpenSSL's buffers, which this class can't reach.

    Requests go to ``/v1/`` under Vault's address, which must be https except on loopback, through
    ``http.client``, on a connection of their own: no proxy, and no redirect is ever followed, which
    would carry the token elsewhere - Vault's standbys forward requests to the active node themselves,
    so a redirect is answered as an error. A fetch through decrypt or find_max_decrypted_length runs
    on the calling thread, blocking it until Vault answers or the
    :attr:`~HashiCorpVaultSecretCacheOptions.timeout` passes (per attempt, covering the connection,
    the response's headers and its whole body); through decrypt_async or
    find_max_decrypted_length_async it awaits the token provider's
    :meth:`~VaultTokenProvider.get_token_async` and makes the requests in a worker thread. Cancelling
    an asynchronous lookup that started the fetch abandons it: the provider's coroutine is cancelled,
    or the request's socket is shut down (on Windows, where that doesn't wake a blocked read, the
    request runs on to Vault's answer or the timeout) and no retry follows; nothing it reads is kept.

    The secret never becomes a ``str``. The response body is read straight off the socket into a
    bytearray of the library's own, and the value is unescaped into another and encrypted from there
    (:class:`SecretJsonBody`); every bytearray holding it is zeroed. What can't be zeroed is below
    that: the socket's and OpenSSL's buffers, and ``http.client``'s own for a chunked response.
    """

    MAX_SECRET_NAME_LENGTH: ClassVar[int] = 512
    """The longest secret path looked up."""

    TOKEN_PURPOSE: ClassVar[str] = "HkdfGuard.Cache.HashiCorpVault.Token"  # noqa: S105 - a protector name
    """The purpose to create the token protector with - ``key_ring.create_protector(TOKEN_PURPOSE)`` -
    so a token protected for the cache can't be decrypted as anything else, nor anything else as it."""

    def __init__(self, address: str, token_provider: VaultTokenProvider, token_protector: DataProtector, key_ring: KeyRing, *,
                 options: HashiCorpVaultSecretCacheOptions | None = None, logger: logging.Logger | None = None) -> None:
        """:param address: Vault's address, e.g. ``https://vault.example.com:8200`` - the same value
            as VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev
            server). A path, if any, is kept as a prefix (Vault behind a reverse proxy).
        :param token_provider: supplies the token every read is made with, protected by
            ``token_protector``
        :param token_protector: decrypts the token ``token_provider`` supplies: a protector on the key
            ring, ``key_ring.create_protector(TOKEN_PURPOSE)``
        :param key_ring: supplies the key every fetched secret is encrypted under; owned by the
            caller - the cache never closes keys
        :param options: the KV engine read and how to reach it; ``None`` for KV version 2 at
            ``secret``, reading the key ``value``
        :param logger: see :class:`RemoteSecretCache`
        :raises TypeError: ``address``, ``token_provider``, ``token_protector`` or ``key_ring`` is
            ``None``, or an option is of the wrong type
        :raises ValueError: ``address`` isn't https (or http on loopback), or holds credentials, a
            query or a fragment; or the mount path, default key or namespace isn't one; or the
            timeout isn't positive, the retry count isn't 3-10 or the retry delay isn't zero to 10
            seconds
        """
        if address is None:
            raise TypeError("address must not be None.")
        if token_provider is None:
            raise TypeError("token_provider must not be None.")
        if token_protector is None:
            raise TypeError("token_protector must not be None.")
        super().__init__(key_ring, SecretNameMatching.EXACT, logger)
        if options is None:
            options = HashiCorpVaultSecretCacheOptions()
        self._https, self._host, self._port, api_base = _api_base(address)
        _check(options)

        self._token_provider = token_provider
        self._token_protector = token_protector
        self._timeout = options.timeout
        self._timeout_seconds = options.timeout.total_seconds()
        self._retry_count = options.retry_count
        self._retry_delay = options.retry_delay
        self._namespace = options.namespace
        self._key = options.default_key
        if options.kv_version is VaultKvVersion.V2:
            self._read_base = f"{api_base}{options.mount_path}/data/"
            self._data_path: tuple[str, ...] = ("data", "data")
        else:
            self._read_base = f"{api_base}{options.mount_path}/"
            self._data_path = ("data",)
        self._ssl_context = (options.ssl_context or ssl.create_default_context()) if self._https else None
        self._closed = False

    @staticmethod
    def is_valid_secret_name(name: str | None) -> bool:
        """Whether ``name`` is a secret's path: ``/``-separated segments of ASCII letters, digits,
        ``-``, ``_`` and ``.``, no segment ``.`` or ``..``, at most :attr:`MAX_SECRET_NAME_LENGTH`
        characters. A key to read follows it in a lookup, after ``#`` (see
        :meth:`RemoteSecretCache.is_valid_key`)."""
        return name is not None and 0 < len(name) <= HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH and _is_valid_path(name)

    def close(self) -> None:
        """Stops the cache reading Vault. Cached secrets can still be read afterwards, but a lookup
        that would read Vault fails with :class:`~hkdfguard.abstractions.ObjectClosedError`. Every
        request has a connection of its own, closed as it completes, so there is nothing else to
        release."""
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def _default_key(self) -> str | None:
        return self._key

    def _is_valid_name(self, name: str) -> bool:
        return self.is_valid_secret_name(name)

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        self._ensure_open()
        # Asked for once per fetch; a provider's failure is its own to retry, so isn't retried here.
        self._read_with_retries(name, self._get_token(), value, _Abandon())

    async def _fetch_async(self, name: str, value: SecretValueSink) -> None:
        self._ensure_open()
        protected_token = await self._get_token_async()
        abandon = _Abandon()
        try:
            await asyncio.to_thread(self._read_with_retries, name, protected_token, value, abandon)
        except asyncio.CancelledError:
            # The thread can't be stopped, but its socket can be shut down, and it retries no more.
            abandon.abandon()
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise ObjectClosedError("This HashiCorp Vault secret cache has been closed.")

    def _get_token(self) -> str:
        # The protected token get_token returns, waited for within the timeout on a thread of its own.
        done = threading.Event()
        outcome: list[tuple[str | None, BaseException | None]] = []

        def run() -> None:
            try:
                outcome.append((self._token_provider.get_token(), None))
            except BaseException as error:  # re-raised on the fetching thread
                outcome.append((None, error))
            finally:
                done.set()

        threading.Thread(target=run, name="hkdfguard-vault-token", daemon=True).start()
        if not done.wait(self._timeout_seconds):
            raise TimeoutError(f"The Vault token provider returned no token within {self._timeout}.")
        token, error = outcome[0]
        if error is not None:
            raise error
        return _require_token(token)

    async def _get_token_async(self) -> str:
        # The protected token get_token_async returns, cancelled once the timeout passes.
        try:
            async with asyncio.timeout(self._timeout_seconds) as deadline:
                token = await self._token_provider.get_token_async()
        except TimeoutError:
            if not deadline.expired():
                raise
            expired = True
        else:
            expired = False
        if expired:
            raise TimeoutError(f"The Vault token provider returned no token within {self._timeout}.")
        return _require_token(token)

    def _read_with_retries(self, path: str, protected_token: str, value: SecretValueSink, abandon: _Abandon) -> None:
        failure: Exception
        for retry in itertools.count():
            try:
                self._read(path, protected_token, value, abandon)
                return
            except VaultRequestError as error:
                if not error.is_transient:
                    raise
                failure = error
            except (OSError, http.client.HTTPException) as error:
                failure = error

            if abandon.abandoned or retry >= self._retry_count or self._closed:
                raise failure

            # A failed attempt has handed nothing to value: the body is read whole before anything is
            # parsed out of it, and a parse failure isn't transient.
            if abandon.wait(_retry_delay(self._retry_delay, retry, secrets.randbelow(101)).total_seconds()):
                raise failure

    def _read(self, path: str, protected_token: str, value: SecretValueSink, abandon: _Abandon) -> None:
        # One attempt: one request, and Vault's whole response, within the attempt's timeout.
        deadline = time.monotonic() + self._timeout_seconds
        connection = (http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout_seconds, context=self._ssl_context)
                      if self._https else http.client.HTTPConnection(self._host, self._port, timeout=self._timeout_seconds))
        try:
            self._send(connection, path, protected_token)
            sock = connection.sock
            if sock is None:
                raise ConnectionError("The connection to Vault was closed before its answer.")
            abandon.track(sock)
            _set_remaining(sock, deadline, path, self._timeout)
            response = connection.getresponse()
            try:
                body = _DeadlineBody(response, sock, deadline, abandon, path, self._timeout)
                self._read_response(path, response.status, body, value)
            finally:
                response.close()
        finally:
            abandon.track(None)
            connection.close()

    def _send(self, connection: http.client.HTTPConnection, path: str, protected_token: str) -> None:
        # Sends the request for path's secret, with the token protected_token holds - decrypted into a
        # bytearray zeroed once http.client has copied it.
        token, length = self._decrypt_token(protected_token)
        try:
            connection.putrequest("GET", self._read_base + path)
            connection.putheader("X-Vault-Request", "true")
            if self._namespace is not None:
                connection.putheader("X-Vault-Namespace", self._namespace)
            with memoryview(token) as view, view[:length] as header:
                connection.putheader(_TOKEN_HEADER, header)
            connection.endheaders()
        finally:
            ArrayUtility.zero_memory(token)

    def _read_response(self, path: str, status: int, body: _DeadlineBody, value: SecretValueSink) -> None:
        if 200 <= status < 300:
            SecretJsonBody.capture_keys(body, value, self._data_path)
            return

        errors = ErrorResponseBody.read_strings(body, "errors")

        # Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        # secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        # (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
        if status == 404 and errors == []:
            return

        detail = ": " + "; ".join(errors) if errors else ""
        raise VaultRequestError(f"Vault refused to read '{path}': HTTP {status}{detail}", status)

    def _decrypt_token(self, protected_token: str) -> tuple[bytearray, int]:
        # The token protected_token holds, decrypted into a bytearray the caller zeroes, and its
        # length. Refused unless it is protected by the token protector - it parses, its key version
        # is on the ring, and it authenticates under TOKEN_PURPOSE - and is a token. Raised outside
        # the protector's exceptions, so nothing is chained: a parser handed an unprotected token
        # could quote it.
        token: bytearray | None = None
        length = -1
        try:
            max_length = self._token_protector.get_max_decrypted_length(protected_token)
            if max_length >= 0:
                token = bytearray(max_length)
                length = self._token_protector.decrypt(protected_token, token)
        except (ValueError, LookupError, CryptographicError):
            length = -1
        if token is None or length < 0:
            ArrayUtility.zero_memory(token)
            raise _not_protected()

        if not is_valid_token(memoryview(token)[:length]):
            ArrayUtility.zero_memory(token)
            raise RuntimeError("The protected Vault token isn't a token: printable ASCII, with no spaces.")
        return token, length


class _Abandon:
    """Abandons a fetch whose asynchronous lookup was cancelled: shuts down the socket of the
    request in flight, and stops the waits between retries."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None

    @property
    def abandoned(self) -> bool:
        return self._event.is_set()

    def wait(self, seconds: float) -> bool:
        return self._event.wait(seconds)

    def track(self, sock: socket.socket | None) -> None:
        # The socket of the request in flight, if any; raises if the fetch was abandoned meanwhile.
        with self._lock:
            self._sock = sock
        if sock is not None and self.abandoned:
            raise _abandoned()

    def abandon(self) -> None:
        self._event.set()
        with self._lock:
            sock = self._sock
            if sock is not None:
                # Already closed, the read it would end fails anyway.
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)


class _DeadlineBody:
    """A response body read within the attempt's deadline: each read waits at most the time left,
    and a body shorter than its Content-Length is a lost connection, not the end."""

    def __init__(self, response: http.client.HTTPResponse, sock: socket.socket, deadline: float, abandon: _Abandon, path: str,  # noqa: PLR0917 - private
                 timeout: timedelta) -> None:
        self._response = response
        self._sock = sock
        self._deadline = deadline
        self._abandon = abandon
        self._path = path
        self._timeout = timeout
        self._expected = response.length
        self._read = 0

    def readinto(self, buffer: memoryview, /) -> int:
        if self._response.isclosed():
            # Read to its end: http.client has closed the socket.
            return 0
        _set_remaining(self._sock, self._deadline, self._path, self._timeout)
        lost = False
        timed_out = False
        read = 0
        try:
            read = self._response.readinto(buffer)
        except http.client.IncompleteRead:
            # Its partial bytes may hold the secret: neither kept nor chained.
            lost = True
        except TimeoutError:
            timed_out = True
        if self._abandon.abandoned:
            raise _abandoned()
        if timed_out:
            raise _timed_out(self._path, self._timeout)
        if lost or (read == 0 and len(buffer) > 0 and self._expected is not None and self._read < self._expected):
            raise ConnectionError(f"The connection was lost during Vault's response to the read of '{self._path}'.")
        self._read += read
        return read


def _require_token(token: object) -> str:
    if not isinstance(token, str) or not token:
        raise RuntimeError("The Vault token provider returned no token.")
    return token


def _set_remaining(sock: socket.socket, deadline: float, path: str, timeout: timedelta) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _timed_out(path, timeout)
    sock.settimeout(remaining)


def _timed_out(path: str, timeout: timedelta) -> TimeoutError:
    return TimeoutError(f"Vault's response to the read of '{path}' took longer than {timeout}.")


def _abandoned() -> ConnectionAbortedError:
    return ConnectionAbortedError("The read from Vault was abandoned: the lookup that started it was cancelled.")


def _not_protected() -> RuntimeError:
    return RuntimeError("The Vault token provider returned a token that isn't protected by the cache's token protector: "
                        "hand over token_protector.encrypt(token), never the token itself.")


def _retry_delay(base_delay: timedelta, retry: int, jitter_millis: int) -> timedelta:
    """The wait before retry number ``retry`` (0 for the first): ``base_delay``, doubled for each
    retry before it, at most :attr:`HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY` - plus
    ``jitter_millis``."""
    maximum = HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY
    backoff = maximum if retry >= 30 else base_delay * (1 << retry)
    return min(backoff, maximum) + timedelta(milliseconds=jitter_millis)


def _check(options: HashiCorpVaultSecretCacheOptions) -> None:
    limits = HashiCorpVaultSecretCacheOptions
    if not isinstance(options, HashiCorpVaultSecretCacheOptions):
        raise TypeError("options must be HashiCorpVaultSecretCacheOptions.")
    if not isinstance(options.kv_version, VaultKvVersion):
        raise TypeError("kv_version must be a VaultKvVersion.")
    if not isinstance(options.timeout, timedelta) or not isinstance(options.retry_delay, timedelta):
        raise TypeError("timeout and retry_delay must be timedeltas.")
    if not isinstance(options.retry_count, int) or isinstance(options.retry_count, bool):
        raise TypeError("retry_count must be an int.")
    if options.ssl_context is not None and not isinstance(options.ssl_context, ssl.SSLContext):
        raise TypeError("ssl_context must be an ssl.SSLContext.")
    if not _is_valid_path(options.mount_path):
        raise ValueError(f"The mount path '{options.mount_path}' isn't a Vault path.")
    if not RemoteSecretCache.is_valid_key(options.default_key):
        raise ValueError(f"The default key '{options.default_key}' isn't a key: 1-{RemoteSecretCache.MAX_KEY_LENGTH} printable ASCII "
                         "characters other than space, '!' and '#'.")
    if options.namespace is not None and not _is_valid_path(options.namespace):
        raise ValueError(f"The namespace '{options.namespace}' isn't a Vault path.")
    if options.timeout <= timedelta(0):
        raise ValueError(f"The timeout must be positive; it is {options.timeout}.")
    if not limits.MIN_RETRY_COUNT <= options.retry_count <= limits.MAX_RETRY_COUNT:
        raise ValueError(f"The retry count must be {limits.MIN_RETRY_COUNT}-{limits.MAX_RETRY_COUNT}; it is {options.retry_count}.")
    if not timedelta(0) <= options.retry_delay <= limits.MAX_RETRY_DELAY:
        raise ValueError(f"The retry delay must be zero to {limits.MAX_RETRY_DELAY}; it is {options.retry_delay}.")


def _api_base(address: str) -> tuple[bool, str, int | None, str]:
    # Whether Vault's address is https, its host and port, and the path of /v1/ under it - refusing an
    # address that would send tokens in the clear (http anywhere but loopback) or that carries
    # credentials, a query or a fragment.
    if not isinstance(address, str):
        raise TypeError("address must be a str.")
    parts = urlsplit(address)
    host = parts.hostname
    if not parts.scheme or not parts.netloc or not host:
        raise ValueError(f"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.")

    scheme = parts.scheme.lower()
    if scheme != "https" and not (scheme == "http" and _is_loopback(host, parts.netloc)):
        raise ValueError(f"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or "
                         "dev server), since every request carries a token.")
    if "@" in parts.netloc or "?" in address or "#" in address:
        raise ValueError(f"Vault's address '{address}' must not hold credentials, a query or a fragment.")

    return scheme == "https", host, parts.port, parts.path.rstrip("/") + "/v1/"


def _is_loopback(host: str, netloc: str) -> bool:
    # localhost, or an IP literal on the loopback network. Only literals are parsed, so no name is
    # ever resolved.
    if host.lower() == "localhost":
        return True
    if not netloc.rsplit("@", maxsplit=1)[-1].startswith("[") and not _IPV4_LITERAL.fullmatch(host):
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_valid_path(path: object) -> bool:
    # '/'-separated segments, none empty, "." or "..": a path that stays where it's put.
    return isinstance(path, str) and all(_PATH_SEGMENT.fullmatch(segment) and segment not in {".", ".."} for segment in path.split("/"))
