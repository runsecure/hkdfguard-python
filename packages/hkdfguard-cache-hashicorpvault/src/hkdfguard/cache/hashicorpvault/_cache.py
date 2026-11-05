"""A protected read-only cache over the secrets in one HashiCorp Vault KV secrets engine."""

from __future__ import annotations

import asyncio
import logging
from types import TracebackType
from typing import ClassVar, Self

from hkdfguard.abstractions import DataProtector, KeyRing, ObjectClosedError
from hkdfguard.cache import RemoteSecretCache, SecretJsonBody, SecretNameMatching, SecretValueSink
from hkdfguard.cache.hashicorpvault._options import HashiCorpVaultSecretCacheOptions, VaultKvVersion
from hkdfguard.integration.hashicorpvault import (
    VaultRequestError,
    VaultTokenProvider,
    api_base,
    check_connection_options,
    is_valid_path,
)
from hkdfguard.integration.hashicorpvault._errors import MAX_ERROR_BODY_LENGTH, describe_status, read_errors
from hkdfguard.integration.hashicorpvault._http import Abandon, DeadlineBody, VaultConnector, exchange, put_protected_token, read_body, with_retries
from hkdfguard.integration.hashicorpvault._token_provider import get_token_within, get_token_within_async


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
        https, host, port, v1_path = api_base(address)
        _check(options)

        self._token_provider = token_provider
        self._token_protector = token_protector
        self._timeout = options.timeout
        self._retry_count = options.retry_count
        self._retry_delay = options.retry_delay
        self._namespace = options.namespace
        self._key = options.default_key
        if options.kv_version is VaultKvVersion.V2:
            self._read_base = f"{v1_path}{options.mount_path}/data/"
            self._data_path: tuple[str, ...] = ("data", "data")
        else:
            self._read_base = f"{v1_path}{options.mount_path}/"
            self._data_path = ("data",)
        self._connector = VaultConnector(https, host, port, options.timeout, options.ssl_context, options.tls)
        self._closed = False

    @staticmethod
    def is_valid_secret_name(name: str | None) -> bool:
        """Whether ``name`` is a secret's path: ``/``-separated segments of ASCII letters, digits,
        ``-``, ``_`` and ``.``, no segment ``.`` or ``..``, at most :attr:`MAX_SECRET_NAME_LENGTH`
        characters. A key to read follows it in a lookup, after ``#`` (see
        :meth:`RemoteSecretCache.is_valid_key`)."""
        return name is not None and 0 < len(name) <= HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH and is_valid_path(name)

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
        self._read_with_retries(name, get_token_within(self._token_provider, self._timeout), value, _abandon())

    async def _fetch_async(self, name: str, value: SecretValueSink) -> None:
        self._ensure_open()
        protected_token = await get_token_within_async(self._token_provider, self._timeout)
        abandon = _abandon()
        try:
            await asyncio.to_thread(self._read_with_retries, name, protected_token, value, abandon)
        except asyncio.CancelledError:
            # The thread can't be stopped, but its socket can be shut down, and it retries no more.
            abandon.abandon()
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise ObjectClosedError("This HashiCorp Vault secret cache has been closed.")

    def _read_with_retries(self, path: str, protected_token: str, value: SecretValueSink, abandon: Abandon) -> None:
        # A failed attempt has handed nothing to value: the body is read whole before anything is
        # parsed out of it, and a parse failure isn't transient.
        with_retries(lambda: self._read(path, protected_token, value, abandon), self._retry_count, self._retry_delay,
                     stopped=lambda: abandon.abandoned or self._closed, wait=abandon.wait)

    def _read(self, path: str, protected_token: str, value: SecretValueSink, abandon: Abandon) -> None:
        # One attempt: one request, with the token protected_token holds - decrypted into a bytearray
        # zeroed once http.client has copied it - and Vault's whole response, within the attempt's
        # timeout. A token that isn't protected by the token protector, or isn't a token, raises
        # RuntimeError.
        with exchange(self._connector, "GET", self._read_base + path, self._namespace, self._timeout,
                      headers=lambda connection: put_protected_token(connection, self._token_protector, protected_token),
                      abandon=abandon, description=f"the read of '{path}'") as (status, body):
            self._read_response(path, status, body, value)

    def _read_response(self, path: str, status: int, body: DeadlineBody, value: SecretValueSink) -> None:
        if 200 <= status < 300:
            SecretJsonBody.capture_keys(body, value, self._data_path)
            return

        # A refusal holds no secret: read whole, up to the limit, and its errors made str.
        buffer = bytearray(MAX_ERROR_BODY_LENGTH)
        errors = read_errors(memoryview(buffer)[:read_body(body, buffer)])

        # Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        # secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        # (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
        if status == 404 and errors == []:
            return

        raise VaultRequestError(f"Vault refused to read '{path}': {describe_status(status, errors)}", status)


def _abandon() -> Abandon:
    return Abandon("The read from Vault was abandoned: the lookup that started it was cancelled.")


def _check(options: HashiCorpVaultSecretCacheOptions) -> None:
    if not isinstance(options, HashiCorpVaultSecretCacheOptions):
        raise TypeError("options must be HashiCorpVaultSecretCacheOptions.")
    if not isinstance(options.kv_version, VaultKvVersion):
        raise TypeError("kv_version must be a VaultKvVersion.")
    check_connection_options(options)
    if not RemoteSecretCache.is_valid_key(options.default_key):
        raise ValueError(f"The default key '{options.default_key}' isn't a key: 1-{RemoteSecretCache.MAX_KEY_LENGTH} printable ASCII "
                         "characters other than space, '!' and '#'.")
