"""The Vault client: a port of vault-client-go."""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import dataclasses
import http.client
import importlib.metadata
import ipaddress
import logging
import platform
import re
import socket
import ssl
import threading
import time
from collections.abc import Buffer, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from types import TracebackType
from typing import Any, ClassVar, Final, Protocol, Self, overload
from urllib.parse import urljoin, urlsplit

from hkdfguard.abstractions import ArrayUtility, DataProtector
from hkdfguard.integration.hashicorpvault._duration import format_go_duration
from hkdfguard.integration.hashicorpvault._errors import VaultRedirectError, VaultRequestError
from hkdfguard.integration.hashicorpvault._generated import VaultApis
from hkdfguard.integration.hashicorpvault._http import NAMESPACE_HEADER, REQUEST_HEADER, VaultConnector, check_tls_options, decrypt_token, put_token
from hkdfguard.integration.hashicorpvault._json import JsonValue, JsonWriter, SecureBuffer
from hkdfguard.integration.hashicorpvault._options import (
    VaultClientOptions,
    VaultRequest,
    VaultRequestCallback,
    VaultRequestOptions,
    VaultResponseCallback,
    check_mfa_credentials,
    copy_headers,
    is_valid_namespace,
    merge_headers,
)
from hkdfguard.integration.hashicorpvault._replication import INDEX_HEADER, ReplicationForwardingMode, ReplicationStateCache
from hkdfguard.integration.hashicorpvault._response import VaultRawResponse, VaultResponse, read_response, reason_phrase, response_error
from hkdfguard.integration.hashicorpvault._retry import default_retry_policy, linear_jitter_backoff
from hkdfguard.integration.hashicorpvault._token_provider import StaticVaultToken, VaultTokenProvider

_HEALTH_PATH: Final = "/v1/sys/health"
_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.integration.hashicorpvault")
_IPV4_LITERAL: Final = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_UNRESERVED: Final = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")

type Query = builtins.list[tuple[str, str]]
type JsonDict = dict[str, JsonValue]


class _Readable(Protocol):
    def readinto(self, buffer: memoryview, /) -> int | None: ...


def _user_agent(version: str, os_name: str, architecture: str, runtime: str) -> str:
    # library/version (OS; architecture; runtime), as vault-client-go's - only what a header can carry.
    agent = f"hkdfguard-integration-hashicorpvault/{version or '0.0.0'} ({os_name.strip()}; {architecture}; Python {runtime})"
    return "".join(c if " " <= c <= "~" else " " for c in agent)


def _version() -> str:
    try:
        return importlib.metadata.version("hkdfguard-integration-hashicorpvault")
    except importlib.metadata.PackageNotFoundError:
        return ""


USER_AGENT: Final = _user_agent(_version(), f"{platform.system()} {platform.release()}", platform.machine(), platform.python_version())
"""The User-Agent every request carries."""


@dataclass(frozen=True, slots=True)
class _Modifiers:
    # The headers and callbacks a client adds to every request. Immutable: the client swaps in a new
    # one when a setting changes, so a request in flight keeps the settings it started with.
    token: VaultTokenProvider | None = None
    namespace: str | None = None
    mfa_credentials: tuple[str, ...] = ()
    response_wrapping_ttl: timedelta = timedelta(0)
    replication_forwarding_mode: ReplicationForwardingMode = ReplicationForwardingMode.NONE
    custom_headers: Mapping[str, tuple[str, ...]] = dataclasses.field(default_factory=dict)
    request_callbacks: tuple[VaultRequestCallback, ...] = ()
    response_callbacks: tuple[VaultResponseCallback, ...] = ()

    def merge(self, options: VaultRequestOptions | None) -> _Modifiers:
        # These with options' over them: options' single values win, its sequences are appended, and
        # its headers replace these headers of the same name.
        if options is None:
            return self
        if not isinstance(options, VaultRequestOptions):
            raise TypeError("options must be VaultRequestOptions.")
        ns = options.namespace
        if ns and not is_valid_namespace(ns):
            raise ValueError(f"The namespace '{ns}' contains non-printable characters.")
        check_mfa_credentials(options.mfa_credentials)
        headers = copy_headers(options.custom_headers)
        ttl = options.response_wrapping_ttl
        if ttl is not None and ttl < timedelta(0):
            raise ValueError(f"The wrapping TTL must not be negative; it is {ttl}.")
        return _Modifiers(
            options.token if options.token is not None else self.token,
            ns or self.namespace,
            self.mfa_credentials + tuple(options.mfa_credentials),
            ttl if ttl else self.response_wrapping_ttl,
            options.replication_forwarding_mode if options.replication_forwarding_mode is not ReplicationForwardingMode.NONE
            else self.replication_forwarding_mode,
            merge_headers(self.custom_headers, headers) if headers else self.custom_headers,
            self.request_callbacks + tuple(options.request_callbacks),
            self.response_callbacks + tuple(options.response_callbacks))


class _DeadlineExceededError(Exception):
    # The request's deadline passed: it fails with a TimeoutError naming it.
    pass


class _Abandon:
    """Abandons a request whose asynchronous call was cancelled: shuts down the socket in flight,
    and stops the waits between retries."""

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
        with self._lock:
            self._sock = sock
        if sock is not None and self.abandoned:
            raise _abandoned()

    def abandon(self) -> None:
        self._event.set()
        with self._lock:
            sock = self._sock
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)


@dataclass(slots=True)
class _Target:
    # Where a request goes: scheme, host and port, and the path with its query.
    https: bool
    host: str
    port: int | None
    path: str

    @property
    def url(self) -> str:
        netloc = f"[{self.host}]" if ":" in self.host else self.host
        return f"{'https' if self.https else 'http'}://{netloc}{'' if self.port is None else f':{self.port}'}{self.path}"


@dataclass(slots=True)
class _Sent:
    request: VaultRequest
    connection: http.client.HTTPConnection
    response: http.client.HTTPResponse


class VaultClient(VaultApis):
    """A HashiCorp Vault client: a port of vault-client-go. The generic :meth:`read`, :meth:`write`,
    :meth:`list` and :meth:`delete` reach any path; the methods generated from Vault's OpenAPI spec
    reach the endpoints generator.json names, typed, grouped as :attr:`auth`, :attr:`secrets` and
    :attr:`system`.

    Tokens are held only protected - encrypted by the client's token protector, a protector on a key
    ring (``key_ring.create_protector(TOKEN_PURPOSE)``) - and supplied by a
    :class:`VaultTokenProvider`. A token is decrypted only as a request is sent, into a bytearray
    zeroed once http.client has copied it into the request. A token Vault returns (a login's, a
    wrapping token) is protected as the response is read, a ``str`` only for the protector's call.
    Request and response bodies are held in bytearrays that are zeroed after use; what a generated
    model holds, though, is ordinary ``str``.

    Defaults are stricter than vault-client-go's: Vault's address must be https except on loopback,
    and redirects - which would carry the token wherever they point - fail with
    :class:`VaultRedirectError` unless :attr:`VaultClientOptions.follow_redirects` is set. Failures
    are retried as vault-client-go retries them (:class:`VaultRetryOptions`).

    Every method blocks the calling thread until Vault answers; each has an ``_async`` counterpart
    that runs the request on a thread of its own, so the event loop isn't blocked, and abandons it -
    shutting its connection down - if the awaiting task is cancelled. A request fails with
    :class:`VaultResponseError` when Vault refuses it, with :class:`VaultRedirectError` for a
    redirect it won't follow, with the ``OSError`` (or ``http.client.HTTPException``) the connection
    raised when Vault can't be reached, with ``TimeoutError`` when it outlives
    :attr:`VaultClientOptions.request_timeout`, and with :class:`VaultJsonError` when the answer isn't
    the JSON expected.

    Thread-safe. Settings changed with the set and clear methods apply to requests started
    afterwards. Each attempt opens a connection of its own, closed once it is answered.
    """

    TOKEN_PURPOSE: ClassVar[str] = "HkdfGuard.Integration.HashiCorpVault.Token"  # noqa: S105 - a protector name
    """The purpose to create the token protector with - ``key_ring.create_protector(TOKEN_PURPOSE)`` -
    so a token protected for the client can't be decrypted as anything else, nor anything else as it."""

    def __init__(self, token_protector: DataProtector, options: VaultClientOptions | None = None, logger: logging.Logger | None = None) -> None:
        """:param token_protector: protects and decrypts tokens: a protector on the key ring,
            ``key_ring.create_protector(TOKEN_PURPOSE)``. Every token the client is given must be
            protected by it.
        :param options: how to reach Vault; ``None`` for the defaults (https://127.0.0.1:8200)
        :param logger: where retries and followed redirects are logged (paths only, never a query);
            ``None`` for the ``hkdfguard.integration.hashicorpvault`` logger
        :raises TypeError: ``token_protector`` is ``None``, or an option is of the wrong type
        :raises ValueError: the address isn't https (or http on loopback, or with
            allow_unencrypted_http), or holds credentials, a query or a fragment; the namespace can't
            be sent; the request timeout or a retry wait is negative; both ``ssl_context`` and
            ``tls`` are given; or a certificate can't be read
        """
        if token_protector is None:
            raise TypeError("token_protector must not be None.")
        if options is None:
            options = VaultClientOptions()
        if not isinstance(options, VaultClientOptions):
            raise TypeError("options must be VaultClientOptions.")
        self._https, self._host, self._port, self._prefix = _base_address(options)
        if not isinstance(options.request_timeout, timedelta) or options.request_timeout < timedelta(0):
            raise ValueError(f"The request timeout must not be negative; it is {options.request_timeout}.")
        if options.retry.retry_wait_min < timedelta(0) or options.retry.retry_wait_max < timedelta(0):
            raise ValueError("The retry waits must not be negative.")
        ns = options.namespace
        if ns and not is_valid_namespace(ns):
            raise ValueError(f"The namespace '{ns}' contains non-printable characters.")
        check_tls_options(options.ssl_context, options.tls)
        # The TLS settings read once, here: a certificate that can't be read fails the constructor.
        self._connector = VaultConnector(self._https, self._host, self._port, options.request_timeout, options.ssl_context, options.tls)

        self._options = options
        self._token_protector = token_protector
        self._logger = logger if logger is not None else _DEFAULT_LOGGER
        self._closed = [False]
        self._owner = True
        retry = options.retry
        self._check_retry = retry.check_retry if retry.check_retry is not None else default_retry_policy
        self._backoff = retry.backoff if retry.backoff is not None else linear_jitter_backoff
        self._replication_states = ReplicationStateCache() if options.enforce_read_your_writes_consistency else None
        self._modifiers_lock = threading.Lock()
        self._modifiers = _Modifiers(options.token, ns or None)

    @property
    def options(self) -> VaultClientOptions:
        """The options the client was created with."""
        return self._options

    def copy(self) -> VaultClient:
        """A client with this one's options, settings (token, namespace, headers, callbacks...) and
        replication states, which then change independently. Closing it does nothing, and it can't
        be used once this client is closed."""
        copied = object.__new__(VaultClient)
        copied.__dict__.update(self.__dict__)
        copied._owner = False
        copied._modifiers_lock = threading.Lock()
        copied._replication_states = None if self._replication_states is None else self._replication_states.copy()
        return copied

    def close(self) -> None:
        """Closes the client: a request started afterwards fails with ``RuntimeError``. A copy's
        close does nothing."""
        if self._owner:
            self._closed[0] = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    # --- Settings ----------------------------------------------------------------------------

    def protect_token(self, token: str) -> StaticVaultToken:
        """``token``, protected by the client's token protector: for :meth:`set_token` or
        :attr:`VaultRequestOptions.token`. A ``str`` can't be erased: keep no other reference to it.

        :raises ValueError: ``token`` is empty, or isn't printable ASCII without spaces
        """
        return StaticVaultToken.protect(self._token_protector, token)

    def set_token(self, token: VaultTokenProvider | str) -> None:
        """Makes every later request with ``token`` - protected first if it is a ``str`` (see
        :meth:`protect_token`) - unless the request sets its own; see
        https://developer.hashicorp.com/vault/docs/concepts/tokens."""
        if token is None:
            raise TypeError("token must not be None.")
        provider = self.protect_token(token) if isinstance(token, str) else token
        if not isinstance(provider, VaultTokenProvider):
            raise TypeError("token must be a VaultTokenProvider or a str.")
        self._update(token=provider)

    def clear_token(self) -> None:
        """Makes later requests without a token, unless they set their own."""
        self._update(token=None)

    def set_namespace(self, ns: str) -> None:
        """Makes every later request in ``ns``, unless the request sets its own; empty for none. See
        https://developer.hashicorp.com/vault/docs/enterprise/namespaces.

        :raises ValueError: ``ns`` contains non-printable characters
        """
        if not isinstance(ns, str):
            raise TypeError("ns must be a str.")
        if ns and not is_valid_namespace(ns):
            raise ValueError(f"The namespace '{ns}' contains non-printable characters.")
        self._update(namespace=ns or None)

    def clear_namespace(self) -> None:
        """Makes later requests in no namespace, unless they set their own."""
        self._update(namespace=None)

    def set_mfa_credentials(self, *credentials: str) -> None:
        """Sends ``credentials`` (X-Vault-MFA) with every later request; see
        https://developer.hashicorp.com/vault/docs/auth/login-mfa.

        :raises ValueError: a credential is empty or not printable ASCII
        """
        check_mfa_credentials(credentials)
        self._update(mfa_credentials=tuple(credentials))

    def clear_mfa_credentials(self) -> None:
        """Stops sending MFA credentials."""
        self._update(mfa_credentials=())

    def set_response_wrapping(self, ttl: timedelta) -> None:
        """Asks Vault to wrap every later response for ``ttl`` (X-Vault-Wrap-TTL); zero to stop. See
        https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.

        :raises ValueError: ``ttl`` is negative
        """
        if not isinstance(ttl, timedelta):
            raise TypeError("ttl must be a timedelta.")
        if ttl < timedelta(0):
            raise ValueError(f"The wrapping TTL must not be negative; it is {ttl}.")
        self._update(response_wrapping_ttl=ttl)

    def clear_response_wrapping(self) -> None:
        """Stops asking Vault to wrap responses."""
        self._update(response_wrapping_ttl=timedelta(0))

    def set_custom_headers(self, headers: Mapping[str, Sequence[str]]) -> None:
        """Adds ``headers`` to every later request, replacing those set before; names starting
        X-Vault- are refused.

        :raises ValueError: a header has no name, is named X-Vault-*, or can't be sent
        """
        if headers is None:
            raise TypeError("headers must not be None.")
        self._update(custom_headers=copy_headers(headers))

    def clear_custom_headers(self) -> None:
        """Stops adding custom headers."""
        self._update(custom_headers={})

    def set_request_callbacks(self, *callbacks: VaultRequestCallback) -> None:
        """Calls ``callbacks`` with each attempt's request before it's sent (without its token),
        replacing those set before."""
        self._update(request_callbacks=tuple(callbacks))

    def clear_request_callbacks(self) -> None:
        """Stops calling request callbacks."""
        self._update(request_callbacks=())

    def set_response_callbacks(self, *callbacks: VaultResponseCallback) -> None:
        """Calls ``callbacks`` once Vault has answered each request, replacing those set before."""
        self._update(response_callbacks=tuple(callbacks))

    def clear_response_callbacks(self) -> None:
        """Stops calling response callbacks."""
        self._update(response_callbacks=())

    def set_replication_forwarding_mode(self, mode: ReplicationForwardingMode) -> None:
        """Sends a forwarding header with every later request (Vault Enterprise): X-Vault-Forward for
        ALWAYS, X-Vault-Inconsistent for INCONSISTENT, none for NONE."""
        if not isinstance(mode, ReplicationForwardingMode):
            raise TypeError("mode must be a ReplicationForwardingMode.")
        self._update(replication_forwarding_mode=mode)

    def clear_replication_forwarding_mode(self) -> None:
        """Stops sending a forwarding header."""
        self._update(replication_forwarding_mode=ReplicationForwardingMode.NONE)

    @staticmethod
    def is_error_status(error: BaseException | None, status: int) -> bool:
        """Whether ``error`` - or the first :class:`VaultRequestError` among its causes - is Vault
        answering with ``status``."""
        while error is not None:
            if isinstance(error, VaultRequestError):
                return error.status_code == status
            error = error.__cause__ or error.__context__
        return False

    # --- Generic requests ----------------------------------------------------------------------

    def read(self, path: str, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """Reads the value at ``path`` (GET /v1/path).

        :param path: the path under /v1/, with or without that prefix
        :returns: Vault's response; ``None`` if it has no body
        """
        return send(self, "GET", v1_path(_require_str(path, "path")), None, query_parameters(options), options, JsonValue.read_json_dict)

    async def read_async(self, path: str, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """:meth:`read` without blocking the event loop."""
        return await send_async(self, "GET", v1_path(_require_str(path, "path")), None, query_parameters(options), options,
                                JsonValue.read_json_dict)

    def read_raw(self, path: str, options: VaultRequestOptions | None = None) -> VaultRawResponse:
        """Reads ``path`` (GET /v1/path) and returns Vault's response as it is: not parsed, not
        checked for an error status, and its body not bound by
        :attr:`VaultClientOptions.request_timeout` - for a large or streamed body. Close it once read."""
        work = self._raw(v1_path(_require_str(path, "path")), options)
        return work(_Abandon())

    async def read_raw_async(self, path: str, options: VaultRequestOptions | None = None) -> VaultRawResponse:
        """:meth:`read_raw` without blocking the event loop while Vault answers."""
        return await _run_async(self._raw(v1_path(_require_str(path, "path")), options), VaultRawResponse.close)

    def write(self, path: str, body: Mapping[str, object], options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """Writes ``body``, as a JSON object, to ``path`` (POST /v1/path). Its values are written as
        :meth:`JsonWriter.value` writes them."""
        return send(self, "POST", v1_path(_require_str(path, "path")), _require_body(body), query_parameters(options), options,
                    JsonValue.read_json_dict)

    async def write_async(self, path: str, body: Mapping[str, object], options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """:meth:`write` without blocking the event loop."""
        return await send_async(self, "POST", v1_path(_require_str(path, "path")), _require_body(body), query_parameters(options), options,
                                JsonValue.read_json_dict)

    def write_from_bytes(self, path: str, body: Buffer, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """Writes ``body`` as it is to ``path`` (POST /v1/path). It is sent from the buffer itself,
        every attempt: leave it unchanged until this returns, then clear it if it holds a secret."""
        return self._bytes(path, body, options)(_Abandon())

    async def write_from_bytes_async(self, path: str, body: Buffer, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """:meth:`write_from_bytes` without blocking the event loop."""
        return await _run_async(self._bytes(path, body, options))

    def write_from_stream(self, path: str, body: _Readable, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """Writes what ``body`` (a binary stream) holds to ``path`` (POST /v1/path). It's read whole
        first - into a bytearray zeroed afterwards - so a retry can send it again. ``body`` isn't closed."""
        return self._stream(path, body, options)(_Abandon())

    async def write_from_stream_async(self, path: str, body: _Readable, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """:meth:`write_from_stream` without blocking the event loop."""
        return await _run_async(self._stream(path, body, options))

    def list(self, path: str, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """Lists the keys at ``path`` (GET /v1/path?list=true)."""
        query = query_parameters(options)
        query.append(("list", "true"))
        return send(self, "GET", v1_path(_require_str(path, "path")), None, query, options, JsonValue.read_json_dict)

    async def list_async(self, path: str, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """:meth:`list` without blocking the event loop."""
        query = query_parameters(options)
        query.append(("list", "true"))
        return await send_async(self, "GET", v1_path(_require_str(path, "path")), None, query, options, JsonValue.read_json_dict)

    def delete(self, path: str, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """Deletes the value at ``path`` (DELETE /v1/path)."""
        return send(self, "DELETE", v1_path(_require_str(path, "path")), None, query_parameters(options), options, JsonValue.read_json_dict)

    async def delete_async(self, path: str, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None:
        """:meth:`delete` without blocking the event loop."""
        return await send_async(self, "DELETE", v1_path(_require_str(path, "path")), None, query_parameters(options), options,
                                JsonValue.read_json_dict)

    @overload
    def unwrap(self, wrapping_token: VaultTokenProvider, *, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None: ...

    @overload
    def unwrap[T](self, wrapping_token: VaultTokenProvider, reader: Callable[[JsonValue], T | None],
                  options: VaultRequestOptions | None = None) -> VaultResponse[T] | None: ...

    def unwrap(self, wrapping_token: VaultTokenProvider, reader: Callable[[JsonValue], object] = JsonValue.read_json_dict,
               options: VaultRequestOptions | None = None) -> VaultResponse[Any] | None:
        """The response ``wrapping_token`` wraps (PUT /v1/sys/wrapping/unwrap, made with that
        token), its data read with ``reader`` - the ``from_json`` of the model the wrapped method
        returns, e.g. ``KvV2ReadResponse.from_json``; JSON values by default. See
        https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.

        :param wrapping_token: the wrapping token - :attr:`VaultResponseWrapInfo.token`, or one
            protected with :meth:`protect_token`
        :raises VaultResponseError: Vault refuses the token: unknown, expired or already used
        """
        return send(self, "PUT", "/v1/sys/wrapping/unwrap", None, None, _with_token(wrapping_token, options), reader)

    @overload
    async def unwrap_async(self, wrapping_token: VaultTokenProvider, *, options: VaultRequestOptions | None = None) -> VaultResponse[JsonDict] | None: ...

    @overload
    async def unwrap_async[T](self, wrapping_token: VaultTokenProvider, reader: Callable[[JsonValue], T | None],
                              options: VaultRequestOptions | None = None) -> VaultResponse[T] | None: ...

    async def unwrap_async(self, wrapping_token: VaultTokenProvider, reader: Callable[[JsonValue], object] = JsonValue.read_json_dict,
                           options: VaultRequestOptions | None = None) -> VaultResponse[Any] | None:
        """:meth:`unwrap` without blocking the event loop."""
        return await send_async(self, "PUT", "/v1/sys/wrapping/unwrap", None, None, _with_token(wrapping_token, options), reader)

    # --- Sending ---------------------------------------------------------------------------------

    def _update(self, **changes: Any) -> None:
        with self._modifiers_lock:
            self._modifiers = dataclasses.replace(self._modifiers, **changes)

    def _raw(self, path: str, options: VaultRequestOptions | None) -> Callable[[_Abandon], VaultRawResponse]:
        modifiers = self._modifiers.merge(options)
        query = query_parameters(options)

        def work(abandon: _Abandon) -> VaultRawResponse:
            sent = self._send_core("GET", path, None, query, modifiers, _deadline(self._options.request_timeout), abandon)
            # The body isn't bound by the timeout.
            if sent.connection.sock is not None:
                sent.connection.sock.settimeout(None)
            return VaultRawResponse(sent.response, sent.connection.close)

        return work

    def _bytes(self, path: str, body: Buffer, options: VaultRequestOptions | None) -> Callable[[_Abandon], VaultResponse[JsonDict] | None]:
        v1 = v1_path(_require_str(path, "path"))
        if not isinstance(body, Buffer):
            raise TypeError("body must be a buffer.")
        modifiers = self._modifiers.merge(options)
        query = query_parameters(options)

        def work(abandon: _Abandon) -> VaultResponse[JsonDict] | None:
            with memoryview(body).cast("B") as view:
                return self._send("POST", v1, view, query, modifiers, JsonValue.read_json_dict, abandon)

        return work

    def _stream(self, path: str, body: _Readable, options: VaultRequestOptions | None) -> Callable[[_Abandon], VaultResponse[JsonDict] | None]:
        v1 = v1_path(_require_str(path, "path"))
        if body is None or not callable(getattr(body, "readinto", None)):
            raise TypeError("body must be a binary stream.")
        modifiers = self._modifiers.merge(options)
        query = query_parameters(options)

        def work(abandon: _Abandon) -> VaultResponse[JsonDict] | None:
            with SecureBuffer() as buffer:
                buffer.read_from(lambda b: body.readinto(b) or 0)
                with buffer.view() as view:
                    return self._send("POST", v1, view, query, modifiers, JsonValue.read_json_dict, abandon)

        return work

    def _prepare[T](self, method: str, path: str, body: object, query: Query | None, options: VaultRequestOptions | None,  # noqa: PLR0917 - private
                    reader: Callable[[JsonValue], T | None]) -> Callable[[_Abandon], VaultResponse[T] | None]:
        # Checked, and the body written, before this returns, so a model the caller changes
        # afterwards isn't half-sent.
        modifiers = self._modifiers.merge(options)
        json = None
        if body is not None:
            json = SecureBuffer()
            try:
                JsonWriter(json).value(body)
            except BaseException:
                json.close()
                raise

        def work(abandon: _Abandon) -> VaultResponse[T] | None:
            if json is None:
                return self._send(method, path, None, query, modifiers, reader, abandon)
            try:
                with json.view() as view:
                    return self._send(method, path, view, query, modifiers, reader, abandon)
            finally:
                json.close()

        return work

    def _send[T](self, method: str, path: str, body: memoryview | None, query: Query | None, modifiers: _Modifiers,  # noqa: PLR0917 - private
                 reader: Callable[[JsonValue], T | None], abandon: _Abandon) -> VaultResponse[T] | None:
        # One request within the request timeout: sent, its whole body read, and parsed.
        timeout = self._options.request_timeout
        deadline = _deadline(timeout)
        timed_out = f"Vault didn't answer {method} {path} within {timeout}."
        try:
            sent = self._send_core(method, path, body, query, modifiers, deadline, abandon)
            try:
                with SecureBuffer(sent.response.length or 0) as content:
                    content.read_from(lambda b: self._read_body(sent, b, deadline, abandon))
                    # sys/health answers 429, 472, 473, 501 and 503 with the health status itself.
                    status = sent.response.status
                    with content.view() as view:
                        if not 200 <= status <= 399 and path != _HEALTH_PATH:
                            raise response_error(status, view, sent.request.method, sent.request.url)
                        return read_response(view, self._token_protector, reader)
            finally:
                abandon.track(None)
                sent.response.close()
                sent.connection.close()
        except _DeadlineExceededError:
            raise TimeoutError(timed_out) from None

    def _read_body(self, sent: _Sent, buffer: memoryview, deadline: float, abandon: _Abandon) -> int:
        sock = sent.connection.sock
        if sent.response.isclosed():
            return 0
        if sock is not None:
            _set_remaining(sock, deadline)
        try:
            return sent.response.readinto(buffer)
        except http.client.IncompleteRead:
            # Its partial bytes may hold a secret: neither kept nor chained.
            raise ConnectionError(f"The connection was lost during Vault's response to {sent.request.method} {_without_query(sent.request.url)}.") \
                from None
        except TimeoutError:
            if abandon.abandoned:
                raise _abandoned() from None
            if _remaining(deadline) <= 0:
                raise _DeadlineExceededError from None
            raise
        except OSError:
            if abandon.abandoned:
                raise _abandoned() from None
            raise

    def _send_core(self, method: str, path: str, body: memoryview | None, query: Query | None, modifiers: _Modifiers,  # noqa: PLR0917 - private
                   deadline: float, abandon: _Abandon) -> _Sent:
        # Sends the request, retrying and following a redirect as configured, and calls the response
        # callbacks. The body of the response it returns is unread; the caller closes it.
        if self._closed[0]:
            raise RuntimeError("This Vault client has been closed.")
        target = _Target(self._https, self._host, self._port, self._prefix + path + query_string(query))

        limiter = self._options.rate_limiter
        if limiter is not None and not limiter.acquire(_remaining(deadline), abandon.wait):
            if abandon.abandoned:
                raise _abandoned()
            raise _DeadlineExceededError
        states = () if self._replication_states is None else self._replication_states.snapshot()

        # Asked for once per request; a provider's failure is its own to retry, so isn't retried here.
        protected_token = None if modifiers.token is None else self._get_token(modifiers.token, deadline, abandon)

        redirects = 1
        while True:
            sent = self._send_with_retries(method, target, path, body, modifiers, states, protected_token, deadline, abandon)
            try:
                location = self._redirect_target(sent, redirects)
            except BaseException:
                sent.response.close()
                sent.connection.close()
                raise
            if location is None:
                try:
                    for callback in modifiers.response_callbacks:
                        callback(sent.request, sent.response.status, sent.response.headers)
                    if self._replication_states is not None:
                        self._replication_states.record(sent.response.headers)
                except BaseException:
                    sent.response.close()
                    sent.connection.close()
                    raise
                return sent

            redirects -= 1
            self._logger.info("Vault redirected %s %s to %s; following it.", method, _without_query(path), _without_query(location.url), extra={"event_id": 2})
            sent.response.close()
            sent.connection.close()
            target = location

    def _redirect_target(self, sent: _Sent, redirects: int) -> _Target | None:
        # Where a redirect response says to go, if following it is allowed; None if it isn't one.
        status = sent.response.status
        if status not in {301, 302, 307}:
            return None

        request = sent.request
        header = sent.response.headers.get("Location")
        location = None
        if header:
            with contextlib.suppress(ValueError):
                location = urljoin(request.url, header)
        parts = urlsplit(location) if location else None
        if parts is None or not parts.hostname:
            raise VaultRedirectError(status, "could not read the redirect location", None, request.method, request.url)
        if not self._options.follow_redirects:
            raise VaultRedirectError(status, "redirects are disabled", location, request.method, request.url)
        if redirects <= 0:
            raise VaultRedirectError(status, "at most one redirect is allowed", location, request.method, request.url)

        scheme = parts.scheme.lower()
        if request.url.lower().startswith("https:") and scheme != "https":
            raise VaultRedirectError(status, "the redirect would cause a protocol downgrade", location, request.method, request.url)
        if scheme != "https" and not (scheme == "http" and (_is_loopback(parts.hostname) or self._options.allow_unencrypted_http)):
            raise VaultRedirectError(status, "the redirect would send the token over unencrypted http", location, request.method, request.url)

        path = parts.path or "/"
        return _Target(scheme == "https", parts.hostname, parts.port, path + (f"?{parts.query}" if parts.query else ""))

    def _send_with_retries(self, method: str, target: _Target, path: str, body: memoryview | None, modifiers: _Modifiers,  # noqa: PLR0917 - private
                           states: tuple[str, ...], protected_token: str | None, deadline: float, abandon: _Abandon) -> _Sent:
        # One request, sent until it succeeds, fails in a way not worth retrying, or runs out of retries.
        retry = self._options.retry
        attempt = 0
        while True:
            request = self._create_request(method, target, body, modifiers, states)
            for request_callback in modifiers.request_callbacks:
                request_callback(request)

            sent: _Sent | None = None
            failure: BaseException | None = None
            try:
                sent = self._send_once(target, request, body, protected_token, deadline, abandon)
            except _DeadlineExceededError:
                raise
            except (OSError, http.client.HTTPException) as error:
                if abandon.abandoned:
                    raise _abandoned() from None
                if _remaining(deadline) <= 0:
                    raise _DeadlineExceededError from None
                if attempt >= retry.retry_max or not self._check_retry(0, error):
                    raise
                failure = error

            if sent is not None and (attempt >= retry.retry_max or not self._check_retry(sent.response.status, None)):
                return sent

            status = 0 if sent is None else sent.response.status
            delay = self._backoff(retry.retry_wait_min, retry.retry_wait_max, attempt, status)
            if not isinstance(delay, timedelta) or delay < timedelta(0):
                delay = timedelta(0)
            if sent is not None:
                abandon.track(None)
                sent.response.close()
                sent.connection.close()
            if delay.total_seconds() >= _remaining(deadline):
                raise _DeadlineExceededError

            self._logger.warning("Vault request %s %s failed (%s); retry %d of %d in %s.", method, _without_query(path),
                                 repr(failure) if failure is not None else f"{status}{reason_phrase(status)}", attempt + 1, retry.retry_max, delay,
                                 extra={"event_id": 1})
            if abandon.wait(delay.total_seconds()):
                raise _abandoned()
            attempt += 1

    def _send_once(self, target: _Target, request: VaultRequest, body: memoryview | None, protected_token: str | None,  # noqa: PLR0917 - private
                   deadline: float, abandon: _Abandon) -> _Sent:
        # One attempt: a connection of its own, the request with the token, if any, in its header -
        # decrypted into a bytearray zeroed once http.client has copied it.
        remaining = _remaining(deadline)
        if remaining <= 0:
            raise _DeadlineExceededError
        connection = self._connector_for(target).connect()
        # Connecting may take what's left of the deadline, and no more.
        connection.timeout = None if remaining == float("inf") else remaining
        try:
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise ConnectionError("The connection to Vault was closed before the request was sent.")
            abandon.track(sock)
            connection.putrequest(request.method, target.path, skip_accept_encoding=True)
            for name, value in request.headers:
                connection.putheader(name, value)
            if body is not None:
                connection.putheader("Content-Length", str(len(body)))
            if protected_token is not None:
                token, length = decrypt_token(self._token_protector, protected_token)
                try:
                    with memoryview(token) as view, view[:length] as header:
                        put_token(connection, header)
                finally:
                    ArrayUtility.zero_memory(token)
            _set_remaining(sock, deadline)
            connection.endheaders(body)
            response = connection.getresponse()
        except TimeoutError:
            connection.close()
            if abandon.abandoned:
                raise _abandoned() from None
            if _remaining(deadline) <= 0:
                raise _DeadlineExceededError from None
            raise
        except BaseException:
            connection.close()
            if abandon.abandoned:
                raise _abandoned() from None
            raise
        return _Sent(request, connection, response)

    def _create_request(self, method: str, target: _Target, body: memoryview | None, modifiers: _Modifiers, states: tuple[str, ...]) -> VaultRequest:
        # A request carrying the client's headers, as vault-client-go's newRequest builds it; the
        # token is added only as it's sent.
        headers: builtins.list[tuple[str, str]] = [(REQUEST_HEADER, "true")]
        if modifiers.namespace:
            headers.append((NAMESPACE_HEADER, modifiers.namespace))
        content_type = False
        for name, values in modifiers.custom_headers.items():
            content_type |= name.lower() == "content-type"
            headers += ((name, value) for value in values)
        if body is not None and not content_type:
            headers.append(("Content-Type", "application/json"))
        headers.append(("User-Agent", USER_AGENT))
        headers += (("X-Vault-MFA", credential) for credential in modifiers.mfa_credentials)
        if modifiers.response_wrapping_ttl > timedelta(0):
            headers.append(("X-Vault-Wrap-TTL", format_go_duration(modifiers.response_wrapping_ttl)))
        if modifiers.replication_forwarding_mode is ReplicationForwardingMode.ALWAYS:
            headers.append(("X-Vault-Forward", "active-node"))
        elif modifiers.replication_forwarding_mode is ReplicationForwardingMode.INCONSISTENT:
            headers.append(("X-Vault-Inconsistent", "forward-active-node"))
        headers += ((INDEX_HEADER, state) for state in states)
        return VaultRequest(method, target.url, headers)

    def _connector_for(self, target: _Target) -> VaultConnector:
        # The client's connector for Vault's own address; for where a redirect points, one with the
        # same TLS context (and no server-name override, which named Vault's own host).
        if (target.https, target.host, target.port) == (self._https, self._host, self._port):
            return self._connector
        context = self._connector.ssl_context or (_default_context() if target.https else None)
        return VaultConnector(target.https, target.host, target.port, self._options.request_timeout, context)

    def _get_token(self, provider: VaultTokenProvider, deadline: float, abandon: _Abandon) -> str:
        # The protected token get_token returns, waited for within the deadline on a thread of its own.
        done = threading.Event()
        outcome: builtins.list[tuple[object, BaseException | None]] = []

        def run() -> None:
            try:
                outcome.append((provider.get_token(), None))
            except BaseException as error:  # re-raised on the requesting thread
                outcome.append((None, error))
            finally:
                done.set()

        threading.Thread(target=run, name="hkdfguard-vault-token", daemon=True).start()
        while not done.wait(min(_remaining(deadline), 0.05)):
            if abandon.abandoned:
                raise _abandoned()
            if _remaining(deadline) <= 0:
                raise _DeadlineExceededError
        token, error = outcome[0]
        if error is not None:
            raise error
        if not isinstance(token, str) or not token:
            raise RuntimeError("The Vault token provider returned no token.")
        return token



# --- For the generated methods -------------------------------------------------------------------


def send[T](client: VaultClient, method: str, path: str, body: object, query: Query | None, options: VaultRequestOptions | None,  # noqa: PLR0917 - the generated methods' one call
            reader: Callable[[JsonValue], T | None]) -> VaultResponse[T] | None:
    """Sends a request - ``body``, if any, as JSON - and reads Vault's response into a
    :class:`VaultResponse`; ``None`` if it has no body. The generated methods all come here."""
    return client._prepare(method, path, body, query, options, reader)(_Abandon())


async def send_async[T](client: VaultClient, method: str, path: str, body: object, query: Query | None,  # noqa: PLR0917
                        options: VaultRequestOptions | None, reader: Callable[[JsonValue], T | None]) -> VaultResponse[T] | None:
    """:func:`send` on a thread of its own, abandoned if the awaiting task is cancelled."""
    return await _run_async(client._prepare(method, path, body, query, options, reader))


def mount_path_or(options: VaultRequestOptions | None, default_mount_path: str) -> str:
    """``options``' mount path, leading and trailing '/' trimmed, or ``default_mount_path``."""
    if options is None or options.mount_path is None:
        return default_mount_path
    return options.mount_path.strip("/") or default_mount_path


def escape_path_segment(value: str) -> str:
    """``value`` as one path segment: everything but A-Z, a-z, 0-9, '-', '_', '.' and '~'
    percent-encoded as UTF-8, '/' included.

    :raises TypeError: ``value`` isn't a ``str``
    """
    return "".join(chr(b) if b in _UNRESERVED else f"%{b:02X}" for b in _require_str(value, "value").encode("utf-8", "surrogatepass"))


def query_parameters(options: VaultRequestOptions | None) -> Query:
    """``options``' query parameters, in a fresh list to add the endpoint's own to."""
    return [] if options is None else [(str(name), str(value)) for name, value in options.query_parameters]


def format_query_value(value: str | bool | int) -> str:
    """``value`` as a query parameter: a bool as true or false."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def query_string(query: Query | None) -> str:
    """``query``, sorted by name (values of one name keep their order) as Go's url.Values.Encode sorts it."""
    if not query:
        return ""
    ordered = sorted(query, key=lambda parameter: parameter[0])
    return "?" + "&".join(f"{escape_path_segment(name)}={escape_path_segment(value)}" for name, value in ordered)


def v1_path(path: str) -> str:
    """``path`` under /v1/, whether or not it starts with "/", "v1/" or "/v1/" already."""
    if path.startswith("/v1/"):
        return path
    if path.startswith("v1/"):
        return "/" + path
    if path.startswith("/"):
        return "/v1" + path
    return "/v1/" + path


# --- Internals -----------------------------------------------------------------------------------


async def _run_async[T](work: Callable[[_Abandon], T], discard: Callable[[T], object] | None = None) -> T:
    # Runs work on a thread of its own; cancelling the awaiting task abandons it. A result that
    # arrives once the task is cancelled is handed to discard.
    loop = asyncio.get_running_loop()
    future: asyncio.Future[T] = loop.create_future()
    abandon = _Abandon()

    def settle(result: T | None, error: BaseException | None) -> None:
        if future.cancelled():
            if error is None and discard is not None:
                discard(result)  # type: ignore[arg-type]  # set when error is None
            return
        if error is not None:
            future.set_exception(error)
        else:
            future.set_result(result)  # type: ignore[arg-type]

    def run() -> None:
        try:
            result = work(abandon)
        except BaseException as error:  # handed to the awaiting task
            _call_soon(loop, settle, None, error)
        else:
            if not _call_soon(loop, settle, result, None) and discard is not None:
                discard(result)

    threading.Thread(target=run, name="hkdfguard-vault-client", daemon=True).start()
    try:
        return await future
    except asyncio.CancelledError:
        abandon.abandon()
        raise


def _call_soon(loop: asyncio.AbstractEventLoop, callback: Callable[..., None], *args: object) -> bool:
    try:
        loop.call_soon_threadsafe(callback, *args)
    except RuntimeError:  # the loop has closed
        return False
    return True


def _with_token(wrapping_token: VaultTokenProvider, options: VaultRequestOptions | None) -> VaultRequestOptions:
    if not isinstance(wrapping_token, VaultTokenProvider):
        raise TypeError("wrapping_token must be a VaultTokenProvider.")
    return dataclasses.replace(options or VaultRequestOptions(), token=wrapping_token)


def _require_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str.")
    return value


def _require_body(body: object) -> Mapping[str, object]:
    if not isinstance(body, Mapping):
        raise TypeError("body must be a Mapping.")
    return body


def _deadline(timeout: timedelta) -> float:
    return float("inf") if not timeout else time.monotonic() + timeout.total_seconds()


def _remaining(deadline: float) -> float:
    return deadline - time.monotonic()


def _set_remaining(sock: socket.socket, deadline: float) -> None:
    remaining = _remaining(deadline)
    if remaining <= 0:
        raise _DeadlineExceededError
    sock.settimeout(None if remaining == float("inf") else remaining)


def _abandoned() -> ConnectionAbortedError:
    return ConnectionAbortedError("The Vault request was abandoned: the task awaiting it was cancelled.")


def _without_query(url: str) -> str:
    return url.split("?", 1)[0]


def _default_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _base_address(options: VaultClientOptions) -> tuple[bool, str, int | None, str]:
    # Whether the address is https, its host and port, and its path prefix with no trailing '/', to
    # put /v1/... after. Refuses an address that would send tokens in the clear (http anywhere but
    # loopback, unless allowed) or that carries credentials, a query or a fragment.
    address = options.address
    if not isinstance(address, str):
        raise TypeError("address must be a str.")
    parts = urlsplit(address)
    scheme = parts.scheme.lower()
    if scheme == "unix":
        raise ValueError(f"Vault's address '{address}' is a unix socket, which this client can't connect to: reach Vault (or its agent) "
                         "over https, or http on loopback.")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        host, port = None, None
    if not scheme or not parts.netloc or not host:
        raise ValueError(f"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.")
    if scheme != "https" and not (scheme == "http" and (_is_loopback(host) or options.allow_unencrypted_http)):
        raise ValueError(f"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or "
                         "dev server), or with allow_unencrypted_http, since every request carries a token.")
    if "@" in parts.netloc or parts.query or parts.fragment or "?" in address or "#" in address:
        raise ValueError(f"Vault's address '{address}' must not hold credentials, a query or a fragment.")
    return scheme == "https", host, port, parts.path.rstrip("/")


def _is_loopback(host: str) -> bool:
    # localhost, or an IP literal on the loopback network. Only literals are parsed, so no name is
    # ever resolved.
    if host.lower() == "localhost":
        return True
    if ":" not in host and not _IPV4_LITERAL.fullmatch(host):
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

