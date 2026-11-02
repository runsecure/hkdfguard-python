"""The protected read-only cache over one Google Cloud project's Secret Manager."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from collections.abc import Callable, Sequence
from types import TracebackType
from typing import Any, Final, Self

import grpc
from google.api_core import exceptions as core_exceptions
from google.api_core import gapic_v1, retry
from google.api_core.client_options import ClientOptions
from google.api_core.gapic_v1 import method_async
from google.auth.credentials import Credentials
from google.cloud.secretmanager_v1 import AccessSecretVersionRequest, SecretManagerServiceClient
from google.cloud.secretmanager_v1.services.secret_manager_service.transports import SecretManagerServiceGrpcTransport
from google.cloud.secretmanager_v1.services.secret_manager_service.transports.base import DEFAULT_CLIENT_INFO
from hkdfguard.abstractions import CryptographicError, KeyRing
from hkdfguard.cache import RemoteSecretCache, SecretNameMatching, SecretValueSink
from hkdfguard.cache.googlesecretmanager._capture import AccessedSecretVersion, ResponseCapture, crc32c

_METHOD: Final = "/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion"

# The client's own defaults for AccessSecretVersion (its transport's _prep_wrapped_messages), which
# the Java client's settings match: RESOURCE_EXHAUSTED and UNAVAILABLE retried with exponential
# backoff from 2 s to 60 s, everything within the timeout.
_RETRYABLE: Final = (core_exceptions.ResourceExhausted, core_exceptions.ServiceUnavailable)
_INITIAL_RETRY_DELAY: Final = 2.0
_MAXIMUM_RETRY_DELAY: Final = 60.0
_RETRY_DELAY_MULTIPLIER: Final = 2.0

# A version's resource name, of a global or a regional secret.
_SECRET_VERSION_NAME: Final = re.compile(r"projects/[^/]+/(?:locations/[^/]+/)?secrets/([^/]+)/versions/[^/]+")

_Stub = Callable[..., Any]


def _is_ascii_letter_or_digit(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9")


class GoogleSecretManagerSecretCache(RemoteSecretCache):
    """A :class:`~hkdfguard.abstractions.ProtectedReadOnlyCache` over the secrets in one Google
    Cloud project's Secret Manager. The first lookup of a name that isn't cached yet reads that one
    secret's latest version with AccessSecretVersion; fetching, encryption, caching and telemetry are
    :class:`RemoteSecretCache`'s. This class never lists secrets or versions, so the principal needs
    only ``secretmanager.versions.access`` on the secrets it reads (the Secret Manager Secret Accessor
    role), never ``secretmanager.secrets.list``.

    Names are matched exactly, as Secret Manager matches secret IDs: ``"Db-Password"`` and
    ``"db-password"`` are two secrets and two entries. A name Secret Manager can't hold - anything but
    1-255 ASCII letters, digits, hyphens and underscores, such as the configuration path
    ``"ConnectionStrings:Admin"`` - is reported missing without a call.

    A payload holding a JSON object, such as ``{"username":"app","password":"..."}``, is cached whole
    under the secret's ID and each member under ``"id#key"`` - ``"Db-Login#password"`` - all from one
    call (see :class:`RemoteSecretCache`).

    A secret that doesn't exist, or has no versions (``NOT_FOUND``), or whose value is empty is
    reported missing. Any other failure (permission denied, a disabled or destroyed latest version,
    Google unreachable, no credentials, the timeout passing) raises the client's
    :class:`google.api_core.exceptions.GoogleAPICallError` (or, for a credential that can't get a
    token, google-auth's exception). A payload whose CRC32C doesn't match the checksum Google returns,
    or a response naming a different secret, is refused with
    :class:`~hkdfguard.abstractions.CryptographicError`; a response that isn't well-formed protobuf
    fails as ``INTERNAL`` (:class:`google.api_core.exceptions.InternalServerError`).

    **The payload never becomes ``bytes``.** The cache makes AccessSecretVersion itself, on the
    client's gRPC channel, with a response deserializer of its own: it reads the few fields it needs
    straight from the message gRPC received, copying the payload into a bytearray, which is encrypted
    and zeroed - refused or not. The client's protobuf (and proto-plus) message, which would hold the
    payload in an immutable ``bytes`` no one can erase, is never built, and the client's own debug
    logging, which would log the whole response, is bypassed. Out of reach, as everywhere in Python:
    the message itself, which gRPC hands the deserializer as ``bytes``, and the transport's buffers
    below it (HTTP/2, TLS decryption).

    The client is the application's: it creates it - credentials, endpoint, channel options - and must
    use the gRPC transport (the default); a REST transport is refused. Only the client's channel is
    used, so its per-call settings don't apply: every call is retried as the client retries
    AccessSecretVersion by default (``RESOURCE_EXHAUSTED`` and ``UNAVAILABLE``, with exponential
    backoff), all within ``timeout``. :meth:`create` makes a client of its own, which :meth:`close`
    closes; a client passed in is never closed.

    decrypt_async and find_max_decrypted_length_async fetch through a future on the same channel, so
    a miss doesn't block the event loop or a thread, and they work from any event loop. Cancelling
    the lookup that started a fetch cancels the call.
    """

    MAX_SECRET_NAME_LENGTH: Final = 255
    """The longest ID Secret Manager accepts for a secret."""

    DEFAULT_TIMEOUT: Final = 60.0
    """How long a fetch may take by default, retries included, in seconds: the client's own default."""

    def __init__(self, client: SecretManagerServiceClient, project_id: str, key_ring: KeyRing, logger: logging.Logger | None = None, *,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        """A cache over a client the caller created, and closes. No call is made until a secret is looked up.

        :param client: e.g. ``SecretManagerServiceClient()`` - the global endpoint, signed in with
            Application Default Credentials. Its transport must be gRPC (the default).
        :param project_id: the project whose secrets are read: its ID or number
        :param key_ring: supplies the key every fetched secret is encrypted under; owned by the
            caller - the cache never closes keys
        :param logger: optional; see :class:`RemoteSecretCache`
        :param timeout: how long a fetch may take, retries included, in seconds
        :raises TypeError: ``client``, ``project_id`` or ``key_ring`` is ``None``
        :raises ValueError: ``project_id`` is empty, or holds anything but ASCII letters, digits,
            hyphens, dots and colons; the client's transport isn't gRPC; or ``timeout`` isn't positive
        """
        if client is None:
            raise TypeError("client must not be None.")
        self._project_id = _check_project_id(project_id)
        self._timeout = _check_timeout(timeout)
        transport = client.transport
        if not isinstance(transport, SecretManagerServiceGrpcTransport):
            raise ValueError("The client's transport must be gRPC (SecretManagerServiceGrpcTransport), so the cache can take the payload out of "
                             f"the response before the client parses it; got {type(transport).__name__}.")
        super().__init__(key_ring, SecretNameMatching.EXACT, logger)
        self._client = client
        self._channel: grpc.Channel = transport.grpc_channel
        self._owns_client = False

    @classmethod
    def create(cls, project_id: str, key_ring: KeyRing, logger: logging.Logger | None = None, *, credentials: Credentials | None = None,
               client_options: ClientOptions | dict[str, Any] | None = None, timeout: float = DEFAULT_TIMEOUT) -> Self:
        """A cache reading secrets through a new gRPC client, which :meth:`close` closes: by default
        to the global endpoint, signed in with Application Default Credentials.

        :param credentials: ``None`` for Application Default Credentials
        :param client_options: the client's options, e.g. ``{"api_endpoint": "secretmanager.europe-west1.rep.googleapis.com"}``
        :raises TypeError: ``project_id`` or ``key_ring`` is ``None``
        :raises ValueError: as the constructor - checked before a client is created
        :raises google.auth.exceptions.DefaultCredentialsError: no credentials were given or found
        """
        _check_project_id(project_id)
        _check_timeout(timeout)
        if key_ring is None:
            raise TypeError("key_ring must not be None.")

        client = SecretManagerServiceClient(credentials=credentials, transport="grpc", client_options=client_options)
        try:
            cache = cls(client, project_id, key_ring, logger, timeout=timeout)
        except BaseException:
            client.transport.close()  # type: ignore[no-untyped-call]
            raise
        cache._owns_client = True
        return cache

    @classmethod
    def is_valid_secret_name(cls, name: str | None) -> bool:
        """Whether Secret Manager accepts ``name`` as a secret ID: 1-:attr:`MAX_SECRET_NAME_LENGTH`
        ASCII letters, digits, hyphens and underscores."""
        if not isinstance(name, str) or not 0 < len(name) <= cls.MAX_SECRET_NAME_LENGTH:
            return False
        return all(_is_ascii_letter_or_digit(c) or c in "-_" for c in name)

    def close(self) -> None:
        """Closes the client :meth:`create` made; a client passed in is left open."""
        if self._owns_client:
            self._client.transport.close()  # type: ignore[no-untyped-call]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def _is_valid_name(self, name: str) -> bool:
        return self.is_valid_secret_name(name)

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        capture = ResponseCapture()
        try:
            call = gapic_v1.method.wrap_method(  # type: ignore[no-untyped-call]
                self._stub(capture), default_retry=self._retry(retry.Retry), default_timeout=self._timeout, client_info=DEFAULT_CLIENT_INFO)
            request, metadata = self._request(name)
            try:
                response = call(request, metadata=metadata)
            except core_exceptions.NotFound:
                return
            _accept(response, name, value)
        finally:
            # Covers a refused response, a retried one, and one that arrives too late.
            capture.close()

    async def _fetch_async(self, name: str, value: SecretValueSink) -> None:
        capture = ResponseCapture()
        try:
            stub = self._stub(capture)

            def start(request: AccessSecretVersionRequest, *, timeout: float | None = None, metadata: Sequence[tuple[str, str]] = (),
                      compression: grpc.Compression | None = None) -> asyncio.Future[AccessedSecretVersion]:
                return _awaitable(stub.future(request, timeout=timeout, metadata=metadata, compression=compression))

            call = method_async.wrap_method(  # type: ignore[no-untyped-call]
                start, default_retry=self._retry(retry.AsyncRetry), default_timeout=self._timeout, client_info=DEFAULT_CLIENT_INFO)
            request, metadata = self._request(name)
            try:
                response = await call(request, metadata=metadata)
            except core_exceptions.NotFound:
                return
            _accept(response, name, value)
        finally:
            capture.close()

    def _stub(self, capture: ResponseCapture) -> Any:
        # A multi-callable whose responses capture parses: the client's own deserializer never runs.
        return self._channel.unary_unary(_METHOD, request_serializer=AccessSecretVersionRequest.serialize,
                                         response_deserializer=capture.deserialize)

    def _retry[R](self, kind: Callable[..., R]) -> R:
        return kind(predicate=retry.if_exception_type(*_RETRYABLE), initial=_INITIAL_RETRY_DELAY, maximum=_MAXIMUM_RETRY_DELAY,
                    multiplier=_RETRY_DELAY_MULTIPLIER, timeout=self._timeout)

    def _request(self, name: str) -> tuple[AccessSecretVersionRequest, tuple[tuple[str, str], ...]]:
        # The request, and the routing header the client would add for it.
        resource_name = f"projects/{self._project_id}/secrets/{name}/versions/latest"
        return AccessSecretVersionRequest(name=resource_name), (
            gapic_v1.routing_header.to_grpc_metadata((("name", resource_name),)),)  # type: ignore[no-untyped-call]


def _awaitable(call: grpc.Future) -> asyncio.Future[AccessedSecretVersion]:
    # The gRPC future as an asyncio one on the running loop. Cancelling the asyncio future cancels the
    # call; the call's outcome is handed over on the loop's thread.
    loop = asyncio.get_running_loop()
    result: asyncio.Future[AccessedSecretVersion] = loop.create_future()

    def transfer(done: grpc.Future) -> None:
        if result.done():
            return
        if done.cancelled():
            # Cancelled by gRPC, not by this lookup (which would have cancelled result first).
            result.set_exception(core_exceptions.Cancelled("The Secret Manager call was cancelled."))  # type: ignore[no-untyped-call]
        elif (error := done.exception()) is not None:
            result.set_exception(error)
        else:
            result.set_result(done.result())

    def on_done(done: grpc.Future) -> None:
        # On gRPC's thread. A loop already closed has nothing waiting; the capture zeroes the response.
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(transfer, done)

    result.add_done_callback(lambda f: call.cancel() if f.cancelled() else None)
    call.add_done_callback(on_done)
    return result


def _check_project_id(project_id: str) -> str:
    if project_id is None:
        raise TypeError("project_id must not be None.")
    if not isinstance(project_id, str):
        raise TypeError("project_id must be a str.")
    if not project_id:
        raise ValueError("The project ID is empty.")
    # Spliced into every resource name, so nothing that could change the path is allowed.
    if not all(_is_ascii_letter_or_digit(c) or c in "-.:" for c in project_id):
        raise ValueError(f"'{project_id}' isn't a Google Cloud project ID or number.")
    return project_id


def _check_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
        raise ValueError(f"The timeout must be a positive number of seconds; got {timeout!r}.")
    return float(timeout)


def _accept(response: AccessedSecretVersion, name: str, value: SecretValueSink) -> None:
    # Checks the response and hands its payload to value, which zeroes it; the capture zeroes it
    # either way.
    _check_response(response, name)
    # A payload holding a JSON object is cached whole and by key.
    if response.data:
        value.set_bytes_with_json_keys(response.data)


def _check_response(response: AccessedSecretVersion, name: str) -> None:
    # The response must be a version of the secret asked for (its project comes back as a number, so
    # only the secret ID can be compared), and match its checksum when it has one.
    reported = _SECRET_VERSION_NAME.fullmatch(response.name)
    if reported is None or reported.group(1) != name:
        raise CryptographicError(f"Secret Manager answered a request for secret '{name}' with '{response.name}'.")
    if response.data_crc32c is not None and response.data_crc32c != crc32c(response.data):
        raise CryptographicError(f"The payload of secret '{name}' doesn't match its CRC32C: it was corrupted in transit.")
