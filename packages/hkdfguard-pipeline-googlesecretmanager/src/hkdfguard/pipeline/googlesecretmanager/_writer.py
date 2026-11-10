"""The secret pipeline writer over one Google Cloud project's Secret Manager."""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Callable, MutableMapping, Sequence
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
from hkdfguard.abstractions import CryptographicError, PipelineDataProtector
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest
from hkdfguard.pipeline.googlesecretmanager._capture import AccessedSecretVersion, ResponseCapture, crc32c

_METHOD: Final = "/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion"

# The client's own defaults for AccessSecretVersion (its transport's _prep_wrapped_messages):
# RESOURCE_EXHAUSTED and UNAVAILABLE retried with exponential backoff from 2 s to 60 s, everything
# within the timeout - as hkdfguard-cache-googlesecretmanager retries.
_RETRYABLE: Final = (core_exceptions.ResourceExhausted, core_exceptions.ServiceUnavailable)
_INITIAL_RETRY_DELAY: Final = 2.0
_MAXIMUM_RETRY_DELAY: Final = 60.0
_RETRY_DELAY_MULTIPLIER: Final = 2.0

# A version's resource name, of a global or a regional secret.
_SECRET_VERSION_NAME: Final = re.compile(r"projects/[^/]+/(?:locations/[^/]+/)?secrets/([^/]+)/versions/[^/]+")


def _is_ascii_letter_or_digit(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9")


class GoogleSecretManagerSecretPipelineWriter(SecretPipelineWriter):
    """The end of a provisioning pipeline: pulls a fixed list of secrets from one Google Cloud
    project's Secret Manager, encrypts each with a
    :class:`~hkdfguard.abstractions.PipelineDataProtector` as soon as it is read, and writes them out
    as one file per secret - the folder layout :class:`~hkdfguard.cache.FilePerSecretCache` reads at
    runtime. It is independent of ``hkdfguard-cache-googlesecretmanager``'s runtime cache, and of any
    key ring. Naming, encrypting, keeping and writing are
    :class:`~hkdfguard.pipeline.SecretPipelineWriter`'s::

        with AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector:
            with GoogleSecretManagerSecretPipelineWriter.create("my-project", protector,
                                                               ["db-login#username", "db-login#password", "api-key"]) as writer:
                writer.pull_secrets()
                writer.write_protected_secret_files(r"C:\\HkdfGuardSecrets\\myapp")
            # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.

    A secret name is a Secret Manager secret ID - 1-255 ASCII letters, digits, hyphens and
    underscores - optionally with a key after ``#``: ``"api-key"`` reads the latest version's whole
    payload, and ``"db-login#password"`` the password member of a payload holding a JSON object
    (written as api-key and db-login__password). A member's string is read as its text; a number,
    true or false as its JSON text. A payload that isn't UTF-8 text is refused with
    :class:`~hkdfguard.cache.InvalidSecretDataError`: the protector encrypts text. Each secret's
    latest version is read with AccessSecretVersion, so the principal needs only
    ``secretmanager.versions.access`` (the Secret Manager Secret Accessor role), never a list
    permission. On GKE, Workload Identity supplies the Application Default Credentials.

    A secret that doesn't exist, or has no versions (``NOT_FOUND``), or whose payload is empty is
    reported missing. Any other failure (permission denied, a disabled or destroyed latest version,
    Google unreachable, no credentials, the timeout passing) raises the client's
    :class:`google.api_core.exceptions.GoogleAPICallError` (or, for a credential that can't get a
    token, google-auth's exception). A payload whose CRC32C doesn't match the checksum Google returns,
    or a response naming a different secret, is refused with
    :class:`~hkdfguard.abstractions.CryptographicError`.

    **The payload never becomes ``bytes``.** As ``hkdfguard-cache-googlesecretmanager`` does, the
    writer makes AccessSecretVersion itself, on the client's gRPC channel, with a response
    deserializer of its own that reads the few fields it needs straight from the message gRPC
    received, copying the payload into a bytearray, which is encrypted and then zeroed - refused or
    not. The client's protobuf message, which would hold the payload in an immutable ``bytes``, is
    never built. Out of reach, as everywhere in Python: the message itself, which gRPC hands the
    deserializer as ``bytes``, and the transport's buffers below it.

    The client must use the gRPC transport (the default); only its channel is used, so every call is
    retried as the client retries AccessSecretVersion by default, all within ``timeout``.
    :meth:`create` makes a client of the writer's own, which :meth:`close` closes; a client passed in
    is never closed. :meth:`pull_secrets_async` reads through a future on the same channel, so it
    blocks neither the event loop nor a thread; cancelling it cancels the call.
    """

    MAX_SECRET_NAME_LENGTH: Final = 255
    """The longest ID Secret Manager accepts for a secret."""

    DEFAULT_TIMEOUT: Final = 60.0
    """How long a read may take by default, retries included, in seconds: the client's own default."""

    def __init__(self, client: SecretManagerServiceClient, project_id: str, protector: PipelineDataProtector, secret_names: Sequence[str], *,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        """A writer over a client the caller created, and closes. No call is made until the secrets are pulled.

        :param client: e.g. ``SecretManagerServiceClient()``. Its transport must be gRPC (the
            default). Only AccessSecretVersion is called.
        :param project_id: the project whose secrets are read: its ID or number
        :param protector: encrypts every value read. Owned by the caller: the writer never closes it.
        :param secret_names: the secrets to pull, each a secret ID with the key to read after ``#``
            if any. Copied: a later change to the sequence isn't seen.
        :param timeout: how long a read may take, retries included, in seconds
        :raises TypeError: ``client``, ``project_id``, ``protector`` or ``secret_names`` is ``None``
        :raises ValueError: ``project_id`` is empty, or holds anything but ASCII letters, digits,
            hyphens, dots and colons; the client's transport isn't gRPC; ``timeout`` isn't positive;
            or ``secret_names`` is empty, or holds ``None``, an ID Secret Manager can't hold (with a
            key), one whose file name isn't one FilePerSecretCache can read, or two with the same
            file name, in any case
        """
        if client is None:
            raise TypeError("client must not be None.")
        self._project_id = _check_project_id(project_id)
        self._timeout = _check_timeout(timeout)
        super().__init__(protector, secret_names, self.is_valid_secret_name)
        transport = client.transport
        if not isinstance(transport, SecretManagerServiceGrpcTransport):
            raise ValueError("The client's transport must be gRPC (SecretManagerServiceGrpcTransport), so the writer can take the payload out "
                             f"of the response before the client parses it; got {type(transport).__name__}.")
        self._client = client
        self._channel: grpc.Channel = transport.grpc_channel
        self._owns_client = False

    @classmethod
    def create(cls, project_id: str, protector: PipelineDataProtector, secret_names: Sequence[str], *, credentials: Credentials | None = None,
               client_options: ClientOptions | dict[str, Any] | None = None, timeout: float = DEFAULT_TIMEOUT) -> Self:
        """A writer reading secrets through a new gRPC client, which :meth:`close` closes: by default
        to the global endpoint, signed in with Application Default Credentials (Workload Identity on GKE).

        :param project_id: the project whose secrets are read: its ID or number
        :param protector: encrypts every value read. Owned by the caller: the writer never closes it.
        :param secret_names: the secrets to pull, each a secret ID with the key to read after ``#``
            if any. Copied: a later change to the sequence isn't seen.
        :param credentials: ``None`` for Application Default Credentials
        :param client_options: the client's options, e.g. ``{"api_endpoint": "secretmanager.europe-west1.rep.googleapis.com"}``
        :param timeout: how long a read may take, retries included, in seconds
        :raises TypeError: ``project_id``, ``protector`` or ``secret_names`` is ``None``
        :raises ValueError: as the constructor - the project ID checked before a client is created
        :raises google.auth.exceptions.DefaultCredentialsError: no credentials were given or found
        """
        _check_project_id(project_id)
        _check_timeout(timeout)
        client = SecretManagerServiceClient(credentials=credentials, transport="grpc", client_options=client_options)
        try:
            writer = cls(client, project_id, protector, secret_names, timeout=timeout)
        except BaseException:
            client.transport.close()  # type: ignore[no-untyped-call]
            raise
        writer._owns_client = True
        return writer

    @classmethod
    def is_valid_secret_name(cls, name: str | None) -> bool:
        """Whether Secret Manager accepts ``name`` as a secret ID: 1-:attr:`MAX_SECRET_NAME_LENGTH`
        ASCII letters, digits, hyphens and underscores."""
        if not isinstance(name, str) or not 0 < len(name) <= cls.MAX_SECRET_NAME_LENGTH:
            return False
        return all(_is_ascii_letter_or_digit(c) or c in "-_" for c in name)

    @staticmethod
    def crc32c(data: bytes | bytearray | memoryview) -> int:
        """CRC32C (Castagnoli), as Secret Manager checksums payloads."""
        return crc32c(data)

    def close(self) -> None:
        """Closes the client :meth:`create` made; a client passed in is left open. Safe to call more than once."""
        if self._owns_client:
            self._client.transport.close()  # type: ignore[no-untyped-call]

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """:raises google.api_core.exceptions.GoogleAPICallError: any Secret Manager failure but NOT_FOUND
        :raises CryptographicError: the payload doesn't match its CRC32C, or the response names a different secret
        :raises InvalidSecretDataError: the payload isn't UTF-8 text, or a JSON object payload holds a key twice
        """
        capture = ResponseCapture()
        try:
            call = gapic_v1.method.wrap_method(  # type: ignore[no-untyped-call]
                self._stub(capture), default_retry=self._retry(retry.Retry), default_timeout=self._timeout, client_info=DEFAULT_CLIENT_INFO)
            request, metadata = self._request(name)
            try:
                response = call(request, metadata=metadata)
            except core_exceptions.NotFound:
                # Missing: nothing handed over.
                return
            self._accept(response, name, requests, values)
        finally:
            # The payload gRPC was deserialized into, refused or not - a retried response's, and one
            # that arrives too late, included.
            capture.close()

    async def _read_secret_async(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
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
            self._accept(response, name, requests, values)
        finally:
            capture.close()

    def _accept(self, response: AccessedSecretVersion, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        # Checks the response and encrypts its payload - whole and by key - straight from the
        # bytearray it was parsed into, which the capture zeroes either way.
        _check_response(response, name)
        self._protect_secret(response.data, requests, values)

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
            # Cancelled by gRPC, not by this read (which would have cancelled result first).
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


def _check_response(response: AccessedSecretVersion, name: str) -> None:
    # The response must be a version of the secret asked for (its project comes back as a number, so
    # only the secret ID can be compared), and a payload must match its checksum.
    reported = _SECRET_VERSION_NAME.fullmatch(response.name)
    if reported is None or reported.group(1) != name:
        raise CryptographicError(f"Secret Manager answered a request for secret '{name}' with '{response.name}'.")
    # Secret Manager sends a checksum with every payload: data without one can't be told from data
    # corrupted in transit. No data at all (an empty or absent payload) is a missing secret.
    if response.data and (response.data_crc32c is None or response.data_crc32c != crc32c(response.data)):
        raise CryptographicError(f"The payload of secret '{name}' doesn't match its CRC32C, or has none: it was corrupted in transit.")
