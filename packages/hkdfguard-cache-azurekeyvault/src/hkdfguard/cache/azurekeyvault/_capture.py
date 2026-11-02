"""The azure-core pipeline policy that takes a secret out of a Get Secret response before
SecretClient can turn it into a ``str``."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

from azure.core.exceptions import ResponseNotReadError
from azure.core.pipeline import PipelineRequest, PipelineResponse
from azure.core.pipeline.policies import HTTPPolicy
from azure.core.rest import HttpRequest, HttpResponse
from hkdfguard.cache import SecretJsonBody, SecretValueSink

CAPTURE_OPTION: Final = "hkdfguard_secret_capture"
"""The per-request keyword a fetch's :class:`Capture` travels under: passed to
``SecretClient.get_secret``, it reaches the pipeline as one of the request's context options, which
:class:`SecretCapturePolicy` takes out before anything can hand it to the transport."""


class Capture:
    """One fetch's sink, and whether its response reached it."""

    __slots__ = ("captured", "sink")

    def __init__(self, sink: SecretValueSink) -> None:
        if sink is None:
            raise TypeError("sink must not be None.")
        self.sink = sink
        self.captured = False
        """Whether a 200 response passed through the policy, so its value, if any, went to the sink."""


class SecretCapturePolicy(HTTPPolicy[HttpRequest, HttpResponse]):
    """Takes the secret out of a Get Secret response before SecretClient can turn it into a ``str``.
    Acts only on a request made with a :class:`Capture` under :data:`CAPTURE_OPTION`; every other
    request passes through untouched. Stateless: the capture travels in each request's own pipeline
    context, so one client can run any number of fetches at once, from any threads.

    A per-retry policy - after the retry policy, so it runs on every attempt - placed after any
    per-retry policy of the application's, so those see only the redacted body. For a capturing
    request it sets the context's ``stream`` option, so the transport hands the body over unread
    (requests doesn't read it into ``Response.content``, and azure-core doesn't buffer it) - which
    also makes azure-core's NetworkTraceLoggingPolicy, which sits closer to the network, log "Body is
    streamable" rather than the body, even with ``logging_enable``. A 200's body is then read,
    decompressed, through ``iter_bytes`` into :class:`SecretJsonBody`'s bytearray, its top-level
    ``value`` handed to the capture's sink (a JSON object's members as keys too), and the response's
    content replaced by the body with ``value`` blanked, which is what SecretClient deserializes.
    Any other status is read in full, as azure-core would have read it, for SecretClient's error
    handling.

    Not erased, because Python can't: each chunk ``iter_bytes`` yields is an immutable ``bytes``
    (made by urllib3, and by its decompressor for an encoded body) copied into the bytearray and then
    dropped, but never zeroed; a transport that buffers the body regardless hands it over as an
    immutable ``bytes``, which is read in place; and the HTTP stack's own buffers (TLS decryption,
    socket reads). Every bytearray this library makes is zeroed.
    """

    def send(self, request: PipelineRequest[HttpRequest]) -> PipelineResponse[HttpRequest, HttpResponse]:
        capture = _streamed(request)
        response = self.next.send(request)
        if capture is None:
            return response

        http_response = response.http_response
        if http_response.status_code != 200:
            http_response.read()
            return response

        try:
            redacted = SecretJsonBody.capture(_body_of(http_response), capture.sink, "value")
        finally:
            http_response.close()
        _replace_content(http_response, redacted)
        capture.captured = True
        return response


def _streamed(request: PipelineRequest[HttpRequest]) -> Capture | None:
    # The request's capture, if it has one, its response then left unread by the transport. On the
    # first attempt the capture is moved out of the options, which the transport is handed as keyword
    # arguments, into the context itself, where every later attempt finds it.
    context = request.context
    capture = context.options.pop(CAPTURE_OPTION, None)
    if capture is not None:
        context[CAPTURE_OPTION] = capture
    else:
        capture = context.get(CAPTURE_OPTION)
    if capture is None:
        return None
    if not isinstance(capture, Capture):
        raise TypeError(f"{CAPTURE_OPTION} must be a Capture.")

    context.options["stream"] = True
    return capture


def _body_of(response: HttpResponse) -> bytes | _ChunkReader:
    # The body as the transport left it: already read, if it buffered the body regardless of the
    # stream option, else a reader over its chunks.
    try:
        return response.content
    except ResponseNotReadError:
        return _ChunkReader(response.iter_bytes())


def _replace_content(response: HttpResponse, body: bytes) -> None:
    # azure-core's rest responses, sync and async, hold what read() returned in _content, and
    # content, text() and json() read it from there.
    if not hasattr(response, "_content"):
        raise TypeError(f"{type(response).__name__} isn't an azure-core rest response, whose body the capture can replace.")
    response._content = body
    if "Content-Length" in response.headers:
        response.headers["Content-Length"] = str(len(body))
    # iter_bytes decompressed the body, so it is no longer encoded.
    response.headers.pop("Content-Encoding", None)


class _ChunkReader:
    """A :class:`hkdfguard.cache.ReadableBody` over the chunks ``HttpResponse.iter_bytes`` yields."""

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._chunks = chunks
        self._chunk = b""
        self._offset = 0

    def readinto(self, buffer: memoryview, /) -> int:
        while self._offset >= len(self._chunk):
            chunk = next(self._chunks, None)
            if chunk is None:
                self._chunk = b""
                return 0
            self._chunk, self._offset = chunk, 0

        count = min(len(buffer), len(self._chunk) - self._offset)
        buffer[:count] = memoryview(self._chunk)[self._offset:self._offset + count]
        self._offset += count
        return count
