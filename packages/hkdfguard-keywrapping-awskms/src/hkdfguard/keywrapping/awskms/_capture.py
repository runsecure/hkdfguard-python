"""Takes the revealed DEK out of a KMS Decrypt response body, before botocore parses - and logs - it."""

from __future__ import annotations

from collections.abc import Buffer, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Final

from hkdfguard.abstractions import ArrayUtility, CryptographicError, JsonReader, JsonToken, MalformedJsonError

PLAINTEXT_PROPERTY: Final = "Plaintext"

EVENT_NAME: Final = "before-parse.kms.Decrypt"
"""The botocore event the capture handles: emitted by the endpoint once per attempt, after the body has
been read and before the response parser - which logs the whole body at DEBUG - turns it into a dict."""

HANDLER_ID: Final = "hkdfguard.keywrapping.awskms.capture"
"""The handler's unique id on a client's event system, so it is registered there only once however many
wrappers share the client."""

MAX_BODY_LENGTH: Final = 64 * 1024
"""The largest Decrypt body read: a DEK of at most 4096 bytes, base64-encoded, and a key ARN fit many times over."""

_BASE64_VALUES: Final = {c: i for i, c in enumerate(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}
_PAD: Final = ord("=")


class PlaintextCapture:
    """The capture of one Decrypt call made by :class:`AwsKmsKeyWrapper`: :attr:`plaintext` holds the
    revealed key once a successful response has passed through :func:`redact_response`, in a bytearray
    the wrapper zeroes. Active only while :func:`active` holds it, in the thread (or task) making the call."""

    def __init__(self) -> None:
        self.plaintext: bytearray | None = None

    def capture(self, body: Any) -> bytes:
        """Decodes the ``Plaintext`` of ``body`` into :attr:`plaintext` and returns the body with it
        replaced by ``""``.

        :raises CryptographicError: the body isn't one JSON object with exactly one base64 ``Plaintext``
        """
        if not isinstance(body, Buffer):
            raise CryptographicError("AWS KMS answered Decrypt with a body this wrapper can't read.")
        view = memoryview(body).cast("B")
        if len(view) > MAX_BODY_LENGTH:
            raise CryptographicError(f"AWS KMS answered Decrypt with a body over {MAX_BODY_LENGTH} bytes.")

        reader = JsonReader(view)
        span: tuple[int, int] | None = None
        try:
            if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
                raise CryptographicError("AWS KMS answered Decrypt with a body that isn't a JSON object.")
            while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
                is_plaintext = reader.value_text_equals(PLAINTEXT_PROPERTY)
                reader.read()
                if not is_plaintext:
                    reader.skip()
                    continue
                if span is not None:
                    raise CryptographicError("AWS KMS answered Decrypt with more than one Plaintext.")
                if reader.token() is not JsonToken.STRING:
                    raise CryptographicError("AWS KMS answered Decrypt with a Plaintext that isn't a string.")
                self._decode(reader)
                span = (reader.token_start, reader.bytes_consumed)
            if reader.read():
                raise CryptographicError("AWS KMS answered Decrypt with something after its JSON object.")
        except MalformedJsonError:
            # Never chained or quoted: the byte refused may be part of the key.
            self._clear()
            raise CryptographicError("AWS KMS answered Decrypt with a body that isn't valid JSON.") from None
        except BaseException:
            self._clear()
            raise

        if span is None:
            return bytes(view)
        return bytes(view[:span[0]]) + b'""' + bytes(view[span[1]:])

    def _decode(self, reader: JsonReader) -> None:
        text = bytearray(reader.value_length)
        try:
            length = reader.copy_string(text)
            decoded = bytearray(length // 4 * 3)
            written = _decode_base64(memoryview(text)[:length], decoded)
            if written < 0:
                ArrayUtility.zero_memory(decoded)
                raise CryptographicError("AWS KMS answered Decrypt with a Plaintext that isn't base64.")
            self._clear()
            self.plaintext = decoded if written == len(decoded) else _trimmed(decoded, written)
        finally:
            ArrayUtility.zero_memory(text)

    def _clear(self) -> None:
        ArrayUtility.zero_memory(self.plaintext)
        self.plaintext = None


def _trimmed(decoded: bytearray, length: int) -> bytearray:
    # A copy of the first length bytes; the original is zeroed rather than resized in place, which
    # could leave a copy behind.
    result = bytearray(length)
    result[:] = memoryview(decoded)[:length]
    ArrayUtility.zero_memory(decoded)
    return result


def _decode_base64(encoded: memoryview, destination: bytearray) -> int:
    # Standard, padded base64 (RFC 4648 section 4) - what KMS writes - decoded four characters at a
    # time. Every intermediate value is below 256, so CPython hands out its cached small ints and no
    # heap integer ever holds a piece of the key. Returns the bytes written, or -1 if it isn't base64.
    length = len(encoded)
    if length % 4 != 0:
        return -1
    written = 0
    for i in range(0, length, 4):
        last = i + 4 == length
        pad = 0
        if last and encoded[i + 3] == _PAD:
            pad = 2 if encoded[i + 2] == _PAD else 1
        s0 = _BASE64_VALUES.get(encoded[i])
        s1 = _BASE64_VALUES.get(encoded[i + 1])
        s2 = 0 if pad == 2 else _BASE64_VALUES.get(encoded[i + 2])
        s3 = 0 if pad >= 1 else _BASE64_VALUES.get(encoded[i + 3])
        if s0 is None or s1 is None or s2 is None or s3 is None:
            return -1
        destination[written] = ((s0 << 2) & 0xFC) | (s1 >> 4)
        written += 1
        if pad < 2:
            destination[written] = ((s1 & 0x0F) << 4) | (s2 >> 2)
            written += 1
        if pad < 1:
            destination[written] = ((s2 & 0x03) << 6) | s3
            written += 1
    return written


# The capture of the Decrypt call the current thread (or task) is making, if a wrapper is making one.
# A ContextVar, so concurrent calls through one shared client never see each other's.
_ACTIVE: Final[ContextVar[PlaintextCapture | None]] = ContextVar("hkdfguard_aws_kms_capture", default=None)


@contextmanager
def active(capture: PlaintextCapture) -> Iterator[None]:
    """Makes ``capture`` the one :func:`redact_response` uses, for calls made in this context until exit."""
    token = _ACTIVE.set(capture)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def redact_response(response_dict: dict[str, Any] | None = None, **_: Any) -> None:
    """The ``before-parse`` handler: when this context is making a wrapper's Decrypt and the response
    succeeded, replaces the body botocore is about to parse and log with the redacted one; otherwise -
    the application's own calls on the client, error responses - leaves it as it is."""
    capture = _ACTIVE.get()
    if capture is None or response_dict is None:
        return
    status = response_dict.get("status_code")
    if not isinstance(status, int) or status >= 300:
        return
    response_dict["body"] = capture.capture(response_dict.get("body"))
