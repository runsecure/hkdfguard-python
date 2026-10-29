"""Takes a secret out of a JSON response body before an SDK can turn it into a ``str``."""

from __future__ import annotations

from collections.abc import Buffer, Sequence
from dataclasses import dataclass, field
from typing import Final

from hkdfguard.abstractions import ArrayUtility
from hkdfguard.cache._body import ResponseBody
from hkdfguard.cache._errors import InvalidSecretDataError
from hkdfguard.cache._json_reader import JsonReader, JsonToken, MalformedJsonError
from hkdfguard.cache._remote_secret_cache import SecretValueSink
from hkdfguard.cache._secret_json_keys import set_keys

_BASE64: Final = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_VALUES: Final = {c: i for i, c in enumerate(_BASE64)}
_PAD: Final = ord("=")


class SecretJsonBody:
    """Takes a secret out of a JSON response body before an SDK can turn it into a ``str``. A stream
    body is read into a bytearray of the library's own; the named string property is unescaped (and
    base64-decoded, for a binary property) straight into another and handed to a
    :class:`SecretValueSink`; and what's returned is the same body with that value replaced by
    ``""`` - for the SDK to parse as usual, holding nothing secret. Every bytearray that held the
    value is zeroed before returning.

    Not erased, because Python can't: a body passed in as ``bytes`` (read in place, never copied, and
    left as it is - the caller should zero a ``bytearray`` it passes once done), the HTTP stack's own
    buffers, and the small ints CPython makes for each byte as it is unescaped or decoded.
    """

    MAX_BODY_LENGTH: Final = 1024 * 1024
    """The largest body read: far beyond any secret store's response, so a larger one is refused."""

    _INITIAL_BUFFER_LENGTH: Final = 16 * 1024

    @staticmethod
    def capture(body: ResponseBody, value: SecretValueSink, text_property: str, base64_property: str | None = None, *,
                object_path: Sequence[str] = ()) -> bytes:
        """Reads ``body`` to its end and hands the value of its ``text_property`` (as UTF-8 bytes,
        with :meth:`SecretValueSink.set_bytes_with_json_keys`, so a JSON object's members are keys
        too) - or, when the body holds ``base64_property`` instead, the bytes it encodes, whole - to
        ``value``, and returns the body with both values replaced by ``""``. The properties are looked
        for at the top level, or in the object reached through ``object_path``'s property names -
        ``["data", "data"]`` for ``{"data":{"data":{"value":"..."}}}``. A missing, null or empty
        property, or a path that leads to no object, hands nothing over. A stream is read but not closed.

        :param body: the whole body, or a stream to read it from
        :param base64_property: ``None`` for none
        :returns: the body, redacted
        :raises TypeError: ``body`` or ``value`` is ``None``
        :raises ValueError: ``text_property``, or a name in ``object_path``, is ``None`` or empty
        :raises InvalidSecretDataError: ``body`` isn't a JSON object, is :attr:`MAX_BODY_LENGTH`
            bytes or more, or holds more than one non-empty secret value; the base64 value isn't
            base64; or the value is a JSON object holding a member name more than once
        :raises OSError: reading ``body`` failed
        """
        if not text_property:
            raise ValueError("The text property is None or empty.")
        target = _Target(text_property, base64_property, value)
        return SecretJsonBody._read(body, value, object_path, target)

    @staticmethod
    def capture_keys(body: ResponseBody, value: SecretValueSink, object_path: Sequence[str]) -> None:
        """Reads ``body`` to its end and hands each member of the object reached through
        ``object_path``'s property names to ``value`` as a key, as
        :meth:`SecretValueSink.set_bytes_with_json_keys` describes - for a store whose secrets are
        sets of keys, such as HashiCorp Vault's KV: ``["data", "data"]`` for
        ``{"data":{"data":{"username":"...","password":"..."}}}``. A path that leads to no object
        hands nothing over. A stream is read but not closed.

        :raises TypeError: ``body`` or ``value`` is ``None``
        :raises ValueError: a name in ``object_path`` is ``None`` or empty
        :raises InvalidSecretDataError: ``body`` isn't a JSON object, or is :attr:`MAX_BODY_LENGTH`
            bytes or more; or the object holds a member name more than once
        :raises OSError: reading ``body`` failed
        """
        SecretJsonBody._read(body, value, object_path, _Target(None, None, value))

    @staticmethod
    def _read(body: ResponseBody, value: SecretValueSink, object_path: Sequence[str], target: _Target) -> bytes:
        # Reads body and walks it for target; returns the body redacted, for a target with a text property.
        if body is None:
            raise TypeError("body must not be None.")
        if value is None:
            raise TypeError("value must not be None.")
        if object_path is None:
            raise TypeError("object_path must not be None.")
        path = tuple(object_path)
        if not all(path):
            raise ValueError("A property name in the path is None or empty.")

        if isinstance(body, Buffer):
            view = memoryview(body).cast("B")
            if len(view) >= SecretJsonBody.MAX_BODY_LENGTH:
                raise InvalidSecretDataError(f"The response body is {SecretJsonBody.MAX_BODY_LENGTH} bytes or more.")
            return SecretJsonBody._parse(view, len(view), path, target)

        buffer = bytearray(SecretJsonBody._INITIAL_BUFFER_LENGTH)
        length = 0
        try:
            while read := body.readinto(memoryview(buffer)[length:]):
                length += read
                buffer = SecretJsonBody._grow_if_full(buffer, length)
            return SecretJsonBody._parse(buffer, length, path, target)
        finally:
            ArrayUtility.zero_memory(buffer)

    @staticmethod
    def _grow_if_full(buffer: bytearray, length: int) -> bytearray:
        # buffer, or once it's full a new one twice its size, the original zeroed. Never resized in
        # place: a reallocation could leave a copy of the body behind.
        if length < len(buffer):
            return buffer
        if len(buffer) >= SecretJsonBody.MAX_BODY_LENGTH:
            raise InvalidSecretDataError(f"The response body is {SecretJsonBody.MAX_BODY_LENGTH} bytes or more.")

        larger = bytearray(min(len(buffer) * 2, SecretJsonBody.MAX_BODY_LENGTH))
        memoryview(larger)[:length] = buffer
        ArrayUtility.zero_memory(buffer)
        return larger

    @staticmethod
    def _parse(json: Buffer, length: int, path: tuple[str, ...], target: _Target) -> bytes:
        reader = JsonReader(json, length)
        malformed: MalformedJsonError | None = None
        try:
            if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
                raise InvalidSecretDataError("The response body isn't a JSON object.")
            _read_object(reader, path, target)
        except MalformedJsonError as error:
            malformed = error
        if malformed is not None:
            # Raised here, so nothing is chained, and never quoting the byte rejected, which may be in the secret.
            raise InvalidSecretDataError(f"The response body isn't valid JSON (at byte {malformed.position} of line {malformed.line}).")

        return b"" if target.text_property is None else _redact(memoryview(json).cast("B"), length, target.secrets)


@dataclass(slots=True)
class _Target:
    # What one read looks for - a text (and base64) property, or, with no text property, every member
    # as a key - and what it has found so far.
    text_property: str | None
    base64_property: str | None
    value: SecretValueSink
    secrets: list[tuple[int, int]] = field(default_factory=list)
    keys: set[str] = field(default_factory=set)
    handed_over: bool = False


def _read_object(reader: JsonReader, path: tuple[str, ...], target: _Target) -> None:
    # Reads the properties of the object reader is at the start of, descending path; returns with
    # reader at its end.
    if not path and target.text_property is None:
        set_keys(reader, target.value, target.keys)
        return

    while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
        if path:
            is_parent = reader.value_text_equals(path[0])
            reader.read()
            if is_parent and reader.token() is JsonToken.START_OBJECT:
                _read_object(reader, path[1:], target)
            else:
                reader.skip()
            continue

        _read_property(reader, target)


def _read_property(reader: JsonReader, target: _Target) -> None:
    # Reads the property reader is at the name of, in the object holding the secret.
    assert target.text_property is not None
    is_text = reader.value_text_equals(target.text_property)
    is_base64 = not is_text and target.base64_property is not None and reader.value_text_equals(target.base64_property)
    reader.read()

    if not (is_text or is_base64) or reader.token() is not JsonToken.STRING:
        reader.skip()
        return

    if reader.value_length > 0:
        if target.handed_over:
            raise InvalidSecretDataError("The response body holds more than one secret value.")

        _hand_over(reader, is_base64, target.value)
        target.handed_over = True

    target.secrets.append((reader.token_start, reader.bytes_consumed))


def _hand_over(reader: JsonReader, is_base64: bool, value: SecretValueSink) -> None:
    # Unescaped, a string is never longer than it is escaped.
    text = bytearray(reader.value_length)
    decoded: bytearray | None = None
    try:
        text_length = reader.copy_string(text)
        if not is_base64:
            value.set_bytes_with_json_keys(memoryview(text)[:text_length])
            return

        decoded = bytearray(text_length // 4 * 3 + 3)
        written = _decode_base64(memoryview(text)[:text_length], memoryview(decoded))
        if written < 0:
            raise InvalidSecretDataError("The response body's binary secret value isn't base64.")
        value.set_bytes(memoryview(decoded)[:written])
    finally:
        ArrayUtility.zero_memory(text)
        ArrayUtility.zero_memory(decoded)


def _decode_base64(encoded: memoryview, destination: memoryview) -> int:
    # Standard base64 (RFC 4648 section 4) into destination, as strictly as Java's Base64.getDecoder():
    # no whitespace or other characters, and padding, if any, complete. Decoded here rather than by
    # binascii, which returns immutable bytes. Returns the bytes written, or -1 if encoded isn't base64.
    length = len(encoded)
    padding = 0
    if length > 0 and encoded[length - 1] == _PAD:
        padding = 2 if length > 1 and encoded[length - 2] == _PAD else 1
    data_length = length - padding
    if (padding > 0 and length % 4 != 0) or data_length % 4 == 1:
        return -1

    accumulated = 0
    bits = 0
    written = 0
    for i in range(data_length):
        sextet = _BASE64_VALUES.get(encoded[i])
        if sextet is None:
            return -1
        accumulated = ((accumulated << 6) | sextet) & 0xFFFF
        bits += 6
        if bits >= 8:
            bits -= 8
            destination[written] = (accumulated >> bits) & 0xFF
            written += 1
    return written


def _redact(json: memoryview, length: int, secrets: list[tuple[int, int]]) -> bytes:
    # The body with each secret value's token - its quotes included - replaced by "".
    redacted = bytearray()
    start = 0
    for token_start, token_end in secrets:
        redacted += json[start:token_start]
        redacted += b'""'
        start = token_end
    redacted += json[start:length]
    return bytes(redacted)
