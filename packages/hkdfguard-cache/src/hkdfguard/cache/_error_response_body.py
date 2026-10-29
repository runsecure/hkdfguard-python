"""Reads the error messages out of a secret store's JSON error response."""

from __future__ import annotations

from collections.abc import Buffer
from typing import Final

from hkdfguard.cache._body import ResponseBody
from hkdfguard.cache._json_reader import JsonReader, JsonToken, MalformedJsonError


class ErrorResponseBody:
    """Reads the error messages out of a secret store's JSON error response - one that holds nothing
    secret, such as HashiCorp Vault's ``{"errors":["permission denied"]}`` - with the same strict
    reader :class:`SecretJsonBody` uses, so a provider needs one JSON reading rule throughout. Never
    use it on a body that may hold a secret: it makes ``str``."""

    MAX_BODY_LENGTH: Final = 64 * 1024
    """The largest error body read; anything beyond it is ignored, and the body reads as not JSON."""

    @staticmethod
    def read_strings(body: ResponseBody, array_property: str) -> list[str] | None:
        """Reads ``body`` to its end (or :attr:`MAX_BODY_LENGTH` bytes) and returns the elements of
        its top-level ``array_property``: a string as its text, anything else as its JSON text.

        :param body: the whole body, or a stream to read it from; a stream is read but not closed
        :returns: the elements; empty if the body is a JSON object without that property; ``None`` if
            the body isn't a JSON object (a proxy's HTML page, say), or the property isn't an array
        :raises TypeError: ``body`` or ``array_property`` is ``None``
        :raises OSError: reading ``body`` failed
        """
        if body is None:
            raise TypeError("body must not be None.")
        if array_property is None:
            raise TypeError("array_property must not be None.")

        data = _read_limited(body, ErrorResponseBody.MAX_BODY_LENGTH)
        reader = JsonReader(data)
        try:
            if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
                return None

            found: list[str] = []
            while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
                is_array = reader.value_text_equals(array_property)
                reader.read()
                if not is_array:
                    reader.skip()
                elif reader.token() is not JsonToken.START_ARRAY:
                    return None
                else:
                    found = _elements(reader, data)

            # Anything after the object makes it not JSON.
            return None if reader.read() else found
        except MalformedJsonError:
            return None


def _read_limited(body: ResponseBody, limit: int) -> memoryview:
    if isinstance(body, Buffer):
        return memoryview(body).cast("B")[:limit]

    buffer = bytearray(limit)
    length = 0
    while length < limit and (read := body.readinto(memoryview(buffer)[length:])):
        length += read
    return memoryview(buffer)[:length]


def _elements(reader: JsonReader, data: memoryview) -> list[str]:
    elements: list[str] = []
    while reader.read() and reader.token() is not JsonToken.END_ARRAY:
        start = reader.token_start
        if reader.token() is JsonToken.STRING:
            elements.append(reader.get_string())
            continue

        reader.skip()
        elements.append(bytes(data[start:reader.bytes_consumed]).decode("utf-8", "replace"))
    return elements
