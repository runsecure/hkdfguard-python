"""Hands a JSON object's members to a SecretValueSink as keys, never as ``str``: each value is
unescaped (or, for a number, true or false, copied) into a bytearray of its own, handed over, and
zeroed."""

from __future__ import annotations

from collections.abc import Buffer
from typing import TYPE_CHECKING

from hkdfguard.abstractions import ArrayUtility, JsonReader, JsonToken, MalformedJsonError
from hkdfguard.cache._errors import InvalidSecretDataError
from hkdfguard.cache._secret_names import is_valid_key

if TYPE_CHECKING:
    from hkdfguard.cache._remote_secret_cache import SecretValueSink

_KEY_VALUE_TOKENS = (JsonToken.STRING, JsonToken.NUMBER, JsonToken.TRUE, JsonToken.FALSE)


def try_set_keys(json: Buffer, value: SecretValueSink) -> None:
    """When ``json`` is exactly one JSON object, hands each of its members over as a key; anything
    else - plain text that merely starts like JSON included - hands nothing over. The whole value is
    checked first, so malformed JSON never hands over part of its members."""
    if not _is_object(json):
        return

    reader = JsonReader(json)
    reader.read()
    set_keys(reader, value, set())


def set_keys(reader: JsonReader, value: SecretValueSink, seen: set[str]) -> None:
    """Hands each member of the object ``reader`` is at the start of over as a key, leaving
    ``reader`` at its end. A string is handed over as its UTF-8 bytes; a number, true or false as its
    JSON text; null, an object, an array, an empty string, or a member whose name isn't a key a name
    can hold, isn't handed over. ``seen`` collects the member names, across every object handed over
    for one secret.

    :raises InvalidSecretDataError: a member name is in ``seen`` already
    """
    while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
        key = reader.get_string()
        # Not named: a key is part of a lookup name, logged only with sensitive logging on.
        if key in seen:
            raise InvalidSecretDataError("The secret holds a key more than once.")
        seen.add(key)

        reader.read()
        if is_valid_key(key) and reader.token() in _KEY_VALUE_TOKENS:
            _set_key(reader, key, value)
        else:
            reader.skip()


def _set_key(reader: JsonReader, key: str, value: SecretValueSink) -> None:
    # Unescaped, a string is never longer than it is escaped; anything else is copied as it is.
    buffer = bytearray(reader.value_length)
    try:
        length = reader.copy_string(buffer) if reader.token() is JsonToken.STRING else reader.copy_raw(buffer)
        value.set_key_bytes(key, memoryview(buffer)[:length])
    finally:
        ArrayUtility.zero_memory(buffer)


def _is_object(json: Buffer) -> bool:
    # One JSON object and nothing after it but whitespace.
    reader = JsonReader(json)
    try:
        if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
            return False

        reader.skip()
        return not reader.read()
    except MalformedJsonError:
        return False
