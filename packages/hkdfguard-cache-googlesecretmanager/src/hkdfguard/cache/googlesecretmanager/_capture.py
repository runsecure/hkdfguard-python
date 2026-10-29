"""Reads an AccessSecretVersion response straight from gRPC's received bytes, so the secret payload
lands only in a bytearray HkdfGuard zeroes - never in a protobuf or proto-plus message's ``bytes``."""

from __future__ import annotations

import threading
from collections.abc import Buffer
from typing import Final

from hkdfguard.abstractions import ArrayUtility

# Protobuf wire types.
_VARINT: Final = 0
_FIXED64: Final = 1
_LENGTH_DELIMITED: Final = 2
_FIXED32: Final = 5

# AccessSecretVersionResponse: string name = 1; SecretPayload payload = 2.
_RESPONSE_NAME: Final = 1
_RESPONSE_PAYLOAD: Final = 2
# SecretPayload: bytes data = 1; optional int64 data_crc32c = 2.
_PAYLOAD_DATA: Final = 1
_PAYLOAD_DATA_CRC32C: Final = 2

_UINT64_LIMIT: Final = 1 << 64
_INT64_SIGN: Final = 1 << 63


def _crc32c_table() -> tuple[int, ...]:
    table = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC32C_TABLE: Final = _crc32c_table()


def crc32c(data: Buffer) -> int:
    """CRC32C (Castagnoli), as Secret Manager checksums payloads. Computed here, a byte at a time: the
    standard library has none, and a payload is at most 64 KiB."""
    crc = 0xFFFFFFFF
    table = _CRC32C_TABLE
    with memoryview(data) as raw, raw.cast("B") as source:
        for byte in source:
            crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


class MalformedResponseError(ValueError):
    """The bytes gRPC received aren't an AccessSecretVersionResponse. Says where, never what: no part
    of the message is quoted. Raised inside gRPC's deserializer, which turns it into an ``INTERNAL``
    status, as a malformed message is for any gRPC client."""


class AccessedSecretVersion:
    """What an AccessSecretVersion response holds, as the cache needs it: the version's resource
    name, its payload's ``data`` in a bytearray of the cache's own, and ``data_crc32c`` (``None`` when
    the response has none). :meth:`zero` erases the payload; its repr never shows it."""

    __slots__ = ("data", "data_crc32c", "name")

    def __init__(self) -> None:
        self.name = ""
        self.data = bytearray()
        self.data_crc32c: int | None = None

    def zero(self) -> None:
        """Zeroes the payload."""
        ArrayUtility.zero_memory(self.data)

    def __repr__(self) -> str:
        return f"AccessedSecretVersion(name={self.name!r}, data=<{len(self.data)} bytes>, data_crc32c={self.data_crc32c!r})"


def parse_access_response(raw: Buffer) -> AccessedSecretVersion:
    """Parses a serialized AccessSecretVersionResponse as protobuf does - fields in any order, a
    repeated message merged, a repeated scalar's last value kept, unknown fields skipped - copying the
    payload straight from ``raw`` into a bytearray (through a memoryview, so no ``bytes`` copy is ever
    made). A payload left behind by a later occurrence, or by a failure, is zeroed.

    :raises MalformedResponseError: ``raw`` isn't a well-formed AccessSecretVersionResponse
    """
    version = AccessedSecretVersion()
    try:
        with memoryview(raw) as outer, outer.cast("B") as view:
            _parse_response(view, version)
    except BaseException:
        version.zero()
        raise
    return version


def _parse_response(view: memoryview, version: AccessedSecretVersion) -> None:
    position, end = 0, len(view)
    while position < end:
        field, wire_type, position = _read_tag(view, position, end)
        if field == _RESPONSE_NAME:
            start, position = _read_length_delimited(view, position, end, wire_type, "name")
            try:
                version.name = str(view[start:position], "utf-8")
            except UnicodeDecodeError:
                raise MalformedResponseError("The response's name isn't UTF-8.") from None
        elif field == _RESPONSE_PAYLOAD:
            start, position = _read_length_delimited(view, position, end, wire_type, "payload")
            _parse_payload(view, start, position, version)
        else:
            position = _skip(view, position, end, wire_type)


def _parse_payload(view: memoryview, position: int, end: int, version: AccessedSecretVersion) -> None:
    while position < end:
        field, wire_type, position = _read_tag(view, position, end)
        if field == _PAYLOAD_DATA:
            start, position = _read_length_delimited(view, position, end, wire_type, "payload data")
            # A later occurrence replaces the earlier one, which is erased first.
            version.zero()
            version.data = bytearray(view[start:position])
        elif field == _PAYLOAD_DATA_CRC32C:
            if wire_type != _VARINT:
                raise MalformedResponseError("The payload's data_crc32c isn't a varint.")
            value, position = _read_varint(view, position, end)
            version.data_crc32c = value - _UINT64_LIMIT if value >= _INT64_SIGN else value
        else:
            position = _skip(view, position, end, wire_type)


def _read_tag(view: memoryview, position: int, end: int) -> tuple[int, int, int]:
    tag, position = _read_varint(view, position, end)
    field = tag >> 3
    if field == 0 or field > 0x1FFFFFFF:
        raise MalformedResponseError("The response holds an invalid field number.")
    return field, tag & 7, position


def _read_varint(view: memoryview, position: int, end: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if position >= end:
            raise MalformedResponseError("The response ends inside a varint.")
        byte = view[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value >= _UINT64_LIMIT:
                raise MalformedResponseError("The response holds a varint over 64 bits.")
            return value, position
    raise MalformedResponseError("The response holds a varint over 10 bytes.")


def _read_length_delimited(view: memoryview, position: int, end: int, wire_type: int, what: str) -> tuple[int, int]:
    # The field's first byte and the position just past it.
    if wire_type != _LENGTH_DELIMITED:
        raise MalformedResponseError(f"The response's {what} isn't length-delimited.")
    length, position = _read_varint(view, position, end)
    if length > end - position:
        raise MalformedResponseError(f"The response's {what} runs past the end of its message.")
    return position, position + length


def _skip(view: memoryview, position: int, end: int, wire_type: int) -> int:
    if wire_type == _VARINT:
        return _read_varint(view, position, end)[1]
    if wire_type == _FIXED64:
        size = 8
    elif wire_type == _FIXED32:
        size = 4
    elif wire_type == _LENGTH_DELIMITED:
        return _read_length_delimited(view, position, end, wire_type, "unknown field")[1]
    else:
        # Groups (3, 4) are proto2 only; 6 and 7 aren't wire types.
        raise MalformedResponseError(f"The response holds a field of wire type {wire_type}.")
    if size > end - position:
        raise MalformedResponseError("The response ends inside a fixed-size field.")
    return position + size


class ResponseCapture:
    """The response deserializer for one fetch's AccessSecretVersion calls, and the place every
    response it parsed is kept until :meth:`close` zeroes them - a retry's, or one that arrived after
    the fetch was cancelled, included. Once closed it parses nothing: a response gRPC delivers later
    is never copied out of gRPC's own bytes. Thread-safe: gRPC deserializes a future's response on
    its own thread."""

    def __init__(self) -> None:
        self._versions: list[AccessedSecretVersion] = []
        self._closed = False
        self._lock = threading.Lock()

    def deserialize(self, raw: bytes) -> AccessedSecretVersion:
        """gRPC's ``response_deserializer``: ``raw`` is gRPC's immutable copy of the message, which
        nothing can zero.

        :raises MalformedResponseError: ``raw`` isn't an AccessSecretVersionResponse
        """
        with self._lock:
            if self._closed:
                return AccessedSecretVersion()
            version = parse_access_response(raw)
            self._versions.append(version)
            return version

    def close(self) -> None:
        """Zeroes every payload parsed, and parses nothing more."""
        with self._lock:
            self._closed = True
            for version in self._versions:
                version.zero()
