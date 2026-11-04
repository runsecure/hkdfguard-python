"""A small BER/DER reader and DER writer, enough for PKCS#12 and PKCS#8.

The reader never copies: every element is a ``memoryview`` slice of the buffer it was read from, so
decrypted contents can be parsed where they lie and wiped once used. It reads BER as well as DER -
indefinite lengths and constructed strings, as NSS and older Java tools write PKCS#12 files - and
:func:`octets` joins a constructed OCTET STRING's segments into a new buffer the caller wipes."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

BOOLEAN: Final = 0x01
INTEGER: Final = 0x02
BIT_STRING: Final = 0x03
OCTET_STRING: Final = 0x04
NULL: Final = 0x05
OBJECT_IDENTIFIER: Final = 0x06
UTF8_STRING: Final = 0x0C
SEQUENCE: Final = 0x30
SET: Final = 0x31
CONTEXT_0: Final = 0xA0  # [0], constructed

_CONSTRUCTED: Final = 0x20
_MAX_DEPTH: Final = 32


class DerError(ValueError):
    """The bytes aren't the ASN.1 they were read as."""


@dataclass(frozen=True, slots=True)
class Element:
    """One element: its identifier octet (``tag``; a high tag number is folded above 0xFF), whether
    it is constructed, its contents - for an indefinite length, up to its end-of-contents - and its
    whole encoding."""

    tag: int
    constructed: bool
    contents: memoryview
    encoding: memoryview
    indefinite: bool = False

    @property
    def number(self) -> int:
        """The tag's class and number, without the constructed bit: [0] is 0x80 either way."""
        return self.tag & ~_CONSTRUCTED

    def children(self) -> list[Element]:
        """The elements a constructed element holds."""
        if not self.constructed:
            raise DerError(f"A primitive element (tag 0x{self.tag:02X}) holds no elements.")
        return list(_elements(self.contents, 0))

    def expect(self, tag: int, what: str) -> Element:
        """``self``, if it has ``tag``."""
        if self.tag != tag:
            raise DerError(f"{what} isn't tag 0x{tag:02X} but 0x{self.tag:02X}.")
        return self


def read(data: memoryview | bytes | bytearray) -> Element:
    """The one element ``data`` holds, refusing anything after it."""
    view = memoryview(data).cast("B") if not isinstance(data, memoryview) or data.format != "B" else data
    element, end = _read(view, 0, 0)
    if end != len(view):
        raise DerError("There is data after the element.")
    return element


def _read(view: memoryview, offset: int, depth: int) -> tuple[Element, int]:  # noqa: PLR0912 - one TLV, every case of it
    if depth > _MAX_DEPTH:
        raise DerError("The elements are nested too deep.")
    start = offset
    if offset + 2 > len(view):
        raise DerError("An element is truncated.")
    first = view[offset]
    offset += 1
    tag = first
    if first & 0x1F == 0x1F:  # a high tag number, in base-128 octets
        number = 0
        while True:
            if offset >= len(view):
                raise DerError("A tag is truncated.")
            octet = view[offset]
            offset += 1
            number = (number << 7) | (octet & 0x7F)
            if number > 0xFFFFFF:
                raise DerError("A tag number is too large.")
            if not octet & 0x80:
                break
        tag = (first & 0xE0) | (number << 8) | 0x1F
    constructed = bool(first & _CONSTRUCTED)

    if offset >= len(view):
        raise DerError("A length is truncated.")
    length_octet = view[offset]
    offset += 1
    if length_octet == 0x80:
        if not constructed:
            raise DerError("A primitive element has an indefinite length.")
        contents_start = offset
        while True:  # its elements, up to the end-of-contents octets 00 00
            if offset + 2 > len(view):
                raise DerError("An indefinite length has no end-of-contents.")
            if view[offset] == 0 and view[offset + 1] == 0:
                contents = view[contents_start:offset]
                offset += 2
                return Element(tag, True, contents, view[start:offset], indefinite=True), offset
            _, offset = _read(view, offset, depth + 1)
    if length_octet & 0x80:
        count = length_octet & 0x7F
        if count > 4 or offset + count > len(view):
            raise DerError("A length is too long or truncated.")
        length = int.from_bytes(view[offset:offset + count], "big")
        offset += count
    else:
        length = length_octet
    end = offset + length
    if end > len(view):
        raise DerError("An element is longer than its data.")
    return Element(tag, constructed, view[offset:end], view[start:end]), end


def _elements(view: memoryview, depth: int) -> Iterator[Element]:
    offset = 0
    while offset < len(view):
        element, offset = _read(view, offset, depth)
        yield element


def sequence(element: Element, what: str, minimum: int = 0, maximum: int | None = None) -> list[Element]:
    """A SEQUENCE's elements, between ``minimum`` and ``maximum`` of them."""
    items = element.expect(SEQUENCE, what).children()
    if len(items) < minimum or (maximum is not None and len(items) > maximum):
        raise DerError(f"{what} has {len(items)} elements.")
    return items


def oid(element: Element) -> str:
    """An OBJECT IDENTIFIER, dotted."""
    data = element.expect(OBJECT_IDENTIFIER, "An object identifier").contents
    if not data or data[-1] & 0x80:
        raise DerError("An object identifier is malformed.")
    arcs: list[int] = []
    value = 0
    for octet in data:
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            arcs.append(value)
            value = 0
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(arc) for arc in head + arcs[1:])


def integer(element: Element, what: str) -> int:
    """An INTEGER."""
    data = element.expect(INTEGER, what).contents
    if not data:
        raise DerError(f"{what} is empty.")
    return int.from_bytes(data, "big", signed=True)


def octets(element: Element, what: str, tag: int = OCTET_STRING, depth: int = 0) -> bytearray:
    """An OCTET STRING's bytes - or of a string with another (implicit) tag - joined from its
    segments when it is constructed, as BER allows. A new buffer the caller wipes."""
    if element.number != tag & ~_CONSTRUCTED:
        raise DerError(f"{what} isn't tag 0x{tag:02X} but 0x{element.tag:02X}.")
    if not element.constructed:
        return bytearray(element.contents)
    if depth > _MAX_DEPTH:
        raise DerError(f"{what} is nested too deep.")
    segments = element.children()
    out = bytearray(sum(len(segment.contents) for segment in segments))  # sized once: growing it would leave copies behind
    written = 0
    for segment in segments:
        part = octets(segment, what, OCTET_STRING, depth + 1)
        if written + len(part) > len(out):
            part[:] = bytes(len(part))
            out[:] = bytes(len(out))
            raise DerError(f"{what} is malformed.")
        out[written:written + len(part)] = part
        written += len(part)
        part[:] = bytes(len(part))
    if written != len(out):
        # Nested segments' headers made the estimate too large: copy into an exact buffer.
        exact = bytearray(written)
        exact[:] = memoryview(out)[:written]
        out[:] = bytes(len(out))
        return exact
    return out


def algorithm(element: Element, what: str) -> tuple[str, Element | None]:
    """An AlgorithmIdentifier: its OID and its parameters, if any."""
    items = sequence(element, what, 1, 2)
    return oid(items[0]), items[1] if len(items) == 2 else None


# --- Writing DER -------------------------------------------------------------------------------


def encode(tag: int, contents: bytes | bytearray) -> bytes:
    """One element, DER: ``tag``, a definite length, ``contents``. For what isn't secret."""
    length = len(contents)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        size = (length.bit_length() + 7) // 8
        header = bytes([tag, 0x80 | size]) + length.to_bytes(size, "big")
    return header + bytes(contents)


def encode_oid(dotted: str) -> bytes:
    """An OBJECT IDENTIFIER, DER."""
    arcs = [int(arc) for arc in dotted.split(".")]
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        rest = arc >> 7
        while rest:
            chunk.append(0x80 | (rest & 0x7F))
            rest >>= 7
        body += bytes(reversed(chunk))
    return encode(OBJECT_IDENTIFIER, body)


def encode_integer(value: int) -> bytes:
    """A non-negative INTEGER, DER."""
    return encode(INTEGER, value.to_bytes(value.bit_length() // 8 + 1, "big"))
