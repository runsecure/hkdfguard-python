"""How text and keys are read, exactly as .NET reads them."""

from __future__ import annotations

import codecs
from collections.abc import Buffer
from typing import Final

from hkdfguard.abstractions import Utf8

# .NET's char.IsWhiteSpace, which string.Trim removes: U+0009-U+000D, U+0020, U+0085, U+00A0 and
# the Zs, Zl and Zp characters. Python's str.isspace also counts U+001C-U+001F, which .NET doesn't.
_WHITESPACE: Final = "".join(
    map(chr, [*range(0x09, 0x0E), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000]),
)

# The byte order marks a .NET StreamReader detects, longest first where one starts another.
_BOMS: Final = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def item_key(text: Buffer, start: int, end: int) -> str:
    """The key of the item whose text is ``text[start:end]``: its UTF-8, each ill-formed sequence
    replaced with U+FFFD as .NET decodes it (CPython's decoder replaces the same maximal
    subparts), trimmed of the whitespace .NET's string.Trim removes."""
    with memoryview(text) as view:
        return str(view[start:end], "utf-8", "replace").strip(_WHITESPACE)


def decode_stream_text(data: bytes, encoding: str | None) -> str:
    """``data`` read from a stream as a .NET StreamReader that detects byte order marks reads it: a
    UTF-8, UTF-16 or UTF-32 BOM selects that encoding and is dropped; without one the text is in
    ``encoding``, UTF-8 by default. Ill-formed input becomes U+FFFD."""
    for bom, bom_encoding in _BOMS:
        if data.startswith(bom):
            return data[len(bom) :].decode(bom_encoding, "replace")
    return data.decode(encoding or "utf-8", "replace")


def utf8_of(text: str | Buffer) -> tuple[bytes | bytearray, bool]:
    """``text`` as UTF-8 bytes that can be searched, and whether they are a copy the caller zeroes.
    A ``str`` is encoded as every port does (an unpaired surrogate becomes U+FFFD); a ``bytes`` or
    ``bytearray`` is used as it is; any other buffer is copied."""
    if isinstance(text, str):
        return Utf8.encode(text), True
    if isinstance(text, (bytes, bytearray)):
        return text, False
    with memoryview(text) as view:
        return bytearray(view.cast("B")), True
