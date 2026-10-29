"""A strict, forward-only JSON reader over bytes, for taking secrets out of JSON without ever making
one a ``str``."""

from __future__ import annotations

import re
from collections.abc import Buffer
from enum import Enum, auto
from typing import Final

from hkdfguard.abstractions import ArrayUtility, WritableBuffer

_QUOTE: Final = 0x22
_BACKSLASH: Final = 0x5C
_WHITESPACE: Final = frozenset(b" \t\r\n")
_DELIMITERS: Final = frozenset(b" \t\r\n,}]")
_DIGITS: Final = frozenset(b"0123456789")
_SIMPLE_ESCAPES: Final = {ord(k): v for k, v in {'"': 0x22, "\\": 0x5C, "/": 0x2F, "b": 0x08, "f": 0x0C, "n": 0x0A, "r": 0x0D, "t": 0x09}.items()}

# What ends a run of plain string bytes: the closing quote, an escape, or a control character
# (which is malformed). re searches a memoryview in place, without copying it.
_STRING_SPECIAL: Final = re.compile(rb'["\\\x00-\x1f]')
_ESCAPE: Final = re.compile(rb"\\")


class JsonToken(Enum):
    START_OBJECT = auto()
    END_OBJECT = auto()
    START_ARRAY = auto()
    END_ARRAY = auto()
    PROPERTY_NAME = auto()
    STRING = auto()
    NUMBER = auto()
    TRUE = auto()
    FALSE = auto()
    NULL = auto()


class MalformedJsonError(ValueError):
    """Malformed JSON, at :attr:`position` bytes into line :attr:`line` (both from 0). Says where,
    never quotes what."""

    def __init__(self, position: int, line: int) -> None:
        super().__init__(f"Malformed JSON at byte {position} of line {line}.")
        self.position = position
        self.line = line


class JsonReader:
    """A forward-only reader over UTF-8 JSON (RFC 8259) held in a buffer, for taking secrets out of
    it without ever making one a ``str``: a string token is reported by where its escaped text lies,
    and unescaped only into a buffer the caller provides (:meth:`copy_string`). The counterpart of
    .NET's Utf8JsonReader, as strict: no comments, trailing commas, leading zeros or unescaped
    control characters, nesting at most :attr:`MAX_DEPTH` deep, and nothing but whitespace after the
    root value. A ``\\u`` escape must be a whole code point - a surrogate pair, never half of one.
    Duplicate property names are reported as they are, for the caller to decide about. Malformed
    JSON raises :class:`MalformedJsonError`, which says where but never quotes it.

    The reader reads ``json`` in place through a ``memoryview`` and never copies it.
    """

    MAX_DEPTH: Final = 64
    """The deepest nesting of objects and arrays read."""

    def __init__(self, json: Buffer, length: int | None = None) -> None:
        """A reader over ``json[0:length]`` - all of it when ``length`` is ``None``."""
        self._json = memoryview(json).cast("B")
        self._end = len(self._json) if length is None else length
        # Whether each open container is an object (True) or an array.
        self._containers: list[bool] = []
        self._position = 0
        self._line = 0
        self._line_start = 0
        self._token: JsonToken | None = None
        self._token_start = 0
        self._value_start = 0
        self._value_end = 0
        self._value_escaped = False
        self._root_done = False

    def token(self) -> JsonToken | None:
        """The token last read; ``None`` before the first. A method, not a property, since every
        :meth:`read` changes it."""
        return self._token

    @property
    def token_start(self) -> int:
        """Where the token last read starts: a string's opening quote."""
        return self._token_start

    @property
    def bytes_consumed(self) -> int:
        """Where the token last read ends: just past a string's closing quote."""
        return self._position

    @property
    def value_length(self) -> int:
        """The length of a string's escaped text, or of a number's or literal's."""
        return self._value_end - self._value_start

    def read(self) -> bool:
        """Reads the next token.

        :returns: ``False`` at the end of the input, once the root value is complete (or before it
            starts, for empty input)
        :raises MalformedJsonError: the input isn't JSON, or holds anything but whitespace after the
            root value
        """
        self._skip_whitespace()
        if self._position >= self._end:
            if self._token is not None and not self._root_done:
                raise self._malformed(self._position)
            return False
        if self._root_done:
            raise self._malformed(self._position)

        if not self._containers:
            self._read_value()
        elif self._containers[-1]:
            self._read_in_object()
        else:
            self._read_in_array()
        return True

    def _read_in_object(self) -> None:
        if self._token is JsonToken.PROPERTY_NAME:
            self._expect(ord(":"))
            self._read_value()
        elif self._json[self._position] == ord("}"):
            self._close(JsonToken.END_OBJECT)
        else:
            if self._token is not JsonToken.START_OBJECT:
                self._expect(ord(","))
            if self._position >= self._end or self._json[self._position] != _QUOTE:
                raise self._malformed(self._position)
            self._read_string(JsonToken.PROPERTY_NAME)

    def _read_in_array(self) -> None:
        if self._json[self._position] == ord("]"):
            self._close(JsonToken.END_ARRAY)
        else:
            if self._token is not JsonToken.START_ARRAY:
                self._expect(ord(","))
            self._read_value()

    def skip(self) -> None:
        """Skips the children of the object or array just started, leaving the reader at its end;
        does nothing after any other token."""
        if self._token not in (JsonToken.START_OBJECT, JsonToken.START_ARRAY):
            return

        target = len(self._containers) - 1
        while len(self._containers) > target:
            self.read()

    def value_text_equals(self, text: str) -> bool:
        """Whether the string or property name just read is, unescaped, exactly ``text`` - for
        matching property names, never secrets."""
        expected = text.encode("utf-8")
        if not self._value_escaped:
            return self._json[self._value_start:self._value_end] == expected

        unescaped = bytearray(self.value_length)
        try:
            length = self.copy_string(unescaped)
            return memoryview(unescaped)[:length] == expected
        finally:
            ArrayUtility.zero_memory(unescaped)

    def copy_string(self, destination: WritableBuffer) -> int:
        """Unescapes the string or property name just read into ``destination``, which must hold at
        least :attr:`value_length` bytes - unescaped, a string is never longer than it is escaped.

        :returns: the number of bytes written
        """
        target = memoryview(destination).cast("B")
        json = self._json
        start, end = self._value_start, self._value_end
        if not self._value_escaped:
            target[:end - start] = json[start:end]
            return end - start

        written = 0
        i = start
        while i < end:
            match = _ESCAPE.search(json, i, end)
            plain_end = end if match is None else match.start()
            # A run of plain bytes, copied view to view.
            target[written:written + plain_end - i] = json[i:plain_end]
            written += plain_end - i
            if match is None:
                break

            escaped = json[plain_end + 1]
            i = plain_end + 2
            if escaped != ord("u"):
                target[written] = _SIMPLE_ESCAPES[escaped]
                written += 1
                continue

            code_point = self._hex(i)
            i += 4
            if 0xD800 <= code_point <= 0xDBFF:
                code_point = 0x10000 + ((code_point - 0xD800) << 10) + (self._hex(i + 2) - 0xDC00)
                i += 6
            written = _write_utf8(code_point, target, written)
        return written

    def copy_raw(self, destination: WritableBuffer) -> int:
        """Copies the number or literal just read, as its JSON text, into ``destination``.

        :returns: the number of bytes written
        """
        length = self.value_length
        memoryview(destination).cast("B")[:length] = self._json[self._value_start:self._value_end]
        return length

    def get_string(self) -> str:
        """The string or property name just read, as a ``str``: only for text that isn't secret, such
        as a property name or an error message. Invalid UTF-8 becomes U+FFFD."""
        unescaped = bytearray(self.value_length)
        try:
            length = self.copy_string(unescaped)
            return unescaped[:length].decode("utf-8", "replace")
        finally:
            ArrayUtility.zero_memory(unescaped)

    def _read_value(self) -> None:
        if self._position >= self._end:
            raise self._malformed(self._position)

        c = self._json[self._position]
        if c == ord("{"):
            self._open(True, JsonToken.START_OBJECT)
        elif c == ord("["):
            self._open(False, JsonToken.START_ARRAY)
        elif c == _QUOTE:
            self._read_string(JsonToken.STRING)
        elif c == ord("t"):
            self._read_literal(b"true", JsonToken.TRUE)
        elif c == ord("f"):
            self._read_literal(b"false", JsonToken.FALSE)
        elif c == ord("n"):
            self._read_literal(b"null", JsonToken.NULL)
        else:
            self._read_number()

    def _open(self, is_object: bool, opened: JsonToken) -> None:
        if len(self._containers) == self.MAX_DEPTH:
            raise self._malformed(self._position)

        self._containers.append(is_object)
        self._token_start = self._position
        self._position += 1
        self._token = opened

    def _close(self, closed: JsonToken) -> None:
        self._containers.pop()
        self._token_start = self._position
        self._position += 1
        self._token = closed
        self._root_done = not self._containers

    def _read_string(self, read: JsonToken) -> None:
        self._token_start = self._position
        escaped = False
        i = self._position + 1
        while True:
            match = _STRING_SPECIAL.search(self._json, i, self._end)
            if match is None:
                raise self._malformed(self._end)

            i = match.start()
            b = self._json[i]
            if b == _QUOTE:
                break
            if b != _BACKSLASH:
                raise self._malformed(i)
            escaped = True
            i = self._check_escape(i + 1)

        self._value_start = self._token_start + 1
        self._value_end = i
        self._value_escaped = escaped
        self._position = i + 1
        self._token = read
        self._root_done = read is JsonToken.STRING and not self._containers

    def _check_escape(self, i: int) -> int:
        # Checks the escape whose character is at i; returns the index just past it.
        if i >= self._end:
            raise self._malformed(i)

        c = self._json[i]
        if c in _SIMPLE_ESCAPES:
            return i + 1
        if c != ord("u"):
            raise self._malformed(i)

        unit = self._hex_or_raise(i + 1)
        if 0xDC00 <= unit <= 0xDFFF:
            raise self._malformed(i)
        if not 0xD800 <= unit <= 0xDBFF:
            return i + 5

        # A high surrogate must be followed by an escaped low one.
        following = i + 5
        if following + 1 >= self._end or self._json[following] != _BACKSLASH or self._json[following + 1] != ord("u"):
            raise self._malformed(following)
        if not 0xDC00 <= self._hex_or_raise(following + 2) <= 0xDFFF:
            raise self._malformed(following + 1)
        return following + 6

    def _hex_or_raise(self, i: int) -> int:
        if i + 4 > self._end:
            raise self._malformed(min(i, self._end))

        value = 0
        for j in range(i, i + 4):
            digit = _hex_digit(self._json[j])
            if digit < 0:
                raise self._malformed(j)
            value = value * 16 + digit
        return value

    def _hex(self, i: int) -> int:
        # Four hex digits already checked by _check_escape.
        value = 0
        for j in range(i, i + 4):
            value = value * 16 + _hex_digit(self._json[j])
        return value

    def _read_literal(self, literal: bytes, read: JsonToken) -> None:
        self._token_start = self._position
        for k, expected in enumerate(literal):
            if self._position + k >= self._end or self._json[self._position + k] != expected:
                raise self._malformed(self._position + k)

        self._value_start = self._position
        self._value_end = self._position + len(literal)
        self._position = self._value_end
        self._check_delimiter()
        self._token = read
        self._root_done = not self._containers

    def _read_number(self) -> None:
        # -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
        self._token_start = self._position
        json, end = self._json, self._end
        i = self._position
        if json[i] == ord("-"):
            i += 1

        if i < end and json[i] == ord("0"):
            i += 1
        else:
            i = self._digits(i)
        if i < end and json[i] == ord("."):
            i = self._digits(i + 1)
        if i < end and json[i] in b"eE":
            i += 1
            if i < end and json[i] in b"+-":
                i += 1
            i = self._digits(i)

        self._value_start = self._position
        self._value_end = i
        self._position = i
        self._check_delimiter()
        self._token = JsonToken.NUMBER
        self._root_done = not self._containers

    def _digits(self, i: int) -> int:
        # One or more digits from i; returns the index past them.
        if i >= self._end or self._json[i] not in _DIGITS:
            raise self._malformed(i)
        while i < self._end and self._json[i] in _DIGITS:
            i += 1
        return i

    def _check_delimiter(self) -> None:
        # A number or literal must be followed by whitespace, a separator, a closing bracket or the end.
        if self._position < self._end and self._json[self._position] not in _DELIMITERS:
            raise self._malformed(self._position)

    def _expect(self, c: int) -> None:
        if self._position >= self._end or self._json[self._position] != c:
            raise self._malformed(self._position)

        self._position += 1
        self._skip_whitespace()

    def _skip_whitespace(self) -> None:
        json, end = self._json, self._end
        while self._position < end and json[self._position] in _WHITESPACE:
            if json[self._position] == ord("\n"):
                self._line += 1
                self._line_start = self._position + 1
            self._position += 1

    def _malformed(self, at: int) -> MalformedJsonError:
        return MalformedJsonError(at - self._line_start, self._line)


def _hex_digit(b: int) -> int:
    if ord("0") <= b <= ord("9"):
        return b - ord("0")
    if ord("a") <= b <= ord("f"):
        return b - ord("a") + 10
    if ord("A") <= b <= ord("F"):
        return b - ord("A") + 10
    return -1


def _write_utf8(c: int, destination: memoryview, written: int) -> int:
    if c < 0x80:
        destination[written] = c
        return written + 1
    if c < 0x800:
        destination[written] = 0xC0 | (c >> 6)
        destination[written + 1] = 0x80 | (c & 0x3F)
        return written + 2
    if c < 0x10000:
        destination[written] = 0xE0 | (c >> 12)
        destination[written + 1] = 0x80 | ((c >> 6) & 0x3F)
        destination[written + 2] = 0x80 | (c & 0x3F)
        return written + 3
    destination[written] = 0xF0 | (c >> 18)
    destination[written + 1] = 0x80 | ((c >> 12) & 0x3F)
    destination[written + 2] = 0x80 | ((c >> 6) & 0x3F)
    destination[written + 3] = 0x80 | (c & 0x3F)
    return written + 4
