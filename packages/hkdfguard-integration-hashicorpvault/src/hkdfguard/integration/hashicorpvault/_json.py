"""The JSON a VaultClient reads Vault's answers into and writes request bodies with."""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections.abc import Buffer, Callable, Iterable, Mapping
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, ClassVar, Final, Self

from hkdfguard.abstractions import ArrayUtility, JsonReader, JsonToken, MalformedJsonError
from hkdfguard.integration.hashicorpvault._errors import VaultJsonError
from hkdfguard.integration.hashicorpvault._token_provider import StaticVaultToken

_MAX_DEPTH: Final = 64
_HEX: Final = b"0123456789abcdef"
_SHORT_ESCAPES: Final = {0x22: b'\\"', 0x5C: b"\\\\", 0x0A: b"\\n", 0x0D: b"\\r", 0x09: b"\\t", 0x08: b"\\b", 0x0C: b"\\f"}
# Go writes up to nine fractional digits; datetime holds six.
_FRACTION: Final = re.compile(r"(\.\d{6})\d+")


class SecureBuffer:
    """A growable bytearray that zeroes what it held: each smaller array as it grows, and the last on
    :meth:`close`. What request bodies are written into and response bodies read into."""

    __slots__ = ("_buffer", "_length")

    _MINIMUM_CAPACITY: ClassVar[int] = 256
    _MAXIMUM_INITIAL_CAPACITY: ClassVar[int] = 1 << 20

    def __init__(self, expected_length: int = 0) -> None:
        """:param expected_length: room to make at first (within limits); 0 or less if unknown"""
        self._buffer = bytearray(min(max(expected_length, self._MINIMUM_CAPACITY), self._MAXIMUM_INITIAL_CAPACITY))
        self._length = 0

    @property
    def buffer(self) -> bytearray:
        """The array the bytes are in, ``[0, length)``. Valid until the buffer next grows or is closed."""
        return self._buffer

    @property
    def length(self) -> int:
        return self._length

    def view(self) -> memoryview:
        """The bytes written, ``[0, length)``, in place; release it before the buffer grows."""
        return memoryview(self._buffer)[:self._length]

    def write_byte(self, b: int) -> None:
        self._reserve(1)
        self._buffer[self._length] = b
        self._length += 1

    def write(self, data: Buffer) -> None:
        with memoryview(data).cast("B") as view:
            self._reserve(len(view))
            self._buffer[self._length:self._length + len(view)] = view
            self._length += len(view)

    def read_from(self, readinto: Callable[[memoryview], int], limit: int | None = None) -> None:
        """Reads with ``readinto`` (a stream's) until it returns 0.

        :param limit: the most bytes the stream may hold; ``None`` for no limit
        :raises VaultJsonError: the stream holds more than ``limit`` bytes (no more than one byte past
            it is read)
        """
        while True:
            want = 8192 if limit is None else min(8192, limit + 1 - self._length)
            self._reserve(want)
            with memoryview(self._buffer) as whole, whole[self._length:self._length + want] as free:
                read = readinto(free)
            if not read:
                return
            self._length += read
            if limit is not None and self._length > limit:
                raise VaultJsonError(f"Vault's response is larger than {limit} bytes, the most this client reads.")

    def close(self) -> None:
        ArrayUtility.zero_memory(self._buffer)
        self._length = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _reserve(self, count: int) -> None:
        if len(self._buffer) - self._length >= count:
            return
        larger = bytearray(max(len(self._buffer) * 2, self._length + count))
        larger[:self._length] = memoryview(self._buffer)[:self._length]
        ArrayUtility.zero_memory(self._buffer)
        self._buffer = larger


class JsonKind(Enum):
    """What kind of JSON value a :class:`JsonValue` is."""

    NULL = "null"
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"


_DESCRIBED: Final = {JsonKind.NULL: "null", JsonKind.STRING: "a string", JsonKind.NUMBER: "a number", JsonKind.BOOLEAN: "a boolean",
                     JsonKind.OBJECT: "an object", JsonKind.ARRAY: "an array"}


class JsonValue:
    """A JSON value from a Vault response: what the client returns where Vault's spec types a value
    loosely (a secret's data, free-form metadata), and what the generated models are read from.
    Immutable; objects keep their members in document order, the last of a repeated name winning.

    The ``as_...`` methods are strict: each raises :class:`VaultJsonError` for a value of another
    kind. The ``read_...`` methods are what the generated models read members with, as leniently as
    the other ports: each returns ``None`` for JSON null, and accepts what Vault writes in place of
    what its spec declares - a number or boolean where a string is declared (its text), an object or
    array there (its JSON text), a number in a string where a number is declared.

    Strings are ordinary ``str``, as in any API client. To read a secret into memory an application
    uses, prefer hkdfguard-cache-hashicorpvault, which never makes one a ``str``.
    """

    __slots__ = ("_bool", "_elements", "_kind", "_members", "_text")

    NULL: ClassVar[JsonValue]
    """JSON null; also what :meth:`member` returns for a member that isn't there."""

    def __init__(self, kind: JsonKind, text: str | None = None, boolean: bool = False, members: dict[str, JsonValue] | None = None,
                 elements: tuple[JsonValue, ...] | None = None) -> None:
        self._kind = kind
        # A string's value, or a number's JSON text.
        self._text = text
        self._bool = boolean
        self._members = members
        self._elements = elements

    @staticmethod
    def of(value: str) -> JsonValue:
        """A string."""
        if not isinstance(value, str):
            raise TypeError("value must be a str.")
        return JsonValue(JsonKind.STRING, value)

    @staticmethod
    def parse(json: str | Buffer, length: int | None = None) -> JsonValue:
        """``json`` - ``[0, length)`` of a buffer - which must be one JSON value (RFC 8259) and nothing else.

        :raises VaultJsonError: it isn't JSON
        """
        data: Buffer = json.encode("utf-8", "surrogatepass") if isinstance(json, str) else json
        try:
            reader = JsonReader(data, length)
            if not reader.read():
                raise VaultJsonError("Expected JSON, found nothing.")
            value = JsonValue.read_from(reader)
            if reader.read():
                raise VaultJsonError("Expected one JSON value; more follows it.")
            return value
        except MalformedJsonError as error:
            raise VaultJsonError(str(error)) from None

    @staticmethod
    def read_from(reader: JsonReader) -> JsonValue:  # noqa: PLR0911 - one per token
        """The value ``reader`` has just read the first token of, leaving the reader at its last token."""
        token = reader.token()
        if token is JsonToken.NULL:
            return JsonValue.NULL
        if token is JsonToken.TRUE:
            return _TRUE
        if token is JsonToken.FALSE:
            return _FALSE
        if token is JsonToken.STRING:
            return JsonValue(JsonKind.STRING, reader.get_string())
        if token is JsonToken.NUMBER:
            raw = bytearray(reader.value_length)
            reader.copy_raw(raw)
            return JsonValue(JsonKind.NUMBER, raw.decode("ascii"))
        if token is JsonToken.START_OBJECT:
            members: dict[str, JsonValue] = {}
            while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
                name = reader.get_string()
                reader.read()
                # The last of a repeated name wins, in the place the first held.
                members[name] = JsonValue.read_from(reader)
            return JsonValue(JsonKind.OBJECT, members=members)
        if token is JsonToken.START_ARRAY:
            elements: list[JsonValue] = []
            while reader.read() and reader.token() is not JsonToken.END_ARRAY:
                elements.append(JsonValue.read_from(reader))
            return JsonValue(JsonKind.ARRAY, elements=tuple(elements))
        raise VaultJsonError(f"Expected a JSON value, not {token}.")

    @property
    def kind(self) -> JsonKind:
        return self._kind

    @property
    def is_null(self) -> bool:
        return self._kind is JsonKind.NULL

    def member(self, name: str) -> JsonValue:
        """The member named ``name`` of an object; :data:`NULL` if it has none, or this isn't an object."""
        if self._members is None:
            return JsonValue.NULL
        return self._members.get(name, JsonValue.NULL)

    def require_object(self, what: str) -> Self:
        """This value, which must be an object.

        :param what: what it is read as, for the message, e.g. ``"KvV2ReadResponse"``
        :raises VaultJsonError: it isn't an object
        """
        if self._kind is not JsonKind.OBJECT:
            raise VaultJsonError(f"Expected a JSON object for {what}, not {self._describe()}.")
        return self

    # --- Strict -------------------------------------------------------------------------------

    def as_str(self) -> str:
        """A string's value."""
        self._expect(JsonKind.STRING)
        assert self._text is not None
        return self._text

    def as_int(self) -> int:
        """A number's value, which must be an integer."""
        self._expect(JsonKind.NUMBER)
        return _parse_int(self._text)

    def as_float(self) -> float:
        """A number's value."""
        self._expect(JsonKind.NUMBER)
        return float(self._text or "")

    def as_decimal(self) -> Decimal:
        """A number's value, exactly."""
        self._expect(JsonKind.NUMBER)
        return Decimal(self._text or "")

    def as_bool(self) -> bool:
        """A boolean's value."""
        self._expect(JsonKind.BOOLEAN)
        return self._bool

    def as_dict(self) -> Mapping[str, JsonValue]:
        """An object's members, in document order; read-only."""
        self._expect(JsonKind.OBJECT)
        return dict(self._members or {})

    def as_list(self) -> list[JsonValue]:
        """An array's elements."""
        self._expect(JsonKind.ARRAY)
        return list(self._elements or ())

    def as_json(self) -> JsonValue:
        """This value, null included: what a list or dict of JSON values is read with."""
        return self

    # --- Lenient, for the generated models -------------------------------------------------------

    def read_str(self) -> str | None:
        """A string as it is; a number or boolean as its text; an object or array as its JSON text;
        ``None`` for null."""
        match self._kind:
            case JsonKind.NULL:
                return None
            case JsonKind.STRING | JsonKind.NUMBER:
                return self._text
            case JsonKind.BOOLEAN:
                return "true" if self._bool else "false"
            case _:
                return str(self)

    def read_int(self) -> int | None:
        """A number, or a string holding one, that is an integer ("4.0" and "1e3" are); ``None`` for null."""
        match self._kind:
            case JsonKind.NULL:
                return None
            case JsonKind.NUMBER | JsonKind.STRING:
                return _parse_int(self._text)
            case _:
                raise self._mismatch("an integer")

    def read_float(self) -> float | None:
        """A number, or a string holding one; ``None`` for null."""
        match self._kind:
            case JsonKind.NULL:
                return None
            case JsonKind.NUMBER:
                return float(self._text or "")
            case JsonKind.STRING:
                try:
                    value = float((self._text or "").strip())
                except ValueError:
                    raise VaultJsonError("Expected a number; the string doesn't hold one.") from None
                if not math.isfinite(value):
                    raise VaultJsonError("Expected a number; the string doesn't hold one.")
                return value
            case _:
                raise self._mismatch("a number")

    def read_bool(self) -> bool | None:
        """A boolean; ``None`` for null."""
        match self._kind:
            case JsonKind.NULL:
                return None
            case JsonKind.BOOLEAN:
                return self._bool
            case _:
                raise self._mismatch("a boolean")

    def read_datetime(self) -> datetime | None:
        """An RFC 3339 date-time as Vault (Go) writes it - fractional digits past six dropped, UTC
        assumed without an offset; ``None`` for null or an empty string."""
        if self._kind is JsonKind.NULL:
            return None
        if self._kind is not JsonKind.STRING:
            raise self._mismatch("a date-time string")
        text = self._text or ""
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(_FRACTION.sub(r"\1", text))
        except ValueError:
            raise VaultJsonError("Expected a date-time; the string isn't one.") from None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)

    def read_list[T](self, element: Callable[[JsonValue], T | None]) -> list[T] | None:
        """An array, each element read with ``element``; ``None`` for null. An element that reads as
        ``None`` (JSON null, where Vault writes a typed value) is refused: read a list that may hold
        nulls with :meth:`as_json` or :meth:`read_object`."""
        if self._kind is JsonKind.NULL:
            return None
        if self._kind is not JsonKind.ARRAY:
            raise self._mismatch("an array")
        return [_required(element(e)) for e in self._elements or ()]

    def read_dict[T](self, value: Callable[[JsonValue], T | None]) -> dict[str, T] | None:
        """An object, each member's value read with ``value``; ``None`` for null. In document order. A
        value that reads as ``None`` is refused, as by :meth:`read_list`."""
        if self._kind is JsonKind.NULL:
            return None
        if self._kind is not JsonKind.OBJECT:
            raise self._mismatch("an object")
        return {name: _required(value(v)) for name, v in (self._members or {}).items()}

    def read_json_dict(self) -> dict[str, JsonValue] | None:
        """An object as its members' JSON values; ``None`` for null."""
        if self._kind is JsonKind.NULL:
            return None
        if self._kind is not JsonKind.OBJECT:
            raise self._mismatch("an object")
        return dict(self._members or {})

    def read_json_list(self) -> list[JsonValue] | None:
        """An array as its elements' JSON values; ``None`` for null."""
        if self._kind is JsonKind.NULL:
            return None
        if self._kind is not JsonKind.ARRAY:
            raise self._mismatch("an array")
        return list(self._elements or ())

    def read_object_dict(self) -> dict[str, object] | None:
        """An object as plain Python (:meth:`read_object`); ``None`` for null."""
        if self._kind is JsonKind.NULL:
            return None
        if self._kind is not JsonKind.OBJECT:
            raise self._mismatch("an object")
        return {name: v.read_object() for name, v in (self._members or {}).items()}

    def read_object_list(self) -> list[object] | None:
        """An array as plain Python (:meth:`read_object`); ``None`` for null."""
        if self._kind is JsonKind.NULL:
            return None
        if self._kind is not JsonKind.ARRAY:
            raise self._mismatch("an array")
        return [e.read_object() for e in self._elements or ()]

    def read_model[T](self, reader: Callable[[JsonValue], T | None]) -> T | None:
        """This value read with ``reader`` - a model's ``from_json``; ``None`` for null."""
        return None if self._kind is JsonKind.NULL else reader(self)

    def read_json(self) -> JsonValue | None:
        """This value; ``None`` for null."""
        return None if self._kind is JsonKind.NULL else self

    def read_object(self) -> object:
        """This value as plain Python: a ``dict`` of ``str`` to values (in document order), a
        ``list``, a ``str``, an ``int`` (an integer) or ``Decimal`` (any other number), a ``bool``, or
        ``None``."""
        match self._kind:
            case JsonKind.NULL:
                return None
            case JsonKind.STRING:
                return self._text
            case JsonKind.BOOLEAN:
                return self._bool
            case JsonKind.NUMBER:
                decimal = Decimal(self._text or "")
                integer = _integral(decimal)
                return decimal if integer is None else integer
            case JsonKind.OBJECT:
                return self.read_object_dict()
            case _:
                return self.read_object_list()

    def write_to(self, writer: JsonWriter) -> None:
        match self._kind:
            case JsonKind.NULL:
                writer.literal("null")
            case JsonKind.BOOLEAN:
                writer.literal("true" if self._bool else "false")
            case JsonKind.NUMBER:
                writer.literal(self._text or "")
            case JsonKind.STRING:
                writer.value(self._text)
            case JsonKind.OBJECT:
                writer.begin_object()
                for name, v in (self._members or {}).items():
                    writer.name(name)
                    v.write_to(writer)
                writer.end_object()
            case _:
                writer.begin_array()
                for e in self._elements or ():
                    e.write_to(writer)
                writer.end_array()

    def __str__(self) -> str:
        """This value as compact JSON text."""
        with SecureBuffer() as buffer:
            self.write_to(JsonWriter(buffer))
            return buffer.view().tobytes().decode("utf-8")

    def __repr__(self) -> str:
        return f"JsonValue({self})"

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, JsonValue) and self._kind is other._kind and self._bool == other._bool and self._text == other._text
                and self._members == other._members and self._elements == other._elements)

    def __hash__(self) -> int:
        return hash((self._kind, self._text, self._bool, self._elements, None if self._members is None else tuple(self._members.items())))

    def _expect(self, expected: JsonKind) -> None:
        if self._kind is not expected:
            raise VaultJsonError(f"Expected a JSON {expected.value}, not {self._describe()}.")

    def _mismatch(self, expected: str) -> VaultJsonError:
        return VaultJsonError(f"Expected {expected}, not {self._describe()}.")

    def _describe(self) -> str:
        return _DESCRIBED[self._kind]


JsonValue.NULL = JsonValue(JsonKind.NULL)
_TRUE: Final = JsonValue(JsonKind.BOOLEAN, boolean=True)
_FALSE: Final = JsonValue(JsonKind.BOOLEAN, boolean=False)


def _required[T](value: T | None) -> T:
    if value is None:
        raise VaultJsonError("Expected a value, not null.")
    return value


def _parse_int(number: str | None) -> int:
    # An integer, written as a JSON number or (leniently) in a string: "12", "-3", "4.0" and "1e3"
    # are integers; "4.5" isn't.
    text = (number or "").strip()
    try:
        return int(text)
    except ValueError:
        pass
    try:
        integer = _integral(Decimal(text))
        if integer is not None:
            return integer
    except InvalidOperation:
        pass
    raise VaultJsonError("Expected an integer; the value isn't one.")


_MAX_INTEGER_DIGITS: Final = 4300
"""The most digits a number read as an integer may have: CPython's own limit on ``int(str)``, which
reads the plain form. A number's exponent is checked before it is expanded, so "1E+10000000" - 12 bytes
- can't make ``int`` build ten million digits."""


def _integral(decimal: Decimal) -> int | None:
    # decimal as an int, or None if it isn't a whole number of at most _MAX_INTEGER_DIGITS digits.
    # adjusted() is the exponent of its leading digit, read without expanding it.
    if not decimal.is_finite() or decimal.adjusted() >= _MAX_INTEGER_DIGITS or decimal != decimal.to_integral_value():
        return None
    return int(decimal)


class VaultModel(ABC):
    """A model of a request or response body Vault's OpenAPI spec defines: every class in
    :mod:`hkdfguard.integration.hashicorpvault.schema`. A model is written as a JSON object holding
    only the members that are set, and read with its ``from_json``."""

    __slots__ = ()

    @abstractmethod
    def write_json(self, writer: JsonWriter) -> None:
        """Writes this model as one JSON object."""


class JsonWriter:
    """Writes a request body as compact UTF-8 JSON into a :class:`SecureBuffer`, zeroed once the
    request has been sent, as the generated models' :meth:`VaultModel.write_json` do. A
    ``bytearray`` (or ``memoryview``) of UTF-8 is written as a string without becoming a ``str``, so a
    secret in one never does.

    :meth:`value` writes ``None``, a ``str``, a UTF-8 ``bytearray`` or ``memoryview``, a ``bool``, an
    ``int``, ``float`` or ``Decimal``, an aware ``datetime`` (RFC 3339), a ``Mapping`` (its keys as
    strings), a ``list`` or ``tuple``, a :class:`VaultModel`, a :class:`JsonValue`, or a
    :class:`StaticVaultToken` (in its protected form). Not thread-safe.
    """

    __slots__ = ("_after_name", "_objects", "_output", "_started")

    def __init__(self, output: SecureBuffer) -> None:
        self._output = output
        # Whether each open container is an object (True) or an array, and whether it has a member yet.
        self._objects: list[bool] = []
        self._started: list[bool] = []
        self._after_name = False

    def begin_object(self) -> Self:
        """Starts an object: then name, value, name, value... and :meth:`end_object`."""
        self._before_value()
        self._open(is_object=True)
        self._output.write_byte(ord("{"))
        return self

    def end_object(self) -> Self:
        self._close(is_object=True)
        self._output.write_byte(ord("}"))
        return self

    def begin_array(self) -> Self:
        """Starts an array: then values and :meth:`end_array`."""
        self._before_value()
        self._open(is_object=False)
        self._output.write_byte(ord("["))
        return self

    def end_array(self) -> Self:
        self._close(is_object=False)
        self._output.write_byte(ord("]"))
        return self

    def name(self, name: str) -> Self:
        """The next member's name, inside an object.

        :raises RuntimeError: not inside an object, or right after another name
        """
        if not isinstance(name, str):
            raise TypeError("name must be a str.")
        if not self._objects or not self._objects[-1] or self._after_name:
            raise RuntimeError("A name goes only inside an object, before its value.")
        if self._started[-1]:
            self._output.write_byte(ord(","))
        self._started[-1] = True
        self._write_str(name)
        self._output.write_byte(ord(":"))
        self._after_name = True
        return self

    def value(self, value: Any) -> Self:  # noqa: PLR0912 - any JSON-shaped value; one case per type
        """Writes ``value`` as JSON; see the class description for the types written.

        :raises TypeError: ``value`` is of a type that isn't written
        :raises ValueError: a number that isn't finite, a naive ``datetime``, text holding an
            unpaired surrogate or bytes that aren't UTF-8, or nesting more than 64 deep
        """
        if value is None:
            self.literal("null")
        elif isinstance(value, bool):
            self.literal("true" if value else "false")
        elif isinstance(value, str):
            self._before_value()
            self._write_str(value)
        elif isinstance(value, (bytearray, memoryview)):
            self._before_value()
            self._write_utf8(value)
        elif isinstance(value, int):
            self.literal(str(value))
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError(f"JSON has no {value}.")
            self.literal(str(int(value)) if value.is_integer() and abs(value) < 1e15 else repr(value))
        elif isinstance(value, Decimal):
            if not value.is_finite():
                raise ValueError(f"JSON has no {value}.")
            self.literal(str(value))
        elif isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError("A datetime is written only with its offset: make it aware.")
            self.value(value.isoformat())
        elif isinstance(value, StaticVaultToken):
            self.value(value.get_token())
        elif isinstance(value, VaultModel):
            value.write_json(self)
        elif isinstance(value, JsonValue):
            value.write_to(self)
        elif isinstance(value, Mapping):
            self.begin_object()
            for key, member in value.items():
                self.name(str(key)).value(member)
            self.end_object()
        elif isinstance(value, (list, tuple)):
            self._write_items(value)
        else:
            raise TypeError(f"A {type(value).__name__} can't be written as JSON.")
        return self

    def literal(self, text: str) -> Self:
        """Writes a JSON literal or number as it is."""
        self._before_value()
        self._output.write(text.encode("ascii"))
        return self

    def _write_items(self, items: Iterable[object]) -> None:
        self.begin_array()
        for item in items:
            self.value(item)
        self.end_array()

    def _before_value(self) -> None:
        if not self._objects:
            return
        if self._objects[-1]:
            if not self._after_name:
                raise RuntimeError("A value inside an object needs a name first.")
            self._after_name = False
            return
        if self._started[-1]:
            self._output.write_byte(ord(","))
        self._started[-1] = True

    def _open(self, *, is_object: bool) -> None:
        if len(self._objects) == _MAX_DEPTH:
            raise ValueError(f"JSON nested more than {_MAX_DEPTH} deep isn't written.")
        self._objects.append(is_object)
        self._started.append(False)

    def _close(self, *, is_object: bool) -> None:
        if not self._objects or self._objects[-1] != is_object or self._after_name:
            raise RuntimeError(f"No open {'object' if is_object else 'array'} to end.")
        self._objects.pop()
        self._started.pop()

    def _write_str(self, text: str) -> None:
        output = self._output
        output.write_byte(0x22)
        for c in text:
            code = ord(c)
            if code < 0x80:
                self._write_ascii(code)
            elif 0xD800 <= code <= 0xDFFF:
                raise ValueError("Text holding an unpaired surrogate isn't written as JSON.")
            else:
                output.write(c.encode("utf-8"))
        output.write_byte(0x22)

    def _write_utf8(self, data: bytearray | memoryview) -> None:
        # Escapes what JSON must, copying the rest byte for byte - once it is known to be UTF-8.
        with memoryview(data).cast("B") as view:
            if not _is_utf8(view):
                raise ValueError("Bytes written as a JSON string must be UTF-8.")
            output = self._output
            output.write_byte(0x22)
            for b in view:
                if b < 0x80:
                    self._write_ascii(b)
                else:
                    output.write_byte(b)
            output.write_byte(0x22)

    def _write_ascii(self, code: int) -> None:
        output = self._output
        escape = _SHORT_ESCAPES.get(code)
        if escape is not None:
            output.write(escape)
        elif code < 0x20:
            output.write(b"\\u00")
            output.write_byte(_HEX[code >> 4])
            output.write_byte(_HEX[code & 0xF])
        else:
            output.write_byte(code)


def _is_utf8(view: memoryview) -> bool:
    # Well-formed UTF-8 (RFC 3629): no overlong forms, surrogates or code points past U+10FFFF.
    i, end = 0, len(view)
    while i < end:
        b = view[i]
        if b < 0x80:
            i += 1
            continue
        if 0xC2 <= b <= 0xDF:
            count, low, high = 1, 0x80, 0xBF
        elif 0xE0 <= b <= 0xEF:
            count = 2
            low, high = (0xA0, 0xBF) if b == 0xE0 else (0x80, 0x9F) if b == 0xED else (0x80, 0xBF)
        elif 0xF0 <= b <= 0xF4:
            count = 3
            low, high = (0x90, 0xBF) if b == 0xF0 else (0x80, 0x8F) if b == 0xF4 else (0x80, 0xBF)
        else:
            return False
        if i + count >= end:
            return False
        if not low <= view[i + 1] <= high:
            return False
        for k in range(2, count + 1):
            if not 0x80 <= view[i + k] <= 0xBF:
                return False
        i += count + 1
    return True
