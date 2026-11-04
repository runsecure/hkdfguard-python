"""What the resolver core's tests share: the port of .NET's TestDoubles.cs (CustomToken,
ReadingResolver, SpyValueProvider), the parts of the integration tests' TestSupport.cs they use
(TemplateFile.CreateResolver), and a ValueProviderBase over a dict that stands in for .NET's
DictionaryValueProvider, which is not ported.

Non-ASCII test text is built with ``chr`` so that the files hold only ASCII.
"""

from __future__ import annotations

from collections.abc import Buffer, Iterable, Mapping

from hkdfguard.abstractions import WritableBuffer
from hkdfguard.integration.configurationresolver import (
    ConfigurationItemReader,
    ConfigurationItemResolver,
    ConfigurationItemTokenBase,
    ConfigurationKeyError,
    ConfigurationKeyErrorCode,
    ConfigurationResolver,
    ValueProvider,
    ValueProviderBase,
    ValueStatus,
)

# --- Characters -------------------------------------------------------------------------------

E_ACUTE = chr(0x00E9)  # LATIN SMALL LETTER E WITH ACUTE
U_DIAERESIS = chr(0x00FC)  # LATIN SMALL LETTER U WITH DIAERESIS
I_DIAERESIS = chr(0x00EF)  # LATIN SMALL LETTER I WITH DIAERESIS
O_DIAERESIS = chr(0x00F6)  # LATIN SMALL LETTER O WITH DIAERESIS
CHECK_MARK = chr(0x2713)  # CHECK MARK
LEFT_GUILLEMET = chr(0x00AB)  # LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
RIGHT_GUILLEMET = chr(0x00BB)  # RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
REPLACEMENT = chr(0xFFFD)  # REPLACEMENT CHARACTER

CAFE = "caf" + E_ACUTE
""""cafe" with an acute e: 4 characters, 5 UTF-8 bytes."""

# --- Doubles ----------------------------------------------------------------------------------


class CustomToken(ConfigurationItemTokenBase):
    """A token with custom start, end, and escape sequences."""

    def __init__(self, start_sequence: str, end_sequence: str, escape_sequence: str | None = None) -> None:
        super().__init__(start_sequence, end_sequence, escape_sequence)


def _write(value: bytes, destination: WritableBuffer) -> tuple[ValueStatus, int]:
    """Writes ``value`` to the start of ``destination``, as .NET's Encoding.UTF8.TryGetBytes does."""
    with memoryview(destination) as view, view.cast("B") as room:
        if len(value) > len(room):
            return ValueStatus.DESTINATION_TOO_SMALL, 0
        room[: len(value)] = value
        return ValueStatus.FOUND, len(value)


class DictValueProvider(ValueProviderBase):
    """A :class:`ValueProviderBase` over a ``dict``: what the tests use where .NET's tests use
    DictionaryValueProvider just as a source of values."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        value = self._values.get(key)
        if value is None:
            return ValueStatus.NOT_FOUND, 0
        return _write(value.encode(), destination)

    def _find_byte_count(self, key: str) -> int | None:
        value = self._values.get(key)
        return None if value is None else len(value.encode())

    def find_byte_count(self, key: str) -> int | None:
        """Exposes the protected sizing method, as .NET's SizingDictionaryValueProvider does."""
        return self._find_byte_count(key)


class SpyValueProvider(ValueProvider):
    """A value provider that records how the resolver calls it."""

    def __init__(self, values: Mapping[str, str], *, throw_on_lookup: BaseException | None = None) -> None:
        self._values = dict(values)
        self.throw_on_lookup = throw_on_lookup
        self.try_get_value_calls: list[str] = []
        self.try_get_bytes_calls: list[str] = []
        self.buffer_lengths: list[int] = []

    def try_get_value(self, key: str) -> tuple[ValueStatus, str | None]:
        self.try_get_value_calls.append(key)
        value = self._values.get(key)
        return (ValueStatus.NOT_FOUND, None) if value is None else (ValueStatus.FOUND, value)

    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        self.try_get_bytes_calls.append(key)
        with memoryview(destination) as view:
            self.buffer_lengths.append(view.nbytes)
        if self.throw_on_lookup is not None:
            raise self.throw_on_lookup

        value = self._values.get(key)
        if value is None:
            return ValueStatus.NOT_FOUND, 0
        return _write(value.encode(), destination)


class ReadingResolver(ConfigurationResolver):
    """Reads the keys of each source before resolving it, so every key in the source is allowed.

    ``also_allowed`` are texts whose keys are allowed as well as the source's, such as the keys
    of items inside values.
    """

    def __init__(
        self,
        token: ConfigurationItemTokenBase,
        *value_providers: ValueProvider,
        ignore_unresolvable_placeholders: bool = False,
        max_resolution_depth: int = 1,
        also_allowed: Iterable[str] = (),
    ) -> None:
        self._reader = ConfigurationItemReader(token)
        self._also_allowed = tuple(also_allowed)
        self._resolver = ConfigurationItemResolver(
            token,
            self._reader,
            *value_providers,
            ignore_unresolvable_placeholders=ignore_unresolvable_placeholders,
            max_resolution_depth=max_resolution_depth,
        )

    def resolve(self, source: str | Buffer, destination: WritableBuffer) -> int:
        if isinstance(source, str):
            text = source
        else:
            with memoryview(source) as view:
                text = str(view, "utf-8", "replace")
        self._reader.read_keys_all([text, *self._also_allowed])
        return self._resolver.resolve(source, destination)


def create_template_resolver(token: ConfigurationItemTokenBase, provider: ValueProvider, template: str | Buffer) -> ConfigurationItemResolver:
    """Reads the keys of a trusted template and creates a resolver that allows only those keys:
    the port of TemplateFile.CreateResolver."""
    reader = ConfigurationItemReader(token)
    reader.read_keys(template)
    return ConfigurationItemResolver(token, reader, provider)


# --- Helpers ----------------------------------------------------------------------------------


def both(source: str) -> list[str | bytes]:
    """``source`` as a ``str`` and as UTF-8 bytes: the two forms .NET's char and byte overloads take."""
    return [source, source.encode()]


def resolve_to_str(resolver: ConfigurationResolver, source: str | Buffer, destination_length: int = 1024) -> str:
    """Resolves ``source`` into a new destination and decodes what was written."""
    destination = bytearray(destination_length)
    written = resolver.resolve(source, destination)
    return destination[:written].decode()


def filled(length: int, fill: int = ord("#")) -> bytearray:
    """A destination of ``length`` bytes, each ``fill``."""
    return bytearray([fill]) * length


def assert_zeroed(destination: bytearray) -> None:
    assert destination == bytearray(len(destination))


def assert_key_error(error: ConfigurationKeyError, key: str, code: ConfigurationKeyErrorCode, source_index: int) -> None:
    """The port of .NET's AssertKeyException: the key, error and index, and a message without the key."""
    assert error.key == key
    assert error.error is code
    assert error.source_index == source_index
    assert str(error) == f"The configuration item at index {source_index} could not be resolved ({code.value})."
    assert key not in str(error)
