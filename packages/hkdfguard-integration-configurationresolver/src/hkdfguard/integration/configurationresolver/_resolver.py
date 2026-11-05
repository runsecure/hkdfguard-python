"""Resolves text by replacing its configuration items with their values."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Buffer

from hkdfguard.abstractions import ArrayUtility, WritableBuffer
from hkdfguard.integration.configurationresolver._errors import ConfigurationKeyError, ConfigurationKeyErrorCode, DestinationTooSmallError
from hkdfguard.integration.configurationresolver._reader import KeyReader
from hkdfguard.integration.configurationresolver._text import item_key, utf8_of
from hkdfguard.integration.configurationresolver._tokens import ConfigurationItemTokenBase
from hkdfguard.integration.configurationresolver._value_providers import CompositeValueProvider, ValueProvider, ValueStatus


class ConfigurationResolver(ABC):
    """Resolves text by replacing its configuration items, such as ``${Name}``, with their values:
    the port of IConfigurationResolver."""

    @abstractmethod
    def resolve(self, source: str | Buffer, destination: WritableBuffer) -> int:
        """Copies ``source`` - a ``str``, or UTF-8 bytes - to ``destination`` as UTF-8, replacing
        each configuration item with its UTF-8 value. ``destination`` must not overlap ``source``.

        :returns: the number of bytes written to ``destination``
        :raises DestinationTooSmallError: ``destination`` is too small for the resolved text
        :raises ConfigurationKeyError: an item's key is not allowed, has no value, or its value kept
            changing while it was read
        """


class ConfigurationItemResolver(ConfigurationResolver):
    """Resolves text by replacing the configuration items a token delimits with values from one or
    more :class:`ValueProvider` s, for only the keys a reader read: the port of
    ConfigurationItemResolver.

    Keys are trimmed of surrounding whitespace, as :class:`ConfigurationItemReader` trims them.
    Only keys the reader's :meth:`~KeyReader.keys` returns are looked up, so read the keys from a
    trusted template first; any other key raises without a provider being asked for it. With
    several value providers, each key is looked up in the order the providers were given, and the
    first that has the key supplies the value, as with :class:`CompositeValueProvider`. A key that
    is not allowed raises :class:`ConfigurationKeyError`, whose message does not contain the key. A
    key that no provider has raises the same way, unless ``ignore_unresolvable_placeholders`` is set.

    The reader's keys are read on each resolve, so the most recent read applies. Empty items such as
    ``${}`` and a start sequence with no matching end sequence are copied unchanged, and a start
    sequence preceded by the token's escape sequence is copied without the escape sequence. By
    default values are inserted as they are; set ``max_resolution_depth`` to also resolve the items
    inside values.

    Values are written by the provider directly into the destination and are never read as ``str``.
    If resolving fails, the whole destination is zeroed, so no partially resolved values are left
    behind.
    """

    def __init__(
        self,
        token: ConfigurationItemTokenBase,
        reader: KeyReader,
        *value_providers: ValueProvider,
        ignore_unresolvable_placeholders: bool = False,
        max_resolution_depth: int = 1,
    ) -> None:
        """:param token: the start, end, and escape sequences of a configuration item
        :param reader: the reader whose keys are the only keys that may be resolved
        :param value_providers: the providers of each key's value, highest priority first
        :param ignore_unresolvable_placeholders: copy an allowed key that no value provider has to
            the destination unchanged, start and end sequences included, instead of raising with
            :attr:`ConfigurationKeyErrorCode.NOT_FOUND`. A key that is not allowed still raises with
            NOT_ALLOWED, and an error a value provider raises, such as VALUE_UNSTABLE, still
            propagates.
        :param max_resolution_depth: the number of levels of items resolved. At 1, the default,
            values are inserted exactly as they are, even if they contain items. At 2, the items in
            each value are resolved too, and their values are inserted as they are; each further
            level resolves one more level of values. Items in values follow the same rules as items
            in the source: their keys must be allowed by the reader, and escape sequences in values
            are applied. Values at the last level are inserted unchanged, escape sequences included.
            A key whose value leads back to itself raises with CYCLE. An error in a value reports
            the position of the item in the source that led to it. A value that is resolved is held
            in a ``bytearray`` that is zeroed afterwards, and is never read as a ``str``.
        :raises TypeError: ``token`` or ``reader`` is ``None``, or ``value_providers`` contains ``None``
        :raises ValueError: ``value_providers`` is empty, or ``max_resolution_depth`` is less than 1
        """
        if token is None:
            raise TypeError("token must not be None.")
        if reader is None:
            raise TypeError("reader must not be None.")
        if max_resolution_depth < 1:
            raise ValueError(f"max_resolution_depth must be at least 1, not {max_resolution_depth}.")
        composite = CompositeValueProvider(*value_providers)

        self._reader = reader
        self._value_provider: ValueProvider = composite.providers[0] if len(composite.providers) == 1 else composite
        self._start = token.start_sequence.encode()
        self._end = token.end_sequence.encode()
        self._escape = (token.escape_sequence or "").encode()
        self._ignore_unresolvable_placeholders = ignore_unresolvable_placeholders
        self._max_resolution_depth = max_resolution_depth

    @property
    def ignore_unresolvable_placeholders(self) -> bool:
        """Whether an allowed key that no value provider has is copied unchanged instead of raising."""
        return self._ignore_unresolvable_placeholders

    @property
    def max_resolution_depth(self) -> int:
        """The number of levels of configuration items that are resolved; 1 by default."""
        return self._max_resolution_depth

    def resolve(self, source: str | Buffer, destination: WritableBuffer) -> int:
        if source is None:
            raise TypeError("source must not be None.")
        if destination is None:
            raise TypeError("destination must not be None.")
        with memoryview(destination) as view:
            out = view.cast("B")
            if out.readonly:
                raise TypeError("destination must be a writable buffer, such as a bytearray.")
            text, owned = utf8_of(source)
            run = _Resolution(self, out, frozenset(self._reader.keys()))
            try:
                run.write(text, depth=1, item_index=None)
                return run.written
            except BaseException:
                ArrayUtility.zero_memory(out)
                raise
            finally:
                if owned:
                    ArrayUtility.zero_memory(text)  # type: ignore[arg-type]
                out.release()


class _Resolution:
    """One resolve call's state: the destination, how much of it is written, the allowed keys, and
    the keys whose values are being resolved, outermost first."""

    def __init__(self, resolver: ConfigurationItemResolver, destination: memoryview, allowed_keys: frozenset[str]) -> None:
        self._resolver = resolver
        self._destination = destination
        self._allowed_keys = allowed_keys
        self._resolving: list[str] = []
        self.written = 0

    def write(self, text: bytes | bytearray, depth: int, item_index: int | None) -> None:
        """Copies ``text`` to the destination, replacing each configuration item with its value.
        ``depth`` is 1 for the source, 2 for a value in it, and so on; ``item_index`` is the index
        of the item in the source that led to this text, or ``None`` for the source itself."""
        resolver = self._resolver
        start, end, escape = resolver._start, resolver._end, resolver._escape
        with memoryview(text) as view:
            position = 0
            while True:
                start_index = text.find(start, position)
                if start_index < 0:
                    self._copy(view[position:])
                    return

                key_start = start_index + len(start)
                if escape and text.endswith(escape, position, start_index):
                    self._copy(view[position : start_index - len(escape)])
                    self._copy(start)
                    consumed = key_start
                else:
                    end_index = text.find(end, key_start)
                    if end_index < 0:
                        self._copy(view[position:])
                        return

                    consumed = end_index + len(end)
                    key = item_key(text, key_start, end_index)
                    if not key:
                        self._copy(view[position:consumed])
                    else:
                        self._copy(view[position:start_index])
                        source_index = start_index if item_index is None else item_index
                        if not self._try_write_value(key, source_index, depth):
                            self._copy(view[start_index:consumed])

                position = consumed

    def _try_write_value(self, key: str, source_index: int, depth: int) -> bool:
        """Writes ``key``'s value to the destination, resolving the items in it if the depth allows.

        :returns: ``False`` when no provider has the key and unresolvable placeholders are ignored,
            so the item is to be copied unchanged
        """
        resolver = self._resolver
        if key not in self._allowed_keys:
            raise ConfigurationKeyError(key, ConfigurationKeyErrorCode.NOT_ALLOWED, source_index)
        if key in self._resolving:
            raise ConfigurationKeyError(key, ConfigurationKeyErrorCode.CYCLE, source_index)

        room = self._destination[self.written :]
        try:
            status, length = resolver._value_provider.try_get_bytes(key, room)
        except ConfigurationKeyError as error:
            if error.source_index is not None:
                raise
            raise ConfigurationKeyError(error.key, error.error, source_index) from error

        if status is ValueStatus.NOT_FOUND and resolver.ignore_unresolvable_placeholders:
            return False
        if status is ValueStatus.DESTINATION_TOO_SMALL:
            raise DestinationTooSmallError
        if status is not ValueStatus.FOUND:
            raise ConfigurationKeyError(key, ConfigurationKeyErrorCode.NOT_FOUND, source_index)
        if not 0 <= length <= len(room):
            raise RuntimeError(f"A value provider reported writing {length} bytes into {len(room)}.")

        if depth >= resolver.max_resolution_depth:
            self.written += length
            return True

        # Move the value to a copy, zero it in the destination, and write it back resolved.
        copy = bytearray(room[:length])
        try:
            if copy.find(resolver._start) < 0:
                self.written += length
                return True
            ArrayUtility.zero_memory(room[:length])
            self._resolving.append(key)
            self.write(copy, depth + 1, source_index)
            self._resolving.pop()
            return True
        finally:
            ArrayUtility.zero_memory(copy)

    def _copy(self, text: memoryview | bytes) -> None:
        length = len(text)
        if length > len(self._destination) - self.written:
            raise DestinationTooSmallError
        self._destination[self.written : self.written + length] = text
        self.written += length
