"""Where configuration values come from."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Final

from hkdfguard.abstractions import ArrayUtility, WritableBuffer
from hkdfguard.integration.configurationresolver._errors import ConfigurationKeyError, ConfigurationKeyErrorCode


class ValueStatus(Enum):
    """The result of asking a :class:`ValueProvider` for a value. Each value is its .NET name."""

    FOUND = "Found"
    """The key was found and its value was written."""

    NOT_FOUND = "NotFound"
    """The key was not found. Nothing was written."""

    DESTINATION_TOO_SMALL = "DestinationTooSmall"
    """The key was found, but its value does not fit in the destination. Nothing usable was written."""


class ValueProvider(ABC):
    """Provides configuration values by key: the port of IValueProvider. Values are UTF-8 bytes, so
    .NET's TryGetChar is :meth:`try_get_bytes` here."""

    @abstractmethod
    def try_get_value(self, key: str) -> tuple[ValueStatus, str | None]:
        """The value for ``key`` as a ``str``. A ``str`` can't be zeroed once created: prefer
        :meth:`try_get_bytes` for secrets.

        :returns: :attr:`ValueStatus.FOUND` and the value, or :attr:`ValueStatus.NOT_FOUND` and ``None``
        """

    @abstractmethod
    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        """Writes the UTF-8 value for ``key`` to the start of ``destination``.

        :returns: whether the value was found and fit in ``destination``, and the number of bytes
            written - 0 unless found
        """


_MAX_READ_ATTEMPTS: Final = 3
"""How many times a value is re-read when it grows between being sized and being read."""


class ValueProviderBase(ValueProvider):
    """Base class for value providers whose values are bytes, such as files or decrypted data.

    Subclasses implement :meth:`try_get_bytes` and :meth:`_find_byte_count`. :meth:`try_get_value`
    is built on them: the value's bytes are read into a ``bytearray`` sized by _find_byte_count,
    decoded, and the ``bytearray`` is zeroed. A value that keeps outgrowing its size, read after
    read, raises :class:`ConfigurationKeyError` with :attr:`ConfigurationKeyErrorCode.VALUE_UNSTABLE`.
    """

    @abstractmethod
    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]: ...

    @abstractmethod
    def _find_byte_count(self, key: str) -> int | None:
        """The number of UTF-8 bytes needed to hold the value for ``key`` - the buffer size
        :meth:`try_get_bytes` needs - or ``None`` if the key was not found."""

    def try_get_value(self, key: str) -> tuple[ValueStatus, str | None]:
        """:raises ConfigurationKeyError: the value kept changing size while it was read"""
        for _ in range(_MAX_READ_ATTEMPTS):
            byte_count = self._find_byte_count(key)
            if byte_count is None:
                return ValueStatus.NOT_FOUND, None

            buffer = bytearray(byte_count)
            try:
                status, length = self.try_get_bytes(key, buffer)
                if status is ValueStatus.FOUND:
                    with memoryview(buffer) as view:
                        return ValueStatus.FOUND, str(view[:length], "utf-8", "replace")
                if status is not ValueStatus.DESTINATION_TOO_SMALL:
                    return status, None
            finally:
                ArrayUtility.zero_memory(buffer)

        raise ConfigurationKeyError(key, ConfigurationKeyErrorCode.VALUE_UNSTABLE)


class CompositeValueProvider(ValueProvider):
    """Provides configuration values from several value providers, in priority order.

    Each lookup asks the providers in the order given, and the first provider that has the key
    supplies the value; the providers after it are not asked. A provider that has the key but whose
    value does not fit in the destination ends the lookup with
    :attr:`ValueStatus.DESTINATION_TOO_SMALL`, rather than falling through to a lower-priority value.
    An exception a provider raises, such as a :class:`ConfigurationKeyError`, is not caught. Put the
    provider you trust most first.
    """

    def __init__(self, *providers: ValueProvider) -> None:
        """:param providers: the providers to ask, highest priority first
        :raises ValueError: ``providers`` is empty
        :raises TypeError: ``providers`` contains ``None``
        """
        if not providers:
            raise ValueError("At least one value provider is required.")
        if any(provider is None for provider in providers):
            raise TypeError("The value providers must not contain None.")
        self._providers = tuple(providers)

    @property
    def providers(self) -> tuple[ValueProvider, ...]:
        """The providers, highest priority first."""
        return self._providers

    def try_get_value(self, key: str) -> tuple[ValueStatus, str | None]:
        for provider in self._providers:
            status, value = provider.try_get_value(key)
            if status is ValueStatus.FOUND:
                return ValueStatus.FOUND, value
        return ValueStatus.NOT_FOUND, None

    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        for provider in self._providers:
            status, written = provider.try_get_bytes(key, destination)
            if status is not ValueStatus.NOT_FOUND:
                return status, written
        return ValueStatus.NOT_FOUND, 0
