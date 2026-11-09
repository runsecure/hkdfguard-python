"""Why a configuration item could not be resolved."""

from __future__ import annotations

from enum import Enum


class ConfigurationKeyErrorCode(Enum):
    """Why a configuration item could not be resolved: the port of the .NET ConfigurationKeyError
    enum. Each value is its .NET name, which is what messages show."""

    NOT_ALLOWED = "NotAllowed"
    """The key was not read by the configuration item reader, so no value provider was asked for it."""

    NOT_FOUND = "NotFound"
    """The key was allowed, but no value provider has a value for it."""

    VALUE_UNSTABLE = "ValueUnstable"
    """The value kept changing size while it was read, such as a secret being replaced."""

    CYCLE = "Cycle"
    """The key's value, resolved through the items in it, leads back to the same key."""


class ConfigurationKeyError(Exception):
    """Raised when the value for a configuration key could not be resolved: the port of
    ConfigurationKeyException.

    The message holds only the item's position and the :attr:`error`, so it is safe to log. The
    key is available from :attr:`key`; it may come from the source text, which may be untrusted,
    so treat it as untrusted input before logging or displaying it.
    """

    def __init__(self, key: str, error: ConfigurationKeyErrorCode, source_index: int | None = None) -> None:
        """:param key: the configuration key; for an item in a source, its trimmed key
        :param error: why the value could not be resolved
        :param source_index: the byte index in the source where the item's start sequence begins,
            or ``None`` when it isn't known, such as when raised by a value provider
        """
        if source_index is None:
            message = f"The value for a configuration key could not be resolved ({error.value})."
        else:
            message = f"The configuration item at index {source_index} could not be resolved ({error.value})."
        super().__init__(message)
        self._key = key
        self._error = error
        self._source_index = source_index

    @property
    def key(self) -> str:
        """The configuration key. When raised by a resolver it comes from the source text and may be untrusted."""
        return self._key

    @property
    def error(self) -> ConfigurationKeyErrorCode:
        """Why the value could not be resolved."""
        return self._error

    @property
    def source_index(self) -> int | None:
        """The index in the UTF-8 source where the item's start sequence begins, or ``None`` when
        raised outside a resolver, such as by a value provider called directly."""
        return self._source_index


class DestinationTooSmallError(ValueError):
    """The destination is too small for the resolved text: the port of the ArgumentException a
    .NET resolver throws for its destination."""

    def __init__(self) -> None:
        super().__init__("The destination is too small for the resolved text.")
