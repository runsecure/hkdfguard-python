"""The start, end and escape sequences of a configuration item."""

from __future__ import annotations

from typing import Final


class ConfigurationItemTokenBase:
    """Base class for tokens that identify configuration items delimited by a start and an end
    sequence, such as ``${Name}``. Use the same token for a reader and the resolver given that
    reader. A token is immutable."""

    DEFAULT_START_SEQUENCE: Final = "${"
    """The default sequence that marks the start of a configuration item."""

    DEFAULT_END_SEQUENCE: Final = "}"
    """The default sequence that marks the end of a configuration item."""

    DEFAULT_ESCAPE_SEQUENCE: Final = "$"
    """The escape sequence of :class:`DefaultToken`, so that ``$${Name}`` is written as the literal
    text ``${Name}``."""

    def __init__(self, start_sequence: str = DEFAULT_START_SEQUENCE, end_sequence: str = DEFAULT_END_SEQUENCE, escape_sequence: str | None = None) -> None:
        """:param start_sequence: marks the start of a configuration item
        :param end_sequence: marks the end of a configuration item
        :param escape_sequence: directly before a start sequence, makes it literal text instead of
            the start of an item; ``None``, the default, for no escape sequence
        :raises TypeError: ``start_sequence`` or ``end_sequence`` is ``None``
        :raises ValueError: ``start_sequence`` or ``end_sequence`` is empty, or ``escape_sequence``
            is empty
        """
        for name, value in (("start_sequence", start_sequence), ("end_sequence", end_sequence)):
            if value is None:
                raise TypeError(f"{name} must not be None.")
            if not value:
                raise ValueError(f"{name} must not be empty.")
        if escape_sequence is not None and not escape_sequence:
            raise ValueError("escape_sequence must not be empty; pass None for no escape sequence.")
        self._start_sequence = start_sequence
        self._end_sequence = end_sequence
        self._escape_sequence = escape_sequence

    @property
    def start_sequence(self) -> str:
        """The sequence that marks the start of a configuration item."""
        return self._start_sequence

    @property
    def end_sequence(self) -> str:
        """The sequence that marks the end of a configuration item."""
        return self._end_sequence

    @property
    def escape_sequence(self) -> str | None:
        """The sequence that, directly before a start sequence, makes it literal text, or ``None``
        if the token has none.

        The escape sequence is removed and the start sequence is copied as text, so with the escape
        sequence ``$``, ``$${Name}`` is written as ``${Name}`` and ``Name`` is not a key. Only the
        start sequence is escaped: the text after it is read as usual, so it can contain other
        items. An escape sequence anywhere else is ordinary text.
        """
        return self._escape_sequence


class DefaultToken(ConfigurationItemTokenBase):
    """A token that uses the default ``${`` and ``}`` sequences, with ``$`` as its escape sequence,
    so ``$${Name}`` is written as the literal text ``${Name}``."""

    def __init__(self) -> None:
        super().__init__(escape_sequence=ConfigurationItemTokenBase.DEFAULT_ESCAPE_SEQUENCE)
