"""Reads the keys of the configuration items in a template."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Buffer, Iterable
from typing import BinaryIO

from hkdfguard.abstractions import ArrayUtility
from hkdfguard.integration.configurationresolver._text import decode_stream_text, item_key, utf8_of
from hkdfguard.integration.configurationresolver._tokens import ConfigurationItemTokenBase


class KeyReader(ABC):
    """What a resolver needs of a reader: the keys it may resolve - the ``Keys`` member of .NET's
    IConfigurationItemReader. :class:`ConfigurationItemReader` implements it."""

    @abstractmethod
    def keys(self) -> list[str]:
        """The keys of the most recent read."""


class ConfigurationItemReader(KeyReader):
    """Reads text and extracts the keys of the configuration items delimited by a token's start
    and end sequences: the port of ConfigurationItemReader.

    Keys are trimmed of surrounding whitespace, and empty keys are skipped. A start sequence with
    no matching end sequence is ignored, and so is a start sequence preceded by the token's escape
    sequence. Each read replaces the keys :meth:`keys` returns.
    """

    def __init__(self, token: ConfigurationItemTokenBase) -> None:
        """:raises TypeError: ``token`` is ``None``"""
        if token is None:
            raise TypeError("token must not be None.")
        self._start = token.start_sequence.encode()
        self._end = token.end_sequence.encode()
        self._escape = (token.escape_sequence or "").encode()
        self._keys: tuple[str, ...] = ()

    def keys(self) -> list[str]:
        """The keys extracted by the most recent read, or none if nothing has been read."""
        return list(self._keys)

    def read_keys(self, text: str | Buffer) -> list[str]:
        """Extracts the keys of the configuration items in ``text``: a ``str``, or UTF-8 bytes.

        :returns: the trimmed keys, in the order they appear
        """
        if text is None:
            raise TypeError("text must not be None.")
        keys: list[str] = []
        self._add_keys(text, keys)
        self._keys = tuple(keys)
        return keys

    def read_keys_from(self, stream: BinaryIO, encoding: str | None = None) -> list[str]:
        """Reads ``stream`` to its end as text and extracts the keys of the configuration items it
        contains. It is read from its current position and is left open.

        :param encoding: the stream's encoding, UTF-8 by default; a UTF-8, UTF-16 or UTF-32 byte
            order mark in the stream takes precedence
        :returns: the trimmed keys, in the order they appear
        """
        if stream is None:
            raise TypeError("stream must not be None.")
        return self.read_keys(decode_stream_text(stream.read(), encoding))

    def read_keys_all(self, texts: Iterable[str]) -> list[str]:
        """Extracts the keys of the configuration items in each of several texts, such as the
        values of a configuration, and keeps the keys from all of them. Each text is read on its
        own, so an item can't start in one text and end in the next.

        :returns: the trimmed keys, in the order they appear, text by text
        :raises TypeError: ``texts`` is, or contains, ``None``; or ``texts`` is a single ``str``
        """
        if texts is None:
            raise TypeError("texts must not be None.")
        if isinstance(texts, str):
            raise TypeError("texts must be several texts, not one str: use read_keys for one.")
        keys: list[str] = []
        for text in texts:
            if text is None:
                raise TypeError("The texts must not contain None.")
            self._add_keys(text, keys)
        self._keys = tuple(keys)
        return keys

    def _add_keys(self, text: str | Buffer, keys: list[str]) -> None:
        data, owned = utf8_of(text)
        try:
            start, end, escape = self._start, self._end, self._escape
            position = 0
            while True:
                start_index = data.find(start, position)
                if start_index < 0:
                    return

                escaped = bool(escape) and data.endswith(escape, position, start_index)
                position = start_index + len(start)
                if escaped:
                    continue

                end_index = data.find(end, position)
                if end_index < 0:
                    return

                key = item_key(data, position, end_index)
                if key:
                    keys.append(key)
                position = end_index + len(end)
        finally:
            if owned:
                ArrayUtility.zero_memory(data)  # type: ignore[arg-type]
