"""Reads a key file only after its location passes the platform's checks."""

from __future__ import annotations

import os
from collections.abc import Buffer
from typing import Final

from hkdfguard.abstractions import ArrayUtility, InvalidKeyFileError, WrappedKeyLimits
from hkdfguard.securefile._trust import KeyFileTrust
from hkdfguard.securefile._trusted_file import ReadInto, TrustedFile

_WHITESPACE: Final = frozenset(b" \t\r\n\v\f")
"""What .NET trims: space, tab, CR, LF, VT and FF."""

_HEX_DIGITS: Final = frozenset(b"0123456789abcdefABCDEF")
_ALPHANUMERIC: Final = frozenset(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class TrustedKeyFile:
    """Reads a key file only after its location passes the platform's checks (WindowsKeyFileChecks,
    UnixKeyFileChecks, opened through :class:`TrustedFile`): the Python equivalent of the native
    library's ``hkdfguard_open_file``, for a :meth:`KeyWrapper.read_key_file
    <hkdfguard.abstractions.KeyWrapper.read_key_file>` with no native library to read through - a
    network KMS's key wrapper, say. The contents are then held to the same rules: 1 to
    :attr:`WrappedKeyLimits.MAX_BYTES` bytes, never more than one byte past that read, and not
    something that looks like an unwrapped key.

    Windows, Linux and Apple silicon Macs are supported, with no native HkdfGuard library installed:
    on Windows the checks are Win32 calls made through ``ctypes``; on Linux and macOS, ``os.lstat`` and
    ``os.readlink``.
    """

    PLAINTEXT_KEY_LENGTH: Final = 32
    """The length of an unwrapped DEK; a file this size, or this size plus one line ending (LF or CRLF),
    is probably a plaintext key."""

    PLAINTEXT_TEXT_SCAN_LIMIT: Final = 96
    """A 32-byte key as text is at most 64 hex digits; this allows surrounding whitespace."""

    @staticmethod
    def read(path: str | os.PathLike[str], trust: KeyFileTrust) -> bytearray:
        """Reads the key file at ``path``, still wrapped, refusing it unless only the operating
        system's administrators and ``trust`` could have written or replaced it, and refusing contents
        that aren't a wrapped key. A key file is a few hundred bytes on a local drive, so it is read on
        the calling thread.

        :param path: the key file's path, absolute or relative to the working directory
        :param trust: who besides administrators is trusted; :attr:`KeyFileTrust.ADMINISTRATORS_ONLY` for no one
        :returns: the file's contents, still wrapped; the caller owns them
        :raises FileNotFoundError: the file, or a folder in its path, doesn't exist
        :raises PermissionError: this account may not read it, or its location isn't trusted
        :raises InvalidKeyFileError: it is empty, too long, or holds what looks like an unwrapped key (an ``OSError``)
        :raises OSError: it can't be read, or another process has it open for writing
        :raises TypeError: ``path`` or ``trust`` is ``None``, or ``path`` is not a ``str`` path
        :raises ValueError: ``path`` is empty or holds a NUL, or ``trust`` names a principal that can't be trusted
        :raises NotImplementedError: not Windows, Linux or an Apple silicon Mac
        """
        text = TrustedFile.require_path(path, "key file")
        TrustedFile.require_trust(trust)
        with TrustedFile.open_trusted(text, trust) as opened:
            return TrustedKeyFile.read_contents(opened.readinto, opened.path)

    @staticmethod
    def read_contents(readinto: ReadInto, path: str) -> bytearray:
        """Reads at most one byte past :attr:`WrappedKeyLimits.MAX_BYTES` through ``readinto`` - so a
        wrong path (a log, a device) can't make startup allocate an unbounded buffer - and refuses an
        empty file, one over the limit, and one that looks like an unwrapped key. Whatever is read is
        zeroed once copied out or refused.

        :param readinto: reads into the view it is given, returning the count; 0 (or ``None``) at the end
        :param path: the path, for messages
        :returns: the contents, in a buffer the caller owns
        :raises InvalidKeyFileError: the contents are refused
        :raises OSError: the file could not be read
        """
        buffer = bytearray(WrappedKeyLimits.MAX_BYTES + 1)
        view = memoryview(buffer)
        try:
            total = TrustedFile.fill(readinto, buffer)

            if total == 0:
                raise InvalidKeyFileError(f"Key file '{path}' is empty.")
            if total > WrappedKeyLimits.MAX_BYTES:
                raise InvalidKeyFileError(f"Key file '{path}' is larger than {WrappedKeyLimits.MAX_BYTES} bytes (WrappedKeyLimits.MAX_BYTES); "
                                          "a wrapped key never is.")
            if TrustedKeyFile.looks_like_plaintext_key(view[:total]):
                raise InvalidKeyFileError(f"Key file '{path}' holds what looks like an unwrapped 32-byte key, not a wrapped one. Treat that key "
                                          "as exposed: replace it, and write key files with the key wrapper.")

            # Copied straight from the buffer: no intermediate copy outlives the zeroing below.
            contents = bytearray(total)
            contents[:] = view[:total]
            return contents
        finally:
            ArrayUtility.zero_memory(buffer)

    @staticmethod
    def looks_like_plaintext_key(contents: Buffer) -> bool:
        """The native library's test for a plaintext key written to disk: 32 raw bytes, optionally
        followed by one line ending (LF or CRLF), or a 32-byte key as 64 hex digits or as base64 (standard
        or URL-safe, padded or not), with any surrounding whitespace. The raw form is decided by length
        and the trailing line-ending bytes alone - never by trimming, since a raw key's own last bytes may
        be whitespace values. Reads ``contents`` in place, making no copy of it."""
        with memoryview(contents) as raw, raw.cast("B") as data:
            length = len(data)
            if length == TrustedKeyFile.PLAINTEXT_KEY_LENGTH:
                return True
            if length == TrustedKeyFile.PLAINTEXT_KEY_LENGTH + 1 and data[length - 1] == 0x0A:
                return True
            if length == TrustedKeyFile.PLAINTEXT_KEY_LENGTH + 2 and data[length - 2] == 0x0D and data[length - 1] == 0x0A:
                return True
            if len(data) > TrustedKeyFile.PLAINTEXT_TEXT_SCAN_LIMIT:
                return False

            start, end = 0, len(data)
            while start < end and data[start] in _WHITESPACE:
                start += 1
            while end > start and data[end - 1] in _WHITESPACE:
                end -= 1
            return TrustedKeyFile._is_hex_key(data, start, end) or TrustedKeyFile._is_base64_key(data, start, end)

    @staticmethod
    def _is_hex_key(text: memoryview, start: int, end: int) -> bool:
        return end - start == TrustedKeyFile.PLAINTEXT_KEY_LENGTH * 2 and all(text[i] in _HEX_DIGITS for i in range(start, end))

    @staticmethod
    def _is_base64_key(text: memoryview, start: int, end: int) -> bool:
        # 32 bytes: 43 characters, then one '=' when padded.
        if end - start == 44 and text[start + 43] == ord("="):
            end -= 1
        if end - start != 43:
            return False

        url_safe = standard = False
        for i in range(start, end):
            c = text[i]
            if c in _ALPHANUMERIC:
                continue
            if c in b"+/":
                standard = True
            elif c in b"-_":
                url_safe = True
            else:
                return False
        return not (url_safe and standard)
