"""Reads a key file only after its location passes the platform's checks."""

from __future__ import annotations

import os
import platform
import sys
from collections.abc import Buffer, Callable
from pathlib import PureWindowsPath
from typing import Final

from hkdfguard.abstractions import ArrayUtility, InvalidKeyFileError, WrappedKeyLimits
from hkdfguard.securefile import _unix, _win32
from hkdfguard.securefile._trust import KeyFileTrust
from hkdfguard.securefile._unix import UnixKeyFileChecks
from hkdfguard.securefile._windows import DriveType, WindowsKeyFileChecks

_WHITESPACE: Final = frozenset(b" \t\r\n\v\f")
"""What .NET trims: space, tab, CR, LF, VT and FF."""

_HEX_DIGITS: Final = frozenset(b"0123456789abcdefABCDEF")
_ALPHANUMERIC: Final = frozenset(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class TrustedKeyFile:
    """Reads a key file only after its location passes the platform's checks (WindowsKeyFileChecks,
    UnixKeyFileChecks): the Python equivalent of the native library's ``hkdfguard_open_file``, for a
    :meth:`KeyWrapper.read_key_file <hkdfguard.abstractions.KeyWrapper.read_key_file>` with no native
    library to read through - a network KMS's key wrapper, say. The contents are then held to the same
    rules: 1 to :attr:`WrappedKeyLimits.MAX_BYTES` bytes, never more than one byte past that read, and
    not something that looks like an unwrapped key.

    Windows, Linux and Apple silicon Macs are supported, with no native HkdfGuard library installed:
    on Windows the checks are Win32 calls made through ``ctypes``; on Linux and macOS, ``os.lstat`` and
    ``os.readlink``.
    """

    PLAINTEXT_KEY_LENGTH: Final = 32
    """The length of an unwrapped DEK; a file this size is probably a plaintext key."""

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
        if path is None:
            raise TypeError("path must not be None.")
        text = os.fspath(path)
        if not isinstance(text, str):
            raise TypeError("path must be a str or os.PathLike[str].")
        if not text:
            raise ValueError("A key file path is required.")
        if "\0" in text:
            raise ValueError("A key file path can't contain a NUL character.")
        if trust is None:
            raise TypeError("trust must not be None.")
        if not isinstance(trust, KeyFileTrust):
            raise TypeError("trust must be a KeyFileTrust.")

        # Dispatches to one platform's wiring; each is exercised by the real-file tests on its own platform.
        if sys.platform == "win32":
            return TrustedKeyFile._read_windows(text, trust)
        if sys.platform.startswith("linux"):
            return TrustedKeyFile._read_unix(text, trust)
        if sys.platform == "darwin":
            # .NET and Java read struct stat at arm64 offsets; os.lstat has no such limit, but the
            # supported platforms are kept the same in every port.
            machine = platform.machine()
            if machine != "arm64":
                raise NotImplementedError(f"Key files are read on Apple silicon Macs only; this process is {machine}.")
            return TrustedKeyFile._read_unix(text, trust)
        raise NotImplementedError("Key files are read on Windows, Linux and macOS only.")

    @staticmethod
    def _read_windows(path: str, trust: KeyFileTrust) -> bytearray:
        # Wires the WindowsKeyFileChecks policy to real files; exercised by the Windows-only real-file tests.
        trusted = WindowsKeyFileChecks.trusted_principals(trust, _win32.canonical_sid, _win32.account_name)
        # GetFullPathNameW resolves a relative path against the working directory, as .NET's
        # Path.GetFullPath does, and the short names in it are then expanded.
        full = _win32.full_path(path)
        WindowsKeyFileChecks.verify_path_form(full, DriveType.NETWORK if full.startswith("\\\\")
                                              else DriveType.from_win32(_win32.drive_type(PureWindowsPath(full).anchor)))

        # Read sharing only: refused if another process has it open for writing, and no one can open
        # it for writing while it's read.
        with _win32.open_file(full) as file:
            WindowsKeyFileChecks.verify_final_path(full, file.final_path())

            # The file through its own handle; the folders by path, which the final-path check ties to
            # the folders it was opened through, and which no untrusted principal can then change.
            WindowsKeyFileChecks.verify_trusted_only(file.security_descriptor(), full, full, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted,
                                                     account_name=_win32.account_name)
            folder = PureWindowsPath(full).parent
            while True:
                name = str(folder)
                security = _win32.security_descriptor_of(name)
                if folder.parent == folder:
                    WindowsKeyFileChecks.verify_trusted_only(security, full, name, WindowsKeyFileChecks.GUARDED_ROOT_RIGHTS, trusted,
                                                             account_name=_win32.account_name)
                    break

                WindowsKeyFileChecks.verify_not_reparse_point(_win32.file_attributes(name), full, name)
                WindowsKeyFileChecks.verify_trusted_only(security, full, name, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted,
                                                         account_name=_win32.account_name)
                folder = folder.parent

            return TrustedKeyFile.read_contents(file.readinto, full)

    @staticmethod
    def _read_unix(path: str, trust: KeyFileTrust) -> bytearray:
        # Wires the UnixKeyFileChecks policy to real files; exercised by the Unix-only real-file tests.
        # The working directory is already a resolved path; resolve_trusted handles ".." itself.
        if path.startswith("/"):
            absolute = path
        else:
            working_directory = os.getcwd()
            absolute = working_directory + path if working_directory.endswith("/") else f"{working_directory}/{path}"
        resolved = UnixKeyFileChecks.resolve_trusted(absolute, trust, _unix.status_or_none, _unix.read_link)

        # resolved holds no symbolic link, so O_NOFOLLOW changes nothing for a file that passed; it
        # only makes certain the last component is still not one when it is opened.
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with open(descriptor, "rb", buffering=0) as file:
            return TrustedKeyFile.read_contents(file.readinto, path)

    @staticmethod
    def read_contents(readinto: Callable[[memoryview], int | None], path: str) -> bytearray:
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
            total = 0
            while total < len(buffer):
                read = readinto(view[total:])
                if not read:
                    break
                total += read

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
        """The native library's test for a plaintext key written to disk: exactly 32 bytes, or a 32-byte
        key as 64 hex digits or as base64 (standard or URL-safe, padded or not), with any surrounding
        whitespace. Reads ``contents`` in place, making no copy of it."""
        with memoryview(contents) as raw, raw.cast("B") as data:
            if len(data) == TrustedKeyFile.PLAINTEXT_KEY_LENGTH:
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
