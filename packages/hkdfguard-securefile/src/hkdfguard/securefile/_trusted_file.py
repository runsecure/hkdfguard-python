"""Reads any file only after its location passes the platform's checks."""

from __future__ import annotations

import os
import platform
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import PureWindowsPath
from typing import NamedTuple

from hkdfguard.abstractions import ArrayUtility
from hkdfguard.securefile import _unix, _win32
from hkdfguard.securefile._trust import KeyFileTrust
from hkdfguard.securefile._unix import UnixKeyFileChecks
from hkdfguard.securefile._windows import DriveType, WindowsKeyFileChecks

type ReadInto = Callable[[memoryview], int | None]
"""Reads into the view it is given, returning the count; 0 (or ``None``) at the end."""


class FileTooLargeError(OSError):
    """A file :class:`TrustedFile` read is longer than its caller allows - .NET's
    ``InvalidDataException`` from ``TrustedFile.ReadAsync``. An ``OSError``, so code that handles
    every way a file can fail to load still catches it."""


class OpenedFile(NamedTuple):
    """A file :meth:`TrustedFile.open_trusted` opened: how to read it, and the path to name it by."""

    readinto: ReadInto
    path: str


class TrustedFile:
    """Reads a file only after its location passes the platform's checks (WindowsKeyFileChecks,
    UnixKeyFileChecks) - the same symbolic-link, ownership and permission checks
    :class:`TrustedKeyFile <hkdfguard.securefile.TrustedKeyFile>` applies - but with none of a key
    file's rules about its contents: for secret files, certificates and anything else that must come
    from where only the operating system's administrators and :class:`KeyFileTrust` principals could
    have put it. What the contents must look like is the caller's to check.

    The caller says how large the file may be. At most one byte past that is read, whatever the file
    reports as its length, so a wrong path (a log, a device) can't make it read without end; the
    buffer is allocated at that size up front, so keep it close to the largest file expected. Files
    are small and local, so they are read on the calling thread.
    """

    @staticmethod
    def read(path: str | os.PathLike[str], trust: KeyFileTrust, max_bytes: int) -> bytearray:
        """Reads the file at ``path``, refusing it unless only the operating system's administrators
        and ``trust`` could have written or replaced it, or if it is longer than ``max_bytes``. For
        contents that are not themselves secret - a value encrypted elsewhere, a public certificate;
        use :meth:`read_with` for anything that is.

        :param path: the file's path, absolute or relative to the working directory
        :param trust: who besides administrators is trusted; :attr:`KeyFileTrust.ADMINISTRATORS_ONLY` for no one
        :param max_bytes: the longest file accepted
        :returns: the file's contents, which may be empty, in a buffer the caller owns
        :raises FileNotFoundError: the file, or a folder in its path, doesn't exist
        :raises PermissionError: this account may not read it, or its location isn't trusted
        :raises FileTooLargeError: it is longer than ``max_bytes`` (an ``OSError``)
        :raises OSError: it can't be read, or another process has it open for writing
        :raises TypeError: ``path``, ``trust`` or ``max_bytes`` is ``None`` or of the wrong type
        :raises ValueError: ``path`` is empty or holds a NUL, ``max_bytes`` isn't positive or is too
            large for one buffer, or ``trust`` names a principal that can't be trusted
        :raises NotImplementedError: not Windows, Linux or an Apple silicon Mac
        """
        text = TrustedFile.require_path(path, "file")
        TrustedFile._require_arguments(trust, max_bytes)
        with TrustedFile.open_trusted(text, trust) as opened:
            return TrustedFile.read_contents(opened.readinto, opened.path, max_bytes)

    @staticmethod
    def read_with[T](path: str | os.PathLike[str], trust: KeyFileTrust, max_bytes: int, parse: Callable[[memoryview], T]) -> T:
        """Reads the file at ``path`` as :meth:`read` does, and hands the contents to ``parse`` - for
        contents that are themselves secret, such as a PFX or a PEM private key. The buffer they are
        read into is zeroed once parse returns or raises, and the read-only view parse is given is
        released then, so parse must not keep it, and should zero any copy it makes.

        :param parse: turns the contents, which may be empty, into the result
        :returns: what ``parse`` returned
        :raises TypeError: ``parse`` isn't callable, or as :meth:`read`
        :raises FileNotFoundError: as :meth:`read`, which lists every other exception
        """
        text = TrustedFile.require_path(path, "file")
        TrustedFile._require_arguments(trust, max_bytes)
        if not callable(parse):
            raise TypeError("parse must be callable.")
        with TrustedFile.open_trusted(text, trust) as opened:
            return TrustedFile.parse_contents(opened.readinto, opened.path, max_bytes, parse)

    @staticmethod
    def require_path(path: str | os.PathLike[str], what: str) -> str:
        """``path`` as a ``str``, refusing one that is ``None``, not a ``str`` path, empty or holds a
        NUL; ``what`` names the file in the messages ("file", "key file")."""
        if path is None:
            raise TypeError("path must not be None.")
        text = os.fspath(path)
        if not isinstance(text, str):
            raise TypeError("path must be a str or os.PathLike[str].")
        if not text:
            raise ValueError(f"A {what} path is required.")
        if "\0" in text:
            raise ValueError(f"A {what} path can't contain a NUL character.")
        return text

    @staticmethod
    def require_trust(trust: KeyFileTrust) -> None:
        """Refuses a ``trust`` that is ``None`` or not a :class:`KeyFileTrust`."""
        if trust is None:
            raise TypeError("trust must not be None.")
        if not isinstance(trust, KeyFileTrust):
            raise TypeError("trust must be a KeyFileTrust.")

    @staticmethod
    def _require_arguments(trust: KeyFileTrust, max_bytes: int) -> None:
        TrustedFile.require_trust(trust)
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise TypeError("max_bytes must be an int.")
        if max_bytes <= 0:
            raise ValueError(f"max_bytes must be positive; it is {max_bytes}.")
        if max_bytes >= sys.maxsize:
            raise ValueError(f"max_bytes must be less than {sys.maxsize}; it is {max_bytes}.")

    @staticmethod
    @contextmanager
    def open_trusted(path: str, trust: KeyFileTrust) -> Iterator[OpenedFile]:
        """Opens ``path`` for reading once the platform's checks have passed, refusing it if another
        process has it open for writing; while it's open, no one can open it for writing. Closed when
        the ``with`` block ends. ``path`` must already have passed :meth:`require_path`, and ``trust``
        :meth:`require_trust`.

        :raises FileNotFoundError: the file, or a folder in its path, doesn't exist
        :raises PermissionError: this account may not read it, or its location isn't trusted
        :raises OSError: another process has it open for writing
        :raises ValueError: ``trust`` names a principal that can't be trusted
        :raises NotImplementedError: not Windows, Linux or an Apple silicon Mac
        """
        # Dispatches to one platform's wiring; each is exercised by the real-file tests on its own platform.
        if sys.platform == "win32":
            opener = TrustedFile._open_windows
        elif sys.platform.startswith("linux"):
            opener = TrustedFile._open_unix
        elif sys.platform == "darwin":
            # .NET and Java read struct stat at arm64 offsets; os.lstat has no such limit, but the
            # supported platforms are kept the same in every port.
            machine = platform.machine()
            if machine != "arm64":
                raise NotImplementedError(f"Trusted files are read on Apple silicon Macs only; this process is {machine}.")
            opener = TrustedFile._open_unix
        else:
            raise NotImplementedError("Trusted files are read on Windows, Linux and macOS only.")

        with opener(path, trust) as opened:
            yield opened

    @staticmethod
    @contextmanager
    def _open_windows(path: str, trust: KeyFileTrust) -> Iterator[OpenedFile]:
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

            yield OpenedFile(file.readinto, full)

    @staticmethod
    @contextmanager
    def _open_unix(path: str, trust: KeyFileTrust) -> Iterator[OpenedFile]:
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
            yield OpenedFile(file.readinto, path)

    @staticmethod
    def fill(readinto: ReadInto, buffer: bytearray) -> int:
        """Reads through ``readinto`` until ``buffer`` is full or the file ends, returning the count.
        Callers make ``buffer`` one byte longer than the longest file they accept, so filling it means
        the file is too long."""
        view = memoryview(buffer)
        total = 0
        while total < len(buffer):
            read = readinto(view[total:])
            if not read:
                break
            total += read
        return total

    @staticmethod
    def read_contents(readinto: ReadInto, path: str, max_bytes: int) -> bytearray:
        """Reads at most one byte past ``max_bytes`` through ``readinto``, refusing a longer file, and
        returns what was read. The read buffer is zeroed once copied out or refused.

        :param path: the path, for messages
        :returns: the contents, which may be empty, in a buffer the caller owns
        :raises FileTooLargeError: the contents are longer than ``max_bytes``
        :raises OSError: the file could not be read
        """
        buffer = bytearray(max_bytes + 1)
        try:
            total = TrustedFile._fill_bounded(readinto, buffer, path)
            # Copied straight from the buffer: no intermediate copy outlives the zeroing below.
            contents = bytearray(total)
            contents[:] = memoryview(buffer)[:total]
            return contents
        finally:
            ArrayUtility.zero_memory(buffer)

    @staticmethod
    def parse_contents[T](readinto: ReadInto, path: str, max_bytes: int, parse: Callable[[memoryview], T]) -> T:
        """Reads as :meth:`read_contents` does, and returns what ``parse`` makes of a read-only view
        of the contents; the buffer is zeroed, and the view released, whether parse returns or raises.

        :raises FileTooLargeError: the contents are longer than ``max_bytes``
        :raises OSError: the file could not be read
        """
        buffer = bytearray(max_bytes + 1)
        try:
            total = TrustedFile._fill_bounded(readinto, buffer, path)
            with memoryview(buffer) as whole, whole[:total] as part, part.toreadonly() as contents:
                return parse(contents)
        finally:
            ArrayUtility.zero_memory(buffer)

    @staticmethod
    def _fill_bounded(readinto: ReadInto, buffer: bytearray, path: str) -> int:
        total = TrustedFile.fill(readinto, buffer)
        if total == len(buffer):
            raise FileTooLargeError(f"'{path}' is larger than {len(buffer) - 1} bytes, the most it may be.")
        return total
