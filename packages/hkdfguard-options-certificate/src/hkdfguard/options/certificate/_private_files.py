"""Files only this account can read, for the moment Python's ``ssl`` module needs a path: a new
directory under the temporary folder - mode 0700 on Unix, an owner-only protected DACL on Windows -
holding files written 0600, all deleted when the block ends, however it ends. Only ciphertext and
what isn't secret is ever written into one: a key is encrypted before it is written."""

from __future__ import annotations

import contextlib
import os
import secrets
import sys
import tempfile
from collections.abc import Buffer, Iterator

_created: list[str] = []  # the directories made and not yet removed, for the tests to check none is left behind


class PrivateDirectory:
    """A directory made by :func:`private_directory`; :meth:`write` adds a file to it."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._files: list[str] = []

    def write(self, name: str, data: Buffer) -> str:
        """Writes a new file ``name``, owner read/write only, and returns its path."""
        path = os.path.join(self.path, name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        self._files.append(path)
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
        return path

    def remove(self) -> None:
        for path in self._files:
            with contextlib.suppress(FileNotFoundError):
                os.remove(path)
        self._files.clear()
        try:
            os.rmdir(self.path)
        except FileNotFoundError:
            pass
        except OSError:
            return  # something else was put in it: left for leftover_directories() to report, not raised over the block's own error
        with contextlib.suppress(ValueError):
            _created.remove(self.path)


@contextlib.contextmanager
def private_directory() -> Iterator[PrivateDirectory]:
    """A new directory only this account can open, removed with everything in it at the end."""
    parent = tempfile.gettempdir()
    if sys.platform == "win32":
        from hkdfguard.options.certificate import _win32  # noqa: PLC0415

        while True:
            path = os.path.join(parent, "hkdfguard-" + secrets.token_hex(12))
            try:
                _win32.create_private_directory(path)
                break
            except FileExistsError:
                continue
    else:
        path = tempfile.mkdtemp(prefix="hkdfguard-", dir=parent)  # mode 0700
    _created.append(path)
    directory = PrivateDirectory(path)
    try:
        yield directory
    finally:
        directory.remove()


def leftover_directories() -> list[str]:
    """The private directories still in place: none, once every load and TLS context has finished."""
    return [path for path in _created if os.path.exists(path)]
