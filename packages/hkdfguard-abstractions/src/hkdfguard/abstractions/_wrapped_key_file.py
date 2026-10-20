"""Reads a wrapped DEK from a key file with ordinary file I/O, after checking that only a trusted
account can have written it - the default :meth:`KeyWrapper.read_key_file`."""

from __future__ import annotations

import logging
import os
import posixpath
import stat
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Final

from hkdfguard.abstractions._errors import InvalidKeyFileError
from hkdfguard.abstractions._rules import WrappedKeyLimits

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.abstractions")


@dataclass(frozen=True)
class PathStatus:
    """What stat reports about one path that the permission rules look at: its owner and its mode."""

    owner_id: int
    mode: int

    @staticmethod
    def of(info: os.stat_result) -> PathStatus:
        return PathStatus(info.st_uid, info.st_mode)


class KeyFilePermissions:
    """The rule a key file is held to on a POSIX system, applied to the file's real path (symbolic
    links resolved, so a mounted-secret link is fine but what it points to is what is checked):

    1. The file is a regular file, owned by root or the current user, and writable by no one else.
    2. Every directory above it, up to ``/``, is owned by root or the current user and writable by no
       one else - except a sticky directory such as ``/tmp``, where only an entry's owner (or the
       directory's) can replace it, and the file's owner is already trusted.

    A wrapped DEK is not secret, but whoever can replace it chooses which key the process encrypts
    under; this keeps that to the account that runs the process, and root. Applied by
    :meth:`WrappedKeyFile.read`; the native key wrapper reads through the native library's own checks.
    """

    @staticmethod
    def verify_file(path: str, status: PathStatus, trusted_owners: Collection[int]) -> None:
        if not stat.S_ISREG(status.mode):
            raise PermissionError(f"Key file '{path}' is not a regular file.")
        KeyFilePermissions._verify_owner_and_writers(path, status, trusted_owners, allow_sticky=False)

    @staticmethod
    def verify_directory(path: str, status: PathStatus, trusted_owners: Collection[int]) -> None:
        if not stat.S_ISDIR(status.mode):
            raise PermissionError(f"'{path}', above a key file, is not a directory.")
        KeyFilePermissions._verify_owner_and_writers(path, status, trusted_owners, allow_sticky=True)

    @staticmethod
    def verify_directories(real_path: str, get_status: Callable[[str], PathStatus], trusted_owners: Collection[int]) -> None:
        """Every directory from ``real_path``'s parent up to ``/``. ``get_status`` must not follow links."""
        directory = posixpath.dirname(real_path)
        while True:
            KeyFilePermissions.verify_directory(directory, get_status(directory), trusted_owners)
            parent = posixpath.dirname(directory)
            if parent == directory:
                return
            directory = parent

    @staticmethod
    def _verify_owner_and_writers(path: str, status: PathStatus, trusted_owners: Collection[int], *, allow_sticky: bool) -> None:
        if status.owner_id not in trusted_owners:
            raise PermissionError(f"'{path}' is owned by uid {status.owner_id}; a key file is only read from a location owned by root "
                                  "or the current user. Fix the ownership, or call without_key_file_permission_checks().")
        if status.mode & (stat.S_IWGRP | stat.S_IWOTH) and not (allow_sticky and status.mode & stat.S_ISVTX):
            raise PermissionError(f"'{path}' is writable by its group or by every user (mode {stat.S_IMODE(status.mode):04o}); a key file is only "
                                  "read from a location only its owner can modify. Fix the permissions, or call "
                                  "without_key_file_permission_checks().")


class WrappedKeyFile:
    """Reads a wrapped-DEK key file with ordinary file I/O - the default
    :meth:`KeyWrapper.read_key_file`, for key wrappers with no native library of their own to read
    through (a remote KMS, say, or a test double). A wrapper backed by the native KMS library reads
    through that library instead, which also checks who could have written the file."""

    @staticmethod
    def read(path: str | os.PathLike[str], *, verify_permissions: bool = True, logger: logging.Logger | None = None) -> bytearray:
        """Reads a wrapped DEK, refusing an empty file or one over WrappedKeyLimits.MAX_BYTES - never
        reading more than one byte past the limit, whatever the file's size, so a wrong path (a log, a
        device) or a file still growing can't make startup allocate without bound.

        With ``verify_permissions`` on a POSIX system the file is first checked against
        :class:`KeyFilePermissions`: the file's status is read from the descriptor it is then read
        through, so it cannot be swapped between the check and the read. Windows has no check here; a
        warning is logged to ``logger`` (``None``: the ``hkdfguard.abstractions`` logger) instead of
        pretending there is one.

        :returns: the file's contents, still wrapped
        :raises TypeError: ``path`` is ``None``
        :raises ValueError: ``path`` is empty
        :raises PermissionError: the file or a directory above it fails the permission rule
        :raises InvalidKeyFileError: the file is empty or larger than the limit (an ``OSError``)
        :raises OSError: the file can't be opened or read
        """
        if path is None:
            raise TypeError("path must not be None.")
        text = os.fspath(path)
        if not text:
            raise ValueError("A key file path is required.")
        return _read(text, verify_permissions=verify_permissions, logger=logger or _DEFAULT_LOGGER)


def _read(path: str, *, verify_permissions: bool, logger: logging.Logger) -> bytearray:
    geteuid = getattr(os, "geteuid", None)
    if verify_permissions and geteuid is None:
        logger.warning("Key file '%s' was not permission-checked: ownership and write-permission checks are not implemented on this platform.",
                       path)

    if verify_permissions and geteuid is not None:
        real_path = os.path.realpath(path)
        trusted = {0, geteuid()}
        descriptor = os.open(real_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            KeyFilePermissions.verify_file(real_path, PathStatus.of(os.fstat(descriptor)), trusted)
            KeyFilePermissions.verify_directories(real_path, lambda p: PathStatus.of(os.lstat(p)), trusted)
            file = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
    else:
        file = open(path, "rb")  # noqa: SIM115 - closed by the with block below

    buffer = bytearray(WrappedKeyLimits.MAX_BYTES + 1)
    total = 0
    with file:
        view = memoryview(buffer)
        while total < len(buffer):
            read = file.readinto(view[total:])
            if not read:
                break
            total += read

    if total == 0:
        raise InvalidKeyFileError(f"Key file '{path}' is empty.")
    if total > WrappedKeyLimits.MAX_BYTES:
        raise InvalidKeyFileError(f"Key file '{path}' is larger than {WrappedKeyLimits.MAX_BYTES} bytes (WrappedKeyLimits.MAX_BYTES); a wrapped key never is.")
    return buffer[:total]
