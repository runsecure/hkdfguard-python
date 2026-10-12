"""Reads a wrapped DEK from a key file, after checking that only a trusted account can have written it."""

from __future__ import annotations

import logging
import os
import posixpath
import stat
from collections.abc import Callable, Collection
from dataclasses import dataclass

from hkdfguard.abstractions import WrappedKeyLimits


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
    under; this keeps that to the account that runs the process, and root.
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


def read_key_file(path: str, *, verify_permissions: bool, logger: logging.Logger) -> bytearray:
    """Reads a wrapped DEK, refusing an empty file or one over WrappedKeyLimits.MAX_BYTES - never
    reading more than one byte past the limit, so a wrong path can't make startup allocate without bound.

    With ``verify_permissions`` on a POSIX system the file is first checked against
    :class:`KeyFilePermissions`: the file's status is read from the descriptor it is then read through,
    so it cannot be swapped between the check and the read. Windows has no check here yet; a warning is
    logged instead of pretending there is one.

    :raises PermissionError: the file or a directory above it fails the permission rule
    :raises OSError: the file can't be read, is empty, or is larger than the limit
    """
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
        raise OSError(f"Key file '{path}' is empty.")
    if total > WrappedKeyLimits.MAX_BYTES:
        raise OSError(f"Key file '{path}' is larger than {WrappedKeyLimits.MAX_BYTES} bytes (WrappedKeyLimits.MAX_BYTES); a wrapped key never is.")
    return buffer[:total]
