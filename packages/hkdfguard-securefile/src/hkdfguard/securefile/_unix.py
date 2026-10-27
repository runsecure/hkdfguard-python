"""The Linux and macOS key-file location rules, and the two system calls they need."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Final

from hkdfguard.securefile._trust import KeyFileTrust


class UnixFileType(Enum):
    OTHER = "other"
    REGULAR_FILE = "regular file"
    DIRECTORY = "directory"
    SYMBOLIC_LINK = "symbolic link"


@dataclass(frozen=True)
class UnixFileStatus:
    """What lstat reports about one path: who owns it, its permissions, and its type."""

    GROUP_WRITE: ClassVar[int] = stat.S_IWGRP
    """S_IWGRP: writable by the file's group."""

    OTHER_WRITE: ClassVar[int] = stat.S_IWOTH
    """S_IWOTH: writable by every other user."""

    owner_id: int
    group_id: int
    mode: int
    """The permission bits of ``st_mode`` (the low twelve: set-id, sticky, and read, write and
    execute for owner, group and others)."""
    type: UnixFileType
    """What kind of file it is - a symbolic link is reported as such, never followed."""


class UnixKeyFileChecks:
    """Decides whether a key file's path on Linux or macOS can be trusted: resolves it the way the
    kernel would, from ``/``, checking everything it passes through. Every directory and the file
    itself must be owned by root or a :attr:`KeyFileTrust.unix_user_ids` user, must not be writable by
    others, and may be writable by its group only if that is a :attr:`KeyFileTrust.unix_group_ids`
    group. A symbolic link is followed only if a trusted user owns it, and its target is then checked
    in turn - so macOS's root-owned /etc to private/etc works, and a link anyone else made doesn't.
    Nothing under /tmp, /var/tmp or another world-writable directory passes, sticky or not.

    The path is checked before it is opened, not through the opened descriptor. That is enough:
    nobody untrusted can write to any directory on the resolved path, or to the file, so nobody
    untrusted can change what it resolves to between the check and the open.
    """

    MAX_SYMBOLIC_LINKS: Final = 40
    """The kernel's own limit on symbolic links followed in one lookup."""

    @staticmethod
    def resolve_trusted(path: str, trust: KeyFileTrust, get_status: Callable[[str], UnixFileStatus | None],  # noqa: PLR0912 - one walk, as in .NET
                        read_link: Callable[[str], str | None]) -> str:
        """Resolves ``path``, checking each component, and returns the resolved path, which contains
        no symbolic links.

        :param path: an absolute path
        :param trust: who besides root is trusted
        :param get_status: lstat-style status of a path, or ``None`` if nothing is there
        :param read_link: a symbolic link's stored target, or ``None`` if it can't be read as one
        :raises FileNotFoundError: nothing is at the path, or a directory on it is missing
        :raises PermissionError: a component is not trusted, or the path isn't a regular file
        :raises OSError: a component could not be examined
        :raises ValueError: the path is not absolute
        """
        if not path.startswith("/"):
            raise ValueError(f"'{path}' is not an absolute path.")

        root = get_status("/")
        if root is None:
            raise PermissionError("'/' could not be examined.")
        UnixKeyFileChecks._require_trusted("/", root, trust, path)

        pending: list[str] = []
        UnixKeyFileChecks._push_components(pending, path)
        resolved = "/"
        resolved_type = UnixFileType.DIRECTORY
        links_followed = 0

        while pending:
            name = pending.pop()
            if name in ("", "."):
                continue

            if resolved_type != UnixFileType.DIRECTORY:
                raise FileNotFoundError(f"Key file '{path}' runs through '{resolved}', which is not a directory.")

            if name == "..":
                # resolved never contains a symbolic link, so its parent is its lexical parent.
                resolved = UnixKeyFileChecks.parent_of(resolved)
                continue

            candidate = f"/{name}" if resolved == "/" else f"{resolved}/{name}"
            status = get_status(candidate)
            if status is None:
                raise FileNotFoundError(f"Key file '{path}' was not found ('{candidate}' does not exist).")

            if status.type == UnixFileType.SYMBOLIC_LINK:
                if not UnixKeyFileChecks._is_trusted_user(status.owner_id, trust):
                    raise UnixKeyFileChecks._untrusted(path, f"'{candidate}' is a symbolic link owned by uid {status.owner_id}, "
                                                             "and only links owned by root or a trusted user are followed")
                links_followed += 1
                if links_followed > UnixKeyFileChecks.MAX_SYMBOLIC_LINKS:
                    raise UnixKeyFileChecks._untrusted(path, f"it follows more than {UnixKeyFileChecks.MAX_SYMBOLIC_LINKS} symbolic links")

                target = read_link(candidate)
                if target is None:
                    raise UnixKeyFileChecks._untrusted(path, f"'{candidate}' could not be read as a symbolic link")
                if target.startswith("/"):
                    resolved = "/"
                UnixKeyFileChecks._push_components(pending, target)
                continue

            UnixKeyFileChecks._require_trusted(candidate, status, trust, path)
            resolved = candidate
            resolved_type = status.type

        if resolved_type != UnixFileType.REGULAR_FILE:
            raise UnixKeyFileChecks._untrusted(path, f"it resolves to '{resolved}', which is not a regular file")

        return resolved

    @staticmethod
    def _require_trusted(candidate: str, status: UnixFileStatus, trust: KeyFileTrust, path: str) -> None:
        if not UnixKeyFileChecks._is_trusted_user(status.owner_id, trust):
            raise UnixKeyFileChecks._untrusted(path, f"'{candidate}' is owned by uid {status.owner_id}, not root or a trusted user")

        if status.mode & UnixFileStatus.OTHER_WRITE:
            raise UnixKeyFileChecks._untrusted(path, f"'{candidate}' is writable by every user")

        if status.mode & UnixFileStatus.GROUP_WRITE and status.group_id not in trust.unix_group_ids:
            raise UnixKeyFileChecks._untrusted(path, f"'{candidate}' is writable by group {status.group_id}, which is not a trusted group")

    @staticmethod
    def _is_trusted_user(uid: int, trust: KeyFileTrust) -> bool:
        return uid == 0 or uid in trust.unix_user_ids

    @staticmethod
    def _untrusted(path: str, why: str) -> PermissionError:
        return PermissionError(f"Key file '{path}' is not trusted: {why}. Keep key files where only root (or a trusted deployer, see "
                               "KeyFileTrust) can write, all the way up from /.")

    @staticmethod
    def _push_components(pending: list[str], path: str) -> None:
        # Empty components (from "//" or a trailing "/") are kept, as .NET's Split keeps them, and skipped like ".".
        pending.extend(reversed(path.split("/")))

    @staticmethod
    def parent_of(path: str) -> str:
        """The lexical parent of an absolute path with no symbolic links; "/" is its own parent."""
        slash = path.rfind("/")
        return "/" if slash <= 0 else path[:slash]


# --- The system calls ----------------------------------------------------------------------------
#
# Python has both: os.lstat (os.stat with follow_symlinks=False) describes the path itself, never
# what a symbolic link points to, reading struct stat through the C library with the layout this
# interpreter was built for - so, unlike .NET and Java, there is no statx call or struct offset to get
# right per architecture - and os.readlink returns a link's stored target.


def status_or_none(path: str) -> UnixFileStatus | None:
    """lstat: describes the path itself, never what a symbolic link points to.

    :returns: the status, or ``None`` when nothing is there (ENOENT or ENOTDIR)
    :raises PermissionError: this account may not look (EACCES)
    :raises OSError: lstat failed for any other reason
    """
    try:
        info = os.lstat(path)
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ENOTDIR):
            return None
        if error.errno == errno.EACCES:
            raise PermissionError(f"This account may not look up '{path}' (EACCES).") from error
        raise OSError(error.errno, f"Could not look up '{path}' (errno {error.errno}).") from error

    mode = info.st_mode
    kind = (UnixFileType.REGULAR_FILE if stat.S_ISREG(mode) else UnixFileType.DIRECTORY if stat.S_ISDIR(mode)
            else UnixFileType.SYMBOLIC_LINK if stat.S_ISLNK(mode) else UnixFileType.OTHER)
    return UnixFileStatus(info.st_uid, info.st_gid, stat.S_IMODE(mode), kind)


def read_link(path: str) -> str | None:
    """readlink: a symbolic link's target, exactly as stored (possibly relative).

    :returns: the target, or ``None`` if the path isn't a symbolic link (or isn't there)
    :raises PermissionError: this account may not read it (EACCES)
    :raises OSError: readlink failed for any other reason
    """
    try:
        return os.readlink(path)
    except OSError as error:
        if error.errno in (errno.EINVAL, errno.ENOENT, errno.ENOTDIR):
            return None
        if error.errno == errno.EACCES:
            raise PermissionError(f"This account may not read the symbolic link '{path}' (EACCES).") from error
        raise OSError(error.errno, f"readlink('{path}') failed with errno {error.errno}.") from error
