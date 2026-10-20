"""What the macOS and Linux loaders both ask of a path: lstat's owner, permissions and type."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from enum import Enum


class UnixFileType(Enum):
    OTHER = "special file"
    REGULAR_FILE = "regular file"
    DIRECTORY = "directory"
    SYMBOLIC_LINK = "symbolic link"


@dataclass(frozen=True)
class UnixFileStatus:
    """What lstat reports about one path: its owner, group, permission bits, and type."""

    owner_id: int
    group_id: int
    mode: int
    type: UnixFileType

    @staticmethod
    def of(path: str) -> UnixFileStatus:
        """lstat: describes the path itself, never what a symbolic link points to.

        :raises OSError: lstat failed
        """
        info = os.lstat(path)
        kind = (UnixFileType.REGULAR_FILE if stat.S_ISREG(info.st_mode) else UnixFileType.DIRECTORY if stat.S_ISDIR(info.st_mode)
                else UnixFileType.SYMBOLIC_LINK if stat.S_ISLNK(info.st_mode) else UnixFileType.OTHER)
        return UnixFileStatus(info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), kind)


def probe(path: str) -> int:
    """lstat's errno for ``path``, or 0 if something is there - so "can't look" is never mistaken
    for "not there"."""
    try:
        os.lstat(path)
        return 0
    except OSError as error:
        return error.errno or errno.EIO
