"""Who, besides the operating system's administrators, may have written a key file."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import ClassVar, Final

_MAX_ID: Final = 0xFFFF_FFFF
"""The largest uid or gid: both are unsigned 32-bit integers."""


@dataclass(frozen=True, slots=True, init=False)
class KeyFileTrust:
    """Who, besides the operating system's administrators, :class:`TrustedKeyFile` trusts to have
    written a key file it reads. A key file and every folder above it must be owned by a trusted
    principal, and no one else may write, replace, rename or re-permission any of them: whoever can
    replace a key file - and can also wrap under the KEK, as anyone allowed to encrypt with a network
    KMS key can - chooses the DEK new data is encrypted under.

    Always trusted: SYSTEM, Administrators and TrustedInstaller on Windows; root on Linux and macOS.
    :attr:`ADMINISTRATORS_ONLY` trusts no one else, which is the default. Add the account or group
    your deployment writes key files as - never the account the application runs as, unless it is a
    developer machine: an application that can rewrite its own key files can be made to roll back to
    an older one.

    Immutable, and every list is copied, so a list changed afterwards doesn't change what is trusted::

        trust = KeyFileTrust(windows_principals=["S-1-5-21-1111111111-2222222222-3333333333-1005"],
                             unix_user_ids=[1001], unix_group_ids=[2001])
    """

    ADMINISTRATORS_ONLY: ClassVar[KeyFileTrust]
    """Trusts only the operating system's administrators. The default."""

    windows_principals: tuple[str, ...]
    """Windows security identifiers (SIDs, such as a deployers group's ``"S-1-5-21-...-1005"``) that may
    also own, and hold write rights on, a key file and the folders above it. Checked when a key file is
    read: Everyone, Authenticated Users, Users, Interactive and Anonymous are refused then."""

    unix_user_ids: tuple[int, ...]
    """Linux and macOS user ids that may also own a key file, the directories above it, and the
    symbolic links on its path."""

    unix_group_ids: tuple[int, ...]
    """Linux and macOS group ids whose members may write a key file or a directory above it: a
    group-writable file or directory is refused unless its group is listed. Writable by others is
    refused whatever is listed."""

    def __init__(self, *, windows_principals: Iterable[str] = (), unix_user_ids: Iterable[int] = (), unix_group_ids: Iterable[int] = ()) -> None:
        """:raises TypeError: a list is ``None``, a SID is not a ``str``, or an id is not an ``int``
        :raises ValueError: a uid or gid is outside 0 to 4294967295
        """
        object.__setattr__(self, "windows_principals", _require_sids(windows_principals))
        object.__setattr__(self, "unix_user_ids", _require_ids(unix_user_ids, "unix_user_ids"))
        object.__setattr__(self, "unix_group_ids", _require_ids(unix_group_ids, "unix_group_ids"))



def _require_sids(sids: Iterable[str]) -> tuple[str, ...]:
    if sids is None or isinstance(sids, str):
        raise TypeError("windows_principals must be a list of SID strings.")
    copy = tuple(sids)
    for sid in copy:
        if not isinstance(sid, str):
            raise TypeError(f"windows_principals holds {sid!r}, which is not a SID string.")
    return copy


def _require_ids(ids: Iterable[int], name: str) -> tuple[int, ...]:
    if ids is None:
        raise TypeError(f"{name} must be a list of ids.")
    copy = tuple(ids)
    for value in copy:
        # bool is an int, but True is no one's id.
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} holds {value!r}, which is not an integer id.")
        if not 0 <= value <= _MAX_ID:
            raise ValueError(f"{name} holds {value}, which is not a valid id (0 to {_MAX_ID}).")
    return copy


KeyFileTrust.ADMINISTRATORS_ONLY = KeyFileTrust()
