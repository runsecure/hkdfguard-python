"""The Windows key-file location rules."""

from __future__ import annotations

import enum
from collections.abc import Callable
from typing import Final

from hkdfguard.securefile import _win32
from hkdfguard.securefile._trust import KeyFileTrust
from hkdfguard.securefile._win32 import SecurityDescriptorInfo


class DriveType(enum.IntEnum):
    """What GetDriveTypeW reports for a drive root, by its DRIVE_* value, named in messages as .NET's
    DriveType names it."""

    UNKNOWN = 0
    NO_ROOT_DIRECTORY = 1
    REMOVABLE = 2
    FIXED = 3
    NETWORK = 4
    CD_ROM = 5
    RAM = 6

    @classmethod
    def from_win32(cls, value: int) -> DriveType:
        """The type GetDriveTypeW's return value names; anything it doesn't define is :attr:`UNKNOWN`."""
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN

    def __str__(self) -> str:
        return _DRIVE_TYPE_NAMES[self]


_DRIVE_TYPE_NAMES: Final = {
    DriveType.UNKNOWN: "Unknown", DriveType.NO_ROOT_DIRECTORY: "NoRootDirectory", DriveType.REMOVABLE: "Removable",
    DriveType.FIXED: "Fixed", DriveType.NETWORK: "Network", DriveType.CD_ROM: "CDRom", DriveType.RAM: "Ram",
}

type AccountName = Callable[[str], str | None]
"""The account a SID string maps to, or ``None`` - for describing principals (:func:`_win32.account_name`)."""


class WindowsKeyFileChecks:
    """Decides whether a key file on Windows can be trusted, by the native library's
    (``hkdfguard_open_file``'s) rules:

    - The path names a file on a local fixed drive. UNC paths, device paths (``\\\\?\\``, ``\\\\.\\``)
      and network drives are refused before anything is opened, so no server named in a path is ever
      contacted.
    - The opened file's final path - with every symbolic link, junction, mount point and substituted
      drive resolved - is the path that was asked for, once the full path has expanded any 8.3 short
      name (it expands each one that exists on disk; a path still spelled with a short name doesn't
      match the final path and is refused). So nothing on the path redirects it, and the folders
      checked are the ones the file is in.
    - The file, and every folder above it, is owned by a trusted principal, and grants no one else any
      right to write, append, delete, rename, change its permissions or take ownership. For a folder
      that also covers creating files and folders in it. The drive root is held only to what could
      rename or delete what's beneath it, since a default ``C:\\`` lets Authenticated Users create
      folders.

    Trusted principals are SYSTEM, Administrators, TrustedInstaller and
    :attr:`KeyFileTrust.windows_principals`.
    """

    SYSTEM: Final = "S-1-5-18"
    ADMINISTRATORS: Final = "S-1-5-32-544"
    TRUSTED_INSTALLER: Final = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    """NT SERVICE\\TrustedInstaller has no well-known SID type; this is its fixed service SID."""

    ALWAYS_TRUSTED: Final = (SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER)

    NEVER_TRUSTED: Final = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-7"})
    """Groups every account, or every signed-in one, is in - Everyone, Authenticated Users, Users,
    Interactive, Anonymous: trusting one trusts everybody."""

    # File access rights (winnt.h).
    WRITE_DATA: Final = 0x0002  # FILE_WRITE_DATA, FILE_ADD_FILE on a folder
    APPEND_DATA: Final = 0x0004  # FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY on a folder
    WRITE_EXTENDED_ATTRIBUTES: Final = 0x0010  # FILE_WRITE_EA
    DELETE_SUBDIRECTORIES_AND_FILES: Final = 0x0040  # FILE_DELETE_CHILD
    DELETE: Final = 0x00010000
    CHANGE_PERMISSIONS: Final = 0x00040000  # WRITE_DAC
    TAKE_OWNERSHIP: Final = 0x00080000  # WRITE_OWNER
    GENERIC_ALL: Final = 0x10000000
    GENERIC_WRITE: Final = 0x40000000

    GUARDED_RIGHTS: Final = (WRITE_DATA | APPEND_DATA | WRITE_EXTENDED_ATTRIBUTES | DELETE_SUBDIRECTORIES_AND_FILES | DELETE | CHANGE_PERMISSIONS
                             | TAKE_OWNERSHIP | GENERIC_ALL | GENERIC_WRITE)
    """Any right that lets a principal change what this path reads: write or append data (on a folder,
    create files or folders), delete or rename (Delete on the item, DeleteSubdirectoriesAndFiles on its
    parent), write extended attributes, or take over the ACL. Generic bits are listed too, since an ACE
    can carry them unmapped."""

    GUARDED_ROOT_RIGHTS: Final = DELETE_SUBDIRECTORIES_AND_FILES | CHANGE_PERMISSIONS | TAKE_OWNERSHIP | GENERIC_ALL
    """On the drive root, only what lets a principal rename or delete an entry directly beneath it."""

    _RIGHT_NAMES: Final = (
        "ReadData", "WriteData", "AppendData", "ReadExtendedAttributes", "WriteExtendedAttributes", "ExecuteFile",
        "DeleteSubdirectoriesAndFiles", "ReadAttributes", "WriteAttributes", None, None, None, None, None, None, None,
        "Delete", "ReadPermissions", "ChangePermissions", "TakeOwnership", "Synchronize", None, None, None,
        "AccessSystemSecurity", "MaximumAllowed", None, None, "GenericAll", "GenericExecute", "GenericWrite", "GenericRead",
    )
    """How :meth:`describe_rights` names an access mask's bits: .NET's FileSystemRights names, then the generic bits."""

    @staticmethod
    def trusted_principals(trust: KeyFileTrust, canonical_sid: Callable[[str], str | None], account_name: AccountName) -> tuple[str, ...]:
        """The principals ``trust`` trusts, the always-trusted ones included, as canonical SID strings.

        :param canonical_sid: a SID string's canonical form, or ``None`` if it isn't one (:func:`_win32.canonical_sid`)
        :raises ValueError: a listed SID isn't valid, or is one that every account is in
        """
        trusted = list(WindowsKeyFileChecks.ALWAYS_TRUSTED)
        for value in trust.windows_principals:
            sid = canonical_sid(value) if value else None
            if sid is None:
                raise ValueError(f"KeyFileTrust.windows_principals holds '{value}', which is not a security identifier (S-1-...).")

            if sid in WindowsKeyFileChecks.NEVER_TRUSTED:
                raise ValueError(f"KeyFileTrust.windows_principals holds {WindowsKeyFileChecks._describe(sid, account_name)}, which every account "
                                 "(or every signed-in one) is in; trusting it would trust anyone to replace a key file.")
            trusted.append(sid)
        return tuple(trusted)

    @staticmethod
    def verify_path_form(full_path: str, drive_type: DriveType) -> None:
        """Refuses a path that isn't on a local fixed drive, before anything is opened.

        :param full_path: the absolute path (:func:`_win32.full_path`)
        :param drive_type: the type of the drive the path's root names
        :raises PermissionError: it isn't
        """
        if full_path.startswith(("\\\\", "//")):
            raise WindowsKeyFileChecks._untrusted(full_path, "it is a UNC or device path; key files are only read from a local drive")

        if drive_type != DriveType.FIXED:
            raise WindowsKeyFileChecks._untrusted(full_path, f"it is on a {drive_type} drive; key files are only read from a local fixed drive")

    @staticmethod
    def verify_final_path(full_path: str, final_path: str) -> None:
        """Requires the opened file's final path to be the one that was asked for.

        :param full_path: the absolute path that was opened
        :param final_path: GetFinalPathNameByHandleW's answer for the opened handle (``\\\\?\\C:\\...``)
        :raises PermissionError: they differ
        """
        local_prefix = "\\\\?\\"
        is_local = final_path.startswith(local_prefix) and not _equals_ignore_case(final_path[:8], "\\\\?\\UNC\\")
        opened = final_path[len(local_prefix):] if is_local else None

        if opened is None or not _equals_ignore_case(opened, full_path):
            raise WindowsKeyFileChecks._untrusted(full_path, f"it opens '{final_path}' - its path runs through a symbolic link, junction, mount point "
                                                             "or substituted drive. Configure it as the full, real path")

    @staticmethod
    def verify_not_reparse_point(attributes: int, full_path: str, folder: str) -> None:
        """Refuses a folder that is a symbolic link, junction or other reparse point.

        :param attributes: the folder's GetFileAttributesW value; :data:`_win32.INVALID_FILE_ATTRIBUTES`
            has every bit set, so a folder that can't be examined is refused too
        :raises PermissionError: it is one
        """
        if attributes & _win32.FILE_ATTRIBUTE_REPARSE_POINT:
            raise WindowsKeyFileChecks._untrusted(full_path, f"'{folder}' is a symbolic link, junction or other reparse point")

    @staticmethod
    def verify_trusted_only(security: SecurityDescriptorInfo, full_path: str, item: str, guarded_rights: int, trusted: tuple[str, ...], *,
                            account_name: AccountName) -> None:
        """Requires a trusted owner, and no Allow entry granting any of ``guarded_rights``
        (:attr:`GUARDED_RIGHTS` for the file and folders, :attr:`GUARDED_ROOT_RIGHTS` for the drive
        root) to anyone else. Inherit-only entries don't apply to the item itself, and Deny entries can
        only remove access, so both are ignored. A missing DACL grants everyone everything, and an
        entry whose trustee can't be read the plain way (an object ACE) can't be evaluated: both are
        refused.

        :raises PermissionError: the owner is untrusted, or an untrusted principal holds a guarded right
        """
        owner = security.owner_sid
        if owner is None or owner not in trusted:
            raise WindowsKeyFileChecks._untrusted(full_path, f"'{item}' is owned by {WindowsKeyFileChecks._describe(owner, account_name)}, not SYSTEM, "
                                                             "Administrators, TrustedInstaller or a trusted deployer")

        if security.grants_everyone_full:
            raise WindowsKeyFileChecks._untrusted(full_path, f"'{item}' has no DACL, which grants every user full control")

        for ace in security.aces:
            if ace.flags & _win32.INHERIT_ONLY_ACE:
                continue

            if ace.type in (_win32.ACCESS_DENIED_ACE_TYPE, _win32.ACCESS_DENIED_OBJECT_ACE_TYPE, _win32.ACCESS_DENIED_CALLBACK_ACE_TYPE,
                            _win32.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE):
                continue  # can only remove access
            if ace.type in (_win32.ACCESS_ALLOWED_ACE_TYPE, _win32.ACCESS_ALLOWED_CALLBACK_ACE_TYPE):
                if ace.mask & guarded_rights and ace.sid not in trusted:
                    raise WindowsKeyFileChecks._untrusted(full_path, f"'{item}' grants {WindowsKeyFileChecks.describe_rights(ace.mask)} to "
                                                                     f"{WindowsKeyFileChecks._describe(ace.sid, account_name)}")
                continue
            raise WindowsKeyFileChecks._untrusted(full_path, f"'{item}' has an access control entry of type 0x{ace.type:02X}, which this check "
                                                             "can't evaluate")

    @staticmethod
    def describe_rights(mask: int) -> str:
        """An access mask as hex, then the names of its bits, such as ``"0x00120116 (WriteData, AppendData, ...)"``."""
        mask &= 0xFFFFFFFF
        names = [WindowsKeyFileChecks._RIGHT_NAMES[bit] or f"0x{1 << bit:08X}" for bit in range(32) if mask & (1 << bit)]
        return f"0x{mask:08X}" + (f" ({', '.join(names)})" if names else "")

    @staticmethod
    def _untrusted(path: str, why: str) -> PermissionError:
        return PermissionError(f"Key file '{path}' is not trusted: {why}. Keep key files in a folder of their own that only administrators (or a "
                               "trusted deployer, see KeyFileTrust) can modify, with inherited permissions removed.")

    @staticmethod
    def _describe(sid: str | None, account_name: AccountName) -> str:
        if sid is None:
            return "an unknown principal"
        name = account_name(sid)
        return sid if name is None else f"{name} ({sid})"


def _equals_ignore_case(first: str, second: str) -> bool:
    """Ordinal comparison ignoring case, character by character with simple case mapping, as .NET's
    OrdinalIgnoreCase and NTFS compare names: unlike ``str.upper``, it never turns one character into
    several ("ß" is not "SS")."""
    return len(first) == len(second) and all(a == b or _simple_upper(a) == _simple_upper(b) for a, b in zip(first, second, strict=True))


def _simple_upper(character: str) -> str:
    upper = character.upper()
    return upper if len(upper) == 1 else character
