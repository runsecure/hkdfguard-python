"""The Windows key-file location rules. The policy itself runs on every platform, against security
descriptors built here; the tests that need Windows to parse SDDL, canonicalize a SID or name an
account run on Windows only. test_trusted_key_file.py runs the rules against real files."""

from __future__ import annotations

import sys

import pytest
from hkdfguard.securefile import KeyFileTrust
from hkdfguard.securefile._win32 import (
    ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE,
    FILE_ATTRIBUTE_REPARSE_POINT,
    INHERIT_ONLY_ACE,
    INVALID_FILE_ATTRIBUTES,
    Ace,
    SecurityDescriptorInfo,
)
from hkdfguard.securefile._windows import DriveType, WindowsKeyFileChecks

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only: Windows parses the SDDL and SIDs.")

KEY_FILE = "C:\\HkdfGuardKeys\\myapp\\v1.key"

SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
USERS = "S-1-5-32-545"
AUTHENTICATED_USERS = "S-1-5-11"
DEPLOYERS = "S-1-5-21-1111111111-2222222222-3333333333-1005"

# FileSystemRights values.
FULL_CONTROL = 0x1F01FF
MODIFY = 0x1301BF
WRITE = 0x116
READ_AND_EXECUTE_SYNCHRONIZE = 0x1200A9

ACCOUNTS = {SYSTEM: "NT AUTHORITY\\SYSTEM", ADMINISTRATORS: "BUILTIN\\Administrators", USERS: "BUILTIN\\Users"}

checks = WindowsKeyFileChecks


def canonical(sid: str) -> str | None:
    """A stand-in for ConvertStringSidToSidW: a well-formed SID string is its own canonical form."""
    return sid if sid.startswith("S-1-") else None


def trusted(*extra: str) -> tuple[str, ...]:
    return checks.trusted_principals(KeyFileTrust(windows_principals=extra), canonical, ACCOUNTS.get)


def allow(sid: str | None, rights: int, flags: int = 0) -> Ace:
    return Ace(ACCESS_ALLOWED_ACE_TYPE, flags, rights, sid)


def locked(owner: str | None, *extra: Ace) -> SecurityDescriptorInfo:
    aces = (allow(SYSTEM, FULL_CONTROL), allow(ADMINISTRATORS, FULL_CONTROL), allow(TRUSTED_INSTALLER, FULL_CONTROL),
            allow(USERS, READ_AND_EXECUTE_SYNCHRONIZE), *extra)
    return SecurityDescriptorInfo(owner, False, aces)


def verify(security: SecurityDescriptorInfo, item: str = KEY_FILE, guarded: int = checks.GUARDED_RIGHTS,
           trust: tuple[str, ...] | None = None) -> None:
    checks.verify_trusted_only(security, KEY_FILE, item, guarded, trusted() if trust is None else trust, account_name=ACCOUNTS.get)


# --- Trusted principals ---------------------------------------------------------------------------


def test_trusted_principals_always_include_system_administrators_and_trusted_installer() -> None:
    assert trusted() == (SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER)


def test_trusted_principals_add_the_listed_deployers() -> None:
    assert DEPLOYERS in trusted(DEPLOYERS)


@pytest.mark.parametrize("sid", ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-7"])  # Everyone, Authenticated Users, Users, Interactive, Anonymous
def test_trusted_principals_refuse_groups_everyone_is_in(sid: str) -> None:
    with pytest.raises(ValueError, match="every account"):
        trusted(sid)


@pytest.mark.parametrize("value", ["HkdfGuardDeployers", ""])
def test_trusted_principals_refuse_something_that_is_not_a_sid(value: str) -> None:
    with pytest.raises(ValueError, match="not a security identifier"):
        trusted(value)


# --- Path form, final path, reparse points ----------------------------------------------------------


def test_verify_path_form_a_local_fixed_drive_passes() -> None:
    checks.verify_path_form(KEY_FILE, DriveType.FIXED)


@pytest.mark.parametrize("path", ["\\\\server\\share\\v1.key", "\\\\?\\C:\\HkdfGuardKeys\\v1.key", "\\\\.\\PhysicalDrive0", "//server/share/v1.key"])
def test_verify_path_form_unc_and_device_paths_are_refused(path: str) -> None:
    with pytest.raises(PermissionError, match="UNC or device path"):
        checks.verify_path_form(path, DriveType.FIXED)


@pytest.mark.parametrize("drive_type", [t for t in DriveType if t != DriveType.FIXED])
def test_verify_path_form_other_drives_are_refused(drive_type: DriveType) -> None:
    with pytest.raises(PermissionError, match=f"{drive_type} drive"):
        checks.verify_path_form(KEY_FILE, drive_type)


@pytest.mark.parametrize(("value", "name"), [(0, "Unknown"), (1, "NoRootDirectory"), (2, "Removable"), (3, "Fixed"), (4, "Network"), (5, "CDRom"),
                                             (6, "Ram"), (7, "Unknown"), (-1, "Unknown")])
def test_drive_types_are_named_as_dotnet_names_them(value: int, name: str) -> None:
    assert str(DriveType.from_win32(value)) == name


@pytest.mark.parametrize("final_path", ["\\\\?\\C:\\HkdfGuardKeys\\myapp\\v1.key", "\\\\?\\c:\\hkdfguardkeys\\MYAPP\\v1.KEY"])
def test_verify_final_path_the_same_path_passes(final_path: str) -> None:
    checks.verify_final_path(KEY_FILE, final_path)


@pytest.mark.parametrize("final_path", [
    "\\\\?\\D:\\elsewhere\\v1.key",                   # a junction or symbolic link on the path
    "\\\\?\\C:\\real\\HkdfGuardKeys\\myapp\\v1.key",  # a substituted drive
    "\\\\?\\UNC\\server\\share\\myapp\\v1.key",       # a mapped network drive
    "\\\\?\\unc\\server\\share\\myapp\\v1.key",
    "C:\\HkdfGuardKeys\\myapp\\v1.key",               # not the form GetFinalPathNameByHandleW returns
])
def test_verify_final_path_elsewhere_or_remote_is_refused(final_path: str) -> None:
    with pytest.raises(PermissionError) as error:
        checks.verify_final_path(KEY_FILE, final_path)
    assert final_path in str(error.value)


def test_verify_final_path_a_short_name_requested_is_refused() -> None:
    with pytest.raises(PermissionError):
        checks.verify_final_path("C:\\PROGRA~1\\HkdfGuard\\v1.key", "\\\\?\\C:\\Program Files\\HkdfGuard\\v1.key")


def test_verify_final_path_compares_case_as_ntfs_does_never_expanding_one_character_into_several() -> None:
    checks.verify_final_path("C:\\Schlüssel\\v1.key", "\\\\?\\C:\\SCHLÜSSEL\\V1.KEY")
    with pytest.raises(PermissionError):
        checks.verify_final_path("C:\\Straße\\v1.key", "\\\\?\\C:\\STRASSE\\v1.key")


def test_verify_not_reparse_point_a_real_folder_passes() -> None:
    checks.verify_not_reparse_point(0x10, KEY_FILE, "C:\\HkdfGuardKeys")  # FILE_ATTRIBUTE_DIRECTORY


def test_verify_not_reparse_point_a_junction_or_link_is_refused() -> None:
    with pytest.raises(PermissionError, match="reparse point"):
        checks.verify_not_reparse_point(0x10 | FILE_ATTRIBUTE_REPARSE_POINT, KEY_FILE, "C:\\HkdfGuardKeys")


def test_verify_not_reparse_point_a_folder_that_can_not_be_examined_is_refused() -> None:
    with pytest.raises(PermissionError):
        checks.verify_not_reparse_point(INVALID_FILE_ATTRIBUTES, KEY_FILE, "C:\\HkdfGuardKeys")


# --- Owner and DACL -------------------------------------------------------------------------------


def test_verify_trusted_only_a_trusted_owner_and_read_only_for_everyone_else_passes() -> None:
    verify(locked(ADMINISTRATORS))


def test_verify_trusted_only_an_untrusted_owner_is_refused() -> None:
    with pytest.raises(PermissionError, match="is owned by BUILTIN\\\\Users \\(S-1-5-32-545\\)"):
        verify(locked(USERS))


def test_verify_trusted_only_no_owner_is_refused() -> None:
    with pytest.raises(PermissionError, match="an unknown principal"):
        verify(locked(None))


def test_verify_trusted_only_no_dacl_is_refused() -> None:
    # A NULL DACL grants everyone everything.
    with pytest.raises(PermissionError, match="no DACL"):
        verify(SecurityDescriptorInfo(ADMINISTRATORS, True, ()))


@pytest.mark.parametrize("rights", [checks.WRITE_DATA, checks.APPEND_DATA, checks.WRITE_EXTENDED_ATTRIBUTES, checks.DELETE_SUBDIRECTORIES_AND_FILES,
                                    checks.DELETE, checks.CHANGE_PERMISSIONS, checks.TAKE_OWNERSHIP, MODIFY, FULL_CONTROL,
                                    checks.GENERIC_ALL, checks.GENERIC_WRITE])
def test_verify_trusted_only_any_write_right_for_an_untrusted_principal_is_refused(rights: int) -> None:
    with pytest.raises(PermissionError, match="grants"):
        verify(locked(ADMINISTRATORS, allow(USERS, rights)))


def test_verify_trusted_only_a_trusted_deployer_may_own_and_modify() -> None:
    security = locked(DEPLOYERS, allow(DEPLOYERS, MODIFY))

    verify(security, trust=trusted(DEPLOYERS))
    with pytest.raises(PermissionError):
        verify(security)


def test_verify_trusted_only_ignores_deny_and_inherit_only_entries() -> None:
    # A folder's: only a folder carries entries meant for what's created inside it.
    security = SecurityDescriptorInfo(ADMINISTRATORS, False, (allow(ADMINISTRATORS, FULL_CONTROL), Ace(ACCESS_DENIED_ACE_TYPE, 0, FULL_CONTROL, USERS),
                                                              allow(AUTHENTICATED_USERS, MODIFY, INHERIT_ONLY_ACE | 0x3)))

    verify(security, "C:\\HkdfGuardKeys")


@pytest.mark.parametrize("ace_type", [0x05, 0x0B, 0x11])  # allowed object, allowed callback object, and a type this check doesn't know
def test_verify_trusted_only_an_entry_it_can_not_evaluate_is_refused(ace_type: int) -> None:
    security = locked(ADMINISTRATORS, Ace(ace_type, 0, checks.WRITE_DATA, None))

    with pytest.raises(PermissionError, match=f"type 0x{ace_type:02X}, which this check can't evaluate"):
        verify(security)


@pytest.mark.parametrize("ace_type", [0x06, 0x0A, 0x0C])  # the denied object and callback forms
def test_verify_trusted_only_ignores_every_kind_of_deny_entry(ace_type: int) -> None:
    verify(locked(ADMINISTRATORS, Ace(ace_type, 0, FULL_CONTROL, None)))


def test_verify_trusted_only_the_drive_root_allows_creating_folders_but_not_renaming_them() -> None:
    # A default C:\: Authenticated Users may create folders (AppendData) in the root itself.
    root = locked(TRUSTED_INSTALLER, allow(AUTHENTICATED_USERS, checks.APPEND_DATA))
    verify(root, "C:\\", checks.GUARDED_ROOT_RIGHTS)

    # The same entry on any folder below the root is refused: they could create files there.
    with pytest.raises(PermissionError):
        verify(root, "C:\\HkdfGuardKeys")

    renamable = locked(TRUSTED_INSTALLER, allow(AUTHENTICATED_USERS, checks.APPEND_DATA), allow(AUTHENTICATED_USERS, checks.DELETE_SUBDIRECTORIES_AND_FILES))
    with pytest.raises(PermissionError):
        verify(renamable, "C:\\", checks.GUARDED_ROOT_RIGHTS)


def test_verify_trusted_only_describes_an_unmappable_sid_by_its_value_and_names_the_rights() -> None:
    with pytest.raises(PermissionError) as error:
        verify(locked(ADMINISTRATORS, allow(DEPLOYERS, WRITE)))

    message = str(error.value)
    assert f"to {DEPLOYERS}." in message
    assert "grants 0x00000116 (WriteData, AppendData, WriteExtendedAttributes, WriteAttributes)" in message


def test_describe_rights_names_generic_and_unnamed_bits() -> None:
    assert checks.describe_rights(0) == "0x00000000"
    assert checks.describe_rights(0x10000200) == "0x10000200 (0x00000200, GenericAll)"


# --- Against Windows itself -----------------------------------------------------------------------


@windows_only
def test_on_windows_sids_are_canonicalized_and_aliases_accepted() -> None:
    from hkdfguard.securefile import _win32

    assert checks.trusted_principals(KeyFileTrust(windows_principals=["BA", "s-1-5-21-1111111111-2222222222-3333333333-1005"]),
                                     _win32.canonical_sid, _win32.account_name)[3:] == (ADMINISTRATORS, DEPLOYERS)
    with pytest.raises(ValueError, match="not a security identifier"):
        checks.trusted_principals(KeyFileTrust(windows_principals=["HkdfGuardDeployers"]), _win32.canonical_sid, _win32.account_name)
    with pytest.raises(ValueError, match="Everyone"):
        checks.trusted_principals(KeyFileTrust(windows_principals=["WD"]), _win32.canonical_sid, _win32.account_name)


@windows_only
def test_on_windows_sddl_descriptors_are_parsed_as_the_policy_expects() -> None:
    from hkdfguard.securefile import _win32

    def sddl(text: str) -> None:
        checks.verify_trusted_only(_win32.security_descriptor_from_sddl(text), KEY_FILE, KEY_FILE, checks.GUARDED_RIGHTS, trusted(),
                                   account_name=_win32.account_name)

    sddl("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;BU)")
    sddl("O:BAD:(A;;FA;;;BA)(D;;FA;;;BU)(A;OICIIO;0x1301BF;;;AU)")
    for refused, why in [
        ("O:BUD:(A;;FA;;;SY)", "is owned by"),
        ("D:(A;;FA;;;SY)", "an unknown principal"),
        ("O:BAD:NO_ACCESS_CONTROL", "no DACL"),
        ("O:BAD:(A;;FA;;;SY)(A;;GA;;;BU)", "grants"),                         # unmapped generic rights
        ("O:BAD:(A;;FA;;;SY)(A;;GW;;;BU)", "grants"),
        ("O:BAD:(A;;FA;;;SY)(OA;;0x2;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", "can't evaluate"),  # an allow-object ACE
    ]:
        with pytest.raises(PermissionError, match=why):
            sddl(refused)


@windows_only
def test_on_windows_an_unmappable_sid_is_described_by_its_value() -> None:
    from hkdfguard.securefile import _win32

    security = _win32.security_descriptor_from_sddl(f"O:BAD:(A;;FA;;;SY)(A;;0x116;;;{DEPLOYERS})")
    with pytest.raises(PermissionError, match=f"to {DEPLOYERS}\\."):
        checks.verify_trusted_only(security, KEY_FILE, KEY_FILE, checks.GUARDED_RIGHTS, trusted(), account_name=_win32.account_name)
    assert _win32.account_name(ADMINISTRATORS) is not None


@windows_only
def test_on_windows_invalid_sddl_is_refused() -> None:
    from hkdfguard.securefile import _win32

    with pytest.raises(ValueError, match="Invalid SDDL"):
        _win32.security_descriptor_from_sddl("not SDDL")
