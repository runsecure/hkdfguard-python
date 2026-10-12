from __future__ import annotations

import ctypes
import errno
import functools
import os
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Buffer, Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from hkdfguard.abstractions import ArrayUtility, CryptographicError, WritableBuffer
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1, NativeLibraryNotFoundError, native_library, resolve_library
from hkdfguard.keywrapping.v1._interop._kms import OK, AbstractHkdfGuardKmsLibrary, CpuArchitecture, KmsResult
from hkdfguard.keywrapping.v1._interop._linux import LinuxHkdfGuardKmsLibrary
from hkdfguard.keywrapping.v1._interop._macos import MacOsHkdfGuardKmsLibrary, MacOsNativeLibraryLoader, UnixFileStatus, UnixFileType
from hkdfguard.keywrapping.v1._interop._windows import (
    VerifiedSigner,
    WindowsHkdfGuardKmsLibrary,
    WindowsNativeLibraryLoader,
    windows_subject_name,
)

IS_WINDOWS = sys.platform == "win32"
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows only.")


# --- Test doubles and environment -------------------------------------------------------------


class FakeKmsLibrary(AbstractHkdfGuardKmsLibrary):
    """A scriptable stand-in for a platform's native KMS library, recording every call."""

    def __init__(self) -> None:
        self.wrap_status = self.unwrap_status = self.generate_status = OK
        self.wrap_payload: bytes | None = None
        self.unwrap_payload: bytes | None = None
        self.generate_payload: bytes | None = None
        self.unwrap_garbage_on_failure: bytes | None = None
        self.describe: Callable[[int], str | None] | None = None
        self.throw_on_call: BaseException | None = None
        self.calls: list[str] = []
        self.last_service: str | None = None
        self.last_input: bytes | None = None

    def describe_status(self, status: int) -> str | None:
        return self.describe(status) if self.describe else None

    def _record(self, name: str, service: str, data: Buffer | None) -> None:
        self.calls.append(name)
        self.last_service = service
        self.last_input = bytes(data) if data is not None else None
        if self.throw_on_call is not None:
            raise self.throw_on_call

    @staticmethod
    def _emit(destination: WritableBuffer, payload: bytes) -> KmsResult:
        memoryview(destination).cast("B")[: len(payload)] = payload
        return KmsResult(OK, len(payload))

    def wrap_dek(self, service: str, dek: Buffer, destination: WritableBuffer) -> KmsResult:
        self._record("wrap", service, dek)
        return KmsResult(self.wrap_status, 0) if self.wrap_status != OK else self._emit(destination, self.wrap_payload or bytes(dek))

    def unwrap_dek(self, service: str, wrapped: Buffer, destination: WritableBuffer) -> KmsResult:
        self._record("unwrap", service, wrapped)
        if self.unwrap_status != OK:
            if self.unwrap_garbage_on_failure:
                memoryview(destination).cast("B")[: len(self.unwrap_garbage_on_failure)] = self.unwrap_garbage_on_failure
            return KmsResult(self.unwrap_status, 0)
        return self._emit(destination, self.unwrap_payload or bytes(wrapped))

    def generate_and_wrap_dek(self, service: str, destination: WritableBuffer) -> KmsResult:
        self._record("generate", service, None)
        return KmsResult(self.generate_status, 0) if self.generate_status != OK else self._emit(destination, self.generate_payload or bytes(64))


DEFAULT_WINDOWS_SERVICE = "com.hkdfguard.native.windows.test"
UNPROVISIONED_SERVICE = "hkdfguard.integrationtest.unprovisioned"


def windows_library_installed() -> bool:
    return IS_WINDOWS and os.path.isfile(WindowsNativeLibraryLoader.installed_path())


installed_windows_library = pytest.mark.skipif(not windows_library_installed(), reason="The Windows native KMS library is not installed.")


@functools.cache
def provisioned_service() -> tuple[str | None, str]:
    """The service native integration tests run against: HKDFGUARD_TEST_SERVICE if set; otherwise on
    Windows the provisioned test KEK, unless the installed library reports it absent or forbidden."""
    explicit = os.environ.get("HKDFGUARD_TEST_SERVICE")
    if explicit:
        return explicit, ""
    if not IS_WINDOWS:
        return None, "Set HKDFGUARD_TEST_SERVICE to a service provisioned with hkdfguard-v1-initialize to run native integration tests."
    if not windows_library_installed():
        return None, f"The native KMS library is not installed at {WindowsNativeLibraryLoader.installed_path()}."
    try:
        library = WindowsNativeLibraryLoader.load()
        kek_exists = library.hkdfguard_kek_exists
        kek_exists.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int32)]
        kek_exists.restype = ctypes.c_int
        exists = ctypes.c_int32()
        status = kek_exists(DEFAULT_WINDOWS_SERVICE.encode(), ctypes.byref(exists))
    except Exception:
        return DEFAULT_WINDOWS_SERVICE, ""
    if status == 0 and exists.value:
        return DEFAULT_WINDOWS_SERVICE, ""
    if status in (0, WindowsHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND):
        return None, (f"The test KEK '{DEFAULT_WINDOWS_SERVICE}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, "
                      "or set HKDFGUARD_TEST_SERVICE to a provisioned service.")
    if status == WindowsHkdfGuardKmsLibrary.ERR_ACCESS_DENIED:
        return None, (f"The test KEK '{DEFAULT_WINDOWS_SERVICE}' exists, but this account may not use it. Add it to the HkdfGuardUsers group "
                      "(then sign out and in), or run the tests elevated.")
    return DEFAULT_WINDOWS_SERVICE, ""


@pytest.fixture
def service() -> str:
    name, reason = provisioned_service()
    if name is None:
        pytest.skip(reason)
    return name


# --- NativeHkdfKeyWrapperV1 -------------------------------------------------------------------


def test_wrap_delegates_to_the_library() -> None:
    library = FakeKmsLibrary()
    library.wrap_payload = bytes([10, 20, 30, 40])
    result = bytearray(16)

    assert NativeHkdfKeyWrapperV1("service.a", library).wrap(bytes([1, 2, 3, 4, 5]), result) == 4

    assert (library.calls, library.last_service, library.last_input) == (["wrap"], "service.a", bytes([1, 2, 3, 4, 5]))
    assert result[:4] == bytes([10, 20, 30, 40])


@pytest.mark.parametrize("status", [-1, -2, -7])
def test_a_failing_wrap_raises_naming_the_status(status: int) -> None:
    library = FakeKmsLibrary()
    library.wrap_status = status

    with pytest.raises(CryptographicError) as error:
        NativeHkdfKeyWrapperV1("service.d", library).wrap(bytes(3), bytearray(8))

    assert str(error.value) == f"Native KMS wrap failed for service 'service.d' with status {status}."


def test_a_failure_the_library_can_describe_names_what_the_status_means() -> None:
    library = FakeKmsLibrary()
    library.unwrap_status = -13
    library.describe = lambda s: "this account is not authorized to use the KEK" if s == -13 else None

    with pytest.raises(CryptographicError) as error:
        NativeHkdfKeyWrapperV1("service.d", library).unwrap(b"\x01", bytearray(32))

    assert str(error.value) == ("Native KMS unwrap failed for service 'service.d' with status -13 "
                                "(this account is not authorized to use the KEK).")


def test_unwrap_delegates_and_a_failure_zeroes_the_result_buffer() -> None:
    library = FakeKmsLibrary()
    library.unwrap_payload = bytes([1, 2, 3, 4, 5])
    result = bytearray(16)
    assert NativeHkdfKeyWrapperV1("service.a", library).unwrap(bytes([10, 20]), result) == 5
    assert result[:5] == bytes([1, 2, 3, 4, 5])

    library.unwrap_status = -6
    library.unwrap_garbage_on_failure = b"\x09\x09\x09"
    result = bytearray(b"\xff" * 8)
    with pytest.raises(CryptographicError, match=r"unwrap failed for service 'service\.a' with status -6"):
        NativeHkdfKeyWrapperV1("service.a", library).unwrap(bytes(3), result)
    assert result == bytearray(8)


def test_generate_and_wrap_delegates_and_failures_raise() -> None:
    library = FakeKmsLibrary()
    library.generate_payload = bytes([11, 22, 33, 44, 55])
    result = bytearray(16)
    assert NativeHkdfKeyWrapperV1("service.e", library).generate_and_wrap(result) == 5
    assert result[:5] == bytes([11, 22, 33, 44, 55])

    library.generate_status = -3
    with pytest.raises(CryptographicError, match=r"generate-and-wrap failed for service 'service\.e' with status -3\."):
        NativeHkdfKeyWrapperV1("service.e", library).generate_and_wrap(bytearray(16))


def test_a_library_that_fails_to_load_raises_and_still_zeroes_an_unwrap_buffer() -> None:
    library = FakeKmsLibrary()
    library.throw_on_call = PermissionError("not signed by the HkdfGuard publisher")
    wrapper = NativeHkdfKeyWrapperV1("service.g", library)
    result = bytearray(b"\x01\x02\x03")

    with pytest.raises(PermissionError):
        wrapper.unwrap(b"\x01", result)
    assert result == bytearray(3)


@pytest.mark.parametrize("name", ["", ".service", "my..service", "my-service", "a" * 129])
def test_an_invalid_service_name_is_refused_before_any_native_call(name: str) -> None:
    library = FakeKmsLibrary()
    with pytest.raises(ValueError):
        NativeHkdfKeyWrapperV1(name, library)
    with pytest.raises(TypeError):
        NativeHkdfKeyWrapperV1(None, library)  # type: ignore[arg-type]
    assert library.calls == []


def test_the_default_binding_is_this_platforms_and_is_resolved_once() -> None:
    assert native_library() is native_library()
    assert isinstance(resolve_library("win32"), WindowsHkdfGuardKmsLibrary)
    assert isinstance(resolve_library("linux"), LinuxHkdfGuardKmsLibrary)
    assert isinstance(resolve_library("darwin"), MacOsHkdfGuardKmsLibrary)
    with pytest.raises(NotImplementedError, match="freebsd14"):
        resolve_library("freebsd14")


# --- Status codes -----------------------------------------------------------------------------


def test_status_constants_match_the_native_headers() -> None:
    assert [getattr(WindowsHkdfGuardKmsLibrary, n) for n in (
        "ERR_INVALID_ARG", "ERR_BUFFER_TOO_SMALL", "ERR_PROVIDER", "ERR_CRYPTO", "ERR_AUTH_FAILED", "ERR_MALFORMED", "ERR_INTERNAL",
        "ERR_SERVICE_NAME_INVALID", "ERR_INVALID_POLICY", "ERR_GROUP_INVALID", "ERR_KEK_MISMATCH", "ERR_KEK_NOT_FOUND",
        "ERR_ACCESS_DENIED", "ERR_KEK_ACL_INVALID")] == list(range(-1, -15, -1))
    assert [getattr(LinuxHkdfGuardKmsLibrary, n) for n in (
        "ERR_INVALID_ARGUMENT", "ERR_BUFFER_TOO_SMALL", "ERR_PROVIDER_UNAVAILABLE", "ERR_PROVIDER_ERROR", "ERR_CRYPTO_ERROR",
        "ERR_INTERNAL_ERROR", "ERR_INVALID_UTF8", "ERR_MISSING_SERVICE_NAME")] == list(range(-1, -9, -1))
    assert MacOsHkdfGuardKmsLibrary.ERR_KEYCHAIN_READ_FAILED == -18
    assert MacOsHkdfGuardKmsLibrary.ERR_FINGERPRINT_MISMATCH == -16


def test_windows_describes_every_defined_status_and_nothing_else() -> None:
    library = WindowsHkdfGuardKmsLibrary()
    assert all(library.describe_status(s) for s in range(-14, 0))
    assert library.describe_status(-15) is None and library.describe_status(1) is None
    assert "HkdfGuardUsers" in (library.describe_status(-13) or "")
    assert "provision" in (library.describe_status(-12) or "")


def test_macos_describes_every_returned_status_but_not_the_reserved_ones() -> None:
    library = MacOsHkdfGuardKmsLibrary()
    assert all(library.describe_status(s) for s in (-1, -2, *range(-18, -4)))
    assert library.describe_status(-3) is None and library.describe_status(-4) is None and library.describe_status(-19) is None
    assert LinuxHkdfGuardKmsLibrary().describe_status(-1) is None


# --- Windows loader: location ---------------------------------------------------------------


def sddl(text: str):  # type: ignore[no-untyped-def]
    from hkdfguard.keywrapping.v1._interop import _win32

    return _win32.security_descriptor_from_sddl(text)


USERS = "S-1-5-32-545"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"


@windows_only
def test_installed_path_is_under_program_files() -> None:
    expected = Path(os.environ["PROGRAMFILES"], "HkdfGuard", "v1", "HkdfGuardV1.dll")
    assert Path(WindowsNativeLibraryLoader.installed_path()) == expected


@windows_only
def test_load_from_a_missing_file_names_the_only_supported_path() -> None:
    missing = str(Path(tempfile.gettempdir(), f"hkdfguard-missing-{uuid.uuid4().hex}", "HkdfGuardV1.dll"))
    with pytest.raises(NativeLibraryNotFoundError, match=r"never loaded from anywhere else") as error:
        WindowsNativeLibraryLoader.load_from(missing, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER)
    assert missing in str(error.value)


@windows_only
def test_load_from_a_user_writable_folder_is_refused(tmp_path: Path) -> None:
    planted = tmp_path / WindowsNativeLibraryLoader.FILE_NAME
    planted.write_bytes(b"MZ")

    with pytest.raises(PermissionError):
        WindowsNativeLibraryLoader.load_from(str(planted), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER)


@windows_only
def test_a_trusted_owner_and_read_only_for_everyone_else_passes() -> None:
    WindowsNativeLibraryLoader.verify_trusted_only(sddl(f"O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{TRUSTED_INSTALLER})(A;;0x1200a9;;;BU)"), "test")


@windows_only
@pytest.mark.parametrize("right", ["0x2", "0x4", "0x10", "0x40", "0x10000", "WD", "WO", "0x1301bf", "GA", "GW"])
def test_any_write_right_for_an_untrusted_principal_is_refused(right: str) -> None:
    with pytest.raises(PermissionError, match=USERS):
        WindowsNativeLibraryLoader.verify_trusted_only(sddl(f"O:BAD:(A;;{right};;;BU)"), "test")


@windows_only
def test_an_untrusted_missing_or_orphaned_owner_is_refused() -> None:
    with pytest.raises(PermissionError):
        WindowsNativeLibraryLoader.verify_trusted_only(sddl("O:BUD:(A;;FA;;;SY)"), "test")
    with pytest.raises(PermissionError, match="an unknown principal"):
        WindowsNativeLibraryLoader.verify_trusted_only(sddl("D:(A;;FA;;;SY)"), "test")
    orphan = "S-1-5-21-1-2-3-4242"
    with pytest.raises(PermissionError, match=orphan):
        WindowsNativeLibraryLoader.verify_trusted_only(sddl(f"O:{orphan}D:(A;;FA;;;SY)"), "test")


@windows_only
def test_principals_are_named_by_account_and_sid() -> None:
    with pytest.raises(PermissionError, match=rf"\\.*\({USERS}\)"):
        WindowsNativeLibraryLoader.verify_trusted_only(sddl("O:SYD:(A;;FA;;;BU)"), "test")


@windows_only
def test_no_dacl_at_all_is_refused_and_an_allow_object_ace_fails_closed() -> None:
    with pytest.raises(PermissionError, match="no DACL"):
        WindowsNativeLibraryLoader.verify_trusted_only(sddl("O:SYD:NO_ACCESS_CONTROL"), "test")
    with pytest.raises(PermissionError, match="can't evaluate"):
        WindowsNativeLibraryLoader.verify_trusted_only(sddl("O:SYD:(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)"), "test")


@windows_only
def test_inherit_only_and_deny_entries_are_ignored() -> None:
    WindowsNativeLibraryLoader.verify_trusted_only(sddl("O:SYD:(D;;FW;;;BU)(A;;FA;;;SY)(A;OICIIO;FA;;;BU)(A;;FR;;;BU)"), "test")


@windows_only
def test_a_default_system_drive_acl_passes_the_root_rule() -> None:
    WindowsNativeLibraryLoader.verify_drive_root(
        sddl("O:SYD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x4;;;AU)"), "C:\\")


@windows_only
@pytest.mark.parametrize("right", ["0x40", "WD", "WO", "GA", "FA"])
def test_a_root_right_that_could_rename_a_folder_beneath_is_refused(right: str) -> None:
    with pytest.raises(PermissionError, match=USERS):
        WindowsNativeLibraryLoader.verify_drive_root(sddl(f"O:SYD:(A;OICI;FA;;;SY)(A;;{right};;;BU)"), "C:\\")


@windows_only
@pytest.mark.parametrize("right", ["0x1", "0x4", "GW"])
def test_root_rights_that_only_create_entries_are_allowed(right: str) -> None:
    WindowsNativeLibraryLoader.verify_drive_root(sddl(f"O:SYD:(A;OICI;FA;;;SY)(A;;{right};;;BU)"), "C:\\")
    with pytest.raises(PermissionError):
        WindowsNativeLibraryLoader.verify_drive_root(sddl("O:BUD:(A;OICI;FA;;;SY)"), "C:\\")


@windows_only
def test_a_junction_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction), str(target)], check=True, capture_output=True)

    with pytest.raises(PermissionError, match="symbolic link or junction"):
        WindowsNativeLibraryLoader.verify_not_reparse_point(str(junction))
    WindowsNativeLibraryLoader.verify_not_reparse_point(str(target))


# --- Windows loader: image kind and signer ----------------------------------------------------


@pytest.mark.parametrize(("arch", "machine"), [(CpuArchitecture.X64, 0x8664), (CpuArchitecture.ARM64, 0xAA64), (CpuArchitecture.X86, 0x014C)])
def test_a_dll_for_this_process_architecture_passes(arch: CpuArchitecture, machine: int) -> None:
    WindowsNativeLibraryLoader.verify_image_kind("test", 0x2002, machine, arch)


def test_an_executable_or_a_dll_for_another_architecture_is_refused() -> None:
    with pytest.raises(PermissionError, match="not a DLL"):
        WindowsNativeLibraryLoader.verify_image_kind("test", 0x0002, 0x8664, CpuArchitecture.X64)
    for arch, machine in [(CpuArchitecture.X64, 0xAA64), (CpuArchitecture.ARM64, 0x8664), (CpuArchitecture.X64, 0x014C),
                          (CpuArchitecture.OTHER, 0)]:
        with pytest.raises(PermissionError):
            WindowsNativeLibraryLoader.verify_image_kind("test", 0x2002, machine, arch)


def test_a_file_that_is_not_a_pe_image_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "x.dll"
    path.write_bytes(b"MZ\x90\x00")
    with pytest.raises(PermissionError, match="PE header"):
        WindowsNativeLibraryLoader.verify_image_kind(str(path))


ARTIFACT_SIGNING_EKU = "1.3.6.1.4.1.311.97.1.0"
GENUINE_EKUS = [ARTIFACT_SIGNING_EKU, WindowsNativeLibraryLoader.CODE_SIGNING_EKU, WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU]


def verify_signer(ekus: list[str], subject: str = WindowsNativeLibraryLoader.EXPECTED_PUBLISHER,
                  root: str = WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256) -> None:
    WindowsNativeLibraryLoader.verify_signer_identity("test", subject, ekus, root, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER)


def test_the_pinned_root_profile_and_publisher_pass_in_either_hex_case() -> None:
    verify_signer(GENUINE_EKUS)
    verify_signer(GENUINE_EKUS, root=WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256.lower())


@pytest.mark.parametrize(("ekus", "subject", "root", "message"), [
    (GENUINE_EKUS, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, "A" * 64, "A" * 64),
    ([WindowsNativeLibraryLoader.CODE_SIGNING_EKU, ARTIFACT_SIGNING_EKU], WindowsNativeLibraryLoader.EXPECTED_PUBLISHER,
     WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256, WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU),
    ([ARTIFACT_SIGNING_EKU, WindowsNativeLibraryLoader.CODE_SIGNING_EKU, "1.3.6.1.4.1.311.97.1.2.3.4"], WindowsNativeLibraryLoader.EXPECTED_PUBLISHER,
     WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256, WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU),
    ([ARTIFACT_SIGNING_EKU, WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU], WindowsNativeLibraryLoader.EXPECTED_PUBLISHER,
     WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256, WindowsNativeLibraryLoader.CODE_SIGNING_EKU),
    ([], WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256, "code signing"),
    (GENUINE_EKUS, "CN=Someone Else", WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256, "not the expected HkdfGuard publisher"),
])
def test_a_signer_failing_any_requirement_is_refused(ekus: list[str], subject: str, root: str, message: str) -> None:
    with pytest.raises(PermissionError) as error:
        verify_signer(ekus, subject, root)
    assert message in str(error.value)


def test_verify_signature_wraps_reader_failures_but_not_refusals_and_applies_the_policy() -> None:
    cause = RuntimeError("no chain")

    def raise_cause(path: str) -> VerifiedSigner:
        raise cause

    with pytest.raises(PermissionError) as error:
        WindowsNativeLibraryLoader.verify_signature("test", WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, raise_cause)
    assert error.value.__cause__ is cause

    refusal = PermissionError("untrusted")

    def refuse(path: str) -> VerifiedSigner:
        raise refusal

    with pytest.raises(PermissionError) as error:
        WindowsNativeLibraryLoader.verify_signature("test", WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, refuse)
    assert error.value is refusal

    with pytest.raises(PermissionError):
        WindowsNativeLibraryLoader.verify_signature("test", WindowsNativeLibraryLoader.EXPECTED_PUBLISHER,
                                                    lambda p: VerifiedSigner(WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, GENUINE_EKUS, "A" * 64))


def test_subjects_are_formatted_as_windows_formats_them() -> None:
    genuine = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "co"),
                         x509.NameAttribute(NameOID.LOCALITY_NAME, "Littleton"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Torin Blair"),
                         x509.NameAttribute(NameOID.COMMON_NAME, "Torin Blair")])
    assert windows_subject_name(genuine) == WindowsNativeLibraryLoader.EXPECTED_PUBLISHER

    special = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme, Inc."), x509.NameAttribute(NameOID.COMMON_NAME, 'Build "Bot"')])
    assert windows_subject_name(special) == 'CN="Build ""Bot""", O="Acme, Inc."'


@windows_only
def test_an_unsigned_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "x.dll"
    path.write_bytes(b"MZ\x90\x00")
    with pytest.raises(PermissionError):
        WindowsNativeLibraryLoader.verify_signature(str(path), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER)


# --- Against the installed Windows library ---------------------------------------------------


@installed_windows_library
def test_the_installed_library_passes_every_check() -> None:
    path = WindowsNativeLibraryLoader.installed_path()
    signer = WindowsNativeLibraryLoader.read_verified_signer(path)

    assert signer.leaf_subject == WindowsNativeLibraryLoader.EXPECTED_PUBLISHER
    assert signer.root_sha256 == WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256
    assert {WindowsNativeLibraryLoader.CODE_SIGNING_EKU, WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU} <= set(signer.leaf_eku_oids)
    WindowsNativeLibraryLoader.verify_location(path)
    WindowsNativeLibraryLoader.verify_image_kind(path)
    assert WindowsNativeLibraryLoader.load() is WindowsNativeLibraryLoader.load()


@installed_windows_library
def test_the_installed_provisioning_tool_passes_the_signer_checks_but_is_not_a_dll() -> None:
    tool = str(Path(WindowsNativeLibraryLoader.installed_path()).with_name("hkdfguard-v1-initialize.exe"))
    assert os.path.isfile(tool)

    WindowsNativeLibraryLoader.verify_signature(tool, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER)
    with pytest.raises(PermissionError, match="not a DLL"):
        WindowsNativeLibraryLoader.verify_image_kind(tool)


@installed_windows_library
def test_a_valid_signature_from_another_publisher_or_a_tampered_copy_is_refused(tmp_path: Path) -> None:
    path = WindowsNativeLibraryLoader.installed_path()
    with pytest.raises(PermissionError, match="not the expected HkdfGuard publisher"):
        WindowsNativeLibraryLoader.verify_signature(path, "CN=Someone Else")

    data = bytearray(Path(path).read_bytes())
    data[len(data) // 2] ^= 0xFF
    copy = tmp_path / "copy.dll"
    copy.write_bytes(data)
    with pytest.raises(PermissionError):
        WindowsNativeLibraryLoader.verify_signature(str(copy), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER)


@installed_windows_library
def test_the_windows_binding_calls_into_the_installed_library() -> None:
    # No KEK is provisioned for this name, so the library answers with an error - proving it ran.
    assert WindowsHkdfGuardKmsLibrary().wrap_dek(UNPROVISIONED_SERVICE, bytes(32), bytearray(512)).status < 0


# --- macOS loader policy, on simulated filesystems (runs everywhere) --------------------------

ROOT, USER, OTHER_USER, WHEEL, ADMIN, STAFF = 0, 501, 502, 0, 80, 20
HOME = "/Users/dev"


def d(owner: int, group: int, mode: int) -> UnixFileStatus:
    return UnixFileStatus(owner, group, mode, UnixFileType.DIRECTORY)


def f(owner: int, group: int, mode: int) -> UnixFileStatus:
    return UnixFileStatus(owner, group, mode, UnixFileType.REGULAR_FILE)


def system_install() -> dict[str, UnixFileStatus]:
    return {"/": d(ROOT, WHEEL, 0o755), "/Library": d(ROOT, WHEEL, 0o755), "/Library/Application Support": d(ROOT, ADMIN, 0o775),
            "/Library/Application Support/HkdfGuard": d(ROOT, WHEEL, 0o755), "/Library/Application Support/HkdfGuard/v1": d(ROOT, WHEEL, 0o755),
            MacOsNativeLibraryLoader.system_path(): f(ROOT, WHEEL, 0o644)}


def user_install() -> dict[str, UnixFileStatus]:
    return {"/": d(ROOT, WHEEL, 0o755), "/Users": d(ROOT, ADMIN, 0o755), HOME: d(USER, STAFF, 0o755),
            f"{HOME}/.hkdfguard": d(USER, STAFF, 0o700), f"{HOME}/.hkdfguard/v1": d(USER, STAFF, 0o700),
            MacOsNativeLibraryLoader.user_path(HOME): f(USER, STAFF, 0o644)}


def verify_system(fs: dict[str, UnixFileStatus]) -> None:
    MacOsNativeLibraryLoader.verify_location(MacOsNativeLibraryLoader.system_path(), fs.__getitem__, [ROOT])


def verify_user(fs: dict[str, UnixFileStatus]) -> None:
    MacOsNativeLibraryLoader.verify_location(MacOsNativeLibraryLoader.user_path(HOME), fs.__getitem__, [ROOT, USER])


@pytest.mark.parametrize("version", ["13.0", "15.4", "26.0", "14.7.1"])
def test_arm64_on_macos_13_or_later_is_supported(version: str) -> None:
    MacOsNativeLibraryLoader.require_supported_platform(CpuArchitecture.ARM64, version)


def test_x64_and_other_architectures_and_old_macos_are_refused() -> None:
    with pytest.raises(OSError, match="Rosetta"):
        MacOsNativeLibraryLoader.require_supported_platform(CpuArchitecture.X64, "15.0")
    for arch in (CpuArchitecture.X86, CpuArchitecture.ARM, CpuArchitecture.OTHER):
        with pytest.raises(OSError, match=arch.value):
            MacOsNativeLibraryLoader.require_supported_platform(arch, "15.0")
    with pytest.raises(OSError, match=r"macOS 13 or later; this is macOS 12\.7\.6"):
        MacOsNativeLibraryLoader.require_supported_platform(CpuArchitecture.ARM64, "12.7.6")


def test_the_two_locations_are_the_agreed_paths() -> None:
    assert MacOsNativeLibraryLoader.system_path() == "/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib"
    assert MacOsNativeLibraryLoader.user_path("/Users/dev") == MacOsNativeLibraryLoader.user_path("/Users/dev/") \
        == "/Users/dev/.hkdfguard/v1/libhkdfguard_v1.dylib"


def test_choose_path_prefers_the_system_install_and_falls_back_only_when_it_is_absent() -> None:
    assert MacOsNativeLibraryLoader.choose_path(lambda p: 0, HOME).is_system
    user = MacOsNativeLibraryLoader.user_path(HOME)
    for absent in (errno.ENOENT, errno.ENOTDIR):
        choice = MacOsNativeLibraryLoader.choose_path(lambda p, a=absent: 0 if p == user else a, HOME)  # type: ignore[misc]
        assert (choice.path, choice.is_system) == (user, False)


@pytest.mark.parametrize("error", [errno.EACCES, 62, errno.EIO])
def test_a_system_install_that_cannot_be_examined_is_refused_without_falling_back(error: int) -> None:
    probed: list[str] = []

    def probe(path: str) -> int:
        probed.append(path)
        return error

    with pytest.raises(PermissionError, match=f"errno {error}"):
        MacOsNativeLibraryLoader.choose_path(probe, HOME)
    assert probed == [MacOsNativeLibraryLoader.system_path()]


@pytest.mark.parametrize("home", [HOME, "", "relative/home"])
def test_with_neither_install_usable_both_locations_are_named(home: str) -> None:
    with pytest.raises(NativeLibraryNotFoundError) as error:
        MacOsNativeLibraryLoader.choose_path(lambda p: 0 if not p.startswith("/") else errno.ENOENT, home)
    assert MacOsNativeLibraryLoader.system_path() in str(error.value)
    assert ".hkdfguard/v1/libhkdfguard_v1.dylib" in str(error.value)


@pytest.mark.parametrize(("path", "parent"), [("/a/b/c.dylib", "/a/b"), ("/a/b/", "/a"), ("/a", "/"), ("/", None)])
def test_parent_of_walks_up_to_root(path: str, parent: str | None) -> None:
    assert MacOsNativeLibraryLoader.parent_of(path) == parent


def test_standard_installs_pass() -> None:
    verify_system(system_install())
    verify_user(user_install())


def test_ownership_and_write_permission_rules() -> None:
    fs = system_install()
    fs["/Library/Application Support/HkdfGuard/v1"] = d(USER, STAFF, 0o755)
    with pytest.raises(PermissionError, match=r"owned by uid 501.*owned by root\."):
        verify_system(fs)

    fs = user_install()
    fs[MacOsNativeLibraryLoader.user_path(HOME)] = f(OTHER_USER, STAFF, 0o644)
    with pytest.raises(PermissionError, match="root or the current user"):
        verify_user(fs)

    fs = user_install()
    fs[f"{HOME}/.hkdfguard"] = d(USER, STAFF, 0o702)
    with pytest.raises(PermissionError, match="writable by every user"):
        verify_user(fs)

    fs = user_install()
    fs[HOME] = d(USER, STAFF, 0o775)
    with pytest.raises(PermissionError, match="writable by group 20"):
        verify_user(fs)


def test_only_the_shared_system_directories_may_be_admin_writable() -> None:
    for directory in ("/", "/Library", "/Library/Application Support"):
        fs = system_install()
        fs[directory] = d(ROOT, ADMIN, 0o775)
        verify_system(fs)

    fs = system_install()
    fs["/Library/Application Support"] = d(ROOT, STAFF, 0o775)
    with pytest.raises(PermissionError):
        verify_system(fs)

    for directory in ("/Library/Application Support/HkdfGuard", "/Library/Application Support/HkdfGuard/v1"):
        for group in (WHEEL, ADMIN):
            fs = system_install()
            fs[directory] = d(ROOT, group, 0o775)
            with pytest.raises(PermissionError, match=f"'{directory}' is writable by group {group}"):
                verify_system(fs)

    fs = system_install()
    fs[MacOsNativeLibraryLoader.system_path()] = f(ROOT, ADMIN, 0o664)
    with pytest.raises(PermissionError):
        verify_system(fs)

    fs = user_install()
    fs["/Users"] = d(ROOT, ADMIN, 0o775)
    verify_user(fs)
    fs[HOME] = d(ROOT, ADMIN, 0o775)
    with pytest.raises(PermissionError):
        verify_user(fs)


@pytest.mark.parametrize("kind", [UnixFileType.SYMBOLIC_LINK, UnixFileType.DIRECTORY, UnixFileType.OTHER])
def test_the_library_must_be_a_regular_file_and_its_parents_real_directories(kind: UnixFileType) -> None:
    fs = system_install()
    fs[MacOsNativeLibraryLoader.system_path()] = UnixFileStatus(ROOT, WHEEL, 0o644, kind)
    with pytest.raises(PermissionError, match=rf"\(it is a {kind.value}\)"):
        verify_system(fs)

    fs = user_install()
    fs[f"{HOME}/.hkdfguard"] = UnixFileStatus(USER, STAFF, 0o755, UnixFileType.SYMBOLIC_LINK)
    with pytest.raises(PermissionError, match=r"is not a directory \(it is a symbolic link\)"):
        verify_user(fs)


def test_the_code_requirement_pins_the_hkdfguard_team_and_any_failure_is_refused() -> None:
    assert MacOsNativeLibraryLoader.CODE_REQUIREMENT == (
        'identifier "libhkdfguard_v1" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
        ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "MFW3T8R8J3"')
    checked: list[str] = []
    MacOsNativeLibraryLoader.verify_signature("/x.dylib", lambda p, r: checked.append(r) or 0)  # type: ignore[func-returns-value]
    assert checked == [MacOsNativeLibraryLoader.CODE_REQUIREMENT]
    for status in (-67050, -67062):
        with pytest.raises(PermissionError, match=rf"MFW3T8R8J3.*OSStatus {status}"):
            MacOsNativeLibraryLoader.verify_signature("/x.dylib", lambda p, r, s=status: s)  # type: ignore[misc]


def test_dyld_library_path_shadowing_is_refused_and_only_that_variable_is_read() -> None:
    for search_path in (None, "", "/opt/lib:/usr/local/lib"):
        MacOsNativeLibraryLoader.refuse_shadowing(lambda n, s=search_path: s, lambda p: False)  # type: ignore[misc]
    for search_path in ("/tmp/decoy", "/opt/lib:/tmp/decoy/:/usr/local/lib"):
        with pytest.raises(PermissionError, match=r"/tmp/decoy/libhkdfguard_v1\.dylib.*DYLD_LIBRARY_PATH"):
            MacOsNativeLibraryLoader.refuse_shadowing(lambda n, s=search_path: s, lambda p: p == "/tmp/decoy/libhkdfguard_v1.dylib")  # type: ignore[misc]
    asked: list[str] = []
    MacOsNativeLibraryLoader.refuse_shadowing(asked.append, lambda p: True)
    assert asked == ["DYLD_LIBRARY_PATH"]


def test_the_loaded_image_must_be_the_verified_file() -> None:
    system = MacOsNativeLibraryLoader.system_path()
    MacOsNativeLibraryLoader.verify_loaded_image(system, system)
    with pytest.raises(PermissionError, match="unloaded"):
        MacOsNativeLibraryLoader.verify_loaded_image(system, "/tmp/decoy/libhkdfguard_v1.dylib")
    with pytest.raises(PermissionError, match=MacOsNativeLibraryLoader.PROBE_EXPORT):
        MacOsNativeLibraryLoader.verify_loaded_image(system, None)


# --- Native integration (a provisioned KEK) --------------------------------------------------


def test_wrap_and_unwrap_round_trip_a_32_byte_dek(service: str) -> None:
    wrapper = NativeHkdfKeyWrapperV1(service)
    dek = os.urandom(32)
    wrapped = bytearray(512)

    length = wrapper.wrap(dek, wrapped)
    assert length > 0 and bytes(wrapped[:length]) != dek

    recovered = bytearray(32)
    assert wrapper.unwrap(wrapped[:length], recovered) == 32
    assert recovered == dek


def test_generate_and_wrap_produces_a_dek_that_unwraps_the_same_every_time(service: str) -> None:
    wrapper = NativeHkdfKeyWrapperV1(service)
    wrapped = bytearray(512)
    payload = wrapped[: wrapper.generate_and_wrap(wrapped)]

    first, second = bytearray(32), bytearray(32)
    assert wrapper.unwrap(payload, first) == 32 and wrapper.unwrap(payload, second) == 32
    assert not ArrayUtility.is_null_or_empty(first)
    assert first == second


def test_a_payload_wrapped_for_one_service_does_not_unwrap_under_another(service: str) -> None:
    wrapped = bytearray(512)
    length = NativeHkdfKeyWrapperV1(service).wrap(os.urandom(32), wrapped)
    other = os.environ.get("HKDFGUARD_TEST_SERVICE_OTHER") or UNPROVISIONED_SERVICE

    destination = bytearray(32)
    with pytest.raises(CryptographicError):
        NativeHkdfKeyWrapperV1(other).unwrap(wrapped[:length], destination)
    assert destination == bytearray(32)


def test_the_binding_reports_buffer_and_payload_errors(service: str) -> None:
    library = native_library()
    dek = os.urandom(32)

    too_small = library.wrap_dek(service, dek, bytearray(1))
    assert too_small.status < 0 and too_small.bytes_written > 1

    wrapped = bytearray(512)
    status, length = library.wrap_dek(service, dek, wrapped)
    assert status == OK
    assert library.unwrap_dek(service, wrapped[:length], bytearray(1)).status < 0
    assert library.generate_and_wrap_dek(service, bytearray(1)).status < 0

    corrupted = bytearray(wrapped[:length])
    corrupted[0] ^= 0xFF
    corrupted[length // 2] ^= 0xFF
    recovered = bytearray(32)
    assert library.unwrap_dek(service, corrupted, recovered).status < 0
    assert recovered == bytearray(32)
