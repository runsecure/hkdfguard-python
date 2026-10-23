from __future__ import annotations

import base64
import ctypes
import errno
import os
import stat
import subprocess
import sys
import tempfile
import threading
import uuid
from collections.abc import Buffer, Callable, Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from hkdfguard.abstractions import ArrayUtility, CryptographicError, InvalidKeyFileError, KeyWrapper, WrappedKeyLimits, WritableBuffer
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1, NativeLibraryNotFoundError, native_library, resolve_library
from hkdfguard.keywrapping.v1._interop._kms import OK, AbstractHkdfGuardKmsLibrary, CpuArchitecture, KmsResult
from hkdfguard.keywrapping.v1._interop._linux import LinuxHkdfGuardKmsLibrary
from hkdfguard.keywrapping.v1._interop._macos import MacOsHkdfGuardKmsLibrary, MacOsNativeLibraryLoader
from hkdfguard.keywrapping.v1._interop._unix import UnixFileStatus, UnixFileType
from hkdfguard.keywrapping.v1._interop._windows import (
    VerifiedSigner,
    WindowsHkdfGuardKmsLibrary,
    WindowsNativeLibraryLoader,
    windows_subject_name,
)
from hkdfguard_test_support import (
    DEFAULT_TEST_SERVICE,
    SERVICE_VARIABLE,
    await_native_access,
    kek_exists,
    key_directory,
    long_path,
    native_test_service,
    private_key_directory,
    private_key_directory_root,
    provisioned_service,
    untrusted_directory,
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
        self.open_file_status = OK
        self.open_file_payload: bytes = bytes(range(132))
        self.last_open_file_path: str | None = None
        self.last_open_file_capacity: int | None = None

    def describe_status(self, status: int) -> str | None:
        return self.describe(status) if self.describe else super().describe_status(status)

    def harden_process(self, flags: int) -> int:
        self.calls.append("harden")
        return OK

    def _open_file(self, path: str, destination: WritableBuffer) -> KmsResult:
        self.calls.append("open_file")
        self.last_open_file_path = path
        self.last_open_file_capacity = len(memoryview(destination).cast("B"))
        if self.throw_on_call is not None:
            raise self.throw_on_call
        if self.open_file_status != OK:
            return KmsResult(self.open_file_status, 0)
        return self._emit(destination, self.open_file_payload)

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


UNPROVISIONED_SERVICE = "hkdfguard.integrationtest.unprovisioned"


def windows_library_installed() -> bool:
    return IS_WINDOWS and os.path.isfile(WindowsNativeLibraryLoader.installed_path())


installed_windows_library = pytest.mark.skipif(not windows_library_installed(), reason="The Windows native KMS library is not installed.")


@pytest.fixture
def service() -> str:
    """HKDFGUARD_TEST_SERVICE, or DEFAULT_TEST_SERVICE where Windows or macOS reports it provisioned,
    after its first native call has answered in time; skips the test when there is none."""
    return native_test_service()


# --- NativeHkdfKeyWrapperV1 -------------------------------------------------------------------


def test_wrap_delegates_to_the_library() -> None:
    library = FakeKmsLibrary()
    library.wrap_payload = bytes([10, 20, 30, 40])
    result = bytearray(16)

    assert NativeHkdfKeyWrapperV1("service.a", library).wrap(bytes([1, 2, 3, 4, 5]), result) == 4

    assert (library.calls, library.last_service, library.last_input) == (["wrap"], "service.a", bytes([1, 2, 3, 4, 5]))
    assert result[:4] == bytes([10, 20, 30, 40])


@pytest.mark.parametrize("status", [-7, -13, -40])  # reserved codes: no platform returns them, so there is no meaning to add
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

    library.generate_status = -40
    with pytest.raises(CryptographicError, match=r"generate-and-wrap failed for service 'service\.e' with status -40\."):
        NativeHkdfKeyWrapperV1("service.e", library).generate_and_wrap(bytearray(16))


@pytest.mark.parametrize("written", [-1, 17])
@pytest.mark.parametrize("operation", ["wrap", "unwrap", "generate-and-wrap"])
def test_a_success_reporting_a_written_count_outside_the_buffer_is_refused_and_zeroes_the_result(operation: str, written: int) -> None:
    class Miscounting(FakeKmsLibrary):
        def wrap_dek(self, service: str, dek: Buffer, destination: WritableBuffer) -> KmsResult:
            return super().wrap_dek(service, dek, destination)._replace(bytes_written=written)

        def unwrap_dek(self, service: str, wrapped: Buffer, destination: WritableBuffer) -> KmsResult:
            return super().unwrap_dek(service, wrapped, destination)._replace(bytes_written=written)

        def generate_and_wrap_dek(self, service: str, destination: WritableBuffer) -> KmsResult:
            return super().generate_and_wrap_dek(service, destination)._replace(bytes_written=written)

    library = Miscounting()
    library.generate_payload = bytes([7] * 5)
    wrapper = NativeHkdfKeyWrapperV1("service.f", library)
    calls: dict[str, Callable[[bytearray], int]] = {
        "wrap": lambda result: wrapper.wrap(bytes([7] * 5), result),
        "unwrap": lambda result: wrapper.unwrap(bytes([7] * 5), result),
        "generate-and-wrap": wrapper.generate_and_wrap,
    }
    result = bytearray(16)

    with pytest.raises(CryptographicError, match=rf"{operation} for service 'service\.f' reported {written} bytes written into a 16-byte buffer\."):
        calls[operation](result)
    assert result == bytearray(16)


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
    expected = {"win32": WindowsHkdfGuardKmsLibrary, "linux": LinuxHkdfGuardKmsLibrary, "darwin": MacOsHkdfGuardKmsLibrary}.get(sys.platform)
    if expected is not None:
        assert type(native_library()) is expected
    assert isinstance(resolve_library("win32"), WindowsHkdfGuardKmsLibrary)
    assert isinstance(resolve_library("linux"), LinuxHkdfGuardKmsLibrary)
    assert isinstance(resolve_library("darwin"), MacOsHkdfGuardKmsLibrary)
    with pytest.raises(NotImplementedError, match="freebsd14"):
        resolve_library("freebsd14")


# --- Status codes -----------------------------------------------------------------------------


SHARED_STATUS_CODES = {
    "ERR_INVALID_ARGUMENT": -1, "ERR_BUFFER_TOO_SMALL": -2, "ERR_PROVIDER_UNAVAILABLE": -3, "ERR_PROVIDER_ERROR": -4, "ERR_CRYPTO_ERROR": -5,
    "ERR_INTERNAL_ERROR": -6, "ERR_INVALID_SERVICE_NAME": -8, "ERR_POLICY_INVALID": -9, "ERR_PAYLOAD_MALFORMED": -10,
    "ERR_PAYLOAD_AUTH_FAILED": -11, "ERR_PAYLOAD_UNSUPPORTED": -12, "ERR_KEK_FINGERPRINT_MISMATCH": -16, "ERR_KEK_NOT_FOUND": -17,
    "ERR_KEK_ACCESS_DENIED": -18, "ERR_KEK_INVALID": -19, "ERR_PROCESS_HARDENING_FAILED": -20, "ERR_FILE_NOT_FOUND": -32,
    "ERR_FILE_ACCESS_DENIED": -33, "ERR_FILE_IO": -34, "ERR_FILE_TOO_SHORT": -35, "ERR_FILE_TOO_LONG": -36, "ERR_FILE_PLAINTEXT_KEY": -37,
    "ERR_FILE_MALFORMED": -38, "ERR_FILE_UNTRUSTED": -39, "ERR_WIN_GROUP_INVALID": -64, "ERR_MAC_ACCESS_CONTROL_CREATION_FAILED": -96,
    "ERR_MAC_KEY_GENERATION_FAILED": -97, "ERR_MAC_KEYCHAIN_WRITE_FAILED": -98, "ERR_MAC_KEK_VERIFICATION_FAILED": -99,
    "ERR_MAC_KEYCHAIN_READ_FAILED": -100,
}
"""Every status code, exactly as every platform's hkdfguard.h defines it."""

RESERVED_STATUS_CODES = [-7, -13, -14, -15, -21, -31, -40, -63, -65, -79, -80, -95, -101, -111, 1]

PLATFORM_LIBRARIES: list[Callable[[], AbstractHkdfGuardKmsLibrary]] = [WindowsHkdfGuardKmsLibrary, LinuxHkdfGuardKmsLibrary, MacOsHkdfGuardKmsLibrary]


def test_ok_is_zero() -> None:
    assert OK == 0


@pytest.mark.parametrize(("name", "value"), SHARED_STATUS_CODES.items())
def test_the_status_codes_match_the_native_header_on_every_platform(name: str, value: int) -> None:
    assert getattr(AbstractHkdfGuardKmsLibrary, name) == value
    for library in PLATFORM_LIBRARIES:
        assert getattr(library, name) == value


@pytest.mark.parametrize("create", PLATFORM_LIBRARIES)
def test_every_platform_describes_every_defined_status_and_nothing_else(create: Callable[[], AbstractHkdfGuardKmsLibrary]) -> None:
    library = create()
    for name, status in SHARED_STATUS_CODES.items():
        assert library.describe_status(status), f"{type(library).__name__}: no description for {name} ({status})"
    for reserved in RESERVED_STATUS_CODES:
        assert library.describe_status(reserved) is None, f"{type(library).__name__} describes reserved status {reserved}"


@pytest.mark.parametrize("create", PLATFORM_LIBRARIES)
def test_every_platform_says_how_to_provision_a_missing_kek(create: Callable[[], AbstractHkdfGuardKmsLibrary]) -> None:
    assert "provision" in (create().describe_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND) or "")


def test_the_shared_descriptions_match_the_other_ports() -> None:
    library = FakeKmsLibrary()
    assert library.describe_status(-17) == "no KEK is provisioned for this service; run hkdfguard provision"
    assert library.describe_status(-18) == "the KEK exists, but this account is not authorized to use it"
    assert "key exposure" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY) or "")
    assert library.describe_status(-64) == ("an HKLM\\Software\\Policies\\HkdfGuard\\KeyUseGroups entry is unresolvable, not a group, "
                                            "not host-local, or over-broad")


def test_windows_adds_its_own_hints_and_names_the_current_command_line_tool() -> None:
    library = WindowsHkdfGuardKmsLibrary()
    access_denied = library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED) or ""
    assert "not authorized" in access_denied and "HkdfGuardUsers" in access_denied and "KeyUseGroups" in access_denied
    not_found = library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND) or ""
    assert "hkdfguard provision" in not_found and "v1-initialize" not in not_found
    assert "HKLM\\Software\\Policies\\HkdfGuard" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_POLICY_INVALID) or "")
    # Codes Windows has nothing to add to fall back to the shared meaning.
    assert library.describe_status(-37) == FakeKmsLibrary().describe_status(-37)


def test_linux_adds_its_own_hints() -> None:
    library = LinuxHkdfGuardKmsLibrary()
    assert "/etc/hkdfguard/policy.toml" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_POLICY_INVALID) or "")
    assert "different KEK" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH) or "")
    assert "hkdfguard provision" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND) or "")
    assert library.describe_status(-1) == FakeKmsLibrary().describe_status(-1)


def test_macos_adds_its_own_hints() -> None:
    library = MacOsHkdfGuardKmsLibrary()
    assert "keychain" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED) or "")
    assert "Secure Enclave" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_PROVIDER_UNAVAILABLE) or "")
    assert library.describe_status(-1) == FakeKmsLibrary().describe_status(-1)


# --- open_file: the interop returns the file's bytes, or raises --------------------------------


def test_open_file_returns_exactly_the_bytes_the_native_library_read() -> None:
    library = FakeKmsLibrary()

    data = library.open_file("C:\\keys\\dek.bin")

    assert type(data) is bytes and data == bytes(range(132))
    assert library.last_open_file_path == "C:\\keys\\dek.bin"


@pytest.mark.parametrize("read", [-1, WrappedKeyLimits.MAX_BYTES + 1])
def test_open_file_refuses_a_read_count_outside_its_buffer(read: int) -> None:
    class MisreportingLibrary(FakeKmsLibrary):
        def _open_file(self, path: str, destination: WritableBuffer) -> KmsResult:
            super()._open_file(path, destination)
            return KmsResult(OK, read)

    with pytest.raises(CryptographicError, match=f"reported {read} bytes read"):
        MisreportingLibrary().open_file("C:\\keys\\dek.bin")


def test_open_file_passes_a_buffer_large_enough_for_every_platforms_wrapped_dek() -> None:
    library = FakeKmsLibrary()
    library.open_file_payload = os.urandom(WrappedKeyLimits.MAX_BYTES)

    assert library.open_file(Path("dek.bin")) == library.open_file_payload
    assert library.last_open_file_capacity == WrappedKeyLimits.MAX_BYTES >= 276
    assert library.last_open_file_path == "dek.bin"


@pytest.mark.parametrize(("status", "expected"), [
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND, FileNotFoundError),
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_ACCESS_DENIED, PermissionError),
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED, PermissionError),
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_SHORT, InvalidKeyFileError),
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_LONG, InvalidKeyFileError),
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY, InvalidKeyFileError),
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_MALFORMED, InvalidKeyFileError),
    (AbstractHkdfGuardKmsLibrary.ERR_FILE_IO, OSError),
    (AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT, ValueError),
    (AbstractHkdfGuardKmsLibrary.ERR_INTERNAL_ERROR, OSError),
])
def test_open_file_turns_each_refusal_into_the_matching_exception(status: int, expected: type[Exception]) -> None:
    library = FakeKmsLibrary()
    library.open_file_status = status

    with pytest.raises(expected) as error:
        library.open_file("C:\\keys\\dek.bin")

    assert type(error.value) is expected
    assert str(error.value) == (f"Key file 'C:\\keys\\dek.bin' was refused by the native library with status {status} "
                                f"({library.describe_status(status)}).")


def test_every_invalid_data_refusal_is_still_an_os_error() -> None:
    assert issubclass(InvalidKeyFileError, OSError)


def test_open_file_says_when_a_status_is_unknown() -> None:
    library = FakeKmsLibrary()
    library.open_file_status = -63

    with pytest.raises(OSError) as error:
        library.open_file("dek.bin")

    assert type(error.value) is OSError
    assert str(error.value) == "Key file 'dek.bin' was refused by the native library with status -63 (unknown status)."


@pytest.mark.parametrize(("path", "expected"), [(None, TypeError), ("", ValueError), ("dek\0.bin", ValueError),
                                                ("dek\ud800.bin", ValueError), (b"dek.bin", TypeError)])
def test_open_file_refuses_a_missing_or_unusable_path_before_reaching_the_native_library(path: object, expected: type[Exception]) -> None:
    library = FakeKmsLibrary()

    with pytest.raises(expected):
        library.open_file(path)  # type: ignore[arg-type]

    assert library.calls == []


def test_a_failure_names_the_status_and_its_shared_meaning() -> None:
    library = FakeKmsLibrary()
    library.unwrap_status = AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND

    with pytest.raises(CryptographicError) as error:
        NativeHkdfKeyWrapperV1("service.d", library).unwrap(b"\x01", bytearray(32))

    assert str(error.value) == ("Native KMS unwrap failed for service 'service.d' with status -17 "
                                "(no KEK is provisioned for this service; run hkdfguard provision).")


# --- NativeHkdfKeyWrapperV1.read_key_file ------------------------------------------------------


def test_read_key_file_reads_through_the_native_library_not_python_file_io() -> None:
    library = FakeKmsLibrary()
    wrapper = NativeHkdfKeyWrapperV1("service.h", library)

    # The path doesn't exist: only the native library is asked about it.
    read = wrapper.read_key_file("C:\\no\\such\\dek.bin")

    assert type(read) is bytearray and read == bytes(range(132))
    assert library.calls == ["open_file"]
    assert library.last_open_file_path == "C:\\no\\such\\dek.bin"


def test_read_key_file_through_the_abstract_type_reaches_the_native_library_whatever_the_permission_setting() -> None:
    library = FakeKmsLibrary()
    wrapper: KeyWrapper = NativeHkdfKeyWrapperV1("service.h", library)

    wrapper.read_key_file("dek.bin", verify_permissions=False)

    assert library.calls == ["open_file"]


def test_read_key_file_surfaces_a_refusal() -> None:
    library = FakeKmsLibrary()
    library.open_file_status = AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY

    with pytest.raises(InvalidKeyFileError, match="key exposure") as error:
        NativeHkdfKeyWrapperV1("service.h", library).read_key_file("dek.bin")

    assert "'dek.bin'" in str(error.value) and "status -37" in str(error.value)


def test_read_key_file_surfaces_a_library_that_fails_to_load() -> None:
    library = FakeKmsLibrary()
    library.throw_on_call = PermissionError("not signed by the HkdfGuard publisher")

    with pytest.raises(PermissionError, match="not signed"):
        NativeHkdfKeyWrapperV1("service.h", library).read_key_file("dek.bin")


# --- Windows loader: location ---------------------------------------------------------------


def sddl(text: str):  # type: ignore[no-untyped-def]
    from hkdfguard.keywrapping.v1._interop import _win32

    return _win32.security_descriptor_from_sddl(text)


USERS = "S-1-5-32-545"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"


@windows_only
def test_installed_path_is_under_program_files() -> None:
    expected = Path(os.environ["PROGRAMFILES"], "HkdfGuard", "v1", "HkdfGuard.dll")
    assert WindowsNativeLibraryLoader.FILE_NAME == "HkdfGuard.dll"
    assert Path(WindowsNativeLibraryLoader.installed_path()) == expected


@windows_only
def test_load_from_a_missing_file_names_the_only_supported_path() -> None:
    missing = str(Path(tempfile.gettempdir(), f"hkdfguard-missing-{uuid.uuid4().hex}", "HkdfGuard.dll"))
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
def test_the_installed_command_line_tool_passes_the_signer_checks_but_is_not_a_dll() -> None:
    tool = str(Path(WindowsNativeLibraryLoader.installed_path()).with_name("hkdfguard.exe"))
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
    assert WindowsHkdfGuardKmsLibrary()._open_file("no-such-dek.bin", bytearray(512)).status == AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND


@installed_windows_library
def test_the_module_windows_mapped_is_the_installed_library() -> None:
    # Worked out independently of the loader: %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll.
    expected = os.path.join(os.environ["PROGRAMFILES"], "HkdfGuard", "v1", "HkdfGuard.dll")
    library = WindowsNativeLibraryLoader.load()

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    kernel32.GetModuleFileNameW.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32_767)
    length = kernel32.GetModuleFileNameW(library._handle, buffer, len(buffer))

    assert 0 < length < len(buffer)
    assert buffer.value.lower() == expected.lower()
    assert WindowsNativeLibraryLoader.load()._handle == library._handle


@installed_windows_library
def test_the_installed_library_is_validly_signed_by_the_expected_publisher() -> None:
    WindowsNativeLibraryLoader.verify_signature(WindowsNativeLibraryLoader.installed_path(), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER)


@installed_windows_library
def test_kek_exists_answers_for_an_unprovisioned_service() -> None:
    status, exists = kek_exists(UNPROVISIONED_SERVICE)

    assert not exists
    assert status == OK or WindowsHkdfGuardKmsLibrary().describe_status(status) is not None, f"undescribed status {status}"


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
    assert MacOsNativeLibraryLoader.system_path() == "/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib"
    assert MacOsNativeLibraryLoader.user_path("/Users/dev") == MacOsNativeLibraryLoader.user_path("/Users/dev/") \
        == "/Users/dev/.hkdfguard/v1/libhkdfguard.dylib"


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
    assert ".hkdfguard/v1/libhkdfguard.dylib" in str(error.value)


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
        'identifier "libhkdfguard" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
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
        with pytest.raises(PermissionError, match=r"/tmp/decoy/libhkdfguard\.dylib.*DYLD_LIBRARY_PATH"):
            MacOsNativeLibraryLoader.refuse_shadowing(lambda n, s=search_path: s, lambda p: p == "/tmp/decoy/libhkdfguard.dylib")  # type: ignore[misc]
    asked: list[str] = []
    MacOsNativeLibraryLoader.refuse_shadowing(asked.append, lambda p: True)
    assert asked == ["DYLD_LIBRARY_PATH"]


def test_the_loaded_image_must_be_the_verified_file() -> None:
    system = MacOsNativeLibraryLoader.system_path()
    MacOsNativeLibraryLoader.verify_loaded_image(system, system)
    with pytest.raises(PermissionError, match="unloaded"):
        MacOsNativeLibraryLoader.verify_loaded_image(system, "/tmp/decoy/libhkdfguard.dylib")
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


def test_multiple_keys_under_one_service_wrap_and_unwrap_independently(service: str) -> None:
    wrapper = NativeHkdfKeyWrapperV1(service)
    deks = [os.urandom(32), os.urandom(32)]
    payloads: list[bytes] = []
    for dek in deks:
        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        payloads.append(bytes(wrapped[: wrapper.wrap(dek, wrapped)]))
    assert payloads[0] != payloads[1]

    for dek, payload in zip(deks, payloads, strict=True):
        recovered = bytearray(32)
        assert wrapper.unwrap(payload, recovered) == 32
        assert recovered == dek


def test_the_library_directly_wraps_unwraps_and_generates_with_ok_statuses(service: str) -> None:
    library = native_library()
    dek = os.urandom(32)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    status, written = library.wrap_dek(service, dek, wrapped)
    assert status == OK and written > 0
    recovered = bytearray(32)
    assert library.unwrap_dek(service, wrapped[:written], recovered) == (OK, 32)
    assert recovered == dek

    generated = bytearray(WrappedKeyLimits.MAX_BYTES)
    status, written = library.generate_and_wrap_dek(service, generated)
    assert status == OK and written > 0
    fresh = bytearray(32)
    assert library.unwrap_dek(service, generated[:written], fresh) == (OK, 32)
    assert not ArrayUtility.is_null_or_empty(fresh) and any(fresh)


def test_the_library_directly_refuses_too_small_buffers_and_corrupt_payloads(service: str) -> None:
    # The binding's own answers, without the wrapper's checks and zeroing in between.
    library = native_library()

    status, required = library.wrap_dek(service, os.urandom(32), bytearray(1))
    assert status < 0 and 32 < required <= WrappedKeyLimits.MAX_BYTES  # an error, and a capacity that suffices
    exact = bytearray(required)
    status, written = library.wrap_dek(service, os.urandom(32), exact)
    assert status == OK and 0 < written <= required
    assert library.generate_and_wrap_dek(service, bytearray(1)).status < 0

    payload = bytearray(exact[:written])
    assert library.unwrap_dek(service, payload, bytearray(1)).status < 0

    payload[0] ^= 0xFF
    payload[len(payload) // 2] ^= 0xFF
    recovered = bytearray(32)
    assert library.unwrap_dek(service, payload, recovered).status < 0
    assert recovered == bytearray(32), "the native library wrote into the destination of a failed unwrap"


def test_too_small_buffers_and_corrupt_payloads_fail_through_the_wrapper(service: str) -> None:
    wrapper = NativeHkdfKeyWrapperV1(service)
    with pytest.raises(CryptographicError):
        wrapper.wrap(bytes(32), bytearray(8))
    with pytest.raises(CryptographicError):
        wrapper.generate_and_wrap(bytearray(8))

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    with pytest.raises(CryptographicError):
        wrapper.unwrap(wrapped[:length], bytearray(8))

    wrapped[0] ^= 0xFF
    wrapped[length // 2] ^= 0xFF
    destination = bytearray(32)
    with pytest.raises(CryptographicError):
        wrapper.unwrap(wrapped[:length], destination)
    assert destination == bytearray(32)


# --- Key files read through the real native library (hkdfguard_open_file) -----------------------
#
# Refusals of a file's size, contents or location need no KEK, so they run wherever the Windows
# library is installed; reading back a real wrapped key needs a provisioned service.


@pytest.fixture
def key_dir(tmp_path: Path) -> Iterator[Path]:
    """Where these tests write key files (hkdfguard_test_support.key_directory): tmp_path in long form
    on Windows; on Linux a private 0700 directory outside /tmp, which the library refuses."""
    with key_directory(tmp_path) as directory:
        yield directory


def reader() -> NativeHkdfKeyWrapperV1:
    # Any valid name: reading a file never touches a KEK.
    return NativeHkdfKeyWrapperV1("hkdfguard.keyfile.reader")


def write(directory: Path, name: str, contents: bytes) -> Path:
    path = directory / name
    path.write_bytes(contents)
    return path


def wrap_to_file(service: str, directory: Path) -> tuple[Path, bytes, bytes]:
    dek = os.urandom(32)
    buffer = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = NativeHkdfKeyWrapperV1(service).wrap(dek, buffer)
    wrapped = bytes(buffer[:length])
    return write(directory, "wrapped-dek.bin", wrapped), wrapped, dek


def test_the_long_path_helper_expands_short_names(tmp_path: Path) -> None:
    directory = long_path(tmp_path) / "a folder with a long name"
    directory.mkdir()
    short = directory
    if sys.platform == "win32":
        buffer = ctypes.create_unicode_buffer(32_767)
        if 0 < ctypes.WinDLL("kernel32").GetShortPathNameW(str(directory), buffer, len(buffer)) < len(buffer):
            short = Path(buffer.value)  # the same as directory where the volume has no 8.3 names

    assert long_path(short) == directory


linux_only = pytest.mark.skipif(sys.platform != "linux", reason="Linux only.")


@linux_only
def test_the_key_directory_on_linux_is_private_trusted_outside_the_shared_temporary_directories_and_removed(tmp_path: Path) -> None:
    uid = os.geteuid()  # type: ignore[attr-defined,unused-ignore]
    with key_directory(tmp_path) as directory:
        status = os.lstat(directory)
        assert stat.S_ISDIR(status.st_mode) and stat.S_IMODE(status.st_mode) == 0o700 and status.st_uid == uid
        assert untrusted_directory(directory, uid) is None
        assert directory == Path(os.path.realpath(directory))
        assert not any(directory == Path(shared) or Path(shared) in directory.parents for shared in ("/tmp", "/var/tmp", "/dev/shm"))
        assert tmp_path not in (directory, *directory.parents)
        write(directory, "dek.bin", bytes(132))
    assert not directory.exists()


@linux_only
def test_untrusted_directory_refuses_group_or_world_writable_directories_sticky_or_not(tmp_path: Path) -> None:
    uid = os.geteuid()  # type: ignore[attr-defined,unused-ignore]
    with private_key_directory() as directory:
        for mode, sticky in ((0o1777, True), (0o777, False), (0o770, False), (0o702, False)):
            shared = directory / f"mode-{mode:o}"
            shared.mkdir()
            shared.chmod(mode)
            (shared / "inner").mkdir(mode=0o700)

            for path in (shared, shared / "inner"):
                reason = untrusted_directory(path, uid)
                assert reason is not None and f"'{shared}'" in reason and "writable by its group or by other users" in reason
                assert ("sticky" in reason) == sticky
        link = directory / "link"
        link.symlink_to(directory)
        assert "symbolic link" in (untrusted_directory(link, uid) or "")
        assert "owned by uid" in (untrusted_directory(directory, uid + 1) or "")  # this user's directory, judged for another
    if os.stat("/tmp").st_mode & stat.S_IWOTH:
        assert "'/tmp'" in (untrusted_directory(Path("/tmp"), uid) or "")


@linux_only
def test_the_private_root_prefers_a_trusted_runtime_directory_then_home_and_otherwise_says_why() -> None:
    uid = os.geteuid()  # type: ignore[attr-defined,unused-ignore]
    with private_key_directory() as directory:
        runtime, home, shared = directory / "runtime", directory / "home", directory / "shared"
        runtime.mkdir(mode=0o700)
        home.mkdir(mode=0o700)
        shared.mkdir()
        shared.chmod(0o1777)

        assert private_key_directory_root({"XDG_RUNTIME_DIR": str(runtime), "HOME": str(home)}, uid, "") == (runtime / "hkdfguard-tests", "")
        assert stat.S_IMODE(os.lstat(runtime / "hkdfguard-tests").st_mode) == 0o700

        expected = home / ".cache" / "hkdfguard-tests"
        assert private_key_directory_root({"XDG_RUNTIME_DIR": str(shared), "HOME": str(home)}, uid, "") == (expected, "")
        assert private_key_directory_root({"HOME": str(home)}, uid, "") == (expected, "")
        assert private_key_directory_root({}, uid, str(home)) == (expected, "")
        assert stat.S_IMODE(os.lstat(home / ".cache").st_mode) == 0o700

        (shared / "home").mkdir(mode=0o700)
        root, reason = private_key_directory_root({"XDG_RUNTIME_DIR": "relative", "HOME": str(shared / "home")}, uid, "")
        assert root is None
        assert "not an absolute path" in reason and f"'{shared}'" in reason and "sticky" in reason and "/tmp" in reason

        loose = directory / "loose"
        loose.mkdir(mode=0o700)
        (loose / ".cache").mkdir(mode=0o700)
        (loose / ".cache").chmod(0o775)
        root, reason = private_key_directory_root({"HOME": str(loose)}, uid, "")
        assert root is None and f"'{loose / '.cache'}'" in reason and "XDG_RUNTIME_DIR is not set" in reason


@linux_only
def test_without_a_private_root_the_key_directory_skips_rather_than_passes() -> None:
    with private_key_directory() as directory:
        shared = directory / "shared"
        shared.mkdir()
        shared.chmod(0o1777)
        (shared / "home").mkdir(mode=0o700)

        with pytest.raises(pytest.skip.Exception, match=r"No private directory for key files.*sticky"), \
                private_key_directory({"HOME": str(shared / "home")}):
            pytest.fail("a key directory under a sticky, world-writable directory")
        assert not (shared / "home" / ".cache").exists()  # nothing is made under an untrusted home


def test_off_macos_waiting_for_native_access_never_calls() -> None:
    calls: list[str] = []

    await_native_access("hkdfguard.test.elsewhere", calls.append, platform="linux")
    await_native_access("hkdfguard.test.elsewhere", calls.append, platform="win32")

    assert calls == []


def test_on_macos_a_first_native_call_that_never_returns_fails_saying_why_and_once_per_service() -> None:
    release = threading.Event()
    calls: list[str] = []

    def blocked(service: str) -> None:
        calls.append(service)
        release.wait(30)

    try:
        for _ in range(2):
            with pytest.raises(pytest.fail.Exception, match=r"'hkdfguard\.test\.blocked'.*keychain.*Always Allow.*\(-18\)"):
                await_native_access("hkdfguard.test.blocked", blocked, timeout=0.05, platform="darwin")
    finally:
        release.set()
    assert calls == ["hkdfguard.test.blocked"]


def test_on_macos_a_first_native_call_that_answers_in_time_passes_whatever_it_answered() -> None:
    calls: list[str] = []

    def refused(service: str) -> None:
        calls.append(service)
        raise CryptographicError("status -18")

    await_native_access("hkdfguard.test.answers", refused, timeout=30, platform="darwin")
    await_native_access("hkdfguard.test.answers", refused, timeout=30, platform="darwin")

    assert calls == ["hkdfguard.test.answers"]


def test_the_shared_service_is_the_variable_or_the_one_default_test_service() -> None:
    assert DEFAULT_TEST_SERVICE == "com.hkdfguard.integration.test.221"
    name, reason = provisioned_service()
    if os.environ.get(SERVICE_VARIABLE):
        assert (name, reason) == (os.environ[SERVICE_VARIABLE], "")
    elif name is not None:
        assert name == DEFAULT_TEST_SERVICE and sys.platform in ("win32", "darwin")
    else:
        assert reason


@installed_windows_library
def test_native_a_missing_key_file_is_not_found(key_dir: Path) -> None:
    path = key_dir / "missing.bin"

    with pytest.raises(FileNotFoundError) as error:
        reader().read_key_file(path)

    assert f"'{path}'" in str(error.value) and "status -32" in str(error.value)


@installed_windows_library
def test_native_a_key_file_in_a_missing_folder_is_not_found(key_dir: Path) -> None:
    with pytest.raises(FileNotFoundError, match="status -32"):
        reader().read_key_file(key_dir / "no-such-folder" / "dek.bin")


PLAINTEXT_FORMS: dict[str, Callable[[bytes], bytes]] = {
    "raw": lambda dek: dek,
    "hex": lambda dek: dek.hex().upper().encode("ascii"),
    "lower-hex": lambda dek: dek.hex().encode("ascii"),
    "base64": base64.b64encode,
    "base64-with-newline": lambda dek: base64.b64encode(dek) + b"\n",
}


@installed_windows_library
@pytest.mark.parametrize("form", PLAINTEXT_FORMS)
def test_native_a_key_file_holding_what_looks_like_an_unwrapped_key_is_refused_as_a_key_exposure(key_dir: Path, form: str) -> None:
    path = write(key_dir, f"plaintext-{form}.bin", PLAINTEXT_FORMS[form](os.urandom(32)))

    with pytest.raises(InvalidKeyFileError) as error:
        reader().read_key_file(path)

    assert "status -37" in str(error.value) and "key exposure" in str(error.value)


@installed_windows_library
@pytest.mark.parametrize(("size", "status"), [(0, -35), (100, -35), (131, -35), (133, -36), (4096, -36)])
def test_native_a_key_file_of_the_wrong_size_is_refused(key_dir: Path, size: int, status: int) -> None:
    contents = bytearray(size)
    if size:
        contents[0] = 0x7F  # never mistaken for text
    path = write(key_dir, f"size-{size}.bin", bytes(contents))

    with pytest.raises(InvalidKeyFileError) as error:
        reader().read_key_file(path)

    assert f"status {status}" in str(error.value) and f"'{path}'" in str(error.value)


@installed_windows_library
def test_native_a_folder_is_not_a_key_file(key_dir: Path) -> None:
    with pytest.raises(OSError, match="was refused by the native library"):
        reader().read_key_file(key_dir)


@installed_windows_library
def test_native_a_key_file_reached_through_a_junction_is_untrusted(key_dir: Path) -> None:
    target = key_dir / "real"
    target.mkdir()
    (target / "dek.bin").write_bytes(bytes(132))
    junction = key_dir / "junction"

    # mklink /J needs no elevation, unlike a symbolic link.
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction), str(target)], check=True, capture_output=True)
    try:
        with pytest.raises(PermissionError) as error:
            reader().read_key_file(junction / "dek.bin")

        assert "status -39" in str(error.value)
    finally:
        os.rmdir(junction)  # removes the junction itself, not what it points at


@installed_windows_library
def test_native_a_key_ring_refuses_to_build_from_a_plaintext_key_file(key_dir: Path) -> None:
    from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
    from hkdfguard.dataencryptionkey import KeyRingBuilder

    path = write(key_dir, "plaintext.bin", os.urandom(32))

    with pytest.raises(InvalidKeyFileError, match="status -37"):
        (KeyRingBuilder().with_key_wrapper(reader()).with_crypto_provider_factory(AesGcmCryptoProviderFactory())
         .with_key_refresh_interval(60).with_key_file(1, path).build())


def test_native_a_key_file_the_wrapper_wrote_reads_back_still_wrapped_and_unwraps_to_its_dek(service: str, key_dir: Path) -> None:
    path, wrapped, dek = wrap_to_file(service, key_dir)
    wrapper = NativeHkdfKeyWrapperV1(service)

    read = wrapper.read_key_file(path)

    assert read == wrapped
    recovered = bytearray(32)
    assert wrapper.unwrap(read, recovered) == 32
    assert recovered == dek


def test_native_a_key_ring_built_from_a_key_file_reads_it_through_the_native_library(service: str, key_dir: Path) -> None:
    from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
    from hkdfguard.dataencryptionkey import KeyRingBuilder

    path, _, _ = wrap_to_file(service, key_dir)

    with (KeyRingBuilder().with_key_wrapper(NativeHkdfKeyWrapperV1(service)).with_crypto_provider_factory(AesGcmCryptoProviderFactory())
          .with_key_refresh_interval(60).with_key_file(4, path).build()) as ring:
        assert ring.current_version == 4
        protector = ring.create_protector("native-key-file")
        formatted = protector.encrypt("value")
        result = bytearray(protector.get_max_decrypted_length(formatted))
        assert result[: protector.decrypt(formatted, result)].decode() == "value"


def test_native_a_key_file_of_the_right_size_with_an_unknown_version_is_malformed(service: str, key_dir: Path) -> None:
    path, wrapped, _ = wrap_to_file(service, key_dir)
    tampered = bytearray(wrapped)
    # The version byte: first on Linux and Windows; on macOS, the suite id after the 32-byte KEK fingerprint.
    tampered[32 if sys.platform == "darwin" else 0] ^= 0xFF
    path.write_bytes(tampered)

    with pytest.raises(InvalidKeyFileError, match="status -38"):
        reader().read_key_file(path)
