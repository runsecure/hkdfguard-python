"""NativeProcessHardening: the decision against a fake library everywhere, and opt-in self-tests that
harden this very test process (HKDFGUARD_TEST_PROCESS_HARDENING=1)."""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Buffer, Callable

import pytest
from hkdfguard.abstractions import WritableBuffer
from hkdfguard.keywrapping.v1 import NativeProcessHardening, ProcessHardeningOptions
from hkdfguard.keywrapping.v1._interop._kms import OK, AbstractHkdfGuardKmsLibrary, CpuArchitecture, KmsResult
from hkdfguard.keywrapping.v1._interop._linux import LinuxHkdfGuardKmsLibrary, LinuxNativeLibraryLoader
from hkdfguard.keywrapping.v1._interop._macos import MacOsHkdfGuardKmsLibrary
from hkdfguard.keywrapping.v1._interop._windows import WindowsHkdfGuardKmsLibrary, WindowsNativeLibraryLoader


class FakeHardeningLibrary(AbstractHkdfGuardKmsLibrary):
    """Answers hkdfguard_harden_process_with_flags with a scripted status, recording the flags; the
    KMS calls are never reached."""

    def __init__(self, status: int = OK, describe: Callable[[int], str | None] | None = None) -> None:
        self.status = status
        self.describe = describe
        self.harden_call_count = 0
        self.last_harden_flags: int | None = None

    def describe_status(self, status: int) -> str | None:
        return self.describe(status) if self.describe else super().describe_status(status)

    def harden_process(self, flags: int) -> int:
        self.harden_call_count += 1
        self.last_harden_flags = flags
        return self.status

    def wrap_dek(self, service: str, dek: Buffer, destination: WritableBuffer) -> KmsResult:
        raise AssertionError("not reached")

    def unwrap_dek(self, service: str, wrapped: Buffer, destination: WritableBuffer) -> KmsResult:
        raise AssertionError("not reached")

    def generate_and_wrap_dek(self, service: str, destination: WritableBuffer) -> KmsResult:
        raise AssertionError("not reached")

    def _open_file(self, path: str, destination: WritableBuffer) -> KmsResult:
        raise AssertionError("not reached")


# --- The decision, against a fake library (runs everywhere) -----------------------------------


def test_apply_succeeds_when_the_library_reports_ok() -> None:
    library = FakeHardeningLibrary()

    NativeProcessHardening.apply(library=library)

    assert library.harden_call_count == 1


def test_apply_by_default_passes_no_flags() -> None:
    library = FakeHardeningLibrary()

    NativeProcessHardening.apply(library=library)

    assert library.last_harden_flags == 0


def test_apply_require_protected_signature_passes_the_native_flag() -> None:
    library = FakeHardeningLibrary()

    NativeProcessHardening.apply(ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE, library=library)

    assert library.last_harden_flags == AbstractHkdfGuardKmsLibrary.HARDEN_REQUIRE_PROTECTED_SIGNATURE
    assert AbstractHkdfGuardKmsLibrary.HARDEN_REQUIRE_PROTECTED_SIGNATURE == 0x1
    assert int(ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE) == 1
    assert int(ProcessHardeningOptions.NONE) == 0


@pytest.mark.parametrize("options", [2, 3, -1, ProcessHardeningOptions(2), ProcessHardeningOptions(3)])
def test_apply_refuses_an_unknown_option_before_reaching_the_native_library(options: int) -> None:
    library = FakeHardeningLibrary()

    with pytest.raises(ValueError, match="Unknown process hardening option"):
        NativeProcessHardening.apply(options, library=library)
    assert library.harden_call_count == 0


@pytest.mark.parametrize("options", [None, "1", 1.0, True])
def test_apply_refuses_options_that_are_not_flags(options: object) -> None:
    library = FakeHardeningLibrary()

    with pytest.raises(TypeError):
        NativeProcessHardening.apply(options, library=library)  # type: ignore[arg-type]
    assert library.harden_call_count == 0


def test_apply_raises_naming_the_status_and_its_meaning() -> None:
    library = FakeHardeningLibrary(
        AbstractHkdfGuardKmsLibrary.ERR_PROCESS_HARDENING_FAILED,
        lambda s: "could not disable core dumps" if s == AbstractHkdfGuardKmsLibrary.ERR_PROCESS_HARDENING_FAILED else None)

    with pytest.raises(RuntimeError) as raised:
        NativeProcessHardening.apply(library=library)

    assert str(raised.value) == "Native process hardening failed with status -20 (could not disable core dumps)."


def test_apply_raises_with_just_the_status_when_its_meaning_is_unknown() -> None:
    library = FakeHardeningLibrary(-150)

    with pytest.raises(RuntimeError) as raised:
        NativeProcessHardening.apply(library=library)

    assert str(raised.value).endswith("status -150.")


def test_an_unknown_flag_the_native_library_refuses_is_reported_too() -> None:
    library = FakeHardeningLibrary(AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT)

    with pytest.raises(RuntimeError, match="status -1 "):
        NativeProcessHardening.apply(library=library)


@pytest.mark.parametrize(("create", "hint"), [
    (WindowsHkdfGuardKmsLibrary, "access lists"),
    (LinuxHkdfGuardKmsLibrary, "ptrace"),
    (MacOsHkdfGuardKmsLibrary, "Hardened Runtime"),
])
def test_each_platform_describes_a_hardening_failure_in_its_own_terms(create: Callable[[], AbstractHkdfGuardKmsLibrary], hint: str) -> None:
    assert hint in (create().describe_status(AbstractHkdfGuardKmsLibrary.ERR_PROCESS_HARDENING_FAILED) or "")


def test_the_options_are_exported_from_the_package() -> None:
    import hkdfguard.keywrapping.v1 as package

    assert "NativeProcessHardening" in package.__all__
    assert "ProcessHardeningOptions" in package.__all__


# --- Opt-in: hardening this very test process ---------------------------------------------------

VARIABLE = "HKDFGUARD_TEST_PROCESS_HARDENING"
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")


def _installed_linux_library() -> str | None:
    if not IS_LINUX:
        return None
    try:
        return next((path for path in LinuxNativeLibraryLoader.candidate_paths(CpuArchitecture.current()) if os.path.isfile(path)), None)
    except OSError:
        return None


def _hardening_skip_reason(platform: str) -> str | None:
    """Why a test that hardens the test process itself can't run here, or ``None`` if it can: it
    needs HKDFGUARD_TEST_PROCESS_HARDENING=1, its platform, and that platform's library installed."""
    if os.environ.get(VARIABLE) != "1":
        return f"Hardens the test process itself; set {VARIABLE}=1 to run it."
    if (platform == "Linux" and not IS_LINUX) or (platform == "Windows" and not IS_WINDOWS):
        return f"{platform} only."
    if platform == "Linux" and _installed_linux_library() is None:
        return "Needs the Linux native library (libhkdfguard1) installed."
    if platform == "Windows" and not os.path.isfile(WindowsNativeLibraryLoader.installed_path()):
        return f"Needs the Windows native library installed at {WindowsNativeLibraryLoader.installed_path()}."
    return None


def process_hardening(platform: str) -> pytest.MarkDecorator:
    reason = _hardening_skip_reason(platform)
    return pytest.mark.skipif(reason is not None, reason=reason or "")


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5


def _open_own_process(access: int) -> tuple[int | None, int]:
    """OpenProcess on this process, without SeDebugPrivilege: the handle (closed again) or ``None``,
    and the last error."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(access, 0, os.getpid())
    error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
    if handle:
        kernel32.CloseHandle(handle)
    return handle, error


@process_hardening("Linux")
def test_apply_on_linux_disables_core_dumps_and_clears_the_dumpable_flag() -> None:
    pr_get_dumpable, rlimit_core = 3, 4
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    limits = (ctypes.c_uint64 * 2)()
    libc.getrlimit.argtypes = [ctypes.c_int, ctypes.c_void_p]
    libc.getrlimit.restype = ctypes.c_int

    NativeProcessHardening.apply()

    assert libc.prctl(pr_get_dumpable, 0, 0, 0, 0) == 0
    assert libc.getrlimit(rlimit_core, limits) == 0
    assert limits[0] == 0  # soft
    assert limits[1] == 0  # hard


@process_hardening("Windows")
def test_apply_on_windows_closes_the_process_to_its_own_account() -> None:
    """The process's access list then grants its own account only query, synchronize and terminate -
    so even this process, asking without SeDebugPrivilege, can no longer open itself to read its
    memory, though it can still query it."""
    NativeProcessHardening.apply()

    readable, error = _open_own_process(PROCESS_VM_READ)
    assert readable is None
    assert error == ERROR_ACCESS_DENIED

    queryable, _ = _open_own_process(PROCESS_QUERY_LIMITED_INFORMATION)
    assert queryable is not None

    # Idempotent: hardening an already hardened process succeeds.
    NativeProcessHardening.apply()


@process_hardening("Windows")
def test_apply_on_windows_with_require_protected_signature_succeeds() -> None:
    """The strict form, on Windows: a console process sharing no named objects - this test process -
    can meet REQUIRE_PROTECTED_SIGNATURE, and threads started afterwards are closed too."""
    NativeProcessHardening.apply(ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE)

    readable, _ = _open_own_process(PROCESS_VM_READ)
    assert readable is None
