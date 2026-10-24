"""Wraps and reveals DEKs under a KEK held by the platform's native HkdfGuard KMS library - a TPM or
Platform Crypto Provider key on Windows, a Secure Enclave key on macOS, the strongest available
provider on Linux - called through ctypes."""

from __future__ import annotations

import enum
import os
import sys
import threading
from collections.abc import Buffer, Callable

from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, ServiceNames, WritableBuffer
from hkdfguard.keywrapping.v1._interop._kms import OK, AbstractHkdfGuardKmsLibrary, KmsResult, NativeLibraryNotFoundError

__all__ = ["NativeHkdfKeyWrapperV1", "NativeLibraryNotFoundError", "NativeProcessHardening", "ProcessHardeningOptions"]

_library_lock = threading.Lock()
_library: AbstractHkdfGuardKmsLibrary | None = None


def resolve_library(platform_name: str) -> AbstractHkdfGuardKmsLibrary:
    """The binding for ``platform_name`` (a ``sys.platform`` value). Binding loads nothing yet: each
    binding loads and verifies its native library on its first call.

    :raises NotImplementedError: there is no native KMS library for this platform
    """
    if platform_name == "win32":
        from hkdfguard.keywrapping.v1._interop._windows import WindowsHkdfGuardKmsLibrary  # noqa: PLC0415 - only this platform's binding
        return WindowsHkdfGuardKmsLibrary()
    if platform_name.startswith("linux"):
        from hkdfguard.keywrapping.v1._interop._linux import LinuxHkdfGuardKmsLibrary  # noqa: PLC0415 - only this platform's binding
        return LinuxHkdfGuardKmsLibrary()
    if platform_name == "darwin":
        from hkdfguard.keywrapping.v1._interop._macos import MacOsHkdfGuardKmsLibrary  # noqa: PLC0415 - only this platform's binding
        return MacOsHkdfGuardKmsLibrary()
    raise NotImplementedError(f"hkdfguard-keywrapping-v1 has no native KMS library for '{platform_name}'.")


def native_library() -> AbstractHkdfGuardKmsLibrary:
    """This platform's binding, resolved once per process."""
    global _library  # noqa: PLW0603 - one binding per process, as in every port
    with _library_lock:
        if _library is None:
            _library = resolve_library(sys.platform)
        return _library


class NativeHkdfKeyWrapperV1(KeyWrapper):
    """Wraps a DEK, or reveals a previously wrapped one, via the current OS's native HkdfGuard KMS
    library - a TPM2, Secure Enclave, or Platform Crypto Provider key held entirely outside this
    process, identified only by a service name. One instance handles both directions, and any number
    of wrapped payloads sharing the service.

    Calls are local and block until the native library answers. A non-OK status raises
    :class:`CryptographicError` naming it (and what it means, where the platform says); a missing or
    unverifiable library raises :class:`NativeLibraryNotFoundError` or ``PermissionError`` on the first call.
    """

    def __init__(self, service_name: str, *, _library: AbstractHkdfGuardKmsLibrary | None = None) -> None:
        """:param service_name: identifies the KEK: 1-128 ASCII letters, digits or '.', not starting
            with '.' and without ".." (see ServiceNames)
        :param _library: for this package's tests only, not public API - the binding to call instead of this platform's
        :raises TypeError: ``service_name`` is ``None``
        :raises ValueError: ``service_name`` breaks a ServiceNames rule
        :raises NotImplementedError: there is no native KMS library for this platform
        """
        # Checked here, before the name can ever reach native code.
        ServiceNames.require_valid(service_name, "service_name")
        self._service_name = service_name
        self._library = _library if _library is not None else native_library()

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        return self._complete(lambda: self._library.wrap_dek(self._service_name, plaintext, result), "wrap", result)

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        try:
            return self._complete(lambda: self._library.unwrap_dek(self._service_name, wrapped, result), "unwrap", result)
        except BaseException:
            # Whatever a failed call left in the DEK buffer is erased.
            ArrayUtility.zero_memory(result)
            raise

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        return self._complete(lambda: self._library.generate_and_wrap_dek(self._service_name, result), "generate-and-wrap", result)

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        """Reads a key file through the native library's hkdfguard_open_file rather than Python file
        I/O. Besides the size and format checks, the native library refuses a file another account
        could have written or replaced - its path, owner and permissions are checked the way only the
        platform can - and one holding what looks like an unwrapped key. The bytes come back still
        wrapped, ready for :meth:`unwrap`. The checks can't be turned off.

        :raises FileNotFoundError: the file, or a folder in its path, does not exist
        :raises PermissionError: this account may not read the file, or its path is not trusted
        :raises InvalidKeyFileError: the file is the wrong size, holds what looks like an unwrapped
            key, or isn't a valid wrapped DEK (an ``OSError``)
        :raises OSError: the file could not be read for another reason
        :raises ValueError: the path is empty, or the native library refused it as invalid
        """
        return bytearray(self._library.open_file(path))

    def _complete(self, call: Callable[[], KmsResult], operation: str, result: WritableBuffer) -> int:
        status, written = call()
        if status == OK:
            # A success claiming more bytes than result holds (or a negative count) is refused rather than trusted.
            capacity = len(memoryview(result).cast("B"))
            if not 0 <= written <= capacity:
                ArrayUtility.zero_memory(result)
                raise CryptographicError(f"Native KMS {operation} for service '{self._service_name}' reported {written} bytes written "
                                         f"into a {capacity}-byte buffer.")
            return written

        # Name the status's meaning when it is known - "-18" alone tells an operator nothing.
        description = self._library.describe_status(status)
        meaning = f" ({description})" if description else ""
        raise CryptographicError(f"Native KMS {operation} failed for service '{self._service_name}' with status {status}{meaning}.")


class ProcessHardeningOptions(enum.IntFlag):
    """How strict :meth:`NativeProcessHardening.apply` is."""

    NONE = 0
    """Harden as far as this process allows; on macOS a weak code signature is only logged."""

    REQUIRE_PROTECTED_SIGNATURE = 1
    """Fail unless no other process of the same user can attach a debugger to, or inject code into,
    this process - what the native command-line tools themselves require. On Windows it also closes
    everything the process creates afterwards (threads, child processes, named pipes and other named
    objects) to its own user, so use it in a service that shares no objects with other processes by
    name. On macOS it fails unless the host executable is signed with the Hardened Runtime and
    without the get-task-allow or DYLD_* entitlements, so unsigned hosts (python itself, a virtual
    environment's interpreter) can't use it. On Linux it adds nothing: the plain call already
    guarantees it."""


class NativeProcessHardening:
    """Opt-in hardening of the whole process, through the native KMS library's
    hkdfguard_harden_process_with_flags. DEKs pass through this process's memory, so a crash dump,
    or another process of the same user attaching a debugger or reading its memory, could recover
    them. The native library never does this on its own: it changes process-wide state the
    application owns. What it does:

    - **Windows:** crash reports leave out the heap (WerSetFlags NOHEAP), and the process's and its
      existing threads' access lists are replaced so that only SYSTEM may read or write its memory,
      inject threads or duplicate its handles - the account it runs as keeps only query, synchronize
      and terminate. Threads started later keep the default access unless
      :attr:`ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE` is passed; call it early, before
      starting worker threads.
    - **Linux:** the core dump limit is set to zero (hard limit included) and the process's dumpable
      flag is cleared, which also stops ptrace and /proc/<pid>/mem access by other processes of the
      same user.
    - **macOS:** core dumps are disabled and debugger attachment is denied; the host executable's
      code signature decides whether code injection is possible, which the library can check but
      not change.

    It is opt-in because it is process-wide: debuggers, py-spy and crash dumps stop working for the
    application. Call it once, early, and after any privilege drop (on Linux the kernel resets the
    dumpable flag when a process's credentials change). It is a same-user barrier: it does not stop
    administrators, root, SYSTEM, a process with CAP_SYS_PTRACE or SeDebugPrivilege, or the kernel,
    and it does not keep memory out of swap, the page file or hibernation files; those are host
    settings.
    """

    @staticmethod
    def apply(options: ProcessHardeningOptions | int = ProcessHardeningOptions.NONE, *,
              _library: AbstractHkdfGuardKmsLibrary | None = None) -> None:
        """Applies the hardening with ``options``, loading the native KMS library if it isn't already.

        :param options: :attr:`ProcessHardeningOptions.NONE` (the default), or
            :attr:`ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE`
        :param _library: for this package's tests only, not public API - the binding to call instead of this platform's
        :raises TypeError: ``options`` is not an int or :class:`ProcessHardeningOptions`
        :raises ValueError: ``options`` has a flag this library doesn't define - refused before the
            native call
        :raises RuntimeError: the hardening failed, or the process can't meet
            :attr:`ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE`; treat it as a reason not to start
        :raises NativeLibraryNotFoundError: the native KMS library is not installed
        :raises NotImplementedError: there is no native KMS library for this platform
        """
        if isinstance(options, bool) or not isinstance(options, int):
            raise TypeError("options must be a ProcessHardeningOptions.")
        # Checked here so an unknown flag never reaches native code, which would refuse it anyway.
        value = int(options)
        if value & ~int(ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE):
            raise ValueError(f"Unknown process hardening option: {value}.")

        flags = AbstractHkdfGuardKmsLibrary.HARDEN_REQUIRE_PROTECTED_SIGNATURE if value & ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE else 0
        native = _library if _library is not None else native_library()
        status = native.harden_process(flags)
        if status == OK:
            return

        description = native.describe_status(status)
        meaning = f" ({description})" if description else ""
        raise RuntimeError(f"Native process hardening failed with status {status}{meaning}.")
