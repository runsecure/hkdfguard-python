"""Wraps and reveals DEKs under a KEK held by the platform's native HkdfGuard KMS library - a TPM or
Platform Crypto Provider key on Windows, a Secure Enclave key on macOS, the strongest available
provider on Linux - called through ctypes."""

from __future__ import annotations

import logging
import os
import sys
import threading
from collections.abc import Buffer, Callable

from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, ServiceNames, WritableBuffer
from hkdfguard.keywrapping.v1._interop._kms import OK, AbstractHkdfGuardKmsLibrary, KmsResult, NativeLibraryNotFoundError

__all__ = ["NativeHkdfKeyWrapperV1", "NativeLibraryNotFoundError"]

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

    def __init__(self, service_name: str, library: AbstractHkdfGuardKmsLibrary | None = None) -> None:
        """:param service_name: identifies the KEK: 1-128 ASCII letters, digits or '.', not starting
            with '.' and without ".." (see ServiceNames)
        :param library: tests only - the binding to call instead of this platform's
        :raises TypeError: ``service_name`` is ``None``
        :raises ValueError: ``service_name`` breaks a ServiceNames rule
        :raises NotImplementedError: there is no native KMS library for this platform
        """
        # Checked here, before the name can ever reach native code.
        ServiceNames.require_valid(service_name, "service_name")
        self._service_name = service_name
        self._library = library if library is not None else native_library()

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        return self._complete(lambda: self._library.wrap_dek(self._service_name, plaintext, result), "wrap")

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        try:
            return self._complete(lambda: self._library.unwrap_dek(self._service_name, wrapped, result), "unwrap")
        except BaseException:
            # Whatever a failed call left in the DEK buffer is erased.
            ArrayUtility.zero_memory(result)
            raise

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        return self._complete(lambda: self._library.generate_and_wrap_dek(self._service_name, result), "generate-and-wrap")

    def read_key_file(self, path: str | os.PathLike[str], *, verify_permissions: bool = True,
                      logger: logging.Logger | None = None) -> bytearray:
        """Reads a key file through the native library's hkdfguard_open_file rather than Python file
        I/O. Besides the size and format checks, the native library refuses a file another account
        could have written or replaced - its path, owner and permissions are checked the way only the
        platform can - and one holding what looks like an unwrapped key. The bytes come back still
        wrapped, ready for :meth:`unwrap`. The native checks can't be turned off, so
        ``verify_permissions`` and ``logger`` are ignored.

        :raises FileNotFoundError: the file, or a folder in its path, does not exist
        :raises PermissionError: this account may not read the file, or its path is not trusted
        :raises InvalidKeyFileError: the file is the wrong size, holds what looks like an unwrapped
            key, or isn't a valid wrapped DEK (an ``OSError``)
        :raises OSError: the file could not be read for another reason
        :raises ValueError: the path is empty, or the native library refused it as invalid
        """
        return bytearray(self._library.open_file(path))

    def _complete(self, call: Callable[[], KmsResult], operation: str) -> int:
        status, written = call()
        if status == OK:
            return written

        # Name the status's meaning when it is known - "-18" alone tells an operator nothing.
        description = self._library.describe_status(status)
        meaning = f" ({description})" if description else ""
        raise CryptographicError(f"Native KMS {operation} failed for service '{self._service_name}' with status {status}{meaning}.")
