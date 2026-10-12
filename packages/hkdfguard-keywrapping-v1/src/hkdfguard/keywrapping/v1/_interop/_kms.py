"""The shared surface over every platform's native KMS library, and the ctypes calls into it."""

from __future__ import annotations

import ctypes
import platform
import threading
from abc import ABC, abstractmethod
from collections.abc import Buffer, Callable
from enum import Enum
from typing import Any, Final, NamedTuple

from hkdfguard.abstractions import WritableBuffer

DEK_LENGTH: Final = 32
OK: Final = 0
"""Status common to every platform's native library: the call succeeded."""


class NativeLibraryNotFoundError(OSError):
    """The platform's native HkdfGuard KMS library is not installed where it is loaded from. The
    message names the location(s); the library is never searched for anywhere else."""


class KmsResult(NamedTuple):
    """What one native KMS call returned: :data:`OK` or a negative, platform-specific status, and
    the bytes written - or, on a buffer-too-small failure, the capacity required."""

    status: int
    bytes_written: int


class CpuArchitecture(Enum):
    X64 = "X64"
    X86 = "X86"
    ARM64 = "ARM64"
    ARM = "ARM"
    OTHER = "OTHER"

    @staticmethod
    def current() -> CpuArchitecture:
        """This interpreter's architecture - X64 under Rosetta or x64 emulation, even on an ARM machine."""
        machine = platform.machine().lower()
        if machine in ("amd64", "x86_64"):
            return CpuArchitecture.X64 if ctypes.sizeof(ctypes.c_void_p) == 8 else CpuArchitecture.X86
        if machine in ("arm64", "aarch64"):
            return CpuArchitecture.ARM64 if ctypes.sizeof(ctypes.c_void_p) == 8 else CpuArchitecture.ARM
        if machine in ("x86", "i386", "i486", "i586", "i686"):
            return CpuArchitecture.X86
        if machine.startswith("arm"):
            return CpuArchitecture.ARM
        return CpuArchitecture.OTHER


class AbstractHkdfGuardKmsLibrary(ABC):
    """A platform's native HkdfGuard KMS library: wraps and unwraps a fixed-length DEK under a
    persistent, per-service KEK held outside this process (a TPM2 key, a Secure Enclave key, ...)
    via hkdfguard_wrap_dek / hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek - identical in
    shape across platforms, but each library's negative status codes mean different things."""

    def describe_status(self, status: int) -> str | None:
        """What a non-OK status means on this platform, or ``None`` when the code is unknown."""
        return None

    @abstractmethod
    def wrap_dek(self, service: str, dek: Buffer, destination: WritableBuffer) -> KmsResult:
        """Wraps ``dek`` (exactly :data:`DEK_LENGTH` bytes) under the KEK identified by ``service``."""

    @abstractmethod
    def unwrap_dek(self, service: str, wrapped: Buffer, destination: WritableBuffer) -> KmsResult:
        """Unwraps a payload from :meth:`wrap_dek` for the same ``service``."""

    @abstractmethod
    def generate_and_wrap_dek(self, service: str, destination: WritableBuffer) -> KmsResult:
        """Generates a fresh DEK and wraps it under ``service``'s KEK; the plaintext never crosses."""


class KmsFunctions:
    """The three native functions, bound through ctypes - identical on every platform::

        int hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int dek_len, uint8_t* out, int* out_len);
        int hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int wrapped_len, uint8_t* out, int* out_len);
        int hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int* out_len);

    Input is copied into a ctypes buffer that is zeroed after the call; output is written straight
    into the caller's buffer, so this code makes no immutable copy of a revealed key.
    """

    def __init__(self, library: Any) -> None:
        self._wrap = self._bind(library, "hkdfguard_wrap_dek", with_input=True)
        self._unwrap = self._bind(library, "hkdfguard_unwrap_dek", with_input=True)
        self._generate = self._bind(library, "hkdfguard_generate_and_wrap_dek", with_input=False)

    @staticmethod
    def _bind(library: Any, name: str, *, with_input: bool) -> Callable[..., int]:
        try:
            function = getattr(library, name)
        except AttributeError:
            raise RuntimeError(f"The HkdfGuard native KMS library has no '{name}' export.") from None
        if with_input:
            function.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        else:
            function.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        function.restype = ctypes.c_int
        return function  # type: ignore[no-any-return]

    def wrap_dek(self, service: str, dek: Buffer, destination: WritableBuffer) -> KmsResult:
        return self._call(self._wrap, service, dek, destination)

    def unwrap_dek(self, service: str, wrapped: Buffer, destination: WritableBuffer) -> KmsResult:
        return self._call(self._unwrap, service, wrapped, destination)

    def generate_and_wrap_dek(self, service: str, destination: WritableBuffer) -> KmsResult:
        return self._call(self._generate, service, None, destination)

    @staticmethod
    def _call(function: Callable[..., int], service: str, data: Buffer | None, destination: WritableBuffer) -> KmsResult:
        output_view = memoryview(destination).cast("B")
        output = (ctypes.c_ubyte * len(output_view)).from_buffer(output_view) if len(output_view) else None
        output_length = ctypes.c_int(len(output_view))
        service_bytes = service.encode("utf-8")

        if data is None:
            status = function(service_bytes, output, ctypes.byref(output_length))
            return KmsResult(status, output_length.value)

        source = memoryview(data).cast("B")
        copy = (ctypes.c_ubyte * len(source)).from_buffer_copy(source) if len(source) else (ctypes.c_ubyte * 1)()
        try:
            status = function(service_bytes, copy, len(source), output, ctypes.byref(output_length))
            return KmsResult(status, output_length.value)
        finally:
            ctypes.memset(copy, 0, ctypes.sizeof(copy))


class NativeKmsLibrary(AbstractHkdfGuardKmsLibrary):
    """A binding that loads its platform's library and binds :class:`KmsFunctions` on first call. A
    failed bind (library missing, or refused by verification) isn't cached, so a fixed installation
    is picked up on the next call."""

    def __init__(self) -> None:
        self._functions: KmsFunctions | None = None
        self._lock = threading.Lock()

    @abstractmethod
    def _bind(self) -> KmsFunctions:
        """Loads (and verifies) the platform's library and binds its three functions."""

    def _bound(self) -> KmsFunctions:
        with self._lock:
            if self._functions is None:
                self._functions = self._bind()
            return self._functions

    def wrap_dek(self, service: str, dek: Buffer, destination: WritableBuffer) -> KmsResult:
        return self._bound().wrap_dek(service, dek, destination)

    def unwrap_dek(self, service: str, wrapped: Buffer, destination: WritableBuffer) -> KmsResult:
        return self._bound().unwrap_dek(service, wrapped, destination)

    def generate_and_wrap_dek(self, service: str, destination: WritableBuffer) -> KmsResult:
        return self._bound().generate_and_wrap_dek(service, destination)
