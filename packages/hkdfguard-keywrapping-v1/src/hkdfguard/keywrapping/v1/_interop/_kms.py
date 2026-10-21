"""The shared surface over every platform's native KMS library, and the ctypes calls into it."""

from __future__ import annotations

import ctypes
import os
import platform
import threading
from abc import ABC, abstractmethod
from collections.abc import Buffer, Callable
from enum import Enum
from typing import Any, Final, NamedTuple

from hkdfguard.abstractions import ArrayUtility, CryptographicError, InvalidKeyFileError, WrappedKeyLimits, WritableBuffer

DEK_LENGTH: Final = 32
OK: Final = 0
"""The call succeeded - the same on every platform, as is every status code (see
:class:`AbstractHkdfGuardKmsLibrary`)."""


class NativeLibraryNotFoundError(OSError):
    """The platform's native HkdfGuard KMS library is not installed where it is loaded from. The
    message names the location(s); the library is never searched for anywhere else."""


class KmsResult(NamedTuple):
    """What one native KMS call returned: :data:`OK` or a negative status, and the bytes written -
    or, on a buffer-too-small failure, the capacity required."""

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
    via hkdfguard_wrap_dek / hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek, and reads
    wrapped-key files through hkdfguard_open_file. The functions are identical in shape across
    platforms, and so are their status codes: the native header's HKDFGUARD_ERR_* table is shared
    number for number by the Windows, Linux and macOS libraries, so it lives here, once."""

    # Status codes, exactly as every platform's hkdfguard.h defines them (HKDFGUARD_OK and
    # HKDFGUARD_ERR_*). Each platform band refines one of the common codes above it.

    # General (-1..-7)
    ERR_INVALID_ARGUMENT: Final = -1
    ERR_BUFFER_TOO_SMALL: Final = -2
    ERR_PROVIDER_UNAVAILABLE: Final = -3
    ERR_PROVIDER_ERROR: Final = -4
    ERR_CRYPTO_ERROR: Final = -5
    ERR_INTERNAL_ERROR: Final = -6

    # Service name and policy (-8..-9)
    ERR_INVALID_SERVICE_NAME: Final = -8
    ERR_POLICY_INVALID: Final = -9

    # Wrapped payload (-10..-15)
    ERR_PAYLOAD_MALFORMED: Final = -10
    ERR_PAYLOAD_AUTH_FAILED: Final = -11
    ERR_PAYLOAD_UNSUPPORTED: Final = -12

    # KEK and process (-16..-31)
    ERR_KEK_FINGERPRINT_MISMATCH: Final = -16
    ERR_KEK_NOT_FOUND: Final = -17
    ERR_KEK_ACCESS_DENIED: Final = -18
    ERR_KEK_INVALID: Final = -19
    ERR_PROCESS_HARDENING_FAILED: Final = -20

    # Key file, hkdfguard_open_file (-32..-39)
    ERR_FILE_NOT_FOUND: Final = -32
    ERR_FILE_ACCESS_DENIED: Final = -33
    ERR_FILE_IO: Final = -34
    ERR_FILE_TOO_SHORT: Final = -35
    ERR_FILE_TOO_LONG: Final = -36
    ERR_FILE_PLAINTEXT_KEY: Final = -37
    ERR_FILE_MALFORMED: Final = -38
    ERR_FILE_UNTRUSTED: Final = -39

    # Windows-specific (-64..-79), refining ERR_POLICY_INVALID
    ERR_WIN_GROUP_INVALID: Final = -64

    # macOS-specific (-96..-111), each refining ERR_PROVIDER_ERROR
    ERR_MAC_ACCESS_CONTROL_CREATION_FAILED: Final = -96
    ERR_MAC_KEY_GENERATION_FAILED: Final = -97
    ERR_MAC_KEYCHAIN_WRITE_FAILED: Final = -98
    ERR_MAC_KEK_VERIFICATION_FAILED: Final = -99
    ERR_MAC_KEYCHAIN_READ_FAILED: Final = -100

    HARDEN_REQUIRE_PROTECTED_SIGNATURE: Final = 0x1
    """hkdfguard_harden_process_with_flags' HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: fail unless
    no other process of the same user can debug or inject into this one. Same bit on every platform."""

    _SHARED_DESCRIPTIONS: Final[dict[int, str]] = {
        ERR_INVALID_ARGUMENT: "invalid argument: a null pointer, wrong DEK length, negative buffer capacity, or bad path",
        ERR_BUFFER_TOO_SMALL: "the output buffer is too small for the result",
        ERR_PROVIDER_UNAVAILABLE: "no key storage provider could be used at all",
        ERR_PROVIDER_ERROR: "the KEK provider or key could not be opened or created",
        ERR_CRYPTO_ERROR: "an ECDH, HKDF, AES or random number operation failed",
        ERR_INTERNAL_ERROR: "an unexpected internal failure in the native library",
        ERR_INVALID_SERVICE_NAME: "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'",
        ERR_POLICY_INVALID: "the machine's HkdfGuard policy is invalid",
        ERR_PAYLOAD_MALFORMED: "the wrapped payload is not a valid WrappedDekV1",
        ERR_PAYLOAD_AUTH_FAILED: "AES-GCM authentication failed: the wrapped payload was altered",
        ERR_PAYLOAD_UNSUPPORTED: "the wrapped payload's version or suite is not one this native library understands",
        ERR_KEK_FINGERPRINT_MISMATCH: "the payload was wrapped under a different KEK than this service's current one",
        ERR_KEK_NOT_FOUND: "no KEK is provisioned for this service; run hkdfguard provision",
        ERR_KEK_ACCESS_DENIED: "the KEK exists, but this account is not authorized to use it",
        ERR_KEK_INVALID: "the existing KEK is unusable as found",
        ERR_PROCESS_HARDENING_FAILED: "process hardening failed",
        ERR_FILE_NOT_FOUND: "the key file, or a folder in its path, does not exist",
        ERR_FILE_ACCESS_DENIED: "this account may not read the key file",
        ERR_FILE_IO: "the key file is not a regular file, is in use by a writer, or could not be read",
        ERR_FILE_TOO_SHORT: "the key file is shorter than a wrapped DEK",
        ERR_FILE_TOO_LONG: "the key file is longer than a wrapped DEK",
        ERR_FILE_PLAINTEXT_KEY: "the key file holds what looks like an UNWRAPPED key (32 raw bytes, or its hex or base64): treat it as a key exposure",
        ERR_FILE_MALFORMED: "the key file is the right size, but is not a valid wrapped DEK",
        ERR_FILE_UNTRUSTED: "the key file's path is not trusted: a link or reparse point, a short or network path, or a file or folder another "
                            "account could replace",
        ERR_WIN_GROUP_INVALID: r"an HKLM\Software\Policies\HkdfGuard\KeyUseGroups entry is unresolvable, not a group, not host-local, or over-broad",
        ERR_MAC_ACCESS_CONTROL_CREATION_FAILED: "the access policy for a new KEK could not be created",
        ERR_MAC_KEY_GENERATION_FAILED: "the Secure Enclave refused to generate a key",
        ERR_MAC_KEYCHAIN_WRITE_FAILED: "the new KEK could not be stored in the keychain",
        ERR_MAC_KEK_VERIFICATION_FAILED: "the new KEK could not be reloaded after it was stored",
        ERR_MAC_KEYCHAIN_READ_FAILED: "the keychain could not be read",
    }

    def describe_status(self, status: int) -> str | None:
        """What a non-OK status means, for error messages - or ``None`` when the code is unknown. The
        meanings are shared by every platform; a platform's binding overrides this to add what to do
        about a code there (which group grants access to a KEK, where the policy lives) and falls back
        to this for the rest."""
        return AbstractHkdfGuardKmsLibrary._SHARED_DESCRIPTIONS.get(status)

    @abstractmethod
    def wrap_dek(self, service: str, dek: Buffer, destination: WritableBuffer) -> KmsResult:
        """Wraps ``dek`` (exactly :data:`DEK_LENGTH` bytes) under the KEK identified by ``service``."""

    @abstractmethod
    def unwrap_dek(self, service: str, wrapped: Buffer, destination: WritableBuffer) -> KmsResult:
        """Unwraps a payload from :meth:`wrap_dek` for the same ``service``."""

    @abstractmethod
    def generate_and_wrap_dek(self, service: str, destination: WritableBuffer) -> KmsResult:
        """Generates a fresh DEK and wraps it under ``service``'s KEK; the plaintext never crosses."""

    def open_file(self, path: str | os.PathLike[str]) -> bytes:
        """Reads a wrapped-key file through the native library's hkdfguard_open_file, which refuses a
        file whose path, owner or permissions mean someone else could have replaced it, and one that
        holds what looks like an unwrapped key - checks only the platform can make. The bytes come
        back still wrapped, ready for :meth:`unwrap_dek`; no KEK is touched.

        :param path: the key file's path, absolute or relative to the current directory
        :returns: the file's wrapped payload: exactly this platform's wrapped DEK length
        :raises TypeError: ``path`` is ``None`` or not a ``str`` path
        :raises ValueError: ``path`` is empty, holds a NUL, or can't be encoded as UTF-8 - refused
            before the native call - or the native library refused it as an invalid argument
        :raises FileNotFoundError: the file, or a folder in its path, does not exist
        :raises PermissionError: this account may not read the file, or its path is not trusted
        :raises InvalidKeyFileError: the file is the wrong size, holds what looks like an unwrapped
            key, or isn't a valid wrapped DEK (an ``OSError``)
        :raises OSError: the file could not be read for another reason
        """
        if path is None:
            raise TypeError("path must not be None.")
        text = os.fspath(path)
        if not isinstance(text, str):
            raise TypeError("path must be a str or os.PathLike[str].")
        if not text:
            raise ValueError("A key file path is required.")
        if "\0" in text:
            raise ValueError("A key file path can't contain a NUL character.")
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("A key file path must be encodable as UTF-8.") from None

        # Every platform's wrapped DEK fits in WrappedKeyLimits.MAX_BYTES (Windows 132, Linux 276,
        # macOS 125 bytes), so one buffer never needs the size probe.
        buffer = bytearray(WrappedKeyLimits.MAX_BYTES)
        status, read = self._open_file(text, buffer)
        if status == OK:
            # A count outside the buffer would slice the wrong bytes (a negative one counts from
            # the end), so a library reporting one is refused rather than trusted.
            if not 0 <= read <= len(buffer):
                ArrayUtility.zero_memory(buffer)
                raise CryptographicError(f"Native KMS open_file for '{text}' reported {read} bytes read into a "
                                         f"{len(buffer)}-byte buffer; the result was discarded.")
            return bytes(buffer[:read])

        message = (f"Key file '{text}' was refused by the native library with status {status} "
                   f"({self.describe_status(status) or 'unknown status'}).")
        if status == self.ERR_FILE_NOT_FOUND:
            raise FileNotFoundError(message)
        if status in (self.ERR_FILE_ACCESS_DENIED, self.ERR_FILE_UNTRUSTED):
            raise PermissionError(message)
        if status in (self.ERR_FILE_TOO_SHORT, self.ERR_FILE_TOO_LONG, self.ERR_FILE_PLAINTEXT_KEY, self.ERR_FILE_MALFORMED):
            raise InvalidKeyFileError(message)
        if status == self.ERR_INVALID_ARGUMENT:
            raise ValueError(message)
        raise OSError(message)

    @abstractmethod
    def _open_file(self, path: str, destination: WritableBuffer) -> KmsResult:
        """The raw hkdfguard_open_file call: reads ``path`` into ``destination`` without unwrapping
        it, returning the status and, on success, the number of bytes read."""

    @abstractmethod
    def harden_process(self, flags: int) -> int:
        """Makes this process's memory harder to recover, through hkdfguard_harden_process_with_flags -
        on every platform: no crash dumps of its memory, and no debugger attach or memory reads by
        other processes of the same user. What that takes differs per platform; see
        ``NativeProcessHardening``.

        :param flags: a bitwise OR of the HARDEN_* flags, or 0
        :returns: :data:`OK` on success, or a negative error code: :attr:`ERR_PROCESS_HARDENING_FAILED`,
            or :attr:`ERR_INVALID_ARGUMENT` for an unknown flag
        """


class KmsFunctions:
    """The native functions, bound through ctypes - identical on every platform::

        int hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int dek_len, uint8_t* out, int* out_len);
        int hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int wrapped_len, uint8_t* out, int* out_len);
        int hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int* out_len);
        int hkdfguard_open_file(const char* path, uint8_t* out, int* out_len);
        int hkdfguard_harden_process_with_flags(unsigned int flags);

    Input is copied into a ctypes buffer that is zeroed after the call; output is written straight
    into the caller's buffer, so this code makes no immutable copy of a revealed key.
    """

    def __init__(self, library: Any) -> None:
        self._wrap = self._bind(library, "hkdfguard_wrap_dek", with_input=True)
        self._unwrap = self._bind(library, "hkdfguard_unwrap_dek", with_input=True)
        self._generate = self._bind(library, "hkdfguard_generate_and_wrap_dek", with_input=False)
        self._open = self._bind(library, "hkdfguard_open_file", with_input=False)
        self._harden = self._bind(library, "hkdfguard_harden_process_with_flags", argtypes=[ctypes.c_uint])

    @staticmethod
    def _bind(library: Any, name: str, *, with_input: bool = False, argtypes: list[Any] | None = None) -> Callable[..., int]:
        try:
            function = getattr(library, name)
        except AttributeError:
            raise RuntimeError(f"The HkdfGuard native KMS library has no '{name}' export.") from None
        if argtypes is not None:
            function.argtypes = argtypes
        elif with_input:
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

    def open_file(self, path: str, destination: WritableBuffer) -> KmsResult:
        """``path`` travels as UTF-8, exactly as a service name does."""
        return self._call(self._open, path, None, destination)

    def harden_process(self, flags: int) -> int:
        return self._harden(ctypes.c_uint(flags))

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
        """Loads (and verifies) the platform's library and binds its functions."""

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

    def _open_file(self, path: str, destination: WritableBuffer) -> KmsResult:
        return self._bound().open_file(path, destination)

    def harden_process(self, flags: int) -> int:
        return self._bound().harden_process(flags)
