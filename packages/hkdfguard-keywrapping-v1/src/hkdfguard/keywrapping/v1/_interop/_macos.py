"""The macOS native KMS binding, and the loader that verifies libhkdfguard.dylib before mapping it."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import stat
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from hkdfguard.keywrapping.v1._interop._kms import CpuArchitecture, KmsFunctions, NativeKmsLibrary, NativeLibraryNotFoundError
from hkdfguard.keywrapping.v1._interop._unix import UnixFileStatus, UnixFileType, probe


@dataclass(frozen=True)
class PathChoice:
    path: str
    is_system: bool


class MacOsNativeLibraryLoader:
    """Loads the macOS native KMS library from one of its two install locations and nowhere else.

    1. **Location.** The system install, :attr:`SYSTEM_DIRECTORY`, whenever it exists; the per-user
       install, ``~/.hkdfguard/v1``, only when there is no system install - and never as a fallback
       when the system install fails a check or merely can't be examined.
    2. **Path integrity.** No component from the file up to / may be a symbolic link, or writable by
       anyone but its owner - except the system directories above an install, which may also be
       writable by wheel or admin when root owns them. A system install is root-owned throughout; a
       user install root- or user-owned.
    3. **Code signature.** Valid, and satisfying :attr:`CODE_REQUIREMENT` - signed by the HkdfGuard team.
    4. **What dyld loaded.** Refuses if a DYLD_LIBRARY_PATH directory holds a :attr:`FILE_NAME`, and
       after dlopen asks dyld (dladdr) which file it mapped; anything else is unloaded and refused.

    Any failed check raises ``PermissionError``; there is no other fallback and no override.
    """

    FILE_NAME: Final = "libhkdfguard.dylib"
    REFUSED_DYLD_VARIABLES: Final = ("DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_VERSIONED_LIBRARY_PATH",
                                     "DYLD_VERSIONED_FRAMEWORK_PATH", "DYLD_IMAGE_SUFFIX")
    """The dyld variables whose presence alone refuses the load: each makes dyld inject code into this process,
    or load another file in place of a library it names - including the frameworks the HkdfGuard native library
    calls with every DEK. None is set on a production host."""
    SYSTEM_DIRECTORY: Final = "/Library/Application Support/HkdfGuard/v1"
    USER_DIRECTORY_UNDER_HOME: Final = ".hkdfguard/v1"
    TEAM_ID: Final = "MFW3T8R8J3"
    CODE_REQUIREMENT: Final = (
        'identifier "libhkdfguard" and anchor apple generic'
        " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"  # Developer ID CA
        " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"  # Developer ID Application leaf
        f' and certificate leaf[subject.OU] = "{TEAM_ID}"')
    MINIMUM_MAC_OS_MAJOR_VERSION: Final = 13
    PROBE_EXPORT: Final = "hkdfguard_wrap_dek"

    # wheel and admin may write to root-owned system directories - only these, above an install.
    _ADMINISTRATIVE_GROUPS: Final = frozenset({0, 80})
    _SHARED_SYSTEM_DIRECTORIES: Final = frozenset({"/", "/Library", "/Library/Application Support", "/Users"})

    _lock: ClassVar = threading.Lock()
    _library: ClassVar[Any] = None

    @classmethod
    def system_path(cls) -> str:
        return f"{cls.SYSTEM_DIRECTORY}/{cls.FILE_NAME}"

    @classmethod
    def user_path(cls, home_directory: str) -> str:
        return f"{home_directory.rstrip('/')}/{cls.USER_DIRECTORY_UNDER_HOME}/{cls.FILE_NAME}"

    @classmethod
    def load(cls) -> Any:
        """Verifies and loads the installed library once per process. A failure isn't cached.

        :raises NativeLibraryNotFoundError: installed at neither location
        :raises PermissionError: the file or its location failed verification
        """
        with cls._lock:
            if cls._library is not None:
                return cls._library

            cls.require_supported_platform(CpuArchitecture.current(), platform.mac_ver()[0])
            choice = cls.choose_path(probe, os.path.expanduser("~"))
            owners = [0] if choice.is_system else [0, os.geteuid()]  # type: ignore[attr-defined,unused-ignore]
            cls.verify_location(choice.path, UnixFileStatus.of, owners)
            cls.verify_signature(choice.path, _check_code_signature)
            cls.refuse_shadowing(os.environ.get, os.path.exists)

            library = ctypes.CDLL(choice.path, mode=os.RTLD_NOW | os.RTLD_LOCAL)  # type: ignore[attr-defined,unused-ignore]
            try:
                export = getattr(library, cls.PROBE_EXPORT, None)
                cls.verify_loaded_image(choice.path, _image_path(ctypes.cast(export, ctypes.c_void_p).value) if export else None)
            except BaseException:
                _dlclose(library._handle)
                raise
            cls._library = library
            return library

    @classmethod
    def require_supported_platform(cls, architecture: CpuArchitecture, os_version: str) -> None:
        """An arm64 process (the library is Apple silicon only) on macOS 13 or later.

        :raises OSError: either requirement is not met (an ``OSError`` with errno ENOTSUP)
        """
        if architecture is not CpuArchitecture.ARM64:
            hint = (" - an Intel Mac, or an x64 Python running under Rosetta; on Apple silicon, use an arm64 Python."
                    if architecture is CpuArchitecture.X64 else ".")
            raise OSError(errno.ENOTSUP, "The HkdfGuard native KMS library requires Apple silicon: an arm64 process on an arm64 Mac. "
                                         f"This process is {architecture.value}{hint}")

        major = int("".join(c for c in os_version.split(".", maxsplit=1)[0] if c.isdigit()) or 0)
        if major < cls.MINIMUM_MAC_OS_MAJOR_VERSION:
            raise OSError(errno.ENOTSUP, f"The HkdfGuard native KMS library requires macOS {cls.MINIMUM_MAC_OS_MAJOR_VERSION} or later; "
                                         f"this is macOS {os_version}.")

    @classmethod
    def choose_path(cls, probe: Callable[[str], int], home_directory: str) -> PathChoice:
        """The system install if it exists, otherwise the user install. ``probe`` returns lstat's
        errno for a path (0 if it exists), so "can't look" is never mistaken for "not there".

        :raises NativeLibraryNotFoundError: neither exists
        :raises PermissionError: an install location could not be examined
        """
        if cls._is_present(cls.system_path(), probe, "system-wide"):
            return PathChoice(cls.system_path(), True)

        user = cls.user_path(home_directory)
        # Only an absolute home: a relative one would resolve against the working directory.
        if home_directory.startswith("/") and cls._is_present(user, probe, "per-user"):
            return PathChoice(user, False)

        raise NativeLibraryNotFoundError(f"The HkdfGuard native KMS library is not installed. Install it at '{cls.system_path()}' "
                                         f"(system-wide) or '{user}' (this user); it is never loaded from anywhere else.")

    @staticmethod
    def _is_present(path: str, probe: Callable[[str], int], kind: str) -> bool:
        error = probe(path)
        if error == 0:
            return True
        if error in (errno.ENOENT, errno.ENOTDIR):
            return False
        raise PermissionError(f"Could not tell whether the {kind} HkdfGuard native library '{path}' exists (lstat failed with errno {error}); "
                              "refusing to guess or to fall back to another location.")

    @classmethod
    def refuse_shadowing(cls, get_environment_variable: Callable[[str], str | None], exists: Callable[[str], bool]) -> None:
        """Refuses before anything is loaded if one of :attr:`REFUSED_DYLD_VARIABLES` is set, or a
        DYLD_LIBRARY_PATH directory holds a :attr:`FILE_NAME`.

        A guard against a misconfigured environment, not against whoever controls it: dyld acts on these
        variables when the process starts, so code they injected has already run - and can hide - by the
        time this looks. Running the host with the Hardened Runtime, which makes dyld ignore them, is what
        keeps that code out."""
        for name in cls.REFUSED_DYLD_VARIABLES:
            if get_environment_variable(name):
                raise PermissionError(f"{name} is set, so dyld may inject code into this process or substitute a library the HkdfGuard "
                                      f"native library uses; refusing to load it. Unset {name}.")
        search_path = get_environment_variable("DYLD_LIBRARY_PATH")
        if not search_path:
            return
        for directory in filter(None, search_path.split(":")):
            candidate = f"{directory.rstrip('/')}/{cls.FILE_NAME}"
            if exists(candidate):
                raise PermissionError(f"'{candidate}' is on DYLD_LIBRARY_PATH and would be loaded in place of the verified HkdfGuard native "
                                      "library; refusing to load. Remove it from DYLD_LIBRARY_PATH.")

    @classmethod
    def verify_loaded_image(cls, expected_path: str, loaded_path: str | None) -> None:
        """The file dyld reports having loaded is the one that was verified."""
        if loaded_path is None:
            raise PermissionError(f"The library loaded for '{expected_path}' has no '{cls.PROBE_EXPORT}' export, or dyld cannot say where it "
                                  "came from; it is not the HkdfGuard native library and has been unloaded.")
        if loaded_path != expected_path:
            raise PermissionError(f"dyld loaded '{loaded_path}' in place of the verified '{expected_path}' (DYLD_LIBRARY_PATH, most likely); "
                                  "it has been unloaded and the HkdfGuard native library was not loaded.")

    @classmethod
    def verify_location(cls, path: str, get_status: Callable[[str], UnixFileStatus], trusted_owners: Collection[int]) -> None:
        """The file and every parent up to /: not a symbolic link, owned by a trusted owner, and not
        writable by anyone else."""
        file = get_status(path)
        if file.type is not UnixFileType.REGULAR_FILE:
            raise PermissionError(f"'{path}' is not a regular file (it is a {file.type.value}).")
        cls.verify_component(path, file, trusted_owners)

        directory = cls.parent_of(path)
        while directory is not None:
            status = get_status(directory)
            if status.type is not UnixFileType.DIRECTORY:
                raise PermissionError(f"'{directory}' is not a directory (it is a {status.type.value}); the library is only loaded through a "
                                      "real path.")
            cls.verify_component(directory, status, trusted_owners)
            directory = cls.parent_of(directory)

    @classmethod
    def verify_component(cls, path: str, status: UnixFileStatus, trusted_owners: Collection[int]) -> None:
        # Root owns the system directories above every install.
        if status.owner_id != 0 and status.owner_id not in trusted_owners:
            owners = "root" if len(trusted_owners) == 1 else "root or the current user"
            raise PermissionError(f"'{path}' is owned by uid {status.owner_id}; the HkdfGuard native library is only loaded from a location "
                                  f"owned by {owners}.")

        if status.mode & stat.S_IWOTH:
            raise PermissionError(f"'{path}' is writable by every user; the HkdfGuard native library is only loaded from a location only its "
                                  "owner can modify.")

        if status.mode & stat.S_IWGRP and not (status.owner_id == 0 and status.group_id in cls._ADMINISTRATIVE_GROUPS
                                               and path in cls._SHARED_SYSTEM_DIRECTORIES):
            raise PermissionError(f"'{path}' is writable by group {status.group_id}; the HkdfGuard native library is only loaded from a location "
                                  "only its owner can modify (administrators may also write only to the system directories above an install: "
                                  f"{', '.join(sorted(cls._SHARED_SYSTEM_DIRECTORIES))}).")

    @classmethod
    def verify_signature(cls, path: str, check_signature: Callable[[str, str], int]) -> None:
        """``check_signature`` returns 0 (errSecSuccess) when the signature is valid and satisfies the
        requirement, else the OSStatus."""
        status = check_signature(path, cls.CODE_REQUIREMENT)
        if status != 0:
            raise PermissionError(f"'{path}' is not validly signed by the HkdfGuard team ({cls.TEAM_ID}); code signature check failed with "
                                  f"OSStatus {status}.")

    @staticmethod
    def parent_of(path: str) -> str | None:
        """macOS paths are '/'-separated whatever platform runs the tests; ``None`` above /."""
        if path == "/":
            return None
        slash = path.rstrip("/").rfind("/")
        return "/" if slash <= 0 else path[:slash]


# --- macOS system calls (bound on first use) ------------------------------------------------------

def _lib_system() -> Any:
    return ctypes.CDLL("/usr/lib/libSystem.B.dylib")


def _dlclose(handle: int) -> None:
    library = _lib_system()
    library.dlclose.argtypes = [ctypes.c_void_p]
    library.dlclose(handle)


class _DlInfo(ctypes.Structure):
    _fields_ = [("dli_fname", ctypes.c_char_p), ("dli_fbase", ctypes.c_void_p), ("dli_sname", ctypes.c_char_p),
                ("dli_saddr", ctypes.c_void_p)]


def _image_path(address: int | None) -> str | None:
    """dladdr: the file dyld actually mapped the code at ``address`` from."""
    library = _lib_system()
    library.dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(_DlInfo)]
    info = _DlInfo()
    if not address or not library.dladdr(address, ctypes.byref(info)) or not info.dli_fname:
        return None
    file_name: bytes = info.dli_fname
    return file_name.decode("utf-8")


def _check_code_signature(path: str, requirement_text: str) -> int:
    """SecStaticCodeCheckValidity against ``requirement_text``, for every architecture, strictly."""
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    void_p = ctypes.c_void_p
    core.CFURLCreateFromFileSystemRepresentation.argtypes = [void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_ubyte]
    core.CFURLCreateFromFileSystemRepresentation.restype = void_p
    core.CFStringCreateWithCString.argtypes = [void_p, ctypes.c_char_p, ctypes.c_uint32]
    core.CFStringCreateWithCString.restype = void_p
    core.CFRelease.argtypes = [void_p]
    security.SecStaticCodeCreateWithPath.argtypes = [void_p, ctypes.c_uint32, ctypes.POINTER(void_p)]
    security.SecRequirementCreateWithString.argtypes = [void_p, ctypes.c_uint32, ctypes.POINTER(void_p)]
    security.SecStaticCodeCheckValidity.argtypes = [void_p, ctypes.c_uint32, void_p]

    references: list[int] = []
    try:
        encoded = path.encode("utf-8")
        url = core.CFURLCreateFromFileSystemRepresentation(None, encoded, len(encoded), 0)
        if not url:
            return -1
        references.append(url)

        code = void_p()
        status = int(security.SecStaticCodeCreateWithPath(url, 0, ctypes.byref(code)))
        if code.value:
            references.append(code.value)
        if status != 0:
            return status

        text = core.CFStringCreateWithCString(None, requirement_text.encode("utf-8"), 0x08000100)  # kCFStringEncodingUTF8
        if not text:
            return -1
        references.append(text)

        requirement = void_p()
        status = int(security.SecRequirementCreateWithString(text, 0, ctypes.byref(requirement)))
        if requirement.value:
            references.append(requirement.value)
        if status != 0:
            return status

        return int(security.SecStaticCodeCheckValidity(code, 1 | (1 << 4), requirement))  # all architectures | strict
    finally:
        for reference in reversed(references):
            core.CFRelease(reference)


class MacOsHkdfGuardKmsLibrary(NativeKmsLibrary):
    """Binds libhkdfguard.dylib, which holds each service's KEK as its own Secure Enclave key,
    loaded only after the checks in :class:`MacOsNativeLibraryLoader`. No call creates a KEK: run
    ``hkdfguard provision --service-name <name>`` first."""

    _PLATFORM_DESCRIPTIONS: Final[dict[int, str]] = {
        NativeKmsLibrary.ERR_PROVIDER_UNAVAILABLE: "this Mac has no Secure Enclave",
        NativeKmsLibrary.ERR_PAYLOAD_AUTH_FAILED:
            "AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK",
        NativeKmsLibrary.ERR_KEK_NOT_FOUND: "no KEK is provisioned for this service in this keychain mode; run hkdfguard provision",
        NativeKmsLibrary.ERR_KEK_ACCESS_DENIED:
            "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed",
        NativeKmsLibrary.ERR_KEK_INVALID: "the keychain item for this service can't be reconstructed into a key",
        NativeKmsLibrary.ERR_PROCESS_HARDENING_FAILED:
            "process hardening failed: core dumps or debugger attachment could not be denied, or (with REQUIRE_PROTECTED_SIGNATURE) the host "
            "executable's code signature still allows it - it needs the Hardened Runtime, without get-task-allow or DYLD_* entitlements",
    }

    def describe_status(self, status: int) -> str | None:
        return self._PLATFORM_DESCRIPTIONS.get(status) or super().describe_status(status)

    def _bind(self) -> KmsFunctions:
        return KmsFunctions(MacOsNativeLibraryLoader.load())
