"""The Win32 calls TrustedKeyFile makes on Windows, through ctypes: the full and long form of a path
(GetFullPathNameW, GetLongPathNameW), the drive type, opening and reading the file with read sharing
only (CreateFileW, ReadFile), the opened handle's final path (GetFinalPathNameByHandleW: the file it
actually refers to, after every symbolic link, junction, mount point and substituted drive has been
resolved, in long-name form), file attributes, and the owner and DACL of the opened handle
(GetSecurityInfo) and of a folder by path (GetNamedSecurityInfoW).

kernel32 is a KnownDLL, always mapped from System32; advapi32 is loaded by its absolute System32 path
with its dependencies resolved from System32 only, never the application directory or PATH. These
are this package's own bindings - it doesn't depend on hkdfguard-keywrapping-v1 - and every function
is given explicit argument and result types. Everything is bound on first use, so importing this
module is safe off Windows. 64-bit Windows only.
"""

from __future__ import annotations

import ctypes
import functools
import os
from ctypes import POINTER, Structure, byref, c_int, c_ubyte, c_uint16, c_uint32, c_void_p, c_wchar_p
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Final, Self

INVALID_FILE_ATTRIBUTES: Final = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x400

ACCESS_ALLOWED_ACE_TYPE: Final = 0x00
ACCESS_DENIED_ACE_TYPE: Final = 0x01
ACCESS_DENIED_OBJECT_ACE_TYPE: Final = 0x06
ACCESS_ALLOWED_CALLBACK_ACE_TYPE: Final = 0x09
ACCESS_DENIED_CALLBACK_ACE_TYPE: Final = 0x0A
ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: Final = 0x0C
INHERIT_ONLY_ACE: Final = 0x08

_GENERIC_READ: Final = 0x80000000
_FILE_SHARE_READ: Final = 0x1
_OPEN_EXISTING: Final = 3
_FILE_ATTRIBUTE_NORMAL: Final = 0x80
_FILE_FLAG_SEQUENTIAL_SCAN: Final = 0x08000000
_FINAL_PATH_FLAGS: Final = 0  # FILE_NAME_NORMALIZED | VOLUME_NAME_DOS

_SE_FILE_OBJECT: Final = 1
_OWNER_SECURITY_INFORMATION: Final = 0x1
_DACL_SECURITY_INFORMATION: Final = 0x4
_SDDL_REVISION_1: Final = 1
LOAD_LIBRARY_SEARCH_SYSTEM32: Final = 0x800

_ERROR_FILE_NOT_FOUND: Final = 2
_ERROR_PATH_NOT_FOUND: Final = 3
_ERROR_ACCESS_DENIED: Final = 5
_ERROR_SHARING_VIOLATION: Final = 32

_MAX_PATH_CHARS: Final = 32768
"""The longest path Windows supports, plus its terminator."""


def _last_error() -> int:
    return int(ctypes.get_last_error())  # type: ignore[attr-defined,unused-ignore]


@functools.cache
def _kernel32() -> Any:
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.GetSystemDirectoryW.argtypes = [c_wchar_p, c_uint32]
    kernel32.GetSystemDirectoryW.restype = c_uint32
    kernel32.GetFullPathNameW.argtypes = [c_wchar_p, c_uint32, c_wchar_p, c_void_p]
    kernel32.GetFullPathNameW.restype = c_uint32
    kernel32.GetLongPathNameW.argtypes = [c_wchar_p, c_wchar_p, c_uint32]
    kernel32.GetLongPathNameW.restype = c_uint32
    kernel32.GetDriveTypeW.argtypes = [c_wchar_p]
    kernel32.GetDriveTypeW.restype = c_uint32
    kernel32.GetFileAttributesW.argtypes = [c_wchar_p]
    kernel32.GetFileAttributesW.restype = c_uint32
    kernel32.CreateFileW.argtypes = [c_wchar_p, c_uint32, c_uint32, c_void_p, c_uint32, c_uint32, c_void_p]
    kernel32.CreateFileW.restype = c_void_p
    kernel32.ReadFile.argtypes = [c_void_p, c_void_p, c_uint32, POINTER(c_uint32), c_void_p]
    kernel32.ReadFile.restype = c_int
    kernel32.CloseHandle.argtypes = [c_void_p]
    kernel32.CloseHandle.restype = c_int
    kernel32.GetFinalPathNameByHandleW.argtypes = [c_void_p, c_wchar_p, c_uint32, c_uint32]
    kernel32.GetFinalPathNameByHandleW.restype = c_uint32
    kernel32.LocalFree.argtypes = [c_void_p]
    kernel32.LocalFree.restype = c_void_p
    return kernel32


@functools.cache
def _system_directory() -> str:
    buffer = ctypes.create_unicode_buffer(1024)
    length = _kernel32().GetSystemDirectoryW(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise OSError("GetSystemDirectoryW failed.")
    return buffer.value


@functools.cache
def _advapi32() -> Any:
    # Its dependencies resolve from System32 only, never the application directory or PATH.
    advapi32 = ctypes.WinDLL(os.path.join(_system_directory(), "advapi32.dll"), use_last_error=True,  # type: ignore[attr-defined,unused-ignore]
                             winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)
    advapi32.GetSecurityInfo.argtypes = [c_void_p, c_uint32, c_uint32, POINTER(c_void_p), POINTER(c_void_p), POINTER(c_void_p),
                                         POINTER(c_void_p), POINTER(c_void_p)]
    advapi32.GetSecurityInfo.restype = c_uint32
    advapi32.GetNamedSecurityInfoW.argtypes = [c_wchar_p, c_uint32, c_uint32, POINTER(c_void_p), POINTER(c_void_p), POINTER(c_void_p),
                                               POINTER(c_void_p), POINTER(c_void_p)]
    advapi32.GetNamedSecurityInfoW.restype = c_uint32
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [c_wchar_p, c_uint32, POINTER(c_void_p), c_void_p]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = c_int
    advapi32.GetSecurityDescriptorOwner.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_int)]
    advapi32.GetSecurityDescriptorOwner.restype = c_int
    advapi32.GetSecurityDescriptorDacl.argtypes = [c_void_p, POINTER(c_int), POINTER(c_void_p), POINTER(c_int)]
    advapi32.GetSecurityDescriptorDacl.restype = c_int
    advapi32.GetAce.argtypes = [c_void_p, c_uint32, POINTER(c_void_p)]
    advapi32.GetAce.restype = c_int
    advapi32.ConvertSidToStringSidW.argtypes = [c_void_p, POINTER(c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = c_int
    advapi32.ConvertStringSidToSidW.argtypes = [c_wchar_p, POINTER(c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = c_int
    advapi32.LookupAccountSidW.argtypes = [c_wchar_p, c_void_p, c_wchar_p, POINTER(c_uint32), c_wchar_p, POINTER(c_uint32), POINTER(c_uint32)]
    advapi32.LookupAccountSidW.restype = c_int
    return advapi32


def _local_free(pointer: int | None) -> None:
    if pointer:
        _kernel32().LocalFree(pointer)


# --- Paths ---------------------------------------------------------------------------------------


def full_path(path: str) -> str:
    """What .NET's Path.GetFullPath returns: GetFullPathNameW's absolute, normalized form (a relative
    path resolved against the working directory), with every 8.3 short name that exists on disk
    expanded to its long name. A short name for something that doesn't exist stays short, and the
    final-path check then refuses it.

    :raises OSError: the path can't be made absolute
    """
    buffer = ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
    length = _kernel32().GetFullPathNameW(path, _MAX_PATH_CHARS, buffer, None)
    if length <= 0 or length >= _MAX_PATH_CHARS:
        raise OSError(f"Could not make '{path}' an absolute path (error {_last_error()}).")
    full = buffer.value
    return full if "~" not in full else _expand_short_names(full)


def _expand_short_names(full: str) -> str:
    """Expands the longest leading part of ``full`` that exists, as .NET does: GetLongPathNameW fails
    outright for a path whose last component is missing."""
    prefix = full
    rest = ""
    while True:
        expanded = _long_path_name(prefix)
        if expanded is not None:
            return expanded + rest

        separator = prefix.rfind("\\")
        # Stop at the root ("C:\" or "\\server\share\"): nothing left to expand.
        if separator <= 2:
            return full
        rest = prefix[separator:] + rest
        prefix = prefix[:separator]


def _long_path_name(path: str) -> str | None:
    buffer = ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
    length = _kernel32().GetLongPathNameW(path, buffer, _MAX_PATH_CHARS)
    return None if length <= 0 or length >= _MAX_PATH_CHARS else buffer.value


def drive_type(root: str) -> int:
    """GetDriveTypeW of a drive root such as ``"C:\\"``: a DRIVE_* value."""
    return int(_kernel32().GetDriveTypeW(root))


def file_attributes(path: str) -> int:
    """GetFileAttributesW: the item's own attributes (a link is not followed), or
    :data:`INVALID_FILE_ATTRIBUTES` - which has every bit set, the reparse-point bit included."""
    return int(_kernel32().GetFileAttributesW(path))


# --- The opened file -----------------------------------------------------------------------------


def open_file(path: str) -> OpenFile:
    """Opens a file for reading with read sharing only: refused if another process has it open for
    writing, and no one can open it for writing while it is held.

    :raises FileNotFoundError: the file, or a folder in its path, doesn't exist
    :raises PermissionError: this account may not read it (or it is a folder)
    :raises OSError: another process has it open for writing, or it can't be opened
    """
    handle = _kernel32().CreateFileW(path, _GENERIC_READ, _FILE_SHARE_READ, None, _OPEN_EXISTING,
                                     _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_SEQUENTIAL_SCAN, None)
    error = _last_error()
    # INVALID_HANDLE_VALUE is -1: all bits set in a pointer-sized value.
    if handle is not None and handle != c_void_p(-1).value:
        return OpenFile(handle)

    if error in (_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND):
        raise FileNotFoundError(f"Key file '{path}' was not found.")
    if error == _ERROR_ACCESS_DENIED:
        raise PermissionError(f"This account may not read key file '{path}'.")
    if error == _ERROR_SHARING_VIOLATION:
        raise OSError(f"Key file '{path}' is open for writing by another process.")
    raise OSError(f"Could not open key file '{path}' (error {error}).")


class OpenFile:
    """A file opened by :func:`open_file`; closing it (or leaving its ``with`` block) closes the handle."""

    def __init__(self, handle: int) -> None:
        self._handle: int | None = handle

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def _open_handle(self) -> int:
        if self._handle is None:
            raise ValueError("The key file has been closed.")
        return self._handle

    def final_path(self) -> str:
        """GetFinalPathNameByHandleW: the path of the file this handle actually refers to.

        :raises OSError: the path could not be read from the handle
        """
        capacity = 512
        while True:
            buffer = ctypes.create_unicode_buffer(capacity)
            length = _kernel32().GetFinalPathNameByHandleW(self._open_handle(), buffer, capacity, _FINAL_PATH_FLAGS)
            if length == 0:
                raise OSError(f"Could not read the opened key file's final path (error {_last_error()}).")
            if length < capacity:
                return buffer.value
            # Too small: length is the size needed, terminator included.
            capacity = length

    def security_descriptor(self) -> SecurityDescriptorInfo:
        """The file's owner and DACL, read through this handle.

        :raises OSError: the descriptor could not be read
        """
        descriptor = c_void_p()
        error = _advapi32().GetSecurityInfo(self._open_handle(), _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                                            None, None, None, None, byref(descriptor))
        if error != 0:
            raise OSError(f"Could not read the opened key file's security descriptor (error {error}).")
        try:
            return _parse(descriptor.value)
        finally:
            _local_free(descriptor.value)

    def readinto(self, destination: memoryview) -> int:
        """ReadFile: up to ``len(destination)`` bytes, straight into ``destination`` - no intermediate
        copy is made.

        :returns: the number of bytes read; 0 at the end of the file
        :raises OSError: the read failed
        """
        if len(destination) == 0:
            return 0
        target = (ctypes.c_char * len(destination)).from_buffer(destination)
        count = c_uint32()
        try:
            if not _kernel32().ReadFile(self._open_handle(), target, len(destination), byref(count), None):
                raise OSError(f"Could not read the key file (error {_last_error()}).")
            return count.value
        finally:
            # Releases the buffer export, so the caller's buffer can be zeroed or freed.
            del target

    def close(self) -> None:
        """Closes the handle. Safe to call more than once."""
        if self._handle is not None:
            handle, self._handle = self._handle, None
            _kernel32().CloseHandle(handle)


# --- Security descriptors ------------------------------------------------------------------------


@dataclass(frozen=True)
class Ace:
    """One ACE: its type, flags (inheritance), the access mask it allows or denies, and its trustee's
    SID string - ``None`` for an ACE type with no plain SID."""

    type: int
    flags: int
    mask: int
    sid: str | None


@dataclass(frozen=True)
class SecurityDescriptorInfo:
    """An item's owner and DACL. ``owner_sid`` is ``None`` if the descriptor has no owner;
    ``grants_everyone_full`` is true when there is no DACL (or a NULL one), which grants every user full
    control."""

    owner_sid: str | None
    grants_everyone_full: bool
    aces: tuple[Ace, ...]


class _AceHeader(Structure):
    _fields_ = [("type", c_ubyte), ("flags", c_ubyte), ("size", c_uint16)]


class _AllowOrDenyAce(Structure):
    _fields_ = [("header", _AceHeader), ("mask", c_uint32), ("sid_start", c_uint32)]


def security_descriptor_of(path: str) -> SecurityDescriptorInfo:
    """The owner and DACL of a file or folder, by path.

    :raises PermissionError: this account may not read them
    :raises OSError: they could not be read
    """
    descriptor = c_void_p()
    error = _advapi32().GetNamedSecurityInfoW(path, _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                                              None, None, None, None, byref(descriptor))
    if error == _ERROR_ACCESS_DENIED:
        raise PermissionError(f"This account may not read the permissions of '{path}'.")
    if error != 0:
        raise OSError(f"Could not read the security descriptor of '{path}' (error {error}).")
    try:
        return _parse(descriptor.value)
    finally:
        _local_free(descriptor.value)


def security_descriptor_from_sddl(sddl: str) -> SecurityDescriptorInfo:
    """A security descriptor written in SDDL - for testing the policy against descriptors a real file
    would be hard to give.

    :raises ValueError: the SDDL is invalid
    """
    descriptor = c_void_p()
    if not _advapi32().ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, _SDDL_REVISION_1, byref(descriptor), None):
        raise ValueError(f"Invalid SDDL (error {_last_error()}): {sddl}")
    try:
        return _parse(descriptor.value)
    finally:
        _local_free(descriptor.value)


def _parse(descriptor: int | None) -> SecurityDescriptorInfo:
    advapi32 = _advapi32()
    owner = c_void_p()
    defaulted = c_int()
    if not advapi32.GetSecurityDescriptorOwner(descriptor, byref(owner), byref(defaulted)):
        raise OSError("Could not read a security descriptor's owner.")
    owner_sid = _sid_to_string(owner.value) if owner.value else None

    present = c_int()
    dacl = c_void_p()
    if not advapi32.GetSecurityDescriptorDacl(descriptor, byref(present), byref(dacl), byref(defaulted)):
        raise OSError("Could not read a security descriptor's DACL.")
    if not present.value or not dacl.value:
        return SecurityDescriptorInfo(owner_sid, True, ())

    # ACL header: AclRevision u8, Sbz1 u8, AclSize u16, AceCount u16 @4, Sbz2 u16.
    ace_count = c_uint16.from_address(dacl.value + 4).value
    aces = []
    for index in range(ace_count):
        pointer = c_void_p()
        if not advapi32.GetAce(dacl, index, byref(pointer)) or pointer.value is None:
            raise OSError(f"Could not read ACE {index} of a DACL.")
        # ACE_HEADER, then - for the plain allow/deny types and their callback forms - Mask u32 @4
        # and the SID @8. Every other type (the object ACEs) has no SID there.
        ace = _AllowOrDenyAce.from_address(pointer.value)
        plain_sid = ace.header.type in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
                                        ACCESS_DENIED_CALLBACK_ACE_TYPE)
        sid = _sid_to_string(pointer.value + _AllowOrDenyAce.sid_start.offset) if plain_sid else None
        aces.append(Ace(ace.header.type, ace.header.flags, ace.mask, sid))
    return SecurityDescriptorInfo(owner_sid, False, tuple(aces))


def _sid_to_string(sid: int) -> str:
    text = c_void_p()
    if not _advapi32().ConvertSidToStringSidW(sid, byref(text)) or text.value is None:
        raise OSError("Could not read a SID.")
    try:
        return ctypes.wstring_at(text.value)
    finally:
        _local_free(text.value)


def canonical_sid(sid: str) -> str | None:
    """A SID string in its canonical form (``"S-1-5-32-544"``), as ConvertStringSidToSidW reads it -
    which also accepts the SDDL aliases, such as ``"BA"`` - or ``None`` if it isn't a SID."""
    binary = c_void_p()
    if not _advapi32().ConvertStringSidToSidW(sid, byref(binary)) or binary.value is None:
        return None
    try:
        return _sid_to_string(binary.value)
    finally:
        _local_free(binary.value)


def account_name(sid: str) -> str | None:
    """The account a SID string maps to, as DOMAIN\\name - or ``None`` if it maps to none here."""
    advapi32 = _advapi32()
    binary = c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, byref(binary)):
        return None
    try:
        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        name_length = c_uint32(256)
        domain_length = c_uint32(256)
        use = c_uint32()
        if not advapi32.LookupAccountSidW(None, binary, name, byref(name_length), domain, byref(domain_length), byref(use)):
            return None
        return f"{domain.value}\\{name.value}" if domain.value else name.value
    finally:
        _local_free(binary.value)
