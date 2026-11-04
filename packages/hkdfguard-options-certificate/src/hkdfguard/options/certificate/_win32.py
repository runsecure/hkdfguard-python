"""The Win32 calls the certificate loader makes beyond the store's own, through ctypes: the
account's SID, and a directory only it can open. kernel32 is a KnownDLL; every other system library
is loaded by its absolute System32 path, so nothing can be planted in the application directory or
on PATH. Everything is bound on first use, so importing this module is safe off Windows."""

from __future__ import annotations

import ctypes
import functools
import os
from ctypes import POINTER, Structure, byref, c_uint32, c_void_p, c_wchar_p
from typing import Any, Final

LOAD_LIBRARY_SEARCH_SYSTEM32: Final = 0x800
_TOKEN_QUERY: Final = 0x0008
_TOKEN_USER: Final = 1
_SDDL_REVISION_1: Final = 1


@functools.cache
def kernel32() -> Any:
    return ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]


@functools.cache
def _system_directory() -> str:
    buffer = ctypes.create_unicode_buffer(1024)
    function = kernel32().GetSystemDirectoryW
    function.argtypes = [c_wchar_p, c_uint32]
    function.restype = c_uint32
    length = function(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise OSError("GetSystemDirectoryW failed.")
    return buffer.value


@functools.cache
def system32(file_name: str) -> Any:
    """A System32 library, its own dependencies resolved from System32 only."""
    return ctypes.WinDLL(os.path.join(_system_directory(), file_name), use_last_error=True,  # type: ignore[attr-defined,unused-ignore]
                         winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)


def last_error() -> int:
    return int(ctypes.get_last_error())  # type: ignore[attr-defined,unused-ignore]


def _local_free(pointer: int | None) -> None:
    if pointer:
        function = kernel32().LocalFree
        function.argtypes = [c_void_p]
        function.restype = c_void_p
        function(pointer)


@functools.cache
def current_user_sid() -> str:
    """The SID of the account the process runs as, from its token - never from the environment."""
    advapi32 = system32("advapi32.dll")
    advapi32.OpenProcessToken.argtypes = [c_void_p, c_uint32, POINTER(c_void_p)]
    advapi32.OpenProcessToken.restype = ctypes.c_int
    advapi32.GetTokenInformation.argtypes = [c_void_p, c_uint32, c_void_p, c_uint32, POINTER(c_uint32)]
    advapi32.GetTokenInformation.restype = ctypes.c_int
    advapi32.ConvertSidToStringSidW.argtypes = [c_void_p, POINTER(c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
    get_process = kernel32().GetCurrentProcess
    get_process.restype = c_void_p
    close_handle = kernel32().CloseHandle
    close_handle.argtypes = [c_void_p]

    token = c_void_p()
    if not advapi32.OpenProcessToken(get_process(), _TOKEN_QUERY, byref(token)):
        raise OSError(f"OpenProcessToken failed with error {last_error()}.")
    try:
        size = c_uint32()
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, size, byref(size)):
            raise OSError(f"GetTokenInformation(TokenUser) failed with error {last_error()}.")
        sid = c_void_p.from_buffer(buffer).value  # TOKEN_USER starts with SID_AND_ATTRIBUTES, its Sid first
        text = c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid, byref(text)):
            raise OSError(f"ConvertSidToStringSidW failed with error {last_error()}.")
        try:
            return str(ctypes.wstring_at(text.value))  # type: ignore[arg-type]
        finally:
            _local_free(text.value)
    finally:
        close_handle(token)


class _SecurityAttributes(Structure):
    _fields_ = [("nLength", c_uint32), ("lpSecurityDescriptor", c_void_p), ("bInheritHandle", ctypes.c_int)]


def create_private_directory(path: str) -> None:
    """Creates ``path`` with a protected DACL granting the current account alone full control, which
    every file made in it inherits - not the inherited DACL of the temporary folder above it.

    :raises FileExistsError: ``path`` exists
    """
    advapi32 = system32("advapi32.dll")
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [c_wchar_p, c_uint32, POINTER(c_void_p), c_void_p]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    create = kernel32().CreateDirectoryW
    create.argtypes = [c_wchar_p, POINTER(_SecurityAttributes)]
    create.restype = ctypes.c_int

    sddl = f"O:{current_user_sid()}D:P(A;OICI;FA;;;{current_user_sid()})"
    descriptor = c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, _SDDL_REVISION_1, byref(descriptor), None):
        raise OSError(f"ConvertStringSecurityDescriptorToSecurityDescriptorW failed with error {last_error()}.")
    try:
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor.value, 0)
        if not create(path, byref(attributes)):
            error = last_error()
            if error == 183:  # ERROR_ALREADY_EXISTS
                raise FileExistsError(path)
            raise OSError(f"CreateDirectoryW('{path}') failed with error {error}.")
    finally:
        _local_free(descriptor.value)
