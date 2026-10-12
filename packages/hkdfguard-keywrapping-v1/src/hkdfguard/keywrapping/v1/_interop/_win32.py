"""The Win32 calls the Windows loader's checks rely on, through ctypes: known-folder lookup, file
attributes, security descriptors and SIDs, and WinVerifyTrust. kernel32 is a KnownDLL; every other
system library is loaded by its absolute System32 path, so nothing can be planted in the application
directory or on PATH. Everything is bound on first use, so importing this module is safe off Windows.
64-bit Windows only."""

from __future__ import annotations

import ctypes
import functools
import os
import uuid
from ctypes import POINTER, Structure, byref, c_ubyte, c_uint16, c_uint32, c_void_p, c_wchar_p
from dataclasses import dataclass
from typing import Any, Final

INVALID_FILE_ATTRIBUTES: Final = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x400

ACCESS_ALLOWED_ACE_TYPE: Final = 0x00
ACCESS_DENIED_ACE_TYPE: Final = 0x01
ACCESS_DENIED_OBJECT_ACE_TYPE: Final = 0x06
ACCESS_ALLOWED_CALLBACK_ACE_TYPE: Final = 0x09
ACCESS_DENIED_CALLBACK_ACE_TYPE: Final = 0x0A
ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: Final = 0x0C
INHERIT_ONLY_ACE: Final = 0x08

_SE_FILE_OBJECT: Final = 1
_OWNER_SECURITY_INFORMATION: Final = 0x1
_DACL_SECURITY_INFORMATION: Final = 0x4
_SDDL_REVISION_1: Final = 1
_KF_FLAG_DONT_VERIFY: Final = 0x4000
LOAD_LIBRARY_SEARCH_SYSTEM32: Final = 0x800


class _Guid(Structure):
    _fields_ = [("data1", c_uint32), ("data2", c_uint16), ("data3", c_uint16), ("data4", c_ubyte * 8)]

    @classmethod
    def of(cls, text: str) -> _Guid:
        value = uuid.UUID(text)
        return cls(value.time_low, value.time_mid, value.time_hi_version, (c_ubyte * 8)(*value.bytes[8:]))


@functools.cache
def _kernel32() -> Any:
    return ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]


@functools.cache
def system_directory() -> str:
    buffer = ctypes.create_unicode_buffer(1024)
    length = _kernel32().GetSystemDirectoryW(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise OSError("GetSystemDirectoryW failed.")
    return buffer.value


@functools.cache
def _system32(file_name: str) -> Any:
    return ctypes.WinDLL(os.path.join(system_directory(), file_name), use_last_error=True)  # type: ignore[attr-defined,unused-ignore]


def _local_free(pointer: int | None) -> None:
    if pointer:
        kernel32 = _kernel32()
        kernel32.LocalFree.argtypes = [c_void_p]
        kernel32.LocalFree.restype = c_void_p
        kernel32.LocalFree(pointer)


def program_files_directory() -> str:
    """The Program Files folder from the known-folder registry setting (only an administrator can
    change it), never from the ProgramFiles environment variable."""
    shell32 = _system32("shell32.dll")
    ole32 = _system32("ole32.dll")
    shell32.SHGetKnownFolderPath.argtypes = [POINTER(_Guid), c_uint32, c_void_p, POINTER(c_wchar_p)]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [c_void_p]

    folder_id = _Guid.of("905e63b6-c1bf-494e-b29c-65b732d3d21a")  # FOLDERID_ProgramFiles
    path = c_wchar_p()
    hresult = shell32.SHGetKnownFolderPath(byref(folder_id), _KF_FLAG_DONT_VERIFY, None, byref(path))
    try:
        if hresult != 0:
            raise OSError(f"SHGetKnownFolderPath(ProgramFiles) failed with HRESULT 0x{hresult & 0xFFFFFFFF:08X}.")
        return str(path.value)
    finally:
        ole32.CoTaskMemFree(ctypes.cast(path, c_void_p))


def file_attributes(path: str) -> int:
    """GetFileAttributesW: the item's own attributes (a link is not followed), or INVALID_FILE_ATTRIBUTES."""
    kernel32 = _kernel32()
    kernel32.GetFileAttributesW.argtypes = [c_wchar_p]
    kernel32.GetFileAttributesW.restype = c_uint32
    return int(kernel32.GetFileAttributesW(path))


# --- Security descriptors ----------------------------------------------------------------------


@dataclass(frozen=True)
class Ace:
    """One ACE: its type, flags, access mask, and trustee SID (``None`` for a type with no plain SID)."""

    type: int
    flags: int
    mask: int
    sid: str | None


@dataclass(frozen=True)
class SecurityDescriptorInfo:
    """An item's owner and DACL. ``grants_everyone_full`` is true when there is no DACL (or a NULL
    one), which grants every user full control."""

    owner_sid: str | None
    grants_everyone_full: bool
    aces: tuple[Ace, ...]


class _AceHeader(Structure):
    _fields_ = [("type", c_ubyte), ("flags", c_ubyte), ("size", c_uint16)]


class _AllowOrDenyAce(Structure):
    _fields_ = [("header", _AceHeader), ("mask", c_uint32), ("sid_start", c_uint32)]


def _advapi32() -> Any:
    advapi32 = _system32("advapi32.dll")
    advapi32.GetNamedSecurityInfoW.argtypes = [c_wchar_p, c_uint32, c_uint32, POINTER(c_void_p), POINTER(c_void_p), POINTER(c_void_p),
                                               POINTER(c_void_p), POINTER(c_void_p)]
    advapi32.GetNamedSecurityInfoW.restype = c_uint32
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [c_wchar_p, c_uint32, POINTER(c_void_p), c_void_p]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    advapi32.GetSecurityDescriptorOwner.argtypes = [c_void_p, POINTER(c_void_p), POINTER(ctypes.c_int)]
    advapi32.GetSecurityDescriptorDacl.argtypes = [c_void_p, POINTER(ctypes.c_int), POINTER(c_void_p), POINTER(ctypes.c_int)]
    advapi32.GetAce.argtypes = [c_void_p, c_uint32, POINTER(c_void_p)]
    advapi32.ConvertSidToStringSidW.argtypes = [c_void_p, POINTER(c_void_p)]
    advapi32.ConvertStringSidToSidW.argtypes = [c_wchar_p, POINTER(c_void_p)]
    advapi32.LookupAccountSidW.argtypes = [c_wchar_p, c_void_p, c_wchar_p, POINTER(c_uint32), c_wchar_p, POINTER(c_uint32),
                                           POINTER(c_uint32)]
    return advapi32


def security_descriptor_of(path: str) -> SecurityDescriptorInfo:
    """The owner and DACL of a file or directory, read without following a link.

    :raises PermissionError: the descriptor could not be read (callers treat this as a refusal)
    """
    advapi32 = _advapi32()
    descriptor = c_void_p()
    error = advapi32.GetNamedSecurityInfoW(path, _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                                           None, None, None, None, byref(descriptor))
    if error != 0:
        raise PermissionError(f"Could not read the security descriptor of '{path}' (error {error}).")
    try:
        return _parse(advapi32, descriptor.value)
    finally:
        _local_free(descriptor.value)


def security_descriptor_from_sddl(sddl: str) -> SecurityDescriptorInfo:
    """A security descriptor written in SDDL - for testing the policy against descriptors a real
    folder would be hard to give.

    :raises ValueError: the SDDL is invalid
    """
    advapi32 = _advapi32()
    descriptor = c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, _SDDL_REVISION_1, byref(descriptor), None):
        raise ValueError(f"Invalid SDDL (error {ctypes.get_last_error()}): {sddl}")  # type: ignore[attr-defined,unused-ignore]
    try:
        return _parse(advapi32, descriptor.value)
    finally:
        _local_free(descriptor.value)


def _parse(advapi32: Any, descriptor: int | None) -> SecurityDescriptorInfo:
    owner = c_void_p()
    defaulted = ctypes.c_int()
    if not advapi32.GetSecurityDescriptorOwner(descriptor, byref(owner), byref(defaulted)):
        raise PermissionError("Could not read a security descriptor's owner.")
    owner_sid = _sid_to_string(advapi32, owner.value) if owner.value else None

    present = ctypes.c_int()
    dacl = c_void_p()
    if not advapi32.GetSecurityDescriptorDacl(descriptor, byref(present), byref(dacl), byref(defaulted)):
        raise PermissionError("Could not read a security descriptor's DACL.")
    if not present.value or not dacl.value:
        return SecurityDescriptorInfo(owner_sid, True, ())

    # ACL header: AclRevision u8, Sbz1 u8, AclSize u16, AceCount u16 @4, Sbz2 u16.
    ace_count = c_uint16.from_address(dacl.value + 4).value
    aces = []
    for index in range(ace_count):
        pointer = c_void_p()
        if not advapi32.GetAce(dacl, index, byref(pointer)):
            raise PermissionError(f"Could not read ACE {index} of a DACL.")
        address = _address(pointer)
        ace = _AllowOrDenyAce.from_address(address)
        plain_sid = ace.header.type in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
                                        ACCESS_DENIED_CALLBACK_ACE_TYPE)
        sid = _sid_to_string(advapi32, address + _AllowOrDenyAce.sid_start.offset) if plain_sid else None
        aces.append(Ace(ace.header.type, ace.header.flags, ace.mask, sid))
    return SecurityDescriptorInfo(owner_sid, False, tuple(aces))


def _address(pointer: c_void_p) -> int:
    """A pointer a successful call filled in; never NULL, or the call would have failed."""
    if pointer.value is None:
        raise PermissionError("A security call returned a NULL pointer.")
    return pointer.value


def _sid_to_string(advapi32: Any, sid: int | None) -> str:
    text = c_void_p()
    if not advapi32.ConvertSidToStringSidW(sid, byref(text)):
        raise PermissionError("Could not read a SID.")
    try:
        return str(ctypes.wstring_at(_address(text)))
    finally:
        _local_free(text.value)


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


# --- WinVerifyTrust ------------------------------------------------------------------------------


class _WintrustFileInfo(Structure):
    _fields_ = [("cbStruct", c_uint32), ("pcwszFilePath", c_wchar_p), ("hFile", c_void_p), ("pgKnownSubject", c_void_p)]


class _WintrustData(Structure):
    _fields_ = [
        ("cbStruct", c_uint32), ("pPolicyCallbackData", c_void_p), ("pSIPClientData", c_void_p), ("dwUIChoice", c_uint32),
        ("fdwRevocationChecks", c_uint32), ("dwUnionChoice", c_uint32), ("pFile", POINTER(_WintrustFileInfo)),
        ("dwStateAction", c_uint32), ("hWVTStateData", c_void_p), ("pwszURLReference", c_wchar_p), ("dwProvFlags", c_uint32),
        ("dwUIContext", c_uint32), ("pSignatureSettings", c_void_p),
    ]


class _CryptProviderSigner(Structure):  # CRYPT_PROVIDER_SGNR; pChainContext is its last member
    _fields_ = [
        ("cbStruct", c_uint32), ("sftVerifyAsOf", c_uint32 * 2), ("csCertChain", c_uint32), ("pasCertChain", c_void_p),
        ("dwSignerType", c_uint32), ("psSigner", c_void_p), ("dwError", c_uint32), ("csCounterSigners", c_uint32),
        ("pasCounterSigners", c_void_p), ("pChainContext", c_void_p),
    ]


class _CertContext(Structure):
    _fields_ = [("dwCertEncodingType", c_uint32), ("pbCertEncoded", POINTER(c_ubyte)), ("cbCertEncoded", c_uint32)]


class _CertChainElement(Structure):
    _fields_ = [("cbSize", c_uint32), ("pCertContext", POINTER(_CertContext))]


class _CertSimpleChain(Structure):
    _fields_ = [("cbSize", c_uint32), ("TrustStatus", c_uint32 * 2), ("cElement", c_uint32), ("rgpElement", POINTER(POINTER(_CertChainElement)))]


class _CertChainContext(Structure):
    _fields_ = [("cbSize", c_uint32), ("TrustStatus", c_uint32 * 2), ("cChain", c_uint32), ("rgpChain", POINTER(POINTER(_CertSimpleChain)))]


_GENERIC_VERIFY_V2: Final = "00AAC56B-CD44-11d0-8CC2-00C04FC295EE"
_UI_NONE: Final = 2
_REVOKE_NONE: Final = 0
_CHOICE_FILE: Final = 1
_STATE_ACTION_VERIFY: Final = 1
_STATE_ACTION_CLOSE: Final = 2
_CACHE_ONLY_URL_RETRIEVAL: Final = 0x1000
_NO_SIGNER_CERT: Final = 0x80096002


@dataclass(frozen=True)
class SignatureVerification:
    """What WinVerifyTrust reported: ``status`` 0 when the signature is valid and trusted, and then
    the signer's leaf and root certificates (DER) from the chain WinVerifyTrust itself validated."""

    status: int
    leaf_der: bytes | None = None
    root_der: bytes | None = None


def verify_embedded_signature(path: str) -> SignatureVerification:
    """WinVerifyTrust with the generic Authenticode policy: the embedded signature is intact and
    chains to a trusted root (honouring a timestamp countersignature). Revocation isn't checked and
    no network fetch is made. The signer's chain is read before the verification state is released."""
    wintrust = _system32("wintrust.dll")
    wintrust.WinVerifyTrust.argtypes = [c_void_p, POINTER(_Guid), POINTER(_WintrustData)]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WTHelperProvDataFromStateData.argtypes = [c_void_p]
    wintrust.WTHelperProvDataFromStateData.restype = c_void_p
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [c_void_p, c_uint32, ctypes.c_int, c_uint32]
    wintrust.WTHelperGetProvSignerFromChain.restype = c_void_p

    file_info = _WintrustFileInfo(ctypes.sizeof(_WintrustFileInfo), path, None, None)
    data = _WintrustData()
    data.cbStruct = ctypes.sizeof(_WintrustData)
    data.dwUIChoice = _UI_NONE
    data.fdwRevocationChecks = _REVOKE_NONE
    data.dwUnionChoice = _CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = _STATE_ACTION_VERIFY
    data.dwProvFlags = _CACHE_ONLY_URL_RETRIEVAL
    action = _Guid.of(_GENERIC_VERIFY_V2)
    no_interactive_user = c_void_p(-1)  # INVALID_HANDLE_VALUE

    status = wintrust.WinVerifyTrust(no_interactive_user, byref(action), byref(data)) & 0xFFFFFFFF
    try:
        if status == 0:
            chain = _read_signer_chain(wintrust, data.hWVTStateData)
            if chain is not None:
                return SignatureVerification(0, *chain)
            status = _NO_SIGNER_CERT
        return SignatureVerification(status)
    finally:
        # Release the state the verify call allocated, whatever it returned.
        data.dwStateAction = _STATE_ACTION_CLOSE
        wintrust.WinVerifyTrust(no_interactive_user, byref(action), byref(data))


def _read_signer_chain(wintrust: Any, state_data: int | None) -> tuple[bytes, bytes] | None:
    provider = wintrust.WTHelperProvDataFromStateData(state_data)
    if not provider:
        return None
    signer_address = wintrust.WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
    if not signer_address:
        return None
    signer = _CryptProviderSigner.from_address(signer_address)
    if signer.cbStruct < ctypes.sizeof(_CryptProviderSigner) or not signer.pChainContext:
        return None

    context = _CertChainContext.from_address(signer.pChainContext)
    if context.cChain < 1 or not context.rgpChain:
        return None
    # The leaf is the first element of the first simple chain; the root, the last element of the
    # last one (cChain is 1 for an ordinary Authenticode chain).
    leaf = _certificate(context.rgpChain[0], first=True)
    root = _certificate(context.rgpChain[context.cChain - 1], first=False)
    return (leaf, root) if leaf is not None and root is not None else None


def _certificate(chain_pointer: Any, *, first: bool) -> bytes | None:
    if not chain_pointer:
        return None
    chain = chain_pointer.contents
    if chain.cElement < 1 or not chain.rgpElement:
        return None
    element = chain.rgpElement[0 if first else chain.cElement - 1]
    if not element or not element.contents.pCertContext:
        return None
    context = element.contents.pCertContext.contents
    if not context.pbCertEncoded or context.cbCertEncoded == 0:
        return None
    return ctypes.string_at(context.pbCertEncoded, context.cbCertEncoded)
