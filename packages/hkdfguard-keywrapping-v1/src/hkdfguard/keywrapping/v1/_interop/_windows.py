"""The Windows native KMS binding, and the loader that verifies HkdfGuard.dll before mapping it."""

from __future__ import annotations

import ctypes
import os
import struct
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any, ClassVar, Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from hkdfguard.keywrapping.v1._interop import _win32
from hkdfguard.keywrapping.v1._interop._kms import CpuArchitecture, KmsFunctions, NativeKmsLibrary, NativeLibraryNotFoundError


@dataclass(frozen=True)
class VerifiedSigner:
    """What the signer policy checks, read from a signature WinVerifyTrust has already accepted: the
    leaf's subject as Windows formats it, its EKU OIDs, and the SHA-256 (hex) of the chain's root."""

    leaf_subject: str
    leaf_eku_oids: Collection[str]
    root_sha256: str


class WindowsNativeLibraryLoader:
    """Loads the Windows native KMS library from its one installed location and nowhere else. The
    library receives every plaintext DEK on unwrap and chooses every "random" DEK on
    generate-and-wrap, so loading an impostor would hand over every key. Five checks, all of which
    must pass before the file is mapped:

    1. The file exists at ``%ProgramFiles%\\HkdfGuard\\v1\\HkdfGuard.dll``, with Program Files read
       from the known-folder registry setting, never the environment.
    2. No component of that path below the drive root is a reparse point (symlink or junction).
    3. Every one of those components is owned by, and writable only by, SYSTEM, Administrators, or
       TrustedInstaller; the drive root is held only to what could rename the folder beneath it.
    4. A valid Authenticode signature issued to :attr:`EXPECTED_PUBLISHER` for code signing under
       HkdfGuard's Artifact Signing profile (:attr:`EXPECTED_PROFILE_EKU`), whose chain - as
       WinVerifyTrust validated it - ends at the pinned root :attr:`EXPECTED_ROOT_SHA256`.
    5. Its PE header marks it a DLL for this process's architecture, refusing the profile's other
       binaries (such as hkdfguard.exe) renamed into place.

    The library's own dependencies are then resolved from System32 only. Any failed check raises
    ``PermissionError``; there is no fallback and no override of the path.
    """

    FILE_NAME: Final = "HkdfGuard.dll"

    EXPECTED_PUBLISHER: Final = "CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US"
    """The Authenticode signer subject, as Windows formats it. The certificate is reissued frequently,
    so a thumbprint can't be pinned - the root and profile EKU are pinned instead."""

    EXPECTED_ROOT_SHA256: Final = "5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270"
    """Microsoft Identity Verification Root Certificate Authority 2020, the root of Azure Artifact
    Signing - so no root a user added to their own store can vouch for the publisher."""

    EXPECTED_PROFILE_EKU: Final = "1.3.6.1.4.1.311.97.492781510.305179978.413069662.611988563"
    CODE_SIGNING_EKU: Final = ExtendedKeyUsageOID.CODE_SIGNING.dotted_string

    TRUSTED_PRINCIPALS: Final = frozenset({
        "S-1-5-18",  # SYSTEM
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # NT SERVICE\TrustedInstaller
    })

    # Any right that changes what this path loads: write/append data, write EAs, delete-child,
    # delete, take over the ACL - plus generic bits an ACE can carry unmapped.
    GUARDED_RIGHTS: Final = 0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000
    # On the drive root, only what renames or deletes an entry beneath it: delete-child, WRITE_DAC,
    # WRITE_OWNER, GENERIC_ALL. Creating new entries there can't affect this path.
    GUARDED_ROOT_RIGHTS: Final = 0x0040 | 0x00040000 | 0x00080000 | 0x10000000

    IMAGE_FILE_EXECUTABLE_IMAGE: Final = 0x0002
    IMAGE_FILE_DLL: Final = 0x2000
    IMAGE_FILE_MACHINE_I386: Final = 0x014C
    IMAGE_FILE_MACHINE_AMD64: Final = 0x8664
    IMAGE_FILE_MACHINE_ARM64: Final = 0xAA64

    _lock: ClassVar = threading.Lock()
    _library: ClassVar[Any] = None

    @staticmethod
    def installed_path() -> str:
        """The single location the library is loaded from."""
        return os.path.join(_win32.program_files_directory(), "HkdfGuard", "v1", WindowsNativeLibraryLoader.FILE_NAME)

    @classmethod
    def load(cls) -> Any:
        """Verifies and loads the installed library once per process. A failure isn't cached.

        :raises NativeLibraryNotFoundError: not installed at :meth:`installed_path`
        :raises PermissionError: the file or its location failed verification
        """
        with cls._lock:
            if cls._library is None:
                cls._library = cls.load_from(cls.installed_path(), cls.EXPECTED_PUBLISHER)
            return cls._library

    @classmethod
    def load_from(cls, path: str, expected_publisher: str) -> Any:
        if not os.path.isfile(path):
            raise NativeLibraryNotFoundError(
                f"The HkdfGuard native KMS library is not installed at '{path}'. Install it there; it is never loaded from anywhere else.")

        cls.verify_location(path)
        cls.verify_signature(path, expected_publisher)
        cls.verify_image_kind(path)
        # A second, separate pass, now checking revocation (network allowed); only a definite revocation refuses.
        cls.verify_not_revoked(path, _win32.revocation_status(path))
        # Absolute path, so no probing for the library itself; its own imports come from System32 only.
        return ctypes.CDLL(os.path.abspath(path), winmode=_win32.LOAD_LIBRARY_SEARCH_SYSTEM32)

    # --- Location -------------------------------------------------------------------------------

    @classmethod
    def verify_location(cls, path: str) -> None:
        """Every component from the file up to the drive root: not a reparse point, owned and
        writable only by trusted principals; the drive root itself by the narrower root rule."""
        item = PureWindowsPath(os.path.abspath(path))
        while True:
            parent = item.parent
            if parent == item:
                cls.verify_drive_root(cls._security_of(str(item)), str(item))
                return
            cls.verify_not_reparse_point(str(item))
            cls.verify_trusted_only(cls._security_of(str(item)), str(item))
            item = parent

    @staticmethod
    def _security_of(path: str) -> _win32.SecurityDescriptorInfo:
        try:
            return _win32.security_descriptor_of(path)
        except PermissionError as error:
            raise PermissionError(f"{error} Refusing to load the HkdfGuard native library from it.") from None

    @staticmethod
    def verify_not_reparse_point(path: str) -> None:
        attributes = _win32.file_attributes(path)
        if attributes == _win32.INVALID_FILE_ATTRIBUTES:
            raise PermissionError(f"'{path}' could not be examined; the HkdfGuard native library is only loaded through a path that can be verified.")
        if attributes & _win32.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(f"'{path}' is a symbolic link or junction; the HkdfGuard native library is only loaded through a real path.")

    @classmethod
    def verify_trusted_only(cls, security: _win32.SecurityDescriptorInfo, display_path: str,
                            account_name: Callable[[str], str | None] = _win32.account_name) -> None:
        """A trusted owner and no Allow entry granting a write right to anyone else. Inherit-only
        entries don't apply to the item and Deny entries only remove access, so both are ignored; a
        missing DACL grants everyone everything and is refused."""
        cls._verify(security, display_path, cls.GUARDED_RIGHTS, account_name)

    @classmethod
    def verify_drive_root(cls, security: _win32.SecurityDescriptorInfo, display_path: str,
                          account_name: Callable[[str], str | None] = _win32.account_name) -> None:
        cls._verify(security, display_path, cls.GUARDED_ROOT_RIGHTS, account_name)

    @classmethod
    def _verify(cls, security: _win32.SecurityDescriptorInfo, display_path: str, guarded_rights: int,
                account_name: Callable[[str], str | None]) -> None:
        def describe(sid: str | None) -> str:
            if sid is None:
                return "an unknown principal"
            name = account_name(sid)
            return f"{name} ({sid})" if name else sid

        if security.owner_sid not in cls.TRUSTED_PRINCIPALS:
            raise PermissionError(f"'{display_path}' is owned by {describe(security.owner_sid)}; the HkdfGuard native library is only loaded "
                                  "from a location owned by SYSTEM, Administrators, or TrustedInstaller.")

        if security.grants_everyone_full:
            raise PermissionError(f"'{display_path}' has no DACL, which grants every user full control; the HkdfGuard native library is only "
                                  "loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.")

        denies = (_win32.ACCESS_DENIED_ACE_TYPE, _win32.ACCESS_DENIED_OBJECT_ACE_TYPE, _win32.ACCESS_DENIED_CALLBACK_ACE_TYPE,
                  _win32.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)
        for ace in security.aces:
            if ace.type in denies or ace.flags & _win32.INHERIT_ONLY_ACE:
                continue
            if ace.type in (_win32.ACCESS_ALLOWED_ACE_TYPE, _win32.ACCESS_ALLOWED_CALLBACK_ACE_TYPE):
                if ace.mask & guarded_rights and ace.sid not in cls.TRUSTED_PRINCIPALS:
                    raise PermissionError(f"'{display_path}' grants 0x{ace.mask & 0xFFFFFFFF:08X} to {describe(ace.sid)}; the HkdfGuard native "
                                          "library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.")
            else:
                # An allow-object ACE, or a type a DACL shouldn't hold: fail closed rather than guess.
                raise PermissionError(f"'{display_path}' has an access control entry of type 0x{ace.type:02X}, which this check can't "
                                      "evaluate; refusing to load from it.")

    # --- Signature ------------------------------------------------------------------------------

    @classmethod
    def verify_signature(cls, path: str, expected_publisher: str,
                         read_signer: Callable[[str], VerifiedSigner] | None = None) -> None:
        """A valid, trusted Authenticode signature whose signer passes :meth:`verify_signer_identity`.
        Any failure reading the signer is reported as a ``PermissionError`` too."""
        try:
            signer = (read_signer or cls.read_verified_signer)(path)
        except PermissionError:
            raise
        except Exception as error:
            raise PermissionError(f"Could not read the Authenticode signer of '{path}'; refusing to load it.") from error
        cls.verify_signer_identity(path, signer.leaf_subject, signer.leaf_eku_oids, signer.root_sha256, expected_publisher)

    CERT_E_REVOKED: Final = 0x800B010C
    """WinVerifyTrust's answer when a certificate in the signer's chain has definitely been revoked."""

    @classmethod
    def verify_not_revoked(cls, path: str, status: int) -> None:
        """The rule for the revocation pass: refuse only a definite revocation. Every other result -
        success, revocation servers offline (CRYPT_E_REVOCATION_OFFLINE), no revocation check possible
        (CRYPT_E_NO_REVOCATION_CHECK), CERT_E_REVOCATION_FAILURE, or anything else - lets the load
        continue: the first pass already validated the signature and its pins, and an offline host must
        still start."""
        if status & 0xFFFFFFFF == cls.CERT_E_REVOKED:
            raise PermissionError(f"'{path}' is signed with a certificate that has been revoked; refusing to load it. "
                                  "Install a current release.")

    @classmethod
    def verify_signer_identity(cls, path: str, leaf_subject: str, leaf_eku_oids: Collection[str], root_sha256: str,
                               expected_publisher: str) -> None:
        """The leaf is issued to ``expected_publisher``, carries the Code Signing and profile EKUs,
        and the chain ends at the pinned root. The chain's trust is WinVerifyTrust's to decide."""
        if leaf_subject != expected_publisher:
            raise PermissionError(f"'{path}' is signed by '{leaf_subject}', not the expected HkdfGuard publisher '{expected_publisher}'.")
        if root_sha256.upper() != cls.EXPECTED_ROOT_SHA256:
            raise PermissionError(f"'{path}' is signed under a root with SHA-256 {root_sha256}, not Microsoft Identity Verification Root "
                                  f"Certificate Authority 2020 ({cls.EXPECTED_ROOT_SHA256}), which HkdfGuard is signed under.")
        if cls.CODE_SIGNING_EKU not in leaf_eku_oids:
            raise PermissionError(f"'{path}' is signed with a certificate not issued for code signing (no EKU {cls.CODE_SIGNING_EKU}).")
        if cls.EXPECTED_PROFILE_EKU not in leaf_eku_oids:
            raise PermissionError(f"'{path}' is signed with a certificate not issued under HkdfGuard's Artifact Signing profile "
                                  f"(no EKU {cls.EXPECTED_PROFILE_EKU}).")

    @staticmethod
    def read_verified_signer(path: str) -> VerifiedSigner:
        """Verifies the signature with WinVerifyTrust and reads the signer from the chain it validated."""
        verification = _win32.verify_embedded_signature(path)
        if verification.status != 0 or verification.leaf_der is None or verification.root_der is None:
            raise PermissionError(f"'{path}' does not carry a valid, trusted Authenticode signature "
                                  f"(WinVerifyTrust status 0x{verification.status:08X}).")

        leaf = x509.load_der_x509_certificate(verification.leaf_der)
        try:
            eku = [oid.dotted_string for oid in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
        except x509.ExtensionNotFound:
            eku = []

        digest = hashes.Hash(hashes.SHA256())
        digest.update(verification.root_der)
        return VerifiedSigner(windows_subject_name(leaf.subject), tuple(eku), digest.finalize().hex().upper())

    # --- Image kind -----------------------------------------------------------------------------

    @classmethod
    def verify_image_kind(cls, path: str, characteristics: int | None = None, machine: int | None = None,
                          process_architecture: CpuArchitecture | None = None) -> None:
        """The PE header marks the file a DLL for this process's architecture. Run after
        :meth:`verify_signature`, whose hash covers the header. With ``characteristics`` and
        ``machine`` given, applies only the policy to them."""
        if characteristics is None or machine is None:
            try:
                with open(path, "rb") as file:
                    dos = file.read(64)
                    if len(dos) < 64 or dos[:2] != b"MZ":
                        raise OSError("no DOS header")
                    (pe_offset,) = struct.unpack_from("<I", dos, 0x3C)
                    file.seek(pe_offset)
                    pe = file.read(24)
                    if len(pe) < 24 or pe[:4] != b"PE\0\0":
                        raise OSError("no PE signature")
                    machine, characteristics = struct.unpack_from("<H", pe, 4)[0], struct.unpack_from("<H", pe, 22)[0]
            except OSError as error:
                raise PermissionError(f"Could not read the PE header of '{path}'; refusing to load it.") from error

        if not characteristics & cls.IMAGE_FILE_DLL:
            raise PermissionError(f"'{path}' is signed by the HkdfGuard publisher but is not a DLL (an executable renamed into place?); "
                                  "refusing to load it.")

        architecture = process_architecture or CpuArchitecture.current()
        expected = {CpuArchitecture.X64: cls.IMAGE_FILE_MACHINE_AMD64, CpuArchitecture.ARM64: cls.IMAGE_FILE_MACHINE_ARM64,
                    CpuArchitecture.X86: cls.IMAGE_FILE_MACHINE_I386}.get(architecture)
        if machine != expected:
            raise PermissionError(f"'{path}' is built for machine type 0x{machine:04X}, but this is a {architecture.value} process; "
                                  "refusing to load it.")


_SHORT_NAMES: Final = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S", "2.5.4.9": "STREET",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "T", "2.5.4.42": "G", "2.5.4.43": "I", "2.5.4.17": "PostalCode",
    "1.2.840.113549.1.9.1": "E", "0.9.2342.19200300.100.1.25": "DC",
}


def windows_subject_name(name: x509.Name) -> str:
    """A distinguished name as Windows formats a certificate subject: most specific attribute first,
    ", " between attributes, " + " within a multi-valued RDN, Windows' short names (S for state, E for
    email), and values quoted when they hold a special character - so :attr:`EXPECTED_PUBLISHER` is
    the same string in every port."""

    def quote(value: str) -> str:
        special = not value or value[0].isspace() or value[-1].isspace() or any(c in ',+="\n<>#;' for c in value)
        return '"' + value.replace('"', '""') + '"' if special else value

    rdns = []
    for rdn in reversed(name.rdns):
        rdns.append(" + ".join(
            f"{_SHORT_NAMES.get(a.oid.dotted_string, 'OID.' + a.oid.dotted_string)}={quote(a.value if isinstance(a.value, str) else a.value.hex())}"
            for a in rdn))
    return ", ".join(rdns)


class WindowsHkdfGuardKmsLibrary(NativeKmsLibrary):
    """Binds HkdfGuard.dll, loaded only from %ProgramFiles%\\HkdfGuard\\v1 after the checks in
    :class:`WindowsNativeLibraryLoader`. It holds the per-service KEK as a persistent, machine-wide,
    non-exportable P-256 key in the Microsoft Platform Crypto Provider (TPM) when available, or the
    Software Key Storage Provider otherwise. No call creates a KEK: an elevated
    ``hkdfguard provision`` must create it first. A service name is 1-128 ASCII letters, digits or '.'."""

    _PLATFORM_DESCRIPTIONS: Final[dict[int, str]] = {
        NativeKmsLibrary.ERR_PROVIDER_ERROR:
            "the KEK's key storage provider (Platform Crypto Provider or Software KSP) could not open or create the key",
        NativeKmsLibrary.ERR_POLICY_INVALID: r"a machine policy value under HKLM\Software\Policies\HkdfGuard is invalid",
        NativeKmsLibrary.ERR_KEK_NOT_FOUND: "no KEK is provisioned for this service; run hkdfguard provision from an elevated prompt",
        NativeKmsLibrary.ERR_KEK_ACCESS_DENIED:
            "the KEK exists, but this account is not authorized to use it (or, for a new KEK, the process is not elevated); "
            "add it to the HkdfGuardUsers group or a KeyUseGroups group",
        NativeKmsLibrary.ERR_KEK_INVALID: "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal",
        NativeKmsLibrary.ERR_PROCESS_HARDENING_FAILED:
            "process hardening failed: the crash-report heap exclusion or the process and thread access lists could not be set, "
            "or (with REQUIRE_PROTECTED_SIGNATURE) the process could not be closed to its own user",
    }

    def describe_status(self, status: int) -> str | None:
        return self._PLATFORM_DESCRIPTIONS.get(status) or super().describe_status(status)

    def _bind(self) -> KmsFunctions:
        return KmsFunctions(WindowsNativeLibraryLoader.load())
