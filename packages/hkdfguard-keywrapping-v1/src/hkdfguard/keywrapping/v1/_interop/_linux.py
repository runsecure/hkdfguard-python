"""The Linux native KMS binding."""

from __future__ import annotations

import ctypes
from typing import Final

from hkdfguard.keywrapping.v1._interop._kms import KmsFunctions, NativeKmsLibrary, NativeLibraryNotFoundError


class LinuxHkdfGuardKmsLibrary(NativeKmsLibrary):
    """Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest available
    provider on the host - TPM2 > PKCS#11 > external secret > software > ephemeral - to hold the
    per-service KEK. Loaded by the dynamic linker's default search, as the .NET port does. No call
    creates a KEK: ``hkdfguard provision --service-name <name>`` (/usr/bin/hkdfguard) must create it
    first, or wrap fails with ERR_KEK_NOT_FOUND."""

    FILE_NAME: Final = "libHkdfGuardKeyProtectionLinux.so"

    _PLATFORM_DESCRIPTIONS: Final[dict[int, str]] = {
        NativeKmsLibrary.ERR_PROVIDER_UNAVAILABLE:
            "no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml",
        NativeKmsLibrary.ERR_PROVIDER_ERROR:
            "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason",
        NativeKmsLibrary.ERR_POLICY_INVALID:
            "/etc/hkdfguard/policy.toml can't be used: unparsable, an invalid or contradictory setting, insecure ownership or permissions, "
            "or a provider this build lacks",
        NativeKmsLibrary.ERR_KEK_NOT_FOUND: "no KEK is provisioned for this service; run hkdfguard provision",
        NativeKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH:
            "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret "
            "has changed",
        NativeKmsLibrary.ERR_PROCESS_HARDENING_FAILED: "process hardening failed: core dumps or ptrace access could not be disabled",
    }

    def describe_status(self, status: int) -> str | None:
        return self._PLATFORM_DESCRIPTIONS.get(status) or super().describe_status(status)

    def _bind(self) -> KmsFunctions:
        try:
            library = ctypes.CDLL(self.FILE_NAME)
        except OSError as error:
            raise NativeLibraryNotFoundError(f"The HkdfGuard native KMS library '{self.FILE_NAME}' could not be loaded: {error}") from error
        return KmsFunctions(library)
