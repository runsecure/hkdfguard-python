"""The Linux native KMS binding."""

from __future__ import annotations

import ctypes
from typing import Final

from hkdfguard.keywrapping.v1._interop._kms import KmsFunctions, NativeKmsLibrary, NativeLibraryNotFoundError


class LinuxHkdfGuardKmsLibrary(NativeKmsLibrary):
    """Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest available
    provider on the host - TPM2 > PKCS#11 > external secret > software > ephemeral - to hold the
    per-service KEK. Loaded by the dynamic linker's default search, as the .NET port does."""

    FILE_NAME: Final = "libHkdfGuardKeyProtectionLinux.so"

    ERR_INVALID_ARGUMENT: Final = -1
    ERR_BUFFER_TOO_SMALL: Final = -2
    ERR_PROVIDER_UNAVAILABLE: Final = -3
    ERR_PROVIDER_ERROR: Final = -4
    ERR_CRYPTO_ERROR: Final = -5
    ERR_INTERNAL_ERROR: Final = -6
    ERR_INVALID_UTF8: Final = -7
    ERR_MISSING_SERVICE_NAME: Final = -8

    def _bind(self) -> KmsFunctions:
        try:
            library = ctypes.CDLL(self.FILE_NAME)
        except OSError as error:
            raise NativeLibraryNotFoundError(f"The HkdfGuard native KMS library '{self.FILE_NAME}' could not be loaded: {error}") from error
        return KmsFunctions(library)
