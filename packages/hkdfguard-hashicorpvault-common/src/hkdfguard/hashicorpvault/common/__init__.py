"""What every HkdfGuard integration with HashiCorp Vault shares: the address, path and token checks,
the retry limits and backoff, and the error Vault's refusals are reported as."""

from hkdfguard.hashicorpvault.common._connection import (
    MAX_RETRY_COUNT,
    MAX_RETRY_DELAY,
    MIN_RETRY_COUNT,
    TOKEN_HEADER,
    VaultConnectionOptions,
    api_base,
    check_connection_options,
    is_valid_path,
    is_valid_segment,
    is_valid_token,
    retry_delay,
)
from hkdfguard.hashicorpvault.common._errors import VaultRequestError

__all__ = [
    "MAX_RETRY_COUNT",
    "MAX_RETRY_DELAY",
    "MIN_RETRY_COUNT",
    "TOKEN_HEADER",
    "VaultConnectionOptions",
    "VaultRequestError",
    "api_base",
    "check_connection_options",
    "is_valid_path",
    "is_valid_segment",
    "is_valid_token",
    "retry_delay",
]
