"""HkdfGuard's integration with HashiCorp Vault: :class:`VaultClient`, a port of vault-client-go -
generic reads and writes, and typed methods generated from Vault's OpenAPI spec - with tokens held
only protected by the key ring; and what every HkdfGuard Vault integration shares: the address,
path and token checks, TLS (:class:`VaultTlsOptions`), the retry limits and backoff, the token
sources and providers, and the error Vault's refusals are reported as."""

from hkdfguard.integration.hashicorpvault._client import VaultClient
from hkdfguard.integration.hashicorpvault._connection import (
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
from hkdfguard.integration.hashicorpvault._errors import VaultJsonError, VaultRedirectError, VaultRequestError, VaultResponseError
from hkdfguard.integration.hashicorpvault._generated import AuthApi, SecretsApi, SystemApi, VaultApis
from hkdfguard.integration.hashicorpvault._json import JsonKind, JsonValue, JsonWriter, VaultModel
from hkdfguard.integration.hashicorpvault._options import (
    DEFAULT_ADDRESS,
    VaultClientOptions,
    VaultRequest,
    VaultRequestCallback,
    VaultRequestOptions,
    VaultResponseCallback,
)
from hkdfguard.integration.hashicorpvault._replication import ReplicationForwardingMode, VaultReplication, VaultReplicationState
from hkdfguard.integration.hashicorpvault._response import (
    VaultMfaConstraint,
    VaultMfaMethod,
    VaultMfaRequirement,
    VaultRawResponse,
    VaultResponse,
    VaultResponseAuth,
    VaultResponseWrapInfo,
)
from hkdfguard.integration.hashicorpvault._retry import Backoff, RetryPolicy, VaultRateLimiter, VaultRetryOptions, default_retry_policy, linear_jitter_backoff
from hkdfguard.integration.hashicorpvault._tls import VaultTlsOptions
from hkdfguard.integration.hashicorpvault._token_provider import StaticVaultToken, VaultTokenProvider
from hkdfguard.integration.hashicorpvault._token_source import MAX_TOKEN_LENGTH, StaticVaultTokenSource, VaultTokenSource, copy_token_within

__all__ = [
    "DEFAULT_ADDRESS",
    "MAX_RETRY_COUNT",
    "MAX_RETRY_DELAY",
    "MAX_TOKEN_LENGTH",
    "MIN_RETRY_COUNT",
    "TOKEN_HEADER",
    "AuthApi",
    "Backoff",
    "JsonKind",
    "JsonValue",
    "JsonWriter",
    "ReplicationForwardingMode",
    "RetryPolicy",
    "SecretsApi",
    "StaticVaultToken",
    "StaticVaultTokenSource",
    "SystemApi",
    "VaultApis",
    "VaultClient",
    "VaultClientOptions",
    "VaultConnectionOptions",
    "VaultJsonError",
    "VaultMfaConstraint",
    "VaultMfaMethod",
    "VaultMfaRequirement",
    "VaultModel",
    "VaultRateLimiter",
    "VaultRawResponse",
    "VaultRedirectError",
    "VaultReplication",
    "VaultReplicationState",
    "VaultRequest",
    "VaultRequestCallback",
    "VaultRequestError",
    "VaultRequestOptions",
    "VaultResponse",
    "VaultResponseAuth",
    "VaultResponseCallback",
    "VaultResponseError",
    "VaultResponseWrapInfo",
    "VaultRetryOptions",
    "VaultTlsOptions",
    "VaultTokenProvider",
    "VaultTokenSource",
    "api_base",
    "check_connection_options",
    "copy_token_within",
    "default_retry_policy",
    "is_valid_path",
    "is_valid_segment",
    "is_valid_token",
    "linear_jitter_backoff",
    "retry_delay",
]
