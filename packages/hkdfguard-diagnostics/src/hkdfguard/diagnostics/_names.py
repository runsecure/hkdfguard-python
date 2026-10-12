"""Span, attribute, event and metric names - identical in every HkdfGuard port, so telemetry from
any of them queries the same way."""

from typing import Final


class SpanNames:
    """Span/operation names, one nested class per component - lowercase, dot-separated
    (OpenTelemetry semantic-convention style: ``hkdfguard.<component>.<operation>``)."""

    class Cache:
        ADD: Final = "hkdfguard.cache.add"
        ADD_OR_UPDATE: Final = "hkdfguard.cache.add_or_update"
        DECRYPT: Final = "hkdfguard.cache.decrypt"

    class DataProtection:
        PROTECTOR_ENCRYPT: Final = "hkdfguard.data_protection.protector.encrypt"
        PROTECTOR_DECRYPT: Final = "hkdfguard.data_protection.protector.decrypt"
        KEY_WRAPPED_KEY_ENCRYPT: Final = "hkdfguard.data_protection.key_wrapped_key.encrypt"
        KEY_WRAPPED_KEY_DECRYPT: Final = "hkdfguard.data_protection.key_wrapped_key.decrypt"
        EPHEMERAL_KEY_INITIALIZE: Final = "hkdfguard.data_protection.ephemeral_key.initialize"
        KEY_RING_ADD: Final = "hkdfguard.data_protection.key_ring.add"
        KEY_RING_GET: Final = "hkdfguard.data_protection.key_ring.get"
        KEY_RING_GET_CURRENT: Final = "hkdfguard.data_protection.key_ring.get_current"
        KEY_RING_ROTATE_EPHEMERAL: Final = "hkdfguard.data_protection.key_ring.rotate_ephemeral"
        FORMAT_PROVIDER_FORMAT: Final = "hkdfguard.data_protection.format.format"
        FORMAT_PROVIDER_PARSE: Final = "hkdfguard.data_protection.format.parse"
        FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH: Final = "hkdfguard.data_protection.format.get_max_decrypted_length"

    class CryptoProviderAesGcm256:
        ENCRYPT: Final = "hkdfguard.crypto_provider_aes_gcm256.encrypt"
        DECRYPT: Final = "hkdfguard.crypto_provider_aes_gcm256.decrypt"
        BACKGROUND_REFRESH: Final = "hkdfguard.crypto_provider_aes_gcm256.background_refresh"

    class EncryptedConfiguration:
        DECRYPT: Final = "hkdfguard.encrypted_configuration.decrypt"


class AttributeNames:
    """Attribute keys shared across every component's spans, events, and metrics."""

    NAME: Final = "hkdfguard.name"
    PLAINTEXT_LENGTH: Final = "hkdfguard.plaintext_length"
    CIPHERTEXT_LENGTH: Final = "hkdfguard.ciphertext_length"
    ENCRYPTED_LENGTH: Final = "hkdfguard.encrypted_length"
    AAD_LENGTH: Final = "hkdfguard.aad_length"
    VALUE_LENGTH: Final = "hkdfguard.value_length"
    KEY_VERSION: Final = "hkdfguard.key_version"
    KEY_RING_BECAME_CURRENT: Final = "hkdfguard.key_ring.became_current"
    OPERATION_NAME: Final = "hkdfguard.operation.name"
    RESULT: Final = "hkdfguard.result"
    ENCRYPTION_COUNT: Final = "hkdfguard.encryption_count"
    ENCRYPTION_LIMIT: Final = "hkdfguard.encryption_limit"
    CONSECUTIVE_FAILURES: Final = "hkdfguard.consecutive_failures"


class EventNames:
    """Fixed span event names. The operation that raised an event is carried as the
    :attr:`AttributeNames.OPERATION_NAME` attribute, so event names stay low-cardinality."""

    SENSITIVE_OPERATION: Final = "hkdfguard.sensitive_operation"

    ENCRYPTION_BUDGET_WARNING: Final = "hkdfguard.encryption_budget_warning"
    """Raised once, on the encrypt span that crosses a key's encryption-count warning threshold."""

    KEY_ACCESS_SUSPENDED: Final = "hkdfguard.key_access_suspended"
    """Raised on the background-refresh span whose failure reached the consecutive-failure limit."""


class MetricNames:
    """Metric instrument names, following the ``hkdfguard.<component>.<noun>`` convention."""

    class Cache:
        OPERATIONS: Final = "hkdfguard.cache.operations"
