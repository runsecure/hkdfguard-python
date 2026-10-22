"""The AES-256-GCM pipeline data protector."""

from __future__ import annotations

import os
import threading

from hkdfguard.abstractions import (
    ArrayUtility,
    EncryptedFormatProvider,
    KeyNotFoundError,
    KeyTrackingValue,
    ObjectClosedError,
    PipelineDataProtector,
    ProtectedConfigurationPurpose,
    Utf8,
    WritableBuffer,
)
from hkdfguard.cryptoprovider.aesgcm256._session import KEY_LENGTH, NONCE_SIZE, TAG_SIZE, AesGcmCryptoSession, EncryptionBudget
from hkdfguard.diagnostics import AttributeNames, HkdfGuardTelemetry, SpanNames

_BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_PAD = ord("=")


def _base64_into(data: bytearray) -> bytearray:
    """Standard padded base64 of ``data``, built directly into a ``bytearray`` - the library codecs
    return an immutable ``bytes`` that could never be zeroed. Only byte-sized values are ever
    computed: CPython caches those, whereas a wider integer would be a freed, unzeroed heap copy."""
    output = bytearray((len(data) + 2) // 3 * 4)
    position = 0
    for i in range(0, len(data), 3):
        count = min(3, len(data) - i)
        b0 = data[i]
        b1 = data[i + 1] if count > 1 else 0
        b2 = data[i + 2] if count > 2 else 0
        output[position] = _BASE64_ALPHABET[b0 >> 2]
        output[position + 1] = _BASE64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]
        output[position + 2] = _BASE64_ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] if count > 1 else _PAD
        output[position + 3] = _BASE64_ALPHABET[b2 & 0x3F] if count > 2 else _PAD
        position += 4
    return output


class AesGcmPipelineDataProtector(PipelineDataProtector):
    """AES-256-GCM :class:`PipelineDataProtector`: generates a random 32-byte key in memory and drives
    a single session around it for its whole lifetime - no key wrapper, no key ring, no refresh. Each
    encrypt/decrypt binds the secret identifier as AAD (via :class:`ProtectedConfigurationPurpose`);
    values are formatted via the given provider and stamped with ``key_version``. close zeroes the
    key and its base64 form; any use afterwards raises :class:`ObjectClosedError`."""

    def __init__(self, format_provider: EncryptedFormatProvider, key_version: int, *,
                 key: bytearray | None = None, budget: EncryptionBudget | None = None) -> None:
        """:param format_provider: formats/parses the protected values, e.g. DefaultFormatProvider
        :param key_version: the version stamped on every value - the version this key will be
            registered under once wrapped
        :param key: tests only - the 32-byte key to use (owned and zeroed by this protector)
        :param budget: tests only - the encryption count to draw on"""
        if format_provider is None:
            raise TypeError("format_provider must not be None.")
        self._format_provider = format_provider
        self._key_version = key_version
        self._key = key if key is not None else bytearray(os.urandom(KEY_LENGTH))
        self._budget = budget if budget is not None else EncryptionBudget()
        self._session: AesGcmCryptoSession | None = AesGcmCryptoSession(self._key, self._budget)
        self._base64: bytearray | None = None
        self._gate = threading.Lock()

    @property
    def key_version(self) -> int:
        return self._key_version

    @property
    def encryption_count(self) -> int:
        """Encryptions performed under this key so far."""
        return self._budget.count

    @property
    def key(self) -> bytearray:
        """The key buffer, for tests to check it is zeroed."""
        return self._key

    @property
    def base64_buffer(self) -> bytearray | None:
        """The base64 buffer once :meth:`get_key_as_base64` has run, for tests to check it is zeroed."""
        return self._base64

    def get_key_as_base64(self) -> memoryview:
        """Encoded once; every call returns a read-only view of the same buffer."""
        with self._gate:
            self._current()
            if self._base64 is None:
                copy = bytearray(self._key)
                try:
                    self._base64 = _base64_into(copy)
                finally:
                    ArrayUtility.zero_memory(copy)
            return memoryview(self._base64).toreadonly()

    def encrypt(self, plaintext: str, secret_identifier: str) -> str:
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.PROTECTOR_ENCRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.PROTECTOR_ENCRYPT,
                                                  {AttributeNames.NAME: str(secret_identifier), AttributeNames.PLAINTEXT_LENGTH: len(plaintext)})

            session = self._current()
            aad = ProtectedConfigurationPurpose.aad_for(secret_identifier)
            plaintext_bytes = Utf8.encode(plaintext)
            try:
                ciphertext = bytearray(NONCE_SIZE + len(plaintext_bytes) + TAG_SIZE)
                session.encrypt(plaintext_bytes, ciphertext, aad=aad)
                return self._format_provider.format(KeyTrackingValue(self._key_version, bytes(ciphertext)))
            finally:
                ArrayUtility.zero_memory(plaintext_bytes)

    def decrypt(self, encrypted: str, secret_identifier: str, result: WritableBuffer) -> int:
        """:raises KeyNotFoundError: the value was protected under a different key version"""
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.PROTECTOR_DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.PROTECTOR_DECRYPT,
                                                  {AttributeNames.NAME: str(secret_identifier), AttributeNames.ENCRYPTED_LENGTH: len(encrypted)})

            session = self._current()
            aad = ProtectedConfigurationPurpose.aad_for(secret_identifier)
            value = self._format_provider.parse(encrypted)
            if value.key_version != self._key_version:
                raise KeyNotFoundError(f"No key is registered for version {value.key_version}.")
            return session.decrypt(value.value, result, aad=aad)

    def get_max_decrypted_length(self, encrypted: str) -> int:
        return self._format_provider.get_max_decrypted_length(encrypted)

    def _current(self) -> AesGcmCryptoSession:
        session = self._session
        if session is None:
            raise ObjectClosedError("This pipeline data protector has been closed.")
        return session

    def close(self) -> None:
        """Closes the session, zeroing the key, and zeroes its base64 form. Safe to call more than once."""
        with self._gate:
            session, self._session = self._session, None
            if session is None:
                return
            session.close()
            ArrayUtility.zero_memory(self._base64)
