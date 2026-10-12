"""One AES-256-GCM key, its encryption budget, and the cipher operations under it."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Buffer
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from hkdfguard.abstractions import ArrayUtility, AuthenticationTagMismatchError, CryptographicError, ObjectClosedError, WritableBuffer
from hkdfguard.diagnostics import AttributeNames, EventNames, HkdfGuardLog, HkdfGuardTelemetry, SpanNames

TAG_SIZE: Final = 16
NONCE_SIZE: Final = 12
KEY_LENGTH: Final = 32


class EncryptionBudget:
    """Counts how many times one AES-256-GCM key has encrypted. With random 96-bit nonces, NIST SP
    800-38D caps a key at 2^32 encryptions; past that, a repeated nonce - which breaks both
    confidentiality and integrity - is no longer negligible. One budget is shared by every session
    on the same key and, through :meth:`for_key`, by every provider in this process that reveals it.
    Thread-safe."""

    DEFAULT_LIMIT: Final = 1 << 31
    """Hard stop: half the NIST limit, since this counter only sees its own process and every process
    sharing a key file draws on the same budget."""

    DEFAULT_WARNING_THRESHOLD: Final = 1 << 28
    """Where a warning is raised - one eighth of the limit."""

    # Budgets by key, for the life of the process. Indexed by an HMAC under a key generated for
    # this process, never by the DEK or a plain hash of it, which would be a stable fingerprint.
    _registry_key: Final = os.urandom(32)
    _registry: Final[dict[bytes, EncryptionBudget]] = {}
    _registry_lock: Final = threading.Lock()

    def __init__(self, warning_threshold: int = DEFAULT_WARNING_THRESHOLD, limit: int = DEFAULT_LIMIT) -> None:
        if limit < 1:
            raise ValueError(f"Limit must be positive; it is {limit}.")
        if warning_threshold < 1 or warning_threshold > limit:
            raise ValueError(f"Warning threshold must be between 1 and the limit; it is {warning_threshold}.")
        self.warning_threshold: Final = warning_threshold
        self.limit: Final = limit
        self._count = 0
        self._lock = threading.Lock()

    @classmethod
    def for_key(cls, key: Buffer) -> EncryptionBudget:
        """The budget for ``key``, shared by every provider in this process revealing the same DEK."""
        mac = HMAC(cls._registry_key, hashes.SHA256())
        mac.update(memoryview(key))
        identity = mac.finalize()
        with cls._registry_lock:
            return cls._registry.setdefault(identity, EncryptionBudget())

    @property
    def count(self) -> int:
        """Encryptions performed so far under this key."""
        with self._lock:
            return self._count

    def consume(self) -> bool:
        """Reserves one encryption. ``True`` exactly once, for the reservation that reaches the warning threshold.

        :raises CryptographicError: the limit has been reached; the key must be rotated
        """
        with self._lock:
            if self._count >= self.limit:
                raise CryptographicError(
                    f"This key has reached its AES-GCM encryption limit of {self.limit} and must be rotated; decryption still works.")
            self._count += 1
            return self._count == self.warning_threshold


class AesGcmCryptoSession:
    """An AES-256-GCM cipher bound to a single 32-byte key, held for a while - by the provider until
    its next background refresh, or by the pipeline protector for its whole lifetime - then closed,
    zeroing the key.

    Thread-safe: ``cryptography``'s AESGCM keeps no per-operation state between calls, so one
    instance serves concurrent operations. An operation that started before close completes on the
    cipher it captured; one starting after close is refused. Plaintext is read from and written to
    the caller's buffers directly (``encrypt_into``/``decrypt_into``), never through an immutable
    copy that couldn't be zeroed.
    """

    def __init__(self, key: bytearray, budget: EncryptionBudget | None = None, logger: logging.Logger | None = None) -> None:
        """:param key: the 32-byte key; owned by this session from here on, and zeroed on close
        :raises ValueError: the key is empty, all zero, or not exactly 32 bytes"""
        if ArrayUtility.is_null_or_empty(key):
            raise ValueError("AES key must not be empty or all zero.")
        if len(key) != KEY_LENGTH:
            raise ValueError(f"AES key must be exactly {KEY_LENGTH} bytes.")

        self._key = key
        self.budget: Final = budget if budget is not None else EncryptionBudget()
        self._logger = logger
        self._aes: AESGCM | None = AESGCM(key)
        self._lock = threading.Lock()

    @property
    def key(self) -> bytearray:
        """The key buffer, for tests to check it is zeroed."""
        return self._key

    @property
    def closed(self) -> bool:
        return self._aes is None

    def encrypt(self, plaintext: WritableBuffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        written = self.try_encrypt(plaintext, result, aad=aad)
        if written is not None:
            return written
        ArrayUtility.zero_memory(plaintext)
        raise ObjectClosedError("This AES-GCM session has been closed.")

    def try_encrypt(self, plaintext: WritableBuffer, result: WritableBuffer, *, aad: Buffer = b"") -> int | None:
        """Encrypts, unless this session is closed - then returns ``None`` having touched nothing,
        so a caller holding a session retired under it can retry on the current one. Once it starts,
        it zeroes ``plaintext`` on success and on every failure.

        :returns: the number of bytes written to ``result`` (layout: nonce | ciphertext | tag)
        """
        aes = self._aes
        if aes is None:
            return None

        telemetry = HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256
        try:
            source = memoryview(plaintext).cast("B")
            with telemetry.start_span(SpanNames.CryptoProviderAesGcm256.ENCRYPT) as span:
                if telemetry.sensitive_logging_enabled:
                    telemetry.log_sensitive_operation(span, SpanNames.CryptoProviderAesGcm256.ENCRYPT,
                                                      {AttributeNames.PLAINTEXT_LENGTH: len(source), AttributeNames.AAD_LENGTH: len(memoryview(aad))})

                if self.budget.consume():
                    span.add_event(EventNames.ENCRYPTION_BUDGET_WARNING,
                                   {AttributeNames.ENCRYPTION_COUNT: self.budget.count, AttributeNames.ENCRYPTION_LIMIT: self.budget.limit})
                    # A span event alone is lost without a tracer; the log is not.
                    HkdfGuardLog.encryption_budget_warning(self._logger, self.budget.count, self.budget.limit)

                output = memoryview(result).cast("B")
                total = NONCE_SIZE + len(source) + TAG_SIZE
                if len(output) < total:
                    raise ValueError("Result buffer too small.")

                nonce = os.urandom(NONCE_SIZE)
                output[:NONCE_SIZE] = nonce
                aes.encrypt_into(nonce, source, memoryview(aad), output[NONCE_SIZE:total])
                return total
        finally:
            ArrayUtility.zero_memory(plaintext)

    def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        written = self.try_decrypt(ciphertext, result, aad=aad)
        if written is None:
            raise ObjectClosedError("This AES-GCM session has been closed.")
        return written

    def try_decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int | None:
        """Decrypts, unless this session is closed - then returns ``None``, having done nothing."""
        aes = self._aes
        if aes is None:
            return None

        telemetry = HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256
        source = memoryview(ciphertext).cast("B")
        with telemetry.start_span(SpanNames.CryptoProviderAesGcm256.DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.CryptoProviderAesGcm256.DECRYPT,
                                                  {AttributeNames.CIPHERTEXT_LENGTH: len(source), AttributeNames.AAD_LENGTH: len(memoryview(aad))})

            if len(source) < NONCE_SIZE + TAG_SIZE:
                raise ValueError("Ciphertext too short.")

            length = len(source) - NONCE_SIZE - TAG_SIZE
            output = memoryview(result).cast("B")
            if len(output) < length:
                raise ValueError("Result buffer too small.")

            try:
                aes.decrypt_into(source[:NONCE_SIZE], source[NONCE_SIZE:], memoryview(aad), output[:length])
            except InvalidTag:
                ArrayUtility.zero_memory(output[:length])
                raise AuthenticationTagMismatchError() from None
            return length

    def close(self) -> None:
        """Releases the cipher and zeroes the key. Safe to call more than once."""
        with self._lock:
            if self._aes is None:
                return
            self._aes = None
            ArrayUtility.zero_memory(self._key)
