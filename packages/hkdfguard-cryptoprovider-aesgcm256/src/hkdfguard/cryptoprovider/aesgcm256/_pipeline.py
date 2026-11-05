"""The AES-256-GCM pipeline data protector."""

from __future__ import annotations

import os
import threading
from collections.abc import Buffer

from hkdfguard.abstractions import (
    ArrayUtility,
    AsyncBinaryDestination,
    BinaryDestination,
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


def _utf8_view(plaintext: object) -> memoryview:
    """``plaintext``'s bytes, as a flat view.

    :raises TypeError: ``plaintext`` isn't a buffer
    """
    if not isinstance(plaintext, Buffer):
        raise TypeError("plaintext must be a str or a buffer of UTF-8 bytes.")
    return memoryview(plaintext).cast("B")


def _code_points(view: memoryview | None) -> int:
    # What len() would give for the str these UTF-8 bytes decode to: every byte but a continuation byte.
    return 0 if view is None else sum(1 for b in view if b & 0xC0 != 0x80)


def _copy_utf8(view: memoryview | None) -> bytearray:
    """A copy of ``view``'s bytes of the protector's own, which the session zeroes as it encrypts.

    :raises ValueError: they aren't well-formed UTF-8
    """
    if view is None or not Utf8.is_valid(view):
        raise ValueError("The plaintext isn't well-formed UTF-8: the pipeline protector encrypts text.")
    return bytearray(view)


class AesGcmPipelineDataProtector(PipelineDataProtector):
    """AES-256-GCM :class:`PipelineDataProtector`: generates a random 32-byte key in memory and drives
    a single session around it for its whole lifetime - no key wrapper, no key ring, no refresh. Each
    encrypt/decrypt binds the secret identifier as AAD (via :class:`ProtectedConfigurationPurpose`);
    values are formatted via the given provider and stamped with ``key_version``. close zeroes the
    key and its base64 form; any use afterwards raises :class:`ObjectClosedError`."""

    def __init__(self, format_provider: EncryptedFormatProvider, key_version: int, *,
                 _key: bytearray | None = None, _budget: EncryptionBudget | None = None) -> None:
        """:param format_provider: formats/parses the protected values, e.g. DefaultFormatProvider
        :param key_version: the version stamped on every value - the version this key will be
            registered under once wrapped
        :param _key: for this package's tests only, not public API - the 32-byte key to use (owned
            and zeroed by this protector)
        :param _budget: for this package's tests only, not public API - the encryption count to draw on"""
        if format_provider is None:
            raise TypeError("format_provider must not be None.")
        self._format_provider = format_provider
        self._key_version = key_version
        self._key = _key if _key is not None else bytearray(os.urandom(KEY_LENGTH))
        self._budget = _budget if _budget is not None else EncryptionBudget()
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
    def _key_buffer(self) -> bytearray:
        """The key buffer - for this package's tests, to check it is zeroed. Not public API."""
        return self._key

    @property
    def _base64_buffer(self) -> bytearray | None:
        """The base64 buffer once :meth:`get_key_as_base64` has run - for this package's tests, to
        check it is zeroed. Not public API."""
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

    def write_dek(self, destination: BinaryDestination) -> None:
        """Encoded afresh, straight from a copy of the key into a ``bytearray`` of its own - never
        through a ``str``, nor the buffer :meth:`get_key_as_base64` returns - which is zeroed once
        the write and flush return or raise. What ``destination`` buffers is its own (see
        :class:`~hkdfguard.abstractions.BinaryDestination`).

        :raises TypeError: ``destination`` is ``None``
        :raises ObjectClosedError: the protector has been closed; nothing is written
        """
        if destination is None:
            raise TypeError("destination must not be None.")
        ascii_key = self._encode_key()
        try:
            destination.write(ascii_key)
            destination.flush()
        finally:
            ArrayUtility.zero_memory(ascii_key)

    async def write_dek_async(self, destination: AsyncBinaryDestination) -> None:
        """:meth:`write_dek`, drained rather than flushed. The ``bytearray`` is zeroed once the
        drain completes, fails or is cancelled.

        :raises TypeError: ``destination`` is ``None``
        :raises ObjectClosedError: the protector has been closed; nothing is written
        """
        if destination is None:
            raise TypeError("destination must not be None.")
        ascii_key = self._encode_key()
        try:
            destination.write(ascii_key)
            await destination.drain()
        finally:
            ArrayUtility.zero_memory(ascii_key)

    def _encode_key(self) -> bytearray:
        # The key's base64 in a bytearray the caller zeroes; the copy it is encoded from is zeroed here.
        with self._gate:
            self._current()
            copy = bytearray(self._key)
            try:
                return _base64_into(copy)
            finally:
                ArrayUtility.zero_memory(copy)

    def encrypt(self, plaintext: str | Buffer, secret_identifier: str) -> str:
        """A ``str`` is encoded into a bytearray; a buffer's bytes are checked to be well-formed
        UTF-8 where they lie - never decoded into a ``str`` - and copied into one. That bytearray is
        what is encrypted, and it is zeroed once encrypted, as it is if the encryption fails: the
        caller's buffer is only read.

        :raises TypeError: ``plaintext`` is neither a ``str`` nor a buffer
        :raises ValueError: ``secret_identifier`` is empty or not valid UTF-16, or a buffer
            ``plaintext`` isn't well-formed UTF-8
        :raises ObjectClosedError: the protector has been closed
        """
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.PROTECTOR_ENCRYPT) as span:
            text = plaintext if isinstance(plaintext, str) else None
            source = None if text is not None else _utf8_view(plaintext)
            if telemetry.sensitive_logging_enabled:
                length = len(text) if text is not None else _code_points(source)
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.PROTECTOR_ENCRYPT,
                                                  {AttributeNames.NAME: str(secret_identifier), AttributeNames.PLAINTEXT_LENGTH: length})

            session = self._current()
            aad = ProtectedConfigurationPurpose.aad_for(secret_identifier)
            plaintext_bytes = Utf8.encode(text) if text is not None else _copy_utf8(source)
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
