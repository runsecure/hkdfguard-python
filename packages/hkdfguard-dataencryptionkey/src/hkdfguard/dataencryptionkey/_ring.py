"""Data encryption keys, the versioned key ring, and its data protectors."""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from collections.abc import Buffer, Callable, Collection
from datetime import timedelta
from types import TracebackType
from typing import Self

from hkdfguard import abstractions
from hkdfguard.abstractions import (
    ArrayUtility,
    CryptoProvider,
    EncryptedFormatProvider,
    KeyNotFoundError,
    KeyTrackingValue,
    KeyVersions,
    ObjectClosedError,
    ProtectedCacheBase,
    Utf8,
    VersionedKey,
    WritableBuffer,
)
from hkdfguard.diagnostics import AttributeNames, HkdfGuardLog, HkdfGuardTelemetry, SpanNames, record_exception


class DataEncryptionKey(abstractions.DataEncryptionKey):
    """A :class:`~hkdfguard.abstractions.DataEncryptionKey` backed by a :class:`CryptoProvider`, which
    owns the key material - how it is revealed and refreshed - and performs the AEAD. This sizes the
    output via the provider and records telemetry. Owns its provider: close closes it."""

    def __init__(self, provider: CryptoProvider) -> None:
        if provider is None:
            raise TypeError("provider must not be None.")
        self._provider = provider
        self._closed = False
        self._lock = threading.Lock()

    def encrypt(self, plaintext: WritableBuffer, *, aad: Buffer = b"") -> bytes:
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT) as span:
            length = len(memoryview(plaintext))
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT,
                                                  {AttributeNames.PLAINTEXT_LENGTH: length, AttributeNames.AAD_LENGTH: len(memoryview(aad))})

            buffer = bytearray(self._provider.get_encrypted_allocation_length(length))
            written = self._provider.encrypt(plaintext, buffer, aad=aad)
            return bytes(memoryview(buffer)[:written])

    def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT,
                                                  {AttributeNames.CIPHERTEXT_LENGTH: len(memoryview(ciphertext)),
                                                   AttributeNames.AAD_LENGTH: len(memoryview(aad))})
            return self._provider.decrypt(ciphertext, result, aad=aad)

    def close(self) -> None:
        """Closes the provider. Safe to call more than once."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._provider.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


def _close_quietly(key: abstractions.DataEncryptionKey | None) -> None:
    close = getattr(key, "close", None)
    if callable(close):
        # Releasing one key must not stop the others.
        with contextlib.suppress(Exception):
            close()


class _DataProtector(abstractions.DataProtector):
    """The default :class:`~hkdfguard.abstractions.DataProtector`, created only by
    :meth:`KeyRing.create_protector`. Its name, UTF-8-encoded once, is the AAD for every value, so a
    value protected under one name fails under another. Encrypt uses the ring's current key on every
    call; decrypt uses whichever version the value names."""

    def __init__(self, name: str, key_ring: KeyRing, format_provider: EncryptedFormatProvider) -> None:
        self._name = name
        self._key_ring = key_ring
        self._format_provider = format_provider
        # Strict: an unpaired surrogate raises rather than becoming U+FFFD, which would give two names one AAD.
        self._aad = bytes(Utf8.encode_strict(name))

    def encrypt(self, plaintext: str) -> str:
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.PROTECTOR_ENCRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.PROTECTOR_ENCRYPT,
                                                  {AttributeNames.NAME: self._name, AttributeNames.PLAINTEXT_LENGTH: len(plaintext)})

            version, key = self._key_ring.get_current()
            plaintext_bytes = Utf8.encode(plaintext)
            try:
                encrypted = key.encrypt(plaintext_bytes, aad=self._aad)
            finally:
                ArrayUtility.zero_memory(plaintext_bytes)
            return self._format_provider.format(KeyTrackingValue(version, encrypted))

    def decrypt(self, encrypted: str, result: WritableBuffer) -> int:
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.PROTECTOR_DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.PROTECTOR_DECRYPT,
                                                  {AttributeNames.NAME: self._name, AttributeNames.ENCRYPTED_LENGTH: len(encrypted)})

            value = self._format_provider.parse(encrypted)
            return self._key_ring.get(value.key_version).decrypt(value.value, result, aad=self._aad)

    def decrypt_to_str(self, encrypted: str) -> str:
        buffer = bytearray(self.get_max_decrypted_length(encrypted))
        try:
            written = self.decrypt(encrypted, buffer)
            return str(memoryview(buffer)[:written], "utf-8", "replace")
        finally:
            ArrayUtility.zero_memory(buffer)

    def get_max_decrypted_length(self, encrypted: str) -> int:
        return self._format_provider.get_max_decrypted_length(encrypted)


class KeyRing(abstractions.KeyRing):
    """Tracks data encryption keys by version. Reads never block; adds are serialized - they only
    happen at startup and rotation. Whichever version is highest is current, the moment it is added.

    The ring owns every key added to it: close closes each one that has a ``close`` method (e.g.
    :class:`DataEncryptionKey`, which stops its provider's refresh and zeroes its key).

    A ring built with ephemeral keys also rotates on a schedule (see
    :meth:`KeyRingBuilder.with_ephemeral_key_rotation`): every interval it adds a fresh ephemeral key
    at the current version + 1 (the builder refuses a key file above every ephemeral version, which
    the first rotation would supersede). A superseded ephemeral key stays registered for
    :attr:`ephemeral_key_retention`, then the next rotation closes and removes it. Keys read from key
    files are never retired. close stops the rotation before closing any key.
    """

    def __init__(self, format_provider: EncryptedFormatProvider) -> None:
        if format_provider is None:
            raise TypeError("format_provider must not be None.")
        self._format_provider = format_provider
        self._keys: dict[int, abstractions.DataEncryptionKey] = {}
        self._current: int | None = None
        self._lock = threading.Lock()
        self._closed = False
        # Rotation and retention, touched only by the one rotation thread (or a test driving one rotation).
        self._stop = threading.Event()
        self._rotation_thread: threading.Thread | None = None
        self.ephemeral_key_rotation_interval: timedelta | None = None
        """How often a fresh ephemeral key is added; ``None`` when this ring doesn't rotate."""
        self.ephemeral_key_retention: timedelta | None = None
        """How long a superseded ephemeral key is kept; ``None`` when this ring doesn't rotate."""
        self._ephemeral_versions: set[int] = set()
        self._superseded_at: dict[int, int] = {}  # version -> time.monotonic_ns() first seen superseded

    # --- Keys -----------------------------------------------------------------------------------

    @property
    def current_version(self) -> int:
        current = self._current
        if current is None:
            raise RuntimeError("No current version has been set. Add a key first.")
        return current

    def add(self, version: int, key: abstractions.DataEncryptionKey) -> None:
        """Registers ``key`` for ``version``; a version higher than every other becomes current. On
        success the ring owns the key; if add raises, ownership stays with the caller.

        :raises ValueError: ``version`` is outside the signed 32-bit range, or a key is already
            registered for it
        :raises ObjectClosedError: the ring has been closed
        """
        if key is None:
            raise TypeError("key must not be None.")
        KeyVersions.require_valid(version)
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.KEY_RING_ADD) as span, self._lock:
            if self._closed:
                raise ObjectClosedError("This key ring has been closed.")
            if version in self._keys:
                raise ValueError(f"A key for version {version} is already registered.")
            self._keys[version] = key
            became_current = self._current is None or version > self._current
            if became_current:
                self._current = version
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.KEY_RING_ADD,
                                                  {AttributeNames.KEY_VERSION: version, AttributeNames.KEY_RING_BECAME_CURRENT: became_current})

    def get(self, version: int) -> abstractions.DataEncryptionKey:
        """:raises KeyNotFoundError: never added, or a superseded ephemeral key since retired"""
        key = self._keys.get(version)
        if key is not None:
            return key
        with HkdfGuardTelemetry.DATA_PROTECTION.start_span(SpanNames.DataProtection.KEY_RING_GET):
            raise KeyNotFoundError(f"No key is registered for version {version}.")

    def find(self, version: int) -> abstractions.DataEncryptionKey | None:
        return self._keys.get(version)

    def get_current(self) -> VersionedKey:
        with self._lock:
            current = self._current
            key = self._keys.get(current) if current is not None else None
        if current is None or key is None:
            with HkdfGuardTelemetry.DATA_PROTECTION.start_span(SpanNames.DataProtection.KEY_RING_GET_CURRENT):
                raise RuntimeError("No current version has been set. Add a key first.")
        return VersionedKey(current, key)

    def create_protector(self, name: str) -> abstractions.DataProtector:
        """A protector bound to this ring, whose name is the AAD of every value it protects.
        ``ProtectedConfigurationPurpose.for_key(key)`` names the protector a configuration reader uses.

        :raises TypeError: ``name`` is ``None``
        :raises ValueError: ``name`` is empty, starts with the protected cache's reserved AAD prefix,
            or is not valid UTF-16
        """
        if name is None:
            raise TypeError("name must not be None.")
        if not name:
            raise ValueError("A protector name must not be empty.")
        if name.startswith(ProtectedCacheBase.AAD_PREFIX):
            raise ValueError(f"Protector names starting with '{ProtectedCacheBase.AAD_PREFIX}' are reserved for ProtectedCache's entries.")
        return _DataProtector(name, self, self._format_provider)

    # --- Ephemeral key rotation -----------------------------------------------------------------

    def _configure_ephemeral_key_retention(self, retention: timedelta, versions: Collection[int]) -> None:
        self.ephemeral_key_retention = retention
        self._ephemeral_versions.update(versions)

    def _start_ephemeral_key_rotation(self, interval: timedelta, create_key: Callable[[], abstractions.DataEncryptionKey],
                                      logger: logging.Logger) -> None:
        self.ephemeral_key_rotation_interval = interval
        self._rotation_thread = threading.Thread(target=self._run_rotation, args=(interval.total_seconds(), create_key, logger),
                                                 name="hkdfguard-key-ring-rotation", daemon=True)
        self._rotation_thread.start()

    def _run_rotation(self, interval: float, create_key: Callable[[], abstractions.DataEncryptionKey], logger: logging.Logger) -> None:
        next_tick = time.monotonic() + interval
        while not self._stop.wait(max(0.0, next_tick - time.monotonic())):
            next_tick = max(next_tick + interval, time.monotonic())
            try:
                self._rotate_ephemeral_key(create_key, logger, self._stop.is_set)
            except Exception:
                return

    def _rotate_ephemeral_key(self, create_key: Callable[[], abstractions.DataEncryptionKey], logger: logging.Logger | None,
                              stopping: Callable[[], bool]) -> bool:
        """One rotation: create a key, add it at the current version + 1, then retire every ephemeral
        key whose retention has run out. A failure is recorded and logged and the current key stays in
        use; during shutdown it is re-raised instead. A key created but not added is always closed.

        :returns: True if a new key became current
        """
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.tracer.start_as_current_span(SpanNames.DataProtection.KEY_RING_ROTATE_EPHEMERAL, record_exception=False,
                                                    set_status_on_exception=False) as span:
            current = self.current_version
            if current == KeyVersions.MAX_VALUE:
                exhausted = RuntimeError(f"Version {current} is current, so there is no higher version to rotate to; the current key stays in use.")
                span.record_exception(exhausted)
                HkdfGuardLog.ephemeral_key_rotation_failed(logger, current, exhausted)
                return False

            key: abstractions.DataEncryptionKey | None = None
            try:
                key = create_key()
                self.add(current + 1, key)
                self._ephemeral_versions.add(current + 1)
                span.set_attribute(AttributeNames.KEY_VERSION, current + 1)
                HkdfGuardLog.ephemeral_key_rotated(logger, current + 1)
            except Exception as error:
                # Not added, so not owned by the ring: release its revealed key here.
                _close_quietly(key)
                if stopping():
                    raise
                record_exception(span, error)
                HkdfGuardLog.ephemeral_key_rotation_failed(logger, current, error)
                return False

        self._retire_superseded_ephemeral_keys(time.monotonic_ns(), logger, stopping)
        return True

    def _retire_superseded_ephemeral_keys(self, now_ns: int, logger: logging.Logger | None, stopping: Callable[[], bool]) -> None:
        """Retires every ephemeral key superseded at least the retention ago: removes it, so get/find
        no longer find it, and closes it. An ephemeral key is first seen as superseded by the rotation
        after the one replacing it, so it is kept at least the retention. Key-file versions are never touched."""
        retention = self.ephemeral_key_retention
        if retention is None:
            return

        current = self.current_version
        for version in self._ephemeral_versions:
            if version != current:
                self._superseded_at.setdefault(version, now_ns)

        retention_ns = int(retention.total_seconds() * 1_000_000_000)
        for version, superseded_at in list(self._superseded_at.items()):
            if version == current or now_ns - superseded_at < retention_ns:
                continue
            del self._superseded_at[version]
            self._ephemeral_versions.discard(version)
            with self._lock:
                key = self._keys.pop(version, None)
            if key is None:
                continue
            try:
                close = getattr(key, "close", None)
                if callable(close):
                    close()
                HkdfGuardLog.ephemeral_key_retired(logger, version)
            except Exception as error:
                if not stopping():
                    HkdfGuardLog.ephemeral_key_retirement_failed(logger, version, error)

    # --- Lifetime -------------------------------------------------------------------------------

    def close(self) -> None:
        """Stops rotation, then closes every key that has a ``close`` method. Safe to call more than
        once. A rotation still waiting on its key wrapper is not waited for: when it finishes it finds
        the ring closed and closes its own key."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            keys = list(self._keys.values())
        for key in keys:
            _close_quietly(key)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

