"""The default protected cache and a read-only collection of caches."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Final, Self

from hkdfguard import abstractions
from hkdfguard.abstractions import KeyRing, KeyTrackingValue, ProtectedCacheBase, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.diagnostics import AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, SpanNames

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.cache")


class ProtectedCache(ProtectedCacheBase, abstractions.ProtectedCache):
    """The default :class:`hkdfguard.abstractions.ProtectedCache`, backed by a :class:`KeyRing`:
    every add/add_or_update encrypts under the ring's current key and records its version, and every
    decrypt reveals under the version the entry recorded (see :class:`ProtectedCacheBase`), so the
    cache follows key rotation while values stored earlier stay readable. add's insert-if-absent is
    atomic, so a duplicate name is rejected even under concurrent callers. Nothing here ever holds
    plaintext beyond the duration of a single call.

    Every add/add_or_update counts toward :meth:`CacheMetrics.operations`, tagged with the operation
    and its result. The logger receives a debug entry per operation while sensitive logging is
    enabled, and an error entry per failure.
    """

    def __init__(self, key_ring: KeyRing, logger: logging.Logger | None = None) -> None:
        """:param key_ring: supplies the current key for every add and the recorded version's key for
            every decrypt; owned by the caller - the cache never closes keys
        :param logger: receives debug entries for sensitive operations and errors for failures;
            ``None`` for the ``hkdfguard.cache`` logger
        """
        super().__init__(key_ring)
        self._logger = logger if logger is not None else _DEFAULT_LOGGER

    def add(self, name: str, plaintext: WritableBuffer | str) -> None:
        """:raises TypeError: ``name`` or ``plaintext`` is ``None``, or ``plaintext`` is immutable bytes
        :raises ValueError: a value is already stored under this name (ignoring ASCII case),
            ``plaintext`` is empty, or ``name`` is not valid UTF-16
        """
        self._run(SpanNames.Cache.ADD, name, plaintext, only_if_absent=True)

    def add_or_update(self, name: str, plaintext: WritableBuffer | str) -> None:
        """:raises TypeError: ``name`` or ``plaintext`` is ``None``, or ``plaintext`` is immutable bytes
        :raises ValueError: ``plaintext`` is empty, or ``name`` is not valid UTF-16
        """
        self._run(SpanNames.Cache.ADD_OR_UPDATE, name, plaintext, only_if_absent=False)

    def _run(self, operation: str, name: str, plaintext: WritableBuffer | str, *, only_if_absent: bool) -> None:
        telemetry = HkdfGuardTelemetry.CACHE
        with telemetry.start_span(operation) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, operation, {AttributeNames.NAME: str(name),
                                                                    AttributeNames.PLAINTEXT_LENGTH: _length(plaintext)})
                HkdfGuardLog.sensitive_operation_logged(self._logger, operation, name)

            try:
                # Encrypting zeroes a buffer plaintext on every path, a None name included.
                entry: KeyTrackingValue = self._encrypt_any(name, plaintext)
                if only_if_absent:
                    if not self._put_entry_if_absent(name, entry):
                        raise ValueError(f"An item with the name '{name}' has already been added.")
                else:
                    self._put_entry(name, entry)
                _record_operation(operation, success=True)
            except Exception as exception:
                # The span records the exception as it escapes.
                HkdfGuardLog.operation_failed(self._logger, operation, exception)
                _record_operation(operation, success=False)
                raise


def _length(plaintext: object) -> int:
    if isinstance(plaintext, str):
        return len(plaintext)
    if isinstance(plaintext, (bytearray, memoryview)):
        return memoryview(plaintext).nbytes
    return 0


def _record_operation(operation: str, *, success: bool) -> None:
    CacheMetrics.operations().add(1, {AttributeNames.OPERATION_NAME: operation, AttributeNames.RESULT: "success" if success else "error"})


class ProtectedCacheCollection(ProtectedReadOnlyCache):
    """Aggregates several :class:`ProtectedReadOnlyCache` sources into one read-only surface.
    :meth:`add` registers a source and returns this same instance for fluent chaining
    (``ProtectedCacheCollection().add(a).add(b)``). decrypt/find_max_decrypted_length check each
    source in the order it was added, returning the first match. This never owns or writes encrypted
    values of its own - storing values stays the concern of whichever sources support it (e.g. a
    writable :class:`ProtectedCache` among them). Safe to read while sources are being added.
    """

    def __init__(self) -> None:
        """An empty collection: every lookup misses until a source is added."""
        self._sources: tuple[ProtectedReadOnlyCache, ...] = ()
        self._lock = threading.Lock()

    def add(self, source: ProtectedReadOnlyCache) -> Self:
        """Registers ``source``, checked after every source already added.

        :returns: this same collection, for fluent chaining
        :raises TypeError: ``source`` is ``None``
        """
        if source is None:
            raise TypeError("source must not be None.")
        with self._lock:
            # Copy-on-write: readers iterate whichever tuple they read, never a changing one.
            self._sources = (*self._sources, source)
        return self

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """:returns: the bytes the first source holding ``name`` wrote, or 0 if none does"""
        written = self._first_match(name, lambda source: source.decrypt(name, result) or None)
        return written or 0

    def find_max_decrypted_length(self, name: str) -> int | None:
        for source in self._sources:
            max_length = source.find_max_decrypted_length(name)
            if max_length is not None:
                return max_length
        return None

    def _first_match[T](self, name: str, decrypt: Callable[[ProtectedReadOnlyCache], T | None]) -> T | None:
        telemetry = HkdfGuardTelemetry.CACHE
        with telemetry.start_span(SpanNames.Cache.DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.Cache.DECRYPT, {AttributeNames.NAME: str(name)})

            for source in self._sources:
                value = decrypt(source)
                if value is not None:
                    return value
            return None
