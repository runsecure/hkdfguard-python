"""Shared plumbing for every protected cache."""

from __future__ import annotations

import threading
from collections.abc import Buffer

from hkdfguard.abstractions._buffers import ArrayUtility, Utf8, WritableBuffer
from hkdfguard.abstractions._interfaces import KeyRing, KeyTrackingValue, ProtectedReadOnlyCache
from hkdfguard.abstractions._rules import ascii_upper
from hkdfguard.diagnostics import AttributeNames, HkdfGuardTelemetry, SpanNames


class ProtectedCacheBase(ProtectedReadOnlyCache):
    """Shared :class:`ProtectedReadOnlyCache` plumbing: a :class:`KeyRing` to encrypt and decrypt
    through, a thread-safe map of encrypted entries keyed by name, and the encrypt/decrypt/telemetry
    logic every concrete cache needs. decrypt and find_max_decrypted_length fall back to
    :meth:`_try_populate` on a miss - by default nothing, but a subclass backed by an external source
    overrides it to fetch a value and encrypt it in on demand.

    **Keys come from the ring, so the cache follows rotation.** Every value is encrypted under the
    ring's current key when stored, and its entry records that version; decrypt uses exactly that
    version. The cache never owns or closes keys.

    **Every entry is bound to its name.** Each value is encrypted with AAD derived from its name
    (see :meth:`aad_for`) and decrypted with the AAD of the name it is looked up by, so a ciphertext
    that ends up under any other name fails authentication.

    Names match ignoring ASCII case only (see :meth:`_canonical_name`), and the AAD follows the
    same rule, so every spelling that reaches an entry also authenticates against it.
    """

    AAD_PREFIX = "HkdfGuard.Cache:"
    """The prefix of every cache entry's AAD, keeping it distinct from any other purpose."""

    def __init__(self, key_ring: KeyRing) -> None:
        if key_ring is None:
            raise TypeError("key_ring must not be None.")
        self._key_ring = key_ring
        # Keyed by _canonical_name, so lookups match exactly the names whose AAD they produce.
        self._data: dict[str, KeyTrackingValue] = {}
        self._lock = threading.Lock()

    @staticmethod
    def aad_for(name: str) -> bytes:
        """The AAD a value stored under ``name`` is bound to: the UTF-8 bytes of :attr:`AAD_PREFIX`
        followed by ``name``, with ASCII a-z upper-cased.

        :raises TypeError: ``name`` is ``None``
        :raises ValueError: ``name`` is not valid UTF-16 (an unpaired surrogate)
        """
        if name is None:
            raise TypeError("name must not be None.")
        return bytes(Utf8.encode_strict(ProtectedCacheBase.AAD_PREFIX + ascii_upper(name)))

    @staticmethod
    def _canonical_name(name: str) -> str:
        """How names are matched: two names are one entry exactly when their canonical names are
        equal - ASCII a-z upper-cased, every other character compared as-is."""
        if name is None:
            raise TypeError("name must not be None.")
        return ascii_upper(name)

    def _try_populate(self, name: str) -> bool:
        """Called when ``name`` isn't stored, before decrypt/find_max_decrypted_length give up.
        Override to pull a value in from an external source and store it (via :meth:`_encrypt` and
        :meth:`_put_entry` for this same name) before returning ``True``."""
        return False

    def _put_entry(self, name: str, entry: KeyTrackingValue) -> None:
        """Stores an entry from :meth:`_encrypt`/:meth:`_encrypt_text` for this same name, replacing any."""
        with self._lock:
            self._data[self._canonical_name(name)] = entry

    def _put_entry_if_absent(self, name: str, entry: KeyTrackingValue) -> bool:
        """Stores an entry unless one is already stored under ``name``; ``True`` if it was stored."""
        key = self._canonical_name(name)
        with self._lock:
            if key in self._data:
                return False
            self._data[key] = entry
            return True

    def _get_entry(self, name: str) -> KeyTrackingValue | None:
        """The entry stored under ``name``, without falling back to :meth:`_try_populate`."""
        with self._lock:
            return self._data.get(self._canonical_name(name))

    def _remove_entry(self, name: str) -> bool:
        with self._lock:
            return self._data.pop(self._canonical_name(name), None) is not None

    def _find_entry(self, name: str) -> KeyTrackingValue | None:
        entry = self._get_entry(name)
        if entry is not None:
            return entry
        return self._get_entry(name) if self._try_populate(name) else None

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """:raises KeyNotFoundError: the entry's key version is no longer in the ring"""
        telemetry = HkdfGuardTelemetry.ROOT
        with telemetry.start_span(SpanNames.Cache.DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.Cache.DECRYPT, {AttributeNames.NAME: str(name)})

            entry = self._find_entry(name)
            if entry is None:
                return 0
            return self._key_ring.get(entry.key_version).decrypt(entry.value, result, aad=self.aad_for(name))

    def find_max_decrypted_length(self, name: str) -> int | None:
        entry = self._find_entry(name)
        return None if entry is None else len(entry.value)

    def _encrypt(self, name: str, plaintext: WritableBuffer) -> KeyTrackingValue:
        """Encrypts ``plaintext`` under the ring's current key, bound to ``name`` - store the result
        under that same name. ``plaintext`` is zeroed on every path.

        :raises ValueError: ``plaintext`` is empty (a missing name reads as 0 bytes, so an empty value
            would be indistinguishable from none), or ``name`` is not valid UTF-16
        :raises RuntimeError: the ring has no key yet
        """
        try:
            if len(memoryview(plaintext)) == 0:
                raise ValueError("An empty value cannot be cached: decrypt reports a missing name as 0 bytes.")

            aad = self.aad_for(name)
            # Resolved on every call, so a value stored after a rotation uses the new key.
            version, key = self._key_ring.get_current()
            return KeyTrackingValue(version, key.encrypt(plaintext, aad=aad))
        finally:
            # Normally already done by the key; this covers a failure before encrypting.
            ArrayUtility.zero_memory(plaintext)

    def _encrypt_text(self, name: str, plaintext: str) -> KeyTrackingValue:
        """:meth:`_encrypt` for text, as UTF-8; the ``bytearray`` it is encoded into is zeroed on every
        path. ``plaintext`` and the temporary ``bytes`` made while encoding it are immutable and are not."""
        if not plaintext:
            raise ValueError("An empty value cannot be cached: decrypt reports a missing name as 0 bytes.")
        encoded = Utf8.encode(plaintext)
        try:
            return self._encrypt(name, encoded)
        finally:
            ArrayUtility.zero_memory(encoded)

    def _encrypt_any(self, name: str, plaintext: WritableBuffer | str | Buffer) -> KeyTrackingValue:
        """Encrypts a ``str`` as UTF-8 text, or a writable buffer as bytes (zeroing it)."""
        if isinstance(plaintext, str):
            return self._encrypt_text(name, plaintext)
        if isinstance(plaintext, (bytearray, memoryview)):
            return self._encrypt(name, plaintext)
        raise TypeError("plaintext must be a str or a writable buffer (bytearray or memoryview); bytes can't be zeroed.")
