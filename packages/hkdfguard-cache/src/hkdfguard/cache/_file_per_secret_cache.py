"""A read-only cache over a folder holding one already encrypted file per secret."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from hkdfguard.abstractions import (
    ArrayUtility,
    EncryptedFormatProvider,
    KeyRing,
    KeyTrackingValue,
    ProtectedConfigurationPurpose,
    ProtectedReadOnlyCache,
    WritableBuffer,
)
from hkdfguard.diagnostics import AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, SpanNames
from hkdfguard.securefile import KeyFileTrust, TrustedFile

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.cache")

_NAME: Final = re.compile(r"[A-Za-z0-9._-]+")
"""The characters a name may hold: ASCII letters, digits, '-', '_' and '.'."""


class FilePerSecretCache(ProtectedReadOnlyCache):
    """A :class:`ProtectedReadOnlyCache` over a folder on the local filesystem holding one file per
    secret: the file named ``name`` holds that secret's value, already encrypted under the key ring
    and formatted (``enc::v{version}::{base64}``). Nothing is read up front: the first lookup of a
    name reads that one file, authenticates its value, and caches it - still encrypted, exactly as the
    file holds it - so every later lookup is served from memory without touching the disk.
    Surrounding whitespace in a file, such as a trailing newline, is ignored.

    **Every file is read through** :class:`TrustedFile <hkdfguard.securefile.TrustedFile>`. It is
    refused - with a ``PermissionError``, and not cached - unless it and every folder above it are
    owned, and modifiable, only by the operating system's administrators and the principals the
    :class:`KeyFileTrust <hkdfguard.securefile.KeyFileTrust>` adds, with no untrusted symbolic link on
    the way. Add the account that deploys secrets, never the one the application runs as.

    **Every value is bound to its name.** A file's value must be encrypted with the purpose
    ``ProtectedConfigurationPurpose.for_key(name)`` - as ``AesGcmPipelineDataProtector.encrypt(value,
    name)``, or ``ring.create_protector(ProtectedConfigurationPurpose.for_key(name))``, writes it - and
    a file copied under any other name fails authentication with an
    :class:`AuthenticationTagMismatchError <hkdfguard.abstractions.AuthenticationTagMismatchError>`
    when it is loaded, rather than decrypting as that name's value. A file that fails is not cached,
    so it is read again on the next lookup.

    A name is a file name: 1-:attr:`MAX_NAME_LENGTH` ASCII letters, digits, ``-``, ``_`` and ``.``,
    not starting with ``.`` (see :meth:`is_valid_name`), so it can never reach outside the folder. Any
    other name, a missing file, a missing folder and an empty file are all reported missing - decrypt
    returns 0 - so the cache can sit in a :class:`ProtectedCacheCollection
    <hkdfguard.cache.ProtectedCacheCollection>` beside sources with other naming rules. A missing
    secret isn't remembered: its file is looked for again on the next lookup. Unlike the other caches,
    names are matched exactly, since each spelling is bound - and authenticated - separately; files
    are found as the filesystem finds them: exactly on Linux, ignoring case on Windows and, by
    default, macOS. A file longer than :attr:`MAX_FILE_LENGTH` bytes is refused with a
    :class:`FileTooLargeError <hkdfguard.securefile.FileTooLargeError>` (an ``OSError``), reading no
    more than one byte past that; any other failure to read or parse it propagates, and nothing is
    cached.

    decrypt and find_max_decrypted_length read a file on the calling thread; decrypt_async and
    find_max_decrypted_length_async read it in a worker thread (:func:`asyncio.to_thread`), so a miss
    doesn't block the event loop. Cancelling the awaiting task stops it waiting, but Python can't
    interrupt a thread, so that read runs on to its end and caches what it loaded. Concurrent misses
    on one name may each read the file; the first value stored is kept.

    A cached value is kept for the life of the instance: a file changed after its secret was loaded
    is picked up by a new cache instance. Each value decrypts with the key version it names, so it
    keeps decrypting after a key rotation for as long as the ring holds that version.

    Telemetry: each file load is a :attr:`SpanNames.Cache.POPULATE` span on
    :attr:`HkdfGuardTelemetry.CACHE`, counted in :meth:`CacheMetrics.operations` as ``"success"``,
    ``"not_found"`` or ``"error"``; with sensitive logging on, the secret's name (never a value) is
    logged. A failed load is logged as an error.
    """

    MAX_NAME_LENGTH: Final = 255
    """The longest name a secret's file can have."""

    MAX_FILE_LENGTH: Final = 64 * 1024
    """The longest file, in bytes, that is read: room for a formatted secret of about 48 KB."""

    def __init__(self, folder_path: str | os.PathLike[str], trust: KeyFileTrust, key_ring: KeyRing, format_provider: EncryptedFormatProvider,
                 logger: logging.Logger | None = None) -> None:
        """:param folder_path: the folder holding one file per secret, absolute or relative to the
            working directory
        :param trust: who besides administrators is trusted to have written the folder and its files;
            :attr:`KeyFileTrust.ADMINISTRATORS_ONLY` for no one
        :param key_ring: supplies the key each file's value names; owned by the caller - the cache
            never closes keys
        :param format_provider: parses each file's formatted value - the same format the values were
            written in
        :param logger: receives a debug entry per loaded name while sensitive logging is enabled, and
            an error entry per failed load; ``None`` for the ``hkdfguard.cache`` logger
        :raises TypeError: ``folder_path``, ``trust``, ``key_ring`` or ``format_provider`` is ``None``,
            or ``folder_path`` isn't a ``str`` path, or ``trust`` isn't a ``KeyFileTrust``
        :raises ValueError: ``folder_path`` is empty or holds a NUL
        :raises FileNotFoundError: ``folder_path`` doesn't name an existing folder
        """
        folder = TrustedFile.require_path(folder_path, "secrets folder")
        TrustedFile.require_trust(trust)
        if key_ring is None:
            raise TypeError("key_ring must not be None.")
        if format_provider is None:
            raise TypeError("format_provider must not be None.")

        self._folder_path: Final = os.path.abspath(folder)
        if not os.path.isdir(self._folder_path):
            raise FileNotFoundError(f"The secrets folder '{self._folder_path}' doesn't exist.")

        self._trust = trust
        self._key_ring = key_ring
        self._format_provider = format_provider
        self._logger = logger if logger is not None else _DEFAULT_LOGGER
        # Each loaded secret's value as its file held it: encrypted, bound to its name. Exact names,
        # since each spelling is bound - and authenticated - separately.
        self._values: dict[str, KeyTrackingValue] = {}
        self._lock = threading.Lock()

    @property
    def folder_path(self) -> str:
        """The full path of the folder the secrets' files are read from."""
        return self._folder_path

    @staticmethod
    def is_valid_name(name: str | None) -> bool:
        """Whether ``name`` can be a secret's file name: 1-:attr:`MAX_NAME_LENGTH` ASCII letters,
        digits, ``-``, ``_`` and ``.``, not starting with ``.``."""
        return (isinstance(name, str)
                and 0 < len(name) <= FilePerSecretCache.MAX_NAME_LENGTH
                and not name.startswith(".")
                and _NAME.fullmatch(name) is not None)

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """:raises TypeError: ``name`` is ``None``
        :raises AuthenticationTagMismatchError: the file's value wasn't encrypted for this name, or was altered
        :raises PermissionError: the file's location isn't trusted, or this account may not read it
        :raises KeyNotFoundError: the value's key version is no longer in the ring
        :raises FileTooLargeError: the file is longer than :attr:`MAX_FILE_LENGTH`
        :raises EncryptedFormatError: the file doesn't hold a formatted value
        """
        with self._decrypt_span(name):
            value = self._get_value(name)
            return 0 if value is None else self._decrypt_value(name, value, result)

    def find_max_decrypted_length(self, name: str) -> int | None:
        """:raises TypeError: ``name`` is ``None``
        :raises AuthenticationTagMismatchError: the file's value wasn't encrypted for this name, or was altered
        :raises PermissionError: the file's location isn't trusted, or this account may not read it
        """
        value = self._get_value(name)
        return None if value is None else len(value.value)

    async def decrypt_async(self, name: str, result: WritableBuffer) -> int:
        """:meth:`decrypt`, reading a file not yet loaded in a worker thread.

        :raises TypeError: ``name`` is ``None``
        """
        with self._decrypt_span(name):
            value = await self._get_value_async(name)
            return 0 if value is None else self._decrypt_value(name, value, result)

    async def find_max_decrypted_length_async(self, name: str) -> int | None:
        """:meth:`find_max_decrypted_length`, reading a file not yet loaded in a worker thread.

        :raises TypeError: ``name`` is ``None``
        """
        value = await self._get_value_async(name)
        return None if value is None else len(value.value)

    @contextmanager
    def _decrypt_span(self, name: str) -> Iterator[None]:
        # Current across an await too: OpenTelemetry's context lives in contextvars, which follow the task.
        telemetry = HkdfGuardTelemetry.CACHE
        with telemetry.start_span(SpanNames.Cache.DECRYPT) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.Cache.DECRYPT, {AttributeNames.NAME: str(name)})
            yield

    def _decrypt_value(self, name: str, value: KeyTrackingValue, result: WritableBuffer) -> int:
        return self._key_ring.get(value.key_version).decrypt(value.value, result, aad=ProtectedConfigurationPurpose.aad_for(name))

    def _cached(self, name: str) -> KeyTrackingValue | None:
        if name is None:
            raise TypeError("name must not be None.")
        with self._lock:
            return self._values.get(name)

    def _get_value(self, name: str) -> KeyTrackingValue | None:
        # The cached value for name, loading it from its file on a miss; None if name can't be a file
        # name or there is no value.
        cached = self._cached(name)
        if cached is not None or not self.is_valid_name(name):
            return cached
        return self._load(name)

    async def _get_value_async(self, name: str) -> KeyTrackingValue | None:
        # _get_value, loading in a worker thread; to_thread copies the context, so the populate span
        # is a child of the decrypt span.
        cached = self._cached(name)
        if cached is not None or not self.is_valid_name(name):
            return cached
        return await asyncio.to_thread(self._load, name)

    def _load(self, name: str) -> KeyTrackingValue | None:
        # Reads, parses and authenticates name's file, caching its value; None if there is none.
        # Concurrent misses may each load the file; the first stored is kept.
        telemetry = HkdfGuardTelemetry.CACHE
        # The span records the exception as it escapes.
        with telemetry.start_span(SpanNames.Cache.POPULATE) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.Cache.POPULATE, {AttributeNames.NAME: name})
                HkdfGuardLog.sensitive_operation_logged(self._logger, SpanNames.Cache.POPULATE, name)

            try:
                encrypted = self._read(name)
                if encrypted is None:
                    _record_operation("not_found")
                    return None

                value = self._format_provider.parse(encrypted)
                self._authenticate(name, value)
                with self._lock:
                    stored = self._values.setdefault(name, value)
                _record_operation("success")
                return stored
            except Exception as exception:
                HkdfGuardLog.operation_failed(self._logger, SpanNames.Cache.POPULATE, exception)
                _record_operation("error")
                raise

    def _authenticate(self, name: str, value: KeyTrackingValue) -> None:
        # Decrypts value once into a buffer that is zeroed at once, so only a value that authenticates
        # under name - and a key version the ring holds - is ever cached. AEAD ciphertext is never
        # shorter than its plaintext, so the buffer is always large enough.
        plaintext = bytearray(len(value.value))
        try:
            self._decrypt_value(name, value, plaintext)
        finally:
            ArrayUtility.zero_memory(plaintext)

    def _read(self, name: str) -> str | None:
        # The secret's formatted value from its trusted file, trimmed; None if the file or folder
        # doesn't exist, or the file is empty. The contents are a value encrypted elsewhere, not a
        # secret, but the buffer is zeroed all the same.
        try:
            contents = TrustedFile.read(os.path.join(self._folder_path, name), self._trust, self.MAX_FILE_LENGTH)
        except FileNotFoundError:
            return None

        try:
            # Malformed UTF-8 becomes U+FFFD, as in .NET, which the format provider then refuses.
            encrypted = contents.decode("utf-8", errors="replace").strip()
        finally:
            ArrayUtility.zero_memory(contents)
        return encrypted or None


def _record_operation(result: str) -> None:
    CacheMetrics.operations().add(1, {AttributeNames.OPERATION_NAME: SpanNames.Cache.POPULATE, AttributeNames.RESULT: result})
