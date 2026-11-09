"""A read-only cache over one JSON file holding every secret, already encrypted."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from hkdfguard.abstractions import (
    ArrayUtility,
    EncryptedFormatProvider,
    JsonReader,
    JsonToken,
    KeyRing,
    KeyTrackingValue,
    MalformedJsonError,
    ProtectedConfigurationPurpose,
    ProtectedReadOnlyCache,
    WritableBuffer,
)
from hkdfguard.cache import FilePerSecretCache, InvalidSecretDataError
from hkdfguard.diagnostics import AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, SpanNames
from hkdfguard.securefile import KeyFileTrust, TrustedFile

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.cache.jsonsecretsfile")

_ROOT_KINDS: Final[dict[JsonToken | None, str]] = {
    JsonToken.START_ARRAY: "an array",
    JsonToken.STRING: "a string",
    JsonToken.NUMBER: "a number",
    JsonToken.TRUE: "true",
    JsonToken.FALSE: "false",
    JsonToken.NULL: "null",
}


class JsonSecretsFileReadOnlyCache(ProtectedReadOnlyCache):
    """A :class:`ProtectedReadOnlyCache` over one JSON file holding every secret, as a pipeline's
    ``SecretPipelineWriter.write_json_secrets`` (``hkdfguard-pipeline``) writes it: a single object
    whose members map each secret's name to its value, already encrypted under the key ring and
    formatted (``enc::v{version}::{base64}``). Nothing is read up front: the first lookup reads the
    whole file, authenticates every value in it, and keeps them - still encrypted, exactly as the
    file holds them - so every later lookup is served from memory without touching the disk.

    **The file is read through** :class:`TrustedFile <hkdfguard.securefile.TrustedFile>`. It is
    refused - with a ``PermissionError``, and nothing kept - unless it and every folder above it are
    owned, and modifiable, only by the operating system's administrators and the principals the
    :class:`KeyFileTrust <hkdfguard.securefile.KeyFileTrust>` adds, with no untrusted symbolic link on
    the way. Add the account that deploys secrets, never the one the application runs as.

    **Every value is bound to its name.** A member's value must be encrypted with the purpose
    ``ProtectedConfigurationPurpose.for_key(name)`` - as ``AesGcmPipelineDataProtector.encrypt(value,
    name)`` writes it - and a value moved under any other name fails authentication. The file is
    delivered as one, so it is loaded as one: a value that fails authentication
    (:class:`AuthenticationTagMismatchError <hkdfguard.abstractions.AuthenticationTagMismatchError>`),
    or names a key version the ring doesn't hold (:class:`KeyNotFoundError
    <hkdfguard.abstractions.KeyNotFoundError>`), fails the whole load, and nothing is kept, so the
    file is read again on the next lookup.

    **The file must be exactly that object** - one member per secret, each name a valid
    FilePerSecretCache name (:meth:`FilePerSecretCache.is_valid_name
    <hkdfguard.cache.FilePerSecretCache.is_valid_name>`), no name twice ignoring case, each value a
    non-empty string, as strict JSON (:class:`JsonReader <hkdfguard.abstractions.JsonReader>`: no
    comments, trailing commas or byte order mark, nothing after the object) - or it is refused with
    an :class:`InvalidSecretDataError <hkdfguard.cache.InvalidSecretDataError>`; a value that isn't a
    formatted value is refused by the format provider (``EncryptedFormatError``). Names are looked up
    ignoring ASCII case, as the values are bound; any name that couldn't be one is reported missing -
    decrypt returns 0 - so the cache can sit in a :class:`ProtectedCacheCollection
    <hkdfguard.cache.ProtectedCacheCollection>` beside sources with other naming rules. A missing file,
    or a missing folder above it, reports every secret missing, and isn't remembered: it is looked for
    again on the next lookup. A file longer than ``max_file_length`` is refused with a
    :class:`FileTooLargeError <hkdfguard.securefile.FileTooLargeError>` (an ``OSError``), reading no
    more than one byte past it; any other failure to read it propagates.

    decrypt and find_max_decrypted_length load the file on the calling thread; decrypt_async and
    find_max_decrypted_length_async load it in a worker thread (:func:`asyncio.to_thread`), so the
    first lookup doesn't block the event loop. One load runs at a time: a lookup made while the file
    is loaded waits for that load, and is served from what it kept. Cancelling the awaiting task stops
    it waiting, but Python can't interrupt a thread, so that load runs on to its end and keeps what it
    loaded.

    The values loaded are kept for the life of the instance: a file changed after it was loaded is
    picked up by a new cache instance. Each value decrypts with the key version it names, so it keeps
    decrypting after a key rotation for as long as the ring holds that version.

    Telemetry: each load of the file is a :attr:`SpanNames.Cache.POPULATE` span on
    :attr:`HkdfGuardTelemetry.CACHE`, counted in :meth:`CacheMetrics.operations` as ``"success"``,
    ``"not_found"`` or ``"error"``; with sensitive logging on, the file's path and each looked-up name
    (never a value) are logged. A failed load is logged as an error.
    """

    DEFAULT_MAX_FILE_LENGTH: Final = 1024 * 1024
    """The longest file read by default, in bytes: room for hundreds of formatted secrets."""

    def __init__(self, file_path: str | os.PathLike[str], trust: KeyFileTrust, key_ring: KeyRing, format_provider: EncryptedFormatProvider,
                 max_file_length: int = DEFAULT_MAX_FILE_LENGTH, *, logger: logging.Logger | None = None) -> None:
        """:param file_path: the JSON file holding the secrets, absolute or relative to the working
            directory
        :param trust: who besides administrators is trusted to have written the file and the folders
            above it; :attr:`KeyFileTrust.ADMINISTRATORS_ONLY` for no one
        :param key_ring: supplies the key each value names; owned by the caller - the cache never
            closes keys
        :param format_provider: parses each formatted value - the same format the values were
            written in
        :param max_file_length: the longest file read, in bytes; the read buffer is this large, so
            keep it close to the largest file expected
        :param logger: receives a debug entry per load while sensitive logging is enabled, and an
            error entry per failed load; ``None`` for the ``hkdfguard.cache.jsonsecretsfile`` logger
        :raises TypeError: ``file_path``, ``trust``, ``key_ring`` or ``format_provider`` is ``None``,
            ``file_path`` isn't a ``str`` path, ``trust`` isn't a ``KeyFileTrust``, or
            ``max_file_length`` isn't an ``int``
        :raises ValueError: ``file_path`` is empty or holds a NUL, or ``max_file_length`` isn't positive
        :raises FileNotFoundError: ``file_path`` doesn't name an existing file
        """
        path = TrustedFile.require_path(file_path, "secrets file")
        TrustedFile.require_trust(trust)
        if key_ring is None:
            raise TypeError("key_ring must not be None.")
        if format_provider is None:
            raise TypeError("format_provider must not be None.")
        if isinstance(max_file_length, bool) or not isinstance(max_file_length, int):
            raise TypeError("max_file_length must be an int.")
        if max_file_length <= 0:
            raise ValueError(f"max_file_length must be positive; it is {max_file_length}.")

        self._file_path: Final = os.path.abspath(path)
        if not os.path.isfile(self._file_path):
            raise FileNotFoundError(f"The secrets file '{self._file_path}' doesn't exist.")

        self._trust = trust
        self._key_ring = key_ring
        self._format_provider = format_provider
        self._max_file_length = max_file_length
        self._logger = logger if logger is not None else _DEFAULT_LOGGER
        # One load at a time; once a load succeeds, its values are kept - by name in lower case,
        # names being ASCII - and the lock is never needed again.
        self._loading = threading.Lock()
        self._values: dict[str, KeyTrackingValue] | None = None

    @property
    def file_path(self) -> str:
        """The full path of the JSON file the secrets are read from."""
        return self._file_path

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """:raises TypeError: ``name`` is ``None``
        :raises AuthenticationTagMismatchError: a value in the file wasn't encrypted for its name, or was altered
        :raises InvalidSecretDataError: the file isn't the secrets object
        :raises EncryptedFormatError: a value in the file isn't a formatted value
        :raises FileTooLargeError: the file is longer than ``max_file_length``
        :raises PermissionError: the file's location isn't trusted, or this account may not read it
        :raises KeyNotFoundError: a value's key version isn't in the ring
        """
        with self._decrypt_span(name):
            value = self._get_value(name)
            return 0 if value is None else self._decrypt_value(name, value, result)

    def find_max_decrypted_length(self, name: str) -> int | None:
        """:raises TypeError: ``name`` is ``None``

        Any failure to load the file raises as :meth:`decrypt` lists.
        """
        value = self._get_value(name)
        return None if value is None else len(value.value)

    async def decrypt_async(self, name: str, result: WritableBuffer) -> int:
        """:meth:`decrypt`, loading the file in a worker thread if it isn't loaded yet.

        :raises TypeError: ``name`` is ``None``
        """
        with self._decrypt_span(name):
            value = await self._get_value_async(name)
            return 0 if value is None else self._decrypt_value(name, value, result)

    async def find_max_decrypted_length_async(self, name: str) -> int | None:
        """:meth:`find_max_decrypted_length`, loading the file in a worker thread if it isn't loaded yet.

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

    @staticmethod
    def _key(name: str) -> str | None:
        # The key name's value is kept under; None if name couldn't be a secret's name. Checked as a
        # FilePerSecretCache name - ASCII only - so lower() folds exactly ASCII case, as names are bound.
        if name is None:
            raise TypeError("name must not be None.")
        return name.lower() if FilePerSecretCache.is_valid_name(name) else None

    def _get_value(self, name: str) -> KeyTrackingValue | None:
        # name's value, loading the file on the first lookup; None if name couldn't be a secret's
        # name, the file is missing, or it holds no value for name.
        key = self._key(name)
        if key is None:
            return None
        values = self._values if self._values is not None else self._load()
        return None if values is None else values.get(key)

    async def _get_value_async(self, name: str) -> KeyTrackingValue | None:
        # _get_value, loading in a worker thread; to_thread copies the context, so the populate span
        # is a child of the decrypt span.
        key = self._key(name)
        if key is None:
            return None
        values = self._values if self._values is not None else await asyncio.to_thread(self._load)
        return None if values is None else values.get(key)

    def _load(self) -> dict[str, KeyTrackingValue] | None:
        # Reads, parses and authenticates the whole file, keeping its values once every one passes;
        # None if the file is missing.
        with self._loading:
            # Another lookup may have loaded it while this one waited.
            if self._values is not None:
                return self._values

            telemetry = HkdfGuardTelemetry.CACHE
            # The span records the exception as it escapes.
            with telemetry.start_span(SpanNames.Cache.POPULATE) as span:
                if telemetry.sensitive_logging_enabled:
                    telemetry.log_sensitive_operation(span, SpanNames.Cache.POPULATE, {AttributeNames.NAME: self._file_path})
                    HkdfGuardLog.sensitive_operation_logged(self._logger, SpanNames.Cache.POPULATE, self._file_path)

                try:
                    contents = self._read()
                    if contents is None:
                        _record_operation("not_found")
                        return None

                    try:
                        values = self._parse(contents)
                    finally:
                        ArrayUtility.zero_memory(contents)
                    for key, value in values.items():
                        self._authenticate(key, value)

                    _record_operation("success")
                    self._values = values
                    return values
                except Exception as exception:
                    HkdfGuardLog.operation_failed(self._logger, SpanNames.Cache.POPULATE, exception)
                    _record_operation("error")
                    raise

    def _read(self) -> bytearray | None:
        # The file's contents from TrustedFile; None if the file or a folder above it doesn't exist.
        # The contents are values encrypted elsewhere, not secrets, but the buffer is zeroed all the same.
        try:
            return TrustedFile.read(self._file_path, self._trust, self._max_file_length)
        except FileNotFoundError:
            return None

    def _parse(self, contents: bytearray) -> dict[str, KeyTrackingValue]:
        # The secrets object's members, by name in lower case, each value parsed but not yet authenticated.
        values: dict[str, KeyTrackingValue] = {}
        reader = JsonReader(contents)
        try:
            if not reader.read():
                raise self._invalid("isn't valid JSON: it is empty")
            token = reader.token()
            if token is not JsonToken.START_OBJECT:
                raise self._invalid(f"holds {_ROOT_KINDS.get(token, 'a value')}, not an object of secrets")

            # The reader raises on anything malformed or incomplete, so inside the object each token
            # read is a member's name or the object's end, and after a name, its value.
            while True:
                reader.read()
                if reader.token() is JsonToken.END_OBJECT:
                    break

                name = reader.get_string()
                if not FilePerSecretCache.is_valid_name(name):
                    raise self._invalid(f"names a secret '{name}', which isn't a secret's name")

                reader.read()
                encrypted = reader.get_string().strip() if reader.token() is JsonToken.STRING else ""
                if not encrypted:
                    raise self._invalid(f"holds no value for '{name}': each must be a non-empty string")
                value = self._format_provider.parse(encrypted)
                key = name.lower()
                if key in values:
                    raise self._invalid(f"names '{name}' more than once")
                values[key] = value

            # Anything after the object - a second value, stray text - raises here.
            reader.read()
        except MalformedJsonError as error:
            # It says where, never quotes what; chaining it would add nothing.
            raise self._invalid(f"isn't valid JSON: {error}") from None
        return values

    def _invalid(self, problem: str) -> InvalidSecretDataError:
        return InvalidSecretDataError(f"The secrets file '{self._file_path}' {problem.rstrip('.')}.")

    def _authenticate(self, key: str, value: KeyTrackingValue) -> None:
        # Decrypts value once into a buffer that is zeroed at once, so only values that authenticate
        # under their names - and key versions the ring holds - are ever kept. AEAD ciphertext is never
        # shorter than its plaintext, so the buffer is always large enough; the AAD ignores ASCII case,
        # so the name in lower case binds as it was spelled.
        plaintext = bytearray(len(value.value))
        try:
            self._decrypt_value(key, value, plaintext)
        finally:
            ArrayUtility.zero_memory(plaintext)


def _record_operation(result: str) -> None:
    CacheMetrics.operations().add(1, {AttributeNames.OPERATION_NAME: SpanNames.Cache.POPULATE, AttributeNames.RESULT: result})
