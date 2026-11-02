"""The shared plumbing of a cache over a remote secret store, and the sink a fetch hands values to."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from abc import abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from enum import Enum
from typing import ClassVar, Final

from hkdfguard.abstractions import ArrayUtility, KeyRing, KeyTrackingValue, ProtectedCacheBase, ProtectedReadOnlyCache, Utf8, WritableBuffer
from hkdfguard.cache import _secret_names
from hkdfguard.cache._secret_json_keys import try_set_keys
from hkdfguard.diagnostics import AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, SpanNames, record_exception
from opentelemetry.trace import Span

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.cache")


class SecretNameMatching(Enum):
    """How a :class:`RemoteSecretCache` matches names, which must be how its secret store does."""

    IGNORE_ASCII_CASE = "ignore_ascii_case"
    """Names differing only in ASCII case are one secret (e.g. Azure Key Vault)."""

    EXACT = "exact"
    """Names are matched exactly; names differing in case are different secrets (e.g. AWS Secrets
    Manager, Google Secret Manager). A name holding ``!`` is reported missing without a fetch - none
    of those stores allow it, and it marks case in entry names (see :class:`RemoteSecretCache`)."""


class RemoteSecretCache(ProtectedReadOnlyCache):
    """The shared plumbing of a :class:`ProtectedReadOnlyCache` over a remote secret store: nothing
    is fetched up front; the first decrypt/find_max_decrypted_length for a name that isn't cached yet
    calls :meth:`_fetch` for that one secret, encrypts every value it hands over under the ring's
    current key, and caches the ciphertext; every later lookup is served from the cache. A subclass
    supplies only :meth:`_is_valid_name` and :meth:`_fetch` - one call that reads one secret by name,
    never a listing.

    A name is a secret's name, optionally followed by :attr:`KEY_SEPARATOR` and a key:
    ``"app-config#api-key"`` is the api-key key of the secret app-config, which :meth:`_fetch` hands
    over with :meth:`SecretValueSink.set_key_bytes` (or, for a secret holding a JSON object,
    :meth:`SecretValueSink.set_bytes_with_json_keys`), and ``"app-config"`` is the secret's whole
    value, or its :meth:`_default_key` where the store has one. One fetch caches the whole value and
    every key it hands over, so the first lookup of any of them fetches the secret once and the rest
    are already cached. A key is 1-:attr:`MAX_KEY_LENGTH` printable ASCII characters other than
    space, ``!`` and ``#`` (see :meth:`is_valid_key`), and is matched exactly whatever the store's
    matching.

    A name whose secret :meth:`_is_valid_name` rejects, or whose key isn't one, is reported missing
    without a fetch, so a cache can sit in a ProtectedCacheCollection beside sources with other
    naming rules. A name the fetch hands no value for, or an empty one, is reported missing - decrypt
    returns 0 - and isn't remembered, so it is fetched again on the next request (a key a cached
    secret doesn't hold costs a fetch every time). An exception from :meth:`_fetch` propagates to the
    caller unchanged, and nothing that fetch handed over is cached. Concurrent lookups of the same
    uncached secret - of any of its keys or spellings, from any thread, task or event loop,
    synchronous or asynchronous - share one fetch. A cached value is kept for the life of the
    instance: a later fetch of the same secret adds keys that weren't cached yet, but never replaces
    one that was.

    decrypt_async and find_max_decrypted_length_async fetch through :meth:`_fetch_async`, which a
    store with an asyncio client overrides, so a miss doesn't block the event loop; decrypt and
    find_max_decrypted_length fetch through :meth:`_fetch`, blocking the calling thread until it
    returns (so never call them from a coroutine). Cancelling the task awaiting a lookup cancels the
    fetch only if that lookup started it; a lookup whose shared fetch was cancelled by the lookup that
    started it starts a new one. A fetch raising :class:`asyncio.CancelledError` of its own (its
    task not being cancelled) fails the lookup with a ``RuntimeError`` caused by it, rather than
    reading as the caller's cancellation.

    Encryption, name binding and key rotation are :class:`ProtectedCacheBase`'s. It matches names
    ignoring ASCII case, so keys - and, under :attr:`SecretNameMatching.EXACT`, secret names - are
    stored there under a case-escaped spelling: every upper-case ASCII letter becomes ``!`` and its
    lower-case form, so ``"prod/Db"`` and ``"prod/db"`` are different entries, each bound to its own
    spelling.

    Telemetry: each fetch is a :attr:`SpanNames.Cache.POPULATE` span on
    :attr:`HkdfGuardTelemetry.CACHE`, counted in :meth:`CacheMetrics.operations` as ``"success"``,
    ``"not_found"`` or ``"error"``; with sensitive logging on, the secret's name (never a value) is
    logged. A failed fetch is logged as an error.
    """

    KEY_SEPARATOR: ClassVar[str] = _secret_names.KEY_SEPARATOR
    """Separates a secret's name from a key it holds: ``"app-config#api-key"``."""

    MAX_KEY_LENGTH: ClassVar[int] = _secret_names.MAX_KEY_LENGTH
    """The longest key a name can hold."""

    def __init__(self, key_ring: KeyRing, matching: SecretNameMatching, logger: logging.Logger | None = None) -> None:
        """:param key_ring: supplies the key every fetched secret is encrypted under; owned by the
            caller - the cache never closes keys
        :param matching: how the secret store matches names
        :param logger: receives a debug entry per fetched name while sensitive logging is enabled,
            and an error entry per failed fetch; ``None`` for the ``hkdfguard.cache`` logger
        :raises TypeError: ``key_ring`` or ``matching`` is ``None``
        """
        if matching is None:
            raise TypeError("matching must not be None.")
        self._store = _Store(self, key_ring)
        self._matching = matching
        self._logger = logger if logger is not None else _DEFAULT_LOGGER

    def _default_key(self) -> str | None:
        """The key a name without one reads, for a store whose secrets are all sets of keys
        (HashiCorp Vault's KV); ``None`` - the default - when such a name reads the secret's whole
        value."""
        return None

    @abstractmethod
    def _is_valid_name(self, name: str) -> bool:
        """Whether the secret store can hold a secret named ``name``; a name it can't is never fetched."""

    @abstractmethod
    def _fetch(self, name: str, value: SecretValueSink) -> None:
        """Reads the one secret named ``name`` and hands its current value, and any keys it holds, to
        ``value`` - or returns without doing so if it doesn't exist. Any other failure should raise.
        Called only for a name :meth:`_is_valid_name` accepts, and never while another fetch of the
        same secret is running.
        """

    async def _fetch_async(self, name: str, value: SecretValueSink) -> None:
        """:meth:`_fetch` without blocking the event loop, for decrypt_async and
        find_max_decrypted_length_async. The default runs _fetch in a worker thread
        (:func:`asyncio.to_thread`); a store with an asyncio client overrides it. Cancelling the
        lookup that started the fetch cancels this coroutine - but Python can't interrupt a thread,
        so the default's _fetch runs on to its end, and anything it hands to ``value`` once this has
        been cancelled is refused, never cached.
        """
        await asyncio.to_thread(self._fetch, name, value)

    @staticmethod
    def is_valid_key(key: str | None) -> bool:
        """Whether ``key`` can follow :attr:`KEY_SEPARATOR` in a name: 1-:attr:`MAX_KEY_LENGTH`
        printable ASCII characters other than space, ``!`` and ``#``."""
        return _secret_names.is_valid_key(key)

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """:raises TypeError: ``name`` is ``None``"""
        entry_name = self._entry_name_for(name)
        return 0 if entry_name is None else self._store.decrypt(entry_name, result)

    def find_max_decrypted_length(self, name: str) -> int | None:
        """:raises TypeError: ``name`` is ``None``"""
        entry_name = self._entry_name_for(name)
        return None if entry_name is None else self._store.find_max_decrypted_length(entry_name)

    async def decrypt_async(self, name: str, result: WritableBuffer) -> int:
        """:raises TypeError: ``name`` is ``None``"""
        entry_name = self._entry_name_for(name)
        return 0 if entry_name is None else await self._store.decrypt_async(entry_name, result)

    async def find_max_decrypted_length_async(self, name: str) -> int | None:
        """:raises TypeError: ``name`` is ``None``"""
        entry_name = self._entry_name_for(name)
        return None if entry_name is None else await self._store.find_max_decrypted_length_async(entry_name)

    def _entry_name_for(self, name: str) -> str | None:
        # The entry a name is stored under - its secret's entry name, then '#' and the case-escaped
        # key, if any - or None if the name is missing without a fetch.
        if name is None:
            raise TypeError("name must not be None.")

        secret_name, separator, key_part = name.partition(_secret_names.KEY_SEPARATOR)
        key = key_part if separator else self._default_key()
        exact = self._matching is SecretNameMatching.EXACT
        if ((key is not None and not _secret_names.is_valid_key(key))
                or not self._is_valid_name(secret_name)
                or (exact and _secret_names.UPPER_CASE_MARKER in secret_name)):
            return None

        secret_entry_name = _secret_names.entry_name(secret_name) if exact else secret_name
        return secret_entry_name if key is None else secret_entry_name + _secret_names.KEY_SEPARATOR + _secret_names.entry_name(key)

    def _secret_name_of(self, secret_entry_name: str) -> str:
        return _secret_names.secret_name(secret_entry_name) if self._matching is SecretNameMatching.EXACT else secret_entry_name

    def _populate(self, secret_entry_name: str) -> bool:
        # Fetches the secret stored under secret_entry_name through _fetch, caching everything handed
        # over; False if nothing was.
        secret_name = self._secret_name_of(secret_entry_name)
        with self._populate_span(secret_name) as span:
            sink = SecretValueSink(self._store, secret_entry_name)
            try:
                self._fetch(secret_name, sink)
                return self._cache(sink)
            except BaseException as exception:
                self._fail(sink, span, exception)
                raise

    async def _populate_async(self, secret_entry_name: str) -> bool:
        # _populate through _fetch_async. Raises CancelledError only when the lookup is being
        # cancelled; a fetch's own CancelledError is a failure.
        secret_name = self._secret_name_of(secret_entry_name)
        with self._populate_span(secret_name) as span:
            sink = SecretValueSink(self._store, secret_entry_name)
            try:
                await self._fetch_async(secret_name, sink)
                return self._cache(sink)
            except asyncio.CancelledError as cancelled:
                if _being_cancelled():
                    self._fail(sink, span, cancelled)
                    raise
                failure = RuntimeError("The fetch was cancelled, though the lookup was not.")
                self._fail(sink, span, failure)
                raise failure from cancelled
            except BaseException as exception:
                self._fail(sink, span, exception)
                raise

    @contextmanager
    def _populate_span(self, secret_name: str) -> Iterator[Span]:
        # Exceptions are recorded by _fail, not as they escape, so a cancellation is recorded too.
        telemetry = HkdfGuardTelemetry.CACHE
        with telemetry.tracer.start_as_current_span(SpanNames.Cache.POPULATE, record_exception=False, set_status_on_exception=False) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.Cache.POPULATE, {AttributeNames.NAME: secret_name})
                HkdfGuardLog.sensitive_operation_logged(self._logger, SpanNames.Cache.POPULATE, secret_name)
            yield span

    def _cache(self, sink: SecretValueSink) -> bool:
        # Closes the sink and caches what it holds; False if it holds nothing.
        values = sink._close()
        if not values:
            _record_operation("not_found")
            return False

        # A fetch that began just after another finished may find values already stored; keep those.
        for entry_name, value in values.items():
            self._store._put_entry_if_absent(entry_name, value)
        _record_operation("success")
        return True

    def _fail(self, sink: SecretValueSink, span: Span, exception: BaseException) -> None:
        sink._close()
        record_exception(span, exception)
        HkdfGuardLog.operation_failed(self._logger, SpanNames.Cache.POPULATE, exception)
        _record_operation("error")


def _record_operation(result: str) -> None:
    CacheMetrics.operations().add(1, {AttributeNames.OPERATION_NAME: SpanNames.Cache.POPULATE, AttributeNames.RESULT: result})


def _being_cancelled() -> bool:
    # Whether the running task has been asked to cancel - by the caller, or a timeout around it.
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


class _Store(ProtectedCacheBase):
    """The entries, keyed by entry name, and the fetches filling them."""

    def __init__(self, owner: RemoteSecretCache, key_ring: KeyRing) -> None:
        super().__init__(key_ring)
        self._owner = owner
        # One fetch per uncached secret at a time, whichever of its names was asked for and however,
        # keyed by the secret's canonical entry name; removed once it completes, whatever the outcome.
        # concurrent.futures.Future, so threads and every event loop can share one.
        self._fetches: dict[str, concurrent.futures.Future[bool]] = {}
        self._fetches_lock = threading.Lock()

    def _encrypt_entry(self, entry_name: str, plaintext: WritableBuffer) -> KeyTrackingValue:
        return self._encrypt(entry_name, plaintext)

    def _try_populate(self, name: str) -> bool:
        # Fetches the secret name belongs to, or waits for the fetch already running;
        # ProtectedCacheBase then looks name up again.
        secret_entry_name = _secret_part(name)
        key = self._canonical_name(secret_entry_name)
        while True:
            fetch, started = self._start_or_join(key)
            if not started:
                try:
                    return fetch.result()
                except concurrent.futures.CancelledError:
                    if not fetch.cancelled():
                        raise
                # Cancelled by the lookup that started it: fetch again.
                self._forget(key, fetch)
                continue

            try:
                populated = self._owner._populate(secret_entry_name)
            except BaseException as exception:
                self._fail(key, fetch, exception)
                raise
            self._complete(key, fetch, populated)
            return populated

    async def _try_populate_async(self, name: str) -> bool:
        # As _try_populate, without blocking. The lookup that starts a fetch runs it in its own task,
        # so cancelling that lookup cancels the fetch, and the shared future, so its waiters start
        # their own; every other lookup awaits the shared future shielded, so cancelling it only stops
        # that lookup waiting.
        secret_entry_name = _secret_part(name)
        key = self._canonical_name(secret_entry_name)
        fetch, started = self._start_or_join(key)
        if not started:
            return await self._join(name, key, fetch)

        try:
            populated = await self._owner._populate_async(secret_entry_name)
        except asyncio.CancelledError:
            self._forget(key, fetch)
            fetch.cancel()
            raise
        except BaseException as exception:
            self._fail(key, fetch, exception)
            raise
        self._complete(key, fetch, populated)
        return populated

    async def _join(self, name: str, key: str, running: concurrent.futures.Future[bool]) -> bool:
        try:
            return await asyncio.shield(asyncio.wrap_future(running))
        except asyncio.CancelledError:
            if _being_cancelled() or not running.cancelled():
                raise
        # Cancelled by the lookup that started it: fetch again, unless this one has stopped waiting too.
        self._forget(key, running)
        return await self._try_populate_async(name)

    def _start_or_join(self, key: str) -> tuple[concurrent.futures.Future[bool], bool]:
        # The fetch already running for key and False, or a new one this caller has registered - and
        # must run - and True.
        with self._fetches_lock:
            running = self._fetches.get(key)
            if running is not None:
                return running, False
            fetch: concurrent.futures.Future[bool] = concurrent.futures.Future()
            self._fetches[key] = fetch
            return fetch, True

    def _complete(self, key: str, fetch: concurrent.futures.Future[bool], populated: bool) -> None:
        self._forget(key, fetch)
        fetch.set_result(populated)

    def _fail(self, key: str, fetch: concurrent.futures.Future[bool], exception: BaseException) -> None:
        self._forget(key, fetch)
        fetch.set_exception(exception)

    def _forget(self, key: str, fetch: concurrent.futures.Future[bool]) -> None:
        with self._fetches_lock:
            if self._fetches.get(key) is fetch:
                del self._fetches[key]


def _secret_part(entry_name: str) -> str:
    return entry_name.partition(_secret_names.KEY_SEPARATOR)[0]


class SecretValueSink:
    """Receives what :meth:`RemoteSecretCache._fetch` read, and encrypts each value at once, bound
    to its own name within the secret being fetched - nothing else can be stored through it, and it
    refuses every call once that fetch has returned (or been cancelled). Set the secret's whole value
    at most once, and each key at most once; an empty value counts as none. Thread-safe, so a fetch
    may hand values over from whichever thread its client answers on.

    Values go in as a ``bytearray`` (or a writable ``memoryview`` over one), which is zeroed as a
    side effect - immutable ``bytes`` can't be zeroed, so they are refused with ``TypeError``; a
    provider holding a secret in ``bytes`` has already lost the ability to erase it, and should take
    it out of the response before it becomes one (see :class:`SecretJsonBody`).

    Created by the cache for each fetch; never construct one.
    """

    def __init__(self, store: _Store, secret_entry_name: str) -> None:
        self._store = store
        self._secret_entry_name = secret_entry_name
        self._values: dict[str, KeyTrackingValue] = {}
        self._closed = False
        # Reentrant: set_bytes_with_json_keys sets keys and then the whole value.
        self._lock = threading.RLock()

    def set_bytes(self, plaintext: WritableBuffer) -> None:
        """Encrypts ``plaintext`` as the secret's whole value. ``plaintext`` is zeroed as a side effect.

        :raises TypeError: ``plaintext`` isn't a writable buffer
        :raises RuntimeError: the value was already set, or the fetch has returned
        """
        _require_writable(plaintext)
        with self._lock:
            self._set(self._secret_entry_name, plaintext)

    def set_text(self, text: str) -> None:
        """Encrypts ``text``'s UTF-8 bytes as the secret's whole value. The bytearray it is encoded
        into is zeroed once encrypted; ``text`` itself, and the temporary ``bytes`` CPython makes
        while encoding it, are immutable and are not - prefer :meth:`set_bytes` for a secret.

        :raises RuntimeError: the value was already set, or the fetch has returned
        """
        with self._lock:
            self._ensure_unset(self._secret_entry_name)
            self._set(self._secret_entry_name, Utf8.encode(text))

    def set_key_bytes(self, key: str, plaintext: WritableBuffer) -> None:
        """Encrypts ``plaintext`` as the value of one key the secret holds - looked up as
        ``"name#key"``. ``plaintext`` is zeroed as a side effect, even when it is refused.

        :raises TypeError: ``plaintext`` isn't a writable buffer
        :raises ValueError: ``key`` isn't one a name can hold (see :meth:`RemoteSecretCache.is_valid_key`)
        :raises RuntimeError: that key was already set, or the fetch has returned
        """
        _require_writable(plaintext)
        with self._lock:
            try:
                if not _secret_names.is_valid_key(key):
                    raise ValueError(f"'{key}' isn't a key: 1-{_secret_names.MAX_KEY_LENGTH} printable ASCII characters other than space, '!' and '#'.")
                self._set(self._secret_entry_name + _secret_names.KEY_SEPARATOR + _secret_names.entry_name(key), plaintext)
            finally:
                ArrayUtility.zero_memory(plaintext)

    def set_bytes_with_json_keys(self, plaintext: WritableBuffer) -> None:
        """Encrypts ``plaintext`` as the secret's whole value and, when it is a JSON object - such as
        an AWS Secrets Manager key/value secret - each of its top-level members as a key: a string as
        its UTF-8 bytes, a number, true or false as its JSON text. A member that is null, an object or
        an array, or whose name isn't a key a name can hold, is left out. Anything that isn't a JSON
        object - plain text, an array, malformed JSON - is the whole value only. ``plaintext`` is
        zeroed as a side effect, and every buffer a member was unescaped into is zeroed once
        encrypted. The JSON is read in place, never as a ``str``.

        :raises TypeError: ``plaintext`` isn't a writable buffer
        :raises InvalidSecretDataError: the JSON object holds a member name more than once
        :raises RuntimeError: the value or a key was already set, or the fetch has returned
        """
        _require_writable(plaintext)
        with self._lock:
            try:
                try_set_keys(plaintext, self)
                self.set_bytes(plaintext)
            finally:
                ArrayUtility.zero_memory(plaintext)

    def _close(self) -> dict[str, KeyTrackingValue]:
        # Refuses every later call, and returns every value set, by the entry name it was encrypted under.
        with self._lock:
            self._closed = True
            return dict(self._values)

    def _set(self, entry_name: str, plaintext: WritableBuffer) -> None:
        try:
            self._ensure_unset(entry_name)
            if memoryview(plaintext).nbytes > 0:
                self._values[entry_name] = self._store._encrypt_entry(entry_name, plaintext)
        finally:
            ArrayUtility.zero_memory(plaintext)

    def _ensure_unset(self, entry_name: str) -> None:
        if self._closed:
            raise RuntimeError("The fetch this value belongs to has already returned.")
        if entry_name in self._values:
            raise RuntimeError("A value has already been set for this secret or key.")


def _require_writable(plaintext: object) -> None:
    if not isinstance(plaintext, (bytearray, memoryview)) or memoryview(plaintext).readonly:
        raise TypeError("plaintext must be a writable buffer (bytearray or memoryview); bytes can't be zeroed.")
