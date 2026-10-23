"""The AES-256-GCM crypto provider and its factory."""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from collections.abc import Buffer, Callable
from typing import TYPE_CHECKING, Final

from hkdfguard.abstractions import (
    ArrayUtility,
    CryptographicError,
    CryptoProvider,
    CryptoProviderFactory,
    KeyWrapper,
    ObjectClosedError,
    RefreshFailurePolicy,
    WrappedKeyLimits,
    WritableBuffer,
)
from hkdfguard.cryptoprovider.aesgcm256._session import KEY_LENGTH, NONCE_SIZE, TAG_SIZE, AesGcmCryptoSession, EncryptionBudget
from hkdfguard.diagnostics import AttributeNames, EventNames, HkdfGuardLog, HkdfGuardTelemetry, SpanNames, record_exception

if TYPE_CHECKING:
    from opentelemetry.trace import Span

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.cryptoprovider.aesgcm256")


def _validate(expiry_seconds: int, max_refresh_failures: int | None) -> None:
    if not 1 <= expiry_seconds <= 300:
        raise ValueError(f"expiry_seconds must be between 1 and 300; it is {expiry_seconds}.")
    limit = RefreshFailurePolicy.MAX_ALLOWED_REFRESH_FAILURES
    if max_refresh_failures is not None and not 1 <= max_refresh_failures <= limit:
        raise ValueError(f"max_refresh_failures must be between 1 and {limit}; it is {max_refresh_failures}.")


def _reveal(key_wrapper: KeyWrapper, wrapped: Buffer, budget: EncryptionBudget | None, logger: logging.Logger) -> AesGcmCryptoSession:
    """Reveals the DEK through the key wrapper and builds a session around it. A ``None`` budget
    means the process-wide one for whichever key is revealed."""
    key = bytearray(KEY_LENGTH)
    try:
        written = key_wrapper.unwrap(wrapped, key)
        # A wrapper that reveals fewer bytes (e.g. a KMS returning a 128-bit data key) would
        # otherwise leave the rest of the key zero and silently weaken every session.
        if written != KEY_LENGTH:
            raise CryptographicError(f"Key wrapper revealed {written} bytes; a {KEY_LENGTH}-byte DEK is required.")
        return AesGcmCryptoSession(key, budget if budget is not None else EncryptionBudget.for_key(key), logger)
    except BaseException:
        ArrayUtility.zero_memory(key)
        raise


def _quietly(action: Callable[[], object]) -> None:
    """Runs code the application supplies (its logger, its tracer) so that an exception from it can
    never decide whether the key stays in use."""
    with contextlib.suppress(Exception):
        action()


class _Reveal:
    """One reveal of the key on a worker thread, which a refresh can stop waiting for.

    The key wrapper's call may block (the native one does), and a call can't be cancelled. So it runs
    here, and a refresh that gives up on it calls :meth:`abandon`: whatever key it later reveals is
    zeroed as soon as it arrives, never put into use."""

    def __init__(self, key_wrapper: KeyWrapper, wrapped: Buffer, budget: EncryptionBudget, logger: logging.Logger) -> None:
        # Its own copy: close zeroes the provider's wrapped payload without waiting for this call.
        self._wrapped = bytearray(wrapped)
        self._key_wrapper = key_wrapper
        self._budget = budget
        self._logger = logger
        self._lock = threading.Lock()
        self._abandoned = False
        self.session: AesGcmCryptoSession | None = None
        self.error: Exception | None = None
        self.finished = threading.Event()
        # Set when the reveal finishes, or by close so a refresh waiting on it stops at once.
        self.wake = threading.Event()
        threading.Thread(target=self._run, name="hkdfguard-aesgcm-reveal", daemon=True).start()

    def _run(self) -> None:
        try:
            session = _reveal(self._key_wrapper, self._wrapped, self._budget, self._logger)
        except Exception as error:  # handed to the waiting refresh
            self.error = error
        else:
            with self._lock:
                if self._abandoned:
                    session.close()
                else:
                    self.session = session
        finally:
            ArrayUtility.zero_memory(self._wrapped)
            self.finished.set()
            self.wake.set()

    def abandon(self) -> None:
        with self._lock:
            self._abandoned = True
            session, self.session = self.session, None
        if session is not None:
            session.close()


class AesGcmCryptoProvider(CryptoProvider):
    """Tracks one cached :class:`AesGcmCryptoSession`, bound to a single wrapped DEK. A background
    thread, ticking every ``expiry_seconds``, reveals the DEK afresh through the key wrapper and swaps
    a new session in - so encrypt/decrypt never pay the unwrap cost; only :meth:`create` does, once.
    The replaced session is kept one more interval before being closed (zeroing its key), so an
    operation that captured it just before the swap completes normally.

    A refresh re-reveals the *same* DEK: it is a periodic check that the KEK is still accessible.
    What happens when the check fails is the refresh-failure policy: by default,
    :attr:`RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES` consecutive failures close every session
    (zeroing the DEK) and suspend encrypt/decrypt - they raise :class:`CryptographicError` - until a
    later refresh succeeds. A ``None`` ``max_refresh_failures`` keeps the last good session in use
    (fail open). A refresh that takes longer than one refresh interval counts as failed, so a key
    wrapper that hangs instead of failing still suspends key access on schedule.
    """

    MAX_ENCRYPTIONS_PER_KEY: Final = EncryptionBudget.DEFAULT_LIMIT
    """Encryptions after which this provider refuses to encrypt (decryption keeps working). The count
    is per DEK and shared by every provider in this process that reveals it; a refresh doesn't reset it."""

    ENCRYPTION_WARNING_THRESHOLD: Final = EncryptionBudget.DEFAULT_WARNING_THRESHOLD
    """Encryptions after which an :attr:`EventNames.ENCRYPTION_BUDGET_WARNING` event is raised, once."""

    def __init__(self, key_wrapper: KeyWrapper, wrapped: bytearray, expiry_seconds: int, max_refresh_failures: int | None,  # noqa: PLR0917 - private, called by create
                 budget: EncryptionBudget, first_session: AesGcmCryptoSession, logger: logging.Logger,
                 refresh_timeout: float | None = None) -> None:
        """Use :meth:`create`, which reveals the first key before constructing."""
        self._key_wrapper = key_wrapper
        self._wrapped = wrapped
        self._interval = float(expiry_seconds)
        # How long a refresh waits for the key wrapper: one refresh interval.
        self._refresh_timeout = refresh_timeout if refresh_timeout is not None else self._interval
        self._max_refresh_failures = max_refresh_failures
        self._budget = budget
        self._logger = logger
        self._gate = threading.Lock()
        self._current: AesGcmCryptoSession | None = first_session
        # The session a refresh replaced: closed one interval later, on the next swap or on close.
        self._retiring: AesGcmCryptoSession | None = None
        self._consecutive_failures = 0
        # A reveal a refresh stopped waiting for, while it may still be running; and the one a
        # refresh is waiting on now, so close can wake it. See _refresh_once.
        self._abandoned: _Reveal | None = None
        self._waiting: _Reveal | None = None
        self._closed = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run_refresh_loop, name="hkdfguard-aesgcm-refresh", daemon=True)
        self._thread.start()

    @classmethod
    def create(cls, key_wrapper: KeyWrapper, wrapped: Buffer, expiry_seconds: int,
               max_refresh_failures: int | None = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES,
               logger: logging.Logger | None = None, *, budget: EncryptionBudget | None = None,
               _refresh_timeout: float | None = None) -> AesGcmCryptoProvider:
        """Reveals the DEK through ``key_wrapper`` and starts the background refresh.

        :param wrapped: the wrapped DEK payload. A ``bytearray`` is owned by the provider from here
            on and zeroed when it closes; other buffers are copied.
        :param expiry_seconds: how long each session is used before the next refresh, 1-300
        :param max_refresh_failures: consecutive failed refreshes tolerated before failing closed,
            1 to :attr:`RefreshFailurePolicy.MAX_ALLOWED_REFRESH_FAILURES` (100); ``None`` to fail open
        :param logger: receives an error per failed refresh, a critical entry when key access is
            suspended, an info entry when it resumes, and a warning near the encryption limit;
            ``None`` for the ``hkdfguard.cryptoprovider.aesgcm256`` logger
        :param budget: tests only - the encryption count to draw on
        :param _refresh_timeout: tests only - how long a refresh waits for the key wrapper, in
            seconds; one refresh interval otherwise
        :raises ValueError: an argument is out of range (before any key wrapper call)
        """
        if key_wrapper is None:
            raise TypeError("key_wrapper must not be None.")
        _validate(expiry_seconds, max_refresh_failures)
        owned = wrapped if isinstance(wrapped, bytearray) else bytearray(wrapped)
        effective_logger = logger if logger is not None else _DEFAULT_LOGGER

        first = _reveal(key_wrapper, owned, budget, effective_logger)
        return cls(key_wrapper, owned, expiry_seconds, max_refresh_failures, first.budget, first, effective_logger, _refresh_timeout)

    @property
    def max_refresh_failures(self) -> int | None:
        """The refresh-failure policy; ``None`` means fail open."""
        return self._max_refresh_failures

    @property
    def key_access_suspended(self) -> bool:
        """True while this provider has failed closed and every encrypt/decrypt raises."""
        return self._current is None and not self._closed

    @property
    def encryption_count(self) -> int:
        """Encryptions performed under this provider's key so far."""
        return self._budget.count

    @property
    def current_session(self) -> AesGcmCryptoSession | None:
        """The session in use, for tests; ``None`` while suspended or after close."""
        return self._current

    def encrypt(self, plaintext: WritableBuffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        while True:
            try:
                session = self._session()
            except BaseException:
                # Suspended or closed: no session will zero the plaintext, so honour the contract here.
                ArrayUtility.zero_memory(plaintext)
                raise

            # Once it starts, the session zeroes plaintext itself. None means it was retired and
            # closed after it was read here, before it started: go round for its replacement.
            written = session.try_encrypt(plaintext, result, aad=aad)
            if written is not None:
                return written

    def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        while True:
            written = self._session().try_decrypt(ciphertext, result, aad=aad)
            if written is not None:
                return written

    def _session(self) -> AesGcmCryptoSession:
        session = self._current
        if session is not None:
            return session
        if self._closed:
            raise ObjectClosedError("This AES-GCM crypto provider has been closed.")
        raise CryptographicError(
            f"Key access is suspended: {self._max_refresh_failures} consecutive attempts to re-reveal the key through the key wrapper "
            "failed. Operations resume once a refresh succeeds.")

    def get_encrypted_allocation_length(self, length: int) -> int:
        return length + NONCE_SIZE + TAG_SIZE

    def get_decrypted_allocation_length(self, length: int) -> int:
        # Never negative: input shorter than the nonce and tag can't be valid, but a size computed
        # from it must still be a usable buffer length.
        return max(0, length - NONCE_SIZE - TAG_SIZE)

    def _run_refresh_loop(self) -> None:
        # Ticks at fixed intervals from creation; ticks missed while a slow refresh ran collapse into one.
        next_tick = time.monotonic() + self._interval
        while not self._stop.wait(max(0.0, next_tick - time.monotonic())):
            next_tick = max(next_tick + self._interval, time.monotonic())
            try:
                self._refresh_once()
            except Exception as error:
                # Never let one refresh end the loop: with no more refreshes, the key would stay in
                # use for good. Whatever went wrong counts as a failed refresh.
                self._refresh_failed(None, error)

    def _refresh_once(self) -> None:
        """Re-reveals the key, waiting at most one refresh interval for the key wrapper.

        A wrapper that hangs rather than failing (a busy TPM resource manager, a keychain prompt
        nobody can answer, a KMS endpoint that never replies) must still count towards the
        refresh-failure policy, or a revoked KEK would never suspend key access. A reveal that misses
        its deadline is abandoned, not cancelled - a native call can't be - and until it returns no
        new one starts, so a stuck wrapper never accumulates calls; each tick in the meantime is a
        failed refresh."""
        telemetry = HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256
        with telemetry.tracer.start_as_current_span(SpanNames.CryptoProviderAesGcm256.BACKGROUND_REFRESH, record_exception=False,
                                                    set_status_on_exception=False) as span:
            if self._abandoned is not None:
                if not self._abandoned.finished.is_set():
                    self._refresh_failed(span, TimeoutError(
                        "The key wrapper has still not returned from a refresh that timed out; no new refresh starts until it does."))
                    return
                self._abandoned = None

            reveal = _Reveal(self._key_wrapper, self._wrapped, self._budget, self._logger)
            with self._gate:
                self._waiting = reveal
            try:
                reveal.wake.wait(self._refresh_timeout)
            finally:
                with self._gate:
                    self._waiting = None

            if self._stop.is_set():
                # Shutdown: whatever the in-flight refresh did or will do is not a failure.
                reveal.abandon()
                return
            if not reveal.finished.is_set():
                reveal.abandon()
                self._abandoned = reveal
                self._refresh_failed(span, TimeoutError(f"The key wrapper did not reveal the key within {self._refresh_timeout:g} seconds."))
                return
            if reveal.error is not None:
                self._refresh_failed(span, reveal.error)
                return
            fresh = reveal.session
            assert fresh is not None  # finished without an error means a session

            with self._gate:
                # close may have run while the key was being revealed: never put a session back.
                if self._closed:
                    fresh.close()
                    return
                outgoing, self._current = self._current, fresh
                stale, self._retiring = self._retiring, outgoing
            if stale is not None:
                stale.close()

            previous, self._consecutive_failures = self._consecutive_failures, 0
            if self._max_refresh_failures is not None and previous >= self._max_refresh_failures:
                _quietly(lambda: HkdfGuardLog.key_access_resumed(self._logger, previous))

    def _refresh_failed(self, span: Span | None, error: Exception) -> None:
        self._consecutive_failures += 1
        failures = self._consecutive_failures

        # Enforce the policy before anything that runs application code (telemetry, the logger), so
        # an exception there can't leave the key in use past the limit. >= rather than ==, and a
        # suspend that is a no-op once suspended, so no tick can step over it.
        suspended_now = (self._max_refresh_failures is not None and failures >= self._max_refresh_failures
                         and self._suspend_key_access())

        if span is not None:
            _quietly(lambda: record_exception(span, error))
        # Logged on every failure, whatever the policy: under fail-open it is the only sign the KEK is gone.
        _quietly(lambda: HkdfGuardLog.key_refresh_failed(self._logger, failures, self._policy_description(), error))
        if suspended_now:
            if span is not None:
                _quietly(lambda: span.add_event(EventNames.KEY_ACCESS_SUSPENDED, {AttributeNames.CONSECUTIVE_FAILURES: failures}))
            _quietly(lambda: HkdfGuardLog.key_access_suspended(self._logger, failures))

    def _policy_description(self) -> str:
        if self._max_refresh_failures is not None:
            return f"fail closed after {self._max_refresh_failures} consecutive failures"
        return "fail open (the last good key stays in use)"

    def _suspend_key_access(self) -> bool:
        """Fails closed: zeroes every revealed copy of the DEK until a refresh succeeds. Returns whether
        this call suspended access - ``False`` if it already was, or the provider is closed."""
        with self._gate:
            if self._closed:
                return False
            retiring, self._retiring = self._retiring, None
            current, self._current = self._current, None
        for session in (retiring, current):
            if session is not None:
                session.close()
        return current is not None

    def close(self) -> None:
        """Stops the background refresh, then zeroes the wrapped payload and every revealed key. A
        refresh still waiting on the key wrapper is abandoned rather than waited for, so a stuck
        wrapper can't block close; whatever key it later reveals is zeroed when it arrives. Safe to
        call more than once, from any thread."""
        with self._gate:
            if self._closed:
                return
            self._closed = True
            waiting = self._waiting
        self._stop.set()
        if waiting is not None:
            waiting.wake.set()
        if threading.current_thread() is not self._thread:
            self._thread.join()

        with self._gate:
            retiring, self._retiring = self._retiring, None
            current, self._current = self._current, None
        for session in (retiring, current):
            if session is not None:
                session.close()
        ArrayUtility.zero_memory(self._wrapped)


class AesGcmCryptoProviderFactory(CryptoProviderFactory):
    """Creates :class:`AesGcmCryptoProvider` instances. Every provider logs failed refreshes, key
    access suspension and resumption, and an approaching encryption limit to the logger given here -
    keep those entries visible: they are how an operator learns a KEK has gone or a key needs rotating."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger

    def create(self, wrapper: KeyWrapper, wrapped: bytearray, expiry_seconds: int,
               max_refresh_failures: int | None = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES) -> AesGcmCryptoProvider:
        return AesGcmCryptoProvider.create(wrapper, wrapped, expiry_seconds, max_refresh_failures, self._logger)

    def create_ephemeral(self, wrapper: KeyWrapper, expiry_seconds: int,
                         max_refresh_failures: int | None = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES) -> AesGcmCryptoProvider:
        # Fail on bad arguments before asking the key wrapper to generate anything.
        if wrapper is None:
            raise TypeError("wrapper must not be None.")
        _validate(expiry_seconds, max_refresh_failures)

        # Sized to the same limit a key file is held to; trimmed to what was written.
        buffer = bytearray(WrappedKeyLimits.MAX_BYTES)
        length = wrapper.generate_and_wrap(buffer)
        if not 1 <= length <= len(buffer):
            raise CryptographicError(f"Key wrapper reported {length} bytes of wrapped key; between 1 and {len(buffer)} are expected.")
        return self.create(wrapper, buffer[:length], expiry_seconds, max_refresh_failures)
