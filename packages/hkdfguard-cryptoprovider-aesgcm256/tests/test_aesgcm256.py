from __future__ import annotations

import base64
import logging
import os
import re
import struct
import threading
import time
from collections.abc import Buffer, Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from hkdfguard.abstractions import (
    AuthenticationTagMismatchError,
    CryptographicError,
    EncryptedFormatError,
    EncryptedFormatProvider,
    KeyNotFoundError,
    KeyTrackingValue,
    KeyWrapper,
    ObjectClosedError,
    RefreshFailurePolicy,
    WritableBuffer,
)
from hkdfguard.cryptoprovider.aesgcm256 import (
    AesGcmCryptoProvider,
    AesGcmCryptoProviderFactory,
    AesGcmCryptoSession,
    AesGcmPipelineDataProtector,
    EncryptionBudget,
)
from hkdfguard.diagnostics import AttributeNames, EventNames, HkdfGuardLog, HkdfGuardTelemetry, SpanNames
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

WRAPPED = b"wrapped"


# --- Helpers ----------------------------------------------------------------------------------


class FakeKeyWrapper(KeyWrapper):
    """Reveals a fresh random key (or a fixed one), counting calls. Thread-safe."""

    def __init__(self, fixed_key: bytes | None = None) -> None:
        self.fixed_key = fixed_key
        self.unwrap_calls = 0
        self.generate_calls = 0
        self.throw_on_unwrap: BaseException | None = None
        self.bytes_written_override: int | None = None
        self._lock = threading.Lock()

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        with self._lock:
            self.unwrap_calls += 1
        if self.throw_on_unwrap is not None:
            raise self.throw_on_unwrap
        view = memoryview(result).cast("B")
        written = self.bytes_written_override if self.bytes_written_override is not None else len(view)
        filled = min(written, len(view))
        view[:filled] = (self.fixed_key or os.urandom(32))[:filled]
        return written

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        self.generate_calls += 1
        memoryview(result).cast("B")[:32] = bytes([7] * 32)
        return 32


class GatedKeyWrapper(KeyWrapper):
    """Unwrap blocks until released, standing in for a slow network KMS."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.released = threading.Event()
        self.key = os.urandom(32)

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        self.started.set()
        self.released.wait(10)
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:7] = WRAPPED
        return 7


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self._records_lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        with self._records_lock:
            self.records.append(record)

    def with_event_id(self, event_id: int) -> list[logging.LogRecord]:
        with self._records_lock:
            return [r for r in self.records if getattr(r, HkdfGuardLog.EVENT_ID_KEY, None) == event_id]


def recording_logger() -> tuple[logging.Logger, RecordingHandler]:
    logger = logging.Logger(f"recording-{id(object())}", logging.DEBUG)
    handler = RecordingHandler()
    logger.addHandler(handler)
    return logger, handler


class TestFormatProvider(EncryptedFormatProvider):
    """enc::v{version}::{base64}, minimally - the real one lives in hkdfguard-dataencryptionkey."""

    __test__ = False
    _FORMAT = re.compile(r"enc::v(-?\d+)::([A-Za-z0-9+/]*={0,2})")

    def format(self, value: KeyTrackingValue) -> str:
        return f"enc::v{value.key_version}::{base64.b64encode(value.value).decode()}"

    def parse(self, encrypted: str) -> KeyTrackingValue:
        match = self._FORMAT.fullmatch(encrypted)
        if match is None:
            raise EncryptedFormatError("Invalid encrypted format.")
        return KeyTrackingValue(int(match.group(1)), base64.b64decode(match.group(2)))

    def get_max_decrypted_length(self, encrypted: str) -> int:
        return len(self.parse(encrypted).value)


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    HkdfGuardTelemetry.set_tracer_provider(provider)
    yield exporter
    HkdfGuardTelemetry.set_tracer_provider(None)


def finished(exporter: InMemorySpanExporter, name: str) -> list:  # type: ignore[type-arg]
    return [s for s in exporter.get_finished_spans() if s.name == name]


def create(wrapper: KeyWrapper, expiry_seconds: int = 60, max_refresh_failures: int | None = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES,
           logger: logging.Logger | None = None, budget: EncryptionBudget | None = None) -> AesGcmCryptoProvider:
    return AesGcmCryptoProvider.create(wrapper, bytearray(WRAPPED), expiry_seconds, max_refresh_failures, logger, budget=budget)


def round_trip(provider: AesGcmCryptoProvider | AesGcmCryptoSession, plaintext: bytes = b"top secret", aad: bytes = b"") -> bytes:
    encrypted = bytearray(len(plaintext) + 28)
    written = provider.encrypt(bytearray(plaintext), encrypted, aad=aad)
    decrypted = bytearray(len(plaintext))
    assert provider.decrypt(encrypted[:written], decrypted, aad=aad) == len(plaintext)
    return bytes(decrypted)


# --- EncryptionBudget -------------------------------------------------------------------------


def test_budget_defaults_are_half_and_one_eighth_of_the_nist_limit() -> None:
    budget = EncryptionBudget()
    assert (budget.limit, budget.warning_threshold, budget.count) == (1 << 31, 1 << 28, 0)


def test_budget_warns_exactly_once_at_the_threshold_and_stops_at_the_limit() -> None:
    budget = EncryptionBudget(warning_threshold=3, limit=4)

    assert [budget.consume() for _ in range(4)] == [False, False, True, False]
    with pytest.raises(CryptographicError, match="limit of 4"):
        budget.consume()
    assert budget.count == 4


def test_budget_under_concurrency_never_exceeds_the_limit() -> None:
    budget = EncryptionBudget(warning_threshold=1, limit=1000)

    def worker() -> int:
        successes = 0
        for _ in range(500):
            try:
                budget.consume()
                successes += 1
            except CryptographicError:
                pass
        return successes

    with ThreadPoolExecutor(8) as pool:
        assert sum(pool.map(lambda _: worker(), range(8))) == 1000
    assert budget.count == 1000


@pytest.mark.parametrize(("threshold", "limit"), [(0, 10), (11, 10), (1, 0)])
def test_budget_refuses_an_invalid_threshold_or_limit(threshold: int, limit: int) -> None:
    with pytest.raises(ValueError):
        EncryptionBudget(threshold, limit)


def test_the_budget_registry_is_keyed_by_the_keys_value() -> None:
    key = os.urandom(32)
    assert EncryptionBudget.for_key(key) is EncryptionBudget.for_key(bytearray(key))
    assert EncryptionBudget.for_key(key) is not EncryptionBudget.for_key(os.urandom(32))


# --- AesGcmCryptoSession ----------------------------------------------------------------------


def session() -> AesGcmCryptoSession:
    return AesGcmCryptoSession(bytearray(os.urandom(32)))


def test_session_round_trips_with_and_without_aad() -> None:
    cipher = session()
    assert round_trip(cipher) == b"top secret"
    assert round_trip(cipher, aad=b"context") == b"top secret"
    assert round_trip(cipher, bytes(11)) == bytes(11)


def test_session_decrypts_the_nist_gcm_test_vector_in_the_shared_layout() -> None:
    # NIST GCM spec, test case 16 (AES-256, 96-bit IV, with AAD), stored as nonce | ciphertext | tag -
    # the layout every port writes.
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    plaintext = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    stored = bytes.fromhex("cafebabefacedbaddecaf888"
                           "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                           "76fc6ece0f4e1768cddf8853bb2d551b")

    decrypted = bytearray(len(plaintext))
    assert AesGcmCryptoSession(bytearray(key)).decrypt(stored, decrypted, aad=aad) == len(plaintext)
    assert decrypted == plaintext


def test_session_decrypt_with_wrong_aad_or_tampered_ciphertext_fails_and_reveals_nothing() -> None:
    cipher = session()
    encrypted = bytearray(11 + 28)
    cipher.encrypt(bytearray(b"hello world"), encrypted, aad=b"correct")

    result = bytearray(11)
    with pytest.raises(AuthenticationTagMismatchError):
        cipher.decrypt(encrypted, result, aad=b"wrong")
    assert result == bytearray(11)

    encrypted[15] ^= 0xFF
    with pytest.raises(AuthenticationTagMismatchError):
        cipher.decrypt(encrypted, result, aad=b"correct")


def test_session_refuses_bad_buffers_and_keys() -> None:
    cipher = session()
    with pytest.raises(ValueError, match="too small"):
        cipher.encrypt(bytearray(b"hello world"), bytearray(11))
    with pytest.raises(ValueError, match="too short"):
        cipher.decrypt(bytes(10), bytearray(4))
    encrypted = bytearray(11 + 28)
    cipher.encrypt(bytearray(b"hello world"), encrypted)
    with pytest.raises(ValueError, match="too small"):
        cipher.decrypt(encrypted, bytearray(10))
    with pytest.raises(ValueError):
        AesGcmCryptoSession(bytearray(os.urandom(10)))
    with pytest.raises(ValueError):
        AesGcmCryptoSession(bytearray(32))


def test_session_empty_plaintext_is_an_authenticated_empty_message() -> None:
    cipher = session()
    encrypted = bytearray(28)

    assert cipher.encrypt(bytearray(), encrypted, aad=b"aad") == 28
    assert cipher.decrypt(encrypted, bytearray(), aad=b"aad") == 0
    with pytest.raises(AuthenticationTagMismatchError):
        cipher.decrypt(encrypted, bytearray(), aad=b"other")


def test_session_close_zeroes_the_key_and_refuses_later_use() -> None:
    key = bytearray(os.urandom(32))
    cipher = AesGcmCryptoSession(key)
    plaintext = bytearray(b"secret")

    cipher.close()
    cipher.close()

    assert key == bytearray(32)
    assert cipher.try_encrypt(bytearray(b"still here"), bytearray(64)) is None
    assert cipher.try_decrypt(bytes(40), bytearray(12)) is None
    with pytest.raises(ObjectClosedError):
        cipher.encrypt(plaintext, bytearray(64))
    assert plaintext == bytearray(6)
    with pytest.raises(ObjectClosedError):
        cipher.decrypt(bytes(40), bytearray(12))


def test_try_encrypt_on_a_closed_session_leaves_the_plaintext_and_the_count_untouched() -> None:
    budget = EncryptionBudget()
    cipher = AesGcmCryptoSession(bytearray(os.urandom(32)), budget)
    cipher.close()
    plaintext = bytearray(b"still here")

    assert cipher.try_encrypt(plaintext, bytearray(64)) is None
    assert plaintext == b"still here"
    assert budget.count == 0


def test_session_concurrent_operations_each_round_trip_under_their_own_nonce() -> None:
    cipher = session()
    nonces: set[bytes] = set()
    lock = threading.Lock()

    def worker(w: int) -> None:
        encrypted = bytearray(4 + 28)
        decrypted = bytearray(4)
        for i in range(300):
            value = w * 1000 + i
            aad = struct.pack(">i", w)
            cipher.encrypt(bytearray(struct.pack(">i", value)), encrypted, aad=aad)
            with lock:
                assert bytes(encrypted[:12]) not in nonces
                nonces.add(bytes(encrypted[:12]))
            cipher.decrypt(encrypted, decrypted, aad=aad)
            assert struct.unpack(">i", decrypted)[0] == value

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(worker, range(8)))
    assert len(nonces) == 2400


# --- AesGcmCryptoProvider ---------------------------------------------------------------------


def test_create_reveals_the_first_key_eagerly() -> None:
    wrapper = FakeKeyWrapper()
    with create(wrapper):
        assert wrapper.unwrap_calls == 1


def test_create_propagates_a_key_wrapper_failure() -> None:
    wrapper = FakeKeyWrapper()
    wrapper.throw_on_unwrap = RuntimeError("reveal failed")
    with pytest.raises(RuntimeError, match="reveal failed"):
        create(wrapper)


@pytest.mark.parametrize("expiry", [0, -1, 301])
def test_create_refuses_an_expiry_out_of_range_before_any_unwrap(expiry: int) -> None:
    wrapper = FakeKeyWrapper()
    with pytest.raises(ValueError):
        create(wrapper, expiry)
    assert wrapper.unwrap_calls == 0


@pytest.mark.parametrize("failures", [0, -1])
def test_create_refuses_max_refresh_failures_below_one(failures: int) -> None:
    with pytest.raises(ValueError):
        create(FakeKeyWrapper(), max_refresh_failures=failures)


@pytest.mark.parametrize("written", [0, 16, 31, 33])
def test_create_refuses_a_key_of_the_wrong_length(written: int) -> None:
    wrapper = FakeKeyWrapper()
    wrapper.bytes_written_override = written
    with pytest.raises(CryptographicError, match=f"revealed {written} bytes"):
        create(wrapper)


def test_allocation_lengths_add_and_remove_the_nonce_and_tag() -> None:
    with create(FakeKeyWrapper()) as provider:
        assert provider.get_encrypted_allocation_length(10) == 38
        assert provider.get_decrypted_allocation_length(38) == 10
        assert [provider.get_decrypted_allocation_length(n) for n in (0, 27, 28)] == [0, 0, 0]


def test_background_refresh_reveals_the_key_again_and_close_stops_it() -> None:
    wrapper = FakeKeyWrapper()
    provider = create(wrapper, 1)
    time.sleep(1.5)
    assert wrapper.unwrap_calls == 2

    provider.close()
    time.sleep(1.2)
    assert wrapper.unwrap_calls == 2
    with pytest.raises(ObjectClosedError):
        provider.encrypt(bytearray(b"\x01"), bytearray(64))


def test_close_twice_is_safe_and_zeroes_the_wrapped_payload_and_the_key() -> None:
    wrapped = bytearray(WRAPPED)
    provider = AesGcmCryptoProvider.create(FakeKeyWrapper(), wrapped, 60)
    session_ = provider.current_session
    assert session_ is not None

    provider.close()
    provider.close()

    assert wrapped == bytearray(len(WRAPPED))
    assert session_.key == bytearray(32)


def test_a_refresh_swaps_in_a_new_session_and_retires_the_old_one_an_interval_later() -> None:
    with create(FakeKeyWrapper(os.urandom(32)), 1) as provider:
        first = provider.current_session
        assert first is not None
        time.sleep(1.3)
        assert provider.current_session is not first
        assert not first.closed
        time.sleep(1.0)
        assert first.closed


def test_a_failing_or_short_refresh_is_recorded_and_the_current_session_stays(spans: InMemorySpanExporter) -> None:
    wrapper = FakeKeyWrapper()
    with create(wrapper, 1) as provider:
        ciphertext = bytearray(40)
        written = provider.encrypt(bytearray(b"still works!"), ciphertext)

        wrapper.bytes_written_override = 16
        time.sleep(1.4)
        wrapper.bytes_written_override = None
        wrapper.throw_on_unwrap = CryptographicError("unwrap failed")
        time.sleep(1.0)

        refreshes = finished(spans, SpanNames.CryptoProviderAesGcm256.BACKGROUND_REFRESH)
        assert any(s.status.status_code == StatusCode.ERROR and "revealed 16 bytes" in (s.status.description or "") for s in refreshes)
        assert any(s.status.description == "unwrap failed" for s in refreshes)
        result = bytearray(12)
        provider.decrypt(ciphertext[:written], result)
        assert result == b"still works!"


def test_refreshes_under_concurrent_load_never_fail_an_operation_mid_swap() -> None:
    failures: list[BaseException] = []
    with create(FakeKeyWrapper(os.urandom(32)), 1) as provider:
        deadline = time.monotonic() + 2.5

        def worker() -> None:
            encrypted = bytearray(14 + 28)
            decrypted = bytearray(14)
            while time.monotonic() < deadline:
                try:
                    provider.encrypt(bytearray(b"pounding on it"), encrypted)
                    provider.decrypt(encrypted, decrypted)
                except BaseException as error:
                    failures.append(error)
                    return

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert failures == []


def test_encrypt_past_the_keys_limit_fails_while_decrypt_still_works() -> None:
    with create(FakeKeyWrapper(os.urandom(32)), max_refresh_failures=None, budget=EncryptionBudget(1, 2)) as provider:
        ciphertext = bytearray(33)
        provider.encrypt(bytearray(b"value"), ciphertext)
        provider.encrypt(bytearray(b"value"), bytearray(33))

        with pytest.raises(CryptographicError, match="must be rotated"):
            provider.encrypt(bytearray(b"value"), bytearray(33))
        assert provider.encryption_count == 2
        result = bytearray(5)
        provider.decrypt(ciphertext, result)
        assert result == b"value"


def test_the_encryption_count_survives_a_refresh_and_is_shared_by_providers_of_one_key() -> None:
    key = os.urandom(32)
    with create(FakeKeyWrapper(key), 1, budget=EncryptionBudget(1, 4)) as provider:
        provider.encrypt(bytearray(b"one"), bytearray(64))
        time.sleep(1.4)
        provider.encrypt(bytearray(b"two"), bytearray(64))
        assert provider.encryption_count == 2

    with create(FakeKeyWrapper(key)) as first, create(FakeKeyWrapper(key)) as second, create(FakeKeyWrapper(os.urandom(32))) as other:
        first.encrypt(bytearray(b"one"), bytearray(64))
        second.encrypt(bytearray(b"two"), bytearray(64))
        assert first.encryption_count == second.encryption_count == 2
        assert other.encryption_count == 0

    with create(FakeKeyWrapper(key)) as rebuilt:
        assert rebuilt.encryption_count == 2


def test_crossing_the_warning_threshold_raises_one_event_and_one_log_entry(spans: InMemorySpanExporter) -> None:
    logger, handler = recording_logger()
    with create(FakeKeyWrapper(os.urandom(32)), logger=logger, budget=EncryptionBudget(2, 7919)) as provider:
        for _ in range(4):
            provider.encrypt(bytearray(b"value"), bytearray(64))

    warnings = [e for s in finished(spans, SpanNames.CryptoProviderAesGcm256.ENCRYPT) for e in s.events
                if e.name == EventNames.ENCRYPTION_BUDGET_WARNING]
    assert len(warnings) == 1
    assert warnings[0].attributes[AttributeNames.ENCRYPTION_COUNT] == 2
    assert warnings[0].attributes[AttributeNames.ENCRYPTION_LIMIT] == 7919
    (entry,) = handler.with_event_id(HkdfGuardLog.ENCRYPTION_BUDGET_WARNING)
    assert entry.levelno == logging.WARNING
    assert "2 encryptions of its 7919" in entry.getMessage()


def test_public_limits_match_the_budget_defaults() -> None:
    assert AesGcmCryptoProvider.MAX_ENCRYPTIONS_PER_KEY == 1 << 31
    assert AesGcmCryptoProvider.ENCRYPTION_WARNING_THRESHOLD == 1 << 28


def test_fail_closed_is_the_default_and_none_opts_into_fail_open() -> None:
    with create(FakeKeyWrapper()) as defaulted, create(FakeKeyWrapper(), max_refresh_failures=None) as fail_open:
        assert defaulted.max_refresh_failures == 3
        assert fail_open.max_refresh_failures is None
        assert not defaulted.key_access_suspended


def test_fail_closed_suspends_after_consecutive_failures_and_resumes_on_success(spans: InMemorySpanExporter) -> None:
    logger, handler = recording_logger()
    wrapper = FakeKeyWrapper(os.urandom(32))
    with create(wrapper, 1, 2, logger) as provider:
        ciphertext = bytearray(36)
        provider.encrypt(bytearray(b"survives"), ciphertext)

        revoked = CryptographicError("KEK revoked")
        wrapper.throw_on_unwrap = revoked  # ticks ~1 s and ~2 s fail
        time.sleep(2.6)

        assert provider.key_access_suspended
        plaintext = bytearray(b"x")
        with pytest.raises(CryptographicError, match="suspended"):
            provider.encrypt(plaintext, bytearray(64))
        assert plaintext == bytearray(1)
        with pytest.raises(CryptographicError):
            provider.decrypt(ciphertext, bytearray(8))

        suspended = [e for s in finished(spans, SpanNames.CryptoProviderAesGcm256.BACKGROUND_REFRESH) for e in s.events
                     if e.name == EventNames.KEY_ACCESS_SUSPENDED]
        assert len(suspended) == 1
        assert suspended[0].attributes[AttributeNames.CONSECUTIVE_FAILURES] == 2
        failures = handler.with_event_id(HkdfGuardLog.KEY_REFRESH_FAILED)
        assert len(failures) == 2
        assert all(r.levelno == logging.ERROR and r.exc_info and r.exc_info[1] is revoked for r in failures)
        assert all("fail closed after 2 consecutive failures" in r.getMessage() for r in failures)
        (critical,) = handler.with_event_id(HkdfGuardLog.KEY_ACCESS_SUSPENDED)
        assert critical.levelno == logging.CRITICAL

        wrapper.throw_on_unwrap = None  # tick ~3 s succeeds
        time.sleep(1.0)

        assert not provider.key_access_suspended
        result = bytearray(8)
        provider.decrypt(ciphertext, result)
        assert result == b"survives"
        (resumed,) = handler.with_event_id(HkdfGuardLog.KEY_ACCESS_RESUMED)
        assert resumed.levelno == logging.INFO


def test_fail_open_logs_every_failure_but_never_suspends() -> None:
    logger, handler = recording_logger()
    wrapper = FakeKeyWrapper(os.urandom(32))
    with create(wrapper, 1, None, logger) as provider:
        wrapper.throw_on_unwrap = CryptographicError("KEK unreachable")
        time.sleep(2.6)

        failures = handler.with_event_id(HkdfGuardLog.KEY_REFRESH_FAILED)
        assert len(failures) >= 2
        assert all("fail open" in r.getMessage() for r in failures)
        assert any("(2 consecutive)" in r.getMessage() for r in failures)
        assert not handler.with_event_id(HkdfGuardLog.KEY_ACCESS_SUSPENDED)
        assert not provider.key_access_suspended

        wrapper.throw_on_unwrap = None
        time.sleep(1.2)
        assert not handler.with_event_id(HkdfGuardLog.KEY_ACCESS_RESUMED)


def test_successful_refreshes_log_nothing() -> None:
    logger, handler = recording_logger()
    with create(FakeKeyWrapper(), 1, 1, logger):
        time.sleep(1.3)
    assert handler.records == []


def test_fail_closed_counts_only_consecutive_failures() -> None:
    wrapper = FakeKeyWrapper(os.urandom(32))
    with create(wrapper, 1, 2) as provider:
        wrapper.throw_on_unwrap = CryptographicError("blip")  # ~1 s fails
        time.sleep(1.3)
        wrapper.throw_on_unwrap = None                         # ~2 s succeeds
        time.sleep(1.0)
        wrapper.throw_on_unwrap = CryptographicError("blip")  # ~3 s fails
        time.sleep(1.0)

        assert wrapper.unwrap_calls >= 4
        assert not provider.key_access_suspended
        assert provider.encrypt(bytearray(b"still open"), bytearray(64)) == 38


def test_close_while_suspended_reports_closed_not_suspended() -> None:
    wrapper = FakeKeyWrapper()
    provider = create(wrapper, 1, 1)
    wrapper.throw_on_unwrap = CryptographicError("KEK unavailable")
    time.sleep(1.5)
    assert provider.key_access_suspended

    provider.close()

    assert not provider.key_access_suspended
    with pytest.raises(ObjectClosedError):
        provider.encrypt(bytearray(b"\x01"), bytearray(64))


def test_close_while_a_refresh_is_failing_because_of_the_shutdown_does_not_raise() -> None:
    class FailsOnShutdown(FakeKeyWrapper):
        def __init__(self) -> None:
            super().__init__()
            self.refresh_started = threading.Event()
            self.shutdown = threading.Event()

        def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
            if self.unwrap_calls == 0:
                return super().unwrap(wrapped, result)
            self.refresh_started.set()
            self.shutdown.wait(10)
            raise CryptographicError("KMS connection closed during shutdown.")

    wrapper = FailsOnShutdown()
    provider = create(wrapper, 1)
    assert wrapper.refresh_started.wait(10)

    closing = threading.Thread(target=provider.close)
    closing.start()
    time.sleep(0.1)
    wrapper.shutdown.set()
    closing.join(10)
    assert not closing.is_alive()


def test_close_from_inside_a_key_wrapper_call_does_not_deadlock() -> None:
    holder: list[AesGcmCryptoProvider] = []
    closed = threading.Event()

    class ClosesFromInside(FakeKeyWrapper):
        def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
            written = super().unwrap(wrapped, result)
            if self.unwrap_calls > 1:
                holder[0].close()
                closed.set()
            return written

    holder.append(create(ClosesFromInside(os.urandom(32)), 1))

    assert closed.wait(10)
    with pytest.raises(ObjectClosedError):
        holder[0].encrypt(bytearray(b"\x01"), bytearray(64))


def test_encrypt_zeroes_the_plaintext_on_success_failure_and_after_close() -> None:
    provider = create(FakeKeyWrapper())
    plaintext = bytearray(b"top secret")
    provider.encrypt(plaintext, bytearray(64))
    assert plaintext == bytearray(10)

    plaintext = bytearray(b"top secret")
    with pytest.raises(ValueError):
        provider.encrypt(plaintext, bytearray(1))
    assert plaintext == bytearray(10)

    provider.close()
    plaintext = bytearray(b"top secret")
    with pytest.raises(ObjectClosedError):
        provider.encrypt(plaintext, bytearray(64), aad=b"aad")
    assert plaintext == bytearray(10)


def test_a_failed_reveal_zeroes_what_the_wrapper_wrote() -> None:
    captured: list[WritableBuffer] = []

    class ShortWrapper(FakeKeyWrapper):
        def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
            captured.append(result)
            super().unwrap(wrapped, result)
            return 16

    with pytest.raises(CryptographicError):
        create(ShortWrapper(os.urandom(32)))
    assert bytes(captured[0]) == bytes(32)


# --- AesGcmCryptoProviderFactory --------------------------------------------------------------


def test_factory_creates_working_providers_passing_the_policy_through() -> None:
    factory = AesGcmCryptoProviderFactory()
    wrapper = FakeKeyWrapper()

    with factory.create(wrapper, bytearray(WRAPPED), 60, 4) as created, factory.create_ephemeral(wrapper, 60, 5) as ephemeral, \
            factory.create(wrapper, bytearray(WRAPPED), 60) as defaulted, factory.create(wrapper, bytearray(WRAPPED), 60, None) as fail_open:
        assert round_trip(created) == round_trip(ephemeral) == b"top secret"
        assert (created.max_refresh_failures, ephemeral.max_refresh_failures) == (4, 5)
        assert defaulted.max_refresh_failures == RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES
        assert fail_open.max_refresh_failures is None
    assert wrapper.generate_calls == 1


def test_factory_hands_its_logger_to_every_provider() -> None:
    logger, handler = recording_logger()
    factory = AesGcmCryptoProviderFactory(logger)
    wrapper = FakeKeyWrapper()
    with factory.create(wrapper, bytearray(WRAPPED), 1), factory.create_ephemeral(wrapper, 1):
        wrapper.throw_on_unwrap = CryptographicError("KEK revoked")
        time.sleep(1.4)
        assert len(handler.with_event_id(HkdfGuardLog.KEY_REFRESH_FAILED)) >= 2


@pytest.mark.parametrize(("expiry", "failures"), [(0, None), (301, None), (60, 0)])
def test_factory_refuses_bad_arguments_before_calling_the_key_wrapper(expiry: int, failures: int | None) -> None:
    factory = AesGcmCryptoProviderFactory()
    wrapper = FakeKeyWrapper()
    with pytest.raises(ValueError):
        factory.create(wrapper, bytearray(WRAPPED), expiry, failures)
    with pytest.raises(ValueError):
        factory.create_ephemeral(wrapper, expiry, failures)
    assert (wrapper.unwrap_calls, wrapper.generate_calls) == (0, 0)


def test_factory_refuses_an_impossible_wrapped_length() -> None:
    class Oversized(FakeKeyWrapper):
        def generate_and_wrap(self, result: WritableBuffer) -> int:
            return len(memoryview(result)) + 1

    wrapper = Oversized()
    with pytest.raises(CryptographicError):
        AesGcmCryptoProviderFactory().create_ephemeral(wrapper, 60)
    assert wrapper.unwrap_calls == 0


def test_create_blocks_only_until_a_slow_key_wrapper_answers() -> None:
    wrapper = GatedKeyWrapper()
    result: list[AesGcmCryptoProvider] = []
    thread = threading.Thread(target=lambda: result.append(AesGcmCryptoProviderFactory().create_ephemeral(wrapper, 60)))
    thread.start()

    assert wrapper.started.wait(10)
    assert not result
    wrapper.released.set()
    thread.join(10)
    with result[0] as provider:
        assert round_trip(provider) == b"top secret"


# --- AesGcmPipelineDataProtector --------------------------------------------------------------

ID = "Pipeline:Secret"
VERSION = 3


def pipeline(version: int = VERSION, **kwargs: object) -> AesGcmPipelineDataProtector:
    return AesGcmPipelineDataProtector(TestFormatProvider(), version, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("plaintext", ["hello", "héllo wörld ✓ 🔐", "", "é-秘密-" * 1500])
def test_pipeline_round_trips(plaintext: str) -> None:
    with pipeline() as protector:
        formatted = protector.encrypt(plaintext, ID)
        assert protector.decrypt_to_str(formatted, ID) == plaintext

        result = bytearray(protector.get_max_decrypted_length(formatted))
        assert bytes(result[: protector.decrypt(formatted, ID, result)]) == plaintext.encode()


def test_pipeline_refuses_an_empty_or_invalid_secret_identifier() -> None:
    with pipeline() as protector:
        formatted = protector.encrypt("hello", ID)
        for bad in ["", "Key\ud800"]:
            with pytest.raises(ValueError):
                protector.encrypt("hello", bad)
            with pytest.raises(ValueError):
                protector.decrypt(formatted, bad, bytearray(16))


@pytest.mark.parametrize("lookup", ["pipeline:secret", "PIPELINE:SECRET"])
def test_pipeline_secret_identifiers_ignore_ascii_case(lookup: str) -> None:
    with pipeline() as protector:
        assert protector.decrypt_to_str(protector.encrypt("hello", ID), lookup) == "hello"


def test_pipeline_binds_each_value_to_its_identifier() -> None:
    long_id = ":".join(f"Section{i}" for i in range(60))
    with pipeline() as protector:
        admin = protector.encrypt("admin-secret", "ConnectionStrings:Admin")
        assert protector.decrypt_to_str(admin, "ConnectionStrings:Admin") == "admin-secret"
        with pytest.raises(AuthenticationTagMismatchError):
            protector.decrypt(admin, "ConnectionStrings:Reporting", bytearray(32))

        value = protector.encrypt("hello", long_id)
        assert protector.decrypt_to_str(value, long_id) == "hello"
        with pytest.raises(CryptographicError):
            protector.decrypt(value, long_id + "X", bytearray(16))


def test_pipeline_stamps_its_version_and_fresh_nonces() -> None:
    with pipeline(42) as protector:
        formatted = protector.encrypt("hello", ID)
        assert protector.key_version == 42
        assert formatted.startswith("enc::v42::")
        assert "hello" not in formatted
        assert protector.encrypt("hello", ID) != formatted


def test_pipeline_refuses_another_version_another_instance_and_malformed_input() -> None:
    with pipeline() as protector, pipeline() as other:
        formatted = protector.encrypt("hello", ID)
        with pytest.raises(KeyNotFoundError):
            protector.decrypt(formatted.replace(f"::v{VERSION}::", "::v99::"), ID, bytearray(16))
        with pytest.raises(CryptographicError):
            other.decrypt(formatted, ID, bytearray(16))
        with pytest.raises(EncryptedFormatError):
            protector.decrypt("not-a-valid-format", ID, bytearray(16))


def test_pipeline_with_sensitive_logging_enabled_still_round_trips(spans: InMemorySpanExporter) -> None:
    original = HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled
    HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled = True
    try:
        with pipeline() as protector:
            assert protector.decrypt_to_str(protector.encrypt("hello", ID), ID) == "hello"
        assert finished(spans, SpanNames.DataProtection.PROTECTOR_ENCRYPT)[0].events
    finally:
        HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled = original


def test_pipeline_key_as_base64_is_a_read_only_view_of_one_buffer_holding_the_key() -> None:
    key = os.urandom(32)
    with pipeline(key=bytearray(key)) as protector:
        first = protector.get_key_as_base64()
        second = protector.get_key_as_base64()

        assert bytes(first) == base64.b64encode(key)
        assert first.readonly
        assert first.obj is second.obj

        formatted = protector.encrypt("hello", ID)
        with pipeline(key=bytearray(base64.b64decode(bytes(first)))) as reader:
            assert reader.decrypt_to_str(formatted, ID) == "hello"


@pytest.mark.parametrize("length", range(1, 7))
def test_pipeline_base64_encoding_matches_the_standard_codec_for_every_padding(length: int) -> None:
    from hkdfguard.cryptoprovider.aesgcm256._pipeline import _base64_into

    data = os.urandom(length)
    assert _base64_into(bytearray(data)) == base64.b64encode(data)


def test_pipeline_counts_against_the_keys_budget() -> None:
    with pipeline(key=bytearray(os.urandom(32)), budget=EncryptionBudget(1, 2)) as protector:
        formatted = protector.encrypt("one", ID)
        protector.encrypt("two", ID)
        assert protector.encryption_count == 2
        with pytest.raises(CryptographicError):
            protector.encrypt("three", ID)
        assert protector.decrypt_to_str(formatted, ID) == "one"


def test_pipeline_close_zeroes_the_key_and_its_base64_and_refuses_later_use() -> None:
    key = bytearray(os.urandom(32))
    protector = pipeline(key=key)
    protector.get_key_as_base64()
    base64_buffer = protector.base64_buffer
    formatted = protector.encrypt("hello", ID)

    protector.close()
    protector.close()

    assert key == bytearray(32)
    assert base64_buffer == bytearray(44)
    with pytest.raises(ObjectClosedError):
        protector.encrypt("hello", ID)
    with pytest.raises(ObjectClosedError):
        protector.decrypt(formatted, ID, bytearray(16))
    with pytest.raises(ObjectClosedError):
        protector.get_key_as_base64()


def test_pipeline_requires_a_format_provider() -> None:
    with pytest.raises(TypeError):
        AesGcmPipelineDataProtector(None, VERSION)  # type: ignore[arg-type]


def test_base64_into_matches_the_standard_encoding_for_every_padding_case() -> None:
    from hkdfguard.cryptoprovider.aesgcm256._pipeline import _base64_into

    for length in range(0, 70):
        data = os.urandom(length)
        assert bytes(_base64_into(bytearray(data))) == base64.b64encode(data)
