from __future__ import annotations

import base64
import logging
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Buffer, Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from hkdfguard import abstractions
from hkdfguard.abstractions import (
    AuthenticationTagMismatchError,
    CryptographicError,
    CryptoProvider,
    CryptoProviderFactory,
    EncryptedFormatError,
    EncryptedFormatProvider,
    InvalidKeyFileError,
    KeyNotFoundError,
    KeyTrackingValue,
    KeyWrapper,
    ObjectClosedError,
    ProtectedCacheBase,
    ProtectedConfigurationPurpose,
    WrappedKeyFile,
    WrappedKeyLimits,
    WritableBuffer,
)
from hkdfguard.abstractions._wrapped_key_file import KeyFilePermissions, PathStatus
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider, AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import Base64ConversionUtility, DataEncryptionKey, DefaultFormatProvider, KeyRing, KeyRingBuilder
from hkdfguard.diagnostics import AttributeNames, HkdfGuardLog, HkdfGuardTelemetry, SpanNames
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

# --- Helpers ----------------------------------------------------------------------------------


class FixedKeyWrapper(KeyWrapper):
    """Reveals and "generates" one fixed key, counting calls."""

    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or os.urandom(32)
        self.unwrap_calls = 0

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        self.unwrap_calls += 1
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32


def new_key() -> DataEncryptionKey:
    return DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(), b"wrapped", 60))


class RecordingFactory(CryptoProviderFactory):
    """A real AES-GCM factory, recording every call's arguments and every provider it made."""

    def __init__(self) -> None:
        self.inner = AesGcmCryptoProviderFactory()
        self.create_expiries: list[int] = []
        self.ephemeral_expiries: list[int] = []
        self.policies: list[int | None] = []
        self.wrapped: list[bytes] = []
        self.providers: list[CryptoProvider] = []

    def create(self, wrapper: KeyWrapper, wrapped: bytearray, expiry_seconds: int, max_refresh_failures: int | None = 3) -> CryptoProvider:
        self.create_expiries.append(expiry_seconds)
        self.policies.append(max_refresh_failures)
        self.wrapped.append(bytes(wrapped))
        provider = self.inner.create(wrapper, wrapped, expiry_seconds, max_refresh_failures)
        self.providers.append(provider)
        return provider

    def create_ephemeral(self, wrapper: KeyWrapper, expiry_seconds: int, max_refresh_failures: int | None = 3) -> CryptoProvider:
        self.ephemeral_expiries.append(expiry_seconds)
        self.policies.append(max_refresh_failures)
        provider = self.inner.create_ephemeral(wrapper, expiry_seconds, max_refresh_failures)
        self.providers.append(provider)
        return provider


class RecordingFormatProvider(EncryptedFormatProvider):
    def __init__(self) -> None:
        self.inner = DefaultFormatProvider()
        self.format_called = self.parse_called = False

    def format(self, value: KeyTrackingValue) -> str:
        self.format_called = True
        return self.inner.format(value)

    def parse(self, encrypted: str) -> KeyTrackingValue:
        self.parse_called = True
        return self.inner.parse(encrypted)

    def get_max_decrypted_length(self, encrypted: str) -> int:
        return self.inner.get_max_decrypted_length(encrypted)


class TrackingKey(abstractions.DataEncryptionKey):
    def __init__(self, throw_on_close: bool = False) -> None:
        self.closed = False
        self.throw_on_close = throw_on_close

    def encrypt(self, plaintext: WritableBuffer, *, aad: Buffer = b"") -> bytes:
        return b""

    def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        return 0

    def close(self) -> None:
        self.closed = True
        if self.throw_on_close:
            raise RuntimeError("close failed")


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def with_event_id(self, event_id: int) -> list[logging.LogRecord]:
        return [r for r in list(self.records) if getattr(r, HkdfGuardLog.EVENT_ID_KEY, None) == event_id]


def recording_logger() -> tuple[logging.Logger, RecordingHandler]:
    logger = logging.Logger(f"recording-{id(object())}", logging.DEBUG)
    handler = RecordingHandler()
    logger.addHandler(handler)
    return logger, handler


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled
    HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled = original


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    HkdfGuardTelemetry.set_tracer_provider(provider)
    yield exporter
    HkdfGuardTelemetry.set_tracer_provider(None)


def builder(factory: CryptoProviderFactory | None = None) -> KeyRingBuilder:
    return (KeyRingBuilder().with_key_wrapper(FixedKeyWrapper()).with_crypto_provider_factory(factory or AesGcmCryptoProviderFactory())
            .with_key_refresh_interval(60))


def ring_with_one_key(format_provider: EncryptedFormatProvider | None = None) -> KeyRing:
    ring = KeyRing(format_provider or DefaultFormatProvider())
    ring.add(1, new_key())
    return ring


# --- Base64ConversionUtility ------------------------------------------------------------------


@pytest.mark.parametrize(("text", "valid"), [("AAAA", True), ("AAA=", True), ("AA==", True), ("", True), ("not valid base64!!!", False),
                                              ("AAA", False), ("A===", False), ("AA=A", False), ("=AAA", False), ("AAAA\n", False)])
def test_base64_validation_is_strict(text: str, valid: bool) -> None:
    assert Base64ConversionUtility.is_base64(text) is valid


def test_base64_lengths_and_round_trips() -> None:
    assert [Base64ConversionUtility.get_binary_length(t) for t in ("", "QQ==", "QUI=", "QUJD")] == [0, 1, 2, 3]
    assert [Base64ConversionUtility.get_base64_length(bytes(n)) for n in range(5)] == [0, 4, 4, 4, 8]
    with pytest.raises(EncryptedFormatError):
        Base64ConversionUtility.get_binary_length("AAA")

    text = Base64ConversionUtility.to_base64_string(b"hello world")
    destination = bytearray(Base64ConversionUtility.get_binary_length(text))
    assert Base64ConversionUtility.from_base64(text, destination) == 11 and destination == b"hello world"
    assert Base64ConversionUtility.is_base64(b"AAAA") and not Base64ConversionUtility.is_base64(b"\xc3\xa9AA")
    for bad, size in (("not valid base64!!!", 16), ("QUJD", 1), ("QUJ", 16)):
        with pytest.raises(EncryptedFormatError):
            Base64ConversionUtility.from_base64(bad, bytearray(size))


# --- DefaultFormatProvider --------------------------------------------------------------------

PROVIDER = DefaultFormatProvider()


def test_the_wire_format_matches_every_other_port() -> None:
    assert PROVIDER.format(KeyTrackingValue(1, bytes([1, 2, 3]))) == "enc::v1::AQID"
    parsed = PROVIDER.parse("enc::v7::aGVsbG8=")
    assert (parsed.key_version, parsed.value) == (7, b"hello")
    assert PROVIDER.parse(PROVIDER.format(KeyTrackingValue(-5, b"\x01"))).key_version == -5
    assert PROVIDER.parse(PROVIDER.format(KeyTrackingValue(1, b""))).value == b""


def test_format_parse_and_max_length_work_with_sensitive_logging(sensitive: None) -> None:
    formatted = PROVIDER.format(KeyTrackingValue(2, b"abc"))
    assert PROVIDER.parse(formatted).value == b"abc"
    assert PROVIDER.get_max_decrypted_length(formatted) == 3


@pytest.mark.parametrize("text", ["", "no-delimiters-at-all", "enc::onlyonepart", "wrong::v1::AAAA", "enc::1::AAAA", "enc::vNotANumber::AAAA",
                                  "enc::v1::not-valid-base64!!!", "enc::v+1::AQID", "enc::v 1::AQID", "enc::v1 ::AQID", "enc::v~1::AQID",
                                  "enc::v::AQID", "enc::v-::AQID", "enc::v١::AQID", "enc::v1_0::AQID", "enc::v99999999999::AQID",
                                  "enc::v1::AQID    ", "enc::v1::AQ ID", "enc::v1::AQID\t", "enc::v1::AQID\r\n", "enc::v1:: AQID"])
def test_anything_but_the_canonical_form_is_malformed(text: str) -> None:
    with pytest.raises(EncryptedFormatError):
        PROVIDER.parse(text)
    with pytest.raises(EncryptedFormatError):
        PROVIDER.get_max_decrypted_length(text)


def test_the_length_limit_applies_to_format_and_parse() -> None:
    assert DefaultFormatProvider.DEFAULT_MAX_ENCRYPTED_LENGTH == 4096 == PROVIDER.max_encrypted_length
    # "enc::v1234::" is 12 characters, leaving 4084 for base64 - which encodes 3063 bytes.
    exact = KeyTrackingValue(1234, os.urandom(3063))
    formatted = PROVIDER.format(exact)
    assert len(formatted) == 4096 and PROVIDER.parse(formatted).value == exact.value
    with pytest.raises(ValueError, match="4096"):
        PROVIDER.format(KeyTrackingValue(1234, os.urandom(3064)))
    with pytest.raises(EncryptedFormatError):
        PROVIDER.parse("enc::v1234::" + "A" * 4088)

    small = DefaultFormatProvider(64)
    with pytest.raises(ValueError):
        small.format(KeyTrackingValue(1, bytes(40)))
    assert len(small.parse(small.format(KeyTrackingValue(1, bytes(39)))).value) == 39
    for bad in (0, -1):
        with pytest.raises(ValueError):
            DefaultFormatProvider(bad)


# --- DataEncryptionKey ------------------------------------------------------------------------


def test_a_key_round_trips_with_and_without_aad_and_sizes_exactly() -> None:
    with new_key() as key:
        encrypted = key.encrypt(bytearray(b"top secret"))
        assert len(encrypted) == 10 + 28
        result = bytearray(10)
        assert key.decrypt(encrypted, result) == 10 and result == b"top secret"

        encrypted = key.encrypt(bytearray(b"top secret"), aad=b"context-a")
        with pytest.raises(AuthenticationTagMismatchError):
            key.decrypt(encrypted, bytearray(10), aad=b"context-b")


def test_a_key_zeroes_the_plaintext_and_reuses_its_cached_session(sensitive: None) -> None:
    wrapper = FixedKeyWrapper()
    with DataEncryptionKey(AesGcmCryptoProvider.create(wrapper, b"wrapped", 60)) as key:
        plaintext = bytearray(b"top secret")
        one = key.encrypt(plaintext, aad=b"aad")
        assert plaintext == bytearray(10)
        key.decrypt(one, bytearray(10), aad=b"aad")
        key.decrypt(key.encrypt(bytearray(b"two")), bytearray(3))
        assert wrapper.unwrap_calls == 1


def test_closing_a_key_closes_its_provider_once() -> None:
    key = new_key()
    key.close()
    key.close()
    with pytest.raises(ObjectClosedError):
        key.encrypt(bytearray(b"top secret"))


def test_an_over_allocating_provider_is_trimmed() -> None:
    class OverAllocating(CryptoProvider):
        def encrypt(self, plaintext: WritableBuffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
            data = bytes(plaintext)
            memoryview(result)[: len(data)] = data
            return len(data)

        def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
            raise NotImplementedError

        def get_encrypted_allocation_length(self, length: int) -> int:
            return length + 10

        def get_decrypted_allocation_length(self, length: int) -> int:
            return length

        def close(self) -> None:
            pass

    assert DataEncryptionKey(OverAllocating()).encrypt(bytearray(b"abc")) == b"abc"


# --- KeyRing ----------------------------------------------------------------------------------


def test_an_empty_ring_has_no_current_key() -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        with pytest.raises(RuntimeError):
            _ = ring.current_version
        with pytest.raises(RuntimeError):
            ring.get_current()
        with pytest.raises(RuntimeError):
            ring.create_protector("purpose").encrypt("hello")


def test_the_highest_version_added_is_current_whatever_the_order(sensitive: None) -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        key = new_key()
        ring.add(1, new_key())
        ring.add(5, key)
        ring.add(3, new_key())
        assert ring.current_version == 5
        assert ring.get_current() == (5, key)
        assert ring.get(5) is key and ring.find(5) is key and ring.find(999) is None
        with pytest.raises(KeyNotFoundError):
            ring.get(999)


def test_a_rejected_add_leaves_ownership_with_the_caller() -> None:
    ring = ring_with_one_key()
    rejected = new_key()
    with pytest.raises(ValueError, match="already registered"):
        ring.add(1, rejected)
    ring.close()

    assert len(rejected.encrypt(bytearray(b"value"))) > 0
    rejected.close()
    with pytest.raises(ObjectClosedError):
        ring.add(2, TrackingKey())


def test_close_closes_every_closable_key_and_keeps_going_past_a_failure() -> None:
    ring = KeyRing(DefaultFormatProvider())
    real, failing, after = new_key(), TrackingKey(throw_on_close=True), TrackingKey()
    ring.add(1, real)
    ring.add(2, failing)
    ring.add(3, after)

    ring.close()
    ring.close()

    assert failing.closed and after.closed
    with pytest.raises(ObjectClosedError):
        real.encrypt(bytearray(b"value"))


@pytest.mark.parametrize("version", [-(2**31), -1, 0, 2**31 - 1])
def test_any_int_version_becomes_current_and_round_trips(version: int) -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(version, new_key())
        assert ring.current_version == version
        protector = ring.create_protector("range")
        assert protector.decrypt_to_str(protector.encrypt("value")) == "value"


# --- Data protectors --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["HkdfGuard.Cache:", "HkdfGuard.Cache:SECRET", "", "purpose\ud800", "purpose\udc00tail"])
def test_create_protector_refuses_reserved_empty_and_invalid_names(name: str) -> None:
    with KeyRing(DefaultFormatProvider()) as ring, pytest.raises(ValueError):
        ring.create_protector(name)


@pytest.mark.parametrize("name", ["hkdfguard.cache:secret", "MyApp.Cache:secret", "HkdfGuard.EncryptedConfiguration:ConnectionStrings:Admin"])
def test_create_protector_accepts_every_other_name(name: str) -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        assert ring.create_protector(name) is not None


def test_no_protector_can_share_a_cache_entrys_aad() -> None:
    assert ProtectedCacheBase.aad_for("secret") == b"HkdfGuard.Cache:SECRET"
    with KeyRing(DefaultFormatProvider()) as ring, pytest.raises(ValueError, match="reserved"):
        ring.create_protector("HkdfGuard.Cache:SECRET")


@pytest.mark.parametrize("plaintext", ["hello", "x" * 4096, "é-秘密-" * 1500])
def test_a_protector_round_trips_small_and_large_values(plaintext: str, sensitive: None) -> None:
    with KeyRing(DefaultFormatProvider(100_000)) as ring:
        ring.add(1, new_key())
        protector = ring.create_protector("purpose")
        formatted = protector.encrypt(plaintext)

        assert protector.decrypt_to_str(formatted) == plaintext
        result = bytearray(protector.get_max_decrypted_length(formatted))
        assert bytes(result[: protector.decrypt(formatted, result)]) == plaintext.encode()


def test_a_protector_refuses_another_name_another_version_and_malformed_input() -> None:
    with ring_with_one_key() as ring:
        formatted = ring.create_protector("purpose-a").encrypt("hello")
        with pytest.raises(AuthenticationTagMismatchError):
            ring.create_protector("purpose-b").decrypt(formatted, bytearray(16))
        with pytest.raises(KeyNotFoundError):
            ring.create_protector("purpose-a").decrypt(formatted.replace("::v1::", "::v99::"), bytearray(16))
        with pytest.raises(EncryptedFormatError):
            ring.create_protector("purpose-a").decrypt("not-a-valid-format", bytearray(16))


def test_a_protector_uses_the_rings_format_provider_and_propagates_key_failures() -> None:
    recording = RecordingFormatProvider()
    with ring_with_one_key(recording) as ring:
        formatted = ring.create_protector("purpose").encrypt("hello")
        assert ring.create_protector("purpose").decrypt_to_str(formatted) == "hello"
        assert recording.format_called and recording.parse_called

    class Throwing(TrackingKey):
        def encrypt(self, plaintext: WritableBuffer, *, aad: Buffer = b"") -> bytes:
            raise RuntimeError("encrypt failed")

    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, Throwing())
        with pytest.raises(RuntimeError, match="encrypt failed"):
            ring.create_protector("purpose").encrypt("hello")


# --- KeyRingBuilder ---------------------------------------------------------------------------


def test_builder_configuration_and_its_limits() -> None:
    assert KeyRingBuilder().with_service_name("my.service").service_name == "my.service"
    for bad in (".service", "my..service", "my-service", ""):
        with pytest.raises(ValueError):
            KeyRingBuilder().with_service_name(bad)
    with pytest.raises(TypeError):
        KeyRingBuilder().with_service_name(None)  # type: ignore[arg-type]

    assert KeyRingBuilder().with_key_refresh_interval(300).key_refresh_interval == 300
    for interval in (-1, 0, 301):
        with pytest.raises(ValueError):
            KeyRingBuilder().with_key_refresh_interval(interval)

    b = KeyRingBuilder()
    assert b.max_refresh_failures == KeyRingBuilder.DEFAULT_MAX_REFRESH_FAILURES == 3
    assert b.with_max_refresh_failures(5).max_refresh_failures == 5
    assert b.with_fail_open_on_refresh_failure().max_refresh_failures is None
    with pytest.raises(ValueError):
        b.with_max_refresh_failures(0)
    with pytest.raises(ValueError, match="already registered"):
        KeyRingBuilder().with_key_file(1, "a.bin").with_key_file(1, "b.bin")


def test_build_with_missing_configuration_names_what_is_missing() -> None:
    factory = AesGcmCryptoProviderFactory()
    with pytest.raises(RuntimeError, match=r"A key wrapper is required - call with_key_wrapper first\."):
        KeyRingBuilder().with_crypto_provider_factory(factory).with_key_refresh_interval(60).with_ephemeral_key(1).build()
    with pytest.raises(RuntimeError, match="A crypto provider factory is required"):
        KeyRingBuilder().with_key_wrapper(FixedKeyWrapper()).with_key_refresh_interval(60).with_ephemeral_key(1).build()
    with pytest.raises(RuntimeError, match="At least one key file or ephemeral key"):
        builder().build()
    with pytest.raises(RuntimeError, match="key refresh interval"):
        KeyRingBuilder().with_key_wrapper(FixedKeyWrapper()).with_crypto_provider_factory(factory).with_ephemeral_key(1).build()


def test_build_gives_a_working_ring_whose_highest_version_is_current(tmp_path: Path) -> None:
    (tmp_path / "v1.bin").write_bytes(b"wrapped-v1")
    (tmp_path / "v2.bin").write_bytes(b"wrapped-v2")
    recording = RecordingFormatProvider()

    with builder().with_key_file(1, tmp_path / "v1.bin").with_key_file(2, tmp_path / "v2.bin").with_ephemeral_key(3) \
            .with_format_provider(recording).build() as ring:
        assert ring.current_version == 3
        protector = ring.create_protector("purpose")
        assert protector.decrypt_to_str(protector.encrypt("hello")) == "hello"
        assert recording.format_called


def test_build_passes_the_refresh_interval_and_policy_through(tmp_path: Path) -> None:
    path = tmp_path / "v1.bin"
    path.write_bytes(b"wrapped")
    factories = [RecordingFactory() for _ in range(3)]

    with builder(factories[0]).with_key_refresh_interval(123).with_max_refresh_failures(5).with_key_file(1, path).with_ephemeral_key(42).build(), \
            builder(factories[1]).with_key_file(1, path).with_ephemeral_key(2).build(), \
            builder(factories[2]).with_fail_open_on_refresh_failure().with_key_file(1, path).with_ephemeral_key(2).build():
        assert factories[0].create_expiries == [123] and factories[0].ephemeral_expiries == [123]
        assert factories[0].policies == [5, 5]
        assert factories[1].policies == [3, 3]
        assert factories[2].policies == [None, None]


def test_a_failed_build_closes_every_provider_it_created(tmp_path: Path) -> None:
    path = tmp_path / "v1.bin"
    path.write_bytes(b"wrapped")

    duplicate = RecordingFactory()
    with pytest.raises(ValueError):
        builder(duplicate).with_key_file(1, path).with_ephemeral_key(1).build()
    assert len(duplicate.providers) == 2

    missing = RecordingFactory()
    with pytest.raises(FileNotFoundError):
        builder(missing).with_key_file(1, path).with_key_file(2, tmp_path / "missing.bin").build()
    assert len(missing.providers) == 1

    for provider in duplicate.providers + missing.providers:
        with pytest.raises(ObjectClosedError):
            provider.encrypt(bytearray(b"\x01"), bytearray(64))


def test_the_built_ring_owns_its_providers() -> None:
    factory = RecordingFactory()
    builder(factory).with_ephemeral_key(1).build().close()
    with pytest.raises(ObjectClosedError):
        factory.providers[0].encrypt(bytearray(b"\x01"), bytearray(64))


@pytest.mark.parametrize("length", [1, 156, WrappedKeyLimits.MAX_BYTES])
def test_key_files_up_to_the_limit_are_read_whole(tmp_path: Path, length: int) -> None:
    content = os.urandom(length)
    path = tmp_path / "v1.bin"
    path.write_bytes(content)
    factory = RecordingFactory()

    with builder(factory).with_key_file(1, path).build():
        assert factory.wrapped == [content]


@pytest.mark.parametrize(("length", "message"), [(0, "is empty"), (WrappedKeyLimits.MAX_BYTES + 1, "larger than 512 bytes"),
                                                 (10 * 1024 * 1024, "larger than 512 bytes")])
def test_empty_or_oversized_key_files_are_refused(tmp_path: Path, length: int, message: str) -> None:
    path = tmp_path / "v1.bin"
    path.write_bytes(bytes(length))
    with pytest.raises(InvalidKeyFileError, match=message):
        builder().with_key_file(1, path).build()
    with pytest.raises(OSError, match=message):  # still an OSError, as it always was
        WrappedKeyFile.read(path)


def test_the_default_read_refuses_a_missing_path_before_opening_anything() -> None:
    with pytest.raises(TypeError):
        WrappedKeyFile.read(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        WrappedKeyFile.read("")


# --- Ephemeral key rotation -------------------------------------------------------------------

FAST = timedelta(milliseconds=150)


def test_rotation_and_retention_settings_and_their_limits() -> None:
    b = KeyRingBuilder()
    assert b.ephemeral_key_rotation_interval == timedelta(hours=24) == KeyRingBuilder.DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL
    assert b.ephemeral_key_retention == timedelta(hours=24)
    assert b.with_ephemeral_key_rotation(timedelta(hours=6)).ephemeral_key_rotation_interval == timedelta(hours=6)
    b.with_ephemeral_key_rotation(KeyRingBuilder.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL)
    for bad in (timedelta(minutes=59), timedelta(0), KeyRingBuilder.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL + timedelta(milliseconds=1)):
        with pytest.raises(ValueError):
            KeyRingBuilder().with_ephemeral_key_rotation(bad)
    assert b.without_ephemeral_key_rotation().ephemeral_key_rotation_interval is None
    assert b.with_ephemeral_key_retention(timedelta(minutes=1)).ephemeral_key_retention == timedelta(minutes=1)
    with pytest.raises(ValueError):
        KeyRingBuilder().with_ephemeral_key_retention(timedelta(seconds=59))


def test_a_ring_with_an_ephemeral_key_rotates_and_old_values_still_decrypt() -> None:
    logger, handler = recording_logger()
    with builder().with_ephemeral_key(1)._with_ephemeral_key_rotation_for_testing(FAST).with_logger(logger).build() as ring:
        protector = ring.create_protector("rotation")
        under_v1 = protector.encrypt("written under v1")
        assert ring.ephemeral_key_rotation_interval == FAST

        time.sleep(FAST.total_seconds() * 4)

        assert ring.current_version >= 3
        assert protector.encrypt("now").split("::")[1] == f"v{ring.current_version}"
        assert protector.decrypt_to_str(under_v1) == "written under v1"
        assert any(r.levelno == logging.INFO for r in handler.with_event_id(HkdfGuardLog.EPHEMERAL_KEY_ROTATED))


def test_key_files_alone_or_rotation_off_never_rotate(tmp_path: Path) -> None:
    path = tmp_path / "v4.bin"
    path.write_bytes(b"wrapped")
    factory = RecordingFactory()
    with builder(factory).with_key_file(4, path)._with_ephemeral_key_rotation_for_testing(FAST).build() as files_only, \
            builder(factory).with_ephemeral_key(1).without_ephemeral_key_rotation()._with_ephemeral_key_retention_for_testing(FAST).build() as off:
        time.sleep(FAST.total_seconds() * 3)
        assert files_only.ephemeral_key_rotation_interval is None and files_only.current_version == 4
        assert off.ephemeral_key_rotation_interval is None and off.ephemeral_key_retention is None and off.current_version == 1
        assert len(factory.ephemeral_expiries) == 1


def test_rotated_keys_get_the_rings_expiry_and_policy() -> None:
    factory = RecordingFactory()
    with builder(factory).with_max_refresh_failures(7).with_ephemeral_key(1)._with_ephemeral_key_rotation_for_testing(FAST).build():
        time.sleep(FAST.total_seconds() * 3)
    assert len(factory.ephemeral_expiries) >= 2
    assert set(factory.ephemeral_expiries) == {60} and set(factory.policies) == {7}


def test_a_failed_rotation_keeps_the_current_key_and_logs_and_the_next_succeeds() -> None:
    class Flaky(RecordingFactory):
        armed = False
        failures = 0

        def create_ephemeral(self, wrapper: KeyWrapper, expiry_seconds: int, max_refresh_failures: int | None = 3) -> CryptoProvider:
            if self.armed and self.failures < 1:
                self.failures += 1
                raise CryptographicError("KEK unavailable")
            return super().create_ephemeral(wrapper, expiry_seconds, max_refresh_failures)

    logger, handler = recording_logger()
    factory = Flaky()
    with builder(factory).with_ephemeral_key(1)._with_ephemeral_key_rotation_for_testing(FAST).with_logger(logger).build() as ring:
        factory.armed = True
        time.sleep(FAST.total_seconds() * 4)

        (failure,) = handler.with_event_id(HkdfGuardLog.EPHEMERAL_KEY_ROTATION_FAILED)
        assert failure.levelno == logging.ERROR and "version 1 stays current" in failure.getMessage()
        assert ring.current_version >= 2


def test_close_stops_rotation_even_while_a_rotation_waits_on_the_key_wrapper() -> None:
    factory = RecordingFactory()
    ring = builder(factory).with_ephemeral_key(1)._with_ephemeral_key_rotation_for_testing(FAST).build()
    ring.close()
    calls = len(factory.ephemeral_expiries)
    time.sleep(FAST.total_seconds() * 3)
    assert len(factory.ephemeral_expiries) == calls

    hanging = threading.Event()
    release = threading.Event()

    class Hanging(RecordingFactory):
        armed = False

        def create_ephemeral(self, wrapper: KeyWrapper, expiry_seconds: int, max_refresh_failures: int | None = 3) -> CryptoProvider:
            if self.armed:
                hanging.set()
                release.wait(10)
            return super().create_ephemeral(wrapper, expiry_seconds, max_refresh_failures)

    hanging_factory = Hanging()
    ring = builder(hanging_factory).with_ephemeral_key(1)._with_ephemeral_key_rotation_for_testing(FAST).build()
    hanging_factory.armed = True
    assert hanging.wait(10)
    started = time.monotonic()
    ring.close()
    assert time.monotonic() - started < 1  # never waits on the hung KMS call

    release.set()
    time.sleep(0.3)
    # The late key found the ring closed and closed itself.
    with pytest.raises(ObjectClosedError):
        hanging_factory.providers[-1].encrypt(bytearray(b"\x01"), bytearray(64))


def test_a_rotating_ring_retires_superseded_keys_once_their_retention_passes() -> None:
    logger, handler = recording_logger()
    factory = RecordingFactory()
    with builder(factory).with_ephemeral_key(1)._with_ephemeral_key_rotation_for_testing(FAST) \
            ._with_ephemeral_key_retention_for_testing(FAST * 2.5).with_logger(logger).build() as ring:
        protector = ring.create_protector("retention")
        under_v1 = protector.encrypt("written under v1")

        time.sleep(FAST.total_seconds() * 8)

        assert ring.find(1) is None
        with pytest.raises(KeyNotFoundError):
            protector.decrypt(under_v1, bytearray(64))
        assert any("version 1 " in r.getMessage() for r in handler.with_event_id(HkdfGuardLog.EPHEMERAL_KEY_RETIRED))
        with pytest.raises(ObjectClosedError):
            factory.providers[0].encrypt(bytearray(b"\x01"), bytearray(64))
        current = ring.current_version
        assert current >= 5 and ring.find(current) is not None and ring.find(current - 1) is not None
        assert protector.decrypt_to_str(protector.encrypt("still works")) == "still works"


def never_stopping() -> bool:
    return False


def test_retire_keeps_a_superseded_key_until_its_retention_has_passed() -> None:
    logger, handler = recording_logger()
    with KeyRing(DefaultFormatProvider()) as ring:
        superseded = TrackingKey()
        ring.add(1, superseded)
        ring._configure_ephemeral_key_retention(timedelta(hours=1), [1])

        assert ring._rotate_ephemeral_key(TrackingKey, logger, never_stopping)
        assert ring.find(1) is not None

        ring._retire_superseded_ephemeral_keys(time.monotonic_ns() + 59 * 60 * 10**9, logger, never_stopping)
        assert ring.find(1) is not None and not superseded.closed

        ring._retire_superseded_ephemeral_keys(time.monotonic_ns() + 61 * 60 * 10**9, logger, never_stopping)
        assert ring.find(1) is None and superseded.closed and ring.current_version == 2
        (retired,) = handler.with_event_id(HkdfGuardLog.EPHEMERAL_KEY_RETIRED)
        assert "version 1 " in retired.getMessage()


def test_retire_never_touches_key_files_or_the_current_key_and_needs_retention() -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        key_file, ephemeral = TrackingKey(), TrackingKey()
        ring.add(1, key_file)
        ring.add(2, ephemeral)
        ring._configure_ephemeral_key_retention(timedelta(hours=1), [2])

        assert ring._rotate_ephemeral_key(TrackingKey, None, never_stopping)
        ring._retire_superseded_ephemeral_keys(time.monotonic_ns() + 365 * 86400 * 10**9, None, never_stopping)

        assert ring.find(1) is not None and not key_file.closed
        assert ring.find(2) is None and ephemeral.closed
        assert ring.find(3) is not None and ring.current_version == 3

    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, TrackingKey())
        assert ring._rotate_ephemeral_key(TrackingKey, None, never_stopping)
        ring._retire_superseded_ephemeral_keys(time.monotonic_ns() + 365 * 86400 * 10**9, None, never_stopping)
        assert ring.ephemeral_key_retention is None and ring.find(1) is not None


def test_retire_removes_a_key_whose_close_fails_and_logs_it() -> None:
    logger, handler = recording_logger()
    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, TrackingKey(throw_on_close=True))
        ring._configure_ephemeral_key_retention(timedelta(minutes=1), [1])
        assert ring._rotate_ephemeral_key(TrackingKey, logger, never_stopping)

        ring._retire_superseded_ephemeral_keys(time.monotonic_ns() + 2 * 60 * 10**9, logger, never_stopping)

        assert ring.find(1) is None
        (failure,) = handler.with_event_id(HkdfGuardLog.EPHEMERAL_KEY_RETIREMENT_FAILED)
        assert failure.levelno == logging.ERROR


def test_rotate_closes_a_key_it_could_not_add_and_refuses_at_the_last_version() -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, TrackingKey())
        made = TrackingKey()

        def take_version_two_first() -> TrackingKey:
            ring.add(2, TrackingKey())
            return made

        assert not ring._rotate_ephemeral_key(take_version_two_first, None, never_stopping)
        assert made.closed and ring.current_version == 2

    logger, handler = recording_logger()
    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(2**31 - 1, TrackingKey())
        created: list[int] = []
        assert not ring._rotate_ephemeral_key(lambda: created.append(1) or TrackingKey(), logger, never_stopping)  # type: ignore[func-returns-value]
        assert created == []
        (entry,) = handler.records
        assert entry.exc_info is not None and "no higher version" in str(entry.exc_info[1])


def test_rotate_during_shutdown_reraises_and_still_closes_its_key() -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, TrackingKey())
        made = TrackingKey()
        stopping = threading.Event()

        def fail_during_shutdown() -> TrackingKey:
            stopping.set()
            ring.add(2, TrackingKey())  # makes the rotation's own add fail
            return made

        with pytest.raises(ValueError):
            ring._rotate_ephemeral_key(fail_during_shutdown, None, stopping.is_set)
        assert made.closed


def test_rotate_records_a_span_tagged_with_the_new_version(spans: InMemorySpanExporter) -> None:
    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(41, TrackingKey())
        assert ring._rotate_ephemeral_key(TrackingKey, None, never_stopping)

    (rotation,) = [s for s in spans.get_finished_spans() if s.name == SpanNames.DataProtection.KEY_RING_ROTATE_EPHEMERAL]
    assert rotation.attributes is not None and rotation.attributes[AttributeNames.KEY_VERSION] == 42


# --- Pipeline interop -------------------------------------------------------------------------

ID = "Pipeline:Secret"


def ring_holding(key: bytes, version: int = 3) -> KeyRing:
    ring = KeyRing(DefaultFormatProvider())
    ring.add(version, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(key), b"\x01", 60)))
    return ring


def test_pipeline_values_decrypt_through_a_ring_protector_for_the_identifiers_purpose() -> None:
    with AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as pipeline:
        formatted = pipeline.encrypt("hello", ID)
        key = base64.b64decode(bytes(pipeline.get_key_as_base64()))

        with ring_holding(key) as ring:
            assert ring.create_protector(ProtectedConfigurationPurpose.for_key(ID)).decrypt_to_str(formatted) == "hello"
            assert ring.create_protector(ProtectedConfigurationPurpose.for_key(ID.upper())).decrypt_to_str(formatted) == "hello"
            with pytest.raises(AuthenticationTagMismatchError):
                ring.create_protector(ID).decrypt(formatted, bytearray(16))
            with pytest.raises(AuthenticationTagMismatchError):
                ring.create_protector(ProtectedConfigurationPurpose.for_key("Pipeline:Other")).decrypt(formatted, bytearray(16))

            # And the reverse: what the ring writes under the purpose, the pipeline reads.
            written = ring.create_protector(ProtectedConfigurationPurpose.for_key(ID)).encrypt("from the ring")
            assert pipeline.decrypt_to_str(written, ID) == "from the ring"


# --- Native end to end ------------------------------------------------------------------------


@pytest.fixture(scope="module")
def native_service() -> str:
    explicit = os.environ.get("HKDFGUARD_TEST_SERVICE")
    if explicit:
        return explicit
    if sys.platform != "win32":
        pytest.skip("Set HKDFGUARD_TEST_SERVICE to a provisioned service to run native end-to-end tests.")
    from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1, NativeLibraryNotFoundError

    candidate = "com.hkdfguard.native.windows.test"
    try:
        NativeHkdfKeyWrapperV1(candidate).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))
    except NativeLibraryNotFoundError as error:
        pytest.skip(str(error))
    except CryptographicError as error:
        if "status -17" in str(error) or "status -18" in str(error):  # KEK not found / access denied
            pytest.skip(f"The Windows test KEK is unavailable: {error} Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, "
                        "or set HKDFGUARD_TEST_SERVICE to a provisioned service.")
        raise
    return candidate


@pytest.fixture
def key_dir(tmp_path: Path) -> Path:
    """tmp_path with every 8.3 short name expanded: the native library refuses a key file path that
    uses one, and Windows can hand out %TEMP% in short form (C:\\Users\\RUNNER~1\\... on CI runners)."""
    if sys.platform == "win32":
        import ctypes

        buffer = ctypes.create_unicode_buffer(32_767)
        length = ctypes.WinDLL("kernel32").GetLongPathNameW(str(tmp_path), buffer, len(buffer))
        if 0 < length < len(buffer):
            return Path(buffer.value)
    return tmp_path


def native_builder(service: str) -> KeyRingBuilder:
    from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1

    return (KeyRingBuilder().with_service_name(service).with_key_wrapper(NativeHkdfKeyWrapperV1(service))
            .with_crypto_provider_factory(AesGcmCryptoProviderFactory()).with_key_refresh_interval(60))


def run_pipeline(service: str, directory: Path, secrets: dict[str, str]) -> tuple[Path, dict[str, str]]:
    """What a release pipeline does: protect configuration under a fresh key, wrap that key under
    the native KEK, and write the wrapped key as the release's key file."""
    from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1

    with AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as pipeline:
        configuration = {key: pipeline.encrypt(secret, key) for key, secret in secrets.items()}
        dek = bytearray(base64.b64decode(bytes(pipeline.get_key_as_base64())))
        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        length = NativeHkdfKeyWrapperV1(service).wrap(dek, wrapped)
        path = directory / "wrapped-dek-v3.bin"
        path.write_bytes(wrapped[:length])
        return path, configuration


def read(ring: KeyRing, configuration: dict[str, str], key: str) -> str:
    return ring.create_protector(ProtectedConfigurationPurpose.for_key(key)).decrypt_to_str(configuration[key])


def test_a_deployment_decrypts_through_its_natively_wrapped_key_file(native_service: str, key_dir: Path) -> None:
    key_file, configuration = run_pipeline(native_service, key_dir, {"ConnectionStrings:Admin": "Server=db;Password=s3cret", "Api:Key": "k-0123"})

    with native_builder(native_service).with_key_file(3, key_file).build() as ring:
        assert read(ring, configuration, "ConnectionStrings:Admin") == "Server=db;Password=s3cret"
        assert read(ring, configuration, "Api:Key") == "k-0123"

    configuration["Api:Key"] = configuration["ConnectionStrings:Admin"]  # an edited configuration file
    with native_builder(native_service).with_key_file(3, key_file).build() as ring, pytest.raises(AuthenticationTagMismatchError):
        read(ring, configuration, "Api:Key")


def test_a_restart_reading_the_same_key_file_reveals_the_same_key(native_service: str, key_dir: Path) -> None:
    key_file, configuration = run_pipeline(native_service, key_dir, {"Secret": "survives a restart"})

    with native_builder(native_service).with_key_file(3, key_file).build() as first:
        assert read(first, configuration, "Secret") == "survives a restart"
    with native_builder(native_service).with_key_file(3, key_file).build() as second:
        assert read(second, configuration, "Secret") == "survives a restart"


def test_a_key_file_for_another_service_or_tampered_refuses_to_build(native_service: str, key_dir: Path) -> None:
    key_file, _ = run_pipeline(native_service, key_dir, {"Secret": "value"})
    other = os.environ.get("HKDFGUARD_TEST_SERVICE_OTHER") or "hkdfguard.integrationtest.unprovisioned"
    with pytest.raises(CryptographicError):
        native_builder(other).with_key_file(3, key_file).build()

    data = bytearray(key_file.read_bytes())
    data[len(data) // 2] ^= 0x01
    key_file.write_bytes(data)
    # Refused when the key file is read (a structural byte) or when it is unwrapped (anything else).
    with pytest.raises((CryptographicError, InvalidKeyFileError)):
        native_builder(native_service).with_key_file(3, key_file).build()


def test_runtime_keys_generated_through_the_native_kek_protect_values_and_the_cache(native_service: str) -> None:
    from hkdfguard.cache import ProtectedCache

    with native_builder(native_service).with_ephemeral_key(100).build() as ring:
        protector = ring.create_protector("session")
        formatted = protector.encrypt("runtime value")
        assert formatted.startswith("enc::v100::")
        assert protector.decrypt_to_str(formatted) == "runtime value"

        cache = ProtectedCache(ring)
        cache.add("token", "cached secret")
        assert cache.decrypt_to_str("token") == "cached secret"


def test_deployed_and_runtime_keys_together_and_refresh_against_the_real_kek(native_service: str, key_dir: Path) -> None:
    key_file, configuration = run_pipeline(native_service, key_dir, {"Secret": "from the release"})

    with native_builder(native_service).with_key_file(3, key_file).with_ephemeral_key(100).build() as ring:
        assert read(ring, configuration, "Secret") == "from the release"
        assert ring.current_version == 100
        assert ring.create_protector("new").encrypt("value").startswith("enc::v100::")

    with native_builder(native_service).with_key_refresh_interval(1).with_ephemeral_key(1).build() as ring:
        protector = ring.create_protector("refresh")
        before = protector.encrypt("written before the refreshes")
        time.sleep(2.5)  # two background re-reveals through the native KEK
        assert protector.decrypt_to_str(before) == "written before the refreshes"
        assert protector.decrypt_to_str(protector.encrypt("written after")) == "written after"


@pytest.mark.parametrize("version", [-(2**31) - 1, 2**31])
def test_a_version_outside_the_signed_32_bit_range_is_refused_everywhere(version: int) -> None:
    from hkdfguard.abstractions import KeyTrackingValue

    with pytest.raises(ValueError, match="key_version must be between"):
        DefaultFormatProvider().format(KeyTrackingValue(version, b"x"))
    with KeyRing(DefaultFormatProvider()) as ring, pytest.raises(ValueError, match="version must be between"):
        ring.add(version, TrackingKey())
    with pytest.raises(ValueError, match="version must be between"):
        KeyRingBuilder().with_key_file(version, "a.bin")
    with pytest.raises(ValueError, match="version must be between"):
        KeyRingBuilder().with_ephemeral_key(version)


def _status(owner: int, mode: int) -> PathStatus:
    return PathStatus(owner, mode)


_FILE = stat.S_IFREG
_DIR = stat.S_IFDIR


@pytest.mark.parametrize(("owner", "mode"), [(1000, _FILE | 0o600), (1000, _FILE | 0o644), (0, _FILE | 0o644), (0, _FILE | 0o400)])
def test_a_key_file_owned_by_root_or_the_user_and_writable_by_no_one_else_passes(owner: int, mode: int) -> None:
    KeyFilePermissions.verify_file("/etc/k.bin", _status(owner, mode), {0, 1000})


@pytest.mark.parametrize(("owner", "mode", "message"), [
    (1001, _FILE | 0o600, "owned by uid 1001"),
    (1000, _FILE | 0o660, "writable by its group"),
    (1000, _FILE | 0o666, "writable by its group or by every user"),
    (1000, _FILE | 0o602, "writable by its group or by every user"),
    (1000, _FILE | stat.S_ISVTX | 0o666, "writable"),  # the sticky exemption is for directories only
    (1000, stat.S_IFLNK | 0o777, "not a regular file"),
    (1000, _DIR | 0o700, "not a regular file"),
])
def test_a_key_file_that_someone_else_owns_or_can_write_is_refused(owner: int, mode: int, message: str) -> None:
    with pytest.raises(PermissionError, match=message):
        KeyFilePermissions.verify_file("/etc/k.bin", _status(owner, mode), {0, 1000})


def test_every_directory_above_a_key_file_is_checked_up_to_the_root() -> None:
    tree = {"/": _status(0, _DIR | 0o755), "/srv": _status(0, _DIR | 0o755), "/srv/app": _status(1000, _DIR | 0o700)}
    seen: list[str] = []

    def get(path: str) -> PathStatus:
        seen.append(path)
        return tree[path]

    KeyFilePermissions.verify_directories("/srv/app/k.bin", get, {0, 1000})
    assert seen == ["/srv/app", "/srv", "/"]

    cases = (("/srv/app", _status(1000, _DIR | 0o770)), ("/srv", _status(1002, _DIR | 0o755)), ("/", _status(0, _DIR | 0o757)),
             ("/srv", _status(0, stat.S_IFLNK | 0o777)))
    for bad_path, bad_status in cases:
        broken = {**tree, bad_path: bad_status}
        with pytest.raises(PermissionError, match=re.escape(f"'{bad_path}'")):
            KeyFilePermissions.verify_directories("/srv/app/k.bin", broken.__getitem__, {0, 1000})


def test_a_sticky_world_writable_directory_such_as_tmp_is_allowed_above_a_key_file() -> None:
    tree = {"/": _status(0, _DIR | 0o755), "/tmp": _status(0, _DIR | stat.S_ISVTX | 0o777)}
    KeyFilePermissions.verify_directories("/tmp/k.bin", tree.__getitem__, {0, 1000})
    tree["/tmp"] = _status(0, _DIR | 0o777)
    with pytest.raises(PermissionError, match="writable"):
        KeyFilePermissions.verify_directories("/tmp/k.bin", tree.__getitem__, {0, 1000})


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership and permission bits")
def test_a_group_writable_key_file_stops_the_build_unless_the_checks_are_turned_off(tmp_path: Path) -> None:
    path = tmp_path / "k.bin"
    path.write_bytes(b"wrapped")
    path.chmod(0o664)
    tmp_path.chmod(0o700)

    with pytest.raises(PermissionError, match="writable by its group"):
        builder().with_key_file(1, path).build()
    with builder().with_key_file(1, path).without_key_file_permission_checks().build():
        pass


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership and permission bits")
def test_a_symlinked_key_file_is_judged_by_what_it_points_to(tmp_path: Path) -> None:
    target = tmp_path / "real.bin"
    target.write_bytes(b"wrapped")
    target.chmod(0o666)
    link = tmp_path / "link.bin"
    link.symlink_to(target)

    with pytest.raises(PermissionError, match=r"real\.bin"):
        builder().with_key_file(1, link).build()


@pytest.mark.skipif(hasattr(os, "geteuid"), reason="only platforms without the POSIX checks warn")
def test_a_platform_without_the_checks_warns_rather_than_pretending(tmp_path: Path) -> None:
    path = tmp_path / "k.bin"
    path.write_bytes(b"wrapped")
    logger, handler = recording_logger()

    assert WrappedKeyFile.read(path, verify_permissions=True, logger=logger) == b"wrapped"
    assert any("not permission-checked" in r.getMessage() for r in handler.records)

    handler.records.clear()
    WrappedKeyFile.read(str(path), verify_permissions=False, logger=logger)
    assert handler.records == []

    # The builder hands its own logger to the key wrapper's read.
    handler.records.clear()
    with builder().with_logger(logger).with_key_file(1, path).build():
        assert any("not permission-checked" in r.getMessage() for r in handler.records)


# --- Key files are read through the key wrapper ----------------------------------------------------


class FileReadingKeyWrapper(FixedKeyWrapper):
    """A key wrapper with its own way of reading key files, recording every read."""

    def __init__(self, payload: bytes = b"read-by-the-wrapper", error: BaseException | None = None) -> None:
        super().__init__()
        self.payload = payload
        self.error = error
        self.reads: list[tuple[str, bool]] = []

    def read_key_file(self, path: str | os.PathLike[str], *, verify_permissions: bool = True,
                      logger: logging.Logger | None = None) -> bytearray:
        self.reads.append((os.fspath(path), verify_permissions))
        if self.error is not None:
            raise self.error
        return bytearray(self.payload)


def wrapper_builder(wrapper: KeyWrapper, factory: CryptoProviderFactory | None = None) -> KeyRingBuilder:
    return (KeyRingBuilder().with_key_wrapper(wrapper).with_crypto_provider_factory(factory or AesGcmCryptoProviderFactory())
            .with_key_refresh_interval(60))


def test_build_reads_every_key_file_through_the_key_wrapper(tmp_path: Path) -> None:
    wrapper = FileReadingKeyWrapper()
    factory = RecordingFactory()

    # Neither file exists: only the key wrapper is asked about them.
    with wrapper_builder(wrapper, factory).with_key_file(2, tmp_path / "v2.bin").with_key_file(1, tmp_path / "v1.bin").build() as ring:
        assert ring.current_version == 2

    assert wrapper.reads == [(str(tmp_path / "v1.bin"), True), (str(tmp_path / "v2.bin"), True)]
    assert factory.wrapped == [b"read-by-the-wrapper", b"read-by-the-wrapper"]


def test_build_passes_the_permission_setting_to_the_key_wrapper(tmp_path: Path) -> None:
    wrapper = FileReadingKeyWrapper()

    with wrapper_builder(wrapper).with_key_file(1, tmp_path / "v1.bin").without_key_file_permission_checks().build():
        pass

    assert wrapper.reads == [(str(tmp_path / "v1.bin"), False)]


@pytest.mark.parametrize("error", [InvalidKeyFileError("Key file 'v1.bin' was refused with status -37."), PermissionError("untrusted"),
                                   FileNotFoundError("missing")])
def test_a_key_wrapper_refusing_a_key_file_stops_the_build_before_any_key_is_created(tmp_path: Path, error: OSError) -> None:
    factory = RecordingFactory()
    wrapper = FileReadingKeyWrapper(error=error)

    with pytest.raises(type(error)) as raised:
        wrapper_builder(wrapper, factory).with_ephemeral_key(9).with_key_file(1, tmp_path / "v1.bin").build()

    assert raised.value is error
    assert factory.providers == []


def test_a_key_wrapper_without_its_own_read_uses_the_default_file_read(tmp_path: Path) -> None:
    path = tmp_path / "v1.bin"
    path.write_bytes(b"wrapped-on-disk")
    wrapper = FixedKeyWrapper()

    assert wrapper.read_key_file(path, verify_permissions=False) == bytearray(b"wrapped-on-disk")
    assert type(wrapper.read_key_file(path, verify_permissions=False)) is bytearray
    with pytest.raises(FileNotFoundError):
        wrapper.read_key_file(tmp_path / "missing.bin")
