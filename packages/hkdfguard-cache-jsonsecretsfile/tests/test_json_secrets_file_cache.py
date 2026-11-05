"""JsonSecretsFileReadOnlyCache over a real file TrustedFile accepts, with values written by a ring's protectors or a pipeline."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
import shutil
import sys
from collections.abc import Buffer, Coroutine, Iterator, MutableMapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from hkdfguard.abstractions import (
    AuthenticationTagMismatchError,
    EncryptedFormatError,
    KeyNotFoundError,
    KeyTrackingValue,
    KeyWrapper,
    PipelineDataProtector,
    ProtectedConfigurationPurpose,
    ProtectedReadOnlyCache,
    WritableBuffer,
)
from hkdfguard.cache import FilePerSecretCache, InvalidSecretDataError, ProtectedCacheCollection
from hkdfguard.cache.jsonsecretsfile import JsonSecretsFileReadOnlyCache
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider, AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.diagnostics import AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest
from hkdfguard.securefile import FileTooLargeError, KeyFileTrust, TrustedFile
from hkdfguard_test_support import current_user_trust, trusted_directory
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader, NumberDataPoint
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

# --- Helpers ----------------------------------------------------------------------------------


class FixedKeyWrapper(KeyWrapper):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


class InMemoryWriter(SecretPipelineWriter):
    """A pipeline writer over values held in memory, so a test can read exactly what write_json_secrets writes."""

    def __init__(self, protector: PipelineDataProtector, values: dict[str, str]) -> None:
        super().__init__(protector, list(values), lambda _: True)
        self._values = values

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        plaintext = bytearray(self._values[name].encode())
        try:
            self._protect_secret(plaintext, requests, values)
        finally:
            plaintext[:] = bytes(len(plaintext))


def new_key(key: bytes | None = None) -> DataEncryptionKey:
    return DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(key if key is not None else os.urandom(32)), b"wrapped", 60))


@pytest.fixture
def ring() -> Iterator[DefaultKeyRing]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, new_key())
        yield ring


@pytest.fixture
def folder() -> Iterator[Path]:
    """A folder TrustedFile accepts under current_user_trust (hkdfguard_test_support.trusted_directory)."""
    if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
        pytest.skip("Trusted files are read on Windows, Linux and macOS only.")
    with trusted_directory() as directory:
        yield directory


@pytest.fixture
def path(folder: Path) -> Path:
    return folder / "secrets.json"


def create_cache(path: Path, ring: DefaultKeyRing, max_file_length: int = JsonSecretsFileReadOnlyCache.DEFAULT_MAX_FILE_LENGTH,
                 logger: logging.Logger | None = None) -> JsonSecretsFileReadOnlyCache:
    return JsonSecretsFileReadOnlyCache(path, current_user_trust(), ring, DefaultFormatProvider(), max_file_length, logger=logger)


def encrypt(ring: DefaultKeyRing, name: str, value: str) -> str:
    return ring.create_protector(ProtectedConfigurationPurpose.for_key(name)).encrypt(value)


def write(path: Path, ring: DefaultKeyRing, values: dict[str, str]) -> None:
    """Writes each secret encrypted for its name, as one JSON object."""
    write_raw(path, json.dumps({name: encrypt(ring, name, value) for name, value in values.items()}))


def write_raw(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def decrypt_string(cache: ProtectedReadOnlyCache, name: str, size: int = 64) -> str:
    result = bytearray(size)
    return result[:cache.decrypt(name, result)].decode("utf-8")


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


# --- Reading ----------------------------------------------------------------------------------


def test_what_a_pipeline_writes_decrypts_under_the_key_it_wraps(path: Path) -> None:
    with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 1) as protector,
          InMemoryWriter(protector, {"db-password": "pässwörd", "api-key": "key"}) as writer):
        writer.pull_secrets()
        writer.write_json_secrets(path)
        dek = base64.b64decode(bytes(protector.get_key_as_base64()))

    # What the application holds once the pipeline's key has been wrapped and unwrapped.
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, new_key(dek))
        cache = create_cache(path, ring)

        assert decrypt_string(cache, "db-password") == "pässwörd"
        assert decrypt_string(cache, "api-key") == "key"


def test_a_value_decrypts_through_every_member_under_its_name_ignoring_ascii_case(path: Path, ring: DefaultKeyRing) -> None:
    write(path, ring, {"Db-Password": "value"})
    cache = create_cache(path, ring)

    assert decrypt_string(cache, "Db-Password") == "value"
    assert decrypt_string(cache, "DB-PASSWORD") == "value"
    assert decrypt_string(cache, "db-password") == "value"
    max_length = cache.find_max_decrypted_length("Db-Password")
    assert max_length is not None and max_length >= 5

    result = bytearray(16)
    assert result[:run(cache.decrypt_async("dB-pAsSwOrD", result))] == b"value"
    assert run(cache.find_max_decrypted_length_async("Db-Password")) == max_length


def test_the_file_is_read_once_even_by_concurrent_lookups_then_served_from_memory(path: Path, ring: DefaultKeyRing,
                                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    values = {f"secret-{i:03d}": f"value-{i}" for i in range(200)}
    write(path, ring, values)
    cache = create_cache(path, ring)
    reads: list[str] = []
    real_read = TrustedFile.read

    def counting_read(file_path: str | os.PathLike[str], trust: KeyFileTrust, max_bytes: int) -> bytearray:
        reads.append(os.fspath(file_path))
        return real_read(file_path, trust, max_bytes)

    monkeypatch.setattr(TrustedFile, "read", staticmethod(counting_read))

    async def look_up_all() -> list[str]:
        async def look_up(name: str) -> str:
            result = bytearray(64)
            return result[:await cache.decrypt_async(name, result)].decode()

        return await asyncio.gather(*(look_up(name) for name in values))

    results = run(look_up_all())
    path.unlink()

    assert results == list(values.values())
    assert decrypt_string(cache, "secret-007") == "value-7"
    assert reads == [cache.file_path]


@pytest.mark.parametrize("name", ["absent", "", ".hidden", "../item", "ıtem", "it em", "item/", "ITEM:x"])
def test_a_name_the_file_doesnt_hold_or_that_cant_be_one_is_missing(path: Path, ring: DefaultKeyRing, name: str) -> None:
    write(path, ring, {"item": "value"})
    cache = create_cache(path, ring)

    assert cache.decrypt(name, bytearray(16)) == 0
    assert run(cache.decrypt_async(name, bytearray(16))) == 0
    assert cache.find_max_decrypted_length(name) is None
    assert run(cache.find_max_decrypted_length_async(name)) is None


def test_a_missing_file_reports_every_secret_missing_and_isnt_remembered(path: Path, ring: DefaultKeyRing) -> None:
    write(path, ring, {"item": "value"})
    cache = create_cache(path, ring)
    path.unlink()

    assert cache.decrypt("item", bytearray(16)) == 0
    assert run(cache.decrypt_async("item", bytearray(16))) == 0

    write(path, ring, {"item": "later"})
    assert decrypt_string(cache, "item") == "later"


def test_a_folder_removed_after_construction_reports_every_secret_missing(folder: Path, ring: DefaultKeyRing) -> None:
    sub = folder / "sub"
    sub.mkdir()
    write(sub / "secrets.json", ring, {"item": "value"})
    cache = create_cache(sub / "secrets.json", ring)
    shutil.rmtree(sub)

    assert cache.decrypt("item", bytearray(16)) == 0


@pytest.mark.parametrize(("text", "problem"), [
    ("", "valid JSON"),
    ("not json", "valid JSON"),
    ('["item"]', "holds an array, not an object of secrets"),
    ('"item"', "holds a string, not an object of secrets"),
    ("null", "holds null, not an object of secrets"),
    ('{"item":1}', "no value for 'item'"),
    ('{"item":{"a":"b"}}', "no value for 'item'"),
    ('{"item":["{0}"]}', "no value for 'item'"),
    ('{"item":null}', "no value for 'item'"),
    ('{"item":true}', "no value for 'item'"),
    ('{"item":"  "}', "no value for 'item'"),
    ('{"item":""}', "no value for 'item'"),
    ('{"../item":"x"}', "isn't a secret's name"),
    ('{"":"x"}', "isn't a secret's name"),
    ('{"ıtem":"x"}', "isn't a secret's name"),
    ('{"item":"{0}","ITEM":"{0}"}', "'ITEM' more than once"),
    ('{"item":"{0}"} {}', "valid JSON"),
    ('{"item":"{0}" ', "valid JSON"),
    ('{"item":"{0}",}', "valid JSON"),
    ('{"item":"{0}"} // comment', "valid JSON"),
    ('﻿{"item":"{0}"}', "valid JSON"),
])
def test_a_file_that_isnt_the_secrets_object_is_refused_and_not_kept(path: Path, ring: DefaultKeyRing, text: str, problem: str) -> None:
    write_raw(path, text.replace("{0}", encrypt(ring, "item", "value")))
    cache = create_cache(path, ring)

    with pytest.raises(InvalidSecretDataError) as raised:
        cache.decrypt("item", bytearray(16))
    assert problem in str(raised.value)
    assert cache.file_path in str(raised.value)
    # Nothing chained that could quote the file.
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None or raised.value.__suppress_context__
    with pytest.raises(InvalidSecretDataError):
        run(cache.decrypt_async("item", bytearray(16)))

    write(path, ring, {"item": "fixed"})
    assert decrypt_string(cache, "item") == "fixed"


def test_a_value_that_isnt_a_formatted_value_is_refused_by_the_format_provider(path: Path, ring: DefaultKeyRing) -> None:
    write_raw(path, json.dumps({"item": "plain text"}))
    cache = create_cache(path, ring)

    with pytest.raises(EncryptedFormatError):
        cache.decrypt("item", bytearray(16))


def test_whitespace_and_line_endings_around_the_object_and_its_values_are_accepted(path: Path, ring: DefaultKeyRing) -> None:
    write_raw(path, f'\r\n  {{\r\n\t"item" :  " {encrypt(ring, "item", "value")}\\n" ,\n"other":"{encrypt(ring, "other", "x")}"}}\n\n')

    assert decrypt_string(create_cache(path, ring), "item") == "value"


def test_a_value_moved_under_another_name_fails_the_whole_file(path: Path, ring: DefaultKeyRing) -> None:
    write_raw(path, json.dumps({"reader": encrypt(ring, "reader", "fine"), "writer": encrypt(ring, "reader", "moved")}))
    cache = create_cache(path, ring)

    with pytest.raises(AuthenticationTagMismatchError):
        cache.decrypt("reader", bytearray(16))
    with pytest.raises(AuthenticationTagMismatchError):
        run(cache.decrypt_async("reader", bytearray(16)))


def test_a_value_under_a_key_version_the_ring_doesnt_hold_fails_the_whole_file(path: Path, ring: DefaultKeyRing) -> None:
    write_raw(path, json.dumps({"item": encrypt(ring, "item", "fine"),
                                "old": DefaultFormatProvider().format(KeyTrackingValue(7, secrets.token_bytes(40)))}))

    with pytest.raises(KeyNotFoundError):
        create_cache(path, ring).decrypt("item", bytearray(16))


def test_values_under_older_key_versions_still_decrypt_after_rotation(path: Path, ring: DefaultKeyRing) -> None:
    old = encrypt(ring, "item", "old")
    ring.add(2, new_key())
    write_raw(path, json.dumps({"item": old, "other": encrypt(ring, "other", "new")}))
    cache = create_cache(path, ring)

    assert decrypt_string(cache, "item") == "old"
    assert decrypt_string(cache, "other") == "new"


def test_a_file_in_an_untrusted_location_is_refused_and_not_kept(path: Path, ring: DefaultKeyRing) -> None:
    if sys.platform != "win32" and os.geteuid() == 0:
        pytest.skip("root's files are trusted")
    write(path, ring, {"item": "value"})
    untrusted = JsonSecretsFileReadOnlyCache(path, KeyFileTrust.ADMINISTRATORS_ONLY, ring, DefaultFormatProvider())

    with pytest.raises(PermissionError):
        untrusted.decrypt("item", bytearray(16))
    with pytest.raises(PermissionError):
        run(untrusted.decrypt_async("item", bytearray(16)))
    assert decrypt_string(create_cache(path, ring), "item") == "value"


def test_a_file_over_the_maximum_length_is_refused(path: Path, ring: DefaultKeyRing) -> None:
    write(path, ring, {"item": "value"})
    cache = create_cache(path, ring, max_file_length=16)

    with pytest.raises(FileTooLargeError):
        cache.decrypt("item", bytearray(16))
    with pytest.raises(FileTooLargeError):
        run(cache.find_max_decrypted_length_async("item"))


def test_a_large_value_decrypts(path: Path) -> None:
    # Over the default format's limit, so ring and cache both allow longer values.
    format_provider = DefaultFormatProvider(max_encrypted_length=16 * 1024)
    with DefaultKeyRing(format_provider) as ring:
        ring.add(1, new_key())
        value = "x" * 5000
        write(path, ring, {"large": value})
        cache = JsonSecretsFileReadOnlyCache(path, current_user_trust(), ring, format_provider)

        assert decrypt_string(cache, "large", size=len(value)) == value


def test_a_cancelled_lookup_raises_and_the_file_is_still_loaded(path: Path, ring: DefaultKeyRing) -> None:
    write(path, ring, {"item": "value"})
    cache = create_cache(path, ring)

    async def cancelled() -> None:
        task = asyncio.ensure_future(cache.decrypt_async("item", bytearray(16)))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(cancelled())
    assert decrypt_string(cache, "item") == "value"


def test_the_cache_sits_in_a_collection_beside_sources_with_other_names(path: Path, ring: DefaultKeyRing) -> None:
    write(path, ring, {"item": "from json"})
    collection = ProtectedCacheCollection().add(create_cache(path, ring))

    assert decrypt_string(collection, "ITEM") == "from json"
    assert decrypt_string(collection, "ConnectionStrings:Admin") == ""


def test_the_json_a_pipeline_writes_and_the_files_it_writes_hold_the_same_values(folder: Path) -> None:
    with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 1) as protector,
          InMemoryWriter(protector, {"db-password": "pässwörd", "api-key": "key"}) as writer):
        writer.pull_secrets()
        writer.write_json_secrets(folder / "secrets.json")
        writer.write_protected_secret_files(folder / "files")
        dek = base64.b64decode(bytes(protector.get_key_as_base64()))

    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, new_key(dek))
        from_json = create_cache(folder / "secrets.json", ring)
        from_files = FilePerSecretCache(folder / "files", current_user_trust(), ring, DefaultFormatProvider())

        for name in ("db-password", "api-key"):
            assert decrypt_string(from_json, name) == decrypt_string(from_files, name)


# --- Telemetry --------------------------------------------------------------------------------


@pytest.fixture
def telemetry() -> Iterator[tuple[InMemorySpanExporter, InMemoryMetricReader]]:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    HkdfGuardTelemetry.set_tracer_provider(tracer_provider)
    HkdfGuardTelemetry.set_meter_provider(MeterProvider(metric_readers=[reader]))
    try:
        yield exporter, reader
    finally:
        HkdfGuardTelemetry.set_tracer_provider(None)
        HkdfGuardTelemetry.set_meter_provider(None)


def populate_results(reader: InMemoryMetricReader) -> list[str]:
    data = reader.get_metrics_data()
    results: list[str] = []
    if data is None:
        return results
    for resource in data.resource_metrics:
        for scope in resource.scope_metrics:
            for metric in scope.metrics:
                if metric.name != MetricNames.Cache.OPERATIONS:
                    continue
                for point in metric.data.data_points:
                    assert isinstance(point, NumberDataPoint)
                    attributes = dict(point.attributes or {})
                    if attributes.get(AttributeNames.OPERATION_NAME) == SpanNames.Cache.POPULATE:
                        results.extend([str(attributes[AttributeNames.RESULT])] * int(point.value))
    return sorted(results)


def test_each_load_is_a_populate_span_counted_by_result(path: Path, ring: DefaultKeyRing,
                                                        telemetry: tuple[InMemorySpanExporter, InMemoryMetricReader]) -> None:
    exporter, reader = telemetry
    write_raw(path, "not json")
    cache = create_cache(path, ring)
    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item", bytearray(16))
    path.unlink()
    cache.decrypt("item", bytearray(16))
    write(path, ring, {"item": "value"})
    decrypt_string(cache, "item")
    decrypt_string(cache, "item")

    populates = [span for span in exporter.get_finished_spans() if span.name == SpanNames.Cache.POPULATE]
    assert len(populates) == 3
    assert len([span for span in exporter.get_finished_spans() if span.name == SpanNames.Cache.DECRYPT]) == 4
    assert populate_results(reader) == ["error", "not_found", "success"]


def test_sensitive_logging_logs_the_file_and_the_names_never_a_value(path: Path, ring: DefaultKeyRing, caplog: pytest.LogCaptureFixture) -> None:
    write(path, ring, {"item": "s3cret-value"})
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    try:
        with caplog.at_level(logging.DEBUG, logger="hkdfguard.cache.jsonsecretsfile"):
            assert decrypt_string(create_cache(path, ring), "item") == "s3cret-value"
    finally:
        HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original

    assert any(str(path.resolve()) in record.getMessage() or os.path.abspath(path) in record.getMessage() for record in caplog.records)
    assert not any("s3cret-value" in record.getMessage() for record in caplog.records)


def test_a_failed_load_is_logged_as_an_error_to_the_logger_given(path: Path, ring: DefaultKeyRing, caplog: pytest.LogCaptureFixture) -> None:
    write_raw(path, "[]")
    logger = logging.getLogger("test.jsonsecretsfile")
    with caplog.at_level(logging.ERROR, logger="test.jsonsecretsfile"), pytest.raises(InvalidSecretDataError):
        create_cache(path, ring, logger=logger).decrypt("item", bytearray(16))

    assert [record.levelno for record in caplog.records if record.name == "test.jsonsecretsfile"] == [logging.ERROR]


# --- Arguments --------------------------------------------------------------------------------


def test_the_constructor_validates_its_arguments(folder: Path, path: Path, ring: DefaultKeyRing) -> None:
    format_provider = DefaultFormatProvider()
    trust = current_user_trust()
    write(path, ring, {"item": "value"})

    with pytest.raises(TypeError):
        JsonSecretsFileReadOnlyCache(None, trust, ring, format_provider)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        JsonSecretsFileReadOnlyCache("", trust, ring, format_provider)
    with pytest.raises(ValueError):
        JsonSecretsFileReadOnlyCache("a\0b", trust, ring, format_provider)
    with pytest.raises(TypeError):
        JsonSecretsFileReadOnlyCache(path, None, ring, format_provider)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        JsonSecretsFileReadOnlyCache(path, trust, None, format_provider)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        JsonSecretsFileReadOnlyCache(path, trust, ring, None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        JsonSecretsFileReadOnlyCache(path, trust, ring, format_provider, max_file_length=0)
    with pytest.raises(TypeError):
        JsonSecretsFileReadOnlyCache(path, trust, ring, format_provider, max_file_length=True)
    with pytest.raises(FileNotFoundError):
        JsonSecretsFileReadOnlyCache(folder / "absent.json", trust, ring, format_provider)
    with pytest.raises(FileNotFoundError):
        JsonSecretsFileReadOnlyCache(folder, trust, ring, format_provider)
    assert JsonSecretsFileReadOnlyCache(path, trust, ring, format_provider).file_path == os.path.abspath(path)


def test_a_none_name_raises(path: Path, ring: DefaultKeyRing) -> None:
    write(path, ring, {"item": "value"})
    cache = create_cache(path, ring)

    with pytest.raises(TypeError):
        cache.decrypt(None, bytearray(16))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        cache.find_max_decrypted_length(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        run(cache.decrypt_async(None, bytearray(16)))  # type: ignore[arg-type]
