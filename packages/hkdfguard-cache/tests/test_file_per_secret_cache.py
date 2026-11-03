"""FilePerSecretCache over a real folder TrustedFile accepts, with values written by a ring's protectors."""

from __future__ import annotations

import asyncio
import base64
import os
import re
import secrets
import shutil
import sys
from collections.abc import Buffer, Coroutine, Iterator
from pathlib import Path
from typing import Any

import pytest
from hkdfguard.abstractions import (
    AuthenticationTagMismatchError,
    KeyNotFoundError,
    KeyTrackingValue,
    KeyWrapper,
    ProtectedConfigurationPurpose,
    ProtectedReadOnlyCache,
    WritableBuffer,
)
from hkdfguard.cache import FilePerSecretCache, ProtectedCache, ProtectedCacheCollection
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.diagnostics import AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames
from hkdfguard.securefile import FileTooLargeError, KeyFileTrust
from hkdfguard_test_support import current_user_trust, trusted_directory
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader, NumberDataPoint
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

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


def new_key() -> DataEncryptionKey:
    return DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60))


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


def create_cache(folder: Path, ring: DefaultKeyRing) -> FilePerSecretCache:
    return FilePerSecretCache(folder, current_user_trust(), ring, DefaultFormatProvider())


def write(folder: Path, ring: DefaultKeyRing, name: str, value: str, suffix: str = "") -> None:
    """Writes value to name's file, encrypted as a pipeline or deployer would: bound to that name."""
    encrypted = ring.create_protector(ProtectedConfigurationPurpose.for_key(name)).encrypt(value)
    (folder / name).write_bytes((encrypted + suffix).encode("ascii"))


def decrypt_string(cache: ProtectedReadOnlyCache, name: str, size: int = 64) -> str:
    result = bytearray(size)
    return result[:cache.decrypt(name, result)].decode("utf-8")


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


# --- Reading ----------------------------------------------------------------------------------


def test_a_file_decrypts_through_every_member(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "Db-Password", "value")
    cache = create_cache(folder, ring)

    assert decrypt_string(cache, "Db-Password") == "value"
    max_length = cache.find_max_decrypted_length("Db-Password")
    assert max_length is not None and max_length >= 5

    result = bytearray(16)
    assert result[:run(cache.decrypt_async("Db-Password", result))] == b"value"
    assert run(cache.find_max_decrypted_length_async("Db-Password")) == max_length


SECRET_COUNT = 20

# Non-ASCII fragments, so each secret also exercises multi-byte UTF-8 - "🔑" outside the BMP.
NON_ASCII = ["café", "naïve", "日本語", "Ωμέγα", "🔑", "Größe"]


def random_secrets() -> dict[str, str]:
    """SECRET_COUNT secrets, each a random base64 run of random length plus random non-ASCII text,
    under names that differ only by number."""
    return {f"Secret-{i:02d}": " ".join((base64.b64encode(secrets.token_bytes(16 + secrets.randbelow(113))).decode("ascii"),
                                        secrets.choice(NON_ASCII), secrets.choice(NON_ASCII)))
            for i in range(SECRET_COUNT)}


def write_and_verify_encrypted(folder: Path, ring: DefaultKeyRing, values: dict[str, str]) -> None:
    """Writes every secret encrypted, and checks each file holds only the formatted ciphertext: ASCII
    base64, with neither the secret's random text nor its non-ASCII text anywhere in it."""
    for name, value in values.items():
        write(folder, ring, name, value)

        on_disk = (folder / name).read_bytes()
        assert all(b < 0x80 for b in on_disk), "The file holds a non-ASCII byte."
        text = on_disk.decode("ascii")
        assert re.fullmatch(r"enc::v1::[A-Za-z0-9+/]+=*", text)
        assert value.split(" ")[0] not in text
        assert value.encode("utf-8") not in on_disk


def assert_each_decrypts(cache: FilePerSecretCache, values: dict[str, str]) -> None:
    """Checks every secret through every member, synchronous and asynchronous."""
    for name, value in values.items():
        max_length = cache.find_max_decrypted_length(name)
        assert max_length is not None
        assert run(cache.find_max_decrypted_length_async(name)) == max_length
        assert max_length >= len(value.encode("utf-8"))

        result = bytearray(max_length)
        assert result[:cache.decrypt(name, result)].decode("utf-8") == value
        assert result[:run(cache.decrypt_async(name, result))].decode("utf-8") == value


def test_twenty_random_secrets_are_only_ciphertext_on_disk_and_each_decrypts_through_every_member(folder: Path, ring: DefaultKeyRing) -> None:
    values = random_secrets()
    write_and_verify_encrypted(folder, ring, values)

    assert_each_decrypts(create_cache(folder, ring), values)


def test_twenty_random_secrets_loaded_concurrently_are_served_from_memory_once_their_files_are_gone(folder: Path, ring: DefaultKeyRing) -> None:
    values = random_secrets()
    write_and_verify_encrypted(folder, ring, values)
    cache = create_cache(folder, ring)

    # Every secret's first lookup at once, half of them twice, so loads also race each other.
    async def load_all() -> list[int | None]:
        names = [*values, *list(values)[:SECRET_COUNT // 2]]
        return await asyncio.gather(*(cache.find_max_decrypted_length_async(name) for name in names))

    assert all(max_length is not None and max_length > 0 for max_length in run(load_all()))

    for name in values:
        (folder / name).unlink()
    assert not any(folder.iterdir())

    assert_each_decrypts(cache, values)


def test_surrounding_whitespace_is_ignored(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "item", "value", suffix="\r\n")

    assert decrypt_string(create_cache(folder, ring), "item") == "value"


def test_a_file_is_read_once_then_served_from_memory(folder: Path, ring: DefaultKeyRing) -> None:
    cache = create_cache(folder, ring)
    write(folder, ring, "item", "first")
    assert decrypt_string(cache, "item") == "first"

    write(folder, ring, "item", "second")
    assert decrypt_string(cache, "item") == "first"
    (folder / "item").unlink()
    assert decrypt_string(cache, "item") == "first"
    result = bytearray(16)
    assert result[:run(cache.decrypt_async("item", result))] == b"first"


def test_a_changed_file_is_picked_up_by_a_new_instance(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "item", "first")
    assert decrypt_string(create_cache(folder, ring), "item") == "first"

    write(folder, ring, "item", "second")
    assert decrypt_string(create_cache(folder, ring), "item") == "second"


def test_a_missing_secret_isnt_remembered_so_a_file_added_later_is_found(folder: Path, ring: DefaultKeyRing) -> None:
    cache = create_cache(folder, ring)
    assert cache.decrypt("item", bytearray(16)) == 0

    write(folder, ring, "item", "value")
    assert decrypt_string(cache, "item") == "value"


def test_a_missing_or_empty_file_is_missing(folder: Path, ring: DefaultKeyRing) -> None:
    (folder / "empty").write_bytes(b" \n")
    cache = create_cache(folder, ring)

    for name in ("absent", "empty"):
        assert cache.decrypt(name, bytearray(16)) == 0
        assert cache.find_max_decrypted_length(name) is None
        assert run(cache.decrypt_async(name, bytearray(16))) == 0
        assert run(cache.find_max_decrypted_length_async(name)) is None


def test_a_folder_removed_after_construction_reports_every_secret_missing(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "item", "value")
    cache = create_cache(folder, ring)
    shutil.rmtree(folder)

    assert cache.decrypt("item", bytearray(16)) == 0
    assert run(cache.decrypt_async("item", bytearray(16))) == 0


@pytest.mark.parametrize("name", ["", ".hidden", "..", "../item", "sub/item", "sub\\item", "db:password", "café", "item\n", "a" * 256])
def test_a_name_that_cant_be_a_file_name_is_missing_without_reading_outside_the_folder(folder: Path, ring: DefaultKeyRing, name: str) -> None:
    (folder / "sub").mkdir()
    write(folder, ring, "item", "value")
    write(folder / "sub", ring, "item", "value")
    cache = FilePerSecretCache(folder / "sub", current_user_trust(), ring, DefaultFormatProvider())

    assert not FilePerSecretCache.is_valid_name(name)
    assert cache.decrypt(name, bytearray(16)) == 0
    assert cache.find_max_decrypted_length(name) is None
    assert run(cache.decrypt_async(name, bytearray(16))) == 0


def test_is_valid_name_accepts_up_to_max_name_length_of_letters_digits_and_punctuation() -> None:
    assert FilePerSecretCache.is_valid_name("Db-Password_v2.txt")
    assert FilePerSecretCache.is_valid_name("a" * FilePerSecretCache.MAX_NAME_LENGTH)
    assert not FilePerSecretCache.is_valid_name("a" * (FilePerSecretCache.MAX_NAME_LENGTH + 1))
    assert not FilePerSecretCache.is_valid_name(None)
    assert not FilePerSecretCache.is_valid_name(42)  # type: ignore[arg-type]


def test_names_are_matched_exactly(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "item", "value")
    cache = create_cache(folder, ring)
    assert decrypt_string(cache, "item") == "value"

    if sys.platform.startswith("linux"):
        # Linux finds files exactly, so another spelling is another, missing, file.
        assert cache.decrypt("ITEM", bytearray(16)) == 0
    elif sys.platform == "win32":
        # Windows finds the same file by another spelling (as macOS does by default); the spelling is
        # loaded and authenticated for itself. ProtectedConfigurationPurpose ignores ASCII case, so
        # the file's value is that spelling's too.
        assert decrypt_string(cache, "ITEM") == "value"


# --- Name binding -----------------------------------------------------------------------------


def test_a_file_copied_under_another_name_fails_authentication(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "admin", "secret")
    shutil.copyfile(folder / "admin", folder / "reader")
    cache = create_cache(folder, ring)

    with pytest.raises(AuthenticationTagMismatchError):
        cache.decrypt("reader", bytearray(16))
    with pytest.raises(AuthenticationTagMismatchError):
        cache.find_max_decrypted_length("reader")
    with pytest.raises(AuthenticationTagMismatchError):
        run(cache.decrypt_async("reader", bytearray(16)))
    with pytest.raises(AuthenticationTagMismatchError):
        run(cache.find_max_decrypted_length_async("reader"))


def test_a_file_that_fails_authentication_isnt_cached_so_a_fixed_file_is_read_next_time(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "admin", "secret")
    shutil.copyfile(folder / "admin", folder / "reader")
    cache = create_cache(folder, ring)
    with pytest.raises(AuthenticationTagMismatchError):
        cache.decrypt("reader", bytearray(16))

    write(folder, ring, "reader", "fixed")
    assert decrypt_string(cache, "reader") == "fixed"


def test_a_file_in_an_untrusted_location_is_refused_and_not_cached(folder: Path, ring: DefaultKeyRing) -> None:
    if sys.platform != "win32" and os.geteuid() == 0:  # type: ignore[attr-defined,unused-ignore]
        pytest.skip("Running as root, whose files are trusted.")
    write(folder, ring, "item", "value")
    untrusted = FilePerSecretCache(folder, KeyFileTrust.ADMINISTRATORS_ONLY, ring, DefaultFormatProvider())

    with pytest.raises(PermissionError, match="not trusted"):
        untrusted.decrypt("item", bytearray(16))
    with pytest.raises(PermissionError, match="not trusted"):
        run(untrusted.decrypt_async("item", bytearray(16)))
    assert decrypt_string(create_cache(folder, ring), "item") == "value"


# --- Keys -------------------------------------------------------------------------------------


def test_a_value_under_an_older_key_version_still_decrypts_after_rotation(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "item", "old")
    ring.add(2, new_key())
    write(folder, ring, "other", "new")
    cache = create_cache(folder, ring)

    assert (folder / "item").read_text().startswith("enc::v1::")
    assert (folder / "other").read_text().startswith("enc::v2::")
    assert decrypt_string(cache, "item") == "old"
    assert decrypt_string(cache, "other") == "new"


def test_a_value_under_a_key_version_the_ring_doesnt_hold_raises(folder: Path, ring: DefaultKeyRing) -> None:
    (folder / "item").write_text(DefaultFormatProvider().format(KeyTrackingValue(7, os.urandom(40))))
    cache = create_cache(folder, ring)

    with pytest.raises(KeyNotFoundError):
        cache.decrypt("item", bytearray(64))
    with pytest.raises(KeyNotFoundError):
        cache.find_max_decrypted_length("item")


# --- Files the cache refuses ------------------------------------------------------------------


def test_a_file_over_max_file_length_is_refused(folder: Path, ring: DefaultKeyRing) -> None:
    (folder / "huge").write_bytes(bytes(FilePerSecretCache.MAX_FILE_LENGTH + 1))
    cache = create_cache(folder, ring)

    with pytest.raises(FileTooLargeError, match=f"larger than {FilePerSecretCache.MAX_FILE_LENGTH} bytes"):
        cache.decrypt("huge", bytearray(16))
    with pytest.raises(FileTooLargeError):
        run(cache.find_max_decrypted_length_async("huge"))


def test_a_file_that_isnt_a_formatted_value_is_refused_and_not_cached(folder: Path, ring: DefaultKeyRing) -> None:
    (folder / "item").write_bytes("plaintext, not enc::v1::... \xff".encode("latin-1"))
    cache = create_cache(folder, ring)

    with pytest.raises(ValueError, match="Invalid encrypted format"):
        cache.decrypt("item", bytearray(16))

    write(folder, ring, "item", "fixed")
    assert decrypt_string(cache, "item") == "fixed"


def test_a_large_value_decrypts(folder: Path) -> None:
    # Over the default format's limit, so ring and cache both allow longer values.
    format_provider = DefaultFormatProvider(max_encrypted_length=16 * 1024)
    with DefaultKeyRing(format_provider) as large_ring:
        large_ring.add(1, new_key())
        value = "x" * (8 * 1024 + 10)
        write(folder, large_ring, "large", value)
        cache = FilePerSecretCache(folder, current_user_trust(), large_ring, format_provider)

        result = bytearray(len(value))
        assert cache.decrypt("large", result) == len(value)
        assert result.decode("ascii") == value


# --- Asynchronous lookups ---------------------------------------------------------------------


def test_a_cancelled_lookup_raises_cancelled_error(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "item", "value")
    cache = create_cache(folder, ring)

    async def cancelled() -> None:
        task = asyncio.create_task(cache.decrypt_async("item", bytearray(16)))
        await asyncio.sleep(0)  # let it start the read
        task.cancel()
        await task

    with pytest.raises(asyncio.CancelledError):
        run(cancelled())


def test_in_a_collection_a_local_cache_answers_first_and_the_folder_answers_the_rest(folder: Path, ring: DefaultKeyRing) -> None:
    write(folder, ring, "Db-Password", "from-file")
    local = ProtectedCache(ring)
    local.add("ConnectionStrings:Admin", bytearray(b"from-memory"))
    caches = ProtectedCacheCollection().add(local).add(create_cache(folder, ring))

    assert decrypt_string(caches, "ConnectionStrings:Admin") == "from-memory"
    assert decrypt_string(caches, "Db-Password") == "from-file"
    result = bytearray(16)
    assert result[:run(caches.decrypt_async("Db-Password", result))] == b"from-file"
    assert caches.decrypt("absent", bytearray(16)) == 0


# --- Telemetry --------------------------------------------------------------------------------


@pytest.fixture
def sensitive() -> Iterator[None]:
    original = HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = True
    yield
    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = original


def test_sensitive_logging_doesnt_change_the_result(folder: Path, ring: DefaultKeyRing, sensitive: None) -> None:
    write(folder, ring, "item", "value")

    assert decrypt_string(create_cache(folder, ring), "item") == "value"


def test_each_load_is_a_populate_span_counted_as_success_not_found_or_error(folder: Path, ring: DefaultKeyRing, sensitive: None) -> None:
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    HkdfGuardTelemetry.set_tracer_provider(tracer_provider)
    HkdfGuardTelemetry.set_meter_provider(meter_provider)
    try:
        write(folder, ring, "Found", "value")
        shutil.copyfile(folder / "Found", folder / "copied")
        cache = create_cache(folder, ring)
        assert decrypt_string(cache, "Found") == "value"
        assert decrypt_string(cache, "Found") == "value"  # from memory: no second load
        assert cache.decrypt("missing", bytearray(16)) == 0
        with pytest.raises(AuthenticationTagMismatchError):
            cache.decrypt("copied", bytearray(16))
        assert cache.decrypt("not:a:file", bytearray(16)) == 0  # never loaded

        found, missing, failed = [s for s in exporter.get_finished_spans() if s.name == SpanNames.Cache.POPULATE]
        assert found.instrumentation_scope is not None and found.instrumentation_scope.name == HkdfGuardTelemetry.CACHE.source_name
        assert any(e.attributes and e.attributes.get(AttributeNames.NAME) == "Found" for e in found.events)
        assert found.status.status_code != StatusCode.ERROR and missing.status.status_code != StatusCode.ERROR
        assert failed.status.status_code == StatusCode.ERROR
        assert [e.name for e in failed.events].count("exception") == 1
        decrypts = [s for s in exporter.get_finished_spans() if s.name == SpanNames.Cache.DECRYPT]
        assert len(decrypts) == 5
        assert found.parent is not None and found.parent.span_id == decrypts[0].context.span_id

        data = reader.get_metrics_data()
        assert data is not None
        points = [(dict(p.attributes or {}), p.value) for rm in data.resource_metrics for sm in rm.scope_metrics
                  for m in sm.metrics if m.name == MetricNames.Cache.OPERATIONS for p in m.data.data_points if isinstance(p, NumberDataPoint)]
        for result in ("success", "not_found", "error"):
            assert ({AttributeNames.OPERATION_NAME: SpanNames.Cache.POPULATE, AttributeNames.RESULT: result}, 1) in points
    finally:
        HkdfGuardTelemetry.set_tracer_provider(None)
        HkdfGuardTelemetry.set_meter_provider(None)
        meter_provider.shutdown()


# --- Arguments --------------------------------------------------------------------------------


def test_the_constructor_validates_its_arguments(folder: Path, ring: DefaultKeyRing) -> None:
    trust = current_user_trust()
    format_provider = DefaultFormatProvider()

    with pytest.raises(TypeError):
        FilePerSecretCache(None, trust, ring, format_provider)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="secrets folder path is required"):
        FilePerSecretCache("", trust, ring, format_provider)
    with pytest.raises(TypeError):
        FilePerSecretCache(folder, None, ring, format_provider)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FilePerSecretCache(folder, ring, ring, format_provider)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FilePerSecretCache(folder, trust, None, format_provider)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FilePerSecretCache(folder, trust, ring, None)  # type: ignore[arg-type]
    with pytest.raises(FileNotFoundError):
        FilePerSecretCache(folder / "absent", trust, ring, format_provider)
    (folder / "file").write_bytes(b"")
    with pytest.raises(FileNotFoundError):
        FilePerSecretCache(folder / "file", trust, ring, format_provider)
    assert FilePerSecretCache(folder, trust, ring, format_provider).folder_path == os.path.abspath(folder)
    assert FilePerSecretCache(str(folder), trust, ring, format_provider).folder_path == os.path.abspath(folder)


def test_a_none_name_raises(folder: Path, ring: DefaultKeyRing) -> None:
    cache = create_cache(folder, ring)

    with pytest.raises(TypeError):
        cache.decrypt(None, bytearray(16))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        cache.find_max_decrypted_length(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        run(cache.decrypt_async(None, bytearray(16)))  # type: ignore[arg-type]
