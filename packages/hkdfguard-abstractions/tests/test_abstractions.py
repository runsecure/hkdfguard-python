from __future__ import annotations

from collections.abc import Buffer, Callable

import pytest
from hkdfguard.abstractions import (
    ArrayUtility,
    DataEncryptionKey,
    InvalidKeyFileError,
    KeyNotFoundError,
    KeyRing,
    KeyTrackingValue,
    KeyWrapper,
    ProtectedCacheBase,
    ProtectedConfigurationPurpose,
    RefreshFailurePolicy,
    ServiceNames,
    Utf8,
    VersionedKey,
    WrappedKeyLimits,
    WritableBuffer,
)
from hkdfguard.diagnostics import HkdfGuardTelemetry

# --- ArrayUtility -----------------------------------------------------------------------------


def test_is_null_or_empty_is_true_for_none_empty_and_all_zero() -> None:
    assert ArrayUtility.is_null_or_empty(None)
    assert ArrayUtility.is_null_or_empty(b"")
    assert ArrayUtility.is_null_or_empty(bytearray(16))


def test_is_null_or_empty_is_false_with_any_non_zero_byte_even_the_last() -> None:
    data = bytearray(64)
    data[-1] = 1
    assert not ArrayUtility.is_null_or_empty(data)


def test_zero_memory_clears_a_buffer_or_a_view_of_part_of_one() -> None:
    data = bytearray(b"\x01\x02\x03\x04\x05")
    ArrayUtility.zero_memory(memoryview(data)[1:3])
    assert data == bytearray(b"\x01\x00\x00\x04\x05")

    ArrayUtility.zero_memory(data)
    assert data == bytearray(5)

    ArrayUtility.zero_memory(None)
    ArrayUtility.zero_memory(bytearray())


# --- Utf8 -------------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "hello", "héllo wörld ✓ 🔐", "秘密", "\u007f\u0080߿ࠀ￿"])
def test_encode_well_formed_text_matches_the_standard_codec(text: str) -> None:
    assert Utf8.encode(text) == text.encode()
    assert Utf8.encode_strict(text) == text.encode()


def test_an_unpaired_surrogate_becomes_ufffd_as_in_every_other_port() -> None:
    assert Utf8.encode("a\ud800b") == bytearray(b"a\xef\xbf\xbdb")
    assert Utf8.encode("\udc00") == bytearray(b"\xef\xbf\xbd")


def test_encode_strict_refuses_an_unpaired_surrogate() -> None:
    for text in ["Key\ud800Tail", "Key\udc00Tail", "Key\ud800"]:
        with pytest.raises(ValueError, match="unpaired surrogate"):
            Utf8.encode_strict(text)


def test_a_surrogate_pair_held_as_two_code_points_encodes_as_its_character() -> None:
    assert Utf8.encode_strict("😀") == "😀".encode()


# --- ServiceNames -----------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a", "7", "my.service", "com.example.Orders2", "trailing."])
def test_valid_service_names_pass(name: str) -> None:
    assert ServiceNames.is_valid(name)
    assert ServiceNames.get_problem(name) is None
    ServiceNames.require_valid(name, "name")


def test_exactly_max_length_passes_and_one_more_fails() -> None:
    assert ServiceNames.MAX_LENGTH == 128
    assert ServiceNames.is_valid("a" * 128)
    assert "at most 128 characters; this one is 129" in (ServiceNames.get_problem("a" * 129) or "")


@pytest.mark.parametrize(("name", "reason"), [
    (None, "required"), ("", "required"), (".service", "can't start with '.'"), (".", "can't start with '.'"),
    ("my..service", "can't contain '..'"), ("my...service", "can't contain '..'"), ("service..", "can't contain '..'"),
    ("my-service", "U+002D at position 2"), ("my service", "U+0020 at position 2"), ("my_service", "U+005F at position 2"),
    ("café", "U+00E9 at position 3"), ("a/b", "U+002F at position 1"), ("a\0b", "U+0000 at position 1"),
])
def test_invalid_service_names_fail_with_the_reason(name: str | None, reason: str) -> None:
    assert not ServiceNames.is_valid(name)
    assert reason in (ServiceNames.get_problem(name) or "")


def test_require_valid_reports_the_parameter_and_reason() -> None:
    with pytest.raises(TypeError, match="serviceName"):
        ServiceNames.require_valid(None, "serviceName")
    with pytest.raises(ValueError, match=r"^serviceName: .*can't contain '\.\.'"):
        ServiceNames.require_valid("a..b", "serviceName")


# --- ProtectedConfigurationPurpose ------------------------------------------------------------


def test_for_key_prefixes_and_upper_cases_the_full_key_path() -> None:
    assert ProtectedConfigurationPurpose.for_key("ConnectionStrings:Admin") == "HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:ADMIN"


def test_aad_for_is_the_utf8_bytes_of_the_purpose() -> None:
    assert ProtectedConfigurationPurpose.aad_for("Database:Password") == ProtectedConfigurationPurpose.for_key("Database:Password").encode()


def test_aad_for_known_vector_for_cross_language_ports() -> None:
    assert ProtectedConfigurationPurpose.aad_for("ConnectionStrings:café") == "HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:CAFé".encode()


def test_an_empty_or_none_key_is_refused() -> None:
    for function in (ProtectedConfigurationPurpose.for_key, ProtectedConfigurationPurpose.aad_for):
        with pytest.raises(ValueError, match="must not be empty"):
            function("")
        with pytest.raises(TypeError):
            function(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(("first", "second"), [("secret", "SECRET"), ("Secret", "secret"), ("Connection_Strings:Admin-1", "connection_strings:ADMIN-1")])
def test_keys_differing_only_in_ascii_case_share_a_purpose(first: str, second: str) -> None:
    assert ProtectedConfigurationPurpose.for_key(first) == ProtectedConfigurationPurpose.for_key(second)
    assert ProtectedConfigurationPurpose.aad_for(first) == ProtectedConfigurationPurpose.aad_for(second)


@pytest.mark.parametrize(("first", "second"), [("café", "CAFÉ"), ("ſecret", "Secret"), ("ıd", "ID"), ("straße", "STRASSE")])
def test_non_ascii_case_variants_never_share_a_purpose(first: str, second: str) -> None:
    assert ProtectedConfigurationPurpose.for_key(first) != ProtectedConfigurationPurpose.for_key(second)


def test_only_ascii_letters_are_upper_cased() -> None:
    assert ProtectedConfigurationPurpose.for_key("café:über-1_中") == f"{ProtectedConfigurationPurpose.PREFIX}:CAFé:üBER-1_中"


def test_purposes_never_merge_keys_that_differ_beyond_ascii_case_for_any_code_point() -> None:
    seen: dict[str, str] = {}
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        key = chr(cp)
        other = seen.setdefault(ProtectedConfigurationPurpose.for_key(key), key)
        assert other == key or other.lower() == key.lower(), f"U+{cp:04X} shares a purpose with {other!r}"


def test_purposes_refuse_an_unpaired_surrogate_and_accept_a_pair() -> None:
    for key in ["Key\ud800Tail", "Key\udc00Tail", "Key\ud800"]:
        with pytest.raises(ValueError):
            ProtectedConfigurationPurpose.for_key(key)
        with pytest.raises(ValueError):
            ProtectedConfigurationPurpose.aad_for(key)

    assert ProtectedConfigurationPurpose.for_key("Key😀Tail") == f"{ProtectedConfigurationPurpose.PREFIX}:KEY😀TAIL"


# --- Shared values ----------------------------------------------------------------------------


def test_shared_limits_match_the_other_ports() -> None:
    assert RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES == 3
    assert WrappedKeyLimits.MAX_BYTES == 512
    assert ProtectedCacheBase.AAD_PREFIX == "HkdfGuard.Cache:"
    assert ProtectedConfigurationPurpose.PREFIX == "HkdfGuard.EncryptedConfiguration"


def test_key_tracking_value_is_immutable() -> None:
    value = KeyTrackingValue(7, b"\x01\x02")
    assert (value.key_version, value.value) == (7, b"\x01\x02")
    with pytest.raises(AttributeError):
        value.key_version = 8  # type: ignore[misc]


# --- ProtectedCacheBase -----------------------------------------------------------------------


class MaskingKey(DataEncryptionKey):
    """A reversible stand-in for real AEAD: XORs every byte with a fixed mask."""

    MASK = 0xA5

    def __init__(self, throw_on_decrypt: bool = False) -> None:
        self.throw_on_decrypt = throw_on_decrypt
        self.encrypt_aads: list[bytes] = []
        self.decrypt_aads: list[bytes] = []

    def encrypt(self, plaintext: WritableBuffer, *, aad: Buffer = b"") -> bytes:
        self.encrypt_aads.append(bytes(aad))
        output = bytes(b ^ self.MASK for b in memoryview(plaintext).cast("B"))
        ArrayUtility.zero_memory(plaintext)
        return output

    def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        self.decrypt_aads.append(bytes(aad))
        if self.throw_on_decrypt:
            raise RuntimeError("decrypt failed")
        data = bytes(ciphertext)
        view = memoryview(result).cast("B")
        if len(view) < len(data):
            raise ValueError("Result buffer too small.")
        view[: len(data)] = bytes(b ^ self.MASK for b in data)
        return len(data)


class FakeKeyRing(KeyRing):
    def __init__(self, key: DataEncryptionKey, version: int = 1) -> None:
        self.keys: dict[int, DataEncryptionKey] = {version: key}

    def add(self, version: int, key: DataEncryptionKey) -> None:
        self.keys[version] = key

    @property
    def current_version(self) -> int:
        return max(self.keys)

    def get_current(self) -> VersionedKey:
        return VersionedKey(self.current_version, self.keys[self.current_version])

    def get(self, version: int) -> DataEncryptionKey:
        if version not in self.keys:
            raise KeyNotFoundError(f"No key is registered for version {version}.")
        return self.keys[version]

    def find(self, version: int) -> DataEncryptionKey | None:
        return self.keys.get(version)


class TestCache(ProtectedCacheBase):
    __test__ = False

    def __init__(self, ring: KeyRing | None = None, key: DataEncryptionKey | None = None) -> None:
        super().__init__(ring or FakeKeyRing(key or MaskingKey()))
        self.on_try_populate: Callable[[str], bool] | None = None
        self.populate_requests: list[str] = []

    def store(self, name: str, plaintext: bytearray | str) -> None:
        self._put_entry(name, self._encrypt_any(name, plaintext))

    def store_if_absent(self, name: str, plaintext: bytearray) -> bool:
        return self._put_entry_if_absent(name, self._encrypt(name, plaintext))

    def store_under_another_name(self, encrypted_for: str, stored_as: str, plaintext: bytearray) -> None:
        self._put_entry(stored_as, self._encrypt(encrypted_for, plaintext))

    def version_of(self, name: str) -> int:
        entry = self._get_entry(name)
        assert entry is not None
        return entry.key_version

    def remove(self, name: str) -> bool:
        return self._remove_entry(name)

    def _try_populate(self, name: str) -> bool:
        self.populate_requests.append(name)
        return self.on_try_populate(name) if self.on_try_populate else super()._try_populate(name)


def decrypt_bytes(cache: ProtectedCacheBase, name: str) -> bytes:
    result = bytearray(64)
    return bytes(result[: cache.decrypt(name, result)])


def decrypt_text(cache: ProtectedCacheBase, name: str) -> str:
    """Decrypts as a caller does: size the buffer, decrypt into it, then decode."""
    result = bytearray(cache.find_max_decrypted_length(name) or 0)
    return result[: cache.decrypt(name, result)].decode()


def test_a_stored_value_decrypts_as_bytes_or_text() -> None:
    cache = TestCache()
    cache.store("item", bytearray(b"value"))
    cache.store("text", "héllo")

    assert decrypt_bytes(cache, "item") == b"value"
    assert decrypt_text(cache, "text") == "héllo"


def test_a_missing_name_reads_as_zero_or_none() -> None:
    cache = TestCache()

    assert cache.decrypt("missing", bytearray(16)) == 0
    assert cache.find_max_decrypted_length("missing") is None


def test_names_ignore_ascii_case_only() -> None:
    cache = TestCache()
    cache.store("Item", bytearray(b"value"))
    cache.store("café", bytearray(b"value"))

    assert decrypt_bytes(cache, "ITEM") == b"value"
    assert cache.decrypt("CAFÉ", bytearray(16)) == 0
    assert decrypt_bytes(cache, "CAFé") == b"value"
    assert cache.find_max_decrypted_length("item") == 5


def test_a_miss_populates_through_try_populate_and_a_hit_does_not() -> None:
    cache = TestCache()

    def populate(name: str) -> bool:
        cache.store(name, bytearray(b"fetched"))
        return True

    cache.on_try_populate = populate
    assert decrypt_bytes(cache, "remote") == b"fetched"
    assert decrypt_bytes(cache, "remote") == b"fetched"
    assert cache.populate_requests == ["remote"]


def test_try_populate_claiming_success_but_storing_nothing_reads_as_missing() -> None:
    cache = TestCache()
    cache.on_try_populate = lambda name: True

    assert cache.decrypt("remote", bytearray(16)) == 0
    assert cache.find_max_decrypted_length("remote") is None


def test_storing_zeroes_the_callers_buffer_and_refuses_an_empty_value() -> None:
    cache = TestCache()
    plaintext = bytearray(b"secret")
    cache.store("item", plaintext)
    assert plaintext == bytearray(6)

    with pytest.raises(ValueError, match="empty value"):
        cache.store("empty", bytearray())
    with pytest.raises(ValueError, match="empty value"):
        cache.store("empty", "")
    with pytest.raises(TypeError, match="can't be zeroed"):
        cache._encrypt_any("item", b"immutable")


def test_a_failing_key_propagates_from_decrypt() -> None:
    cache = TestCache(key=MaskingKey(throw_on_decrypt=True))
    cache.store("item", bytearray(b"value"))

    with pytest.raises(RuntimeError, match="decrypt failed"):
        cache.decrypt("item", bytearray(16))


def test_reads_with_sensitive_logging_enabled_still_work() -> None:
    original = HkdfGuardTelemetry.ROOT.sensitive_logging_enabled
    HkdfGuardTelemetry.ROOT.sensitive_logging_enabled = True
    try:
        cache = TestCache()
        cache.store("item", bytearray(b"value"))
        assert decrypt_bytes(cache, "item") == b"value"
    finally:
        HkdfGuardTelemetry.ROOT.sensitive_logging_enabled = original


@pytest.mark.parametrize("length", [512, 513, 2 * 1024 * 1024])
def test_small_and_large_text_values_round_trip(length: int) -> None:
    cache = TestCache()
    cache.store("big", "x" * length)

    assert decrypt_text(cache, "big") == "x" * length


def test_every_value_is_encrypted_and_decrypted_with_its_names_aad() -> None:
    key = MaskingKey()
    cache = TestCache(key=key)

    cache.store("Item", bytearray(b"value"))
    cache.decrypt("ITEM", bytearray(16))
    cache.decrypt("item", bytearray(16))

    expected = ProtectedCacheBase.aad_for("Item")
    assert key.encrypt_aads == [expected]
    assert key.decrypt_aads == [expected, expected]


def test_aad_for_is_the_prefix_plus_the_name_with_only_ascii_letters_upper_cased() -> None:
    # A known vector, for every port to reproduce byte for byte.
    assert ProtectedCacheBase.aad_for("api-Key_1:café") == "HkdfGuard.Cache:API-KEY_1:CAFé".encode()
    assert ProtectedCacheBase.aad_for("item") == ProtectedCacheBase.aad_for("ITEM")
    assert ProtectedCacheBase.aad_for("café") != ProtectedCacheBase.aad_for("CAFÉ")


def test_aad_for_refuses_none_and_invalid_utf16_and_storing_still_zeroes_the_plaintext() -> None:
    with pytest.raises(TypeError):
        ProtectedCacheBase.aad_for(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ProtectedCacheBase.aad_for("bad\ud800name")

    cache = TestCache()
    plaintext = bytearray(b"value")
    with pytest.raises(ValueError):
        cache.store("bad\ud800name", plaintext)
    assert plaintext == bytearray(5)


def test_a_value_stored_under_another_name_is_decrypted_with_the_lookup_names_aad() -> None:
    key = MaskingKey()
    cache = TestCache(key=key)

    cache.store_under_another_name("admin", "reporting", bytearray(b"secret"))
    cache.decrypt("reporting", bytearray(16))

    assert key.encrypt_aads == [ProtectedCacheBase.aad_for("admin")]
    assert key.decrypt_aads == [ProtectedCacheBase.aad_for("reporting")]


def test_each_entry_records_its_version_and_decrypts_with_that_versions_key() -> None:
    first, second = MaskingKey(), MaskingKey()
    ring = FakeKeyRing(first)
    cache = TestCache(ring)

    cache.store("before", bytearray(b"one"))
    ring.add(2, second)
    cache.store("after", bytearray(b"two"))

    assert (cache.version_of("before"), cache.version_of("after")) == (1, 2)
    assert decrypt_bytes(cache, "before") == b"one"
    assert decrypt_bytes(cache, "after") == b"two"
    assert (len(first.decrypt_aads), len(second.decrypt_aads)) == (1, 1)

    del ring.keys[1]
    with pytest.raises(KeyNotFoundError):
        cache.decrypt("before", bytearray(16))


def test_put_if_absent_stores_only_the_first_and_remove_drops_it() -> None:
    cache = TestCache()

    assert cache.store_if_absent("item", bytearray(b"one"))
    assert not cache.store_if_absent("ITEM", bytearray(b"two"))
    assert decrypt_bytes(cache, "item") == b"one"

    assert cache.remove("Item")
    assert cache.decrypt("item", bytearray(16)) == 0


def test_overlaps_detects_shared_memory_between_buffers_and_views() -> None:
    from hkdfguard.abstractions import ArrayUtility

    buffer = bytearray(32)
    view = memoryview(buffer)
    assert ArrayUtility.overlaps(buffer, buffer)
    assert ArrayUtility.overlaps(view[:16], view[15:])
    assert ArrayUtility.overlaps(buffer, view[31:])
    assert not ArrayUtility.overlaps(view[:16], view[16:])
    assert not ArrayUtility.overlaps(buffer, bytearray(32))
    assert not ArrayUtility.overlaps(bytearray(0), buffer)

    fresh = bytearray(8)
    assert ArrayUtility.overlaps(fresh, fresh)
    fresh.extend(b"still resizable")  # no buffer export is left held by the check


def test_key_versions_accept_exactly_the_signed_32_bit_range() -> None:
    from hkdfguard.abstractions import KeyVersions

    for version in (-(2**31), -1, 0, 2**31 - 1):
        KeyVersions.require_valid(version)
    for version in (-(2**31) - 1, 2**31):
        assert not KeyVersions.is_valid(version)
        with pytest.raises(ValueError, match="version must be between"):
            KeyVersions.require_valid(version)


# --- Key files ----------------------------------------------------------------------------------


class _MinimalKeyWrapper(KeyWrapper):
    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError


def test_a_key_wrapper_must_read_its_own_key_files_there_is_no_unchecked_default() -> None:
    # Whoever can replace a key file chooses the DEK, so every key wrapper decides how it trusts one.
    with pytest.raises(TypeError, match="read_key_file"):
        _MinimalKeyWrapper()  # type: ignore[abstract]
    assert issubclass(InvalidKeyFileError, OSError)
