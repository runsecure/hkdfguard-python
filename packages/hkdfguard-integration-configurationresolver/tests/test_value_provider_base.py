"""The port of .NET's ValueProviderBaseScenarioTests, and of ProviderScenarioTests' sizing test
over a dict-backed ValueProviderBase in place of DictionaryValueProvider.

Python's ValueProviderBase builds only ``try_get_value`` on a subclass's bytes - there is no
TryGetChar or TryGetCharCount - so the tests of those are not ported.
"""

from __future__ import annotations

import pytest
from configurationresolver_core_test_support import CAFE, E_ACUTE, DictValueProvider, create_template_resolver
from hkdfguard.abstractions import WritableBuffer
from hkdfguard.integration.configurationresolver import (
    ConfigurationKeyError,
    ConfigurationKeyErrorCode,
    DefaultToken,
    ValueProvider,
    ValueProviderBase,
    ValueStatus,
)

LARGE = "x" * 600


class ScriptedBytesProvider(ValueProviderBase):
    """A byte-based provider whose reported sizes and actual contents are scripted per call. A
    ``None`` count, or a ``None`` read, is a key not found."""

    def __init__(self, counts: list[int | None], reads: list[str | None]) -> None:
        self._counts = counts
        self._reads = reads
        self._count_calls = 0
        self.read_calls = 0

    @classmethod
    def fixed(cls, value: str) -> ScriptedBytesProvider:
        count = len(value.encode())
        return cls([count] * 4, [value] * 4)

    @classmethod
    def missing(cls) -> ScriptedBytesProvider:
        return cls([None] * 3, [])

    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        value = self._reads[self.read_calls]
        self.read_calls += 1
        if value is None:
            return ValueStatus.NOT_FOUND, 0
        encoded = value.encode()
        with memoryview(destination) as view, view.cast("B") as room:
            if len(encoded) > len(room):
                return ValueStatus.DESTINATION_TOO_SMALL, 0
            room[: len(encoded)] = encoded
        return ValueStatus.FOUND, len(encoded)

    def _find_byte_count(self, key: str) -> int | None:
        count = self._counts[self._count_calls % len(self._counts)]
        self._count_calls += 1
        return count


class ThrowingProvider(ValueProvider):
    """A provider that raises the same :class:`ConfigurationKeyError` for every lookup."""

    def __init__(self, source_index: int | None) -> None:
        self.exception = ConfigurationKeyError("Key", ConfigurationKeyErrorCode.VALUE_UNSTABLE, source_index)

    def try_get_value(self, key: str) -> tuple[ValueStatus, str | None]:
        raise self.exception

    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        raise self.exception


@pytest.mark.parametrize("value", [CAFE, "", LARGE], ids=["cafe", "empty", "large"])
def test_bytes_source_is_read_as_string(value: str) -> None:
    provider = ScriptedBytesProvider.fixed(value)

    assert provider.try_get_value("Key") == (ValueStatus.FOUND, value)


def test_bytes_source_missing_key_is_not_found() -> None:
    provider = ScriptedBytesProvider.missing()

    assert provider.try_get_value("Key") == (ValueStatus.NOT_FOUND, None)
    assert provider.read_calls == 0


def test_bytes_source_removed_between_sizing_and_reading_is_not_found() -> None:
    provider = ScriptedBytesProvider(counts=[4], reads=[None])

    assert provider.try_get_value("Key") == (ValueStatus.NOT_FOUND, None)


@pytest.mark.parametrize(
    ("first_count", "second"),
    [
        (3, "abcdef"),
        (3, "y" * 600),
        (600, "y" * 700),
        (600, "abcdef"),
    ],
)
def test_bytes_source_that_changes_size_is_read_again(first_count: int, second: str) -> None:
    too_large = "z" * (first_count + 1)
    provider = ScriptedBytesProvider(counts=[first_count, len(second.encode())], reads=[too_large, second])

    assert provider.try_get_value("Key") == (ValueStatus.FOUND, second)
    assert provider.read_calls == 2


def test_bytes_source_that_keeps_growing_throws() -> None:
    provider = ScriptedBytesProvider(counts=[1, 1, 1], reads=["ab", "ab", "ab"])

    with pytest.raises(ConfigurationKeyError) as error:
        provider.try_get_value("Key")

    assert error.value.key == "Key"
    assert error.value.error is ConfigurationKeyErrorCode.VALUE_UNSTABLE
    assert error.value.source_index is None
    assert str(error.value) == "The value for a configuration key could not be resolved (ValueUnstable)."
    assert provider.read_calls == 3


def assert_reported_at(error: ConfigurationKeyError, provider: ThrowingProvider, source_index: int) -> None:
    assert error.key == "Key"
    assert error.error is ConfigurationKeyErrorCode.VALUE_UNSTABLE
    assert error.source_index == source_index
    assert "Key" not in str(error)
    assert error.__cause__ is provider.exception
    assert provider.exception.source_index is None


def test_provider_key_exception_is_reported_at_its_position_in_the_template() -> None:
    provider = ThrowingProvider(source_index=None)
    resolver = create_template_resolver(DefaultToken(), provider, "${Key}")
    source = f"{E_ACUTE} ${{Key}}"

    # The acute e is 2 UTF-8 bytes, so the item is at byte 3 whether the source is a str or bytes;
    # .NET's char index here is 2.
    for form in (source, source.encode()):
        with pytest.raises(ConfigurationKeyError) as error:
            resolver.resolve(form, bytearray(16))

        assert_reported_at(error.value, provider, 3)


def test_provider_key_exception_with_a_position_is_not_wrapped() -> None:
    provider = ThrowingProvider(source_index=7)
    resolver = create_template_resolver(DefaultToken(), provider, "${Key}")

    for form in ("${Key}", b"${Key}"):
        with pytest.raises(ConfigurationKeyError) as error:
            resolver.resolve(form, bytearray(16))

        assert error.value is provider.exception


def test_base_sizing_methods_report_the_required_buffer_size() -> None:
    provider = DictValueProvider({"Key": CAFE})

    assert provider.find_byte_count("Key") == 5
    assert provider.find_byte_count("Missing") is None
    assert provider.try_get_value("Key") == (ValueStatus.FOUND, CAFE)
    assert provider.try_get_value("Missing") == (ValueStatus.NOT_FOUND, None)
