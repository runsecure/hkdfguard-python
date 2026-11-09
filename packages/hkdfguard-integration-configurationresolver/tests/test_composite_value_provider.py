"""The port of .NET's CompositeValueProviderTests. Values are UTF-8 bytes, so .NET's TryGetChar
test is the TryGetBytes test here."""

from __future__ import annotations

import pytest
from configurationresolver_core_test_support import O_DIAERESIS, SpyValueProvider
from hkdfguard.integration.configurationresolver import (
    CompositeValueProvider,
    ConfigurationKeyError,
    ConfigurationKeyErrorCode,
    ValueProvider,
    ValueStatus,
)

LOW_ONLY = "l" + O_DIAERESIS


def new_high() -> SpyValueProvider:
    return SpyValueProvider({"Shared": "high", "HighOnly": "h"})


def new_low() -> SpyValueProvider:
    return SpyValueProvider({"Shared": "low", "LowOnly": LOW_ONLY})


def test_try_get_value_returns_the_value_from_the_first_provider_that_has_the_key() -> None:
    high, low = new_high(), new_low()
    provider = CompositeValueProvider(high, low)

    assert provider.try_get_value("Shared") == (ValueStatus.FOUND, "high")
    assert provider.try_get_value("LowOnly") == (ValueStatus.FOUND, LOW_ONLY)
    assert provider.try_get_value("Missing") == (ValueStatus.NOT_FOUND, None)

    assert high.try_get_value_calls == ["Shared", "LowOnly", "Missing"]
    assert low.try_get_value_calls == ["LowOnly", "Missing"]


def test_try_get_bytes_writes_the_value_from_the_first_provider_that_has_the_key() -> None:
    high, low = new_high(), new_low()
    provider = CompositeValueProvider(high, low)
    destination = bytearray(8)

    status, shared_written = provider.try_get_bytes("Shared", destination)
    assert status is ValueStatus.FOUND
    assert destination[:shared_written] == b"high"
    status, low_written = provider.try_get_bytes("LowOnly", destination)
    assert status is ValueStatus.FOUND
    assert destination[:low_written] == LOW_ONLY.encode()
    assert provider.try_get_bytes("Missing", destination) == (ValueStatus.NOT_FOUND, 0)
    assert low.try_get_bytes_calls == ["LowOnly", "Missing"]


def test_destination_too_small_in_the_first_provider_does_not_fall_through() -> None:
    high, low = new_high(), new_low()
    provider = CompositeValueProvider(high, low)

    assert provider.try_get_bytes("Shared", bytearray(2)) == (ValueStatus.DESTINATION_TOO_SMALL, 0)
    assert low.try_get_bytes_calls == []


def test_provider_exception_propagates() -> None:
    low = new_low()
    failing = SpyValueProvider({}, throw_on_lookup=ConfigurationKeyError("Shared", ConfigurationKeyErrorCode.VALUE_UNSTABLE))
    provider = CompositeValueProvider(failing, low)

    with pytest.raises(ConfigurationKeyError):
        provider.try_get_bytes("Shared", bytearray(8))
    assert low.try_get_bytes_calls == []


def test_providers_are_in_priority_order_and_copied() -> None:
    high, low = new_high(), new_low()
    providers: list[ValueProvider] = [high, low]
    provider = CompositeValueProvider(*providers)

    providers.clear()

    assert provider.providers == (high, low)
    assert provider.providers[0] is high
    assert provider.providers[1] is low


def test_constructor_invalid_providers_throws() -> None:
    with pytest.raises(TypeError):
        CompositeValueProvider(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="At least one"):
        CompositeValueProvider()
    # .NET throws ArgumentException for a null provider; Python reports a None with TypeError.
    with pytest.raises(TypeError):
        CompositeValueProvider(new_high(), None)  # type: ignore[arg-type]
