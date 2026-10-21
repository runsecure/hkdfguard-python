"""HkdfGuardOptions: reading configuration, validation, and applying onto a KeyRingBuilder."""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Buffer
from datetime import timedelta
from pathlib import Path

import pytest
from hkdfguard.abstractions import KeyWrapper, WritableBuffer
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.dataencryptionkey import KeyRingBuilder
from hkdfguard.options import HkdfGuardOptions, KeyFileOptions, OptionsValidationError


class FixedKeyWrapper(KeyWrapper):
    """Always reveals and "generates" the same fixed key: isolates apply_to/build from the native KMS
    while still running a real KeyRingBuilder.build."""

    def __init__(self) -> None:
        self.key = os.urandom(32)

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError("FixedKeyWrapper only reveals.")

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32


def finish(builder: KeyRingBuilder) -> KeyRingBuilder:
    return builder.with_key_wrapper(FixedKeyWrapper()).with_crypto_provider_factory(AesGcmCryptoProviderFactory()).with_key_refresh_interval(60)


def valid_options() -> HkdfGuardOptions:
    return HkdfGuardOptions(service_name="my.service", key_refresh_interval=60, ephemeral_keys=[1])


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / "wrapped-dek-v1.bin"
    path.write_bytes(b"wrapped")
    return path


# --- apply_to --------------------------------------------------------------------------------


def test_apply_to_returns_the_same_builder_for_chaining() -> None:
    builder = KeyRingBuilder()
    assert HkdfGuardOptions().apply_to(builder) is builder


def test_apply_to_sets_service_name_key_refresh_interval_and_max_refresh_failures() -> None:
    builder = HkdfGuardOptions(service_name="my.service", key_refresh_interval=60, max_refresh_failures=3).apply_to(KeyRingBuilder())

    assert builder.service_name == "my.service"
    assert builder.key_refresh_interval == 60
    assert builder.max_refresh_failures == 3


def test_apply_to_unset_fields_leave_the_builder_defaults_untouched() -> None:
    builder = HkdfGuardOptions().apply_to(KeyRingBuilder())

    assert builder.service_name is None
    assert builder.key_refresh_interval is None
    assert builder.max_refresh_failures == KeyRingBuilder.DEFAULT_MAX_REFRESH_FAILURES
    assert builder.ephemeral_key_rotation_interval == timedelta(hours=24)
    assert builder.ephemeral_key_retention == KeyRingBuilder.DEFAULT_EPHEMERAL_KEY_RETENTION


def test_apply_to_ephemeral_key_rotation_hours_sets_the_interval() -> None:
    builder = HkdfGuardOptions(ephemeral_key_rotation_hours=6).apply_to(KeyRingBuilder())
    assert builder.ephemeral_key_rotation_interval == timedelta(hours=6)


def test_apply_to_ephemeral_key_retention_hours_sets_the_retention() -> None:
    builder = HkdfGuardOptions(ephemeral_key_retention_hours=48).apply_to(KeyRingBuilder())
    assert builder.ephemeral_key_retention == timedelta(hours=48)


def test_apply_to_disable_ephemeral_key_rotation_turns_it_off() -> None:
    builder = HkdfGuardOptions(disable_ephemeral_key_rotation=True).apply_to(KeyRingBuilder())
    assert builder.ephemeral_key_rotation_interval is None


def test_apply_to_fail_open_on_refresh_failure_clears_the_builders_policy() -> None:
    builder = HkdfGuardOptions(fail_open_on_refresh_failure=True).apply_to(KeyRingBuilder())
    assert builder.max_refresh_failures is None


def test_apply_to_an_option_the_builder_rejects_raises() -> None:
    # apply_to doesn't validate; the builder's own checks still hold.
    with pytest.raises(ValueError, match="key_refresh_interval"):
        HkdfGuardOptions(key_refresh_interval=0).apply_to(KeyRingBuilder())


def test_apply_to_with_ephemeral_keys_registers_each_on_build() -> None:
    with finish(HkdfGuardOptions(ephemeral_keys=[1, 2]).apply_to(KeyRingBuilder())).build() as ring:
        assert ring.current_version == 2


def test_apply_to_with_key_files_registers_each_on_build(key_file: Path) -> None:
    options = HkdfGuardOptions(key_files=[KeyFileOptions(1, key_file)])
    with finish(options.apply_to(KeyRingBuilder())).build() as ring:
        assert ring.current_version == 1


def test_apply_to_with_key_files_and_ephemeral_keys_the_highest_version_becomes_current(key_file: Path) -> None:
    options = HkdfGuardOptions(key_files=[KeyFileOptions(1, str(key_file))], ephemeral_keys=[2])
    with finish(options.apply_to(KeyRingBuilder())).build() as ring:
        assert ring.current_version == 2


# --- validate --------------------------------------------------------------------------------


def test_valid_options_have_no_failures() -> None:
    assert valid_options().validate() == []


@pytest.mark.parametrize(("service_name", "reason"), [(".service", "can't start with '.'"), ("my..service", "can't contain '..'"), ("my-service", "U+002D")])
def test_a_service_name_breaking_a_rule_fails_with_the_reason(service_name: str, reason: str) -> None:
    options = valid_options()
    options.service_name = service_name

    assert any(f.startswith("service_name is invalid") and reason in f for f in options.validate())


def test_a_service_name_over_the_limit_fails() -> None:
    options = valid_options()
    options.service_name = "a" * 129
    assert options.validate()


@pytest.mark.parametrize("service_name", [None, "", "   "])
def test_a_missing_service_name_fails(service_name: str | None) -> None:
    options = valid_options()
    options.service_name = service_name
    assert any("service_name" in f for f in options.validate())


@pytest.mark.parametrize("interval", [-1, 0, 301])
def test_a_key_refresh_interval_out_of_range_fails(interval: int) -> None:
    options = valid_options()
    options.key_refresh_interval = interval
    assert any("key_refresh_interval" in f for f in options.validate())


@pytest.mark.parametrize("interval", [1, 300, None])
def test_a_key_refresh_interval_in_range_or_unset_succeeds(interval: int | None) -> None:
    options = valid_options()
    options.key_refresh_interval = interval
    assert options.validate() == []


def test_no_key_files_or_ephemeral_keys_fails() -> None:
    options = valid_options()
    options.ephemeral_keys = []
    assert any("key file or ephemeral key" in f for f in options.validate())


@pytest.mark.parametrize("path", ["", "   "])
def test_a_key_file_without_a_path_fails(path: str) -> None:
    options = valid_options()
    options.ephemeral_keys = []
    options.key_files = [KeyFileOptions(1, path)]
    assert any("missing a path" in f for f in options.validate())


def test_a_version_registered_twice_across_key_files_and_ephemeral_keys_fails() -> None:
    options = valid_options()
    options.key_files = [KeyFileOptions(1, "/tmp/dek.bin")]
    assert any("Version 1 is registered more than once" in f for f in options.validate())


def test_a_version_repeated_within_ephemeral_keys_fails() -> None:
    options = valid_options()
    options.ephemeral_keys = [1, 1]
    assert any("more than once" in f for f in options.validate())


def test_unique_versions_across_key_files_and_ephemeral_keys_succeed() -> None:
    options = valid_options()
    options.ephemeral_keys = [2]
    options.key_files = [KeyFileOptions(1, "/tmp/dek.bin")]
    assert options.validate() == []


def test_a_key_file_above_every_ephemeral_key_fails_while_rotation_is_on() -> None:
    options = valid_options()
    options.key_files = [KeyFileOptions(5, "/tmp/dek.bin")]
    assert any("key_files version 5 is above every ephemeral key version" in f for f in options.validate())


def test_a_key_file_above_every_ephemeral_key_succeeds_with_rotation_disabled() -> None:
    options = valid_options()
    options.key_files = [KeyFileOptions(5, "/tmp/dek.bin")]
    options.disable_ephemeral_key_rotation = True
    assert options.validate() == []


@pytest.mark.parametrize("failures", [0, -1])
def test_max_refresh_failures_below_one_fails(failures: int) -> None:
    options = valid_options()
    options.max_refresh_failures = failures
    assert any("max_refresh_failures" in f for f in options.validate())


@pytest.mark.parametrize("failures", [1, 10, None])
def test_max_refresh_failures_at_least_one_or_unset_succeeds(failures: int | None) -> None:
    options = valid_options()
    options.max_refresh_failures = failures
    assert options.validate() == []


@pytest.mark.parametrize("hours", [1, 24, HkdfGuardOptions.MAX_EPHEMERAL_KEY_ROTATION_HOURS])
def test_ephemeral_key_rotation_hours_in_range_succeed(hours: int) -> None:
    options = valid_options()
    options.ephemeral_key_rotation_hours = hours

    assert options.validate() == []
    options.apply_to(KeyRingBuilder())  # and the builder accepts every hour the validation does


@pytest.mark.parametrize("hours", [0, -1, HkdfGuardOptions.MAX_EPHEMERAL_KEY_ROTATION_HOURS + 1])
def test_ephemeral_key_rotation_hours_out_of_range_fail(hours: int) -> None:
    options = valid_options()
    options.ephemeral_key_rotation_hours = hours
    assert any("ephemeral_key_rotation_hours" in f for f in options.validate())


def test_the_rotation_hour_limit_is_the_builders_limit() -> None:
    limit = timedelta(hours=HkdfGuardOptions.MAX_EPHEMERAL_KEY_ROTATION_HOURS)
    assert limit <= KeyRingBuilder.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL < limit + timedelta(hours=1)


@pytest.mark.parametrize("hours", [1, 24, 24 * 365])
def test_ephemeral_key_retention_hours_at_least_one_succeed(hours: int) -> None:
    options = valid_options()
    options.ephemeral_key_retention_hours = hours

    assert options.validate() == []
    assert options.apply_to(KeyRingBuilder()).ephemeral_key_retention == timedelta(hours=hours)


@pytest.mark.parametrize("hours", [0, -1])
def test_ephemeral_key_retention_hours_below_one_fail(hours: int) -> None:
    options = valid_options()
    options.ephemeral_key_retention_hours = hours
    assert any("ephemeral_key_retention_hours" in f for f in options.validate())


def test_disabling_rotation_while_scheduling_it_fails() -> None:
    options = valid_options()
    options.disable_ephemeral_key_rotation = True
    options.ephemeral_key_rotation_hours = 12
    assert any("disable_ephemeral_key_rotation" in f for f in options.validate())


def test_disabling_rotation_alone_succeeds() -> None:
    options = valid_options()
    options.disable_ephemeral_key_rotation = True
    assert options.validate() == []


def test_fail_open_alone_succeeds() -> None:
    options = valid_options()
    options.fail_open_on_refresh_failure = True
    assert options.validate() == []


def test_fail_open_with_max_refresh_failures_fails() -> None:
    options = valid_options()
    options.fail_open_on_refresh_failure = True
    options.max_refresh_failures = 3
    assert any("fail_open_on_refresh_failure" in f for f in options.validate())


def test_validate_reports_every_failure_at_once() -> None:
    failures = HkdfGuardOptions(service_name="bad..name", key_refresh_interval=0, max_refresh_failures=0).validate()
    assert len(failures) == 4  # service name, interval, max failures, and no keys


def test_require_valid_returns_the_same_options() -> None:
    options = valid_options()
    assert options.require_valid() is options


def test_require_valid_raises_with_every_failure() -> None:
    with pytest.raises(OptionsValidationError) as raised:
        HkdfGuardOptions(key_refresh_interval=0).require_valid()

    assert len(raised.value.failures) == 3
    assert isinstance(raised.value, ValueError)
    assert "key_refresh_interval must be between 1 and 300 seconds." in str(raised.value)


# --- from_mapping ----------------------------------------------------------------------------

DOTNET_APPSETTINGS = """
{
  "HkdfGuard": {
    "ServiceName": "com.example.orders",
    "KeyRefreshInterval": 60,
    "MaxRefreshFailures": 3,
    "EphemeralKeyRotationHours": 12,
    "EphemeralKeyRetentionHours": 48,
    "KeyFiles": [ { "Version": 1, "Path": "/etc/myapp/wrapped-dek-v1.bin" } ],
    "EphemeralKeys": [ 2 ]
  }
}
"""


def test_from_mapping_reads_a_dotnet_appsettings_section() -> None:
    options = HkdfGuardOptions.from_mapping(json.loads(DOTNET_APPSETTINGS)["HkdfGuard"])

    assert options == HkdfGuardOptions(service_name="com.example.orders", key_refresh_interval=60, max_refresh_failures=3,
                                       ephemeral_key_rotation_hours=12, ephemeral_key_retention_hours=48,
                                       key_files=[KeyFileOptions(1, "/etc/myapp/wrapped-dek-v1.bin")], ephemeral_keys=[2])
    assert options.validate() == []


def test_from_mapping_reads_a_snake_case_toml_table() -> None:
    settings = tomllib.loads("""
        [hkdfguard]
        service_name = "com.example.orders"
        key_refresh_interval = 60
        fail_open_on_refresh_failure = true
        disable_ephemeral_key_rotation = true
        ephemeral_keys = [1]
        key_files = [{ version = 2, path = "dek-v2.bin" }]
    """)

    options = HkdfGuardOptions.from_mapping(settings["hkdfguard"])

    assert options.fail_open_on_refresh_failure
    assert options.disable_ephemeral_key_rotation
    assert options.key_files == [KeyFileOptions(2, "dek-v2.bin")]
    assert options.validate() == []


def test_from_mapping_matches_keys_ignoring_case_and_underscores() -> None:
    options = HkdfGuardOptions.from_mapping({"SERVICENAME": "a.b", "Key_Refresh_Interval": 5, "ephemeralkeys": [1]})
    assert (options.service_name, options.key_refresh_interval, options.ephemeral_keys) == ("a.b", 5, [1])


def test_from_mapping_converts_strings_as_ini_files_and_environment_variables_supply_them() -> None:
    options = HkdfGuardOptions.from_mapping({
        "KeyRefreshInterval": " 60 ", "MaxRefreshFailures": "+3", "FailOpenOnRefreshFailure": "False",
        "DisableEphemeralKeyRotation": "TRUE", "EphemeralKeys": ["1", 2], "KeyFiles": [{"Version": "3", "Path": "k.bin"}],
    })

    assert options.key_refresh_interval == 60
    assert options.max_refresh_failures == 3
    assert options.fail_open_on_refresh_failure is False
    assert options.disable_ephemeral_key_rotation is True
    assert options.ephemeral_keys == [1, 2]
    assert options.key_files == [KeyFileOptions(3, "k.bin")]


def test_from_mapping_treats_none_as_unset() -> None:
    options = HkdfGuardOptions.from_mapping(dict.fromkeys(["ServiceName", "KeyRefreshInterval", "FailOpenOnRefreshFailure", "KeyFiles", "EphemeralKeys"]))
    assert options == HkdfGuardOptions()


def test_from_mapping_of_an_empty_section_is_all_defaults() -> None:
    assert HkdfGuardOptions.from_mapping({}) == HkdfGuardOptions()


def test_from_mapping_accepts_key_file_options_and_path_objects() -> None:
    options = HkdfGuardOptions.from_mapping({"KeyFiles": [KeyFileOptions(1, "a.bin"), {"Version": 2, "Path": Path("b.bin")}]})
    assert options.key_files == [KeyFileOptions(1, "a.bin"), KeyFileOptions(2, Path("b.bin"))]


def test_from_mapping_leaves_validation_to_the_caller() -> None:
    options = HkdfGuardOptions.from_mapping({"KeyRefreshInterval": 0})
    assert any("key_refresh_interval" in f for f in options.validate())


def test_from_mapping_key_file_without_a_path_reads_and_then_fails_validation() -> None:
    options = HkdfGuardOptions.from_mapping({"ServiceName": "a.b", "KeyFiles": [{"Version": 1}]})
    assert options.validate() == ["key_files version 1 is missing a path."]


def test_from_mapping_then_require_valid_then_apply_to_builds_a_ring(key_file: Path) -> None:
    settings = {"ServiceName": "my.service", "KeyRefreshInterval": 60, "KeyFiles": [{"Version": 1, "Path": str(key_file)}], "EphemeralKeys": [2]}

    builder = HkdfGuardOptions.from_mapping(settings).require_valid().apply_to(KeyRingBuilder())
    with builder.with_key_wrapper(FixedKeyWrapper()).with_crypto_provider_factory(AesGcmCryptoProviderFactory()).build() as ring:
        assert ring.current_version == 2


@pytest.mark.parametrize(("settings", "message"), [
    ({"ServiceNmae": "a.b"}, r"unknown key 'ServiceNmae'"),
    ({"ServiceName": "a.b", "service_name": "c.d"}, r"'service_name' more than once"),
    ({1: "a.b"}, r"key that is not a string"),
    ({"ServiceName": 5}, r"settings\.service_name must be a string"),
    ({"KeyRefreshInterval": "sixty"}, r"settings\.key_refresh_interval must be an integer"),
    ({"KeyRefreshInterval": 60.5}, r"must be an integer"),
    ({"KeyRefreshInterval": True}, r"must be an integer"),
    ({"FailOpenOnRefreshFailure": "yes"}, r"settings\.fail_open_on_refresh_failure must be true or false"),
    ({"FailOpenOnRefreshFailure": 1}, r"must be true or false"),
    ({"EphemeralKeys": "1"}, r"settings\.ephemeral_keys must be a list"),
    ({"EphemeralKeys": 1}, r"must be a list"),
    ({"EphemeralKeys": [1, "x"]}, r"settings\.ephemeral_keys\[1\] must be an integer"),
    ({"KeyFiles": [{"Path": "a.bin"}]}, r"settings\.key_files\[0\] is missing its version"),
    ({"KeyFiles": [{"Version": 1, "Path": 7}]}, r"settings\.key_files\[0\]\.path must be a path"),
    ({"KeyFiles": [{"Version": 1, "Path": "a", "Size": 3}]}, r"settings\.key_files\[0\] has an unknown key 'Size'"),
])
def test_from_mapping_rejects_bad_settings_naming_where(settings: dict[object, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        HkdfGuardOptions.from_mapping(settings)  # type: ignore[arg-type]


@pytest.mark.parametrize(("settings", "message"), [
    (["ServiceName"], r"settings must be a mapping; it is list"),
    ({"KeyFiles": ["a.bin"]}, r"settings\.key_files\[0\] must be a mapping; it is str"),
])
def test_from_mapping_rejects_a_section_that_is_not_a_mapping(settings: object, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        HkdfGuardOptions.from_mapping(settings)  # type: ignore[arg-type]


def test_a_version_outside_the_signed_32_bit_range_is_reported() -> None:
    options = HkdfGuardOptions(service_name="com.example.orders", ephemeral_keys=[2**31, 1], key_files=[KeyFileOptions(-(2**31) - 1, "a.bin")])

    failures = options.validate()

    assert any("Version 2147483648 is outside the signed 32-bit range" in f for f in failures)
    assert any("Version -2147483649 is outside the signed 32-bit range" in f for f in failures)
    assert not any("Version 1 " in f for f in failures)
