"""The port of .NET's ConfigurationResolverBuilderTests. add_protected_cache is tested with the
protected cache value provider."""

from __future__ import annotations

import pytest
from configurationresolver_core_test_support import CustomToken, DictValueProvider, resolve_to_str
from hkdfguard.integration.configurationresolver import (
    ConfigurationItemReader,
    ConfigurationItemResolver,
    ConfigurationResolverBuilder,
    DefaultToken,
)


def new_high() -> DictValueProvider:
    return DictValueProvider({"Name": "Grace"})


def new_low() -> DictValueProvider:
    return DictValueProvider({"Name": "Ada", "Lang": "${Name}"})


def test_build_uses_the_reader_and_providers_in_the_order_added() -> None:
    reader = ConfigurationItemReader(DefaultToken())
    reader.read_keys("${Name} ${Lang}")

    resolver = ConfigurationResolverBuilder().with_reader(reader).add_value_provider(new_high()).add_value_provider(new_low()).build()

    assert isinstance(resolver, ConfigurationItemResolver)
    assert resolve_to_str(resolver, "${Name} ${Lang} $$${Name}", 256) == "Grace ${Name} $${Name}"


def test_build_defaults_to_the_default_token_and_options() -> None:
    resolver = ConfigurationResolverBuilder().with_reader(ConfigurationItemReader(DefaultToken())).add_value_provider(new_low()).build()

    assert resolver.ignore_unresolvable_placeholders is False
    assert resolver.max_resolution_depth == 1
    assert resolve_to_str(resolver, "$${Name}", 256) == "${Name}"


def test_build_applies_the_token_and_options() -> None:
    token = CustomToken("{{", "}}")
    reader = ConfigurationItemReader(token)
    reader.read_keys("{{Lang}} {{Name}} {{Missing}}")

    resolver = (
        ConfigurationResolverBuilder()
        .with_token(token)
        .with_reader(reader)
        .add_value_provider(DictValueProvider({"Lang": "{{Name}}", "Name": "Ada"}))
        .ignore_unresolvable_placeholders()
        .with_max_resolution_depth(2)
        .build()
    )

    assert resolver.ignore_unresolvable_placeholders is True
    assert resolver.max_resolution_depth == 2
    assert resolve_to_str(resolver, "{{Lang}} {{Missing}} ${Lang}", 256) == "Ada {{Missing}} ${Lang}"


def test_build_each_call_returns_a_new_resolver() -> None:
    builder = ConfigurationResolverBuilder().with_reader(ConfigurationItemReader(DefaultToken())).add_value_provider(new_low())

    assert builder.build() is not builder.build()


def test_build_without_a_reader_or_a_provider_throws() -> None:
    with pytest.raises(RuntimeError, match="reader"):
        ConfigurationResolverBuilder().add_value_provider(new_low()).build()
    with pytest.raises(RuntimeError, match="value provider"):
        ConfigurationResolverBuilder().with_reader(ConfigurationItemReader(DefaultToken())).build()


def test_invalid_arguments_throw() -> None:
    builder = ConfigurationResolverBuilder()

    with pytest.raises(TypeError):
        builder.with_token(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        builder.with_reader(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        builder.add_value_provider(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_resolution_depth"):
        builder.with_max_resolution_depth(0)
