"""The port of the parts of .NET's JsonConfigurationScenarioTests that need only ported code.

Only the "dictionary" provider is ported - a dict-backed ValueProviderBase - so the tests that
.NET runs over each provider run once here. Templates are written to disk as .NET's are, and the
resolved JSON is loaded with the ``json`` module instead of Microsoft.Extensions.Configuration.
.NET's ResolveChars reads a template with File.ReadAllText, which drops a byte order mark; the
``str`` form here is read as ``utf-8-sig`` to match.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path
from typing import Any

import pytest
from configurationresolver_core_test_support import (
    E_ACUTE,
    O_DIAERESIS,
    CustomToken,
    DictValueProvider,
    assert_zeroed,
    create_template_resolver,
    filled,
)
from hkdfguard.integration.configurationresolver import (
    ConfigurationItemReader,
    ConfigurationItemResolver,
    ConfigurationItemTokenBase,
    ConfigurationKeyError,
    ConfigurationKeyErrorCode,
    ConfigurationResolver,
    DefaultToken,
    DestinationTooSmallError,
)

GREETING = "h" + E_ACUTE + "llo"
WORLD = "w" + O_DIAERESIS + "rld"

TEMPLATE = "\n".join(
    [
        "{",
        '  "ConnectionStrings": {',
        '    "Default": "Host=${Database:Host};Port=${ Database:Port };Password=${Database:Password}"',
        "  },",
        f'  "Greeting": "${{Greeting}} {WORLD}",',
        '  "Literal": "${} and $ {not an item}"',
        "}",
    ],
)

VALUES = {
    "Database:Host": "db.internal",
    "Database:Port": "5432",
    "Database:Password": 's3cr\\"t!',
    "Greeting": GREETING,
}

BUFFER_LENGTH = 4096


def write_text(directory: Path, file_name: str, content: str, *, byte_order_mark: bool = False) -> Path:
    path = directory / file_name
    path.write_bytes((codecs.BOM_UTF8 if byte_order_mark else b"") + content.encode())
    return path


def read_text(path: Path) -> str:
    """The port of File.ReadAllText, which drops a UTF-8 byte order mark."""
    return path.read_text(encoding="utf-8-sig")


def create_provider() -> DictValueProvider:
    return DictValueProvider(VALUES)


def create_resolver(token: ConfigurationItemTokenBase, provider: DictValueProvider, template_path: Path) -> ConfigurationItemResolver:
    return create_template_resolver(token, provider, read_text(template_path))


def resolve_forms(resolver: ConfigurationResolver, path: Path) -> list[bytes]:
    """The template resolved as .NET's ResolveChars (a ``str``) and ResolveBytes (the file's bytes) resolve it."""
    resolved = []
    for source in (read_text(path), path.read_bytes()):
        destination = bytearray(BUFFER_LENGTH)
        written = resolver.resolve(source, destination)
        resolved.append(bytes(destination[:written]))
    return resolved


def load_json(resolved: bytes) -> Any:
    """The port of TemplateFile.LoadJson. ``json.loads`` skips a UTF-8 byte order mark in bytes, as .NET's JSON loader does."""
    return json.loads(resolved)


def test_resolved_template_loads_as_configuration(tmp_path: Path) -> None:
    template_path = write_text(tmp_path, "appsettings.template.json", TEMPLATE)
    resolver = create_resolver(DefaultToken(), create_provider(), template_path)

    for resolved in resolve_forms(resolver, template_path):
        configuration = load_json(resolved)

        assert configuration["ConnectionStrings"]["Default"] == 'Host=db.internal;Port=5432;Password=s3cr"t!'
        assert configuration["Greeting"] == f"{GREETING} {WORLD}"
        assert configuration["Literal"] == "${} and $ {not an item}"


def test_reader_lists_the_keys_in_the_template_file(tmp_path: Path) -> None:
    template_path = write_text(tmp_path, "appsettings.template.json", TEMPLATE)
    reader = ConfigurationItemReader(DefaultToken())
    expected = ["Database:Host", "Database:Port", "Database:Password", "Greeting"]

    with template_path.open("rb") as stream:
        assert reader.read_keys_from(stream) == expected

    assert reader.keys() == expected
    assert reader.read_keys(template_path.read_bytes()) == expected


def test_custom_token_resolves_only_its_own_items(tmp_path: Path) -> None:
    template_path = write_text(tmp_path, "custom.template.json", '{ "Host": "{{Database:Host}}", "Kept": "${Database:Host}" }')
    resolver = create_resolver(CustomToken("{{", "}}"), create_provider(), template_path)

    for resolved in resolve_forms(resolver, template_path):
        configuration = load_json(resolved)

        assert configuration["Host"] == "db.internal"
        assert configuration["Kept"] == "${Database:Host}"


def test_template_with_byte_order_mark_resolves_and_loads(tmp_path: Path) -> None:
    template_path = write_text(tmp_path, "bom.template.json", '{ "Host": "${Database:Host}" }', byte_order_mark=True)
    resolver = create_resolver(DefaultToken(), create_provider(), template_path)
    destination = bytearray(BUFFER_LENGTH)

    written = resolver.resolve(template_path.read_bytes(), destination)

    # The byte order mark is copied like any other text; the JSON loader skips it.
    resolved = bytes(destination[:written])
    assert resolved.startswith(codecs.BOM_UTF8)
    assert load_json(resolved)["Host"] == "db.internal"


def test_template_with_missing_value_throws(tmp_path: Path) -> None:
    template = '{ "Value": "${Database:Missing}" }'
    template_path = write_text(tmp_path, "missing.template.json", template)
    resolver = create_resolver(DefaultToken(), create_provider(), template_path)

    for source in (read_text(template_path), template_path.read_bytes()):
        with pytest.raises(ConfigurationKeyError) as error:
            resolver.resolve(source, bytearray(BUFFER_LENGTH))

        assert error.value.key == "Database:Missing"
        assert error.value.error is ConfigurationKeyErrorCode.NOT_FOUND
        assert error.value.source_index == template.index("${")


def test_destination_too_small_for_a_value_throws_and_clears_the_secret() -> None:
    template = "${Database:Password}${Database:Password}"
    resolver = create_template_resolver(DefaultToken(), create_provider(), template)

    for source in (template, template.encode()):
        destination = filled(len('s3cr"t!') + 3)

        with pytest.raises(DestinationTooSmallError):
            resolver.resolve(source, destination)

        assert_zeroed(destination)


def test_destination_too_small_for_the_template_text_throws_and_clears_the_destination(tmp_path: Path) -> None:
    template = read_text(write_text(tmp_path, "small.template.json", TEMPLATE))
    resolver = create_template_resolver(DefaultToken(), create_provider(), template)

    for source in (template, template.encode()):
        destination = filled(template.index("${") - 1)

        with pytest.raises(DestinationTooSmallError):
            resolver.resolve(source, destination)

        assert_zeroed(destination)


def test_template_using_a_key_outside_the_trusted_template_is_rejected(tmp_path: Path) -> None:
    # The trusted template only asks for the host; a substituted template also asks for the password.
    trusted_path = write_text(tmp_path, "trusted.template.json", '{ "Host": "${Database:Host}" }')
    injected_path = write_text(tmp_path, "injected.template.json", '{ "Host": "${Database:Host}", "Leak": "${Database:Password}" }')
    resolver = create_resolver(DefaultToken(), create_provider(), trusted_path)

    for resolved in resolve_forms(resolver, trusted_path):
        assert load_json(resolved)["Host"] == "db.internal"

    leak_index = read_text(injected_path).index("${Database:Password}")
    for source in (read_text(injected_path), injected_path.read_bytes()):
        destination = filled(BUFFER_LENGTH)

        with pytest.raises(ConfigurationKeyError) as error:
            resolver.resolve(source, destination)

        assert error.value.key == "Database:Password"
        assert error.value.error is ConfigurationKeyErrorCode.NOT_ALLOWED
        assert error.value.source_index == leak_index
        assert "Database:Password" not in str(error.value)
        assert_zeroed(destination)


def test_ignore_unresolvable_placeholders_leaves_missing_items_in_the_loaded_configuration(tmp_path: Path) -> None:
    template_path = write_text(tmp_path, "optional.template.json", '{ "Host": "${Database:Host}", "Optional": "${ Feature:Flag }" }')
    reader = ConfigurationItemReader(DefaultToken())
    reader.read_keys(template_path.read_bytes())
    resolver = ConfigurationItemResolver(DefaultToken(), reader, create_provider(), ignore_unresolvable_placeholders=True)

    for resolved in resolve_forms(resolver, template_path):
        configuration = load_json(resolved)

        assert configuration["Host"] == "db.internal"
        assert configuration["Optional"] == "${ Feature:Flag }"


def test_unterminated_item_in_json_runs_to_the_next_closing_brace(tmp_path: Path) -> None:
    # JSON's own closing brace ends the item, so the key includes the JSON that follows it.
    template = '{ "Value": "${unterminated" }'
    template_path = write_text(tmp_path, "unterminated.template.json", template)
    resolver = create_resolver(DefaultToken(), create_provider(), template_path)

    for source in (read_text(template_path), template_path.read_bytes()):
        with pytest.raises(ConfigurationKeyError) as error:
            resolver.resolve(source, bytearray(BUFFER_LENGTH))

        assert error.value.key == 'unterminated"'
        assert error.value.error is ConfigurationKeyErrorCode.NOT_FOUND
        assert error.value.source_index == template.index("${")


def test_value_that_breaks_json_produces_invalid_configuration(tmp_path: Path) -> None:
    # Values are inserted as they are; the resolver does not escape them for JSON.
    template_path = write_text(tmp_path, "quote.template.json", '{ "Value": "${Quote}" }')
    resolver = create_resolver(DefaultToken(), DictValueProvider({"Quote": 'a"b'}), template_path)

    for resolved in resolve_forms(resolver, template_path):
        assert resolved == b'{ "Value": "a"b" }'
        with pytest.raises(json.JSONDecodeError):
            load_json(resolved)
