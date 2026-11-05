"""The port of .NET's ConfigurationItemResolverTests.

.NET resolves chars and UTF-8 bytes; Python resolves a ``str`` or UTF-8 bytes into UTF-8 bytes,
so each char/byte pair of tests is one test here that resolves the source in both forms, and a
source index is always a byte index into the UTF-8 source.
"""

from __future__ import annotations

import pytest
from configurationresolver_core_test_support import (
    CAFE,
    CHECK_MARK,
    E_ACUTE,
    I_DIAERESIS,
    LEFT_GUILLEMET,
    RIGHT_GUILLEMET,
    U_DIAERESIS,
    CustomToken,
    DictValueProvider,
    ReadingResolver,
    SpyValueProvider,
    assert_key_error,
    assert_zeroed,
    both,
    filled,
    resolve_to_str,
)
from hkdfguard.integration.configurationresolver import (
    ConfigurationItemReader,
    ConfigurationItemResolver,
    ConfigurationKeyError,
    ConfigurationKeyErrorCode,
    ConfigurationResolver,
    DefaultToken,
    DestinationTooSmallError,
)

VALUES = {
    "Name": "Ada",
    "value 1": "ONE",
    "value2": "TWO",
    "value3": "THREE",
    "Db:Password": "p@ss",
    "Empty": "",
    "Unicode": CAFE,
}

NESTED = {
    "Url": "https://${Host}:${Port}/",
    "Host": "${Region}.db.internal",
    "Region": "eu",
    "Port": "5432",
    "Self": "a${Self}",
    "Ping": "${Pong}",
    "Pong": "${Ping}",
    "Escaped": "$${Region}",
    "Missing": "[${ Nope }]",
    "Shrinks": "${Region}!",
}

NESTED_KEYS = tuple(NESTED.values())

RESOLVED_TEXT = [
    ("", ""),
    ("plain text", "plain text"),
    ("${Name}", "Ada"),
    ("Hello ${Name}!", "Hello Ada!"),
    ("${ Name }", "Ada"),
    ("${\tName\n}", "Ada"),
    ("${Name}${Name}", "AdaAda"),
    ("${Db:Password}", "p@ss"),
    ("[${Empty}]", "[]"),
    (f"{U_DIAERESIS}n{I_DIAERESIS} ${{Unicode}} {CHECK_MARK}", f"{U_DIAERESIS}n{I_DIAERESIS} {CAFE} {CHECK_MARK}"),
    (
        "this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}",
        "this is my ONE, and this is TWO and lastly this is THREE",
    ),
]

UNCHANGED_TEXT = [
    "${}",
    "${ }",
    "start ${Name",
    "} stray end }",
    "$ {Name} $Name {Name}",
]

PARTIALLY_RESOLVED_TEXT = [
    ("${Name}} extra", "Ada} extra"),
    ("${Name} then ${unterminated", "Ada then ${unterminated"),
    ("${} then ${Name}", "${} then Ada"),
]


def new_resolver() -> ReadingResolver:
    return ReadingResolver(DefaultToken(), DictValueProvider(VALUES))


def create_nested(depth: int) -> ReadingResolver:
    return ReadingResolver(DefaultToken(), DictValueProvider(NESTED), max_resolution_depth=depth, also_allowed=NESTED_KEYS)


def create_allow_listed() -> tuple[ConfigurationItemReader, ConfigurationItemResolver, SpyValueProvider]:
    reader = ConfigurationItemReader(DefaultToken())
    spy = SpyValueProvider(VALUES)
    return reader, ConfigurationItemResolver(DefaultToken(), reader, spy), spy


def assert_resolves(resolver: ConfigurationResolver, source: str, expected: str) -> None:
    for form in both(source):
        assert resolve_to_str(resolver, form) == expected


@pytest.mark.parametrize(("source", "expected"), RESOLVED_TEXT + PARTIALLY_RESOLVED_TEXT)
def test_resolve_replaces_items(source: str, expected: str) -> None:
    assert_resolves(new_resolver(), source, expected)


@pytest.mark.parametrize("source", UNCHANGED_TEXT)
def test_resolve_copies_text_without_complete_items_unchanged(source: str) -> None:
    assert_resolves(new_resolver(), source, source)


@pytest.mark.parametrize(
    ("source", "destination_length", "expected"),
    [
        ("x=${Name}", 16, b"x=Ada" + b"#" * 11),
        ("${Unicode}", 8, CAFE.encode() + b"###"),
    ],
)
def test_resolve_returns_count_and_leaves_rest_of_destination_untouched(source: str, destination_length: int, expected: bytes) -> None:
    for form in both(source):
        destination = filled(destination_length)

        written = new_resolver().resolve(form, destination)

        assert written == 5
        assert destination == expected


@pytest.mark.parametrize(
    ("source", "destination_length", "expected"),
    [
        ("x=${Name}", 5, "x=Ada"),
        # The acute e is 1 character but 2 UTF-8 bytes.
        ("x=${Unicode}", 7, "x=" + CAFE),
    ],
)
def test_resolve_succeeds_when_destination_is_exactly_the_resolved_length(source: str, destination_length: int, expected: str) -> None:
    for form in both(source):
        assert resolve_to_str(new_resolver(), form, destination_length) == expected


def test_resolve_empty_source_into_empty_destination_writes_nothing() -> None:
    resolver = new_resolver()

    assert resolver.resolve("", bytearray()) == 0
    assert resolver.resolve(b"", bytearray()) == 0


@pytest.mark.parametrize(
    ("start", "end", "source", "expected"),
    [
        ("{{", "}}", "{{Name}} and ${Name}", "Ada and ${Name}"),
        ("{{", "}}", "{{ Name }}{{Name}", "Ada{{Name}"),
        ("<%", "%>", "<%Db:Password%>", "p@ss"),
        (LEFT_GUILLEMET, RIGHT_GUILLEMET, f"{LEFT_GUILLEMET} Unicode {RIGHT_GUILLEMET} and {LEFT_GUILLEMET}Name{RIGHT_GUILLEMET}", f"{CAFE} and Ada"),
    ],
)
def test_resolve_uses_the_tokens_start_and_end_sequences(start: str, end: str, source: str, expected: str) -> None:
    resolver = ReadingResolver(CustomToken(start, end), DictValueProvider(VALUES))

    assert_resolves(resolver, source, expected)


@pytest.mark.parametrize(
    ("source", "expected", "keys", "buffer_lengths"),
    [
        ("ab-${Name}-${value2}", "ab-Ada-TWO", ["Name", "value2"], [32 - 3, 32 - 7]),
        # The u with diaeresis is 2 UTF-8 bytes, so the value is written after 3 bytes.
        (f"{U_DIAERESIS}-${{Unicode}}", f"{U_DIAERESIS}-{CAFE}", ["Unicode"], [32 - 3]),
    ],
)
def test_resolve_writes_values_directly_into_the_destination(source: str, expected: str, keys: list[str], buffer_lengths: list[int]) -> None:
    for form in both(source):
        spy = SpyValueProvider(VALUES)
        resolver = ReadingResolver(DefaultToken(), spy)

        assert resolve_to_str(resolver, form, destination_length=32) == expected

        assert spy.try_get_bytes_calls == keys
        assert spy.buffer_lengths == buffer_lengths
        assert spy.try_get_value_calls == []


@pytest.mark.parametrize(
    ("source", "failing_key", "destination_length"),
    [
        ("${Name} ${missing}", "missing", 64),
        ("${Name} ${value2}", "value2", 5),
    ],
)
def test_resolve_never_reads_values_as_strings_even_when_it_fails(source: str, failing_key: str, destination_length: int) -> None:
    for form in both(source):
        spy = SpyValueProvider(VALUES)
        resolver = ReadingResolver(DefaultToken(), spy)

        with pytest.raises((ConfigurationKeyError, DestinationTooSmallError)):
            resolve_to_str(resolver, form, destination_length)

        assert spy.try_get_bytes_calls == ["Name", failing_key]
        assert spy.try_get_value_calls == []


def test_constructor_null_token_throws() -> None:
    with pytest.raises(TypeError, match="token"):
        ConfigurationItemResolver(None, ConfigurationItemReader(DefaultToken()), DictValueProvider(VALUES))  # type: ignore[arg-type]


def test_constructor_null_reader_throws() -> None:
    with pytest.raises(TypeError, match="reader"):
        ConfigurationItemResolver(DefaultToken(), None, DictValueProvider(VALUES))  # type: ignore[arg-type]


def test_constructor_null_value_provider_throws() -> None:
    with pytest.raises(TypeError, match="value providers"):
        ConfigurationItemResolver(DefaultToken(), ConfigurationItemReader(DefaultToken()), None)  # type: ignore[arg-type]


def test_constructor_no_value_providers_throws() -> None:
    with pytest.raises(ValueError, match="value provider"):
        ConfigurationItemResolver(DefaultToken(), ConfigurationItemReader(DefaultToken()))


def test_constructor_null_among_value_providers_throws() -> None:
    # .NET throws ArgumentException; Python reports a None, wherever it is, with TypeError.
    with pytest.raises(TypeError, match="value providers"):
        ConfigurationItemResolver(DefaultToken(), ConfigurationItemReader(DefaultToken()), DictValueProvider(VALUES), None)  # type: ignore[arg-type]


def test_resolve_multiple_providers_uses_the_first_provider_that_has_the_key() -> None:
    for form in both("${Name} ${Db:Password}"):
        high = SpyValueProvider({"Name": "Grace"})
        low = SpyValueProvider(VALUES)
        resolver = ReadingResolver(DefaultToken(), high, low)

        assert resolve_to_str(resolver, form) == "Grace p@ss"

        assert high.try_get_bytes_calls == ["Name", "Db:Password"]
        assert low.try_get_bytes_calls == ["Db:Password"]


def test_resolve_multiple_providers_none_has_the_key_throws_not_found() -> None:
    resolver = ReadingResolver(DefaultToken(), DictValueProvider({"Name": "Grace"}), DictValueProvider(VALUES))

    for form in both("${Name} ${missing}"):
        with pytest.raises(ConfigurationKeyError) as error:
            resolve_to_str(resolver, form)

        assert_key_error(error.value, "missing", ConfigurationKeyErrorCode.NOT_FOUND, 8)


def test_resolve_multiple_providers_value_too_large_in_the_first_provider_does_not_fall_through() -> None:
    high = DictValueProvider({"Name": "Grace Hopper"})
    low = SpyValueProvider(VALUES)
    resolver = ReadingResolver(DefaultToken(), high, low)

    for form in both("${Name}"):
        with pytest.raises(DestinationTooSmallError):
            resolve_to_str(resolver, form, destination_length=5)

    assert low.try_get_bytes_calls == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("${missing}", "${missing}"),
        ("a ${ missing } b ${Name}", "a ${ missing } b Ada"),
        ("${Name}${missing}${Name}", "Ada${missing}Ada"),
        (f"{E_ACUTE} ${{missing}} ${{Unicode}}", f"{E_ACUTE} ${{missing}} {CAFE}"),
    ],
)
def test_resolve_ignore_unresolvable_placeholders_copies_missing_items_unchanged(source: str, expected: str) -> None:
    resolver = ReadingResolver(DefaultToken(), DictValueProvider(VALUES), ignore_unresolvable_placeholders=True)

    assert_resolves(resolver, source, expected)


def test_resolve_ignore_unresolvable_placeholders_copies_the_tokens_own_sequences() -> None:
    resolver = ReadingResolver(CustomToken("{{", "}}"), DictValueProvider(VALUES), ignore_unresolvable_placeholders=True)

    assert_resolves(resolver, "{{Name}} {{ missing }}", "Ada {{ missing }}")


def test_resolve_ignore_unresolvable_placeholders_key_not_read_by_the_reader_still_throws() -> None:
    reader = ConfigurationItemReader(DefaultToken())
    spy = SpyValueProvider(VALUES)
    resolver = ConfigurationItemResolver(DefaultToken(), reader, spy, ignore_unresolvable_placeholders=True)
    reader.read_keys("${Name}")

    with pytest.raises(ConfigurationKeyError) as error:
        resolve_to_str(resolver, "${Name} ${Db:Password}")

    assert_key_error(error.value, "Db:Password", ConfigurationKeyErrorCode.NOT_ALLOWED, 8)
    assert spy.try_get_bytes_calls == ["Name"]


def test_resolve_ignore_unresolvable_placeholders_provider_error_still_propagates() -> None:
    spy = SpyValueProvider(VALUES, throw_on_lookup=ConfigurationKeyError("Name", ConfigurationKeyErrorCode.VALUE_UNSTABLE))
    resolver = ReadingResolver(DefaultToken(), spy, ignore_unresolvable_placeholders=True)

    with pytest.raises(ConfigurationKeyError) as error:
        resolve_to_str(resolver, "${Name}")

    assert error.value.error is ConfigurationKeyErrorCode.VALUE_UNSTABLE


@pytest.mark.parametrize("destination_length", [9, 13])
def test_resolve_ignore_unresolvable_placeholders_destination_too_small_for_the_item_throws_and_clears_destination(destination_length: int) -> None:
    resolver = ReadingResolver(DefaultToken(), DictValueProvider(VALUES), ignore_unresolvable_placeholders=True)

    for form in both("Ada ${missing}"):
        destination = filled(destination_length)

        with pytest.raises(DestinationTooSmallError):
            resolver.resolve(form, destination)

        assert_zeroed(destination)


def test_resolve_ignore_unresolvable_placeholders_is_off_by_default() -> None:
    resolver = ConfigurationItemResolver(DefaultToken(), ConfigurationItemReader(DefaultToken()), DictValueProvider(VALUES))

    assert resolver.ignore_unresolvable_placeholders is False


def test_resolve_keys_read_from_a_trusted_template_are_resolved_in_another_source() -> None:
    reader, resolver, _ = create_allow_listed()
    reader.read_keys("${Name} ${ Db:Password }")

    assert_resolves(resolver, "${Db:Password} for ${Name}", "p@ss for Ada")


@pytest.mark.parametrize(
    ("source", "rejected_key", "source_index"),
    [
        ("${Db:Password}", "Db:Password", 0),
        ("${Name} then ${Db:Password}", "Db:Password", 13),
        ("${name}", "name", 0),
        # The u with diaeresis is 2 UTF-8 bytes: .NET's char index here is 2.
        (f"{U_DIAERESIS} ${{ Db:Password }}", "Db:Password", 3),
    ],
)
def test_resolve_key_not_read_by_the_reader_throws_without_asking_the_provider(source: str, rejected_key: str, source_index: int) -> None:
    reader, resolver, spy = create_allow_listed()
    reader.read_keys("${Name}")

    for form in both(source):
        destination = filled(64)

        with pytest.raises(ConfigurationKeyError) as error:
            resolver.resolve(form, destination)

        assert_key_error(error.value, rejected_key, ConfigurationKeyErrorCode.NOT_ALLOWED, source_index)
        assert rejected_key not in spy.try_get_bytes_calls
        assert_zeroed(destination)


def test_resolve_before_any_keys_are_read_resolves_only_text_without_items() -> None:
    _, resolver, spy = create_allow_listed()

    assert resolve_to_str(resolver, "plain ${} text") == "plain ${} text"
    with pytest.raises(ConfigurationKeyError):
        resolve_to_str(resolver, "${Name}")
    assert spy.try_get_bytes_calls == []


def test_resolve_uses_the_readers_most_recent_keys() -> None:
    reader, resolver, _ = create_allow_listed()
    reader.read_keys("${Name}")
    assert resolve_to_str(resolver, "${Name}") == "Ada"

    reader.read_keys("${value2}")

    assert resolve_to_str(resolver, "${value2}") == "TWO"
    with pytest.raises(ConfigurationKeyError):
        resolve_to_str(resolver, "${Name}")


@pytest.mark.parametrize(
    ("source", "missing_key", "source_index"),
    [
        ("${missing}", "missing", 0),
        ("${Name} then ${ missing }", "missing", 13),
        ("${name}", "name", 0),
        ("${a${Name}}", "a${Name", 0),
        # The acute e is 2 UTF-8 bytes: .NET's char index here is 2.
        (f"{E_ACUTE} ${{missing}}", "missing", 3),
    ],
)
def test_resolve_missing_key_throws_and_clears_destination(source: str, missing_key: str, source_index: int) -> None:
    for form in both(source):
        destination = filled(64)

        with pytest.raises(ConfigurationKeyError) as error:
            new_resolver().resolve(form, destination)

        assert_key_error(error.value, missing_key, ConfigurationKeyErrorCode.NOT_FOUND, source_index)
        assert_zeroed(destination)


@pytest.mark.parametrize(
    ("source", "destination_length"),
    [
        ("literal too long", 4),
        ("ab ${Name}", 2),
        ("ab ${Name}", 5),
        ("${Name} trailing text", 6),
        ("${Unicode}", 4),
        ("${Db:Password} ${Name}", 6),
        ("x", 0),
    ],
)
def test_resolve_destination_too_small_throws_and_clears_destination(source: str, destination_length: int) -> None:
    for form in both(source):
        destination = filled(destination_length)

        with pytest.raises(DestinationTooSmallError):
            new_resolver().resolve(form, destination)

        assert_zeroed(destination)


def test_resolve_provider_throws_propagates_and_clears_destination() -> None:
    spy = SpyValueProvider(VALUES, throw_on_lookup=RuntimeError("provider failed"))
    resolver = ReadingResolver(DefaultToken(), spy)

    for form in both("ab ${Name}"):
        destination = filled(16)

        with pytest.raises(RuntimeError, match="provider failed"):
            resolver.resolve(form, destination)

        assert_zeroed(destination)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("$${Name}", "${Name}"),
        ("$${", "${"),
        ("$${Name} is ${Name}", "${Name} is Ada"),
        ("$$${Name}", "$${Name}"),
        ("$${a ${Name}}", "${a Ada}"),
        ("$ ${Name} $$", "$ Ada $$"),
        (f"{E_ACUTE} $${{Unicode}}", f"{E_ACUTE} ${{Unicode}}"),
    ],
)
def test_resolve_escaped_start_sequence_is_copied_without_the_escape(source: str, expected: str) -> None:
    assert_resolves(new_resolver(), source, expected)


def test_resolve_escaped_item_is_not_a_key_so_it_needs_no_permission() -> None:
    reader, resolver, spy = create_allow_listed()
    reader.read_keys("${Name}")

    assert_resolves(resolver, "${Name} $${Db:Password}", "Ada ${Db:Password}")

    assert spy.try_get_bytes_calls == ["Name", "Name"]


@pytest.mark.parametrize(
    ("escape", "source", "expected"),
    [
        (None, "${{Name}} \\{{Name}}", "$Ada \\Ada"),
        ("\\", "${{Name}} \\{{Name}}", "$Ada {{Name}}"),
    ],
)
def test_resolve_uses_the_tokens_escape_sequence(escape: str | None, source: str, expected: str) -> None:
    resolver = ReadingResolver(CustomToken("{{", "}}", escape), DictValueProvider(VALUES))

    assert_resolves(resolver, source, expected)


def test_max_resolution_depth_defaults_to_one_and_must_be_positive() -> None:
    resolver = ConfigurationItemResolver(DefaultToken(), ConfigurationItemReader(DefaultToken()), DictValueProvider(VALUES))

    assert resolver.max_resolution_depth == 1
    with pytest.raises(ValueError, match="max_resolution_depth"):
        ConfigurationItemResolver(DefaultToken(), ConfigurationItemReader(DefaultToken()), DictValueProvider(VALUES), max_resolution_depth=0)


@pytest.mark.parametrize(
    ("depth", "source", "expected"),
    [
        (1, "${Url}", "https://${Host}:${Port}/"),
        (2, "${Url}", "https://${Region}.db.internal:5432/"),
        (3, "${Url}", "https://eu.db.internal:5432/"),
        (10, "go ${Url} now", "go https://eu.db.internal:5432/ now"),
        (1, "${Escaped}", "$${Region}"),
        (2, "${Escaped}", "${Region}"),
        (2, "${Ping}", "${Ping}"),
        (2, "${Port}${Host}", "5432eu.db.internal"),
    ],
)
def test_resolve_items_in_values_are_resolved_up_to_the_maximum_depth(depth: int, source: str, expected: str) -> None:
    assert_resolves(create_nested(depth), source, expected)


@pytest.mark.parametrize(
    ("depth", "source", "key", "source_index"),
    [
        (2, "${Self}", "Self", 0),
        (5, "x ${Self}", "Self", 2),
        (3, "${Ping}", "Ping", 0),
        (10, "ab ${Pong}", "Pong", 3),
    ],
)
def test_resolve_value_that_leads_back_to_its_key_throws_cycle_and_clears_destination(depth: int, source: str, key: str, source_index: int) -> None:
    resolver = create_nested(depth)

    for form in both(source):
        destination = filled(256)

        with pytest.raises(ConfigurationKeyError) as error:
            resolver.resolve(form, destination)

        assert_key_error(error.value, key, ConfigurationKeyErrorCode.CYCLE, source_index)
        assert_zeroed(destination)


def test_resolve_key_in_a_value_must_be_allowed() -> None:
    spy = SpyValueProvider(NESTED)
    resolver = ReadingResolver(DefaultToken(), spy, max_resolution_depth=3)

    with pytest.raises(ConfigurationKeyError) as error:
        resolve_to_str(resolver, "go ${Host}")

    assert_key_error(error.value, "Region", ConfigurationKeyErrorCode.NOT_ALLOWED, 3)
    assert spy.try_get_bytes_calls == ["Host"]


def test_resolve_missing_key_in_a_value_throws_with_the_source_items_index_or_is_kept_when_ignored() -> None:
    strict = create_nested(2)
    lenient = ReadingResolver(
        DefaultToken(),
        DictValueProvider(NESTED),
        max_resolution_depth=2,
        ignore_unresolvable_placeholders=True,
        also_allowed=NESTED_KEYS,
    )
    source = f"{E_ACUTE} ${{Missing}}"

    with pytest.raises(ConfigurationKeyError) as error:
        resolve_to_str(strict, source.encode())

    assert_key_error(error.value, "Nope", ConfigurationKeyErrorCode.NOT_FOUND, 3)
    assert_resolves(lenient, source, f"{E_ACUTE} [${{ Nope }}]")


def test_resolve_value_that_shrinks_when_resolved_leaves_no_trace_of_the_raw_value() -> None:
    resolver = create_nested(2)
    raw_length = len("${Region}!")

    for form in both("${Shrinks}"):
        destination = filled(64)

        written = resolver.resolve(form, destination)

        assert destination[:written] == b"eu!"
        assert b"Region" not in destination
        # The raw value was written, then zeroed, then overwritten by the resolved one.
        assert destination[written:raw_length] == bytes(raw_length - written)
        assert destination[raw_length:] == b"#" * (64 - raw_length)


def test_resolve_items_in_values_are_written_without_reading_values_as_strings() -> None:
    spy = SpyValueProvider(NESTED)
    resolver = ReadingResolver(DefaultToken(), spy, max_resolution_depth=3, also_allowed=NESTED_KEYS)

    assert resolve_to_str(resolver, "${Url}") == "https://eu.db.internal:5432/"

    assert spy.try_get_bytes_calls == ["Url", "Host", "Region", "Port"]
    assert spy.try_get_value_calls == []
