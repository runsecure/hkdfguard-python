"""The port of .NET's ReaderAndTokenScenarioTests, with tests of what .NET's decoding gives a key
(as the Go and Java ports have): a byte order mark selecting a stream's encoding, invalid UTF-8
replaced per maximal subpart, and trimming of exactly .NET's whitespace.
"""

from __future__ import annotations

import codecs
import io

import pytest
from configurationresolver_core_test_support import (
    CAFE,
    REPLACEMENT,
    CustomToken,
    DictValueProvider,
    ReadingResolver,
    resolve_to_str,
)
from hkdfguard.integration.configurationresolver import ConfigurationItemReader, ConfigurationItemTokenBase, DefaultToken

TEXT = "this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}"


def new_reader() -> ConfigurationItemReader:
    return ConfigurationItemReader(DefaultToken())


def test_read_keys_from_str_bytes_and_stream_return_the_same_keys() -> None:
    reader = new_reader()
    expected = ["value 1", "value2", "value3"]
    encoded = TEXT.encode()

    assert reader.read_keys(TEXT) == expected
    assert reader.read_keys(encoded) == expected
    assert reader.read_keys(bytearray(encoded)) == expected
    assert reader.read_keys(memoryview(encoded)) == expected
    assert reader.read_keys_from(io.BytesIO(encoded)) == expected


def test_read_keys_stream_with_explicit_encoding_decodes_with_it() -> None:
    stream = io.BytesIO(f"${{ {CAFE} }}".encode("latin-1"))

    assert new_reader().read_keys_from(stream, "latin-1") == [CAFE]


def test_read_keys_stream_is_read_from_its_position_and_left_open() -> None:
    stream = io.BytesIO(b"${skipped} ${read}")
    stream.seek(len("${skipped} "))

    assert new_reader().read_keys_from(stream) == ["read"]
    assert not stream.closed


GRINNING_FACE = chr(0x1F600)
BOM_TEXT = f"${{ {CAFE} {GRINNING_FACE} }}"
BOM_KEY = f"{CAFE} {GRINNING_FACE}"


@pytest.mark.parametrize(
    ("data", "encoding", "expected"),
    [
        pytest.param(BOM_TEXT.encode(), None, [BOM_KEY], id="no BOM"),
        pytest.param(codecs.BOM_UTF8 + BOM_TEXT.encode(), None, [BOM_KEY], id="UTF-8"),
        pytest.param(codecs.BOM_UTF16_LE + BOM_TEXT.encode("utf-16-le"), None, [BOM_KEY], id="UTF-16LE"),
        pytest.param(codecs.BOM_UTF16_BE + BOM_TEXT.encode("utf-16-be"), None, [BOM_KEY], id="UTF-16BE"),
        pytest.param(codecs.BOM_UTF32_LE + BOM_TEXT.encode("utf-32-le"), None, [BOM_KEY], id="UTF-32LE"),
        pytest.param(codecs.BOM_UTF32_BE + BOM_TEXT.encode("utf-32-be"), None, [BOM_KEY], id="UTF-32BE"),
        pytest.param(codecs.BOM_UTF8 + BOM_TEXT.encode(), "latin-1", [BOM_KEY], id="BOM over explicit encoding"),
        pytest.param(codecs.BOM_UTF8, None, [], id="only BOM"),
        pytest.param(b"", None, [], id="empty"),
        # Not UTF-8 and no BOM: read as UTF-8, so the e with acute (0xE9) becomes U+FFFD.
        pytest.param(b"${ caf\xe9 }", None, ["caf" + REPLACEMENT], id="latin-1 without encoding"),
        pytest.param(b"\xef\xbb", None, [], id="short BOM"),
    ],
)
def test_read_keys_from_byte_order_mark_selects_the_encoding(data: bytes, encoding: str | None, expected: list[str]) -> None:
    # .NET's StreamReader defaults to UTF-8 and lets a byte order mark select the encoding.
    assert new_reader().read_keys_from(io.BytesIO(data), encoding) == expected


@pytest.mark.parametrize(
    ("text", "key"),
    [
        (b"${a\xffb}", f"a{REPLACEMENT}b"),
        (b"${a\xe0\x80b}", f"a{REPLACEMENT}{REPLACEMENT}b"),  # E0 must be followed by A0-BF
        (b"${a\xf0\x9f\x98b}", f"a{REPLACEMENT}b"),  # a truncated four-byte sequence
        (b"${\xed\xa0\x80}", REPLACEMENT * 3),  # an encoded surrogate
        (b"${a\xc0\xafb}", f"a{REPLACEMENT}{REPLACEMENT}b"),  # an overlong encoding
        (b"${a\xe2\x82}", f"a{REPLACEMENT}"),  # truncated at the end of the item
    ],
)
def test_read_keys_invalid_utf8_is_replaced_per_maximal_subpart(text: bytes, key: str) -> None:
    # As .NET's UTF-8 decoder does: each maximal ill-formed subsequence becomes one U+FFFD.
    assert new_reader().read_keys(text) == [key]


def test_resolve_invalid_utf8_key_is_the_readers_key() -> None:
    resolver = ReadingResolver(DefaultToken(), DictValueProvider({f"a{REPLACEMENT}b": "value"}))

    assert resolve_to_str(resolver, b"[${ a\xffb }]") == "[value]"


@pytest.mark.parametrize(
    ("text", "keys"),
    [
        pytest.param(f"${{{chr(0x00A0)}Name{chr(0x3000)}}}", ["Name"], id="no-break and ideographic space"),
        pytest.param(f"${{{chr(0x0085)}{chr(0x2028)}Name{chr(0x2029)}\v\f\r}}", ["Name"], id="next line and separators"),
        pytest.param(f"${{{chr(0x1680)}{chr(0x2000)}{chr(0x200A)}{chr(0x202F)}{chr(0x205F)}Name}}", ["Name"], id="Zs spaces"),
        pytest.param(f"${{{chr(0x200B)}Name}}", [chr(0x200B) + "Name"], id="zero width space is not whitespace"),
        pytest.param(f"${{{chr(0x00A0)}{chr(0x2003)}}}", [], id="only whitespace"),
        # Python's str.isspace counts the information separators U+001C-U+001F; .NET's Trim keeps them.
        pytest.param(f"${{{chr(0x001C)}Name{chr(0x001F)}}}", [chr(0x001C) + "Name" + chr(0x001F)], id="information separators are kept"),
    ],
)
def test_read_keys_trims_exactly_dotnets_whitespace(text: str, keys: list[str]) -> None:
    assert new_reader().read_keys(text) == keys


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", []),
        ("no items", []),
        ("${} ${ } ${a}", ["a"]),
        ("${a} ${unterminated", ["a"]),
        ("${a}${b}", ["a", "b"]),
        ("$${a} ${b} $${", ["b"]),
        ("$$${a} $${b ${c}}", ["c"]),
    ],
)
def test_read_keys_skips_empty_unterminated_and_escaped_items(text: str, expected: list[str]) -> None:
    assert new_reader().read_keys(text) == expected


def test_keys_returns_the_most_recent_read() -> None:
    reader = new_reader()
    assert reader.keys() == []

    reader.read_keys("${first}")
    reader.read_keys("${second}")

    assert reader.keys() == ["second"]


def test_read_keys_with_custom_token_uses_its_sequences() -> None:
    reader = ConfigurationItemReader(CustomToken("{{", "}}"))

    assert reader.read_keys("{{a}} ${b}") == ["a"]


def test_read_keys_with_custom_escape_sequence_skips_only_its_escaped_items() -> None:
    with_escape = ConfigurationItemReader(CustomToken("{{", "}}", "\\"))
    without_escape = ConfigurationItemReader(CustomToken("{{", "}}"))

    assert with_escape.read_keys(r"\{{a}} ${{b}}") == ["b"]
    assert without_escape.read_keys(r"\{{a}} ${{b}}") == ["a", "b"]


def test_read_keys_from_several_texts_keeps_the_keys_of_all_of_them() -> None:
    reader = new_reader()
    reader.read_keys("${old}")

    keys = reader.read_keys_all(["${a} ${b}", "", "${c", "}${d}", "${a}"])

    assert keys == ["a", "b", "d", "a"]
    assert reader.keys() == keys


def test_read_keys_from_several_texts_null_arguments_throw() -> None:
    reader = new_reader()

    with pytest.raises(TypeError):
        reader.read_keys_all(None)  # type: ignore[arg-type]
    # .NET throws ArgumentException for a null text; Python reports a None with TypeError.
    with pytest.raises(TypeError):
        reader.read_keys_all(["${a}", None])  # type: ignore[list-item]
    # A single str is iterable, but is not several texts.
    with pytest.raises(TypeError):
        reader.read_keys_all("${a}")


def test_reader_null_arguments_throw() -> None:
    with pytest.raises(TypeError):
        ConfigurationItemReader(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        new_reader().read_keys_from(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        new_reader().read_keys(None)  # type: ignore[arg-type]


def test_token_defaults_and_overrides() -> None:
    defaults = DefaultToken()
    custom = CustomToken("<%", "%>")

    assert defaults.start_sequence == ConfigurationItemTokenBase.DEFAULT_START_SEQUENCE == "${"
    assert defaults.end_sequence == ConfigurationItemTokenBase.DEFAULT_END_SEQUENCE == "}"
    assert defaults.escape_sequence == ConfigurationItemTokenBase.DEFAULT_ESCAPE_SEQUENCE == "$"
    assert custom.start_sequence == "<%"
    assert custom.end_sequence == "%>"
    assert custom.escape_sequence is None


def test_token_empty_escape_sequence_throws() -> None:
    with pytest.raises(ValueError, match="escape_sequence"):
        CustomToken("${", "}", "")


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (None, "}", TypeError),
        ("", "}", ValueError),
        ("${", None, TypeError),
        ("${", "", ValueError),
    ],
)
def test_token_null_or_empty_sequence_throws(start: str | None, end: str | None, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        CustomToken(start, end)  # type: ignore[arg-type]
