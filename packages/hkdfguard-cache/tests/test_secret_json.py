from __future__ import annotations

import base64
import io
import os
from collections.abc import Buffer, Callable, Iterator

import pytest
from hkdfguard.abstractions import JsonReader, JsonToken, KeyRing, KeyWrapper, MalformedJsonError, WritableBuffer
from hkdfguard.cache import ErrorResponseBody, InvalidSecretDataError, RemoteSecretCache, SecretJsonBody, SecretNameMatching, SecretValueSink
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing

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


@pytest.fixture
def ring() -> Iterator[DefaultKeyRing]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
        yield ring


class SinkCache(RemoteSecretCache):
    """A RemoteSecretCache whose every fetch is on_fetch, as a provider's capture would be."""

    def __init__(self, ring: KeyRing) -> None:
        super().__init__(ring, SecretNameMatching.EXACT)
        self.on_fetch: Callable[[str, SecretValueSink], object] | None = None

    def _is_valid_name(self, name: str) -> bool:
        return bool(name)

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        if self.on_fetch is not None:
            self.on_fetch(name, value)


def decrypt_bytes(cache: RemoteSecretCache, name: str) -> bytes:
    result = bytearray(256)
    return bytes(result[: cache.decrypt(name, result)])


def utf8(text: str) -> bytes:
    return text.encode()


class FailingStream(io.RawIOBase):
    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Buffer) -> int:
        raise OSError("connection reset")


# --- JsonReader -------------------------------------------------------------------------------


def tokens(json: str) -> list[JsonToken | None]:
    reader = JsonReader(utf8(json))
    found = []
    while reader.read():
        found.append(reader.token())
    return found


def test_every_kind_of_token_is_read() -> None:
    assert tokens(' {"a" : [ "s", -0.5e+10, true, false, null, {}, [] ] }\r\n\t') == [
        JsonToken.START_OBJECT, JsonToken.PROPERTY_NAME, JsonToken.START_ARRAY, JsonToken.STRING, JsonToken.NUMBER, JsonToken.TRUE,
        JsonToken.FALSE, JsonToken.NULL, JsonToken.START_OBJECT, JsonToken.END_OBJECT, JsonToken.START_ARRAY, JsonToken.END_ARRAY,
        JsonToken.END_ARRAY, JsonToken.END_OBJECT]


@pytest.mark.parametrize("json", ["0", "-0", "12", "1.25", "1e5", "1E-5", "-12.5e+3", '"text"', "true", "null", "[]", "{}"])
def test_any_value_can_be_the_root(json: str) -> None:
    assert len(tokens(json)) == (2 if json[0] in "[{" else 1)


def test_empty_or_whitespace_input_has_no_tokens() -> None:
    assert tokens("") == []
    assert tokens(" \n ") == []


@pytest.mark.parametrize("json", [
    "01", "-", "1.", "1.e5", "1e", "1e+", ".5", "+1", "1x", "tru", "trUe", "nul", "falsy",
    "{", "[", '{"a"', '{"a":', '{"a" 1}', '{"a":1,}', "[1,]", "[1 2]", '{"a":1 "b":2}', "{1:2}", "{,}", "[,1]",
    '"unterminated', '"bad \\x escape"', '"\\u12"', '"\\u12G4"', '"\\udc00"', '"\\ud800"', '"\\ud800\\u0041"',
    '"\\ud800x"', '"tab\there"', "1 2", "{} {}", "]", "}", "/* comment */ 1", '{"a":1}/',
])
def test_malformed_json_is_refused(json: str) -> None:
    with pytest.raises(MalformedJsonError):
        tokens(json)


def test_nesting_deeper_than_the_limit_is_refused_and_to_it_is_not() -> None:
    depth = JsonReader.MAX_DEPTH
    assert len(tokens("[" * depth + "]" * depth)) == 2 * depth
    with pytest.raises(MalformedJsonError):
        tokens("[" * (depth + 1) + "]" * (depth + 1))


def test_an_error_is_placed_by_line_and_position_in_it() -> None:
    with pytest.raises(MalformedJsonError) as error:
        tokens('{\n"a":\n  x}')

    assert (error.value.line, error.value.position) == (2, 2)
    assert "x" not in str(error.value)


def test_skip_passes_over_a_containers_children_and_nothing_else() -> None:
    reader = JsonReader(utf8('{"a":{"b":[1,{"c":2}]},"d":3}'))
    reader.read()
    reader.read()
    reader.read()
    assert reader.token() is JsonToken.START_OBJECT

    reader.skip()
    assert reader.token() is JsonToken.END_OBJECT
    reader.read()
    assert reader.get_string() == "d"
    reader.read()
    reader.skip()
    assert reader.token() is JsonToken.NUMBER


def test_copy_string_unescapes_and_value_text_equals_compares_the_unescaped_text() -> None:
    reader = JsonReader(utf8('{"k\\u0065y":"\\u00e9\\u4e2d\\ud83d\\ude00\\""}'))
    reader.read()
    reader.read()
    assert reader.value_text_equals("key")
    assert not reader.value_text_equals("kex")
    assert reader.get_string() == "key"

    reader.read()
    destination = bytearray(reader.value_length)
    length = reader.copy_string(destination)
    assert destination[:length].decode() == 'é中😀"'


def test_the_token_bounds_cover_a_strings_quotes() -> None:
    reader = JsonReader(utf8('{"a": "xyz"}'))
    reader.read()
    reader.read()
    reader.read()

    assert (reader.token_start, reader.bytes_consumed, reader.value_length) == (6, 11, 3)


def test_get_string_replaces_invalid_utf8() -> None:
    reader = JsonReader(b'"\xff"')
    reader.read()

    assert reader.get_string() == "�"


def test_a_reader_over_part_of_a_buffer_reads_only_that_part() -> None:
    reader = JsonReader(b'{"a":1} garbage', 7)
    found = []
    while reader.read():
        found.append(reader.token())

    assert found == [JsonToken.START_OBJECT, JsonToken.PROPERTY_NAME, JsonToken.NUMBER, JsonToken.END_OBJECT]


# --- SecretJsonBody ---------------------------------------------------------------------------


def captured(ring: DefaultKeyRing, body: str, text: str = "value", base64_property: str | None = None, *, stream: bool = True) -> tuple[str, bytes]:
    """Runs capture inside a fetch, as a provider's pipeline does; returns the redacted body and the value cached."""
    cache = SinkCache(ring)
    redacted: list[bytes] = []
    cache.on_fetch = lambda name, sink: redacted.append(
        SecretJsonBody.capture(io.BytesIO(utf8(body)) if stream else utf8(body), sink, text, base64_property))
    value = decrypt_bytes(cache, "item")
    return redacted[0].decode(), value


@pytest.mark.parametrize("stream", [True, False], ids=["stream", "buffer"])
def test_the_text_value_is_handed_over_and_blanked_in_the_body(ring: DefaultKeyRing, stream: bool) -> None:
    redacted, value = captured(ring, '{"id":"x","value":"s3cret","n":1}', stream=stream)

    assert value == b"s3cret"
    assert redacted == '{"id":"x","value":"","n":1}'


def test_a_writable_buffer_body_is_read_in_place_and_left_as_it_is(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)
    body = bytearray(b'{"value":"s3cret"}')
    redacted: list[bytes] = []
    cache.on_fetch = lambda name, sink: redacted.append(SecretJsonBody.capture(memoryview(body), sink, "value"))

    assert decrypt_bytes(cache, "item") == b"s3cret"
    assert redacted == [b'{"value":""}']
    assert body == b'{"value":"s3cret"}'


def test_the_base64_value_is_handed_over_decoded(ring: DefaultKeyRing) -> None:
    redacted, value = captured(ring, '{"SecretString":null,"SecretBinary":"AAH+/w=="}', "SecretString", "SecretBinary")

    assert value == bytes([0, 1, 254, 255])
    assert redacted == '{"SecretString":null,"SecretBinary":""}'


@pytest.mark.parametrize("length", range(1, 10))
def test_base64_of_every_length_decodes_padded_or_not(ring: DefaultKeyRing, length: int) -> None:
    data = bytes(range(250, 250 - length, -1))
    for encoded in (base64.b64encode(data).decode(), base64.b64encode(data).decode().rstrip("=")):
        assert captured(ring, f'{{"b":"{encoded}"}}', "t", "b")[1] == data


def test_escapes_are_unescaped(ring: DefaultKeyRing) -> None:
    _, value = captured(ring, '{"value":"a\\"b\\\\c\\u00e9\\n\\/\\b\\f\\r\\t\\ud83d\\ude00é"}')

    assert value.decode() == 'a"b\\cé\n/\b\f\r\t😀é'


def test_a_nested_property_of_the_same_name_is_left_alone(ring: DefaultKeyRing) -> None:
    redacted, value = captured(ring, '{"tags":{"value":"tag"},"list":[{"value":"x"}],"value":"top"}')

    assert value == b"top"
    assert redacted == '{"tags":{"value":"tag"},"list":[{"value":"x"}],"value":""}'


def test_an_escaped_property_name_is_matched_unescaped(ring: DefaultKeyRing) -> None:
    redacted, value = captured(ring, '{"val\\u0075e":"s3cret"}')

    assert value == b"s3cret"
    assert redacted == '{"val\\u0075e":""}'


@pytest.mark.parametrize("body", ['{"other":"x"}', '{"value":null}', '{"value":42}', '{"value":""}', "{}"])
def test_no_non_empty_string_value_hands_nothing_over(ring: DefaultKeyRing, body: str) -> None:
    redacted, value = captured(ring, body)

    assert value == b""
    assert redacted == body


def test_empty_duplicates_are_blanked_alongside_the_value(ring: DefaultKeyRing) -> None:
    redacted, value = captured(ring, '{"value":"","value":"s","value":""}')

    assert value == b"s"
    assert redacted == '{"value":"","value":"","value":""}'


@pytest.mark.parametrize(("body", "text", "base64_property"), [
    ('{"value":"a","value":"b"}', "value", None),
    ('{"SecretString":"a","SecretBinary":"Yg=="}', "SecretString", "SecretBinary"),
    ('{"SecretBinary":"not base64!"}', "SecretString", "SecretBinary"),
    ('{"SecretBinary":"Yg="}', "SecretString", "SecretBinary"),
    ('{"SecretBinary":"Y"}', "SecretString", "SecretBinary"),
    ('{"SecretBinary":"Yg==Yg=="}', "SecretString", "SecretBinary"),
    ('["value"]', "value", None),
    ('{"value":"unterminated', "value", None),
    ('"value"', "value", None),
    ("", "value", None),
])
def test_a_body_that_cant_be_trusted_is_refused_and_nothing_is_cached(ring: DefaultKeyRing, body: str, text: str, base64_property: str | None) -> None:
    cache = SinkCache(ring)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(utf8(body)), sink, text, base64_property)

    with pytest.raises(InvalidSecretDataError) as error:
        cache.decrypt("item", bytearray(16))
    assert error.value.__cause__ is None and error.value.__context__ is None

    cache.on_fetch = None
    assert cache.decrypt("item", bytearray(16)) == 0


@pytest.mark.parametrize(("body", "position"), [('{"value":"s3cr\\qt"}', 15), ('{"value":"s3cr\x01t"}', 14)])
def test_a_malformed_secret_is_reported_by_position_only_never_by_the_byte_rejected(ring: DefaultKeyRing, body: str, position: int) -> None:
    cache = SinkCache(ring)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(utf8(body)), sink, "value")

    with pytest.raises(InvalidSecretDataError) as error:
        cache.decrypt("item", bytearray(16))

    assert str(error.value) == f"The response body isn't valid JSON (at byte {position} of line 0)."
    assert error.value.__cause__ is None and error.value.__context__ is None


def test_a_malformed_secret_is_reported_by_its_position_in_its_own_line(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(b'{\n  "value":"s3cr\\qt"}'), sink, "value")

    with pytest.raises(InvalidSecretDataError) as error:
        cache.decrypt("item", bytearray(16))
    assert str(error.value) == "The response body isn't valid JSON (at byte 16 of line 1)."


def test_a_body_larger_than_the_first_buffer_is_read_whole(ring: DefaultKeyRing) -> None:
    padding = "x" * 100_000
    redacted, value = captured(ring, f'{{"pad":"{padding}","value":"s3cret"}}')

    assert value == b"s3cret"
    assert redacted == f'{{"pad":"{padding}","value":""}}'


@pytest.mark.parametrize("stream", [True, False], ids=["stream", "buffer"])
def test_a_body_at_the_limit_is_refused(ring: DefaultKeyRing, stream: bool) -> None:
    cache = SinkCache(ring)
    body = bytes(SecretJsonBody.MAX_BODY_LENGTH)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(body) if stream else body, sink, "value")

    with pytest.raises(InvalidSecretDataError, match="bytes or more"):
        cache.decrypt("item", bytearray(16))


def test_a_body_that_cant_be_read_fails_with_the_read_error(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(FailingStream(), sink, "value")

    with pytest.raises(OSError, match="connection reset"):
        cache.decrypt("item", bytearray(16))


def test_a_nested_value_is_handed_over_and_only_it_is_blanked(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)
    body = b'{"value":"top","data":{"value":"middle","data":{"other":1,"value":"s3cret"},"metadata":{"value":"m"}}}'
    redacted: list[bytes] = []
    cache.on_fetch = lambda name, sink: redacted.append(SecretJsonBody.capture(io.BytesIO(body), sink, "value", object_path=["data", "data"]))

    assert decrypt_bytes(cache, "item") == b"s3cret"
    assert redacted == [b'{"value":"top","data":{"value":"middle","data":{"other":1,"value":""},"metadata":{"value":"m"}}}']


@pytest.mark.parametrize("body", ['{"data":null}', '{"data":"value"}', '{"data":[{"value":"x"}]}', '{"other":{"value":"x"}}'])
def test_a_path_leading_to_no_object_hands_nothing_over(ring: DefaultKeyRing, body: str) -> None:
    cache = SinkCache(ring)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(utf8(body)), sink, "value", object_path=["data"])

    assert cache.decrypt("item", bytearray(16)) == 0


def test_values_under_duplicate_parents_are_refused(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)
    body = b'{"data":{"value":"a"},"data":{"value":"b"}}'
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(body), sink, "value", object_path=["data"])

    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item", bytearray(16))


def test_a_text_value_holding_a_json_object_is_handed_over_whole_and_by_key_but_a_base64_one_is_not(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)
    json = '{"user":"app","pass":"s3cret"}'
    body = utf8('{"SecretString":"' + json.replace('"', '\\"') + '"}')
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(body), sink, "SecretString", "SecretBinary")

    assert decrypt_bytes(cache, "item#pass") == b"s3cret"
    assert decrypt_bytes(cache, "item#user") == b"app"
    assert decrypt_bytes(cache, "item") == utf8(json)

    binary = utf8('{"SecretBinary":"' + base64.b64encode(utf8(json)).decode() + '"}')
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture(io.BytesIO(binary), sink, "SecretString", "SecretBinary")
    assert decrypt_bytes(cache, "binary") == utf8(json)
    assert cache.decrypt("binary#pass", bytearray(16)) == 0


def test_capture_keys_hands_over_every_member_of_the_object_at_the_path(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)
    body = b'{"data":{"data":{"username":"app","password":"s3cret","port":5432},"metadata":{"version":3}},"value":"top"}'
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture_keys(io.BytesIO(body), sink, ["data", "data"])

    assert decrypt_bytes(cache, "item#password") == b"s3cret"
    assert decrypt_bytes(cache, "item#username") == b"app"
    assert decrypt_bytes(cache, "item#port") == b"5432"
    assert cache.decrypt("item", bytearray(16)) == 0
    assert cache.decrypt("item#version", bytearray(16)) == 0
    assert cache.decrypt("item#value", bytearray(16)) == 0


@pytest.mark.parametrize("body", ['{"data":{"data":null}}', '{"data":{"other":{"k":"v"}}}', '{"data":{"data":{}}}'])
def test_capture_keys_with_no_keys_at_the_path_hands_nothing_over(ring: DefaultKeyRing, body: str) -> None:
    cache = SinkCache(ring)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture_keys(io.BytesIO(utf8(body)), sink, ["data", "data"])

    assert cache.decrypt("item#k", bytearray(16)) == 0


@pytest.mark.parametrize("body", ['{"data":{"k":"a"},"data":{"k":"b"}}', '{"data":{"k":"a","k":"b"}}', '{"data":{"k":"a",}}', '["data"]'])
def test_capture_keys_refuses_a_body_that_cant_be_trusted_and_caches_nothing(ring: DefaultKeyRing, body: str) -> None:
    cache = SinkCache(ring)
    cache.on_fetch = lambda name, sink: SecretJsonBody.capture_keys(io.BytesIO(utf8(body)), sink, ["data"])

    with pytest.raises(InvalidSecretDataError):
        cache.decrypt("item#k", bytearray(16))


def test_the_arguments_are_checked(ring: DefaultKeyRing) -> None:
    cache = SinkCache(ring)

    def fetch(name: str, sink: SecretValueSink) -> None:
        with pytest.raises(TypeError):
            SecretJsonBody.capture(None, sink, "value")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            SecretJsonBody.capture(b"{}", None, "value")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="text property"):
            SecretJsonBody.capture(b"{}", sink, "")
        with pytest.raises(ValueError, match="text property"):
            SecretJsonBody.capture(b"{}", sink, None)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="path"):
            SecretJsonBody.capture(b"{}", sink, "value", object_path=["data", ""])
        with pytest.raises(ValueError, match="path"):
            SecretJsonBody.capture(b"{}", sink, "value", object_path=[None])  # type: ignore[list-item]
        with pytest.raises(TypeError):
            SecretJsonBody.capture(b"{}", sink, "value", object_path=None)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            SecretJsonBody.capture_keys(None, sink, ["data"])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            SecretJsonBody.capture_keys(b"{}", None, ["data"])  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="path"):
            SecretJsonBody.capture_keys(b"{}", sink, [""])

    cache.on_fetch = fetch
    assert cache.decrypt("item", bytearray(16)) == 0


# --- ErrorResponseBody ------------------------------------------------------------------------


def read_errors(body: str, *, stream: bool = True) -> list[str] | None:
    return ErrorResponseBody.read_strings(io.BytesIO(utf8(body)) if stream else utf8(body), "errors")


@pytest.mark.parametrize("stream", [True, False], ids=["stream", "buffer"])
def test_the_arrays_elements_are_returned_strings_as_their_text_and_anything_else_as_json(stream: bool) -> None:
    body = '{"warnings":["w"],"errors":["permission denied","a \\"quoted\\" \\u00e9",42,{"a":[1]},null],"n":{}}'
    assert read_errors(body, stream=stream) == ["permission denied", 'a "quoted" é', "42", '{"a":[1]}', "null"]


def test_an_object_without_the_property_has_no_errors() -> None:
    assert read_errors('{"data":{"k":"v"}}') == []
    assert read_errors('{"errors":[]}') == []


@pytest.mark.parametrize("body", ["", "<html>Bad Gateway</html>", '["errors"]', '{"errors":"denied"}', '{"errors":["x"]} trailing', '{"errors":["x"'])
def test_a_body_that_isnt_an_object_with_an_array_is_none(body: str) -> None:
    assert read_errors(body) is None


@pytest.mark.parametrize("stream", [True, False], ids=["stream", "buffer"])
def test_a_body_beyond_the_limit_is_read_only_that_far_and_isnt_json(stream: bool) -> None:
    assert read_errors('{"errors":["' + "x" * ErrorResponseBody.MAX_BODY_LENGTH + '"]}', stream=stream) is None


def test_an_error_body_read_failure_propagates_and_none_is_refused() -> None:
    with pytest.raises(OSError, match="connection reset"):
        ErrorResponseBody.read_strings(FailingStream(), "errors")
    with pytest.raises(TypeError):
        ErrorResponseBody.read_strings(None, "errors")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ErrorResponseBody.read_strings(b"", None)  # type: ignore[arg-type]
