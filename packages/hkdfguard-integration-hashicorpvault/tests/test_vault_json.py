"""The JSON a VaultClient reads and writes, Go durations, and reading Vault's response envelope."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from hkdfguard.abstractions import DataProtector
from hkdfguard.integration.hashicorpvault import JsonKind, JsonValue, JsonWriter, StaticVaultToken, VaultJsonError
from hkdfguard.integration.hashicorpvault._duration import format_go_duration, parse_go_duration
from hkdfguard.integration.hashicorpvault._json import SecureBuffer
from hkdfguard.integration.hashicorpvault._response import read_response
from hkdfguard.integration.hashicorpvault.schema import KvV2ReadResponse, TransitEncryptRequest, TransitSetCertificateForKeyRequest
from vault_client_test_support import decrypt

# --- Go durations ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("text", "expected"), [
    ("0", timedelta(0)), ("1h30m", timedelta(hours=1, minutes=30)), ("300ms", timedelta(milliseconds=300)), ("2.5s", timedelta(seconds=2.5)),
    ("-1.5h", -timedelta(hours=1.5)), ("+5m", timedelta(minutes=5)), ("1us", timedelta(microseconds=1)), ("1µs", timedelta(microseconds=1)),
    ("1500ns", timedelta(microseconds=1)), (".5s", timedelta(milliseconds=500)), ("1h1m1s1ms", timedelta(hours=1, minutes=1, seconds=1, milliseconds=1)),
    ("100000h", timedelta(hours=100000)),
])
def test_parse_reads_gos_durations(text: str, expected: timedelta) -> None:
    assert parse_go_duration(text) == expected


@pytest.mark.parametrize("text", ["", "-", "1", "1x", "s", "1..5s", ".s", "1e3s", "99999999999999h"])
def test_parse_refuses_what_isnt_a_duration(text: str) -> None:
    with pytest.raises(ValueError):
        parse_go_duration(text)


@pytest.mark.parametrize(("duration", "text"), [
    (timedelta(0), "0s"), (timedelta(minutes=5), "5m0s"), (timedelta(hours=1, minutes=2, seconds=3.5), "1h2m3.5s"),
    (timedelta(microseconds=1500), "1.5ms"), (timedelta(microseconds=1), "1µs"), (-timedelta(seconds=90), "-1m30s"),
    (timedelta(days=2), "48h0m0s"),
])
def test_format_writes_as_go_does(duration: timedelta, text: str) -> None:
    assert format_go_duration(duration) == text


# --- JsonValue ------------------------------------------------------------------------------------


def test_a_string_property_takes_whatever_json_stands_in_its_place_as_text() -> None:
    value = JsonValue.parse('{"s":"x","n":1.50,"t":true,"o":{"a":[1,null]},"z":null}')
    assert [value.member(n).read_str() for n in ("s", "n", "t", "o", "z", "missing")] == ["x", "1.50", "true", '{"a":[1,null]}', None, None]


def test_numbers_are_read_leniently_but_exactly() -> None:
    value = JsonValue.parse('{"i":12,"f":4.0,"e":1e3,"s":" 7 ","big":123456789012345678901234567890,"half":4.5,"fs":"2.5"}')
    assert [value.member(n).read_int() for n in ("i", "f", "e", "s", "big")] == [12, 4, 1000, 7, 123456789012345678901234567890]
    with pytest.raises(VaultJsonError):
        value.member("half").read_int()
    assert value.member("fs").read_float() == 2.5
    assert value.member("half").as_decimal() == Decimal("4.5")
    with pytest.raises(VaultJsonError):
        JsonValue.parse('"inf"').read_float()


def test_the_strict_readers_refuse_another_kind() -> None:
    value = JsonValue.parse('{"s":"x","n":1}')
    for read in (value.member("s").as_int, value.member("n").as_str, value.as_list, value.member("s").as_bool, value.member("n").as_dict):
        with pytest.raises(VaultJsonError, match="Expected a JSON"):
            read()
    for lenient in (value.member("s").read_bool, value.read_int, value.member("n").read_datetime, value.member("n").read_json_dict):
        with pytest.raises(VaultJsonError, match="Expected"):
            lenient()


def test_a_date_time_is_read_as_go_writes_it_and_without_an_offset_is_utc() -> None:
    value = JsonValue.parse('["2026-01-02T03:04:05.123456789Z","2026-01-02T03:04:05+02:00","2026-01-02T03:04:05",""]')
    first, second, third, empty = (e.read_datetime() for e in value.as_list())
    assert first == datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
    assert second == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2)))
    assert third == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert empty is None
    with pytest.raises(VaultJsonError):
        JsonValue.of("yesterday").read_datetime()


def test_a_number_with_a_huge_exponent_is_refused_without_being_expanded(protector: DataProtector) -> None:
    # 12 bytes that int(Decimal(...)) would expand into ten million digits, pinning a CPU for minutes:
    # what a hostile server could put in every response's lease_duration.
    started = time.monotonic()
    value = JsonValue.parse('{"lease_duration":1E+10000000,"neg":-1e+5000,"edge":9e4299,"over":1e4300}')
    for name in ("lease_duration", "neg", "over"):
        with pytest.raises(VaultJsonError):
            value.member(name).read_int()
    assert value.member("edge").read_int() == 9 * 10**4299  # 4300 digits: as many as int(str) reads
    assert value.read_object() == {"lease_duration": Decimal("1E+10000000"), "neg": Decimal("-1e+5000"), "edge": 9 * 10**4299,
                                   "over": Decimal("1e4300")}
    with pytest.raises(VaultJsonError):
        read_response(memoryview(b'{"lease_duration":1E+10000000,"data":{}}'), protector, JsonValue.read_json_dict)
    assert time.monotonic() - started < 5


def test_read_object_is_plain_python() -> None:
    assert JsonValue.parse('{"a":[1,2.5,"x",true,null],"b":{}}').read_object() == {"a": [1, Decimal("2.5"), "x", True, None], "b": {}}


def test_members_keep_their_order_the_last_of_a_repeated_name_winning() -> None:
    value = JsonValue.parse('{"b":1,"a":2,"b":3}')
    assert list(value.as_dict()) == ["b", "a"]
    assert value.member("b").as_int() == 3


def test_str_is_compact_json_and_equality_is_structural() -> None:
    text = '{"a":[1,"x\\n\\"y",{"b":null}],"c":false}'
    value = JsonValue.parse(' { "a" : [ 1 , "x\\n\\"y" , { "b" : null } ] , "c" : false } ')
    assert str(value) == text
    assert value == JsonValue.parse(text)
    assert hash(value) == hash(JsonValue.parse(text))
    assert value != JsonValue.parse('{"c":false}')
    assert value.kind is JsonKind.OBJECT


def test_read_model_and_read_json_pass_null_through() -> None:
    assert JsonValue.NULL.read_model(KvV2ReadResponse.from_json) is None
    assert JsonValue.NULL.read_json() is None
    assert JsonValue.parse("1").read_json() == JsonValue.parse("1")
    assert JsonValue.NULL.member("x").is_null


def test_a_list_or_dict_of_typed_values_refuses_a_null() -> None:
    with pytest.raises(VaultJsonError, match="null"):
        JsonValue.parse('["a",null]').read_list(JsonValue.read_str)
    assert JsonValue.parse('["a",null]').read_object_list() == ["a", None]
    assert JsonValue.parse('[1,null]').read_json_list() == [JsonValue.parse("1"), JsonValue.NULL]


def test_parse_refuses_what_isnt_one_json_value() -> None:
    for text in ("", "{", "1 2", "[1,]", "{'a':1}"):
        with pytest.raises(VaultJsonError):
            JsonValue.parse(text)


def test_a_generated_model_is_read_leniently_and_refuses_what_isnt_an_object() -> None:
    model = KvV2ReadResponse.from_json(JsonValue.parse('{"data":{"k":"v"},"metadata":{"version":3},"extra":1}'))
    assert model.data is not None and model.data["k"] == JsonValue.of("v")
    assert model.metadata is not None and model.metadata["version"].as_int() == 3
    with pytest.raises(VaultJsonError, match="KvV2ReadResponse"):
        KvV2ReadResponse.from_json(JsonValue.parse("[]"))


# --- JsonWriter -----------------------------------------------------------------------------------


def written(write: Callable[[JsonWriter], object]) -> str:
    with SecureBuffer() as buffer:
        write(JsonWriter(buffer))
        return buffer.view().tobytes().decode()


def test_writing_escapes_what_json_must_and_writes_the_rest_as_utf8() -> None:
    assert written(lambda w: w.value('"\\\n\r\t\b\f\u0001/é\U0001f600')) == '"\\"\\\\\\n\\r\\t\\b\\f\\u0001/é\U0001f600"'


def test_writing_refuses_an_unpaired_surrogate_and_bytes_that_arent_utf8() -> None:
    with pytest.raises(ValueError, match="surrogate"):
        written(lambda w: w.value("\ud800"))
    for bad in (b"\xff", b"\xc0\x80", b"\xed\xa0\x80", b"\xe2\x82", b"\xf4\x90\x80\x80"):
        with pytest.raises(ValueError, match="UTF-8"):
            written(lambda w, b=bad: w.value(bytearray(b)))  # type: ignore[misc]


def test_a_bytearray_is_written_as_a_string() -> None:
    secret = bytearray('pa"ss\nwörd'.encode())
    assert written(lambda w: w.value(secret)) == '"pa\\"ss\\nwörd"'


def test_writing_takes_every_kind_of_value(protector: DataProtector) -> None:
    token = StaticVaultToken.protect(protector, "hvs.x")
    value = {"none": None, "t": True, "i": -3, "f": 1.5, "whole": 2.0, "d": Decimal("1.10"), "s": "x", "l": [1, (2, 3)],
             "time": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), "json": JsonValue.parse('{"a":1}'), "model": TransitEncryptRequest(plaintext="cA=="),
             "token": token, 7: "key"}
    text = written(lambda w: w.value(value))
    assert text == ('{"none":null,"t":true,"i":-3,"f":1.5,"whole":2,"d":1.10,"s":"x","l":[1,[2,3]],"time":"2026-01-02T03:04:05+00:00",'
                    f'"json":{{"a":1}},"model":{{"plaintext":"cA=="}},"token":"{token.get_token()}","7":"key"}}')
    assert decrypt(protector, JsonValue.parse(text).member("token").as_str()) == "hvs.x"


def test_writing_refuses_what_json_cant_hold() -> None:
    for bad, error in ((float("nan"), ValueError), (float("inf"), ValueError), (Decimal("NaN"), ValueError), (object(), TypeError),
                       (datetime(2026, 1, 1), ValueError), ({1, 2}, TypeError)):
        with pytest.raises(error):
            written(lambda w, b=bad: w.value(b))  # type: ignore[misc]


def test_writing_refuses_nesting_deeper_than_64() -> None:
    nested: object = []
    for _ in range(63):
        nested = [nested]
    assert written(lambda w: w.value(nested)).count("[") == 64
    with pytest.raises(ValueError, match="64"):
        written(lambda w: w.value([nested]))


def test_writing_keeps_to_the_grammar() -> None:
    for misuse in (lambda w: w.name("a"), lambda w: w.begin_object().value(1), lambda w: w.begin_array().end_object(),
                   lambda w: w.begin_object().name("a").name("b"), lambda w: w.end_array()):
        with pytest.raises(RuntimeError):
            written(misuse)


def test_a_required_member_left_unset_fails_the_write() -> None:
    with pytest.raises(ValueError, match="needs its certificate_chain"):
        written(lambda w: w.value(TransitSetCertificateForKeyRequest()))


def test_a_secure_buffer_grows_and_is_zeroed_when_it_grows_and_when_closed() -> None:
    buffer = SecureBuffer()
    first = buffer.buffer
    buffer.write(b"x" * 300)
    assert buffer.buffer is not first and not any(first)
    assert buffer.length == 300
    grown = buffer.buffer
    buffer.close()
    assert not any(grown) and buffer.length == 0


# --- The response envelope ------------------------------------------------------------------------


def test_tokens_in_a_response_are_protected_from_its_bytes_and_appear_nowhere_else(protector: DataProtector) -> None:
    body = memoryview(b'{"auth":{"client_token":"hvs.login","accessor":"a"},"wrap_info":{"token":"hvs.wrap","ttl":5},"data":null}')
    response = read_response(body, protector, JsonValue.read_json_dict)
    assert response is not None and response.auth is not None and response.wrap_info is not None
    assert response.auth.client_token is not None and response.wrap_info.token is not None
    assert decrypt(protector, response.auth.client_token) == "hvs.login"
    assert decrypt(protector, response.wrap_info.token) == "hvs.wrap"
    assert "hvs.login" not in repr(response) and "hvs.wrap" not in repr(response)


def test_a_body_without_an_envelope_member_is_read_whole_as_data(protector: DataProtector) -> None:
    response = read_response(memoryview(b'{"request_id":"x","sealed":false}'), protector, JsonValue.read_json_dict)
    assert response is not None and response.data is not None and set(response.data) == {"request_id", "sealed"}
    assert response.request_id is None


def test_an_empty_body_is_none_and_a_response_reads_only_the_view_given(protector: DataProtector) -> None:
    assert read_response(memoryview(b""), protector, JsonValue.read_json_dict) is None
    body = bytearray(b'{"data":{"a":1}}garbage')
    response = read_response(memoryview(body)[:16], protector, JsonValue.read_json_dict)
    assert response is not None and response.data is not None and response.data["a"].as_int() == 1


@pytest.mark.parametrize("body", ['{"auth":[]}', '{"wrap_info":"x"}', '{"auth":{"client_token":5}}', '{"data":{}} {}', '{"data":'])
def test_an_envelope_of_the_wrong_shape_fails_the_response(protector: DataProtector, body: str) -> None:
    with pytest.raises(VaultJsonError):
        read_response(memoryview(body.encode()), protector, JsonValue.read_json_dict)
