"""The AccessSecretVersion response parser and the per-fetch capture, driven directly with the bytes
gRPC would hand the deserializer - the Python counterpart of hkdfguard-java's ReceiveBufferScrubberTest."""

from __future__ import annotations

import pytest
from google.cloud.secretmanager_v1 import AccessSecretVersionResponse, SecretPayload
from hkdfguard.cache.googlesecretmanager import _capture
from hkdfguard.cache.googlesecretmanager._capture import AccessedSecretVersion, MalformedResponseError, ResponseCapture, crc32c, parse_access_response


def payload_of(length: int) -> bytes:
    return bytes(i % 251 + 1 for i in range(length))


def serialized(name: str = "projects/1/secrets/s/versions/1", data: bytes | None = None, crc: int | None = None) -> bytes:
    payload = SecretPayload(data=data or b"")
    if crc is not None:
        payload.data_crc32c = crc
    return bytes(AccessSecretVersionResponse.serialize(AccessSecretVersionResponse(name=name, payload=payload)))


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field(number: int, wire_type: int, body: bytes) -> bytes:
    tag = varint(number << 3 | wire_type)
    return tag + (varint(len(body)) + body if wire_type == 2 else body)


def assert_zeroed(data: bytearray) -> None:
    assert not any(data)


@pytest.mark.parametrize("length", [0, 1, 100, 127, 128, 20_000, 64 * 1024])
def test_a_response_parses_as_protobuf_does(length: int) -> None:
    data = payload_of(length)

    version = parse_access_response(serialized(data=data, crc=crc32c(data)))

    assert version.name == "projects/1/secrets/s/versions/1"
    assert version.data == data
    assert version.data_crc32c == crc32c(data)


def test_the_payload_is_a_bytearray_copy_untouched_by_zeroing_the_source() -> None:
    raw = bytearray(serialized(data=b"value"))

    version = parse_access_response(raw)
    raw[:] = bytes(len(raw))

    assert type(version.data) is bytearray
    assert version.data == b"value"


def test_zero_erases_the_payload() -> None:
    version = parse_access_response(serialized(data=b"value"))

    version.zero()

    assert len(version.data) == 5
    assert_zeroed(version.data)


def test_an_empty_message_parses_as_the_default_instance() -> None:
    version = parse_access_response(b"")

    assert (version.name, version.data, version.data_crc32c) == ("", bytearray(), None)


def test_a_response_without_a_payload_has_no_data_and_no_checksum() -> None:
    version = parse_access_response(AccessSecretVersionResponse.serialize(AccessSecretVersionResponse(name="n")))

    assert (version.name, version.data, version.data_crc32c) == ("n", bytearray(), None)


def test_a_checksum_of_zero_is_present_not_absent() -> None:
    assert parse_access_response(serialized(data=b"x", crc=0)).data_crc32c == 0


def test_a_negative_int64_checksum_is_read_as_signed() -> None:
    assert parse_access_response(serialized(data=b"x", crc=-1)).data_crc32c == -1


def test_unknown_fields_of_every_wire_type_are_skipped_at_both_levels() -> None:
    unknown = field(9, 0, varint(300)) + field(10, 1, bytes(8)) + field(11, 2, b"skipped") + field(12, 5, bytes(4))
    payload = unknown + field(1, 2, b"value") + unknown + field(2, 0, varint(7))

    version = parse_access_response(unknown + field(1, 2, b"name") + field(2, 2, payload) + unknown)

    assert (version.name, version.data, version.data_crc32c) == ("name", bytearray(b"value"), 7)


def test_fields_in_any_order_are_read() -> None:
    raw = field(2, 2, field(2, 0, varint(5)) + field(1, 2, b"value")) + field(1, 2, b"name")

    version = parse_access_response(raw)

    assert (version.name, version.data, version.data_crc32c) == ("name", bytearray(b"value"), 5)


def test_a_repeated_payload_is_merged_and_the_replaced_data_is_zeroed(monkeypatch: pytest.MonkeyPatch) -> None:
    arrays: list[bytearray] = []
    real_bytearray = bytearray

    def recording(*args: object) -> bytearray:
        made = real_bytearray(*args)
        arrays.append(made)
        return made

    monkeypatch.setattr(_capture, "bytearray", recording, raising=False)
    raw = field(2, 2, field(1, 2, b"first") + field(2, 0, varint(9))) + field(2, 2, field(1, 2, b"second"))

    version = parse_access_response(raw)

    # The second occurrence's data replaces the first's; its absent checksum leaves the first's.
    assert (version.data, version.data_crc32c) == (bytearray(b"second"), 9)
    first = [a for a in arrays if len(a) == 5]
    assert len(first) == 1
    assert_zeroed(first[0])


def test_the_last_name_wins() -> None:
    assert parse_access_response(field(1, 2, b"a") + field(1, 2, b"b")).name == "b"


@pytest.mark.parametrize("raw", [
    bytes([0x0A, 0x7F, 1, 2, 3]),                     # name's length past the end
    bytes([0x0A]),                                    # ends before name's length
    bytes([0x80]),                                    # ends inside a tag
    bytes([0x08, 0x01]),                              # name as a varint
    bytes([0x12, 0x02, 0x08, 0x01]),                  # data as a varint
    bytes([0x12, 0x02, 0x12, 0x00]),                  # data_crc32c length-delimited
    bytes([0x12, 0x02, 0x10, 0x80]),                  # data_crc32c ends inside its varint
    bytes([0x00, 0x00]),                              # field number 0
    bytes([0x1B]),                                    # a group (wire type 3)
    bytes([0x1E]),                                    # wire type 6
    bytes([0x19, 0, 0]),                              # fixed64 ends early
    bytes([0x1D, 0]),                                 # fixed32 ends early
    bytes([0x18]) + bytes([0xFF] * 10) + bytes([1]),  # a varint over 10 bytes
    bytes([0x18]) + bytes([0xFF] * 9) + bytes([0x7F]),  # a varint over 64 bits
    bytes([0x0A, 0x02, 0xC3, 0x28]),                  # name isn't UTF-8
    bytes([0x12, 0x03, 0x0A, 0x05, 0x61]),            # data runs past its payload
])
def test_malformed_bytes_are_refused(raw: bytes) -> None:
    with pytest.raises(MalformedResponseError):
        parse_access_response(raw)


def test_a_failed_parse_zeroes_the_payload_it_had_already_copied(monkeypatch: pytest.MonkeyPatch) -> None:
    made: list[AccessedSecretVersion] = []

    class Recording(AccessedSecretVersion):
        __slots__ = ()

        def __init__(self) -> None:
            super().__init__()
            made.append(self)

    monkeypatch.setattr(_capture, "AccessedSecretVersion", Recording)

    with pytest.raises(MalformedResponseError):
        parse_access_response(field(2, 2, field(1, 2, b"secret")) + bytes([0x0A, 0x7F]))

    assert len(made) == 1
    assert made[0].data == bytes(6)


def test_a_malformed_message_says_nothing_of_its_contents() -> None:
    with pytest.raises(MalformedResponseError) as raised:
        parse_access_response(field(2, 2, field(1, 2, b"s3cret")) + bytes([0x0A, 0x02, 0xC3, 0x28]))

    assert "s3cret" not in str(raised.value)
    assert raised.value.__cause__ is None and raised.value.__suppress_context__


def test_the_repr_never_shows_the_payload() -> None:
    version = parse_access_response(serialized(data=b"s3cret", crc=1))

    assert "s3cret" not in repr(version)
    assert "6 bytes" in repr(version)


def test_the_capture_keeps_every_response_it_parsed_and_close_zeroes_them_all() -> None:
    capture = ResponseCapture()
    first = capture.deserialize(serialized(data=b"first"))
    second = capture.deserialize(serialized(data=b"second"))

    capture.close()

    assert_zeroed(first.data)
    assert_zeroed(second.data)
    assert len(first.data) == 5 and len(second.data) == 6


def test_once_closed_the_capture_parses_nothing() -> None:
    capture = ResponseCapture()
    capture.close()

    late = capture.deserialize(serialized(data=b"late"))

    assert (late.name, late.data) == ("", bytearray())


def test_the_capture_raises_for_a_malformed_message_and_keeps_nothing() -> None:
    capture = ResponseCapture()

    with pytest.raises(MalformedResponseError):
        capture.deserialize(bytes([0x0A, 0x7F]))
    capture.close()


def test_crc32c_matches_the_castagnoli_check_value() -> None:
    assert crc32c(b"123456789") == 0xE3069283
    assert crc32c(b"") == 0
    assert crc32c(memoryview(bytearray(b"123456789"))) == 0xE3069283
