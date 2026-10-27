from __future__ import annotations

import os

import pytest
from hkdfguard.abstractions import CryptographicError
from hkdfguard.keywrapping.azurekeyvault import _envelope
from hkdfguard.keywrapping.azurekeyvault._key_id import KeyVaultKeyId

WRAP_VERSION = "0123456789abcdef0123456789abcdef"
SIGN_VERSION = "fedcba9876543210fedcba9876543210"


def envelope(ciphertext_length: int) -> bytearray:
    unsigned = _envelope.build_unsigned(WRAP_VERSION, os.urandom(ciphertext_length))
    result = bytearray(len(unsigned) + 80)
    _envelope.write(unsigned, SIGN_VERSION, os.urandom(64), result)
    return result


# --- The envelope -----------------------------------------------------------------------------------


def test_write_then_parse_round_trips_every_part() -> None:
    ciphertext = os.urandom(256)
    signature = os.urandom(64)
    unsigned = _envelope.build_unsigned(WRAP_VERSION.upper(), ciphertext)
    result = bytearray(512)

    length = _envelope.write(unsigned, SIGN_VERSION, signature, result)
    parts = _envelope.parse(bytes(result[:length]))

    assert length == 256 + _envelope.OVERHEAD
    assert parts == _envelope.Parts(WRAP_VERSION, ciphertext, SIGN_VERSION, signature, _envelope.HEADER_LENGTH + 256)


def test_the_layout_is_the_dotnet_and_java_wrappers_byte_for_byte() -> None:
    # The format AzureKeyVaultKeyWrapper (.NET) and AzureKeyVaultKeyWrapperImpl (Java) write and read;
    # a key file made by any port must be read by the others. The same bytes as the Java test's.
    unsigned = _envelope.build_unsigned(WRAP_VERSION, bytes([0xC1, 0xC2, 0xC3]))
    result = bytearray(len(unsigned) + 80)
    _envelope.write(unsigned, SIGN_VERSION, b"\x5a" * 64, result)

    assert result.hex() == "48474b56" + "01" + WRAP_VERSION + "0003" + "c1c2c3" + SIGN_VERSION + "5a" * 64
    assert _envelope.signed_data(unsigned, _envelope.encode_context("myapp")).hex() == (
        b"HkdfGuard-AzureKeyVault-wrap-v1\0".hex() + "0005" + b"myapp".hex() + unsigned.hex())


@pytest.mark.parametrize("data", [bytes(_envelope.OVERHEAD), os.urandom(300), b"", b"HGKV"])
def test_parse_refuses_what_is_not_an_envelope(data: bytes) -> None:
    with pytest.raises(CryptographicError, match="not a wrapped DEK written by AzureKeyVaultKeyWrapper"):
        _envelope.parse(data)


def test_parse_refuses_another_format_version() -> None:
    data = envelope(256)
    data[4] = 2

    with pytest.raises(CryptographicError, match="format version 2"):
        _envelope.parse(bytes(data))


@pytest.mark.parametrize("delta", [-1, 1])
def test_parse_refuses_a_length_that_disagrees_with_the_header(delta: int) -> None:
    data = envelope(256)
    changed = data[:-1] if delta < 0 else data + b"\0"

    with pytest.raises(CryptographicError, match="but its header describes"):
        _envelope.parse(bytes(changed))


def test_parse_reads_the_ciphertext_length_as_unsigned() -> None:
    parts = _envelope.parse(bytes(envelope(0x8001)))

    assert len(parts.wrapped_dek) == 0x8001


def test_parse_refuses_an_empty_ciphertext() -> None:
    data = bytearray(envelope(256))
    data[21:23] = b"\0\0"

    with pytest.raises(CryptographicError):
        _envelope.parse(bytes(data[:_envelope.OVERHEAD + 1]))


@pytest.mark.parametrize("length", [0, 0x10000])
def test_build_unsigned_refuses_a_ciphertext_it_can_not_encode(length: int) -> None:
    with pytest.raises(CryptographicError, match=f"a {length}-byte wrapped key"):
        _envelope.build_unsigned(WRAP_VERSION, bytes(length))


@pytest.mark.parametrize("version", [None, "", WRAP_VERSION[:31], WRAP_VERSION + "0", "g" * 32, "０" * 32, " " + WRAP_VERSION[1:]])
def test_build_unsigned_and_write_refuse_a_version_that_is_not_key_vaults(version: str | None) -> None:
    with pytest.raises(CryptographicError, match="not 32 hex digits"):
        _envelope.build_unsigned(version, os.urandom(256))

    unsigned = _envelope.build_unsigned(WRAP_VERSION, os.urandom(256))
    result = bytearray(b"\xaa" * 512)
    with pytest.raises(CryptographicError, match="not 32 hex digits"):
        _envelope.write(unsigned, version, os.urandom(64), result)
    assert result == b"\xaa" * 512


@pytest.mark.parametrize("length", [0, 63, 65, 96])
def test_write_refuses_a_signature_that_is_not_es256(length: int) -> None:
    unsigned = _envelope.build_unsigned(WRAP_VERSION, os.urandom(256))

    with pytest.raises(CryptographicError, match=f"a {length}-byte signature"):
        _envelope.write(unsigned, SIGN_VERSION, bytes(length), bytearray(512))


def test_write_refuses_a_result_too_small_and_leaves_it_as_it_was() -> None:
    unsigned = _envelope.build_unsigned(WRAP_VERSION, os.urandom(256))
    result = bytearray(b"\xaa" * 358)

    with pytest.raises(ValueError, match="is 359 bytes; result holds 358"):
        _envelope.write(unsigned, SIGN_VERSION, os.urandom(64), result)
    assert result == b"\xaa" * 358


def test_signed_data_binds_the_domain_context_and_envelope() -> None:
    unsigned = _envelope.build_unsigned(WRAP_VERSION, os.urandom(256))
    context = _envelope.encode_context("app")

    signed = _envelope.signed_data(unsigned, context)

    assert signed != _envelope.signed_data(unsigned, _envelope.encode_context("apq"))
    assert signed != _envelope.signed_data(unsigned, b"")
    assert signed != _envelope.signed_data(unsigned[:-1] + bytes([unsigned[-1] ^ 1]), context)
    # The context is length-prefixed, so it can't run into the envelope.
    assert _envelope.signed_data(b"HGKV" + unsigned[4:], b"ab") != _envelope.signed_data(b"bHGKV" + unsigned[4:], b"a")


def test_encode_context_is_utf8() -> None:
    assert _envelope.encode_context(None) == b""
    assert _envelope.encode_context("") == b""
    assert _envelope.encode_context("café \U0001f511") == "café \U0001f511".encode()
    assert len(_envelope.encode_context("x" * 65_535)) == 65_535


def test_encode_context_refuses_one_too_long_to_length_prefix_or_not_well_formed() -> None:
    with pytest.raises(ValueError, match="65536 bytes in UTF-8; at most 65535"):
        _envelope.encode_context("x" * 65_536)
    with pytest.raises(ValueError, match="at most 65535"):
        _envelope.encode_context("é" * 32_768)
    with pytest.raises(ValueError, match="lone surrogate"):
        _envelope.encode_context("\udc00app")


# --- Key identifiers ----------------------------------------------------------------------------------


def test_a_key_identifier_is_parsed_and_normalized() -> None:
    assert KeyVaultKeyId.parse("https://MyVault.Vault.Azure.NET/keys/My-Key") == KeyVaultKeyId("https://myvault.vault.azure.net", "My-Key", None)
    assert KeyVaultKeyId.parse(f"HTTPS://myvault.vault.azure.net:8443/keys/k/{WRAP_VERSION}/") == \
        KeyVaultKeyId("https://myvault.vault.azure.net:8443", "k", WRAP_VERSION)
    assert str(KeyVaultKeyId.parse("https://myvault.managedhsm.azure.net/keys/k/")) == "https://myvault.managedhsm.azure.net/keys/k"


def test_same_key_ignores_the_version_and_the_names_case_but_not_the_vault() -> None:
    key = KeyVaultKeyId.parse("https://myvault.vault.azure.net/keys/my-key")

    assert key.same_key(KeyVaultKeyId.parse(f"https://MYVAULT.vault.azure.net/keys/MY-KEY/{WRAP_VERSION}"))
    assert not key.same_key(KeyVaultKeyId.parse("https://myvault.vault.azure.net:443/keys/my-key"))
    assert not key.same_key(KeyVaultKeyId.parse("https://other.vault.azure.net/keys/my-key"))
    assert not key.same_key(KeyVaultKeyId.parse("https://myvault.vault.azure.net/keys/my-key2"))


def test_with_version_names_that_version_of_the_same_key() -> None:
    key = KeyVaultKeyId.parse("https://myvault.vault.azure.net/keys/my-key")

    assert str(key.with_version(WRAP_VERSION)) == f"https://myvault.vault.azure.net/keys/my-key/{WRAP_VERSION}"
    assert key.version is None


@pytest.mark.parametrize("key_id", [None, 1, b"https://myvault.vault.azure.net/keys/k", f"https://myvault.vault.azure.net/keys/{'k' * 128}",
                                    "https://myvault.vault.azure.net/keys/k/v-1", "https://myvault.vault.azure.net//keys/k", "https:///keys/k",
                                    "https://myvault.vault.azure.net/keys/k%2D1", "https://-myvault.vault.azure.net/keys/k"])
def test_parse_refuses_what_is_not_a_key_identifier(key_id: object) -> None:
    with pytest.raises(ValueError, match="isn't a Key Vault key identifier"):
        KeyVaultKeyId.parse(key_id)  # type: ignore[arg-type]
