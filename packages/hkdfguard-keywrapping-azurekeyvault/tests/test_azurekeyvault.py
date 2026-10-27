from __future__ import annotations

import base64
import functools
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest
import requests
import urllib3
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ServiceRequestError
from azure.core.pipeline.transport import RequestsTransport
from azure.keyvault.keys.crypto import KeyWrapAlgorithm, SignatureAlgorithm, SignResult, UnwrapResult, VerifyResult, WrapResult
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, WrappedKeyLimits
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.keywrapping.azurekeyvault import AzureKeyVaultKeyWrapper, KeyFileTrust, KeyVaultCryptoClient, _envelope
from hkdfguard_test_support import long_path
from requests.adapters import BaseAdapter

VAULT = "https://hkdfguard-test.vault.azure.net"
WRAPPING_KEY_NAME = "hkdfguard-wrap"
SIGNING_KEY_NAME = "hkdfguard-sign"
WRAPPING_KEY_ID = f"{VAULT}/keys/{WRAPPING_KEY_NAME}"
SIGNING_KEY_ID = f"{VAULT}/keys/{SIGNING_KEY_NAME}"
CONTEXT = "hkdfguard.test"
OAEP_SHA256 = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
NOT_SET: Any = object()

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only.")


# --- Test doubles ---------------------------------------------------------------------------------


@functools.cache
def rsa_key(bits: int, index: int = 0) -> rsa.RSAPrivateKey:
    """An RSA key of ``bits``, generated once per test run: generating one per test would dominate it."""
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


@functools.cache
def ec_key(curve_name: str, index: int = 0) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1() if curve_name == "P-384" else ec.SECP256R1())


def new_version() -> str:
    return uuid.uuid4().hex


def es256(key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
    """A raw r || s signature of a digest, as Key Vault returns it."""
    r, s = decode_dss_signature(key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
    size = (key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


class FakeResponse:
    """The parts of an HTTP response HttpResponseError reads."""

    def __init__(self, status: int, body: str) -> None:
        self.status_code = status
        self.reason = "Fake"
        self._body = body

    def text(self, encoding: str | None = None) -> str:
        return self._body


def refusal(status: int, code: str | None) -> HttpResponseError:
    """The exception the Key Vault client raises for an error response."""
    body = json.dumps({"error": {"code": code, "message": f"{code} from FakeKeyVault."}}) if code is not None else ""
    return HttpResponseError(response=cast(Any, FakeResponse(status, body)))


@dataclass
class KeyVersion:
    version: str
    key: Any  # rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


class FakeKeyVault:
    """An in-process stand-in for a vault holding an RSA wrapping key and an EC signing key, each with
    versions. Its clients do the real cryptography - RSA-OAEP-256, ES256 over a SHA-256 digest - and
    raise the Key Vault client's exceptions, so the wrapper is tested against what Key Vault would do.
    Every call is recorded as ``"{operation}:{name}/{version}"``; each operation can be made to fail,
    or to report another key."""

    def __init__(self, wrapping_bits: int = 2048, signing_curve: str = "P-256", vault: str = VAULT, index: int = 0) -> None:
        self.vault = vault
        self.keys: dict[str, list[KeyVersion]] = {
            WRAPPING_KEY_NAME: [KeyVersion(new_version(), rsa_key(wrapping_bits, index))],
            SIGNING_KEY_NAME: [KeyVersion(new_version(), ec_key(signing_curve, index))],
        }
        self.calls: list[str] = []
        self.failures: dict[str, BaseException] = {}
        self.reported_key_id: dict[str, str | None] = {}
        self.signature_override: bytes | None = None
        self.unwrapped_key_override: Any = NOT_SET
        self.verify_override: Any = NOT_SET
        self.wrap_inputs: list[Any] = []
        self.created: list[str] = []
        self.closed: list[str] = []

    def client(self, key_id: str) -> FakeClient:
        self.created.append(key_id)
        return FakeClient(self, key_id)

    def current_version(self, name: str) -> str:
        return self.keys[name][-1].version

    def rotate(self, name: str) -> str:
        current = self.keys[name][-1].key
        key = rsa_key(current.key_size, len(self.keys[name])) if isinstance(current, rsa.RSAPrivateKey) else ec_key("P-256", len(self.keys[name]))
        self.keys[name].append(KeyVersion(new_version(), key))
        return self.current_version(name)

    def purge(self, name: str, version: str) -> None:
        self.keys[name] = [entry for entry in self.keys[name] if entry.version != version]

    def resolve(self, key_id: str) -> tuple[str, KeyVersion]:
        """The key version an identifier names - its current version if it names none - or KeyNotFound."""
        parts = urlsplit(key_id)
        _, _, name, *rest = parts.path.split("/")
        version = rest[0] if rest and rest[0] else None
        if f"https://{parts.netloc}" != self.vault or name not in self.keys:
            raise refusal(404, "KeyNotFound")
        for entry in self.keys[name]:
            if (version is None and entry is self.keys[name][-1]) or entry.version == version:
                return name, entry
        raise refusal(404, "KeyNotFound")

    def perform(self, operation: str, key_id: str, data: bytes, signature: bytes = b"") -> tuple[str | None, Any]:
        """Does one operation as Key Vault would, returning the full key identifier used and the result."""
        name, entry = self.resolve(key_id)
        self.calls.append(f"{operation}:{name}/{entry.version}")
        if operation in self.failures:
            raise self.failures[operation]
        used = self.reported_key_id.get(operation, f"{self.vault}/keys/{name}/{entry.version}")

        key = entry.key
        if operation == "wrap":
            return used, key.public_key().encrypt(bytes(data), OAEP_SHA256)
        if operation == "unwrap":
            try:
                return used, key.decrypt(data, OAEP_SHA256) if self.unwrapped_key_override is NOT_SET else self.unwrapped_key_override
            except ValueError:
                raise refusal(400, "BadParameter") from None
        if operation == "sign":
            return used, es256(key, data) if self.signature_override is None else self.signature_override
        if self.verify_override is not NOT_SET:
            return used, self.verify_override
        size = len(signature) // 2
        try:
            der = encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"))
            key.public_key().verify(der, data, ec.ECDSA(Prehashed(hashes.SHA256())))
            return used, True
        except Exception:
            return used, False


class FakeClient:
    """A Key Vault client for one key identifier, as CryptographyClient is, over a FakeKeyVault."""

    def __init__(self, vault: FakeKeyVault, key_id: str) -> None:
        self.vault = vault
        self.key_id = key_id

    def wrap_key(self, algorithm: KeyWrapAlgorithm, key: bytes, **kwargs: Any) -> WrapResult:
        assert algorithm == KeyWrapAlgorithm.rsa_oaep_256
        self.vault.wrap_inputs.append(key)
        used, wrapped = self.vault.perform("wrap", self.key_id, key)
        return WrapResult(key_id=used, algorithm=algorithm, encrypted_key=wrapped)

    def unwrap_key(self, algorithm: KeyWrapAlgorithm, encrypted_key: bytes, **kwargs: Any) -> UnwrapResult:
        assert algorithm == KeyWrapAlgorithm.rsa_oaep_256
        used, key = self.vault.perform("unwrap", self.key_id, encrypted_key)
        return UnwrapResult(key_id=used, algorithm=algorithm, key=key)

    def sign(self, algorithm: SignatureAlgorithm, digest: bytes, **kwargs: Any) -> SignResult:
        assert algorithm == SignatureAlgorithm.es256 and len(digest) == 32
        used, signature = self.vault.perform("sign", self.key_id, digest)
        return SignResult(key_id=used, algorithm=algorithm, signature=signature)

    def verify(self, algorithm: SignatureAlgorithm, digest: bytes, signature: bytes, **kwargs: Any) -> VerifyResult:
        assert algorithm == SignatureAlgorithm.es256 and len(digest) == 32
        used, valid = self.vault.perform("verify", self.key_id, digest, signature)
        return VerifyResult(key_id=used, algorithm=algorithm, is_valid=valid)

    def close(self) -> None:
        self.vault.closed.append(self.key_id)


@pytest.fixture
def vault() -> FakeKeyVault:
    return FakeKeyVault()


def wrapper_over(vault: FakeKeyVault, context: str | None = CONTEXT, wrapping_key_id: str = WRAPPING_KEY_ID, signing_key_id: str = SIGNING_KEY_ID,
                 key_file_trust: KeyFileTrust | None = None) -> AzureKeyVaultKeyWrapper:
    return AzureKeyVaultKeyWrapper._over(wrapping_key_id, signing_key_id, vault.client, context, key_file_trust)


def wrap_with(wrapper: AzureKeyVaultKeyWrapper, dek: Buffer) -> bytes:
    result = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(dek, result)
    return bytes(result[:length])


def raise_(error: BaseException) -> Any:
    def call(*args: Any, **kwargs: Any) -> Any:
        raise error
    return call


class Credential:
    """A TokenCredential that hands out a fixed token, or fails as one that can't get a token does."""

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.requests = 0

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        self.requests += 1
        if self.error is not None:
            raise self.error
        return AccessToken("fake-token", int(time.time()) + 3600)


# --- Construction ---------------------------------------------------------------------------------


def test_the_constructor_refuses_missing_or_invalid_arguments(vault: FakeKeyVault) -> None:
    credential = Credential()

    with pytest.raises(TypeError):
        AzureKeyVaultKeyWrapper(None, SIGNING_KEY_ID, credential)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, None, credential)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, SIGNING_KEY_ID, None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID.encode(), SIGNING_KEY_ID, credential)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, SIGNING_KEY_ID, credential, b"context")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, SIGNING_KEY_ID, credential, key_file_trust="S-1-5-18")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, SIGNING_KEY_ID, credential, client_options=[("retry_total", 0)])  # type: ignore[arg-type]
    for option in ("key", "credential"):
        with pytest.raises(ValueError, match="must not name key or credential"):
            AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, SIGNING_KEY_ID, credential, client_options={option: "x"})
    with pytest.raises(ValueError, match="at most 65535"):
        wrapper_over(vault, "x" * 65_536)
    # .NET encodes a lone surrogate as U+FFFD, Java as '?': refused, so no port signs a context another can't.
    with pytest.raises(ValueError, match="lone surrogate"):
        wrapper_over(vault, "app\ud800")


@pytest.mark.parametrize("key_id", [
    "https://hkdfguard-test.vault.azure.net/secrets/hkdfguard-wrap",       # a secret's identifier
    "https://hkdfguard-test.vault.azure.net/keys",                         # no name
    "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap/v/extra",  # too long
    "http://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap",           # not https
    "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap?x=1",      # a query
    "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap#x",        # a fragment
    "https://user@hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap",     # user information
    "https://hkdfguard-test.vault.azure.net/keys/hkdfguard_wrap",          # not a Key Vault name
    "https://hkdfguard-test.vault.azure.net:x/keys/hkdfguard-wrap",        # not a port
    "https://hkdfguard_test.vault.azure.net/keys/hkdfguard-wrap",          # not a host name
    " https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap",         # surrounding white space
    "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-\twrap",        # a tab, which urlsplit would drop
    "/keys/hkdfguard-wrap",                                                # not absolute
    "not a uri",
    "",
])
def test_the_constructor_refuses_what_is_not_a_key_vault_key_identifier(vault: FakeKeyVault, key_id: str) -> None:
    with pytest.raises(ValueError, match="isn't a Key Vault key identifier"):
        wrapper_over(vault, wrapping_key_id=key_id)


@pytest.mark.parametrize("signing_key_id", [
    "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap",
    "https://HKDFGUARD-TEST.vault.azure.net/keys/HKDFGUARD-WRAP/0123456789abcdef0123456789abcdef",
    "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap/",
])
def test_the_constructor_refuses_the_same_key_for_wrapping_and_signing(vault: FakeKeyVault, signing_key_id: str) -> None:
    with pytest.raises(ValueError, match="separate EC P-256 key"):
        wrapper_over(vault, signing_key_id=signing_key_id)


def test_the_constructor_allows_keys_with_the_same_name_in_different_vaults(vault: FakeKeyVault) -> None:
    wrapper_over(vault, signing_key_id=f"https://other-vault.vault.azure.net/keys/{WRAPPING_KEY_NAME}")
    # The port is part of the vault.
    wrapper_over(vault, signing_key_id=f"https://hkdfguard-test.vault.azure.net:8443/keys/{WRAPPING_KEY_NAME}")


def test_the_public_constructor_makes_no_call_until_the_wrapper_is_used() -> None:
    credential = Credential()

    wrapper = AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, SIGNING_KEY_ID, credential, CONTEXT, client_options={"retry_total": 0})

    assert isinstance(wrapper, KeyWrapper)
    assert credential.requests == 0
    assert AzureKeyVaultKeyWrapper.GENERATED_KEY_LENGTH == 32
    assert AzureKeyVaultKeyWrapper.MAX_PLAINTEXT_LENGTH == 190


def test_a_fake_client_is_a_key_vault_crypto_client(vault: FakeKeyVault) -> None:
    client: KeyVaultCryptoClient = vault.client(WRAPPING_KEY_ID)
    assert client is not None


# --- Wrap, unwrap, generate -------------------------------------------------------------------------


def test_wrap_then_unwrap_round_trips_the_dek(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    dek = os.urandom(32)

    wrapped = wrap_with(wrapper, dek)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrapped, revealed) == 32
    assert revealed == dek
    assert len(wrapped) == 256 + _envelope.OVERHEAD == 359


def test_wrap_hands_the_client_bytes_and_leaves_the_callers_plaintext_alone(vault: FakeKeyVault) -> None:
    dek = bytearray(os.urandom(32))
    expected = bytes(dek)

    wrap_with(wrapper_over(vault), dek)

    # bytes, which the SDK's local RSA takes; given a bytearray, it would send the key to Key Vault instead.
    assert type(vault.wrap_inputs[0]) is bytes
    assert vault.wrap_inputs[0] == expected
    # The caller's own buffer is the caller's to zero.
    assert dek == expected


@pytest.mark.parametrize("plaintext", [os.urandom(32), bytearray(os.urandom(32)), memoryview(os.urandom(64))[16:48]])
def test_wrap_accepts_any_buffer_the_key_wrapper_contract_allows(vault: FakeKeyVault, plaintext: bytes | bytearray | memoryview) -> None:
    wrapper = wrapper_over(vault)

    revealed = bytearray(32)
    wrapper.unwrap(wrap_with(wrapper, plaintext), revealed)
    assert revealed == bytes(plaintext)


def test_wrap_wraps_under_the_current_versions_and_records_them(vault: FakeKeyVault) -> None:
    parts = _envelope.parse(wrap_with(wrapper_over(vault), os.urandom(32)))

    assert parts.wrapping_key_version == vault.current_version(WRAPPING_KEY_NAME)
    assert parts.signing_key_version == vault.current_version(SIGNING_KEY_NAME)
    assert vault.calls == [f"wrap:{WRAPPING_KEY_NAME}/{parts.wrapping_key_version}", f"sign:{SIGNING_KEY_NAME}/{parts.signing_key_version}"]
    # Clients for the identifiers as given, without a version.
    assert vault.created == [WRAPPING_KEY_ID, SIGNING_KEY_ID]


def test_wrap_under_a_version_named_at_construction_uses_that_version(vault: FakeKeyVault) -> None:
    pinned = vault.current_version(WRAPPING_KEY_NAME)
    vault.rotate(WRAPPING_KEY_NAME)

    parts = _envelope.parse(wrap_with(wrapper_over(vault, wrapping_key_id=f"{WRAPPING_KEY_ID}/{pinned}"), os.urandom(32)))

    assert parts.wrapping_key_version == pinned


def test_unwrap_verifies_the_signature_first_then_unwraps_under_the_recorded_versions(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    wrapped = wrap_with(wrapper, os.urandom(32))
    vault.calls.clear()
    vault.created.clear()

    wrapper.unwrap(wrapped, bytearray(32))

    wrap_version, sign_version = vault.current_version(WRAPPING_KEY_NAME), vault.current_version(SIGNING_KEY_NAME)
    assert vault.calls == [f"verify:{SIGNING_KEY_NAME}/{sign_version}", f"unwrap:{WRAPPING_KEY_NAME}/{wrap_version}"]
    assert vault.created == [f"{SIGNING_KEY_ID}/{sign_version}", f"{WRAPPING_KEY_ID}/{wrap_version}"]


def test_unwrap_after_both_keys_rotate_still_reveals_older_key_files(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    dek = os.urandom(32)
    old = wrap_with(wrapper, dek)

    vault.rotate(WRAPPING_KEY_NAME)
    vault.rotate(SIGNING_KEY_NAME)
    new = _envelope.parse(wrap_with(wrapper, os.urandom(32)))
    revealed = bytearray(32)
    wrapper.unwrap(old, revealed)

    assert revealed == dek
    assert new.wrapping_key_version == vault.current_version(WRAPPING_KEY_NAME) != _envelope.parse(old).wrapping_key_version
    assert new.signing_key_version == vault.current_version(SIGNING_KEY_NAME) != _envelope.parse(old).signing_key_version


def test_generate_and_wrap_produces_a_32_byte_dek_that_reveals(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    revealed = bytearray(64)

    assert wrapper.unwrap(wrapped[:length], revealed) == AzureKeyVaultKeyWrapper.GENERATED_KEY_LENGTH
    assert not ArrayUtility.is_null_or_empty(revealed[:32])
    assert type(vault.wrap_inputs[0]) is bytes
    assert len(vault.wrap_inputs[0]) == 32


def test_unwrap_a_wrapped_dek_forged_from_the_public_key_is_refused_without_unwrapping(vault: FakeKeyVault) -> None:
    # What anyone holding the public wrapping key can make: a real RSA-OAEP ciphertext of a DEK they
    # chose, signed with an EC key of their own.
    chosen = os.urandom(32)
    ciphertext = vault.keys[WRAPPING_KEY_NAME][-1].key.public_key().encrypt(chosen, OAEP_SHA256)
    unsigned = _envelope.build_unsigned(vault.current_version(WRAPPING_KEY_NAME), ciphertext)
    signed = hashlib.sha256(_envelope.signed_data(unsigned, _envelope.encode_context(CONTEXT))).digest()
    forged = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = _envelope.write(unsigned, vault.current_version(SIGNING_KEY_NAME), es256(ec_key("P-256", 99), signed), forged)

    revealed = bytearray(b"\xaa" * 32)
    with pytest.raises(CryptographicError, match="signature doesn't verify"):
        wrapper_over(vault).unwrap(forged[:length], revealed)

    assert not any(call.startswith("unwrap") for call in vault.calls)
    assert ArrayUtility.is_null_or_empty(revealed)


@pytest.mark.parametrize("offset", [
    0,    # magic
    4,    # format version
    5,    # wrapping key version
    21,   # ciphertext length
    30,   # ciphertext
    278,  # ciphertext, last byte
    279,  # signing key version
    300,  # signature
    358,  # signature, last byte
])
def test_unwrap_a_wrapped_dek_changed_anywhere_is_refused_and_zeroes_the_result(vault: FakeKeyVault, offset: int) -> None:
    wrapper = wrapper_over(vault)
    wrapped = bytearray(wrap_with(wrapper, os.urandom(32)))
    wrapped[offset] ^= 1
    vault.calls.clear()

    revealed = bytearray(b"\xaa" * 32)
    with pytest.raises(CryptographicError):
        wrapper.unwrap(wrapped, revealed)

    assert not any(call.startswith("unwrap") for call in vault.calls)
    assert ArrayUtility.is_null_or_empty(revealed)


@pytest.mark.parametrize("context", ["hkdfguard.other", None, ""])
def test_unwrap_under_another_context_is_refused(vault: FakeKeyVault, context: str | None) -> None:
    wrapped = wrap_with(wrapper_over(vault), os.urandom(32))

    with pytest.raises(CryptographicError, match="signature doesn't verify"):
        wrapper_over(vault, context).unwrap(wrapped, bytearray(32))


def test_no_context_and_an_empty_context_are_the_same_context(vault: FakeKeyVault) -> None:
    wrapped = wrap_with(wrapper_over(vault, None), os.urandom(32))

    assert wrapper_over(vault, "").unwrap(wrapped, bytearray(32)) == 32


def test_unwrap_by_a_wrapper_pinned_to_other_keys_is_refused(vault: FakeKeyVault) -> None:
    wrapped = wrap_with(wrapper_over(vault), os.urandom(32))
    other = FakeKeyVault(vault="https://other-vault.vault.azure.net", index=1)

    with pytest.raises(CryptographicError, match="KeyNotFound \\(HTTP 404\\)"):
        AzureKeyVaultKeyWrapper._over(f"{other.vault}/keys/{WRAPPING_KEY_NAME}", f"{other.vault}/keys/{SIGNING_KEY_NAME}", other.client,
                                      CONTEXT).unwrap(wrapped, bytearray(32))
    assert not any(call.startswith("unwrap") for call in other.calls)


def test_unwrap_when_the_recorded_version_has_been_purged_is_refused(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    wrapped = wrap_with(wrapper, os.urandom(32))
    old = vault.current_version(SIGNING_KEY_NAME)
    vault.rotate(SIGNING_KEY_NAME)
    vault.purge(SIGNING_KEY_NAME, old)

    with pytest.raises(CryptographicError) as error:
        wrapper.unwrap(wrapped, bytearray(32))

    assert str(error.value) == f"Azure Key Vault verify failed for key '{SIGNING_KEY_NAME}': KeyNotFound (HTTP 404)."
    assert isinstance(error.value.__cause__, HttpResponseError)


@pytest.mark.parametrize("wrapped", [b"", bytes(_envelope.OVERHEAD), os.urandom(300), b"HGKV" + os.urandom(300)])
def test_unwrap_refuses_what_is_not_a_wrapped_dek_and_zeroes_the_result(vault: FakeKeyVault, wrapped: bytes) -> None:
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(CryptographicError):
        wrapper_over(vault).unwrap(wrapped, result)

    assert vault.calls == []
    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_into_a_result_too_small_is_refused_and_zeroes_it(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    wrapped = wrap_with(wrapper, os.urandom(32))

    result = bytearray(b"\xaa" * 16)
    with pytest.raises(ValueError, match="result holds 16"):
        wrapper.unwrap(wrapped, result)
    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_writes_into_a_view_of_a_larger_buffer(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    dek = os.urandom(32)
    backing = bytearray(64)

    assert wrapper.unwrap(wrap_with(wrapper, dek), memoryview(backing)[16:]) == 32
    assert backing[16:48] == dek


@pytest.mark.parametrize("key", [b"", None])
def test_unwrap_when_key_vault_returns_no_key_is_refused(vault: FakeKeyVault, key: bytes | None) -> None:
    wrapper = wrapper_over(vault)
    wrapped = wrap_with(wrapper, os.urandom(32))
    vault.unwrapped_key_override = key

    with pytest.raises(CryptographicError, match="returned no key"):
        wrapper.unwrap(wrapped, bytearray(32))


def test_unwrap_when_the_verify_answer_is_not_true_is_refused(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    wrapped = wrap_with(wrapper, os.urandom(32))
    vault.verify_override = None

    with pytest.raises(CryptographicError, match="signature doesn't verify"):
        wrapper.unwrap(wrapped, bytearray(32))
    assert not any(call.startswith("unwrap") for call in vault.calls)


def test_unwrap_zeroes_the_result_whatever_the_failure(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    wrapped = wrap_with(wrapper, os.urandom(32))
    vault.failures["unwrap"] = KeyboardInterrupt()
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(KeyboardInterrupt):
        wrapper.unwrap(wrapped, result)
    assert ArrayUtility.is_null_or_empty(result)


@pytest.mark.parametrize("size", [0, AzureKeyVaultKeyWrapper.MAX_PLAINTEXT_LENGTH + 1])
def test_wrap_refuses_a_plaintext_rsa_oaep_can_not_wrap(vault: FakeKeyVault, size: int) -> None:
    with pytest.raises(ValueError, match=f"got {size}"):
        wrapper_over(vault).wrap(bytes(size), bytearray(WrappedKeyLimits.MAX_BYTES))
    assert vault.calls == []


def test_wrap_accepts_the_largest_plaintext_rsa_oaep_does(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    key = os.urandom(AzureKeyVaultKeyWrapper.MAX_PLAINTEXT_LENGTH)

    revealed = bytearray(AzureKeyVaultKeyWrapper.MAX_PLAINTEXT_LENGTH)
    assert wrapper.unwrap(wrap_with(wrapper, key), revealed) == AzureKeyVaultKeyWrapper.MAX_PLAINTEXT_LENGTH
    assert revealed == key


def test_wrap_into_a_result_too_small_is_refused(vault: FakeKeyVault) -> None:
    result = bytearray(b"\xaa" * 358)
    with pytest.raises(ValueError, match="result holds 358"):
        wrapper_over(vault).wrap(os.urandom(32), result)
    assert result == b"\xaa" * 358


def test_none_arguments_are_refused(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)

    with pytest.raises(TypeError):
        wrapper.wrap(None, bytearray(WrappedKeyLimits.MAX_BYTES))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        wrapper.wrap(os.urandom(32), None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        wrapper.unwrap(None, bytearray(32))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        wrapper.generate_and_wrap(None)  # type: ignore[arg-type]


def test_wrap_under_an_rsa_key_too_large_for_a_key_file_is_refused_before_signing() -> None:
    vault = FakeKeyVault(wrapping_bits=4096)

    with pytest.raises(CryptographicError, match=re.escape("would be 615 bytes; a wrapped DEK is at most 512. Use a 2048- or 3072-bit RSA key")):
        wrap_with(wrapper_over(vault), os.urandom(32))
    assert not any(call.startswith("sign") for call in vault.calls)


def test_wrap_under_an_rsa_3072_key_fits_a_key_file() -> None:
    vault = FakeKeyVault(wrapping_bits=3072)
    wrapper = wrapper_over(vault)
    dek = os.urandom(32)

    wrapped = wrap_with(wrapper, dek)
    revealed = bytearray(32)
    wrapper.unwrap(wrapped, revealed)

    assert len(wrapped) == 487
    assert revealed == dek


def test_wrap_when_the_signing_key_is_not_p256_is_refused() -> None:
    with pytest.raises(CryptographicError, match=re.escape("96-byte signature; an ES256 signature is 64. The signing key must be an EC P-256 key")):
        wrap_with(wrapper_over(FakeKeyVault(signing_curve="P-384")), os.urandom(32))


@pytest.mark.parametrize(("operation", "reported"), [
    ("wrap", f"{VAULT}/keys/hkdfguard-other/0123456789abcdef0123456789abcdef"),
    ("wrap", f"https://other-vault.vault.azure.net/keys/{WRAPPING_KEY_NAME}/0123456789abcdef0123456789abcdef"),
    ("sign", f"{VAULT}/keys/{WRAPPING_KEY_NAME}/0123456789abcdef0123456789abcdef"),
])
def test_wrap_when_key_vault_reports_another_key_is_refused(vault: FakeKeyVault, operation: str, reported: str) -> None:
    vault.reported_key_id[operation] = reported

    with pytest.raises(CryptographicError, match=f"reported key '{reported}' instead"):
        wrap_with(wrapper_over(vault), os.urandom(32))


@pytest.mark.parametrize("operation", ["wrap", "sign"])
def test_wrap_when_key_vault_reports_a_version_that_is_not_key_vaults_is_refused(vault: FakeKeyVault, operation: str) -> None:
    name = WRAPPING_KEY_NAME if operation == "wrap" else SIGNING_KEY_NAME
    vault.reported_key_id[operation] = f"{VAULT}/keys/{name}/v1"

    with pytest.raises(CryptographicError, match="key version 'v1', not 32 hex digits"):
        wrap_with(wrapper_over(vault), os.urandom(32))


@pytest.mark.parametrize("reported", [None, "", "not a key identifier"])
def test_wrap_when_key_vault_reports_no_key_is_refused(vault: FakeKeyVault, reported: str | None) -> None:
    vault.reported_key_id["wrap"] = reported

    with pytest.raises(CryptographicError, match="which isn't a key identifier"):
        wrap_with(wrapper_over(vault), os.urandom(32))


def test_wrap_when_key_vault_reports_no_version_names_the_permission_it_needs(vault: FakeKeyVault) -> None:
    # What the Azure SDK reports when it couldn't read the key: the identifier it was given.
    vault.reported_key_id["sign"] = SIGNING_KEY_ID

    with pytest.raises(CryptographicError, match="didn't report which version it used: give the identity get on the key"):
        wrap_with(wrapper_over(vault), os.urandom(32))


# --- Failures ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("operation", "name"), [("wrap", WRAPPING_KEY_NAME), ("sign", SIGNING_KEY_NAME), ("verify", SIGNING_KEY_NAME),
                                                 ("unwrap", WRAPPING_KEY_NAME)])
def test_key_vault_refusals_are_cryptographic_errors_naming_the_error_and_status(vault: FakeKeyVault, operation: str, name: str) -> None:
    wrapper = wrapper_over(vault)
    wrapped = wrap_with(wrapper, os.urandom(32))
    error = vault.failures[operation] = refusal(403, "Forbidden")

    with pytest.raises(CryptographicError) as raised:
        if operation in ("wrap", "sign"):
            wrap_with(wrapper, os.urandom(32))
        else:
            wrapper.unwrap(wrapped, bytearray(32))

    assert str(raised.value) == f"Azure Key Vault {operation} failed for key '{name}': Forbidden (HTTP 403)."
    assert raised.value.__cause__ is error


def test_a_refusal_without_an_error_code_is_still_named(vault: FakeKeyVault) -> None:
    vault.failures["wrap"] = refusal(500, None)

    with pytest.raises(CryptographicError, match=f"wrap failed for key '{WRAPPING_KEY_NAME}': error \\(HTTP 500\\)\\."):
        wrap_with(wrapper_over(vault), os.urandom(32))


@pytest.mark.parametrize("failure", [ServiceRequestError("Could not connect to the vault."), ClientAuthenticationError("No credential could get a token."),
                                     ValueError("This client's key expired at 2026-01-01 (UTC)")])
def test_client_side_failures_are_cryptographic_errors(vault: FakeKeyVault, failure: Exception) -> None:
    vault.failures["wrap"] = failure

    with pytest.raises(CryptographicError) as raised:
        wrap_with(wrapper_over(vault), os.urandom(32))

    assert str(raised.value) == f"Azure Key Vault wrap failed for key '{WRAPPING_KEY_NAME}': {failure}"
    assert raised.value.__cause__ is failure


def test_keyboard_interrupt_is_left_as_it_is(vault: FakeKeyVault) -> None:
    vault.failures["sign"] = KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        wrap_with(wrapper_over(vault), os.urandom(32))


# --- Clients ----------------------------------------------------------------------------------------


def test_one_client_is_created_per_key_version_and_kept(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    for _ in range(3):
        wrapper.unwrap(wrap_with(wrapper, os.urandom(32)), bytearray(32))

    wrap_version, sign_version = vault.current_version(WRAPPING_KEY_NAME), vault.current_version(SIGNING_KEY_NAME)
    assert sorted(vault.created) == sorted([WRAPPING_KEY_ID, SIGNING_KEY_ID, f"{WRAPPING_KEY_ID}/{wrap_version}", f"{SIGNING_KEY_ID}/{sign_version}"])


def test_close_closes_every_client_and_later_calls_are_refused(vault: FakeKeyVault) -> None:
    with wrapper_over(vault) as wrapper:
        wrapped = wrap_with(wrapper, os.urandom(32))
        wrapper.unwrap(wrapped, bytearray(32))

    assert sorted(vault.closed) == sorted(vault.created)
    result = bytearray(b"\xaa" * 32)
    with pytest.raises(CryptographicError, match="is closed"):
        wrapper.unwrap(wrapped, result)
    with pytest.raises(CryptographicError, match="is closed"):
        wrapper.generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))
    assert ArrayUtility.is_null_or_empty(result)
    wrapper.close()
    assert len(vault.closed) == 4


# --- Through the Azure SDK's own client -------------------------------------------------------------


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwk(name: str, entry: KeyVersion, vault: str) -> dict[str, Any]:
    kid = f"{vault}/keys/{name}/{entry.version}"
    public = entry.key.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        numbers = public.public_numbers()
        return {"kid": kid, "kty": "RSA", "key_ops": ["wrapKey", "unwrapKey"], "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": b64url(numbers.e.to_bytes(3, "big"))}
    point = public.public_numbers()
    return {"kid": kid, "kty": "EC", "crv": "P-256", "key_ops": ["sign", "verify"], "x": b64url(point.x.to_bytes(32, "big")),
            "y": b64url(point.y.to_bytes(32, "big"))}


class KeyVaultHttpStub(BaseAdapter):
    """Key Vault's REST API, over a FakeKeyVault, as the Azure SDK's requests transport reaches it: the
    authentication challenge, getting a key's public half, and wrapkey, unwrapkey, sign and verify.
    Every request is recorded as ``"{METHOD} {path}"``; ``refusals`` makes an operation ("get",
    "wrapkey", ...) answer with an error status and code."""

    CHALLENGE = 'Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net"'

    def __init__(self, vault: FakeKeyVault) -> None:
        super().__init__()
        self.vault = vault
        self.requests: list[str] = []
        self.refusals: dict[str, tuple[int, str]] = {}

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> requests.Response:
        assert request.url is not None
        path = urlsplit(request.url).path
        self.requests.append(f"{request.method} {path}")
        if "Authorization" not in request.headers:
            return self.respond(request, 401, None, {"WWW-Authenticate": self.CHALLENGE})
        assert request.headers["Authorization"] == "Bearer fake-token"

        segments = path.split("/")  # "", "keys", name, version, operation
        operation = segments[4] if len(segments) > 4 else "get"
        if operation in self.refusals:
            status, code = self.refusals[operation]
            return self.respond(request, status, {"error": {"code": code, "message": f"{code} from KeyVaultHttpStub."}})
        key_id = f"{self.vault.vault}/keys/{segments[2]}" + (f"/{segments[3]}" if len(segments) > 3 and segments[3] else "")
        try:
            if operation == "get":
                name, entry = self.vault.resolve(key_id)
                return self.respond(request, 200, {"key": jwk(name, entry, self.vault.vault), "attributes": {"enabled": True}})
            body = json.loads(cast(bytes, request.body))
            names = {"wrapkey": "wrap", "unwrapkey": "unwrap", "sign": "sign", "verify": "verify"}
            if operation == "verify":
                _, valid = self.vault.perform("verify", key_id, unb64url(body["digest"]), unb64url(body["value"]))
                return self.respond(request, 200, {"value": valid})
            used, result = self.vault.perform(names[operation], key_id, unb64url(body["value"]))
            return self.respond(request, 200, {"kid": used, "value": b64url(result)})
        except HttpResponseError as error:
            assert error.error is not None and error.status_code is not None
            return self.respond(request, error.status_code, {"error": {"code": error.error.code, "message": "From the fake vault."}})

    @staticmethod
    def respond(request: requests.PreparedRequest, status: int, body: Any, headers: dict[str, str] | None = None) -> requests.Response:
        content = b"" if body is None else json.dumps(body).encode()
        all_headers = {"Content-Type": "application/json", "Content-Length": str(len(content)), **(headers or {})}
        response = requests.Response()
        response.request = request
        response.url = request.url or ""
        response.status_code = status
        response.headers.update(all_headers)
        response._content = content
        response.raw = urllib3.HTTPResponse(body=io.BytesIO(content), headers=all_headers, status=status, preload_content=False)
        return response

    def close(self) -> None:
        pass

    def client_options(self) -> dict[str, Any]:
        """CryptographyClient options that send every request here, and never retry."""
        session = requests.Session()
        session.mount("https://", self)
        return {"transport": RequestsTransport(session=session, session_owner=False), "retry_total": 0}


def sdk_wrapper(stub: KeyVaultHttpStub, credential: Any = None, wrapping_key_id: str = WRAPPING_KEY_ID, signing_key_id: str = SIGNING_KEY_ID,
                context: str = CONTEXT) -> AzureKeyVaultKeyWrapper:
    return AzureKeyVaultKeyWrapper(wrapping_key_id, signing_key_id, credential or Credential(), context, client_options=stub.client_options())


def operations(stub: KeyVaultHttpStub) -> list[str]:
    """The requests that did more than read a key."""
    return [request for request in stub.requests if request.startswith("POST")]


def test_through_the_sdk_the_dek_round_trips_and_unwrap_reaches_only_the_recorded_versions(vault: FakeKeyVault,
                                                                                           caplog: pytest.LogCaptureFixture) -> None:
    stub = KeyVaultHttpStub(vault)
    dek = os.urandom(32)

    with sdk_wrapper(stub) as wrapper:
        wrapped = wrap_with(wrapper, dek)
        revealed = bytearray(32)
        assert wrapper.unwrap(wrapped, revealed) == 32

    assert revealed == dek
    wrap_version, sign_version = vault.current_version(WRAPPING_KEY_NAME), vault.current_version(SIGNING_KEY_NAME)
    # The SDK reads each key's public half, then wraps and verifies in this process: only signing and
    # unwrapping are calls, unwrapping under the version the key file records.
    assert operations(stub) == [f"POST /keys/{SIGNING_KEY_NAME}/{sign_version}/sign", f"POST /keys/{WRAPPING_KEY_NAME}/{wrap_version}/unwrapkey"]
    assert f"GET /keys/{SIGNING_KEY_NAME}/{sign_version}" in stub.requests
    # The SDK logs a warning whenever it can't do an operation locally and falls back to Key Vault.
    assert not [record for record in caplog.records if record.levelname == "WARNING"]
    assert _envelope.parse(wrapped).wrapping_key_version == wrap_version


def test_through_the_sdk_without_permission_to_read_the_keys_everything_is_done_in_the_vault(vault: FakeKeyVault) -> None:
    stub = KeyVaultHttpStub(vault)
    stub.refusals["get"] = (403, "Forbidden")
    wrap_version, sign_version = vault.current_version(WRAPPING_KEY_NAME), vault.current_version(SIGNING_KEY_NAME)
    dek = os.urandom(32)

    with sdk_wrapper(stub, wrapping_key_id=f"{WRAPPING_KEY_ID}/{wrap_version}", signing_key_id=f"{SIGNING_KEY_ID}/{sign_version}") as wrapper:
        wrapped = wrap_with(wrapper, dek)
        revealed = bytearray(32)
        wrapper.unwrap(wrapped, revealed)

    assert revealed == dek
    assert operations(stub) == [f"POST /keys/{WRAPPING_KEY_NAME}/{wrap_version}/wrapkey", f"POST /keys/{SIGNING_KEY_NAME}/{sign_version}/sign",
                                f"POST /keys/{SIGNING_KEY_NAME}/{sign_version}/verify", f"POST /keys/{WRAPPING_KEY_NAME}/{wrap_version}/unwrapkey"]


def test_through_the_sdk_without_permission_to_read_a_key_named_without_a_version_wrap_is_refused(vault: FakeKeyVault) -> None:
    stub = KeyVaultHttpStub(vault)
    stub.refusals["get"] = (403, "Forbidden")

    with sdk_wrapper(stub) as wrapper, pytest.raises(CryptographicError, match="didn't report which version it used: give the identity get"):
        wrap_with(wrapper, os.urandom(32))


def test_through_the_sdk_a_forged_signature_is_refused_without_unwrapping(vault: FakeKeyVault) -> None:
    stub = KeyVaultHttpStub(vault)
    with sdk_wrapper(stub) as wrapper:
        wrapped = bytearray(wrap_with(wrapper, os.urandom(32)))
        wrapped[-1] ^= 1
        stub.requests.clear()

        with pytest.raises(CryptographicError, match="signature doesn't verify"):
            wrapper.unwrap(wrapped, bytearray(32))

    assert operations(stub) == []


def test_through_the_sdk_a_refusal_names_key_vaults_error_code_and_the_status(vault: FakeKeyVault) -> None:
    stub = KeyVaultHttpStub(vault)
    with sdk_wrapper(stub) as wrapper:
        wrapped = wrap_with(wrapper, os.urandom(32))
        stub.refusals["unwrapkey"] = (403, "ForbiddenByRbac")

        with pytest.raises(CryptographicError) as raised:
            wrapper.unwrap(wrapped, bytearray(32))

    assert str(raised.value) == f"Azure Key Vault unwrap failed for key '{WRAPPING_KEY_NAME}': ForbiddenByRbac (HTTP 403)."
    assert isinstance(raised.value.__cause__, HttpResponseError)


def test_through_the_sdk_a_purged_signing_key_version_is_refused(vault: FakeKeyVault) -> None:
    stub = KeyVaultHttpStub(vault)
    with sdk_wrapper(stub) as wrapper:
        wrapped = wrap_with(wrapper, os.urandom(32))
    old = vault.current_version(SIGNING_KEY_NAME)
    vault.rotate(SIGNING_KEY_NAME)
    vault.purge(SIGNING_KEY_NAME, old)

    # A new wrapper, whose client must fetch the purged version: Key Vault no longer has it.
    with sdk_wrapper(stub) as wrapper, pytest.raises(CryptographicError, match="verify failed for key 'hkdfguard-sign': KeyNotFound \\(HTTP 404\\)"):
        wrapper.unwrap(wrapped, bytearray(32))


def test_through_the_sdk_a_credential_that_can_not_get_a_token_is_a_cryptographic_error(vault: FakeKeyVault) -> None:
    failure = ClientAuthenticationError("DefaultAzureCredential failed to retrieve a token.")
    stub = KeyVaultHttpStub(vault)

    with sdk_wrapper(stub, Credential(failure)) as wrapper, pytest.raises(CryptographicError) as raised:
        wrap_with(wrapper, os.urandom(32))

    assert str(raised.value) == f"Azure Key Vault wrap failed for key '{WRAPPING_KEY_NAME}': {failure.message}"
    assert raised.value.__cause__ is failure


# --- With the rest of HkdfGuard ---------------------------------------------------------------------


def test_a_crypto_provider_generates_and_reveals_its_dek_through_key_vault(vault: FakeKeyVault) -> None:
    wrapper = wrapper_over(vault)
    with AesGcmCryptoProviderFactory().create_ephemeral(wrapper, 60) as provider:
        expected = b"hello, key vault"
        # Encrypt zeroes the plaintext it is given, so it gets a copy.
        plaintext = bytearray(expected)
        encrypted = bytearray(provider.get_encrypted_allocation_length(len(plaintext)))
        encrypted_length = provider.encrypt(plaintext, encrypted)
        decrypted = bytearray(provider.get_decrypted_allocation_length(encrypted_length))
        decrypted_length = provider.decrypt(encrypted[:encrypted_length], decrypted)

        assert decrypted[:decrypted_length] == expected


# --- Key files --------------------------------------------------------------------------------------


@pytest.fixture
def user_writable_key_file() -> Iterator[Path]:
    """A key file in a folder the user running the tests could replace: under the user's temp folder
    (Windows) or the shared /tmp (Linux and macOS) - neither somewhere only administrators can write."""
    root = long_path(Path(tempfile.gettempdir())) if sys.platform == "win32" else Path("/tmp")
    directory = root / f"hkdfguard-keys-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        path = directory / "v1.key"
        path.write_bytes(os.urandom(359))
        yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_read_key_file_by_default_refuses_a_file_the_current_user_could_have_replaced(vault: FakeKeyVault, user_writable_key_file: Path) -> None:
    with pytest.raises(PermissionError, match="not trusted"):
        wrapper_over(vault).read_key_file(user_writable_key_file)


def test_read_key_file_with_no_trust_given_trusts_administrators_only(vault: FakeKeyVault, user_writable_key_file: Path) -> None:
    # The same refusal as the default: None is ADMINISTRATORS_ONLY, never "anyone".
    with pytest.raises(PermissionError, match="not trusted"):
        AzureKeyVaultKeyWrapper(WRAPPING_KEY_ID, SIGNING_KEY_ID, Credential(), None, None).read_key_file(user_writable_key_file)


@pytest.mark.parametrize(("path", "expected"), [(None, TypeError), ("", ValueError)])
def test_read_key_file_refuses_a_missing_path(vault: FakeKeyVault, path: object, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        wrapper_over(vault).read_key_file(path)  # type: ignore[arg-type]


def current_user_sid() -> str:
    whoami = os.path.join(os.environ["SYSTEMROOT"], "System32", "whoami.exe")
    output = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout.strip()
    return output.rsplit(",", 1)[1].strip('"')  # "DOMAIN\name","S-1-5-21-..."


@windows_only
def test_read_key_file_with_the_writers_account_trusted_reads_the_file_and_it_reveals(vault: FakeKeyVault, user_writable_key_file: Path) -> None:
    wrapper = wrapper_over(vault, key_file_trust=KeyFileTrust(windows_principals=[current_user_sid()]))
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    user_writable_key_file.write_bytes(wrapped[:length])

    read = wrapper.read_key_file(user_writable_key_file)

    assert read == wrapped[:length]
    assert wrapper.unwrap(read, bytearray(32)) == 32


@windows_only
def test_read_key_file_trusting_everyone_is_refused(vault: FakeKeyVault, user_writable_key_file: Path) -> None:
    wrapper = wrapper_over(vault, key_file_trust=KeyFileTrust(windows_principals=["S-1-1-0"]))

    with pytest.raises(ValueError, match="every account"):
        wrapper.read_key_file(user_writable_key_file)
