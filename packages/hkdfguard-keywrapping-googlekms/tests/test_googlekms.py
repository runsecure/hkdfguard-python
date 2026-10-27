from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import grpc
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.api_core.exceptions import GoogleAPICallError, RetryError, from_http_status
from google.auth.exceptions import DefaultCredentialsError, RefreshError
from google.cloud.kms_v1 import DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, KeyManagementServiceClient, ProtectionLevel
from google.cloud.kms_v1.services.key_management_service.transports import KeyManagementServiceGrpcTransport
from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, WrappedKeyLimits
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.keywrapping.googlekms import CloudKmsClient, GoogleKmsKeyWrapper, KeyFileTrust
from hkdfguard.keywrapping.googlekms._wrapper import crc32c
from hkdfguard_test_support import long_path

KEY_NAME = "projects/hkdfguard-test/locations/europe-west1/keyRings/hkdfguard/cryptoKeys/dek-wrap"
OTHER_KEY_NAME = "projects/hkdfguard-test/locations/europe-west1/keyRings/hkdfguard/cryptoKeys/other"
CONTEXT = "hkdfguard.test"
LABEL = b"HkdfGuard-GoogleKms-wrap-v1\0"
MAX_AAD_LENGTH = 64 * 1024

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only.")


# --- Test doubles ---------------------------------------------------------------------------------


class StatusError(Exception):
    """Raised by a handler for the fake to answer with an error status."""

    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        super().__init__(details)
        self.code = code
        self.details = details


class FakeCloudKms:
    """A stand-in for Cloud KMS: a gRPC server on the loopback address implementing only the two calls
    GoogleKmsKeyWrapper makes (any other answers UNIMPLEMENTED), reached through a real
    ``KeyManagementServiceClient``, so the client's own error mapping and retries run as they would
    against Cloud KMS. By default it behaves like a set of symmetric keys, each with a primary version:
    ciphertext is AES-GCM under a local key, binding the key name, the version and the additional
    authenticated data, so Decrypt fails unless all three match. It checks request checksums and sets
    response ones as Cloud KMS does. Each call can be replaced with a handler to return what a test
    needs, or raise :class:`StatusError` for an error status. Every request is recorded."""

    SERVICE = "google.cloud.kms.v1.KeyManagementService"

    def __init__(self) -> None:
        self._aead = AESGCM(AESGCM.generate_key(256))
        self._primary_versions: dict[str, int] = {}
        self._lock = threading.Lock()
        self.on_encrypt: Callable[[EncryptRequest], EncryptResponse] | None = None
        self.on_decrypt: Callable[[DecryptRequest], DecryptResponse] | None = None
        self.encrypt_requests: list[EncryptRequest] = []
        self.decrypt_requests: list[DecryptRequest] = []

        self._server = grpc.server(ThreadPoolExecutor(max_workers=4))
        self._server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(self.SERVICE, {
            "Encrypt": grpc.unary_unary_rpc_method_handler(self._serve(self.encrypt_requests, lambda: self.on_encrypt, self.encrypt_normally),
                                                           request_deserializer=EncryptRequest.deserialize,
                                                           response_serializer=EncryptResponse.serialize),
            "Decrypt": grpc.unary_unary_rpc_method_handler(self._serve(self.decrypt_requests, lambda: self.on_decrypt, self._decrypt),
                                                           request_deserializer=DecryptRequest.deserialize,
                                                           response_serializer=DecryptResponse.serialize),
        }),))
        port = self._server.add_insecure_port("127.0.0.1:0")
        self._server.start()
        self._channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        self.client = KeyManagementServiceClient(transport=KeyManagementServiceGrpcTransport(channel=self._channel))

    def close(self) -> None:
        self._channel.close()
        self._server.stop(None)

    def rotate(self, key_name: str) -> None:
        """Makes a new version of the key its primary, as rotating it in Cloud KMS does."""
        with self._lock:
            self._primary_versions[key_name] = self._primary_version(key_name) + 1

    def _primary_version(self, key_name: str) -> int:
        return self._primary_versions.get(key_name, 1)

    @staticmethod
    def _serve(requests: list[Any], handler: Callable[[], Callable[[Any], Any] | None], default: Callable[[Any], Any]) -> Callable[[Any, Any], Any]:
        def serve(request: Any, context: grpc.ServicerContext) -> Any:
            requests.append(request)
            try:
                return (handler() or default)(request)
            except StatusError as error:
                context.abort(error.code, error.details)
        return serve

    def encrypt_normally(self, request: EncryptRequest) -> EncryptResponse:
        """What the fake answers to an Encrypt request, before a test changes it."""
        self._check(request.plaintext, request.plaintext_crc32c, "plaintext")
        self._check(request.additional_authenticated_data, request.additional_authenticated_data_crc32c, "additional_authenticated_data")
        if not 0 < len(request.plaintext) <= 64 * 1024 or len(request.additional_authenticated_data) > MAX_AAD_LENGTH:
            raise StatusError(grpc.StatusCode.INVALID_ARGUMENT, "The request is too large.")

        version = self._primary_version(request.name)
        nonce = os.urandom(12)
        # version (1) | nonce (12) | ciphertext and tag
        ciphertext = bytes([version]) + nonce + self._aead.encrypt(nonce, request.plaintext, self._aad(request.name, version,
                                                                                                         request.additional_authenticated_data))
        return EncryptResponse(name=f"{request.name}/cryptoKeyVersions/{version}", ciphertext=ciphertext, ciphertext_crc32c=crc32c(ciphertext),
                               verified_plaintext_crc32c=request.plaintext_crc32c is not None,
                               verified_additional_authenticated_data_crc32c=request.additional_authenticated_data_crc32c is not None,
                               protection_level=ProtectionLevel.SOFTWARE)

    def _decrypt(self, request: DecryptRequest) -> DecryptResponse:
        self._check(request.ciphertext, request.ciphertext_crc32c, "ciphertext")
        self._check(request.additional_authenticated_data, request.additional_authenticated_data_crc32c, "additional_authenticated_data")
        ciphertext = request.ciphertext
        if len(ciphertext) < 1 + 12 + 16:
            raise StatusError(grpc.StatusCode.INVALID_ARGUMENT, "Decryption failed: the ciphertext is invalid.")
        try:
            plaintext = self._aead.decrypt(ciphertext[1:13], ciphertext[13:], self._aad(request.name, ciphertext[0], request.additional_authenticated_data))
        except InvalidTag:
            # Cloud KMS gives the same answer for another key, another AAD, and tampering.
            raise StatusError(grpc.StatusCode.INVALID_ARGUMENT, "Decryption failed: the ciphertext is invalid.") from None
        return DecryptResponse(plaintext=plaintext, plaintext_crc32c=crc32c(plaintext), used_primary=ciphertext[0] == self._primary_version(request.name),
                               protection_level=ProtectionLevel.SOFTWARE)

    @staticmethod
    def _check(data: bytes, checksum: int | None, field: str) -> None:
        if checksum is not None and checksum != crc32c(data):
            raise StatusError(grpc.StatusCode.INVALID_ARGUMENT, f"The checksum in field {field}_crc32c did not match the data in field {field}.")

    @staticmethod
    def _aad(key_name: str, version: int, aad: bytes) -> bytes:
        return f"{key_name}\0{version}\0".encode() + aad


class StubClient:
    """A client whose calls fail on the client side, before any request is sent - what an application's
    own client could do that the fake Cloud KMS, behind a real client, can't - or return nothing."""

    def __init__(self, error: BaseException | None) -> None:
        self.error = error

    def encrypt(self, *args: Any, **kwargs: Any) -> Any:
        return self._fail()

    def decrypt(self, *args: Any, **kwargs: Any) -> Any:
        return self._fail()

    def _fail(self) -> None:
        if self.error is not None:
            raise self.error
        return None


@pytest.fixture
def kms() -> Iterator[FakeCloudKms]:
    fake = FakeCloudKms()
    try:
        yield fake
    finally:
        fake.close()


def wrapper_over(client: CloudKmsClient, key_name: str = KEY_NAME, context: str | None = CONTEXT,
                 key_file_trust: KeyFileTrust | None = None) -> GoogleKmsKeyWrapper:
    return GoogleKmsKeyWrapper(client, key_name, context, key_file_trust)


def wrap_new(wrapper: GoogleKmsKeyWrapper) -> bytes:
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    return bytes(wrapped[:length])


def filled(size: int) -> bytearray:
    return bytearray(b"\xa5" * size)


# --- Construction ---------------------------------------------------------------------------------


def test_the_wrapper_is_a_key_wrapper(kms: FakeCloudKms) -> None:
    assert isinstance(wrapper_over(kms.client), KeyWrapper)


@pytest.mark.parametrize("key_name", [
    "",
    " ",
    "dek-wrap",
    "projects/p/locations/l/keyRings/r",
    "projects/p/locations/l/keyRings/r/cryptoKeys/",
    "projects//locations/l/keyRings/r/cryptoKeys/k",
    "projects/p/locations//keyRings/r/cryptoKeys/k",
    "projects/p/locations/l/keyRings//cryptoKeys/k",
    "/projects/p/locations/l/keyRings/r/cryptoKeys/k",
    "projects/p/locations/l/keyRings/r/cryptoKeys/k/",
    " projects/p/locations/l/keyRings/r/cryptoKeys/k",
    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    "//cloudkms.googleapis.com/projects/p/locations/l/keyRings/r/cryptoKeys/k",
])
def test_constructor_rejects_a_name_that_is_not_a_keys(kms: FakeCloudKms, key_name: str) -> None:
    with pytest.raises(ValueError, match="isn't a Cloud KMS key's resource name"):
        wrapper_over(kms.client, key_name)


@pytest.mark.parametrize(("client", "key_name", "context", "trust", "expected"), [
    (None, KEY_NAME, CONTEXT, None, TypeError),
    ("kms", None, CONTEXT, None, TypeError),
    ("kms", b"projects/p/locations/l/keyRings/r/cryptoKeys/k", CONTEXT, None, TypeError),
    ("kms", KEY_NAME, b"context", None, TypeError),
    ("kms", KEY_NAME, "\ud800", None, ValueError),
    ("kms", KEY_NAME, "x" * (GoogleKmsKeyWrapper.MAX_CONTEXT_LENGTH + 1), None, ValueError),
    ("kms", KEY_NAME, "é" * (GoogleKmsKeyWrapper.MAX_CONTEXT_LENGTH // 2 + 1), None, ValueError),
    ("kms", KEY_NAME, CONTEXT, "everyone", TypeError),
], ids=["no client", "no key name", "key name as bytes", "context as bytes", "lone surrogate", "context too long", "context too long in utf-8",
        "trust not a KeyFileTrust"])
def test_constructor_rejects_missing_and_malformed_arguments(kms: FakeCloudKms, client: Any, key_name: Any, context: Any, trust: Any,
                                                             expected: type[Exception]) -> None:
    with pytest.raises(expected):
        GoogleKmsKeyWrapper(kms.client if client == "kms" else client, key_name, context, trust)


def test_the_longest_context_fits_cloud_kms_aad_limit(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client, context="x" * GoogleKmsKeyWrapper.MAX_CONTEXT_LENGTH)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrap_new(wrapper), revealed) == 32
    assert len(kms.encrypt_requests[0].additional_authenticated_data) <= MAX_AAD_LENGTH


# --- Wrap and unwrap ------------------------------------------------------------------------------


def test_wrap_then_unwrap_round_trips_the_dek(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)
    dek = os.urandom(32)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(dek, wrapped)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrapped[:length], revealed) == 32
    assert revealed == dek


@pytest.mark.parametrize("kind", [bytes, bytearray, memoryview])
def test_wrap_and_unwrap_take_any_buffer(kms: FakeCloudKms, kind: Callable[[bytes], Any]) -> None:
    wrapper = wrapper_over(kms.client)
    dek = os.urandom(32)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(kind(dek), memoryview(wrapped))
    revealed = bytearray(32)

    assert wrapper.unwrap(kind(bytes(wrapped[:length])), memoryview(revealed)) == 32
    assert revealed == dek


def test_wrap_sends_the_key_the_labelled_context_and_checksums_and_leaves_the_plaintext_alone(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)
    dek = bytearray(os.urandom(32))
    original = bytes(dek)

    wrapper.wrap(dek, bytearray(WrappedKeyLimits.MAX_BYTES))

    [request] = kms.encrypt_requests
    assert request.name == KEY_NAME
    assert request.plaintext == original
    assert request.plaintext_crc32c == crc32c(original)
    assert request.additional_authenticated_data == LABEL + CONTEXT.encode()
    assert request.additional_authenticated_data_crc32c == crc32c(LABEL + CONTEXT.encode())
    # The caller's buffer is the caller's to zero.
    assert dek == original


def test_wrap_retried_by_the_client_sends_the_plaintext_again(kms: FakeCloudKms) -> None:
    # The client retries UNAVAILABLE by default; what it resends must still be the key.
    answers = iter([None])

    def unavailable_once(request: EncryptRequest) -> EncryptResponse:
        if next(answers, True) is None:
            raise StatusError(grpc.StatusCode.UNAVAILABLE, "Try again.")
        return kms.encrypt_normally(request)

    kms.on_encrypt = unavailable_once
    wrapper = wrapper_over(kms.client)
    dek = os.urandom(32)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(dek, wrapped)
    revealed = bytearray(32)

    assert [request.plaintext for request in kms.encrypt_requests] == [dek, dek]
    assert wrapper.unwrap(wrapped[:length], revealed) == 32
    assert revealed == dek


def test_unwrap_pins_the_key_and_sends_checksums(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)
    wrapped = wrap_new(wrapper)

    wrapper.unwrap(wrapped, bytearray(32))

    [request] = kms.decrypt_requests
    assert request.name == KEY_NAME
    assert request.ciphertext == wrapped
    assert request.ciphertext_crc32c == crc32c(wrapped)
    assert request.additional_authenticated_data == LABEL + CONTEXT.encode()
    assert request.additional_authenticated_data_crc32c == crc32c(LABEL + CONTEXT.encode())


def test_a_none_and_an_empty_context_bind_the_label_only(kms: FakeCloudKms) -> None:
    without = wrapper_over(kms.client, context=None)
    empty = wrapper_over(kms.client, context="")

    wrapped = wrap_new(without)
    revealed = bytearray(32)

    assert empty.unwrap(wrapped, revealed) == 32
    assert kms.encrypt_requests[0].additional_authenticated_data == LABEL
    assert kms.decrypt_requests[0].additional_authenticated_data == LABEL


def test_the_context_is_bound_as_utf_8(kms: FakeCloudKms) -> None:
    wrapper_over(kms.client, context="café \U0001f511").generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))

    assert kms.encrypt_requests[0].additional_authenticated_data == LABEL + "café \U0001f511".encode()


def test_generate_and_wrap_wraps_a_fresh_32_byte_dek(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)

    first = wrap_new(wrapper)
    second = wrap_new(wrapper)

    keys = [request.plaintext for request in kms.encrypt_requests]
    assert [len(key) for key in keys] == [32, 32]
    assert keys[0] != keys[1]
    assert first != second
    revealed = bytearray(32)
    wrapper.unwrap(first, revealed)
    assert revealed == keys[0]


def test_key_files_from_every_version_still_unwrap_after_the_key_is_rotated(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)
    before = wrap_new(wrapper)
    kms.rotate(KEY_NAME)
    after = wrap_new(wrapper)

    assert wrapper.unwrap(before, bytearray(32)) == 32
    assert wrapper.unwrap(after, bytearray(32)) == 32
    assert before[0] == 1
    assert after[0] == 2


def test_unwrap_under_another_key_fails_and_zeroes_the_result(kms: FakeCloudKms) -> None:
    wrapped = wrap_new(wrapper_over(kms.client, OTHER_KEY_NAME))
    result = filled(32)

    with pytest.raises(CryptographicError, match="INVALID_ARGUMENT"):
        wrapper_over(kms.client).unwrap(wrapped, result)

    assert ArrayUtility.is_null_or_empty(result)
    assert kms.decrypt_requests[0].name == KEY_NAME


def test_unwrap_under_another_context_fails(kms: FakeCloudKms) -> None:
    wrapped = wrap_new(wrapper_over(kms.client))

    with pytest.raises(CryptographicError, match="INVALID_ARGUMENT"):
        wrapper_over(kms.client, context="hkdfguard.other").unwrap(wrapped, bytearray(32))


def test_unwrap_a_ciphertext_made_without_the_label_is_refused(kms: FakeCloudKms) -> None:
    # Something the same key encrypted for another purpose, with the context as its whole AAD.
    made = kms.client.encrypt(request=EncryptRequest(name=KEY_NAME, plaintext=os.urandom(32), additional_authenticated_data=CONTEXT.encode()))

    with pytest.raises(CryptographicError, match="INVALID_ARGUMENT"):
        wrapper_over(kms.client).unwrap(made.ciphertext, bytearray(32))


def test_unwrap_when_tampered_fails(kms: FakeCloudKms) -> None:
    wrapped = bytearray(wrap_new(wrapper_over(kms.client)))
    wrapped[-1] ^= 1

    with pytest.raises(CryptographicError, match="Decryption failed"):
        wrapper_over(kms.client).unwrap(wrapped, bytearray(32))


@pytest.mark.parametrize("size", [0, WrappedKeyLimits.MAX_BYTES + 1])
def test_unwrap_out_of_bounds_fails_without_calling_kms(kms: FakeCloudKms, size: int) -> None:
    result = filled(32)

    with pytest.raises(CryptographicError, match=f"got {size}"):
        wrapper_over(kms.client).unwrap(bytes(size), result)

    assert kms.decrypt_requests == []
    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_when_the_key_does_not_fit_fails_and_zeroes_the_result(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)
    wrapped = wrap_new(wrapper)
    result = filled(31)

    with pytest.raises(ValueError, match="32 bytes; result holds 31"):
        wrapper.unwrap(wrapped, result)

    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_when_kms_returns_no_plaintext_fails(kms: FakeCloudKms) -> None:
    kms.on_decrypt = lambda request: DecryptResponse(plaintext_crc32c=0)
    result = filled(32)

    with pytest.raises(CryptographicError, match="returned no plaintext"):
        wrapper_over(kms.client).unwrap(bytes(64), result)

    assert ArrayUtility.is_null_or_empty(result)


@pytest.mark.parametrize("missing", [True, False])
def test_unwrap_when_the_plaintext_does_not_match_its_checksum_fails(kms: FakeCloudKms, missing: bool) -> None:
    plaintext = os.urandom(32)
    kms.on_decrypt = lambda request: (DecryptResponse(plaintext=plaintext) if missing
                                      else DecryptResponse(plaintext=plaintext, plaintext_crc32c=crc32c(plaintext) ^ 1))
    result = filled(32)

    with pytest.raises(CryptographicError, match="doesn't match its checksum"):
        wrapper_over(kms.client).unwrap(bytes(64), result)

    assert ArrayUtility.is_null_or_empty(result)


@pytest.mark.parametrize("size", [0, GoogleKmsKeyWrapper.MAX_PLAINTEXT_LENGTH + 1])
def test_wrap_rejects_a_plaintext_kms_would_refuse(kms: FakeCloudKms, size: int) -> None:
    with pytest.raises(ValueError, match=f"got {size}"):
        wrapper_over(kms.client).wrap(bytes(size), bytearray(WrappedKeyLimits.MAX_BYTES))

    assert kms.encrypt_requests == []


def test_wrap_takes_the_largest_plaintext_kms_accepts(kms: FakeCloudKms) -> None:
    # Its real ciphertext would be over the key file limit, so the fake answers with a short one.
    def respond(request: EncryptRequest) -> EncryptResponse:
        response = kms.encrypt_normally(request)
        response.ciphertext = b"c" * 100
        response.ciphertext_crc32c = crc32c(response.ciphertext)
        return response

    kms.on_encrypt = respond

    assert wrapper_over(kms.client).wrap(bytes(GoogleKmsKeyWrapper.MAX_PLAINTEXT_LENGTH), bytearray(100)) == 100
    assert len(kms.encrypt_requests[0].plaintext) == GoogleKmsKeyWrapper.MAX_PLAINTEXT_LENGTH


def test_wrap_when_the_result_is_too_small_fails(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)
    result = filled(10)

    with pytest.raises(ValueError, match="result holds 10"):
        wrapper.wrap(os.urandom(32), result)

    assert result == filled(10)


def responding(kms: FakeCloudKms, **changes: Any) -> Callable[[EncryptRequest], EncryptResponse]:
    """An Encrypt handler answering as the fake would, with the given fields changed."""

    def respond(request: EncryptRequest) -> EncryptResponse:
        response = kms.encrypt_normally(request)
        for name, value in changes.items():
            setattr(response, name, value)
        return response
    return respond


@pytest.mark.parametrize("reported", [
    f"{OTHER_KEY_NAME}/cryptoKeyVersions/1",
    f"{OTHER_KEY_NAME}/cryptoKeyVersions/123456",
    f"{KEY_NAME}2/cryptoKeyVersions/1",
    KEY_NAME,
    f"{KEY_NAME}/cryptoKeyVersions/",
    f"{KEY_NAME}/cryptoKeyVersions/1/extra",
    "",
])
def test_wrap_refuses_a_response_from_any_version_but_this_keys(kms: FakeCloudKms, reported: str) -> None:
    kms.on_encrypt = responding(kms, name=reported)

    with pytest.raises(CryptographicError, match="reported key version"):
        wrapper_over(kms.client).wrap(os.urandom(32), bytearray(WrappedKeyLimits.MAX_BYTES))


@pytest.mark.parametrize(("plaintext_verified", "aad_verified"), [(False, True), (True, False), (False, False)])
def test_wrap_refuses_a_response_that_did_not_verify_the_request_checksums(kms: FakeCloudKms, plaintext_verified: bool, aad_verified: bool) -> None:
    kms.on_encrypt = responding(kms, verified_plaintext_crc32c=plaintext_verified, verified_additional_authenticated_data_crc32c=aad_verified)

    with pytest.raises(CryptographicError, match="didn't verify the request's checksums"):
        wrapper_over(kms.client).wrap(os.urandom(32), bytearray(WrappedKeyLimits.MAX_BYTES))


@pytest.mark.parametrize("missing", [True, False])
def test_wrap_refuses_a_ciphertext_that_does_not_match_its_checksum(kms: FakeCloudKms, missing: bool) -> None:
    def respond(request: EncryptRequest) -> EncryptResponse:
        response = kms.encrypt_normally(request)
        response.ciphertext_crc32c = None if missing else crc32c(response.ciphertext) ^ 1
        return response

    kms.on_encrypt = respond
    result = filled(WrappedKeyLimits.MAX_BYTES)

    with pytest.raises(CryptographicError, match="doesn't match its checksum"):
        wrapper_over(kms.client).wrap(os.urandom(32), result)

    assert result == filled(WrappedKeyLimits.MAX_BYTES)


def test_wrap_when_kms_returns_no_ciphertext_fails(kms: FakeCloudKms) -> None:
    kms.on_encrypt = responding(kms, ciphertext=b"", ciphertext_crc32c=0)

    with pytest.raises(CryptographicError, match="returned no ciphertext"):
        wrapper_over(kms.client).wrap(os.urandom(32), bytearray(WrappedKeyLimits.MAX_BYTES))


def test_wrap_refuses_a_ciphertext_over_the_key_file_limit(kms: FakeCloudKms) -> None:
    ciphertext = bytes(WrappedKeyLimits.MAX_BYTES + 1)
    kms.on_encrypt = responding(kms, ciphertext=ciphertext, ciphertext_crc32c=crc32c(ciphertext))

    with pytest.raises(CryptographicError, match=f"returned {WrappedKeyLimits.MAX_BYTES + 1} bytes"):
        wrapper_over(kms.client).wrap(os.urandom(32), bytearray(2 * WrappedKeyLimits.MAX_BYTES))


# --- Failures -------------------------------------------------------------------------------------


@pytest.mark.parametrize(("code", "operation"), [(grpc.StatusCode.PERMISSION_DENIED, "wrap"), (grpc.StatusCode.FAILED_PRECONDITION, "unwrap"),
                                                 (grpc.StatusCode.NOT_FOUND, "unwrap")])
def test_a_service_refusal_becomes_a_cryptographic_error_naming_the_status(kms: FakeCloudKms, code: grpc.StatusCode, operation: str) -> None:
    def refuse(request: Any) -> Any:
        raise StatusError(code, "Refused by FakeCloudKms.")

    kms.on_encrypt = kms.on_decrypt = refuse
    wrapper = wrapper_over(kms.client)

    with pytest.raises(CryptographicError) as raised:
        if operation == "wrap":
            wrapper.wrap(os.urandom(32), bytearray(WrappedKeyLimits.MAX_BYTES))
        else:
            wrapper.unwrap(bytes(64), bytearray(32))

    assert str(raised.value) == f"Cloud KMS {operation} failed for key '{KEY_NAME}': {code.name}: Refused by FakeCloudKms."
    assert isinstance(raised.value.__cause__, GoogleAPICallError)


def test_an_api_error_without_a_grpc_status_is_named_by_its_http_status() -> None:
    # As the client raises them over its REST transport.
    refusal = from_http_status(403, "Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied.")  # type: ignore[no-untyped-call]

    with pytest.raises(CryptographicError) as raised:
        wrapper_over(StubClient(refusal)).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))

    assert str(raised.value) == (f"Cloud KMS wrap failed for key '{KEY_NAME}': HTTP 403: Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' "
                                 "denied.")


@pytest.mark.parametrize("failure", [RefreshError("The credential could not get a token."),  # type: ignore[no-untyped-call]
                                     DefaultCredentialsError("Your default credentials were not found."),  # type: ignore[no-untyped-call]
                                     RetryError("Timeout of 60.0s exceeded", cause=None),  # type: ignore[no-untyped-call]
                                     OSError("The network is unreachable.")])
def test_a_client_side_failure_becomes_a_cryptographic_error(failure: Exception) -> None:
    result = filled(32)

    with pytest.raises(CryptographicError, match=f"Cloud KMS unwrap failed for key '{KEY_NAME}': ") as raised:
        wrapper_over(StubClient(failure)).unwrap(bytes(64), result)

    assert raised.value.__cause__ is failure
    assert ArrayUtility.is_null_or_empty(result)


def test_a_cryptographic_error_from_the_client_is_not_wrapped_again() -> None:
    failure = CryptographicError("Already a CryptographicError.")

    with pytest.raises(CryptographicError) as raised:
        wrapper_over(StubClient(failure)).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))

    assert raised.value is failure


def test_keyboard_interrupt_is_left_as_it_is_and_the_result_zeroed() -> None:
    result = filled(32)

    with pytest.raises(KeyboardInterrupt):
        wrapper_over(StubClient(KeyboardInterrupt())).unwrap(bytes(64), result)

    assert ArrayUtility.is_null_or_empty(result)


@pytest.mark.parametrize("operation", ["wrap", "unwrap"])
def test_a_client_that_returns_no_response_fails(operation: str) -> None:
    wrapper = wrapper_over(StubClient(None))

    with pytest.raises(CryptographicError, match=f"Cloud KMS {operation} for key '{KEY_NAME}' returned no response"):
        if operation == "wrap":
            wrapper.wrap(os.urandom(32), bytearray(WrappedKeyLimits.MAX_BYTES))
        else:
            wrapper.unwrap(bytes(64), bytearray(32))


# --- Checksums ------------------------------------------------------------------------------------


def test_crc32c_matches_the_castagnoli_check_value() -> None:
    assert crc32c(b"123456789") == 0xE3069283
    assert crc32c(b"") == 0
    assert crc32c(bytearray(32)) == 0x8A9136AA
    assert crc32c(memoryview(b"\xff" * 32)) == 0x62A8AB43


# --- Crypto provider ------------------------------------------------------------------------------


def test_a_crypto_provider_generates_and_reveals_its_dek_through_kms(kms: FakeCloudKms) -> None:
    wrapper = wrapper_over(kms.client)
    with AesGcmCryptoProviderFactory().create_ephemeral(wrapper, 60) as provider:
        expected = b"hello, cloud kms"
        # Encrypt zeroes the plaintext it is given, so it gets a copy.
        plaintext = bytearray(expected)
        encrypted = bytearray(provider.get_encrypted_allocation_length(len(plaintext)))
        encrypted_length = provider.encrypt(plaintext, encrypted)
        decrypted = bytearray(provider.get_decrypted_allocation_length(encrypted_length))
        decrypted_length = provider.decrypt(encrypted[:encrypted_length], decrypted)

        assert decrypted[:decrypted_length] == expected
    assert len(kms.encrypt_requests) == 1


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
        path.write_bytes(os.urandom(113))
        yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_read_key_file_by_default_refuses_a_file_the_current_user_could_have_replaced(kms: FakeCloudKms, user_writable_key_file: Path) -> None:
    with pytest.raises(PermissionError, match="not trusted"):
        wrapper_over(kms.client).read_key_file(user_writable_key_file)


def test_read_key_file_with_no_trust_given_trusts_administrators_only(kms: FakeCloudKms, user_writable_key_file: Path) -> None:
    # The same refusal as the default: None is ADMINISTRATORS_ONLY, never "anyone".
    with pytest.raises(PermissionError, match="not trusted"):
        GoogleKmsKeyWrapper(kms.client, KEY_NAME, CONTEXT, None).read_key_file(user_writable_key_file)


@pytest.mark.parametrize(("path", "expected"), [(None, TypeError), ("", ValueError)])
def test_read_key_file_refuses_a_missing_path(kms: FakeCloudKms, path: object, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        wrapper_over(kms.client).read_key_file(path)  # type: ignore[arg-type]


def current_user_sid() -> str:
    whoami = os.path.join(os.environ["SYSTEMROOT"], "System32", "whoami.exe")
    output = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout.strip()
    return output.rsplit(",", 1)[1].strip('"')  # "DOMAIN\name","S-1-5-21-..."


@windows_only
def test_read_key_file_with_the_writers_account_trusted_reads_the_file_and_it_reveals(kms: FakeCloudKms, user_writable_key_file: Path) -> None:
    wrapper = wrapper_over(kms.client, key_file_trust=KeyFileTrust(windows_principals=[current_user_sid()]))
    wrapped = wrap_new(wrapper)
    user_writable_key_file.write_bytes(wrapped)

    read = wrapper.read_key_file(user_writable_key_file)

    assert read == wrapped
    assert wrapper.unwrap(read, bytearray(32)) == 32


@windows_only
def test_read_key_file_trusting_everyone_is_refused(kms: FakeCloudKms, user_writable_key_file: Path) -> None:
    wrapper = wrapper_over(kms.client, key_file_trust=KeyFileTrust(windows_principals=["S-1-1-0"]))

    with pytest.raises(ValueError, match="every account"):
        wrapper.read_key_file(user_writable_key_file)
