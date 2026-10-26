from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Buffer, Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import botocore.session
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from botocore.stub import Stubber
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, WrappedKeyLimits
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.keywrapping.awskms import AwsKmsKeyWrapper, KeyFileTrust, KmsClient
from hkdfguard_test_support import long_path

KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
CONTEXT = {"purpose": "hkdfguard.test"}

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only.")

type Handler = Callable[[dict[str, Any]], Mapping[str, Any]]


# --- Test doubles ---------------------------------------------------------------------------------


class FakeKms:
    """An in-process stand-in for KMS, implementing only the three calls AwsKmsKeyWrapper makes, with
    keyword arguments as a botocore client takes them. By default it behaves like a symmetric KMS key:
    ciphertext is AES-GCM under a local key, binding the key ID and encryption context, so Decrypt fails
    unless both match. Each call can be replaced with a handler that returns or raises what a test
    needs. Every request is recorded as received; Encrypt's plaintext is also copied when it arrives,
    since the wrapper zeroes the buffer it sent once the call returns."""

    def __init__(self) -> None:
        self._key = AESGCM(AESGCM.generate_key(bit_length=256))
        self.on_encrypt: Handler | None = None
        self.on_decrypt: Handler | None = None
        self.on_generate: Handler | None = None
        self.encrypt_requests: list[dict[str, Any]] = []
        self.encrypt_plaintexts: list[bytes] = []
        self.decrypt_requests: list[dict[str, Any]] = []
        self.generate_requests: list[dict[str, Any]] = []

    def encrypt(self, **request: Any) -> Mapping[str, Any]:
        self.encrypt_requests.append(request)
        self.encrypt_plaintexts.append(bytes(request["Plaintext"]))
        if self.on_encrypt is not None:
            return self.on_encrypt(request)
        return {"KeyId": request["KeyId"], "CiphertextBlob": self._seal(bytes(request["Plaintext"]), request["KeyId"], request.get("EncryptionContext"))}

    def decrypt(self, **request: Any) -> Mapping[str, Any]:
        self.decrypt_requests.append(request)
        if self.on_decrypt is not None:
            return self.on_decrypt(request)
        # Immutable bytes, as botocore returns it.
        return {"KeyId": request["KeyId"], "Plaintext": self._open(request["CiphertextBlob"], request["KeyId"], request.get("EncryptionContext"))}

    def generate_data_key_without_plaintext(self, **request: Any) -> Mapping[str, Any]:
        self.generate_requests.append(request)
        if self.on_generate is not None:
            return self.on_generate(request)
        return {"KeyId": request["KeyId"], "CiphertextBlob": self._seal(os.urandom(32), request["KeyId"], request.get("EncryptionContext"))}

    def _seal(self, plaintext: bytes, key_id: str, context: Mapping[str, str] | None) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._key.encrypt(nonce, plaintext, self._aad(key_id, context))

    def _open(self, sealed: bytes, key_id: str, context: Mapping[str, str] | None) -> bytes:
        if len(sealed) < 28:
            raise service_error("InvalidCiphertextException", 400)
        try:
            return self._key.decrypt(sealed[:12], sealed[12:], self._aad(key_id, context))
        except InvalidTag:
            # Real KMS reports a key mismatch as IncorrectKeyException and a context mismatch or
            # tampering as InvalidCiphertextException; one is enough for a fake.
            raise service_error("InvalidCiphertextException", 400) from None

    @staticmethod
    def _aad(key_id: str, context: Mapping[str, str] | None) -> bytes:
        return (key_id + "".join(f"\0{key}={value}" for key, value in sorted((context or {}).items()))).encode("utf-8")


def botocore_client() -> Any:
    """A real botocore KMS client. Creating one reads the service model from botocore's own files and
    makes no request; every test that calls through it stubs the response (Stubber) or fails before
    anything is sent."""
    return botocore.session.get_session().create_client("kms", region_name="us-east-1", aws_access_key_id="testing",
                                                        aws_secret_access_key="testing")


def service_error(code: str | None, status: int, operation: str = "Decrypt", name: str | None = None) -> ClientError:
    """The exception botocore raises for a KMS error response: the client's modeled exception class
    when ``name`` is given, otherwise a plain ClientError."""
    error: dict[str, Any] = {"Message": f"{code} from FakeKms."}
    if code is not None:
        error["Code"] = code
    response = {"Error": error, "ResponseMetadata": {"RequestId": "fake-request-id", "HTTPStatusCode": status}}
    error_type = ClientError if name is None else getattr(botocore_client().exceptions, name)
    return error_type(response, operation)


def raise_(error: BaseException) -> Handler:
    def handler(request: dict[str, Any]) -> Mapping[str, Any]:
        raise error
    return handler


def wrap_with(wrapper: AwsKmsKeyWrapper, dek: Buffer) -> bytes:
    result = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(dek, result)
    return bytes(result[:length])


# --- Construction ---------------------------------------------------------------------------------


def test_the_constructor_refuses_missing_or_invalid_arguments() -> None:
    kms = FakeKms()

    with pytest.raises(TypeError):
        AwsKmsKeyWrapper(None, KEY_ARN)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AwsKmsKeyWrapper(kms, None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AwsKmsKeyWrapper(kms, b"alias/x")  # type: ignore[arg-type]
    for key_id in ("", " ", "\t "):
        with pytest.raises(ValueError, match="key_id"):
            AwsKmsKeyWrapper(kms, key_id)
    with pytest.raises(ValueError, match="must not be empty"):
        AwsKmsKeyWrapper(kms, KEY_ARN, {"": "x"})
    with pytest.raises(ValueError, match="must not be empty"):
        AwsKmsKeyWrapper(kms, KEY_ARN, {None: "x"})  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        AwsKmsKeyWrapper(kms, KEY_ARN, {1: "x"})  # type: ignore[dict-item]
    with pytest.raises(TypeError, match='encryption_context\\["k"\\] must not be None'):
        AwsKmsKeyWrapper(kms, KEY_ARN, {"k": None})  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        AwsKmsKeyWrapper(kms, KEY_ARN, {"k": 1})  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        AwsKmsKeyWrapper(kms, KEY_ARN, [("k", "v")])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AwsKmsKeyWrapper(kms, KEY_ARN, key_file_trust="S-1-5-18")  # type: ignore[arg-type]


def test_it_is_a_key_wrapper_over_any_client_with_the_three_calls() -> None:
    client: KmsClient = FakeKms()
    assert isinstance(AwsKmsKeyWrapper(client, KEY_ARN), KeyWrapper)
    assert AwsKmsKeyWrapper.GENERATED_KEY_LENGTH == 32
    assert AwsKmsKeyWrapper.MAX_PLAINTEXT_LENGTH == 4096


# --- Wrap, unwrap, generate -------------------------------------------------------------------------


def test_wrap_then_unwrap_round_trips_the_dek() -> None:
    wrapper = AwsKmsKeyWrapper(FakeKms(), KEY_ARN, CONTEXT)
    dek = os.urandom(32)

    revealed = bytearray(32)
    assert wrapper.unwrap(wrap_with(wrapper, dek), revealed) == 32
    assert revealed == dek


def test_wrap_sends_the_key_context_and_algorithm_and_zeroes_its_copy_of_the_plaintext() -> None:
    kms = FakeKms()
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN, CONTEXT)
    dek = bytearray(os.urandom(32))

    wrap_with(wrapper, dek)

    assert len(kms.encrypt_requests) == 1
    request = kms.encrypt_requests[0]
    assert request["KeyId"] == KEY_ARN
    assert request["EncryptionContext"] == CONTEXT
    assert request["EncryptionAlgorithm"] == "SYMMETRIC_DEFAULT"
    assert kms.encrypt_plaintexts[0] == dek
    # The buffer sent is the wrapper's own copy - a bytearray, never an immutable bytes - zeroed once the call returned.
    assert isinstance(request["Plaintext"], bytearray)
    assert request["Plaintext"] is not dek
    assert ArrayUtility.is_null_or_empty(request["Plaintext"])
    # The caller's own buffer is the caller's to zero.
    assert not ArrayUtility.is_null_or_empty(dek)


def test_wrap_zeroes_its_copy_of_the_plaintext_when_kms_refuses() -> None:
    kms = FakeKms()
    kms.on_encrypt = raise_(service_error("AccessDeniedException", 400, "Encrypt"))
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN)

    with pytest.raises(CryptographicError):
        wrap_with(wrapper, os.urandom(32))
    assert ArrayUtility.is_null_or_empty(kms.encrypt_requests[0]["Plaintext"])


@pytest.mark.parametrize("plaintext", [os.urandom(32), bytearray(os.urandom(32)), memoryview(os.urandom(64))[16:48]])
def test_wrap_accepts_any_buffer_the_key_wrapper_contract_allows(plaintext: bytes | bytearray | memoryview) -> None:
    # As NativeHkdfKeyWrapperV1 does: wrap never modifies its plaintext, so immutable bytes are fine here.
    kms = FakeKms()
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN)

    revealed = bytearray(32)
    wrapper.unwrap(wrap_with(wrapper, plaintext), revealed)
    assert revealed == bytes(plaintext)


def test_with_no_context_none_is_sent() -> None:
    kms = FakeKms()
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN, {})

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    wrapper.unwrap(wrapped[:length], bytearray(32))
    wrap_with(wrapper, os.urandom(32))

    assert "EncryptionContext" not in kms.generate_requests[0]
    assert "EncryptionContext" not in kms.decrypt_requests[0]
    assert "EncryptionContext" not in kms.encrypt_requests[0]
    assert "EncryptionContext" not in AwsKmsKeyWrapper(kms, KEY_ARN)._request()


def test_the_context_is_copied_at_construction_and_per_request() -> None:
    kms = FakeKms()
    context = dict(CONTEXT)
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN, context)
    context["purpose"] = "changed"

    wrapper.generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))
    kms.generate_requests[0]["EncryptionContext"]["purpose"] = "changed by the pipeline"
    wrapper.generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))

    assert kms.generate_requests[1]["EncryptionContext"] == CONTEXT


def test_the_context_is_sent_sorted_by_key() -> None:
    kms = FakeKms()
    AwsKmsKeyWrapper(kms, KEY_ARN, {"b": "2", "a": "1", "B": "3"}).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))

    assert list(kms.generate_requests[0]["EncryptionContext"]) == ["B", "a", "b"]


def test_generate_and_wrap_asks_kms_for_a_wrapped_aes_256_key_only() -> None:
    kms = FakeKms()
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN, CONTEXT)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrapped[:length], revealed) == AwsKmsKeyWrapper.GENERATED_KEY_LENGTH
    assert kms.generate_requests == [{"KeyId": KEY_ARN, "KeySpec": "AES_256", "EncryptionContext": CONTEXT}]
    assert kms.encrypt_requests == []
    assert not ArrayUtility.is_null_or_empty(revealed)


def test_unwrap_pins_the_key() -> None:
    kms = FakeKms()
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN, CONTEXT)
    wrapped = wrap_with(wrapper, os.urandom(32))

    wrapper.unwrap(bytearray(wrapped), bytearray(32))

    assert kms.decrypt_requests == [{"KeyId": KEY_ARN, "CiphertextBlob": wrapped, "EncryptionContext": CONTEXT,
                                     "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}]


def test_unwrap_under_another_key_fails_and_zeroes_the_result() -> None:
    kms = FakeKms()
    wrapped = wrap_with(AwsKmsKeyWrapper(kms, "alias/other", CONTEXT), os.urandom(32))

    result = bytearray(b"\xaa" * 32)
    with pytest.raises(CryptographicError) as error:
        AwsKmsKeyWrapper(kms, KEY_ARN, CONTEXT).unwrap(wrapped, result)

    assert isinstance(error.value.__cause__, ClientError)
    assert str(error.value) == f"AWS KMS unwrap failed for key '{KEY_ARN}': InvalidCiphertextException (HTTP 400)."
    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_under_another_context_fails() -> None:
    kms = FakeKms()
    wrapped = wrap_with(AwsKmsKeyWrapper(kms, KEY_ARN, CONTEXT), os.urandom(32))

    with pytest.raises(CryptographicError):
        AwsKmsKeyWrapper(kms, KEY_ARN, {"purpose": "other"}).unwrap(wrapped, bytearray(32))
    with pytest.raises(CryptographicError):
        AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(wrapped, bytearray(32))


def test_unwrap_when_tampered_fails() -> None:
    wrapper = AwsKmsKeyWrapper(FakeKms(), KEY_ARN, CONTEXT)
    wrapped = bytearray(wrap_with(wrapper, os.urandom(32)))
    wrapped[-1] ^= 1

    with pytest.raises(CryptographicError):
        wrapper.unwrap(wrapped, bytearray(32))


@pytest.mark.parametrize("size", [0, WrappedKeyLimits.MAX_BYTES + 1])
def test_unwrap_out_of_bounds_fails_without_calling_kms_and_zeroes_the_result(size: int) -> None:
    kms = FakeKms()
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(CryptographicError, match=f"got {size}"):
        AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(bytes(size), result)

    assert kms.decrypt_requests == []
    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_when_the_key_does_not_fit_fails_and_zeroes_the_result() -> None:
    wrapper = AwsKmsKeyWrapper(FakeKms(), KEY_ARN)
    wrapped = wrap_with(wrapper, os.urandom(32))

    result = bytearray(b"\xaa" * 16)
    with pytest.raises(ValueError, match="result holds 16"):
        wrapper.unwrap(wrapped, result)
    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_writes_into_a_view_of_a_larger_buffer() -> None:
    wrapper = AwsKmsKeyWrapper(FakeKms(), KEY_ARN)
    dek = os.urandom(32)
    backing = bytearray(64)

    assert wrapper.unwrap(wrap_with(wrapper, dek), memoryview(backing)[16:]) == 32
    assert backing[16:48] == dek


def test_unwrap_when_kms_returns_no_plaintext_fails() -> None:
    kms = FakeKms()
    kms.on_decrypt = lambda request: {"KeyId": KEY_ARN}
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(CryptographicError, match="returned no plaintext"):
        AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(bytes(64), result)
    assert ArrayUtility.is_null_or_empty(result)


def test_unwrap_zeroes_the_result_whatever_the_failure() -> None:
    kms = FakeKms()
    kms.on_decrypt = raise_(KeyboardInterrupt())
    result = bytearray(b"\xaa" * 32)

    with pytest.raises(KeyboardInterrupt):
        AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(bytes(64), result)
    assert ArrayUtility.is_null_or_empty(result)


@pytest.mark.parametrize("size", [0, AwsKmsKeyWrapper.MAX_PLAINTEXT_LENGTH + 1])
def test_wrap_refuses_a_plaintext_kms_would_refuse(size: int) -> None:
    kms = FakeKms()

    with pytest.raises(ValueError, match=f"got {size}"):
        AwsKmsKeyWrapper(kms, KEY_ARN).wrap(bytes(size), bytearray(WrappedKeyLimits.MAX_BYTES))
    assert kms.encrypt_requests == []


def test_wrap_accepts_the_largest_plaintext_kms_does() -> None:
    kms = FakeKms()
    kms.on_encrypt = lambda request: {"CiphertextBlob": bytes(200)}

    assert AwsKmsKeyWrapper(kms, KEY_ARN).wrap(bytes(AwsKmsKeyWrapper.MAX_PLAINTEXT_LENGTH), bytearray(WrappedKeyLimits.MAX_BYTES)) == 200


def test_wrap_when_the_result_is_too_small_fails() -> None:
    with pytest.raises(ValueError, match="result holds 8"):
        AwsKmsKeyWrapper(FakeKms(), KEY_ARN).wrap(os.urandom(32), bytearray(8))


@pytest.mark.parametrize("operation", ["wrap", "generate-and-wrap"])
def test_a_ciphertext_over_the_key_file_limit_is_refused(operation: str) -> None:
    kms = FakeKms()
    kms.on_encrypt = kms.on_generate = lambda request: {"CiphertextBlob": bytes(WrappedKeyLimits.MAX_BYTES + 1)}
    wrapper = AwsKmsKeyWrapper(kms, KEY_ARN)
    result = bytearray(2 * WrappedKeyLimits.MAX_BYTES)

    with pytest.raises(CryptographicError, match=f"AWS KMS {operation} for key '{KEY_ARN}' returned 513 bytes; a wrapped DEK is at most 512."):
        if operation == "wrap":
            wrapper.wrap(os.urandom(32), result)
        else:
            wrapper.generate_and_wrap(result)


@pytest.mark.parametrize("response", [{}, {"CiphertextBlob": None}, {"CiphertextBlob": b""}])
def test_generate_and_wrap_when_kms_returns_no_ciphertext_fails(response: Mapping[str, Any]) -> None:
    kms = FakeKms()
    kms.on_generate = lambda request: response

    with pytest.raises(CryptographicError, match="returned no ciphertext"):
        AwsKmsKeyWrapper(kms, KEY_ARN).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))


# --- Failures ---------------------------------------------------------------------------------------


def test_a_service_refusal_becomes_a_cryptographic_error_naming_the_error_code() -> None:
    kms = FakeKms()
    refusal = service_error("AccessDeniedException", 400, "Encrypt")
    kms.on_encrypt = raise_(refusal)

    with pytest.raises(CryptographicError) as error:
        AwsKmsKeyWrapper(kms, KEY_ARN).wrap(os.urandom(32), bytearray(WrappedKeyLimits.MAX_BYTES))

    assert str(error.value) == f"AWS KMS wrap failed for key '{KEY_ARN}': AccessDeniedException (HTTP 400)."
    assert error.value.__cause__ is refusal


def test_a_service_refusal_with_no_error_code_is_named_by_its_type() -> None:
    kms = FakeKms()
    kms.on_decrypt = raise_(service_error(None, 500, name="KMSInternalException"))

    with pytest.raises(CryptographicError) as error:
        AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(bytes(64), bytearray(32))

    assert str(error.value) == f"AWS KMS unwrap failed for key '{KEY_ARN}': KMSInternalException (HTTP 500)."


def test_a_service_refusal_with_no_status_says_so() -> None:
    kms = FakeKms()
    kms.on_generate = raise_(ClientError({"Error": {"Code": "ThrottlingException"}}, "GenerateDataKeyWithoutPlaintext"))

    with pytest.raises(CryptographicError, match="ThrottlingException \\(HTTP unknown\\)"):
        AwsKmsKeyWrapper(kms, KEY_ARN).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))


@pytest.mark.parametrize("failure", [NoCredentialsError(), EndpointConnectionError(endpoint_url="https://kms.us-east-1.amazonaws.com/")])
def test_a_client_side_failure_becomes_a_cryptographic_error(failure: Exception) -> None:
    kms = FakeKms()
    kms.on_generate = raise_(failure)

    with pytest.raises(CryptographicError) as error:
        AwsKmsKeyWrapper(kms, KEY_ARN).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))

    assert str(error.value) == f"AWS KMS generate-and-wrap failed for key '{KEY_ARN}': {failure}"
    assert error.value.__cause__ is failure


def test_what_is_not_a_botocore_failure_is_not_wrapped() -> None:
    kms = FakeKms()
    kms.on_generate = raise_(RuntimeError("a bug in a handler"))

    with pytest.raises(RuntimeError, match="a bug in a handler"):
        AwsKmsKeyWrapper(kms, KEY_ARN).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))


def test_a_client_that_returns_no_response_fails() -> None:
    def no_response(request: dict[str, Any]) -> Any:
        return None

    kms = FakeKms()
    kms.on_generate = no_response

    with pytest.raises(CryptographicError, match="returned no response"):
        AwsKmsKeyWrapper(kms, KEY_ARN).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))


# --- Through a real botocore client -----------------------------------------------------------------


def test_through_a_botocore_client_every_request_passes_the_kms_model_and_serializes() -> None:
    # Stubber answers each call after botocore has validated the parameters against the KMS model and
    # serialized the request (the bytearray plaintext included), and checks they are the expected ones.
    client = botocore_client()
    wrapper = AwsKmsKeyWrapper(client, KEY_ARN, CONTEXT)
    dek = os.urandom(32)
    with Stubber(client) as stub:
        stub.add_response("encrypt", {"CiphertextBlob": b"c" * 184, "KeyId": KEY_ARN},
                          {"KeyId": KEY_ARN, "Plaintext": bytearray(dek), "EncryptionContext": CONTEXT, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
        stub.add_response("decrypt", {"Plaintext": dek, "KeyId": KEY_ARN},
                          {"KeyId": KEY_ARN, "CiphertextBlob": b"c" * 184, "EncryptionContext": CONTEXT, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
        stub.add_response("generate_data_key_without_plaintext", {"CiphertextBlob": b"g" * 184, "KeyId": KEY_ARN},
                          {"KeyId": KEY_ARN, "KeySpec": "AES_256", "EncryptionContext": CONTEXT})

        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        assert wrapper.wrap(dek, wrapped) == 184
        revealed = bytearray(32)
        assert wrapper.unwrap(wrapped[:184], revealed) == 32
        assert wrapper.generate_and_wrap(wrapped) == 184
        stub.assert_no_pending_responses()

    assert revealed == dek
    assert wrapped[:184] == b"g" * 184


def test_through_a_botocore_client_a_modeled_kms_error_is_named_by_its_code() -> None:
    client = botocore_client()
    with Stubber(client) as stub:
        stub.add_client_error("decrypt", service_error_code="IncorrectKeyException", service_message="The key ID in the request does not identify "
                              "a CMK that can perform this operation.", http_status_code=400)
        result = bytearray(b"\xaa" * 32)

        with pytest.raises(CryptographicError) as error:
            AwsKmsKeyWrapper(client, KEY_ARN).unwrap(b"c" * 184, result)

    assert str(error.value) == f"AWS KMS unwrap failed for key '{KEY_ARN}': IncorrectKeyException (HTTP 400)."
    assert type(error.value.__cause__).__name__ == "IncorrectKeyException"
    assert ArrayUtility.is_null_or_empty(result)


def test_through_a_botocore_client_an_unreachable_endpoint_is_a_cryptographic_error() -> None:
    # A client-side failure end to end: nothing listens on the discard port of this machine, so the
    # connection is refused locally and no request leaves it.
    client = botocore.session.get_session().create_client(
        "kms", region_name="us-east-1", endpoint_url="http://127.0.0.1:9", aws_access_key_id="testing",
        aws_secret_access_key="testing",
        config=Config(connect_timeout=5, retries={"total_max_attempts": 1}))

    with pytest.raises(CryptographicError, match=f"AWS KMS generate-and-wrap failed for key '{KEY_ARN}': Could not connect") as error:
        AwsKmsKeyWrapper(client, KEY_ARN).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))
    assert isinstance(error.value.__cause__, EndpointConnectionError)


# --- With the rest of HkdfGuard ---------------------------------------------------------------------


def test_a_crypto_provider_generates_and_reveals_its_dek_through_kms() -> None:
    wrapper = AwsKmsKeyWrapper(FakeKms(), KEY_ARN, CONTEXT)
    with AesGcmCryptoProviderFactory().create_ephemeral(wrapper, 60) as provider:
        expected = b"hello, kms"
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
        path.write_bytes(os.urandom(184))
        yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_read_key_file_by_default_refuses_a_file_the_current_user_could_have_replaced(user_writable_key_file: Path) -> None:
    with pytest.raises(PermissionError, match="not trusted"):
        AwsKmsKeyWrapper(FakeKms(), KEY_ARN, CONTEXT).read_key_file(user_writable_key_file)


def test_read_key_file_with_no_trust_given_trusts_administrators_only(user_writable_key_file: Path) -> None:
    # The same refusal as the default: None is ADMINISTRATORS_ONLY, never "anyone".
    with pytest.raises(PermissionError, match="not trusted"):
        AwsKmsKeyWrapper(FakeKms(), KEY_ARN, None, None).read_key_file(user_writable_key_file)


@pytest.mark.parametrize(("path", "expected"), [(None, TypeError), ("", ValueError)])
def test_read_key_file_refuses_a_missing_path(path: object, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        AwsKmsKeyWrapper(FakeKms(), KEY_ARN).read_key_file(path)  # type: ignore[arg-type]


def current_user_sid() -> str:
    whoami = os.path.join(os.environ["SYSTEMROOT"], "System32", "whoami.exe")
    output = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout.strip()
    return output.rsplit(",", 1)[1].strip('"')  # "DOMAIN\name","S-1-5-21-..."


@windows_only
def test_read_key_file_with_the_writers_account_trusted_reads_the_file_and_it_reveals(user_writable_key_file: Path) -> None:
    wrapper = AwsKmsKeyWrapper(FakeKms(), KEY_ARN, CONTEXT, KeyFileTrust(windows_principals=[current_user_sid()]))
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    user_writable_key_file.write_bytes(wrapped[:length])

    read = wrapper.read_key_file(user_writable_key_file)

    assert read == wrapped[:length]
    assert wrapper.unwrap(read, bytearray(32)) == 32


@windows_only
def test_read_key_file_trusting_everyone_is_refused(user_writable_key_file: Path) -> None:
    wrapper = AwsKmsKeyWrapper(FakeKms(), KEY_ARN, CONTEXT, KeyFileTrust(windows_principals=["S-1-1-0"]))

    with pytest.raises(ValueError, match="every account"):
        wrapper.read_key_file(user_writable_key_file)
