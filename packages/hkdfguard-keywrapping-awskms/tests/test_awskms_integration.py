"""Real calls against a symmetric AWS KMS key the caller provides. botocore resolves credentials and
region the usual way (environment, shared config and credentials files, container or instance role)::

    HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:... AWS_REGION=us-east-1 uv run pytest packages/hkdfguard-keywrapping-awskms

Without HKDFGUARD_TEST_AWS_KMS_KEY_ID every test here is reported as skipped - never as passed. Once
it names a key, a failing call is a test failure. The principal needs kms:Encrypt, kms:Decrypt and
kms:GenerateDataKeyWithoutPlaintext on the key; the tests never create, alter or schedule deletion
of a key."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import botocore.session
import pytest
from hkdfguard.abstractions import ArrayUtility, CryptographicError, WrappedKeyLimits
from hkdfguard.keywrapping.awskms import AwsKmsKeyWrapper

KEY_ID_VARIABLE = "HKDFGUARD_TEST_AWS_KMS_KEY_ID"
CONTEXT = {"purpose": "hkdfguard.integrationtest"}


def configured_key_id() -> str | None:
    """The real KMS key the integration tests run against, if one was given."""
    return os.environ.get(KEY_ID_VARIABLE) or None


pytestmark = pytest.mark.skipif(configured_key_id() is None, reason=f"Set {KEY_ID_VARIABLE} to a symmetric KMS key to run AWS KMS integration tests.")


@pytest.fixture
def key_id() -> str:
    key = configured_key_id()
    assert key is not None
    return key


@pytest.fixture
def client() -> Iterator[Any]:
    # The application creates (and closes) the client; boto3.client("kms") would be the same botocore client.
    kms = botocore.session.get_session().create_client("kms")
    try:
        yield kms
    finally:
        kms.close()


def test_wrap_then_unwrap_round_trips_a_32_byte_dek(client: Any, key_id: str) -> None:
    wrapper = AwsKmsKeyWrapper(client, key_id, CONTEXT)
    dek = bytearray(os.urandom(32))

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(dek, wrapped)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrapped[:length], revealed) == 32
    assert revealed == dek


def test_generate_and_wrap_produces_a_wrapped_dek_that_reveals(client: Any, key_id: str) -> None:
    wrapper = AwsKmsKeyWrapper(client, key_id, CONTEXT)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrapped[:length], revealed) == 32
    assert not ArrayUtility.is_null_or_empty(revealed)


def test_unwrap_under_another_context_is_refused(client: Any, key_id: str) -> None:
    wrapper = AwsKmsKeyWrapper(client, key_id, CONTEXT)
    other = AwsKmsKeyWrapper(client, key_id, {"purpose": "hkdfguard.integrationtest.other"})

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)

    with pytest.raises(CryptographicError):
        other.unwrap(wrapped[:length], bytearray(32))


def test_unwrap_when_tampered_is_refused(client: Any, key_id: str) -> None:
    wrapper = AwsKmsKeyWrapper(client, key_id, CONTEXT)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    wrapped[length - 1] ^= 1

    with pytest.raises(CryptographicError):
        wrapper.unwrap(wrapped[:length], bytearray(32))
