"""Real calls against a symmetric Cloud KMS key the caller provides, named in google.test.properties at
the repository root (or the environment; see :func:`configured_key`). Credentials come from Application
Default Credentials (gcloud auth application-default login, or the attached service account)::

    gcloud auth application-default login
    uv run pytest packages/hkdfguard-keywrapping-googlekms

Without the key every test here is reported as skipped - never as passed. Once it is named, a failing
call - or a value that isn't a key's resource name - is a test failure. The principal needs
roles/cloudkms.cryptoKeyEncrypterDecrypter on the key; the tests never create, change or destroy a key.
See docs/how-to/run-google-kms-integration-tests.md."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from google.cloud import kms
from hkdfguard.abstractions import ArrayUtility, CryptographicError, WrappedKeyLimits
from hkdfguard.keywrapping.googlekms import GoogleKmsKeyWrapper

KEY_NAME_VARIABLE = "HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME"
SETTINGS_FILE = "google.test.properties"
CONTEXT = "hkdfguard.integrationtest"


def settings() -> dict[str, str]:
    """The settings file at the repository root - the nearest directory above this file that holds
    uv.lock - as ``NAME=value`` lines, ``#`` and ``!`` starting a comment; empty if there is none. This
    repository's counterpart of hkdfguard-dotnet's google.runsettings, and the same file as
    hkdfguard-java's: a local file, ignored by git, naming the key only - Application Default
    Credentials sign in with gcloud, so no credential ever goes in it."""
    for directory in Path(__file__).resolve().parents:
        if (directory / "uv.lock").exists():
            file = directory / SETTINGS_FILE
            if not file.exists():
                return {}
            values: dict[str, str] = {}
            for raw in file.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and not line.startswith(("#", "!")) and "=" in line:
                    name, value = line.split("=", 1)
                    values[name.strip()] = value.strip()
            return values
    return {}


def configured_key() -> str | None:
    """The real key's resource name, from the environment, else from the settings file; ``None`` if neither gives one."""
    return os.environ.get(KEY_NAME_VARIABLE) or settings().get(KEY_NAME_VARIABLE) or None


pytestmark = pytest.mark.skipif(configured_key() is None, reason=f"Set {KEY_NAME_VARIABLE} to a symmetric Cloud KMS key, in the environment or "
                                                                f"{SETTINGS_FILE}, to run Cloud KMS integration tests.")


@pytest.fixture(scope="module")
def key_name() -> str:
    # A value that isn't a key's resource name (a placeholder left in place, say) fails with a message
    # naming the variable, rather than as an argument error from the wrapper.
    value = configured_key()
    assert value is not None
    if not re.fullmatch(r"projects/[^/\[]+/locations/[^/\[]+/keyRings/[^/\[]+/cryptoKeys/[^/\[]+", value):
        raise AssertionError(f"{KEY_NAME_VARIABLE} is {value!r}, which isn't a key's resource name. Replace the placeholders in {SETTINGS_FILE} "
                             "(docs/how-to/run-google-kms-integration-tests.md, step 5).")
    return value


@pytest.fixture(scope="module")
def client() -> Iterator[kms.KeyManagementServiceClient]:
    with kms.KeyManagementServiceClient() as client:
        yield client


def test_wrap_then_unwrap_round_trips_a_32_byte_dek(client: kms.KeyManagementServiceClient, key_name: str) -> None:
    wrapper = GoogleKmsKeyWrapper(client, key_name, CONTEXT)
    dek = os.urandom(32)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(dek, wrapped)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrapped[:length], revealed) == 32
    assert revealed == dek


def test_generate_and_wrap_produces_a_wrapped_dek_that_reveals(client: kms.KeyManagementServiceClient, key_name: str) -> None:
    wrapper = GoogleKmsKeyWrapper(client, key_name, CONTEXT)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    revealed = bytearray(32)

    assert wrapper.unwrap(wrapped[:length], revealed) == 32
    assert not ArrayUtility.is_null_or_empty(revealed)


def test_unwrap_under_another_context_is_refused(client: kms.KeyManagementServiceClient, key_name: str) -> None:
    wrapper = GoogleKmsKeyWrapper(client, key_name, CONTEXT)
    other = GoogleKmsKeyWrapper(client, key_name, "hkdfguard.integrationtest.other")

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)

    with pytest.raises(CryptographicError, match="INVALID_ARGUMENT"):
        other.unwrap(wrapped[:length], bytearray(32))


def test_unwrap_when_tampered_is_refused(client: kms.KeyManagementServiceClient, key_name: str) -> None:
    wrapper = GoogleKmsKeyWrapper(client, key_name, CONTEXT)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    wrapped[length - 1] ^= 1

    with pytest.raises(CryptographicError):
        wrapper.unwrap(wrapped[:length], bytearray(32))
