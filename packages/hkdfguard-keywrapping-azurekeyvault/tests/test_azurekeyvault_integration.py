"""Real calls against an RSA wrapping key and an EC P-256 signing key the caller provides, named in
azure.test.properties at the repository root (or the environment; see :func:`configured_keys`).
Credentials come from DefaultAzureCredential (environment, workload or managed identity, Azure CLI,
...)::

    az login
    uv run pytest packages/hkdfguard-keywrapping-azurekeyvault

Without both keys every test here is reported as skipped - never as passed. Once they are named, a
failing call - or a value that isn't a key identifier - is a test failure. The identity needs get,
wrapKey, unwrapKey, sign and verify on the keys; the tests never create, change or delete a key. See
docs/how-to/run-azure-key-vault-integration-tests.md."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from azure.identity import DefaultAzureCredential
from hkdfguard.abstractions import ArrayUtility, CryptographicError, WrappedKeyLimits
from hkdfguard.keywrapping.azurekeyvault import AzureKeyVaultKeyWrapper
from hkdfguard.keywrapping.azurekeyvault._key_id import KeyVaultKeyId

WRAPPING_KEY_VARIABLE = "HKDFGUARD_TEST_AZURE_WRAP_KEY_ID"
SIGNING_KEY_VARIABLE = "HKDFGUARD_TEST_AZURE_SIGN_KEY_ID"
SETTINGS_FILE = "azure.test.properties"
CONTEXT = "hkdfguard.integrationtest"


def settings() -> dict[str, str]:
    """The settings file at the repository root - the nearest directory above this file that holds
    uv.lock - as ``NAME=value`` lines, ``#`` and ``!`` starting a comment; empty if there is none. This
    repository's counterpart of hkdfguard-dotnet's azure.runsettings, and the same file as
    hkdfguard-java's: a local file, ignored by git, naming keys only - DefaultAzureCredential signs in
    with az login, so no credential ever goes in it."""
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


def configured_keys() -> tuple[str, str] | None:
    """The real wrapping and signing keys, each from the environment, else from the settings file;
    ``None`` unless both are given."""
    file = settings()
    wrapping, signing = (os.environ.get(name) or file.get(name) or None for name in (WRAPPING_KEY_VARIABLE, SIGNING_KEY_VARIABLE))
    return (wrapping, signing) if wrapping is not None and signing is not None else None


pytestmark = pytest.mark.skipif(configured_keys() is None, reason=f"Set {WRAPPING_KEY_VARIABLE} to an RSA key and {SIGNING_KEY_VARIABLE} to an EC "
                                                                  f"P-256 key, in the environment or {SETTINGS_FILE}, to run Azure Key Vault integration "
                                                                  "tests.")


def checked(variable: str, value: str) -> str:
    # A value that isn't a key identifier (a placeholder left in place, say) fails with a message
    # naming the variable, rather than as an argument error from the wrapper.
    try:
        KeyVaultKeyId.parse(value)
    except ValueError as error:
        raise AssertionError(f"{variable} is {value!r}, which isn't a key identifier. See docs/how-to/run-azure-key-vault-integration-tests.md.") \
            from error
    return value


@pytest.fixture(scope="module")
def credential() -> Iterator[DefaultAzureCredential]:
    credential = DefaultAzureCredential()
    try:
        yield credential
    finally:
        credential.close()


def wrapper(credential: DefaultAzureCredential, context: str = CONTEXT) -> AzureKeyVaultKeyWrapper:
    keys = configured_keys()
    assert keys is not None
    return AzureKeyVaultKeyWrapper(checked(WRAPPING_KEY_VARIABLE, keys[0]), checked(SIGNING_KEY_VARIABLE, keys[1]), credential, context)


def test_wrap_then_unwrap_round_trips_a_32_byte_dek(credential: DefaultAzureCredential) -> None:
    with wrapper(credential) as azure:
        dek = os.urandom(32)

        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        length = azure.wrap(dek, wrapped)
        revealed = bytearray(32)

        assert azure.unwrap(wrapped[:length], revealed) == 32
        assert revealed == dek


def test_generate_and_wrap_produces_a_wrapped_dek_that_reveals(credential: DefaultAzureCredential) -> None:
    with wrapper(credential) as azure:
        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        length = azure.generate_and_wrap(wrapped)
        revealed = bytearray(32)

        assert azure.unwrap(wrapped[:length], revealed) == 32
        assert not ArrayUtility.is_null_or_empty(revealed)


def test_unwrap_under_another_context_is_refused(credential: DefaultAzureCredential) -> None:
    with wrapper(credential) as azure, wrapper(credential, "hkdfguard.integrationtest.other") as other:
        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        length = azure.generate_and_wrap(wrapped)

        with pytest.raises(CryptographicError, match="signature doesn't verify"):
            other.unwrap(wrapped[:length], bytearray(32))


def test_unwrap_when_tampered_is_refused(credential: DefaultAzureCredential) -> None:
    with wrapper(credential) as azure:
        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        length = azure.generate_and_wrap(wrapped)
        wrapped[length - 1] ^= 1

        with pytest.raises(CryptographicError):
            azure.unwrap(wrapped[:length], bytearray(32))
