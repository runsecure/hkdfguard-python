"""Real calls against a secret the caller provides, named in azure.test.properties at the repository
root (or the environment; see :func:`setting`). Credentials come from DefaultAzureCredential
(environment, workload or managed identity, Azure CLI, ...)::

    az login
    HKDFGUARD_TEST_AZURE_SECRET_ID=https://{vault}.vault.azure.net/secrets/{name} \\
    uv run pytest packages/hkdfguard-cache-azurekeyvault

Without the secret every test here is reported as skipped - never as passed. Once it is named, a
failing call - or a value that isn't a secret identifier - is a test failure. The identity needs
only get on secrets (the Key Vault Secrets User role); the tests never list, create, change or
delete a secret.

To check what the secret holds, not just that it holds something, set
HKDFGUARD_TEST_AZURE_SECRET_JSON to the JSON object it is expected to hold: the whole value and each
member, read as "name#key", are then compared with it. Set HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true
as well when the vault also holds each member as a secret of its own, named by its key; those are
then read and compared too. See docs/how-to/run-azure-key-vault-secret-cache-integration-tests.md."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Buffer, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from azure.identity import DefaultAzureCredential
from hkdfguard.abstractions import KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache.azurekeyvault import AzureKeyVaultSecretCache
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing

SECRET_ID_VARIABLE = "HKDFGUARD_TEST_AZURE_SECRET_ID"
EXPECTED_JSON_VARIABLE = "HKDFGUARD_TEST_AZURE_SECRET_JSON"
SEPARATE_SECRETS_VARIABLE = "HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS"
SETTINGS_FILE = "azure.test.properties"
HOW_TO = "docs/how-to/run-azure-key-vault-secret-cache-integration-tests.md"


def settings() -> dict[str, str]:
    """The settings file at the repository root - the nearest directory above this file that holds
    uv.lock - as ``NAME=value`` lines, ``#`` and ``!`` starting a comment; empty if there is none. The
    same local file, ignored by git, that hkdfguard-keywrapping-azurekeyvault's integration tests and
    hkdfguard-java's read: it names a secret only - DefaultAzureCredential signs in with az login, so
    no credential ever goes in it."""
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


def setting(variable: str) -> str | None:
    """The variable from the environment - where setting it, even to empty, overrides the file - else
    from the settings file; ``None`` if it is unset or empty."""
    value = os.environ[variable] if variable in os.environ else settings().get(variable, "")
    return value.strip() or None


def secret_id() -> tuple[str, str]:
    """The configured secret's vault URL and name. A value that isn't a secret identifier without a
    version (a placeholder left in place, say) fails with a message naming the variable."""
    value = setting(SECRET_ID_VARIABLE)
    assert value is not None
    parts = urlsplit(value)
    segments = parts.path.strip("/").split("/")
    if parts.scheme != "https" or not parts.netloc or len(segments) != 2 or segments[0] != "secrets" \
            or not AzureKeyVaultSecretCache.is_valid_secret_name(segments[1]):
        raise AssertionError(f"{SECRET_ID_VARIABLE} is {value!r}, which isn't a secret identifier without a version: "
                             f"https://{{vault}}.vault.azure.net/secrets/{{name}}. See {HOW_TO}.")
    return f"https://{parts.netloc}/", segments[1]


class _JsonNumber(str):
    """A number in the expected JSON, kept as the text it was written as, which is what the cache
    caches it as."""

    __slots__ = ()


def expected() -> dict[str, Any] | None:
    """The expected secret's JSON object, its numbers kept as their text; ``None`` if it isn't set."""
    value = setting(EXPECTED_JSON_VARIABLE)
    if value is None:
        return None
    parsed = json.loads(value, parse_int=_JsonNumber, parse_float=_JsonNumber)
    if not isinstance(parsed, dict):
        raise AssertionError(f"{EXPECTED_JSON_VARIABLE} isn't a JSON object. See {HOW_TO}.")
    return parsed


def members(expected_object: dict[str, Any]) -> list[tuple[str, str]]:
    """Each member as the cache reveals it under "name#key": a string as its text, a number, true or
    false as its JSON text; null, an object or an array not at all."""
    found: list[tuple[str, str]] = []
    for key, value in expected_object.items():
        if isinstance(value, bool):
            found.append((key, "true" if value else "false"))
        elif isinstance(value, str):
            found.append((key, str(value)))
    return found


def assert_whole_value(whole: str) -> None:
    """Asserts ``whole`` is the expected object, compared as JSON - structurally, numbers by value -
    so whitespace the store added or removed doesn't matter."""
    expected_text = setting(EXPECTED_JSON_VARIABLE)
    assert expected_text is not None
    assert json.loads(whole) == json.loads(expected_text), "The secret's whole value isn't the expected JSON object."


skip_without_secret = pytest.mark.skipif(setting(SECRET_ID_VARIABLE) is None,
                                         reason=f"Set {SECRET_ID_VARIABLE} to a secret's identifier, in the environment or {SETTINGS_FILE}, "
                                                "to run Azure Key Vault secret cache integration tests.")
skip_without_json = pytest.mark.skipif(setting(SECRET_ID_VARIABLE) is None or setting(EXPECTED_JSON_VARIABLE) is None,
                                       reason=f"Set {SECRET_ID_VARIABLE} and {EXPECTED_JSON_VARIABLE} to check a secret's contents.")
skip_without_separate_secrets = pytest.mark.skipif(
    setting(SECRET_ID_VARIABLE) is None or setting(EXPECTED_JSON_VARIABLE) is None or (setting(SEPARATE_SECRETS_VARIABLE) or "").lower() != "true",
    reason=f"Set {SEPARATE_SECRETS_VARIABLE}=true, with {SECRET_ID_VARIABLE} and {EXPECTED_JSON_VARIABLE}, when the vault holds each expected key "
           "as a secret of its own.")


class FixedKeyWrapper(KeyWrapper):
    # The ring's key is local: only the secret comes from Azure.
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


@pytest.fixture(scope="module")
def credential() -> Iterator[DefaultAzureCredential]:
    credential = DefaultAzureCredential()
    try:
        yield credential
    finally:
        credential.close()


@pytest.fixture
def cache(credential: DefaultAzureCredential) -> Iterator[AzureKeyVaultSecretCache]:
    vault_url, _ = secret_id()
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
        with AzureKeyVaultSecretCache(vault_url, credential, ring) as cache:
            yield cache


def decrypt(cache: ProtectedReadOnlyCache, name: str) -> str:
    """The value stored under ``name``, as text; fails the test if there is none."""
    length = cache.find_max_decrypted_length(name)
    assert length is not None, f"Nothing is stored under '{name}'."
    result = bytearray(length)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_async(cache: ProtectedReadOnlyCache, name: str) -> str:
    """:func:`decrypt`, through decrypt_async."""
    length = await cache.find_max_decrypted_length_async(name)
    assert length is not None, f"Nothing is stored under '{name}'."
    result = bytearray(length)
    return result[: await cache.decrypt_async(name, result)].decode()


@skip_without_secret
def test_decrypt_reveals_the_secret(cache: AzureKeyVaultSecretCache) -> None:
    _, name = secret_id()

    length = cache.find_max_decrypted_length(name)
    assert length is not None
    assert cache.decrypt(name, bytearray(length)) > 0


@skip_without_secret
def test_decrypt_async_reveals_the_secret(cache: AzureKeyVaultSecretCache) -> None:
    _, name = secret_id()

    async def scenario() -> int:
        length = await cache.find_max_decrypted_length_async(name)
        assert length is not None
        return await cache.decrypt_async(name, bytearray(length))

    assert asyncio.run(scenario()) > 0


@skip_without_json
def test_decrypt_reveals_the_expected_whole_value(cache: AzureKeyVaultSecretCache) -> None:
    _, name = secret_id()

    assert_whole_value(decrypt(cache, name))


@skip_without_json
def test_decrypt_reveals_every_key_the_secret_holds(cache: AzureKeyVaultSecretCache) -> None:
    _, name = secret_id()
    expected_object = expected()
    assert expected_object is not None

    for key, value in members(expected_object):
        assert decrypt(cache, f"{name}#{key}") == value
    assert cache.decrypt(f"{name}#no-such-key", bytearray(16)) == 0


@skip_without_json
def test_decrypt_async_reveals_every_key_the_secret_holds_and_the_whole_value(cache: AzureKeyVaultSecretCache) -> None:
    _, name = secret_id()
    expected_object = expected()
    assert expected_object is not None

    async def scenario() -> None:
        for key, value in members(expected_object):
            assert await decrypt_async(cache, f"{name}#{key}") == value
        assert await cache.decrypt_async(f"{name}#no-such-key", bytearray(16)) == 0
        assert_whole_value(await decrypt_async(cache, name))

    asyncio.run(scenario())


@skip_without_separate_secrets
def test_each_key_is_also_a_secret_of_its_own_holding_the_same_value(cache: AzureKeyVaultSecretCache) -> None:
    expected_object = expected()
    assert expected_object is not None

    for key, value in members(expected_object):
        assert AzureKeyVaultSecretCache.is_valid_secret_name(key), f"'{key}' can't be a Key Vault secret name."
        assert decrypt(cache, key) == value

        # Key Vault matches secret names ignoring case, so the cache does too.
        assert decrypt(cache, key.upper()) == value


@skip_without_secret
def test_decrypt_of_a_secret_that_does_not_exist_returns_zero(cache: AzureKeyVaultSecretCache) -> None:
    assert cache.decrypt(f"hkdfguard-missing-{uuid.uuid4().hex}", bytearray(16)) == 0
