"""Real reads of a secret the caller provides, in a KV version 2 engine mounted at "secret" (a dev
server's default), with a token the caller provides::

    vault kv put secret/hkdfguard/test value=s3cret port=5432
    HKDFGUARD_TEST_VAULT_ADDR=https://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \\
    HKDFGUARD_TEST_VAULT_CACERT=/path/to/vault-ca.pem HKDFGUARD_TEST_VAULT_SECRET_NAME=hkdfguard/test#value \\
    HKDFGUARD_TEST_VAULT_SECRET_JSON='{"value":"s3cret","port":"5432"}' \\
    uv run pytest packages/hkdfguard-cache-hashicorpvault

Without HKDFGUARD_TEST_VAULT_SECRET_NAME every test here is reported as skipped - never as passed;
once it is set, a failing read is a test failure. HKDFGUARD_TEST_VAULT_CACERT is needed only for a
server certificate the system's trust store doesn't trust. To check what the secret holds, not just
that it holds something, set HKDFGUARD_TEST_VAULT_SECRET_JSON to the JSON object of keys it is
expected to hold: each is then read as "path#key", the path being HKDFGUARD_TEST_VAULT_SECRET_NAME's
without its key, and compared with it. The token needs only read on that secret's path; the tests
never list, write or delete. See docs/how-to/run-hashicorp-vault-cache-integration-tests.md.

The secret's name, Vault's address and its CA certificate are read from the environment, else from
vault.test.properties at the repository root - the same file as hkdfguard-java's: a local file,
ignored by git. The token and the expected JSON, which hold secrets, are read from the environment
only, never from a file."""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from hkdfguard.abstractions import KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache.hashicorpvault import HashiCorpVaultSecretCache, HashiCorpVaultSecretCacheOptions, StaticVaultToken
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing

SECRET_NAME_VARIABLE = "HKDFGUARD_TEST_VAULT_SECRET_NAME"
ADDRESS_VARIABLE = "HKDFGUARD_TEST_VAULT_ADDR"
TOKEN_VARIABLE = "HKDFGUARD_TEST_VAULT_TOKEN"
CA_CERTIFICATE_VARIABLE = "HKDFGUARD_TEST_VAULT_CACERT"
EXPECTED_JSON_VARIABLE = "HKDFGUARD_TEST_VAULT_SECRET_JSON"
SETTINGS_FILE = "vault.test.properties"
DEFAULT_ADDRESS = "https://127.0.0.1:8200"


def settings() -> dict[str, str]:
    """The settings file at the repository root - the nearest directory above this file that holds
    uv.lock - as ``NAME=value`` lines, ``#`` and ``!`` starting a comment; empty if there is none."""
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


def configured(variable: str) -> str | None:
    """``variable`` from the environment, else from the settings file; ``None`` if neither sets it."""
    return os.environ.get(variable) or settings().get(variable) or None


def secret_name() -> str:
    name = configured(SECRET_NAME_VARIABLE)
    assert name is not None
    return name


def secret_path() -> str:
    # The secret's path: the configured name without its key, if it has one.
    return secret_name().partition("#")[0]


pytestmark = pytest.mark.skipif(configured(SECRET_NAME_VARIABLE) is None,
                                reason=f"Set {SECRET_NAME_VARIABLE} to a secret's path#key (with {ADDRESS_VARIABLE} and {TOKEN_VARIABLE}), in the "
                                       f"environment or {SETTINGS_FILE}, to run Vault cache integration tests.")

needs_expected_json = pytest.mark.skipif(not os.environ.get(EXPECTED_JSON_VARIABLE),
                                         reason=f"Set {SECRET_NAME_VARIABLE} and {EXPECTED_JSON_VARIABLE} to check a secret's keys.")


class _Number(str):
    """A JSON number, kept as the text it was written as."""

    __slots__ = ()


def expected_members() -> list[tuple[str, str]]:
    """Each member of the expected JSON object as the cache reveals it under ``path#key``: a string
    as its text, a number, true or false as its JSON text; a null, object or array is left out."""
    text = os.environ.get(EXPECTED_JSON_VARIABLE, "")
    try:
        expected = json.loads(text, parse_int=_Number, parse_float=_Number)
    except ValueError:
        expected = None
    if not isinstance(expected, dict):
        # Never quoting it: it holds the secret's values.
        pytest.fail(f"{EXPECTED_JSON_VARIABLE} isn't a JSON object.")

    members: list[tuple[str, str]] = []
    for key, value in expected.items():
        if isinstance(value, bool):
            members.append((key, "true" if value else "false"))
        elif isinstance(value, str):
            members.append((key, str(value)))
    return members


class FixedKeyWrapper(KeyWrapper):
    def __init__(self, key: bytes) -> None:
        self.key = key

    def wrap(self, plaintext: Any, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Any, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


def ssl_context() -> ssl.SSLContext | None:
    # A context trusting HKDFGUARD_TEST_VAULT_CACERT, and only it, when set; otherwise the cache's
    # default, the system's trust store.
    ca_certificate = configured(CA_CERTIFICATE_VARIABLE)
    return ssl.create_default_context(cafile=ca_certificate) if ca_certificate is not None else None


@pytest.fixture
def cache() -> Iterator[HashiCorpVaultSecretCache]:
    token = os.environ.get(TOKEN_VARIABLE)
    if not token:
        pytest.fail(f"Set {TOKEN_VARIABLE} in the environment (never in {SETTINGS_FILE}) to a token allowed to read {SECRET_NAME_VARIABLE}.")

    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
        protector = ring.create_protector(HashiCorpVaultSecretCache.TOKEN_PURPOSE)
        provider = StaticVaultToken.protect(protector, token)
        del token
        options = HashiCorpVaultSecretCacheOptions(ssl_context=ssl_context())
        with HashiCorpVaultSecretCache(configured(ADDRESS_VARIABLE) or DEFAULT_ADDRESS, provider, protector, ring, options=options) as cache:
            yield cache


def reveal(cache: ProtectedReadOnlyCache, name: str) -> str:
    maximum = cache.find_max_decrypted_length(name)
    assert maximum is not None, f"Nothing is stored under '{name}'."
    result = bytearray(maximum)
    return result[: cache.decrypt(name, result)].decode()


async def reveal_async(cache: ProtectedReadOnlyCache, name: str) -> str:
    maximum = await cache.find_max_decrypted_length_async(name)
    assert maximum is not None, f"Nothing is stored under '{name}'."
    result = bytearray(maximum)
    return result[: await cache.decrypt_async(name, result)].decode()


def test_decrypt_reveals_the_secret(cache: HashiCorpVaultSecretCache) -> None:
    maximum = cache.find_max_decrypted_length(secret_name())
    assert maximum is not None

    assert cache.decrypt(secret_name(), bytearray(maximum)) > 0


def test_decrypt_async_reveals_the_secret(cache: HashiCorpVaultSecretCache) -> None:
    async def main() -> None:
        maximum = await cache.find_max_decrypted_length_async(secret_name())
        assert maximum is not None and maximum > 0
        assert await cache.decrypt_async(secret_name(), bytearray(maximum)) > 0

    asyncio.run(main())


@needs_expected_json
def test_decrypt_reveals_every_key_the_secret_holds(cache: HashiCorpVaultSecretCache) -> None:
    for key, value in expected_members():
        # Compared without letting pytest print either side: they are the secret's values.
        matches = reveal(cache, f"{secret_path()}#{key}") == value
        assert matches, f"'{secret_path()}#{key}' doesn't hold the expected value."
    assert cache.decrypt(f"{secret_path()}#no-such-key", bytearray(16)) == 0


@needs_expected_json
def test_decrypt_async_reveals_every_key_the_secret_holds(cache: HashiCorpVaultSecretCache) -> None:
    async def main() -> None:
        for key, value in expected_members():
            matches = await reveal_async(cache, f"{secret_path()}#{key}") == value
            assert matches, f"'{secret_path()}#{key}' doesn't hold the expected value."
        assert await cache.decrypt_async(f"{secret_path()}#no-such-key", bytearray(16)) == 0

    asyncio.run(main())


def test_decrypt_of_a_secret_that_does_not_exist_returns_zero(cache: HashiCorpVaultSecretCache) -> None:
    assert cache.decrypt(f"hkdfguard/missing-{uuid.uuid4().hex}", bytearray(16)) == 0
