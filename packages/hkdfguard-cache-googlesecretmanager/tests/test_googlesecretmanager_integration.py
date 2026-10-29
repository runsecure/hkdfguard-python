"""Real calls against a Secret Manager secret the caller provides, named in google.test.properties at
the repository root (or the environment; see :func:`configured`). Credentials come from Application
Default Credentials (gcloud auth application-default login, or the attached service account)::

    gcloud auth application-default login
    uv run pytest packages/hkdfguard-cache-googlesecretmanager

Without HKDFGUARD_TEST_GOOGLE_SECRET_NAME every test here is reported as skipped - never as passed.
Once it is named, a failing call - or a value that isn't a secret's resource name - is a test failure.
To check what the secret holds, not just that it holds something, set HKDFGUARD_TEST_GOOGLE_SECRET_JSON
to the JSON object its latest version's payload is expected to hold: the whole value and each member,
read as "id#key", are then compared with it. The principal needs only secretmanager.versions.access on
the secret (the Secret Manager Secret Accessor role); the tests never list, create, alter or delete a
secret. See docs/how-to/run-google-secret-manager-cache-integration-tests.md."""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from collections.abc import Buffer, Iterator
from pathlib import Path
from typing import Any

import pytest
from hkdfguard.abstractions import KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache.googlesecretmanager import GoogleSecretManagerSecretCache
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing

SECRET_NAME_VARIABLE = "HKDFGUARD_TEST_GOOGLE_SECRET_NAME"
EXPECTED_JSON_VARIABLE = "HKDFGUARD_TEST_GOOGLE_SECRET_JSON"
SETTINGS_FILE = "google.test.properties"

_SECRET_NAME = re.compile(r"projects/([^/\[\]{}<>]+)/secrets/([^/\[\]{}<>]+)")


def settings() -> dict[str, str]:
    """The settings file at the repository root - the nearest directory above this file that holds
    uv.lock - as ``NAME=value`` lines, ``#`` and ``!`` starting a comment; empty if there is none. This
    repository's counterpart of hkdfguard-dotnet's google.runsettings, and the same file as
    hkdfguard-java's: a local file, ignored by git, naming the secret only - Application Default
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


def configured(variable: str) -> str | None:
    """The variable's value from the environment, else from the settings file; ``None`` if neither gives one."""
    return os.environ.get(variable) or settings().get(variable) or None


pytestmark = pytest.mark.skipif(configured(SECRET_NAME_VARIABLE) is None,
                                reason=f"Set {SECRET_NAME_VARIABLE} to a secret's resource name (projects/{{project}}/secrets/{{secret}}), in the "
                                       f"environment or {SETTINGS_FILE}, to run Google Secret Manager cache integration tests.")

needs_expected_json = pytest.mark.skipif(configured(EXPECTED_JSON_VARIABLE) is None,
                                         reason=f"Set {SECRET_NAME_VARIABLE} and {EXPECTED_JSON_VARIABLE} to check a secret's contents.")


class _JsonNumber(str):
    """A number in the expected JSON, kept as its text: the cache caches a number member as its JSON text."""

    __slots__ = ()


def expected_json() -> dict[str, Any]:
    """The expected JSON object, its numbers kept as their text."""
    text = configured(EXPECTED_JSON_VARIABLE)
    assert text is not None
    value = json.loads(text, parse_int=_JsonNumber, parse_float=_JsonNumber)
    if not isinstance(value, dict):
        raise AssertionError(f"{EXPECTED_JSON_VARIABLE} isn't a JSON object.")
    return value


def members(expected: dict[str, Any]) -> list[tuple[str, str]]:
    """Each member as the cache reveals it under "name#key": a string as its text, a number, true or
    false as its JSON text. Null, objects and arrays are left out, as the cache leaves them out."""
    found: list[tuple[str, str]] = []
    for key, value in expected.items():
        if isinstance(value, bool):
            found.append((key, "true" if value else "false"))
        elif isinstance(value, str):  # a string, or a _JsonNumber's text
            found.append((key, str(value)))
    return found


def assert_whole_value(whole: str) -> None:
    """Asserts whole is the expected object, compared as JSON (so whitespace doesn't matter)."""
    text = configured(EXPECTED_JSON_VARIABLE)
    assert text is not None
    assert json.loads(whole) == json.loads(text), "The secret's whole value isn't the expected JSON object."


def decrypt(cache: ProtectedReadOnlyCache, name: str) -> str:
    """The value stored under name, as text; fails the test if there is none."""
    length = cache.find_max_decrypted_length(name)
    assert length, f"Nothing is stored under '{name}'."
    result = bytearray(length)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_async(cache: ProtectedReadOnlyCache, name: str) -> str:
    """:func:`decrypt`, through decrypt_async."""
    length = await cache.find_max_decrypted_length_async(name)
    assert length, f"Nothing is stored under '{name}'."
    result = bytearray(length)
    return result[: await cache.decrypt_async(name, result)].decode()


class _FixedKeyWrapper(KeyWrapper):
    """The ring's one key, made up locally: these tests check the cache's Secret Manager calls, not wrapping."""

    def __init__(self) -> None:
        self._key = os.urandom(32)

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self._key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


@pytest.fixture(scope="module")
def secret() -> tuple[str, str]:
    """The configured secret's project and ID. A value that isn't a secret's resource name (a
    placeholder left in place, say) fails with a message naming the variable, rather than as an
    argument error from the cache."""
    value = configured(SECRET_NAME_VARIABLE)
    assert value is not None
    match = _SECRET_NAME.fullmatch(value)
    if match is None:
        raise AssertionError(f"{SECRET_NAME_VARIABLE} is {value!r}, which isn't a secret's resource name: projects/{{project}}/secrets/{{secret}}. "
                             f"Replace the placeholders in {SETTINGS_FILE} (docs/how-to/run-google-secret-manager-cache-integration-tests.md, "
                             "step 5).")
    return match.group(1), match.group(2)


@pytest.fixture
def cache(secret: tuple[str, str]) -> Iterator[GoogleSecretManagerSecretCache]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(_FixedKeyWrapper(), b"wrapped", 60)))
        with GoogleSecretManagerSecretCache.create(secret[0], ring) as cache:
            yield cache


def test_decrypt_reveals_the_secret(cache: GoogleSecretManagerSecretCache, secret: tuple[str, str]) -> None:
    length = cache.find_max_decrypted_length(secret[1])

    assert length
    assert cache.decrypt(secret[1], bytearray(length)) > 0


def test_decrypt_async_reveals_the_secret(cache: GoogleSecretManagerSecretCache, secret: tuple[str, str]) -> None:
    async def scenario() -> None:
        length = await cache.find_max_decrypted_length_async(secret[1])
        assert length
        assert await cache.decrypt_async(secret[1], bytearray(length)) > 0

    asyncio.run(scenario())


@needs_expected_json
def test_decrypt_reveals_the_expected_whole_value_and_every_key(cache: GoogleSecretManagerSecretCache, secret: tuple[str, str]) -> None:
    assert_whole_value(decrypt(cache, secret[1]))
    for key, value in members(expected_json()):
        assert decrypt(cache, f"{secret[1]}#{key}") == value, f"'{secret[1]}#{key}' isn't the expected value."
    assert cache.decrypt(f"{secret[1]}#no-such-key", bytearray(16)) == 0


@needs_expected_json
def test_decrypt_async_reveals_every_key_and_the_expected_whole_value(cache: GoogleSecretManagerSecretCache, secret: tuple[str, str]) -> None:
    async def scenario() -> None:
        for key, value in members(expected_json()):
            assert await decrypt_async(cache, f"{secret[1]}#{key}") == value, f"'{secret[1]}#{key}' isn't the expected value."
        assert_whole_value(await decrypt_async(cache, secret[1]))
        assert await cache.decrypt_async(f"{secret[1]}#no-such-key", bytearray(16)) == 0

    asyncio.run(scenario())


def test_decrypt_of_a_secret_that_does_not_exist_returns_zero(cache: GoogleSecretManagerSecretCache) -> None:
    assert cache.decrypt(f"hkdfguard-missing-{uuid.uuid4().hex}", bytearray(16)) == 0
