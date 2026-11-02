"""Real calls against a secret the caller provides, named in aws.test.properties at the repository root
(or the environment; see :func:`settings`), as the principal whose access keys are in the environment
or the shared credentials file (see :func:`credentials`); the region comes from botocore's usual
chain (``AWS_REGION``, ``AWS_DEFAULT_REGION``, the profile's ``region``)::

    aws configure
    HKDFGUARD_TEST_AWS_SECRET_NAME=prod/my-secret uv run pytest packages/hkdfguard-cache-awssecretsmanager

Without HKDFGUARD_TEST_AWS_SECRET_NAME every test here is reported as skipped - never as passed. Once
it names a secret, a failing call - or a value that isn't a secret name - is a test failure. To check
what the secret holds, not just that it holds something, also set HKDFGUARD_TEST_AWS_SECRET_JSON to the
JSON object its SecretString is expected to hold (a key/value secret, as the console stores one): the
whole value and each key, read as ``"name#key"``, are then compared with it. The principal needs only
secretsmanager:GetSecretValue on that secret's path (and kms:Decrypt on its key, if it isn't the AWS
managed one); the tests never list, create, alter or delete a secret. See
docs/how-to/run-aws-secrets-manager-cache-integration-tests.md."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Buffer, Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import botocore.configloader
import botocore.session
import pytest
from hkdfguard.abstractions import KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache.awssecretsmanager import AwsSecretsManagerSecretCache
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing

SECRET_NAME_VARIABLE = "HKDFGUARD_TEST_AWS_SECRET_NAME"
EXPECTED_JSON_VARIABLE = "HKDFGUARD_TEST_AWS_SECRET_JSON"
SETTINGS_FILE = "aws.test.properties"
HOW_TO = "docs/how-to/run-aws-secrets-manager-cache-integration-tests.md"


def settings() -> dict[str, str]:
    """The settings file at the repository root - the nearest directory above this file that holds
    uv.lock - as ``NAME=value`` lines, ``#`` and ``!`` starting a comment; empty if there is none. The
    same file as hkdfguard-java's: a local file, ignored by git, naming the secret (and its expected
    content) only - credentials come from :func:`credentials`, so no credential ever goes in it."""
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
    """``variable`` from the environment, else from the settings file; ``None`` if neither sets it."""
    return os.environ.get(variable) or settings().get(variable) or None


pytestmark = pytest.mark.skipif(setting(SECRET_NAME_VARIABLE) is None,
                                reason=f"Set {SECRET_NAME_VARIABLE} to a secret's name, in the environment or {SETTINGS_FILE}, to run AWS Secrets "
                                       "Manager cache integration tests.")

requires_expected_json = pytest.mark.skipif(setting(EXPECTED_JSON_VARIABLE) is None,
                                            reason=f"Set {SECRET_NAME_VARIABLE} and {EXPECTED_JSON_VARIABLE}, in the environment or {SETTINGS_FILE}, "
                                                   "to check a secret's contents.")


def credentials() -> dict[str, str]:
    """The test principal's access keys, as ``create_client`` keyword arguments: from
    AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN), else from the shared credentials
    file's profile (AWS_PROFILE, or ``default``) - the file ``aws configure`` writes
    (AWS_SHARED_CREDENTIALS_FILE, or ~/.aws/credentials), read on its own, as hkdfguard-java's tests
    read it. botocore's default chain merges ~/.aws/config into that profile, and a login_session
    there (from ``aws login``) would take precedence over its keys, running the tests as whoever
    signed in rather than as the test principal. No message here ever quotes a key."""
    key_id, secret = os.environ.get("AWS_ACCESS_KEY_ID"), os.environ.get("AWS_SECRET_ACCESS_KEY")
    token = os.environ.get("AWS_SESSION_TOKEN")
    if not (key_id and secret):
        path = Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or Path.home() / ".aws" / "credentials").expanduser()
        if not path.is_file():
            raise AssertionError(f"There is no AWS credentials file at {path}; run aws configure, or set AWS_ACCESS_KEY_ID. See {HOW_TO}.")
        profile_name = os.environ.get("AWS_PROFILE") or "default"
        profile = botocore.configloader.raw_config_parse(str(path)).get(profile_name, {})
        key_id, secret, token = profile.get("aws_access_key_id"), profile.get("aws_secret_access_key"), profile.get("aws_session_token")
        if not (key_id and secret):
            raise AssertionError(f"The [{profile_name}] profile in {path} has no aws_access_key_id and aws_secret_access_key; run aws configure. "
                                 f"See {HOW_TO}.")
    keys = {"aws_access_key_id": key_id, "aws_secret_access_key": secret}
    if token:
        keys["aws_session_token"] = token
    return keys


class FixedKeyWrapper(KeyWrapper):
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


@pytest.fixture
def secret_name() -> str:
    name = setting(SECRET_NAME_VARIABLE)
    assert name is not None
    # A value the cache would report missing without a call (a placeholder or an ARN, say) fails with
    # a message naming the variable, rather than as a secret that isn't there.
    if not AwsSecretsManagerSecretCache.is_valid_secret_name(name):
        raise AssertionError(f"{SECRET_NAME_VARIABLE} is {name!r}, which isn't a secret's name: 1-{AwsSecretsManagerSecretCache.MAX_SECRET_NAME_LENGTH} "
                             f"ASCII letters, digits and /_+=.@- (not an ARN). See {HOW_TO}.")
    return name


@pytest.fixture
def client() -> Iterator[Any]:
    # The application creates (and closes) the client; boto3.client("secretsmanager", ...) would be the same botocore client.
    created = botocore.session.get_session().create_client("secretsmanager", **credentials())
    try:
        yield created
    finally:
        created.close()


@pytest.fixture
def cache(client: Any) -> Iterator[AwsSecretsManagerSecretCache]:
    with DefaultKeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
        yield AwsSecretsManagerSecretCache(client, ring)


# --- The expected secret (hkdfguard-dotnet's ExpectedSecret) ---------------------------------------


class _JsonNumber(str):
    """A JSON number, kept as the text it was written as."""


def expected() -> dict[str, Any]:
    """HKDFGUARD_TEST_AWS_SECRET_JSON's JSON object."""
    text = setting(EXPECTED_JSON_VARIABLE)
    assert text is not None
    try:
        value = json.loads(text, parse_int=_JsonNumber, parse_float=_JsonNumber)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{EXPECTED_JSON_VARIABLE} isn't JSON (at line {error.lineno}, column {error.colno}).") from None
    if not isinstance(value, dict):
        raise AssertionError(f"{EXPECTED_JSON_VARIABLE} isn't a JSON object.")
    return value


def members(expected_object: dict[str, Any]) -> list[tuple[str, str]]:
    """Each member as the cache reveals it under ``"name#key"``: a string as its text, a number, true
    or false as its JSON text; null, objects and arrays aren't keys."""
    found: list[tuple[str, str]] = []
    for key, value in expected_object.items():
        if isinstance(value, bool):
            found.append((key, "true" if value else "false"))
        elif isinstance(value, str):  # a _JsonNumber is its JSON text already
            found.append((key, str(value)))
    return found


def decrypt(cache: ProtectedReadOnlyCache, name: str) -> str:
    """The value stored under ``name``, as text; fails the test if there is none."""
    length = cache.find_max_decrypted_length(name)
    assert length is not None, f"Nothing is stored under {name!r}."
    result = bytearray(length)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_async(cache: ProtectedReadOnlyCache, name: str) -> str:
    """:func:`decrypt`, through decrypt_async."""
    length = await cache.find_max_decrypted_length_async(name)
    assert length is not None and length > 0, f"Nothing is stored under {name!r}."
    result = bytearray(length)
    return result[: await cache.decrypt_async(name, result)].decode()


def assert_whole_value(whole: str) -> None:
    """Asserts ``whole`` is HKDFGUARD_TEST_AWS_SECRET_JSON's object, compared as JSON, so whitespace the
    store added or removed doesn't matter. Never quotes either value."""
    text = setting(EXPECTED_JSON_VARIABLE)
    assert text is not None
    try:
        actual = json.loads(whole, parse_float=Decimal)
    except json.JSONDecodeError:
        actual = None
    if actual != json.loads(text, parse_float=Decimal):
        pytest.fail("The secret's whole value isn't the expected JSON object.")


def assert_key(actual: str, expected_value: str, key: str) -> None:
    # Never quotes either value, as pytest's assertion rewriting would.
    if actual != expected_value:
        pytest.fail(f"Key {key!r} isn't the expected value.")


# --- Tests ----------------------------------------------------------------------------------------


def test_decrypt_reveals_the_secret(cache: AwsSecretsManagerSecretCache, secret_name: str) -> None:
    length = cache.find_max_decrypted_length(secret_name)
    assert length is not None
    assert cache.decrypt(secret_name, bytearray(length)) > 0


def test_decrypt_async_reveals_the_secret(cache: AwsSecretsManagerSecretCache, secret_name: str) -> None:
    async def run() -> None:
        length = await cache.find_max_decrypted_length_async(secret_name)
        assert length is not None and length > 0
        assert await cache.decrypt_async(secret_name, bytearray(length)) > 0

    asyncio.run(run())


@requires_expected_json
def test_decrypt_reveals_the_expected_whole_value_and_every_key(cache: AwsSecretsManagerSecretCache, secret_name: str) -> None:
    expected_object = expected()

    assert_whole_value(decrypt(cache, secret_name))
    for key, value in members(expected_object):
        assert_key(decrypt(cache, f"{secret_name}#{key}"), value, key)
    assert cache.decrypt(f"{secret_name}#no-such-key", bytearray(16)) == 0


@requires_expected_json
def test_decrypt_async_reveals_every_key_and_the_expected_whole_value(cache: AwsSecretsManagerSecretCache, secret_name: str) -> None:
    expected_object = expected()

    async def run() -> None:
        for key, value in members(expected_object):
            assert_key(await decrypt_async(cache, f"{secret_name}#{key}"), value, key)
        assert_whole_value(await decrypt_async(cache, secret_name))
        assert await cache.decrypt_async(f"{secret_name}#no-such-key", bytearray(16)) == 0

    asyncio.run(run())


def test_decrypt_of_a_secret_that_does_not_exist_returns_zero(cache: AwsSecretsManagerSecretCache, secret_name: str) -> None:
    # Beside the configured secret, so a policy granting GetSecretValue on its path covers it: without
    # permission, Secrets Manager answers AccessDenied even for a secret that doesn't exist.
    folder = secret_name[: secret_name.rfind("/") + 1]
    assert cache.decrypt(f"{folder}hkdfguard-missing-{uuid.uuid4().hex}", bytearray(16)) == 0
