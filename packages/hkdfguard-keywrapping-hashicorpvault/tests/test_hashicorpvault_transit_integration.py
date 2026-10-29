"""Real calls against a transit key the caller provides, with a token the caller provides - on a dev
server, the ones scripts/provision-vault-transit-test-key.sh creates and prints::

    HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \\
    HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \\
    uv run pytest packages/hkdfguard-keywrapping-hashicorpvault

Without HKDFGUARD_TEST_VAULT_TRANSIT_KEY every test here is reported as skipped - never as passed;
once it is set, a failing call is a test failure. HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY names a
second key for the cross-key test, which is skipped without it. HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT
names a mount other than "transit", and HKDFGUARD_TEST_VAULT_CACERT a CA for a server certificate
the system's trust store doesn't trust. The token needs only update on encrypt, decrypt and
datakey/wrapped for the keys; the tests never create, rotate, read or delete a key. See
docs/how-to/run-hashicorp-vault-transit-integration-tests.md.

The variables are the .NET integration tests'. The keys, the mount, Vault's address and its CA
certificate are read from the environment, else from vault.test.properties at the repository root -
the file the Vault cache's integration tests read: a local file, ignored by git. The token is read
from the environment only, never from a file."""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import pytest
from hkdfguard.abstractions import ArrayUtility, CryptographicError, WrappedKeyLimits
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.keywrapping.hashicorpvault import HashiCorpVaultTransitKeyWrapper, HashiCorpVaultTransitKeyWrapperOptions, StaticVaultTokenSource

KEY_VARIABLE = "HKDFGUARD_TEST_VAULT_TRANSIT_KEY"
OTHER_KEY_VARIABLE = "HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY"
MOUNT_VARIABLE = "HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT"
ADDRESS_VARIABLE = "HKDFGUARD_TEST_VAULT_ADDR"
TOKEN_VARIABLE = "HKDFGUARD_TEST_VAULT_TOKEN"
CA_CERTIFICATE_VARIABLE = "HKDFGUARD_TEST_VAULT_CACERT"
SETTINGS_FILE = "vault.test.properties"
DEFAULT_ADDRESS = "http://127.0.0.1:8200"
CONTEXT = "hkdfguard.integrationtest"


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


pytestmark = pytest.mark.skipif(configured(KEY_VARIABLE) is None,
                                reason=f"Set {KEY_VARIABLE} (with {ADDRESS_VARIABLE} and {TOKEN_VARIABLE}) to a transit key, in the environment or "
                                       f"{SETTINGS_FILE}, to run Vault transit integration tests.")

needs_other_key = pytest.mark.skipif(configured(OTHER_KEY_VARIABLE) is None,
                                     reason=f"Set {KEY_VARIABLE} and {OTHER_KEY_VARIABLE} to two transit keys to check one refuses the other's DEKs.")


def options() -> HashiCorpVaultTransitKeyWrapperOptions:
    # A context trusting HKDFGUARD_TEST_VAULT_CACERT, and only it, when set; otherwise the wrapper's
    # default, the system's trust store.
    ca_certificate = configured(CA_CERTIFICATE_VARIABLE)
    return HashiCorpVaultTransitKeyWrapperOptions(mount_path=configured(MOUNT_VARIABLE) or "transit",
                                                  ssl_context=ssl.create_default_context(cafile=ca_certificate) if ca_certificate else None)


def create(context: str | None = CONTEXT, key_name: str | None = None, token: str | None = None) -> HashiCorpVaultTransitKeyWrapper:
    if token is None:
        token = os.environ.get(TOKEN_VARIABLE)
        if not token:
            pytest.fail(f"Set {TOKEN_VARIABLE} in the environment (never in {SETTINGS_FILE}) to a token allowed to use {KEY_VARIABLE}.")
    key = key_name or configured(KEY_VARIABLE)
    assert key is not None
    return HashiCorpVaultTransitKeyWrapper(configured(ADDRESS_VARIABLE) or DEFAULT_ADDRESS, key, StaticVaultTokenSource(token), context,
                                           options=options())


def generate(wrapper: HashiCorpVaultTransitKeyWrapper) -> bytearray:
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    return wrapped[:wrapper.generate_and_wrap(wrapped)]


def test_wrap_then_unwrap_round_trips_a_32_byte_dek() -> None:
    wrapper = create()
    dek = os.urandom(32)

    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.wrap(bytearray(dek), wrapped)
    revealed = bytearray(32)

    assert wrapped[:length].startswith(b"vault:v")
    assert wrapper.unwrap(wrapped[:length], revealed) == 32
    assert revealed == dek


def test_generate_and_wrap_in_vault_produces_a_wrapped_dek_that_reveals() -> None:
    # No context: Vault generates the DEK with datakey/wrapped.
    wrapper = create(context=None)
    revealed = bytearray(32)

    assert wrapper.unwrap(generate(wrapper), revealed) == 32
    assert not ArrayUtility.is_null_or_empty(revealed) and any(revealed)


def test_generate_and_wrap_with_a_context_produces_a_wrapped_dek_that_reveals() -> None:
    wrapper = create()
    revealed = bytearray(32)

    assert wrapper.unwrap(generate(wrapper), revealed) == 32
    assert any(revealed)


def test_unwrap_under_another_context_or_none_is_refused() -> None:
    wrapped = generate(create())

    with pytest.raises(CryptographicError):
        create(context="hkdfguard.integrationtest.other").unwrap(wrapped, bytearray(32))
    with pytest.raises(CryptographicError):
        create(context=None).unwrap(wrapped, bytearray(32))


def test_unwrap_when_tampered_is_refused() -> None:
    wrapper = create()
    wrapped = generate(wrapper)
    # Another base64 character, so it reaches Vault and fails there.
    wrapped[12] = ord("B") if wrapped[12] == ord("A") else ord("A")

    with pytest.raises(CryptographicError, match="400"):
        wrapper.unwrap(wrapped, bytearray(32))


@needs_other_key
def test_unwrap_under_another_key_is_refused() -> None:
    wrapped = generate(create())

    with pytest.raises(CryptographicError):
        create(key_name=configured(OTHER_KEY_VARIABLE)).unwrap(wrapped, bytearray(32))


def test_an_invalid_token_is_refused_with_403() -> None:
    wrapper = create(token="hvs.not-a-real-token")

    with pytest.raises(CryptographicError, match="403"):
        wrapper.generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))


def test_a_crypto_provider_generates_and_reveals_its_dek_through_vault() -> None:
    with AesGcmCryptoProviderFactory().create_ephemeral(create(), 60) as provider:
        expected = b"hello, vault transit"
        plaintext = bytearray(expected)
        encrypted = bytearray(provider.get_encrypted_allocation_length(len(plaintext)))
        encrypted_length = provider.encrypt(plaintext, encrypted)
        decrypted = bytearray(provider.get_decrypted_allocation_length(encrypted_length))
        decrypted_length = provider.decrypt(encrypted[:encrypted_length], decrypted)

        assert decrypted[:decrypted_length] == expected
