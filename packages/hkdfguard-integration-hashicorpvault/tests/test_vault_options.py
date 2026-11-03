"""VaultClientOptions: what the client refuses, and what the environment sets."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from hkdfguard.abstractions import DataProtector
from hkdfguard.integration.hashicorpvault import (
    DEFAULT_ADDRESS,
    StaticVaultToken,
    VaultClient,
    VaultClientOptions,
    VaultRequestOptions,
    VaultRetryOptions,
    VaultTlsOptions,
)
from vault_client_test_support import decrypt


@pytest.mark.parametrize("address", ["https://vault.example.com:8200", "http://127.0.0.1:8200", "http://localhost", "http://[::1]:8200",
                                     "https://vault.example.com/prefix/"])
def test_an_address_that_keeps_the_token_safe_is_accepted(protector: DataProtector, address: str) -> None:
    VaultClient(protector, VaultClientOptions(address=address)).close()


@pytest.mark.parametrize(("address", "why"), [
    ("unix:///var/run/vault.sock", "unix socket"),
    ("vault.example.com:8200", "isn't absolute"),
    ("/v1", "isn't absolute"),
    ("http://vault.example.com:8200", "must be https"),
    ("http://127.0.0.1.example.com", "must be https"),
    ("https://user:pw@vault.example.com", "credentials"),
    ("https://vault.example.com/?q=1", "query"),
    ("https://vault.example.com/#f", "fragment"),
])
def test_an_address_that_would_risk_the_token_is_refused_naming_why(protector: DataProtector, address: str, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        VaultClient(protector, VaultClientOptions(address=address))


def test_http_anywhere_is_accepted_when_allowed(protector: DataProtector) -> None:
    VaultClient(protector, VaultClientOptions(address="http://vault.example.com:8200", allow_unencrypted_http=True)).close()


def test_a_missing_protector_or_options_of_the_wrong_type_are_refused(protector: DataProtector) -> None:
    with pytest.raises(TypeError):
        VaultClient(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        VaultClient(protector, {"address": DEFAULT_ADDRESS})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        VaultClient(protector, VaultClientOptions(ssl_context="not a context"))  # type: ignore[arg-type]


def test_negative_times_and_unsendable_namespaces_are_refused(protector: DataProtector) -> None:
    for options in (VaultClientOptions(request_timeout=timedelta(seconds=-1)),
                    VaultClientOptions(retry=VaultRetryOptions(retry_wait_min=timedelta(seconds=-1))),
                    VaultClientOptions(retry=VaultRetryOptions(retry_wait_max=timedelta(seconds=-1))),
                    VaultClientOptions(namespace="bad\u0001")):
        with pytest.raises(ValueError):
            VaultClient(protector, options)


def test_a_requests_unsendable_settings_raise_from_the_call(make_client: object, protector: DataProtector) -> None:
    client = VaultClient(protector)
    for options in (VaultRequestOptions(namespace="a\nb"), VaultRequestOptions(mfa_credentials=[""]),
                    VaultRequestOptions(custom_headers={"X-Vault-Anything": ["x"]}),
                    VaultRequestOptions(response_wrapping_ttl=timedelta(seconds=-1))):
        with pytest.raises(ValueError):
            client.read("a", options)


def test_no_options_are_the_defaults(protector: DataProtector) -> None:
    client = VaultClient(protector)
    options = client.options
    assert (options.address, options.request_timeout, options.follow_redirects, options.allow_unencrypted_http) == (
        "https://127.0.0.1:8200", timedelta(seconds=60), False, False)
    assert (options.retry.retry_wait_min, options.retry.retry_wait_max, options.retry.retry_max) == (
        timedelta(seconds=1), timedelta(milliseconds=1500), 2)
    assert options.token is None and options.namespace is None and options.rate_limiter is None and options.tls is None


def test_replace_keeps_every_other_option() -> None:
    options = VaultClientOptions(address="https://a", namespace="n", follow_redirects=True)
    changed = replace(options, address="https://b")
    assert (changed.address, changed.namespace, changed.follow_redirects) == ("https://b", "n", True)


_EVERYTHING = {
    "VAULT_ADDR": "https://ignored.example.com",
    "VAULT_AGENT_ADDR": "https://agent.example.com:8100",
    "VAULT_CLIENT_TIMEOUT": "1m30s",
    "VAULT_RATE_LIMIT": "2.5:4",
    "VAULT_DISABLE_REDIRECTS": "true",
    "VAULT_TOKEN": "hvs.fromenv",
    "VAULT_NAMESPACE": "team a",
    "VAULT_SKIP_VERIFY": "1",
    "VAULT_CACERT": "/etc/ca.pem",
    "VAULT_CACERT_BYTES": "-----BEGIN CERTIFICATE-----",
    "VAULT_CAPATH": "/etc/cas",
    "VAULT_CLIENT_CERT": "/etc/client.pem",
    "VAULT_CLIENT_KEY": "/etc/client-key.pem",
    "VAULT_TLS_SERVER_NAME": "vault.internal",
    "VAULT_RETRY_WAIT_MIN": "250ms",
    "VAULT_RETRY_WAIT_MAX": "2s",
    "VAULT_MAX_RETRIES": "5",
}


def test_from_environment_reads_every_variable(protector: DataProtector) -> None:
    options = VaultClientOptions.from_environment(protector, _EVERYTHING)
    assert options.address == "https://agent.example.com:8100"
    assert options.request_timeout == timedelta(seconds=90)
    assert options.rate_limiter is not None and (options.rate_limiter.requests_per_second, options.rate_limiter.burst) == (2.5, 4)
    assert options.follow_redirects is False
    assert isinstance(options.token, StaticVaultToken) and decrypt(protector, options.token) == "hvs.fromenv"
    assert options.namespace == "team a"
    assert options.tls == VaultTlsOptions(insecure_skip_verify=True, server_certificate_file=Path("/etc/ca.pem"),
                                          server_certificate_pem=b"-----BEGIN CERTIFICATE-----", server_certificate_directory=Path("/etc/cas"),
                                          client_certificate_file=Path("/etc/client.pem"), client_certificate_key_file=Path("/etc/client-key.pem"),
                                          server_name="vault.internal")
    assert options.retry == VaultRetryOptions(retry_wait_min=timedelta(milliseconds=250), retry_wait_max=timedelta(seconds=2), retry_max=5)


def test_from_environment_with_nothing_set_is_the_defaults() -> None:
    assert VaultClientOptions.from_environment(None, {}) == VaultClientOptions()


def test_from_environment_reads_the_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://process.example.com")
    assert VaultClientOptions.from_environment().address == "https://process.example.com"
    assert os.environ["VAULT_ADDR"] == "https://process.example.com"


def test_from_environment_protects_vault_token_only_given_a_protector(protector: DataProtector) -> None:
    assert VaultClientOptions.from_environment(None, {"VAULT_TOKEN": "hvs.x"}).token is None
    with pytest.raises(ValueError, match="VAULT_TOKEN"):
        VaultClientOptions.from_environment(protector, {"VAULT_TOKEN": "has space"})


def test_from_environment_refuses_what_isnt_a_value() -> None:
    for name, value in (("VAULT_NAMESPACE", "a\nb"), ("VAULT_CLIENT_TIMEOUT", "soon"), ("VAULT_RATE_LIMIT", "fast"), ("VAULT_SKIP_VERIFY", "yes"),
                        ("VAULT_MAX_RETRIES", "many"), ("VAULT_ADDR", "not-a-url")):
        with pytest.raises(ValueError, match=name):
            VaultClientOptions.from_environment(None, {name: value})


def test_from_environment_an_empty_variable_is_unset() -> None:
    assert VaultClientOptions.from_environment(None, {"VAULT_ADDR": "", "VAULT_NAMESPACE": ""}) == VaultClientOptions()


def test_from_environment_disable_redirects_false_leaves_them_as_they_are() -> None:
    assert VaultClientOptions.from_environment(None, {"VAULT_DISABLE_REDIRECTS": "false"}).follow_redirects is False
    limiter = VaultClientOptions.from_environment(None, {"VAULT_RATE_LIMIT": "3.7"}).rate_limiter
    assert limiter is not None and limiter.burst == 3
