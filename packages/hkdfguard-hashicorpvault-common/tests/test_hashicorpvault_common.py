"""The checks and backoff every Vault integration shares."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, replace
from datetime import timedelta

import pytest
from hkdfguard.hashicorpvault.common import (
    MAX_RETRY_COUNT,
    MAX_RETRY_DELAY,
    MIN_RETRY_COUNT,
    VaultRequestError,
    api_base,
    check_connection_options,
    is_valid_path,
    is_valid_segment,
    is_valid_token,
    retry_delay,
)


@dataclass(frozen=True, slots=True)
class Options:
    mount_path: str = "transit"
    namespace: str | None = None
    timeout: timedelta = timedelta(seconds=30)
    retry_count: int = MIN_RETRY_COUNT
    retry_delay: timedelta = timedelta(milliseconds=200)
    ssl_context: ssl.SSLContext | None = None


# --- api_base ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("address", "expected"), [
    ("https://vault.example.com:8200", (True, "vault.example.com", 8200, "/v1/")),
    ("https://vault.example.com/", (True, "vault.example.com", None, "/v1/")),
    ("https://vault.example.com/proxy/vault/", (True, "vault.example.com", None, "/proxy/vault/v1/")),
    ("HTTPS://Vault.Example.com", (True, "vault.example.com", None, "/v1/")),
    ("http://127.0.0.1:8200", (False, "127.0.0.1", 8200, "/v1/")),
    ("http://127.8.9.10", (False, "127.8.9.10", None, "/v1/")),
    ("http://localhost:8200", (False, "localhost", 8200, "/v1/")),
    ("http://[::1]:8200", (False, "::1", 8200, "/v1/")),
])
def test_api_base_splits_an_https_or_loopback_address(address: str, expected: tuple[bool, str, int | None, str]) -> None:
    assert api_base(address) == expected


@pytest.mark.parametrize("address", [
    "http://vault.example.com:8200",  # http off loopback
    "http://10.0.0.1",
    "http://127.0.0.1.example.com",  # a name, never resolved
    "http://[::ffff:10.0.0.1]",
    "ftp://127.0.0.1",
    "vault.example.com:8200",  # not absolute
    "/v1/transit",
    "",
    "https://user:pass@vault.example.com",  # credentials
    "https://vault.example.com?x=1",  # query
    "https://vault.example.com#x",  # fragment
])
def test_api_base_refuses_an_address_that_could_leak_the_token(address: str) -> None:
    with pytest.raises(ValueError, match="Vault's address"):
        api_base(address)


def test_api_base_refuses_a_non_str() -> None:
    with pytest.raises(TypeError):
        api_base(b"https://vault.example.com")  # type: ignore[arg-type]


# --- paths and tokens ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["transit", "kv/team-a", "a.b_c-d/E9", "secret/data/myapp"])
def test_a_path_of_plain_segments_is_valid(path: str) -> None:
    assert is_valid_path(path)


@pytest.mark.parametrize("path", ["", "/transit", "transit/", "a//b", "a/../b", ".", "..", "a/./b", "a b", "a%2Fb", "transít", None, 7])
def test_a_path_that_could_move_is_invalid(path: object) -> None:
    assert not is_valid_path(path)


@pytest.mark.parametrize(("segment", "expected"), [("key", True), ("my-key.v2_1", True), ("", False), (".", False), ("..", False), ("a/b", False)])
def test_is_valid_segment(segment: str, expected: bool) -> None:
    assert is_valid_segment(segment) is expected


@pytest.mark.parametrize(("token", "expected"), [
    (b"hvs.CAESIJ", True), (b"!~", True), (b"", False), (b"has space", False), (b"tab\t", False), (b"\x7f", False), ("é".encode(), False),
])
def test_a_token_is_non_empty_printable_ascii_without_spaces(token: bytes, expected: bool) -> None:
    assert is_valid_token(token) is expected
    assert is_valid_token(bytearray(token)) is expected


# --- retries ------------------------------------------------------------------------------------


@pytest.mark.parametrize(("base", "retry", "jitter", "expected"), [
    (200, 0, 0, 200), (200, 1, 0, 400), (200, 2, 0, 800), (200, 5, 0, 6400), (200, 6, 0, 10000), (200, 9, 0, 10000),
    (200, 0, 100, 300), (200, 9, 100, 10100), (0, 3, 37, 37), (10000, 0, 0, 10000), (10000, 40, 0, 10000),
])
def test_retry_delay_doubles_up_to_the_maximum_plus_the_jitter(base: int, retry: int, jitter: int, expected: int) -> None:
    assert retry_delay(timedelta(milliseconds=base), retry, jitter) == timedelta(milliseconds=expected)


# --- check_connection_options -------------------------------------------------------------------


@pytest.mark.parametrize("options", [
    Options(),
    Options(mount_path="transit/team-a", namespace="team-a/prod"),
    Options(retry_count=MAX_RETRY_COUNT, retry_delay=MAX_RETRY_DELAY),
    Options(retry_delay=timedelta(0)),
    Options(ssl_context=ssl.create_default_context()),
])
def test_check_connection_options_accepts_options_in_range(options: Options) -> None:
    check_connection_options(options)


@pytest.mark.parametrize(("changes", "message"), [
    ({"mount_path": "a/../b"}, "mount path"),
    ({"namespace": "/root"}, "namespace"),
    ({"timeout": timedelta(0)}, "timeout must be positive"),
    ({"retry_count": MIN_RETRY_COUNT - 1}, "retry count"),
    ({"retry_count": MAX_RETRY_COUNT + 1}, "retry count"),
    ({"retry_delay": timedelta(milliseconds=-1)}, "retry delay"),
    ({"retry_delay": MAX_RETRY_DELAY + timedelta(microseconds=1)}, "retry delay"),
])
def test_check_connection_options_refuses_values_out_of_range(changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        check_connection_options(replace(Options(), **changes))  # type: ignore[arg-type]


@pytest.mark.parametrize("changes", [
    {"timeout": 30}, {"retry_delay": 0.2}, {"retry_count": 3.0}, {"retry_count": True}, {"ssl_context": object()},
])
def test_check_connection_options_refuses_values_of_the_wrong_type(changes: dict[str, object]) -> None:
    with pytest.raises(TypeError):
        check_connection_options(replace(Options(), **changes))  # type: ignore[arg-type]


# --- VaultRequestError --------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "transient"), [(429, True), (500, True), (503, True), (599, True), (501, False), (400, False), (403, False),
                                                   (404, False), (307, False)])
def test_a_vault_request_error_is_transient_only_for_429_and_5xx_but_501(status: int, transient: bool) -> None:
    error = VaultRequestError("Vault refused", status)

    assert error.status_code == status
    assert error.is_transient is transient
    assert str(error) == "Vault refused"
