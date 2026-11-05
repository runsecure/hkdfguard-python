"""VaultClient when things go wrong: retries, redirects, timeouts, rate limits, read-your-writes, and TLS."""

from __future__ import annotations

import http.client
import logging
import ssl
import threading
import time
from datetime import timedelta

import pytest
from hkdfguard.abstractions import DataProtector
from hkdfguard.integration.hashicorpvault import (
    StaticVaultToken,
    VaultClient,
    VaultClientOptions,
    VaultRateLimiter,
    VaultRedirectError,
    VaultResponseError,
    VaultRetryOptions,
    VaultTlsOptions,
    VaultTokenProvider,
    default_retry_policy,
    linear_jitter_backoff,
)
from vault_client_test_support import DROP, TOKEN, Answer, FakeVault, MakeClient, Tls


def test_once_retries_run_out_the_last_response_is_the_error(vault: FakeVault, make_client: MakeClient) -> None:
    vault.respond = lambda _: Answer(503, '{"errors":["sealed"]}')
    with pytest.raises(VaultResponseError, match="sealed") as raised:
        make_client().read("a")
    assert raised.value.status_code == 503
    assert len(vault.requests) == 3


def test_no_answer_is_retried_and_once_retries_run_out_its_error_propagates(vault: FakeVault, make_client: MakeClient) -> None:
    vault.respond = lambda _: DROP
    with pytest.raises((OSError, http.client.HTTPException)):
        make_client().read("a")
    assert len(vault.requests) == 3


def test_no_answer_then_an_answer_succeeds(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(lambda _: DROP).then(200, '{"data":{"ok":true}}')
    response = make_client().read("a")
    assert response is not None and response.data is not None and response.data["ok"].as_bool()
    assert len(vault.requests) == 2


class _CountingProvider(VaultTokenProvider):
    def __init__(self, protector: DataProtector, delay: float = 0) -> None:
        self.token = StaticVaultToken.protect(protector, TOKEN).get_token()
        self.delay = delay
        self.calls = 0

    def get_token(self) -> str:
        self.calls += 1
        time.sleep(self.delay)
        return self.token


def test_the_token_provider_is_asked_once_per_request_not_per_retry(vault: FakeVault, make_client: MakeClient, protector: DataProtector) -> None:
    provider = _CountingProvider(protector)
    vault.then(503).then(503)
    make_client(token=provider).read("a")
    assert provider.calls == 1
    assert [r.header("X-Vault-Token") for r in vault.requests] == [TOKEN] * 3


def test_a_custom_retry_policy_and_backoff_are_used(vault: FakeVault, make_client: MakeClient) -> None:
    seen: list[tuple[int, int]] = []

    def backoff(minimum: timedelta, maximum: timedelta, attempt: int, status: int) -> timedelta:
        seen.append((attempt, status))
        return timedelta(0)

    vault.then(418).then(418)
    make_client(retry=VaultRetryOptions(retry_max=5, check_retry=lambda status, failure: status == 418, backoff=backoff)).read("a")
    assert seen == [(0, 418), (1, 418)]
    assert len(vault.requests) == 3


def test_retries_are_logged_without_the_query(vault: FakeVault, make_client: MakeClient, caplog: pytest.LogCaptureFixture) -> None:
    vault.then(503)
    with caplog.at_level(logging.WARNING, "hkdfguard.integration.hashicorpvault"):
        make_client().read("secret/a?secret=hidden")
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "/v1/secret/a" in message and "hidden" not in message and "retry 1 of 2" in message


def test_linear_jitter_backoff_is_between_min_and_max_times_the_attempts() -> None:
    low, high = timedelta(seconds=1), timedelta(seconds=2)
    for attempt in range(3):
        for _ in range(20):
            assert low * (attempt + 1) <= linear_jitter_backoff(low, high, attempt, 503) <= high * (attempt + 1)
    assert linear_jitter_backoff(high, low, 2, 0) == high * 3


def test_the_default_retry_policy_retries_what_another_attempt_may_not_meet() -> None:
    assert [s for s in (0, 200, 400, 403, 412, 429, 500, 501, 503) if default_retry_policy(s, None)] == [0, 412, 429, 500, 503]
    assert default_retry_policy(0, ConnectionResetError())
    refused = ssl.SSLCertVerificationError("bad certificate")
    assert not default_retry_policy(0, refused)
    try:
        try:
            raise refused
        except ssl.SSLError as inner:
            raise OSError("wrapped") from inner
    except OSError as outer:
        assert not default_retry_policy(0, outer)


# --- Redirects ------------------------------------------------------------------------------------


def test_a_relative_redirect_is_resolved_against_the_request(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(307, Location="/v1/elsewhere?x=1").then(200, '{"data":{}}')
    make_client(follow_redirects=True).read("a")
    assert [r.target for r in vault.requests] == ["/v1/a", "/v1/elsewhere?x=1"]
    assert vault.requests[1].header("X-Vault-Token") == TOKEN


def test_a_second_redirect_fails(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(307, Location="/v1/b").then(302, Location="/v1/c")
    with pytest.raises(VaultRedirectError, match="at most one redirect"):
        make_client(follow_redirects=True).read("a")


def test_an_http_redirect_is_followed_on_loopback(vault: FakeVault, make_client: MakeClient) -> None:
    other = FakeVault()
    try:
        vault.then(301, Location=f"http://localhost:{other.port}/v1/moved")
        make_client(follow_redirects=True).read("a")
        assert other.single().target == "/v1/moved"
    finally:
        other.close()


def test_a_redirect_off_loopback_over_http_or_downgrading_https_fails(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(307, Location="http://vault.example.com/v1/a")
    with pytest.raises(VaultRedirectError, match="unencrypted http"):
        make_client(follow_redirects=True).read("a")


def test_a_redirect_without_a_location_fails(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(302)
    with pytest.raises(VaultRedirectError, match="could not read the redirect location") as raised:
        make_client(follow_redirects=True).read("a")
    assert raised.value.redirect_location is None


# --- Timeouts and rate limits ---------------------------------------------------------------------


def test_a_request_outliving_the_timeout_fails_with_timeout_error(vault: FakeVault, make_client: MakeClient) -> None:
    vault.delay = 1.5
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="didn't answer GET /v1/slow"):
        make_client(request_timeout=timedelta(milliseconds=300)).read("slow")
    assert time.monotonic() - started < 1.2


def test_a_slow_token_provider_counts_against_the_timeout(vault: FakeVault, make_client: MakeClient, protector: DataProtector) -> None:
    with pytest.raises(TimeoutError):
        make_client(token=_CountingProvider(protector, delay=1), request_timeout=timedelta(milliseconds=200)).read("a")
    assert vault.requests == []


def test_a_zero_timeout_is_none(vault: FakeVault, make_client: MakeClient) -> None:
    vault.delay = 0.3
    assert make_client(request_timeout=timedelta(0)).read("a") is not None


def test_the_rate_limiter_spaces_requests_out_once_the_burst_is_spent(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client(rate_limiter=VaultRateLimiter(10, 2))
    started = time.monotonic()
    for _ in range(4):
        client.read("a")
    # Two at once, then one every 100 ms.
    assert time.monotonic() - started >= 0.18


def test_a_rate_limited_request_outliving_the_timeout_fails_at_once(vault: FakeVault, make_client: MakeClient) -> None:
    limiter = VaultRateLimiter(0.1, 1)
    client = make_client(rate_limiter=limiter, request_timeout=timedelta(seconds=1))
    client.read("a")
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        client.read("b")
    assert time.monotonic() - started < 0.5
    assert len(vault.requests) == 1


def test_an_abandoned_rate_limited_wait_gives_its_turn_back() -> None:
    limiter = VaultRateLimiter(1, 1)
    assert limiter.acquire(10, lambda _: False)
    assert not limiter.acquire(10, lambda _: True)
    # The turn given back is the one the next request takes: it waits about a second, not two.
    waited: list[float] = []

    def wait(seconds: float) -> bool:
        waited.append(seconds)
        return False

    assert limiter.acquire(10, wait)
    assert waited and waited[0] <= 1.01


def test_the_rate_limiter_refuses_what_isnt_a_rate() -> None:
    for rate, burst in ((0, 1), (-1, 1), (float("nan"), 1), (1, 0)):
        with pytest.raises(ValueError):
            VaultRateLimiter(rate, burst)
    limiter = VaultRateLimiter(2.5, 3)
    assert (limiter.requests_per_second, limiter.burst) == (2.5, 3)


# --- Read-your-writes -----------------------------------------------------------------------------

_STATE_1 = "djE6Y2x1c3Rlci0xOjEwOjEwOjAwZmY="  # v1:cluster-1:10:10:00ff
_STATE_2 = "djE6Y2x1c3Rlci0xOjIwOjIwOjAwZmY="  # v1:cluster-1:20:20:00ff


def test_read_your_writes_sends_the_states_seen_and_a_copys_change_independently(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, "{}", X_Vault_Index=_STATE_1)
    client = make_client(enforce_read_your_writes_consistency=True)
    client.write("a", {})
    copy = client.copy()
    vault.then(200, "{}", X_Vault_Index=_STATE_2)
    copy.read("b")
    client.read("c")
    copy.read("d")
    assert [r.header("X-Vault-Index") for r in vault.requests] == [None, _STATE_1, _STATE_1, _STATE_2]


def test_without_read_your_writes_no_states_are_sent(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, "{}", X_Vault_Index=_STATE_1)
    client = make_client()
    client.write("a", {})
    client.read("b")
    assert vault.requests[1].header("X-Vault-Index") is None


# --- TLS ------------------------------------------------------------------------------------------


def test_tls_options_trust_vaults_ca(tls: Tls, protector: DataProtector) -> None:
    vault = FakeVault(tls.server_context)
    try:
        options = VaultClientOptions(address=vault.address, tls=VaultTlsOptions(server_certificate_pem=tls.ca_pem),
                                     token=StaticVaultToken.protect(protector, TOKEN))
        with VaultClient(protector, options) as client:
            client.read("a")
        assert vault.single().header("X-Vault-Token") == TOKEN
    finally:
        vault.close()


def test_an_untrusted_certificate_is_refused_without_retrying(tls: Tls, protector: DataProtector) -> None:
    vault = FakeVault(tls.server_context)
    try:
        with VaultClient(protector, VaultClientOptions(address=vault.address)) as client, pytest.raises(ssl.SSLCertVerificationError):
            client.read("a")
        assert vault.requests == []
    finally:
        vault.close()


def test_an_ssl_context_of_your_own_is_used(tls: Tls, protector: DataProtector) -> None:
    vault = FakeVault(tls.server_context)
    try:
        context = ssl.create_default_context(cadata=tls.ca_pem.decode())
        with VaultClient(protector, VaultClientOptions(address=vault.address, ssl_context=context)) as client:
            client.read("a")
        assert len(vault.requests) == 1
    finally:
        vault.close()


def test_tls_options_and_an_ssl_context_together_are_refused(protector: DataProtector) -> None:
    with pytest.raises(ValueError, match="together"):
        VaultClient(protector, VaultClientOptions(ssl_context=ssl.create_default_context(), tls=VaultTlsOptions()))


def test_requests_from_several_threads_share_a_client(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    errors: list[BaseException] = []

    def read() -> None:
        try:
            client.read("a")
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(vault.requests) == 8
