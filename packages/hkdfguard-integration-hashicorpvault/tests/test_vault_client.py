"""VaultClient: what it sends, how it holds tokens, and how it reads Vault's answers."""

from __future__ import annotations

import asyncio
import io
import json
import time
from datetime import timedelta
from typing import Any

import pytest
from hkdfguard.abstractions import DataProtector
from hkdfguard.integration.hashicorpvault import (
    JsonValue,
    ReplicationForwardingMode,
    StaticVaultToken,
    VaultClient,
    VaultRedirectError,
    VaultRequest,
    VaultRequestOptions,
    VaultResponseError,
    VaultRetryOptions,
    VaultTokenProvider,
)
from hkdfguard.integration.hashicorpvault._client import USER_AGENT, _user_agent
from vault_client_test_support import TOKEN, Answer, FakeVault, MakeClient, Received, decrypt


def test_read_gets_the_path_with_the_token_and_client_headers(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"request_id":"r1","lease_duration":7,"renewable":true,"data":{"value":"v"},"warnings":["careful"]}')
    response = make_client().read("secret/data/app")

    received = vault.single()
    assert (received.method, received.target) == ("GET", "/v1/secret/data/app")
    assert received.header("X-Vault-Token") == TOKEN
    assert received.header("X-Vault-Request") == "true"
    assert received.header("User-Agent") == USER_AGENT
    assert response is not None
    assert (response.request_id, response.lease_duration, response.renewable, response.warnings) == ("r1", 7, True, ["careful"])
    assert response.data == {"value": JsonValue.of("v")}


@pytest.mark.parametrize("path", ["secret/x", "/secret/x", "v1/secret/x", "/v1/secret/x"])
def test_a_path_is_put_under_v1_once(vault: FakeVault, make_client: MakeClient, path: str) -> None:
    make_client().read(path)
    assert vault.single().target == "/v1/secret/x"


def test_callbacks_never_see_the_token(vault: FakeVault, make_client: MakeClient) -> None:
    seen: list[VaultRequest] = []
    client = make_client()
    client.set_request_callbacks(seen.append)
    client.set_response_callbacks(lambda request, status, headers: seen.append(request))
    client.read("secret/x")
    assert len(seen) == 2
    for request in seen:
        assert request.header("X-Vault-Token") is None
        assert TOKEN not in repr(request) and TOKEN not in str(request.headers)
    with pytest.raises(ValueError, match="token"):
        seen[0].add_header("X-Vault-Token", "stolen")


def test_without_a_token_no_token_header_is_sent(vault: FakeVault, make_client: MakeClient) -> None:
    make_client(with_token=False).read("sys/health")
    assert vault.single().header("X-Vault-Token") is None


def test_set_token_protects_it_and_a_requests_own_token_wins(vault: FakeVault, make_client: MakeClient, protector: DataProtector) -> None:
    client = make_client(with_token=False)
    client.set_token("hvs.second")
    client.read("a")
    client.read("b", VaultRequestOptions(token=StaticVaultToken.protect(protector, "hvs.third")))
    client.clear_token()
    client.read("c")
    assert [r.header("X-Vault-Token") for r in vault.requests] == ["hvs.second", "hvs.third", None]


def test_an_unprotected_token_fails_the_request_without_quoting_it(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client(token=StaticVaultToken("hvs.NotProtectedAtAll"))
    with pytest.raises(RuntimeError) as raised:
        client.read("secret/x")
    assert "hvs.NotProtectedAtAll" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert vault.requests == []


def test_a_token_protected_for_something_else_fails_the_request(vault: FakeVault, make_client: MakeClient, make_ring: Any) -> None:
    other = make_ring().create_protector("Some.Other.Purpose")
    with pytest.raises(RuntimeError, match="protected"):
        make_client(token=StaticVaultToken.protect(other, TOKEN)).read("secret/x")
    assert vault.requests == []


def test_a_protected_value_that_isnt_a_token_fails_the_request(vault: FakeVault, make_client: MakeClient, protector: DataProtector) -> None:
    with pytest.raises(RuntimeError, match="isn't a token"):
        make_client(token=StaticVaultToken(protector.encrypt("has a space"))).read("secret/x")
    assert vault.requests == []


class _Provider(VaultTokenProvider):
    def __init__(self, token: object, delay: float = 0) -> None:
        self.token = token
        self.delay = delay
        self.calls = 0

    def get_token(self) -> str:
        self.calls += 1
        time.sleep(self.delay)
        return self.token  # type: ignore[return-value]  # some tests hand back what isn't a token


def test_a_provider_returning_no_token_fails_the_request(vault: FakeVault, make_client: MakeClient) -> None:
    for token in (None, ""):
        with pytest.raises(RuntimeError, match="no token"):
            make_client(token=_Provider(token)).read("secret/x")
    assert vault.requests == []


def test_an_address_path_is_kept_as_a_prefix(vault: FakeVault, make_client: MakeClient) -> None:
    make_client(address=vault.address + "/proxy/vault/").read("secret/x")
    assert vault.single().target == "/proxy/vault/v1/secret/x"


def test_the_namespace_from_options_is_overridden_per_request_and_cleared(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client(namespace="team-a")
    client.read("a")
    client.read("b", VaultRequestOptions(namespace="team-b"))
    client.set_namespace("team-c")
    client.read("c")
    client.clear_namespace()
    client.read("d")
    assert [r.header("X-Vault-Namespace") for r in vault.requests] == ["team-a", "team-b", "team-c", None]
    with pytest.raises(ValueError, match="non-printable"):
        client.set_namespace("bad\nnamespace")


def test_mfa_credentials_are_appended_clients_first(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    client.set_mfa_credentials("method:111111")
    client.read("a", VaultRequestOptions(mfa_credentials=["other:222222"]))
    assert vault.single().headers["x-vault-mfa"] == ["method:111111", "other:222222"]
    with pytest.raises(ValueError, match="MFA"):
        client.set_mfa_credentials("")


def test_response_wrapping_sends_the_ttl_as_a_go_duration_the_requests_overriding_the_clients(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    client.set_response_wrapping(timedelta(minutes=5))
    client.read("a")
    client.read("b", VaultRequestOptions(response_wrapping_ttl=timedelta(seconds=90)))
    client.clear_response_wrapping()
    client.read("c")
    assert [r.header("X-Vault-Wrap-TTL") for r in vault.requests] == ["5m0s", "1m30s", None]
    with pytest.raises(ValueError, match="negative"):
        client.set_response_wrapping(timedelta(seconds=-1))


def test_the_replication_forwarding_mode_sends_its_header(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    client.set_replication_forwarding_mode(ReplicationForwardingMode.ALWAYS)
    client.read("a")
    client.read("b", VaultRequestOptions(replication_forwarding_mode=ReplicationForwardingMode.INCONSISTENT))
    client.clear_replication_forwarding_mode()
    client.read("c")
    a, b, c = vault.requests
    assert (a.header("X-Vault-Forward"), a.header("X-Vault-Inconsistent")) == ("active-node", None)
    assert (b.header("X-Vault-Forward"), b.header("X-Vault-Inconsistent")) == (None, "forward-active-node")
    assert (c.header("X-Vault-Forward"), c.header("X-Vault-Inconsistent")) == (None, None)


def test_custom_headers_a_requests_replace_same_named_ones_and_keep_the_rest(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    client.set_custom_headers({"X-Team": ["a"], "X-Trace": ["1", "2"]})
    client.read("a", VaultRequestOptions(custom_headers={"x-team": ["b"]}))
    received = vault.single()
    assert received.headers["x-team"] == ["b"]
    assert received.headers["x-trace"] == ["1", "2"]
    for refused in ({"X-Vault-Token": ["x"]}, {"": ["x"]}, {"Host": ["x"]}, {"X-Ok": ["line\r\nbreak"]}):
        with pytest.raises(ValueError):
            client.set_custom_headers(refused)


def test_a_custom_content_type_replaces_the_clients(vault: FakeVault, make_client: MakeClient) -> None:
    make_client().write("a", {"x": 1}, VaultRequestOptions(custom_headers={"Content-Type": ["application/merge-patch+json"]}))
    assert vault.single().header("Content-Type") == "application/merge-patch+json"


def test_a_long_token_is_sent_and_a_long_login_token_protected(vault: FakeVault, make_client: MakeClient, protector: DataProtector) -> None:
    long_token = "hvs." + "A" * 2000
    vault.then(200, json.dumps({"auth": {"client_token": "b." + "B" * 2000}}))
    response = make_client(token=StaticVaultToken.protect(protector, long_token)).write("auth/x/login", {})
    assert vault.single().header("X-Vault-Token") == long_token
    assert response is not None and response.auth is not None and response.auth.client_token is not None
    assert decrypt(protector, response.auth.client_token) == "b." + "B" * 2000


def test_query_parameters_are_sorted_by_name_and_escaped_and_list_adds_list_true(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    client.read("a", VaultRequestOptions(query_parameters=[("z", "1"), ("a b", "x/y"), ("z", "0")]))
    client.list("secret/metadata/", VaultRequestOptions(query_parameters=[("after", "k")]))
    assert vault.requests[0].target == "/v1/a?a%20b=x%2Fy&z=1&z=0"
    assert vault.requests[1].target == "/v1/secret/metadata/?after=k&list=true"


def test_write_posts_the_body_as_json(vault: FakeVault, make_client: MakeClient) -> None:
    make_client().write("secret/data/app", {"data": {"password": "pw", "n": 3, "on": True}, "options": None})
    received = vault.single()
    assert (received.method, received.header("Content-Type")) == ("POST", "application/json")
    assert received.body_text == '{"data":{"password":"pw","n":3,"on":true},"options":null}'


def test_write_from_bytes_and_stream_post_the_body_as_it_is(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    body = bytearray(b'{"raw":true}')
    client.write_from_bytes("a", body)
    client.write_from_stream("b", io.BytesIO(b'{"streamed":1}'))
    assert [r.body for r in vault.requests] == [b'{"raw":true}', b'{"streamed":1}']
    assert body == bytearray(b'{"raw":true}')


def test_an_unwritable_body_raises_from_the_call_sending_nothing(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    with pytest.raises(TypeError, match="can't be written"):
        client.write("a", {"x": object()})
    with pytest.raises(TypeError):
        client.write("a", None)  # type: ignore[arg-type]
    assert vault.requests == []


def test_delete_deletes(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(204)
    assert make_client().delete("secret/metadata/app") is None
    assert vault.single().method == "DELETE"


def test_a_body_without_an_envelope_is_read_whole_as_data(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"initialized":true,"sealed":false}')
    response = make_client().read("sys/health")
    assert response is not None and response.data is not None
    assert response.data["sealed"].as_bool() is False
    assert response.request_id is None


def test_sys_health_errors_are_its_status(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(503, '{"sealed":true}')
    response = make_client(retry=VaultRetryOptions(retry_max=0)).read("sys/health")
    assert response is not None and response.data is not None
    assert response.data["sealed"].as_bool() is True


def test_a_login_token_is_protected_as_it_is_read_and_can_be_set_as_the_clients(vault: FakeVault, make_client: MakeClient,
                                                                                protector: DataProtector) -> None:
    vault.then(200, json.dumps({"auth": {"client_token": "hvs.issued", "accessor": "acc", "policies": ["default"], "metadata": {"role": "r"},
                                         "lease_duration": 3600, "renewable": True, "orphan": True, "entity_id": "e"}}))
    client = make_client(with_token=False)
    response = client.write("auth/approle/login", {"role_id": "r", "secret_id": "s"})
    assert response is not None and response.auth is not None
    auth = response.auth
    assert auth.client_token is not None and auth.client_token.get_token() != "hvs.issued"
    assert decrypt(protector, auth.client_token) == "hvs.issued"
    assert (auth.accessor, auth.policies, auth.metadata, auth.lease_duration, auth.renewable, auth.orphan) == (
        "acc", ["default"], {"role": "r"}, 3600, True, True)
    assert "hvs.issued" not in repr(response)

    client.set_token(auth.client_token)
    client.read("secret/x")
    assert vault.requests[1].header("X-Vault-Token") == "hvs.issued"


def test_a_login_token_escaped_in_json_is_unescaped_before_it_is_protected(vault: FakeVault, make_client: MakeClient,
                                                                           protector: DataProtector) -> None:
    vault.then(200, '{"auth":{"client_token":"hvs.\\u0041\\/b"}}')
    response = make_client().write("auth/x/login", {})
    assert response is not None and response.auth is not None and response.auth.client_token is not None
    assert decrypt(protector, response.auth.client_token) == "hvs.A/b"


def test_a_login_token_that_isnt_one_fails_the_response(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"auth":{"client_token":"has space"}}')
    with pytest.raises(ValueError, match="isn't one"):
        make_client().write("auth/x/login", {})


def test_an_mfa_requirement_is_read(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, json.dumps({"auth": {"mfa_requirement": {"mfa_request_id": "m1", "mfa_constraints": {
        "otp": {"any": [{"type": "totp", "id": "t1", "uses_passcode": True}]}}}}}))
    response = make_client().write("auth/userpass/login/u", {"password": "p"})
    assert response is not None and response.auth is not None and response.auth.mfa_requirement is not None
    requirement = response.auth.mfa_requirement
    assert requirement.mfa_request_id == "m1"
    assert requirement.mfa_constraints is not None
    method = requirement.mfa_constraints["otp"].any
    assert method is not None and (method[0].type, method[0].id, method[0].uses_passcode) == ("totp", "t1", True)


def test_unwrap_puts_with_the_wrapping_token_and_reads_the_wrapped_response(vault: FakeVault, make_client: MakeClient,
                                                                             protector: DataProtector) -> None:
    vault.then(200, json.dumps({"wrap_info": {"token": "hvs.wrapping", "accessor": "a", "ttl": 300, "creation_time": "2026-01-02T03:04:05.123456789Z",
                                              "creation_path": "secret/data/app"}}))
    vault.then(200, '{"data":{"data":{"k":"v"}}}')
    client = make_client()
    wrapped = client.read("secret/data/app", VaultRequestOptions(response_wrapping_ttl=timedelta(minutes=5)))
    assert wrapped is not None and wrapped.wrap_info is not None and wrapped.wrap_info.token is not None
    info = wrapped.wrap_info
    token = info.token
    assert token is not None
    assert (info.ttl, info.creation_path) == (300, "secret/data/app")
    assert info.creation_time is not None and info.creation_time.microsecond == 123456
    assert decrypt(protector, token) == "hvs.wrapping"

    unwrapped = client.unwrap(token)
    unwrap_request = vault.requests[1]
    assert (unwrap_request.method, unwrap_request.target) == ("PUT", "/v1/sys/wrapping/unwrap")
    assert unwrap_request.header("X-Vault-Token") == "hvs.wrapping"
    assert unwrapped is not None and unwrapped.data is not None
    assert unwrapped.data["data"].member("k").as_str() == "v"


def test_a_refusal_is_a_response_error_listing_vaults_errors(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(403, '{"errors":["permission denied"]}')
    vault.then(400, '{"error":"bad"}')
    vault.then(404, "not json")
    vault.then(400)
    client = make_client()
    errors: list[VaultResponseError] = []
    for _ in range(4):
        with pytest.raises(VaultResponseError) as raised:
            client.read("secret/x?q=1")
        errors.append(raised.value)
    assert [(e.status_code, e.errors, e.raw_response_bytes) for e in errors] == [
        (403, ["permission denied"], None), (400, ["bad"], None), (404, [], b"not json"), (400, [], None)]
    assert str(errors[0]) == "403 Forbidden: permission denied"
    assert errors[0].request_method == "GET"
    assert errors[0].request_url.startswith(vault.address)
    assert VaultClient.is_error_status(errors[0], 403)
    assert not errors[0].is_transient


def test_is_error_status_follows_causes_and_is_false_for_other_errors(vault: FakeVault) -> None:
    error = VaultResponseError("x", 404, [], None, "GET", "u")
    try:
        try:
            raise error
        except VaultResponseError as inner:
            raise RuntimeError("wrapped") from inner
    except RuntimeError as outer:
        assert VaultClient.is_error_status(outer, 404)
        assert not VaultClient.is_error_status(outer, 403)
    assert not VaultClient.is_error_status(ValueError("x"), 404)
    assert not VaultClient.is_error_status(None, 404)


def test_a_304_is_not_an_error(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(304)
    assert make_client().read("a") is None


def test_read_raw_returns_the_response_unchecked(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(404, "raw body", X_Extra="1")
    with make_client().read_raw("a", VaultRequestOptions(query_parameters=[("q", "1")])) as raw:
        assert raw.status_code == 404
        assert raw.headers["X-Extra"] == "1"
        assert raw.read() == b"raw body"
    assert vault.single().target == "/v1/a?q=1"


def test_callbacks_the_clients_run_before_the_requests(vault: FakeVault, make_client: MakeClient) -> None:
    calls: list[str] = []
    client = make_client()
    client.set_request_callbacks(lambda r: calls.append("client request"))
    client.set_response_callbacks(lambda r, s, h: calls.append(f"client response {s}"))
    client.read("a", VaultRequestOptions(request_callbacks=[lambda r: calls.append("request")],
                                         response_callbacks=[lambda r, s, h: calls.append("response")]))
    assert calls == ["client request", "request", "client response 200", "response"]


def test_a_request_callback_adds_headers(vault: FakeVault, make_client: MakeClient) -> None:
    make_client().read("a", VaultRequestOptions(request_callbacks=[lambda r: r.add_header("X-Custom", "1")]))
    assert vault.single().header("X-Custom") == "1"


def test_a_raising_response_callback_fails_the_request(vault: FakeVault, make_client: MakeClient) -> None:
    def fail(request: VaultRequest, status: int, headers: Any) -> None:
        raise LookupError("callback")

    with pytest.raises(LookupError, match="callback"):
        make_client().read("a", VaultRequestOptions(response_callbacks=[fail]))


def test_copy_copies_settings_which_then_change_independently(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client(namespace="a")
    copy = client.copy()
    copy.set_namespace("b")
    client.read("x")
    copy.read("y")
    copy.close()
    client.read("z")
    assert [r.header("X-Vault-Namespace") for r in vault.requests] == ["a", "b", "a"]
    client.close()
    for closed in (client, copy):
        with pytest.raises(RuntimeError, match="closed"):
            closed.read("x")


def test_the_async_methods_send_as_the_sync_ones_do(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"data":{"value":"v"}}')
    client = make_client()

    async def run() -> None:
        response = await client.read_async("secret/x")
        assert response is not None and response.data == {"value": JsonValue.of("v")}
        await client.write_async("secret/y", {"a": 1})
        await client.list_async("secret/")
        await client.delete_async("secret/z")
        await client.write_from_bytes_async("secret/b", b"{}")
        async with asyncio.timeout(5):
            raw = await client.read_raw_async("secret/r")
        raw.close()

    asyncio.run(run())
    assert [(r.method, r.target) for r in vault.requests] == [
        ("GET", "/v1/secret/x"), ("POST", "/v1/secret/y"), ("GET", "/v1/secret/?list=true"), ("DELETE", "/v1/secret/z"),
        ("POST", "/v1/secret/b"), ("GET", "/v1/secret/r")]


def test_cancelling_an_async_request_abandons_it(vault: FakeVault, make_client: MakeClient) -> None:
    vault.delay = 2
    client = make_client()

    async def run() -> float:
        task = asyncio.create_task(client.read_async("slow"))
        await asyncio.sleep(0.3)
        started = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return time.monotonic() - started

    assert asyncio.run(run()) < 1


def test_an_async_failure_raises_from_the_await(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(403, '{"errors":["denied"]}')
    with pytest.raises(VaultResponseError, match="denied"):
        asyncio.run(make_client().read_async("x"))


def test_the_user_agent_names_the_library_and_platform_in_printable_ascii() -> None:
    assert USER_AGENT.startswith("hkdfguard-integration-hashicorpvault/")
    assert "Python " in USER_AGENT
    agent = _user_agent("", "Weird\nOSé", "x86", "3.12")
    assert agent == "hkdfguard-integration-hashicorpvault/0.0.0 (Weird OS ; x86; Python 3.12)"


def test_protect_token_holds_only_the_protected_form(make_client: MakeClient, protector: DataProtector) -> None:
    token = make_client().protect_token("hvs.mine")
    assert token.get_token() != "hvs.mine"
    assert decrypt(protector, token) == "hvs.mine"
    for bad in ("", "has space"):
        with pytest.raises(ValueError):
            make_client().protect_token(bad)


def test_a_redirect_is_refused_by_default(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(307, Location="https://elsewhere.example/v1/a")
    with pytest.raises(VaultRedirectError) as raised:
        make_client().read("a")
    assert raised.value.reason == "redirects are disabled"
    assert raised.value.redirect_location == "https://elsewhere.example/v1/a"
    assert VaultClient.is_error_status(raised.value, 307)


def test_received_type_is_what_the_fake_records(vault: FakeVault) -> None:
    assert isinstance(Answer(200), Answer)
    assert Received("GET", "/v1/a?b", {}, b"").path == "/v1/a"
