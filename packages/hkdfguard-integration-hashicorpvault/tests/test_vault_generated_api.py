"""The methods generated from Vault's OpenAPI spec, against the fake Vault."""

from __future__ import annotations

import asyncio
import json

import pytest
from hkdfguard.abstractions import DataProtector
from hkdfguard.integration.hashicorpvault import AuthApi, JsonValue, SecretsApi, SystemApi, VaultRequestOptions
from hkdfguard.integration.hashicorpvault._client import escape_path_segment, mount_path_or
from hkdfguard.integration.hashicorpvault.schema import (
    AppRoleLoginRequest,
    KvV2ReadResponse,
    KvV2WriteRequest,
    TokenCreateRequest,
    TransitEncryptRequest,
    TransitGenerateDataKeyRequest,
    TransitSetCertificateForKeyRequest,
)
from vault_client_test_support import FakeVault, MakeClient, decrypt


def test_a_generated_read_escapes_the_path_and_uses_the_default_or_given_mount(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"data":{"data":{"password":"pw"},"metadata":{"version":2}}}')
    client = make_client()
    response = client.secrets.kv_v2_read("app/db config")
    client.secrets.kv_v2_read("x", options=VaultRequestOptions(mount_path="/kv/"))
    assert [r.target for r in vault.requests] == ["/v1/kv-v2/data/app%2Fdb%20config", "/v1/kv/data/x"]
    assert response is not None and isinstance(response.data, KvV2ReadResponse)
    assert response.data.data == {"password": JsonValue.of("pw")}


def test_a_generated_write_posts_its_model_leaving_out_what_isnt_set(vault: FakeVault, make_client: MakeClient) -> None:
    make_client().secrets.kv_v2_write("app", KvV2WriteRequest(data={"password": "pw"}))
    received = vault.single()
    assert (received.method, received.target) == ("POST", "/v1/kv-v2/data/app")
    assert received.body_text == '{"data":{"password":"pw"}}'


def test_required_members_are_sent_and_their_absence_raises_from_the_call(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    with pytest.raises(ValueError, match="needs its certificate_chain"):
        client.secrets.transit_set_certificate_for_key("key", TransitSetCertificateForKeyRequest(version=1))
    assert vault.requests == []
    client.secrets.transit_set_certificate_for_key("key", TransitSetCertificateForKeyRequest(certificate_chain="pem"))
    assert vault.single().body_text == '{"certificate_chain":"pem"}'


def test_a_transit_encrypt_sends_only_whats_set_and_reads_json_values(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"data":{"ciphertext":"vault:v1:abc","key_version":1}}')
    response = make_client().secrets.transit_encrypt("my-key", TransitEncryptRequest(plaintext="cA==", associated_data="YQ=="),
                                                     options=VaultRequestOptions(mount_path="transit-prod"))
    received = vault.single()
    assert received.target == "/v1/transit-prod/encrypt/my-key"
    assert json.loads(received.body) == {"plaintext": "cA==", "associated_data": "YQ=="}
    assert response is not None and response.data is not None and response.data["ciphertext"].as_str() == "vault:v1:abc"


def test_a_generated_list_adds_list_true_to_the_callers_query(vault: FakeVault, make_client: MakeClient) -> None:
    make_client().secrets.kv_v2_list("dir/", options=VaultRequestOptions(query_parameters=[("after", "a")]))
    assert vault.single().target == "/v1/kv-v2/metadata/dir%2F/?after=a&list=true"


def test_a_free_form_body_is_sent_as_it_is(vault: FakeVault, make_client: MakeClient) -> None:
    make_client().secrets.cubbyhole_write("notes", {"text": "hi", "n": [1]})
    assert vault.single().body_text == '{"text":"hi","n":[1]}'


def test_a_query_parameter_is_sent_only_when_given(vault: FakeVault, make_client: MakeClient) -> None:
    client = make_client()
    client.auth.jwt_oidc_callback(state="s", code="c")
    client.auth.jwt_oidc_callback()
    assert [r.target for r in vault.requests] == ["/v1/auth/jwt/oidc/callback?code=c&state=s", "/v1/auth/jwt/oidc/callback"]


def test_a_token_create_protects_the_issued_token(vault: FakeVault, make_client: MakeClient, protector: DataProtector) -> None:
    vault.then(200, '{"auth":{"client_token":"hvs.child","policies":["p"]}}')
    response = make_client().auth.token_create(TokenCreateRequest(policies=["p"], ttl="1h"))
    assert vault.single().target == "/v1/auth/token/create"
    assert response is not None and response.auth is not None and response.auth.client_token is not None
    assert decrypt(protector, response.auth.client_token) == "hvs.child"


def test_a_login_needs_no_token_and_uses_its_mount(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"auth":{"client_token":"hvs.x"}}')
    make_client(with_token=False).auth.app_role_login(AppRoleLoginRequest(role_id="r", secret_id="s"),
                                                      options=VaultRequestOptions(mount_path="approle-ci"))
    received = vault.single()
    assert received.target == "/v1/auth/approle-ci/login"
    assert received.header("X-Vault-Token") is None


def test_a_generated_method_refuses_a_missing_body_sending_nothing(vault: FakeVault, make_client: MakeClient) -> None:
    with pytest.raises(TypeError):
        make_client().secrets.kv_v2_write("app", None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        make_client().secrets.kv_v2_read(None)  # type: ignore[arg-type]
    assert vault.requests == []


def test_the_async_variants_send_the_same_request(vault: FakeVault, make_client: MakeClient) -> None:
    vault.then(200, '{"data":{"ciphertext":"vault:v1:x"}}')
    client = make_client()
    response = asyncio.run(client.secrets.transit_generate_data_key_async("k", "wrapped", TransitGenerateDataKeyRequest(bits=256)))
    assert vault.single().target == "/v1/transit/datakey/wrapped/k"
    assert response is not None and response.data is not None


def test_escape_path_segment_escapes_all_but_unreserved() -> None:
    assert escape_path_segment("aZ0-_.~/ é?%") == "aZ0-_.~%2F%20%C3%A9%3F%25"
    with pytest.raises(TypeError):
        escape_path_segment(None)  # type: ignore[arg-type]


def test_mount_path_or_trims_slashes_falling_back_to_the_default() -> None:
    assert mount_path_or(None, "secret") == "secret"
    assert mount_path_or(VaultRequestOptions(), "secret") == "secret"
    assert mount_path_or(VaultRequestOptions(mount_path="//kv/v2//"), "secret") == "kv/v2"
    assert mount_path_or(VaultRequestOptions(mount_path="///"), "secret") == "secret"


def test_the_api_groups_reach_through_the_client(make_client: MakeClient) -> None:
    client = make_client()
    assert (type(client.auth), type(client.secrets), type(client.system)) == (AuthApi, SecretsApi, SystemApi)
