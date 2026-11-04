"""The writer's contract, and what only it does, with a real SecretClient and the writer's own pipeline
policy over a stub Key Vault HTTP endpoint."""

from __future__ import annotations

import gzip
import io
import json
import re
import threading
import time
from collections.abc import Sequence
from typing import Any, ClassVar
from urllib.parse import urlsplit

import pytest
import requests
import urllib3
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline import PipelineRequest, PipelineResponse
from azure.core.pipeline.policies import SansIOHTTPPolicy
from azure.core.pipeline.transport import RequestsTransport
from azure.core.rest import HttpRequest, HttpResponse
from azure.keyvault.secrets import SecretClient
from hkdfguard import abstractions
from hkdfguard.abstractions import KeyNotFoundError, PipelineDataProtector
from hkdfguard.cache import InvalidSecretDataError
from hkdfguard.pipeline.azurekeyvault import AzureKeyVaultSecretPipelineWriter
from hkdfguard.pipeline.azurekeyvault._capture import CAPTURE_OPTION
from pipeline_test_support import SecretPipelineWriterContract
from requests.adapters import BaseAdapter

VAULT = "https://hkdfguard-test.vault.azure.net"
TOKEN = "stub-token"

# --- Test doubles ---------------------------------------------------------------------------------


class Credential:
    """A TokenCredential that always has the stub's token."""

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        return AccessToken(TOKEN, int(time.time()) + 3600)


class SecretsHttpStub(BaseAdapter):
    """Key Vault's secrets endpoint over HTTP, as the Azure SDK's requests transport reaches it, behind
    a real SecretClient with no network: a request without a bearer token gets Key Vault's 401
    challenge, and an authorized Get Secret is answered with the secret's JSON (names compared
    ignoring case, as Key Vault does) or a 404. Any other request - listing secrets or versions among
    them - is recorded in ``unexpected_requests`` and refused.

    Like requests itself, it hands a body over unread only when the request asks to stream.
    :meth:`client_options` also installs a policy recording every 200 body SecretClient was given to
    deserialize, so a test can check the secret never reached it."""

    CHALLENGE = 'Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="https://vault.azure.net"'
    GET_SECRET = re.compile(r"/secrets/([^/]+)/?")

    def __init__(self) -> None:
        super().__init__()
        self.secrets: dict[str, str] = {}
        # The name of every authorized Get Secret, in order.
        self.gets: list[str] = []
        # Whether each authorized Get Secret asked for its body unread.
        self.streams: list[bool] = []
        # Every other request, as "METHOD path".
        self.unexpected_requests: list[str] = []
        # Every 200 body SecretClient deserialized.
        self.bodies_seen_by_secret_client: list[str] = []
        # When set, an authorized Get Secret is answered with this status and an error body.
        self.fail_with: int | None = None
        # When set, an authorized Get Secret is answered with this body as it is.
        self.raw_body: str | None = None
        # Compresses every 200 body with gzip, when the request accepts it.
        self.gzip = False
        self._lock = threading.Lock()

    def set(self, name: str, value: str) -> None:
        self.secrets[name.lower()] = value

    def send(self, request: requests.PreparedRequest, stream: bool = False, *args: Any, **kwargs: Any) -> requests.Response:
        assert request.url is not None
        parts = urlsplit(request.url)
        authorization = request.headers.get("Authorization")
        if authorization is None:
            return self.respond(request, 401, b"", stream, {"WWW-Authenticate": self.CHALLENGE})
        if authorization != f"Bearer {TOKEN}":
            return self.error(request, 401, "Unauthorized", stream)

        path = self.GET_SECRET.fullmatch(parts.path)
        if request.method != "GET" or f"https://{parts.netloc}" != VAULT or path is None:
            with self._lock:
                self.unexpected_requests.append(f"{request.method} {parts.path}")
            return self.error(request, 403, "Forbidden", stream)

        name = path.group(1)
        with self._lock:
            self.gets.append(name)
            self.streams.append(stream)

        if self.fail_with is not None:
            return self.error(request, self.fail_with, "Forbidden", stream)
        if self.raw_body is not None:
            return self.ok(request, self.raw_body, stream)
        value = self.secrets.get(name.lower())
        if value is None:
            return self.error(request, 404, "SecretNotFound", stream)

        return self.ok(request, json.dumps({
            "value": value,
            "id": f"{VAULT}/secrets/{name}/0123456789abcdef0123456789abcdef",
            "attributes": {"enabled": True, "created": 1700000000, "updated": 1700000000, "recoveryLevel": "Recoverable+Purgeable"},
            "tags": {"value": "a tag, not the secret"},
        }, ensure_ascii=False), stream)

    def ok(self, request: requests.PreparedRequest, body: str, stream: bool) -> requests.Response:
        content = body.encode()
        headers: dict[str, str] = {}
        if self.gzip and "gzip" in request.headers.get("Accept-Encoding", ""):
            content = gzip.compress(content)
            headers["Content-Encoding"] = "gzip"
        return self.respond(request, 200, content, stream, headers)

    def error(self, request: requests.PreparedRequest, status: int, code: str, stream: bool) -> requests.Response:
        body = json.dumps({"error": {"code": code, "message": f"{code} from the stub vault."}}).encode()
        return self.respond(request, status, body, stream)

    def respond(self, request: requests.PreparedRequest, status: int, content: bytes, stream: bool,
                headers: dict[str, str] | None = None) -> requests.Response:
        all_headers = {"Content-Type": "application/json; charset=utf-8", "Content-Length": str(len(content)), **(headers or {})}
        response = requests.Response()
        response.request = request
        response.url = request.url or ""
        response.status_code = status
        response.reason = "Stub"
        response.headers.update(all_headers)
        response.raw = urllib3.HTTPResponse(body=io.BytesIO(content), headers=all_headers, status=status, preload_content=False, decode_content=False)
        if not stream:
            # As requests does without stream: the body read (and decompressed) into content.
            response._content = response.raw.read(decode_content=True)
            response._content_consumed = True
        return response

    def close(self) -> None:
        pass

    def client_options(self, **extra: Any) -> dict[str, Any]:
        """SecretClient options that send every request here, never retry, and record the bodies SecretClient sees."""
        session = requests.Session()
        session.mount("https://", self)
        return {"transport": RequestsTransport(session=session, session_owner=False), "retry_total": 0,
                "per_call_policies": [BodyRecorder(self)], **extra}


class BodyRecorder(SansIOHTTPPolicy[HttpRequest, HttpResponse]):
    """Outermost, so it sees each response exactly as SecretClient will deserialize it."""

    def __init__(self, stub: SecretsHttpStub) -> None:
        self.stub = stub

    def on_response(self, request: PipelineRequest[HttpRequest], response: PipelineResponse[HttpRequest, HttpResponse]) -> None:
        if response.http_response.status_code == 200:
            self.stub.bodies_seen_by_secret_client.append(response.http_response.read().decode())


# --- The contract, and what only this writer does -------------------------------------------------


class TestAzureKeyVaultSecretPipelineWriter(SecretPipelineWriterContract):
    read_failure: ClassVar[type[BaseException]] = HttpResponseError

    vault: SecretsHttpStub

    @pytest.fixture(autouse=True)
    def _store(self) -> None:
        self.vault = SecretsHttpStub()

    # No key ring anywhere: the only key is the protector's.
    def create_writer_with(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> abstractions.SecretPipelineWriter:
        return self.create(protector, secret_names)

    def set_text(self, name: str, text: str) -> None:
        self.vault.set(name, text)

    def set_keys(self, name: str, json: str) -> None:
        self.vault.set(name, json)

    def fail_reads(self) -> None:
        self.vault.fail_with = 403

    def reads(self) -> list[str]:
        return self.vault.gets

    def create(self, protector: PipelineDataProtector, secret_names: Sequence[str], options: dict[str, Any] | None = None) -> AzureKeyVaultSecretPipelineWriter:
        return AzureKeyVaultSecretPipelineWriter(VAULT, Credential(), protector, secret_names,  # type: ignore[arg-type]
                                                 client_options=options if options is not None else self.vault.client_options())

    def test_secret_client_sees_only_the_body_with_the_value_blanked_and_the_body_is_streamed(self) -> None:
        self.vault.set("Item", "s3cret")
        with self.create(self.protector, ["Item"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["Item"], "Item") == "s3cret"
        assert len(self.vault.bodies_seen_by_secret_client) == 1
        seen = json.loads(self.vault.bodies_seen_by_secret_client[0])
        assert seen["value"] == ""
        assert seen["tags"] == {"value": "a tag, not the secret"}
        assert self.vault.streams == [True]
        assert self.vault.unexpected_requests == []

    def test_a_compressed_body_is_read_decompressed(self) -> None:
        self.vault.gzip = True
        self.vault.set("Item", "s3cret")
        with self.create(self.protector, ["Item"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["Item"], "Item") == "s3cret"

    def test_another_client_on_the_same_options_reads_secrets_as_usual(self) -> None:
        self.vault.set("Item", "s3cret")
        options = self.vault.client_options()
        before = dict(options)
        with self.create(self.protector, ["Item"], options):
            other = SecretClient(VAULT, Credential(), **options)  # type: ignore[arg-type]
            assert other.get_secret("Item").value == "s3cret"
        assert options == before

    def test_a_name_without_a_key_reads_the_whole_value(self) -> None:
        self.vault.set("Db-Login", '{"user":"app"}')
        with self.create(self.protector, ["Db-Login", "Db-Login#user"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["Db-Login"], "Db-Login") == '{"user":"app"}'
            assert self.decrypt(writer.protected_secrets["Db-Login__user"], "Db-Login__user") == "app"
            assert self.vault.gets == ["Db-Login"]

    @pytest.mark.parametrize("body", ['{"value":"x" ', '["value"]', ""])
    def test_a_response_that_isnt_key_vaults_json_is_refused(self, body: str) -> None:
        self.vault.raw_body = body
        with self.create(self.protector, ["Item"]) as writer:
            with pytest.raises(InvalidSecretDataError):
                writer.pull_secrets()
            assert len(writer.protected_secrets) == 0

    def test_a_response_without_a_string_value_holds_nothing(self) -> None:
        self.vault.raw_body = '{"value":5,"id":"' + VAULT + '/secrets/Item/0123456789abcdef0123456789abcdef"}'
        with self.create(self.protector, ["Item"]) as writer, pytest.raises(KeyNotFoundError):
            writer.pull_secrets()

    @pytest.mark.parametrize("secret_name", ["Db_Password", "prod/app"])
    def test_a_name_key_vault_cant_hold_is_refused(self, secret_name: str) -> None:
        with pytest.raises(ValueError):
            self.create(self.protector, [secret_name])

    def test_is_valid_secret_name_is_key_vaults_rule(self) -> None:
        writer = AzureKeyVaultSecretPipelineWriter
        assert writer.is_valid_secret_name("Db-Login-2")
        assert writer.is_valid_secret_name("a" * writer.MAX_SECRET_NAME_LENGTH)
        assert not writer.is_valid_secret_name("a" * (writer.MAX_SECRET_NAME_LENGTH + 1))
        assert not writer.is_valid_secret_name("")
        assert not writer.is_valid_secret_name(None)

    def test_the_constructor_checks_the_vault_credential_and_options(self) -> None:
        with pytest.raises(TypeError):
            AzureKeyVaultSecretPipelineWriter(None, Credential(), self.protector, ["Item"])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            AzureKeyVaultSecretPipelineWriter(VAULT, None, self.protector, ["Item"])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            AzureKeyVaultSecretPipelineWriter(VAULT, Credential(), self.protector, ["Item"], client_options=["x"])  # type: ignore[arg-type]
        for refused in ("policies", "raw_response_hook", "logging_policy", "http_logging_policy", "authentication_policy", "credential"):
            with pytest.raises(ValueError, match=refused):
                self.create(self.protector, ["Item"], self.vault.client_options(**{refused: object()}))

        with AzureKeyVaultSecretPipelineWriter(VAULT, Credential(), self.protector, ["Item"]):  # type: ignore[arg-type]
            pass

    def test_the_applications_per_retry_policies_see_only_the_redacted_body(self) -> None:
        seen: list[str] = []

        class Spy(SansIOHTTPPolicy[HttpRequest, HttpResponse]):
            def on_response(self, request: PipelineRequest[HttpRequest], response: PipelineResponse[HttpRequest, HttpResponse]) -> None:
                if response.http_response.status_code == 200:
                    seen.append(response.http_response.read().decode())

        self.vault.set("Item", "s3cret")
        with self.create(self.protector, ["Item"], self.vault.client_options(per_retry_policies=Spy())) as writer:
            writer.pull_secrets()
        assert len(seen) == 1
        assert "s3cret" not in seen[0]

    def test_a_request_with_something_else_under_the_capture_option_is_refused(self) -> None:
        with self.create(self.protector, ["Item"]) as writer, pytest.raises(TypeError, match="must be a Capture"):
            writer._client.get_secret("Item", **{CAPTURE_OPTION: object()})
