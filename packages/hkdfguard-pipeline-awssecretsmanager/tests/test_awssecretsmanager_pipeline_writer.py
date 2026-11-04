"""The writer's contract, and what only it does, through a real botocore Secrets Manager client - its
serializer, event system, capture and parser included - answered by :class:`FakeSecretsManager`
instead of the network."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Callable, Iterator, Sequence
from typing import Any, ClassVar

import botocore.session
import pytest
from botocore.awsrequest import AWSPreparedRequest, AWSResponse, HeadersDict
from botocore.config import Config
from botocore.exceptions import ClientError, NoRegionError
from botocore.stub import Stubber
from hkdfguard import abstractions
from hkdfguard.abstractions import KeyNotFoundError, PipelineDataProtector
from hkdfguard.cache import InvalidSecretDataError
from hkdfguard.pipeline.awssecretsmanager import AwsSecretsManagerSecretPipelineWriter
from pipeline_test_support import SecretPipelineWriterContract

# --- Test doubles ---------------------------------------------------------------------------------


class FakeSecretsManager:
    """Secrets Manager's JSON 1.1 endpoint, under a real botocore client - no network: a
    ``before-send`` handler answers each request as the HTTP layer would. An authorized
    GetSecretValue is answered with the secret (names matched exactly, as AWS matches them) or
    ResourceNotFoundException; any other operation - ListSecrets and BatchGetSecretValue among them -
    is recorded in :attr:`unexpected_operations` and refused. Each body is sent in small chunks, as
    urllib3 streams one."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._lock = threading.Lock()
        # Every SecretId GetSecretValue was called with, in order.
        self.gets: list[str] = []
        # Every other operation called.
        self.unexpected_operations: list[str] = []
        # When set, GetSecretValue fails with this AWS error type and HTTP status.
        self.fail_with: tuple[str, int] | None = None
        # When set, GetSecretValue is answered with this body as it is.
        self.raw_body: bytes | None = None
        self.chunk_length = 7

    def set_string(self, name: str, value: str) -> None:
        self._secrets[name] = '"SecretString":' + json.dumps(value) + ","

    def set_binary(self, name: str, value: bytes) -> None:
        self._secrets[name] = '"SecretBinary":"' + base64.b64encode(value).decode("ascii") + '",'

    def set_empty(self, name: str) -> None:
        self._secrets[name] = ""

    def client(self) -> Any:
        """A client sending every request here, without retries. Creating one reads the service model
        from botocore's own files and makes no request."""
        client = botocore.session.get_session().create_client("secretsmanager", region_name="us-east-1", aws_access_key_id="testing",
                                                              aws_secret_access_key="testing", config=Config(retries={"total_max_attempts": 1}))
        client.meta.events.register("before-send.secrets-manager", self._answer)
        return client

    def _answer(self, request: AWSPreparedRequest, **_: Any) -> AWSResponse:
        operation = _text(request.headers.get("X-Amz-Target", ""))
        if operation != "secretsmanager.GetSecretValue":
            with self._lock:
                self.unexpected_operations.append(operation)
            return self._error(request, "AccessDeniedException", 400)

        assert _text(request.headers.get("Authorization", "")).startswith("AWS4-HMAC-SHA256 ")
        body = json.loads(bytes(request.body or b""))
        assert set(body) == {"SecretId"}, body  # no VersionId or VersionStage: AWSCURRENT
        name = body["SecretId"]
        with self._lock:
            self.gets.append(name)

        if self.fail_with is not None:
            return self._error(request, *self.fail_with)
        if self.raw_body is not None:
            return self._respond(request, 200, self.raw_body)
        value = self._secrets.get(name)
        if value is None:
            return self._error(request, "ResourceNotFoundException", 400)

        response = ('{"ARN":' + json.dumps(f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{name}-AbCdEf")
                    + ',"Name":' + json.dumps(name) + "," + value
                    + '"VersionId":"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111","VersionStages":["AWSCURRENT"],"CreatedDate":1700000000.0}')
        return self._respond(request, 200, response.encode())

    def _error(self, request: AWSPreparedRequest, error_type: str, status: int) -> AWSResponse:
        body = json.dumps({"__type": error_type, "Message": f"{error_type} in a test."}).encode()
        return self._respond(request, status, body, {"x-amzn-ErrorType": error_type})

    def _respond(self, request: AWSPreparedRequest, status: int, body: bytes, extra: dict[str, str] | None = None) -> AWSResponse:
        headers = HeadersDict({"Content-Type": "application/x-amz-json-1.1", "Content-Length": str(len(body)), "x-amzn-RequestId": "request-1",
                               **(extra or {})})
        chunks = [body[i:i + self.chunk_length] for i in range(0, len(body), self.chunk_length)]
        return AWSResponse(request.url, status, headers, _ChunkedRaw(chunks))


class _ChunkedRaw:
    """The raw stream AWSResponse reads its content from, in chunks, as urllib3's response is."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def stream(self, amt: int | None = None, decode_content: bool | None = None) -> Iterator[bytes]:
        yield from self._chunks


def _text(value: str | bytes) -> str:
    return value.decode() if isinstance(value, bytes) else value


class Recorded:
    """What every GetSecretValue response held as botocore handled it: the body a ``before-parse``
    handler registered by the application saw, and the dict the parser produced (``after-call``)."""

    def __init__(self, client: Any) -> None:
        self.bodies: list[bytes] = []
        self.responses: list[dict[str, Any]] = []
        client.meta.events.register("before-parse.secrets-manager.GetSecretValue", self._before_parse)
        client.meta.events.register("after-call.secrets-manager.GetSecretValue", self._after_call)

    def _before_parse(self, response_dict: dict[str, Any], **_: Any) -> None:
        if response_dict["status_code"] < 300:
            self.bodies.append(bytes(response_dict["body"]))

    def _after_call(self, parsed: dict[str, Any], **_: Any) -> None:
        if "Error" not in parsed:
            self.responses.append(parsed)


# --- The contract, and what only this writer does -------------------------------------------------


class TestAwsSecretsManagerSecretPipelineWriter(SecretPipelineWriterContract):
    read_failure: ClassVar[type[BaseException]] = ClientError

    aws: FakeSecretsManager
    client: Any

    @pytest.fixture(autouse=True)
    def _store(self) -> Iterator[None]:
        self.aws = FakeSecretsManager()
        self.client = self.aws.client()
        yield
        self.client.close()

    # No key ring anywhere: the only key is the protector's.
    def create_writer_with(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> abstractions.SecretPipelineWriter:
        return self.create(protector, secret_names)

    def set_text(self, name: str, text: str) -> None:
        self.aws.set_string(name, text)

    def set_keys(self, name: str, json: str) -> None:
        self.aws.set_string(name, json)

    def fail_reads(self) -> None:
        self.aws.fail_with = ("AccessDeniedException", 400)

    def reads(self) -> list[str]:
        return self.aws.gets

    def create(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> AwsSecretsManagerSecretPipelineWriter:
        return AwsSecretsManagerSecretPipelineWriter(protector, secret_names, self.client)

    def test_the_parsed_response_and_every_later_handler_hold_nothing(self) -> None:
        self.aws.set_string("item", "s3cret")
        recorded = Recorded(self.client)
        with self.create(self.protector, ["item"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["item"], "item") == "s3cret"
        assert len(recorded.responses) == 1
        assert recorded.responses[0]["SecretString"] == ""
        assert recorded.responses[0]["Name"] == "item"
        assert all(b"s3cret" not in body for body in recorded.bodies)
        assert self.aws.unexpected_operations == []

    def test_another_request_on_the_writers_client_passes_through_untouched(self) -> None:
        self.aws.set_string("item", "s3cret")
        with self.create(self.protector, ["item"]):
            assert self.client.get_secret_value(SecretId="item")["SecretString"] == "s3cret"

    def test_a_name_without_a_key_reads_the_whole_secret_string(self) -> None:
        self.aws.set_string("prod/app", '{"user":"app"}')
        with self.create(self.protector, ["prod/app", "prod/app#user"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["prod__app"], "prod__app") == '{"user":"app"}'
            assert self.decrypt(writer.protected_secrets["prod__app__user"], "prod__app__user") == "app"
            assert self.aws.gets == ["prod/app"]

    def test_an_empty_secret_is_missing(self) -> None:
        self.aws.set_empty("empty")
        self.aws.set_string("blank", "")
        with self.create(self.protector, ["empty", "blank"]) as writer, pytest.raises(KeyNotFoundError, match="empty, blank"):
            writer.pull_secrets()

    def test_a_secret_binary_is_refused(self) -> None:
        self.aws.set_binary("binary", bytes([1, 2, 3]))
        with self.create(self.protector, ["binary"]) as writer:
            with pytest.raises(InvalidSecretDataError, match="SecretBinary"):
                writer.pull_secrets()
            assert len(writer.protected_secrets) == 0

    @pytest.mark.parametrize("body", [b'{"SecretString":"x" ', b'["SecretString"]', b"", b'{"SecretString":"a","SecretString":"b"}'])
    def test_a_response_that_isnt_secrets_managers_json_is_refused(self, body: bytes) -> None:
        self.aws.raw_body = body
        with self.create(self.protector, ["item"]) as writer:
            with pytest.raises(InvalidSecretDataError):
                writer.pull_secrets()
            assert len(writer.protected_secrets) == 0

    def test_a_stubbed_client_is_refused_rather_than_read(self) -> None:
        with Stubber(self.client) as stubber, self.create(self.protector, ["item"]) as writer:
            stubber.add_response("get_secret_value", {"Name": "item", "SecretString": "s3cret"}, {"SecretId": "item"})
            with pytest.raises(RuntimeError, match="wasn't captured"):
                writer.pull_secrets()

    @pytest.mark.parametrize("secret_name", ["ConnectionStrings:Admin", "user@example", "a+b", "a=b", ".hidden"])
    def test_a_name_no_file_can_have_is_refused(self, secret_name: str) -> None:
        with pytest.raises(ValueError):
            self.create(self.protector, [secret_name])

    def test_is_valid_secret_name_is_secrets_managers_rule(self) -> None:
        writer = AwsSecretsManagerSecretPipelineWriter
        assert writer.is_valid_secret_name("prod/a_b+c=d.e@f-g")
        assert writer.is_valid_secret_name("a" * writer.MAX_SECRET_NAME_LENGTH)
        assert not writer.is_valid_secret_name("a" * (writer.MAX_SECRET_NAME_LENGTH + 1))
        assert not writer.is_valid_secret_name("")
        assert not writer.is_valid_secret_name(None)
        assert not writer.is_valid_secret_name("a:b")

    def test_a_client_of_the_callers_is_left_open_and_one_of_the_writers_own_is_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.aws.set_string("item", "s3cret")
        with self.create(self.protector, ["item"]) as writer:
            assert writer.client is self.client
        assert self.client.get_secret_value(SecretId="item")["SecretString"] == "s3cret"

        # Credentials are resolved when a request is signed, not when the client is made.
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
        closed: list[bool] = []
        with AwsSecretsManagerSecretPipelineWriter(self.protector, ["item"]) as own:
            own_client: Any = own.client
            assert own_client is not self.client
            original: Callable[[], None] = own_client.close

            def close() -> None:
                closed.append(True)
                original()

            monkeypatch.setattr(own_client, "close", close)
        assert closed == [True]

    def test_without_a_client_or_a_region_the_sdks_refusal_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for variable in ("AWS_DEFAULT_REGION", "AWS_REGION"):
            monkeypatch.delenv(variable, raising=False)
        monkeypatch.setenv("AWS_CONFIG_FILE", "does-not-exist")
        with pytest.raises(NoRegionError):
            AwsSecretsManagerSecretPipelineWriter(self.protector, ["item"])

    def test_a_client_without_an_event_system_is_refused(self) -> None:
        with pytest.raises(TypeError, match="botocore client"):
            AwsSecretsManagerSecretPipelineWriter(self.protector, ["item"], object())  # type: ignore[arg-type]

    def test_the_capture_is_registered_once_however_many_writers_share_the_client(self) -> None:
        self.aws.set_string("item", "s3cret")
        with self.create(self.protector, ["item"]) as first, self.create(self.protector, ["item"]) as second:
            first.pull_secrets()
            second.pull_secrets()
            assert self.decrypt(second.protected_secrets["item"], "item") == "s3cret"
        assert self.aws.gets == ["item", "item"]
