"""The writer's contract, and what only it does, against a fake Secret Manager - a gRPC server on the
loopback address - through a real SecretManagerServiceClient's channel and the writer's own
response deserializer."""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any, ClassVar

import grpc
import pytest
from google.api_core import exceptions as core_exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud.secretmanager_v1 import AccessSecretVersionRequest, AccessSecretVersionResponse, SecretManagerServiceClient, SecretPayload
from google.cloud.secretmanager_v1.services.secret_manager_service.transports import SecretManagerServiceGrpcTransport
from hkdfguard import abstractions
from hkdfguard.abstractions import CryptographicError, KeyNotFoundError, PipelineDataProtector
from hkdfguard.cache import InvalidSecretDataError
from hkdfguard.pipeline.googlesecretmanager import GoogleSecretManagerSecretPipelineWriter
from hkdfguard.pipeline.googlesecretmanager._capture import AccessedSecretVersion, ResponseCapture, crc32c
from pipeline_test_support import SecretPipelineWriterContract, run

PROJECT_ID = "hkdfguard-test"
# Google answers with the project's number, not the ID it was asked with.
PROJECT_NUMBER = "123456789012"

_VERSION_NAME = re.compile(r"projects/([^/]+)/secrets/([^/]+)/versions/([^/]+)")

# --- Test doubles ---------------------------------------------------------------------------------


class FakeSecretManager:
    """A stand-in for Secret Manager: a gRPC server on the loopback address implementing only
    AccessSecretVersion (any other call is recorded and answered UNIMPLEMENTED), reached through a
    real ``SecretManagerServiceClient``'s channel. Secret IDs are matched exactly, as Google matches
    them, and responses name the project by its number and carry a CRC32C, as Google's do for
    payloads added with one."""

    SERVICE = "google.cloud.secretmanager.v1.SecretManagerService"

    def __init__(self) -> None:
        self.secrets: dict[str, bytes] = {}
        self.accesses: list[str] = []
        self.unexpected_calls: list[str] = []
        # When set, every AccessSecretVersion fails with this status instead of answering.
        self.failure: tuple[grpc.StatusCode, str] | None = None
        # Rewrites a response before it is sent.
        self.tamper: Callable[[AccessSecretVersionResponse], AccessSecretVersionResponse] | None = None
        self._lock = threading.Lock()

        fake = self

        class Handler(grpc.GenericRpcHandler):  # type: ignore[misc]
            def service(self, handler_call_details: Any) -> Any:
                if handler_call_details.method == f"/{FakeSecretManager.SERVICE}/AccessSecretVersion":
                    return grpc.unary_unary_rpc_method_handler(fake._access, request_deserializer=AccessSecretVersionRequest.deserialize,
                                                               response_serializer=lambda raw: raw)
                fake.unexpected_calls.append(handler_call_details.method)
                return None

        self._server = grpc.server(ThreadPoolExecutor(max_workers=8))
        self._server.add_generic_rpc_handlers((Handler(),))
        self.port = self._server.add_insecure_port("127.0.0.1:0")
        self._server.start()
        self._channel = grpc.insecure_channel(f"127.0.0.1:{self.port}")
        self.client = SecretManagerServiceClient(transport=SecretManagerServiceGrpcTransport(channel=self._channel))

    def close(self) -> None:
        self._channel.close()
        self._server.stop(None)

    def set(self, secret_id: str, value: str | bytes) -> None:
        self.secrets[secret_id] = value.encode() if isinstance(value, str) else value

    def gets(self) -> list[str]:
        """The secret ID of every access, in order."""
        return [m.group(2) for m in (_VERSION_NAME.fullmatch(a) for a in self.accesses) if m]

    def _access(self, request: AccessSecretVersionRequest, context: grpc.ServicerContext) -> bytes:
        with self._lock:
            self.accesses.append(request.name)
        if self.failure is not None:
            context.abort(*self.failure)

        name = _VERSION_NAME.fullmatch(request.name)
        if name is None or name.group(1) != PROJECT_ID or name.group(3) != "latest":
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Unexpected resource name {request.name}.")
        assert name is not None
        value = self.secrets.get(name.group(2))
        if value is None:
            context.abort(grpc.StatusCode.NOT_FOUND, f"Secret [projects/{PROJECT_NUMBER}/secrets/{name.group(2)}] not found or has no versions.")
        assert value is not None

        response = AccessSecretVersionResponse(name=f"projects/{PROJECT_NUMBER}/secrets/{name.group(2)}/versions/1",
                                               payload=SecretPayload(data=value, data_crc32c=crc32c(value)))
        if self.tamper is not None:
            response = self.tamper(response)
        serialized: bytes = AccessSecretVersionResponse.serialize(response)
        return serialized


# --- The contract, and what only this writer does -------------------------------------------------


class TestGoogleSecretManagerSecretPipelineWriter(SecretPipelineWriterContract):
    read_failure: ClassVar[type[BaseException]] = core_exceptions.GoogleAPICallError

    google: FakeSecretManager

    @pytest.fixture(autouse=True)
    def _store(self) -> Iterator[None]:
        self.google = FakeSecretManager()
        yield
        self.google.close()

    @pytest.fixture
    def parsed(self, monkeypatch: pytest.MonkeyPatch) -> list[AccessedSecretVersion]:
        """Every response the writer's deserializer parsed, to check its payload was zeroed."""
        versions: list[AccessedSecretVersion] = []
        original = ResponseCapture.deserialize

        def recording(capture: ResponseCapture, raw: bytes) -> AccessedSecretVersion:
            version = original(capture, raw)
            versions.append(version)
            return version

        monkeypatch.setattr(ResponseCapture, "deserialize", recording)
        return versions

    # No key ring anywhere: the only key is the protector's.
    def create_writer_with(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> abstractions.SecretPipelineWriter:
        return self.create(protector, secret_names)

    def set_text(self, name: str, text: str) -> None:
        self.google.set(name, text)

    def set_keys(self, name: str, json: str) -> None:
        self.google.set(name, json)

    def fail_reads(self) -> None:
        self.google.failure = (grpc.StatusCode.PERMISSION_DENIED, "Denied in a test.")

    def reads(self) -> list[str]:
        return self.google.gets()

    def create(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> GoogleSecretManagerSecretPipelineWriter:
        return GoogleSecretManagerSecretPipelineWriter(self.google.client, PROJECT_ID, protector, secret_names, timeout=10)

    def test_each_secrets_latest_version_is_read_synchronously_or_asynchronously(self) -> None:
        self.google.set("api-key", "value")
        with self.create(self.protector, ["api-key"]) as writer:
            writer.pull_secrets()
            run(writer.pull_secrets_async())

            assert self.decrypt(writer.protected_secrets["api-key"], "api-key") == "value"
        assert self.google.accesses == [f"projects/{PROJECT_ID}/secrets/api-key/versions/latest"] * 2
        assert self.google.unexpected_calls == []

    def test_a_name_without_a_key_reads_the_whole_payload(self) -> None:
        self.google.set("db_login", '{"user":"app"}')
        with self.create(self.protector, ["db_login", "db_login#user"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["db_login"], "db_login") == '{"user":"app"}'
            assert self.decrypt(writer.protected_secrets["db_login__user"], "db_login__user") == "app"

    def test_the_parsed_payload_is_zeroed(self, parsed: list[AccessedSecretVersion]) -> None:
        self.google.set("item", "s3cret")
        with self.create(self.protector, ["item"]) as writer:
            writer.pull_secrets()
            run(writer.pull_secrets_async())

        assert len(parsed) == 2
        assert all(len(version.data) == 6 and not any(version.data) for version in parsed)

    def test_a_payload_that_isnt_utf8_text_is_refused_and_zeroed(self, parsed: list[AccessedSecretVersion]) -> None:
        self.google.set("binary", bytes([0xFF, 0xFE, 0x00, 0x80]))
        with self.create(self.protector, ["binary"]) as writer:
            with pytest.raises(InvalidSecretDataError, match="UTF-8"):
                writer.pull_secrets()

            assert len(writer.protected_secrets) == 0
        assert len(parsed) == 1 and not any(parsed[0].data)

    def test_a_payload_not_matching_its_checksum_is_refused_and_zeroed(self, parsed: list[AccessedSecretVersion]) -> None:
        self.google.set("item", "s3cret")

        def tamper(response: AccessSecretVersionResponse) -> AccessSecretVersionResponse:
            response.payload.data_crc32c += 1
            return response

        self.google.tamper = tamper
        with self.create(self.protector, ["item"]) as writer:
            with pytest.raises(CryptographicError, match="CRC32C"):
                writer.pull_secrets()

            assert len(writer.protected_secrets) == 0
        assert len(parsed) == 1 and not any(parsed[0].data)

    @pytest.mark.parametrize("name", ["projects/123456789012/secrets/other/versions/1", "not a resource name"])
    def test_a_response_for_another_secret_is_refused(self, name: str) -> None:
        self.google.set("item", "s3cret")

        def tamper(response: AccessSecretVersionResponse) -> AccessSecretVersionResponse:
            response.name = name
            return response

        self.google.tamper = tamper
        with self.create(self.protector, ["item"]) as writer, pytest.raises(CryptographicError, match="answered a request for secret 'item'"):
            writer.pull_secrets()

    def test_a_response_without_a_payload_holds_nothing_and_one_without_a_checksum_is_refused(self) -> None:
        self.google.set("none", "x")
        self.google.set("unchecked", "s3cret")

        def tamper(response: AccessSecretVersionResponse) -> AccessSecretVersionResponse:
            if "/none/" in response.name:
                return AccessSecretVersionResponse(name=response.name)
            return AccessSecretVersionResponse(name=response.name, payload=SecretPayload(data=response.payload.data))

        self.google.tamper = tamper
        with self.create(self.protector, ["none"]) as writer:
            with pytest.raises(KeyNotFoundError, match="none"):
                writer.pull_secrets()
        with self.create(self.protector, ["unchecked"]) as writer, pytest.raises(CryptographicError, match="or has none"):
            writer.pull_secrets()

    def test_create_makes_its_own_client_and_close_closes_it(self) -> None:
        with GoogleSecretManagerSecretPipelineWriter.create(PROJECT_ID, self.protector, ["item"], credentials=AnonymousCredentials(),  # type: ignore[no-untyped-call]
                                                            client_options={"api_endpoint": "127.0.0.1:1"}) as writer:
            pass

        # The channel is closed, so a read fails at once.
        with pytest.raises(ValueError, match="closed channel"):
            writer.pull_secrets()

        with pytest.raises(ValueError):
            GoogleSecretManagerSecretPipelineWriter.create("bad/project", self.protector, ["item"])
        with pytest.raises(TypeError):
            GoogleSecretManagerSecretPipelineWriter.create(None, self.protector, ["item"])  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            GoogleSecretManagerSecretPipelineWriter.create(PROJECT_ID, self.protector, ["item"], timeout=0)

    def test_a_client_passed_in_is_left_open(self) -> None:
        self.google.set("item", "s3cret")
        with self.create(self.protector, ["item"]):
            pass
        with self.create(self.protector, ["item"]) as writer:
            writer.pull_secrets()

    def test_a_rest_client_is_refused(self) -> None:
        client = SecretManagerServiceClient(transport="rest", credentials=AnonymousCredentials())  # type: ignore[no-untyped-call]
        with pytest.raises(ValueError, match="gRPC"):
            GoogleSecretManagerSecretPipelineWriter(client, PROJECT_ID, self.protector, ["item"])

    @pytest.mark.parametrize("secret_name", ["prod/app", "db.login"])
    def test_an_id_secret_manager_cant_hold_is_refused(self, secret_name: str) -> None:
        with pytest.raises(ValueError):
            self.create(self.protector, [secret_name])

    def test_is_valid_secret_name_is_secret_managers_rule(self) -> None:
        writer = GoogleSecretManagerSecretPipelineWriter
        assert writer.is_valid_secret_name("db_login-2")
        assert writer.is_valid_secret_name("a" * writer.MAX_SECRET_NAME_LENGTH)
        assert not writer.is_valid_secret_name("a" * (writer.MAX_SECRET_NAME_LENGTH + 1))
        assert not writer.is_valid_secret_name("")
        assert not writer.is_valid_secret_name(None)

    def test_the_constructor_checks_the_client_and_project(self) -> None:
        with pytest.raises(TypeError):
            GoogleSecretManagerSecretPipelineWriter(None, PROJECT_ID, self.protector, ["item"])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            GoogleSecretManagerSecretPipelineWriter(self.google.client, None, self.protector, ["item"])  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            GoogleSecretManagerSecretPipelineWriter(self.google.client, "", self.protector, ["item"])
        with pytest.raises(ValueError):
            GoogleSecretManagerSecretPipelineWriter(self.google.client, "projects/x", self.protector, ["item"])
        with pytest.raises(ValueError):
            GoogleSecretManagerSecretPipelineWriter(self.google.client, PROJECT_ID, self.protector, ["item"], timeout=-1)

    def test_crc32c_is_castagnolis(self) -> None:
        assert GoogleSecretManagerSecretPipelineWriter.crc32c(b"123456789") == 0xE3069283
