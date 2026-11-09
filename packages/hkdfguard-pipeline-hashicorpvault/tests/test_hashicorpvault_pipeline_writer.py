"""The writer's contract, and what only it does, with its real http.client against a fake Vault on loopback."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from urllib.parse import urlsplit

import pytest
from hkdfguard import abstractions
from hkdfguard.abstractions import KeyNotFoundError, ObjectClosedError, PipelineDataProtector
from hkdfguard.cache import InvalidSecretDataError
from hkdfguard.integration.hashicorpvault import MAX_RETRY_DELAY, StaticVaultTokenSource, VaultRequestError, VaultTokenSource
from hkdfguard.pipeline.hashicorpvault import HashiCorpVaultPipelineOptions, HashiCorpVaultSecretPipelineWriter, VaultKvVersion
from pipeline_test_support import SecretPipelineWriterContract, run

# --- A fake Vault ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Answer:
    """An answer given as it is: a status, a body ("" for none) and any extra headers."""

    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, vault: FakeVault) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.vault = vault

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        self.server.vault.handle(self)

    do_LIST = do_POST = do_PUT = do_DELETE = do_GET  # noqa: N815 - BaseHTTPRequestHandler's names


class FakeVault:
    """A KV secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which the
    writer allows on loopback): a GET of a secret's read path with the expected token is answered as
    Vault answers it - the secret, or 404 with an empty error list - for KV version 2 (the default)
    or 1. A request without that token is refused with 403, as Vault refuses it. Any other request -
    a LIST, a query, another path - is recorded in :attr:`unexpected_requests` and refused. Paths are
    matched exactly, as Vault matches them."""

    TOKEN = "hvs.CAESIFakeTokenForTests"

    def __init__(self, mount_path: str = "secret", kv_version: VaultKvVersion = VaultKvVersion.V2) -> None:
        self.mount_path = mount_path
        self.kv_version = kv_version
        self.secrets: dict[str, dict[str, Any]] = {}
        # Secrets whose data is JSON as it is, which a dict can't hold - a member twice, say.
        self.raw_data: dict[str, str] = {}
        self.deleted: set[str] = set()
        self._lock = threading.Lock()
        self._reads: list[str] = []
        self._tokens: list[str] = []
        self._namespaces: list[str] = []
        self._unexpected: list[str] = []
        # When set, a read with the right token is answered with this.
        self.answer: Answer | None = None
        # Answered instead, once each, before anything else.
        self.next_answers: list[Answer] = []
        self._server = _Server(self)
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    @property
    def address(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/"

    def set_data(self, path: str, data: dict[str, Any]) -> None:
        self.raw_data.pop(path, None)
        self.secrets[path] = data

    def set_raw_data(self, path: str, json_object: str) -> None:
        self.secrets.pop(path, None)
        self.raw_data[path] = json_object

    def set(self, path: str, value: str) -> None:
        self.set_data(path, {"value": value})

    def set_deleted(self, path: str) -> None:
        """A KV version 2 secret whose latest version is deleted: Vault answers 404 with its metadata."""
        self.deleted.add(path)

    @property
    def reads(self) -> list[str]:
        with self._lock:
            return list(self._reads)

    @property
    def tokens(self) -> list[str]:
        with self._lock:
            return list(self._tokens)

    @property
    def namespaces(self) -> list[str]:
        with self._lock:
            return list(self._namespaces)

    @property
    def unexpected_requests(self) -> list[str]:
        with self._lock:
            return list(self._unexpected)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def handle(self, handler: _Handler) -> None:
        parts = urlsplit(handler.path)
        prefix = f"/v1/{self.mount_path}/" + ("data/" if self.kv_version is VaultKvVersion.V2 else "")
        if handler.command != "GET" or parts.query or not parts.path.startswith(prefix):
            with self._lock:
                self._unexpected.append(f"{handler.command} {handler.path}")
            respond(handler, Answer(405, '{"errors":["1 error occurred:\\n\\t* unsupported operation\\n\\n"]}'))
            return

        assert handler.headers.get("X-Vault-Request") == "true"
        token = handler.headers.get("X-Vault-Token")
        path = parts.path[len(prefix):]
        with self._lock:
            self._tokens.append(token or "")
            self._namespaces.append(handler.headers.get("X-Vault-Namespace") or "(none)")
            self._reads.append(path)
            given = self.next_answers.pop(0) if self.next_answers else self.answer

        if token != self.TOKEN:
            respond(handler, Answer(403, '{"errors":["permission denied"]}'))
        elif given is not None:
            respond(handler, given)
        elif path in self.deleted:
            respond(handler, Answer(404, envelope({"data": None, "metadata": metadata(deleted=True)}, 0)))
        elif path in self.raw_data:
            raw = self.raw_data[path]
            respond(handler, Answer(200, '{"data":{"data":' + raw + ',"metadata":{}}}' if self.kv_version is VaultKvVersion.V2 else '{"data":' + raw + "}"))
        elif path not in self.secrets:
            respond(handler, Answer(404, '{"errors":[]}'))
        elif self.kv_version is VaultKvVersion.V2:
            respond(handler, Answer(200, envelope({"data": self.secrets[path], "metadata": metadata(deleted=False)}, 0)))
        else:
            respond(handler, Answer(200, envelope(self.secrets[path], 2764800)))


def metadata(*, deleted: bool) -> dict[str, Any]:
    return {"created_time": "2026-10-28T12:00:00.000000Z", "custom_metadata": None,
            "deletion_time": "2026-10-28T13:00:00.000000Z" if deleted else "", "destroyed": False, "version": 3}


def envelope(data: Any, lease_duration: int) -> str:
    return json.dumps({"request_id": "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a", "lease_id": "", "renewable": False,
                       "lease_duration": lease_duration, "data": data, "wrap_info": None, "warnings": None, "auth": None,
                       "mount_type": "kv"})


def respond(handler: _Handler, answer: Answer) -> None:
    body = answer.body.encode()
    handler.send_response(answer.status)
    handler.send_header("Content-Type", "application/json")
    for name, value in answer.headers.items():
        handler.send_header(name, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class GivingTokenSource(VaultTokenSource):
    """A token source that copies whatever ``give`` returns, as it is, and counts its calls."""

    def __init__(self, give: Callable[[], bytes]) -> None:
        self.give = give
        self.calls = 0

    def copy_token(self, destination: memoryview) -> int:
        self.calls += 1
        token = self.give()
        destination[:len(token)] = token
        return len(token)


# --- The contract, and what only this writer does -------------------------------------------------


class TestHashiCorpVaultSecretPipelineWriter(SecretPipelineWriterContract):
    read_failure: ClassVar[type[BaseException]] = VaultRequestError

    vault: FakeVault
    token: StaticVaultTokenSource

    @pytest.fixture(autouse=True)
    def _store(self) -> Iterator[None]:
        self.vault = FakeVault()
        with StaticVaultTokenSource(FakeVault.TOKEN) as token:
            self.token = token
            yield
        self.vault.close()

    # No key ring anywhere: the token is a plain source, and the only key is the protector's.
    def create_writer_with(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> abstractions.SecretPipelineWriter:
        return self.create(protector, secret_names)

    # A name without a key reads the default key, "value".
    def set_text(self, name: str, text: str) -> None:
        self.vault.set(name, text)

    def set_keys(self, name: str, json: str) -> None:
        self.vault.set_raw_data(name, json)

    def fail_reads(self) -> None:
        self.vault.answer = Answer(403, '{"errors":["permission denied"]}')

    def reads(self) -> list[str]:
        return self.vault.reads

    def create(self, protector: PipelineDataProtector, secret_names: Sequence[str], options: HashiCorpVaultPipelineOptions | None = None,
               vault: FakeVault | None = None, token: VaultTokenSource | None = None) -> HashiCorpVaultSecretPipelineWriter:
        return HashiCorpVaultSecretPipelineWriter((vault or self.vault).address, token or self.token, protector, secret_names,
                                                  options=options or HashiCorpVaultPipelineOptions(retry_delay=timedelta(0)))

    def test_every_read_sends_the_token_and_no_namespace(self) -> None:
        self.vault.set_data("myapp/db", {"username": "app"})
        with self.create(self.protector, ["myapp/db#username"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["myapp__db__username"], "myapp__db__username") == "app"
        assert self.vault.tokens == [FakeVault.TOKEN]
        assert self.vault.namespaces == ["(none)"]
        assert self.vault.unexpected_requests == []

    def test_a_namespace_is_sent_with_every_read(self) -> None:
        self.vault.set("item", "s3cret")
        with self.create(self.protector, ["item"], HashiCorpVaultPipelineOptions(namespace="team-a/prod")) as writer:
            writer.pull_secrets()
        assert self.vault.namespaces == ["team-a/prod"]

    def test_a_deleted_latest_version_or_a_body_without_data_is_missing(self) -> None:
        self.vault.set_deleted("gone")
        with self.create(self.protector, ["gone"]) as writer:
            with pytest.raises(KeyNotFoundError):
                writer.pull_secrets()

            self.vault.answer = Answer(200, '{"data":{"metadata":{"version":3}}}')
            with pytest.raises(KeyNotFoundError, match="gone"):
                writer.pull_secrets()

    def test_the_default_key_is_the_options_one(self) -> None:
        self.vault.set_data("myapp/db", {"password": "s3cret"})
        with self.create(self.protector, ["myapp/db"], HashiCorpVaultPipelineOptions(default_key="password")) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["myapp__db"], "myapp__db") == "s3cret"

    def test_kv_version_1_is_read_at_the_mount_path(self) -> None:
        vault = FakeVault(mount_path="kv", kv_version=VaultKvVersion.V1)
        try:
            vault.set("item", "s3cret")
            with self.create(self.protector, ["item"], HashiCorpVaultPipelineOptions(kv_version=VaultKvVersion.V1, mount_path="kv"), vault) as writer:
                writer.pull_secrets()

                assert self.decrypt(writer.protected_secrets["item"], "item") == "s3cret"
            assert vault.unexpected_requests == []
        finally:
            vault.close()

    @pytest.mark.parametrize(("status", "body", "detail"), [
        (403, '{"errors":["permission denied"]}', ": permission denied"),
        (404, '{"errors":["no handler for route \\"secret/data/item\\""]}', ': no handler for route "secret/data/item"'),
        (404, "<html>Not Found</html>", ""),
        (400, "", ""),
        (307, "", ""),
    ])
    def test_a_vault_error_propagates_with_its_status_and_errors(self, status: int, body: str, detail: str) -> None:
        self.vault.answer = Answer(status, body)
        with self.create(self.protector, ["item"]) as writer:
            with pytest.raises(VaultRequestError) as raised:
                writer.pull_secrets()

        assert raised.value.status_code == status
        assert str(raised.value).startswith(f"Vault refused to read 'item': {status} ")
        assert str(raised.value).endswith(detail)

    def test_a_transient_failure_is_retried(self) -> None:
        self.vault.set("item", "s3cret")
        self.vault.next_answers = [Answer(503, '{"errors":["Vault is sealed"]}'), Answer(429, "")]
        with self.create(self.protector, ["item"]) as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["item"], "item") == "s3cret"
        assert self.vault.reads == ["item"] * 3

    def test_retries_once_spent_raise_the_last_failure(self) -> None:
        self.vault.answer = Answer(503, '{"errors":["Vault is sealed"]}')
        with self.create(self.protector, ["item"]) as writer, pytest.raises(VaultRequestError, match="503 Service Unavailable: Vault is sealed"):
            writer.pull_secrets()
        assert len(self.vault.reads) == 1 + HashiCorpVaultPipelineOptions.MIN_RETRY_COUNT

    @pytest.mark.parametrize("body", ["[]", "", '{"data":'])
    def test_a_success_that_isnt_vaults_json_is_refused(self, body: str) -> None:
        self.vault.answer = Answer(200, body)
        with self.create(self.protector, ["item"]) as writer:
            with pytest.raises(InvalidSecretDataError):
                writer.pull_secrets()
            assert len(writer.protected_secrets) == 0

    @pytest.mark.parametrize("token", [b"", b"has space", b"\x01"])
    def test_a_token_source_supplying_no_token_fails_the_pull_without_a_read(self, token: bytes) -> None:
        source = GivingTokenSource(lambda: token)
        with self.create(self.protector, ["item"], token=source) as writer, pytest.raises(RuntimeError, match="no token"):
            writer.pull_secrets()
        assert self.vault.reads == []

    def test_the_token_is_asked_for_once_per_secret_and_its_failure_propagates_unretried(self) -> None:
        self.vault.set("a", "1")
        self.vault.set("b", "2")
        source = GivingTokenSource(FakeVault.TOKEN.encode)
        with self.create(self.protector, ["a", "b"], token=source) as writer:
            writer.pull_secrets()
        assert source.calls == 2

        def fail() -> bytes:
            raise PermissionError("login refused")

        failing = GivingTokenSource(fail)
        with self.create(self.protector, ["a"], token=failing) as writer, pytest.raises(PermissionError, match="login refused"):
            writer.pull_secrets()
        assert failing.calls == 1

    def test_the_list_is_copied(self) -> None:
        self.vault.set("item", "s3cret")
        names = ["item"]
        with self.create(self.protector, names) as writer:
            names.append("other")

            writer.pull_secrets()

            assert list(writer.protected_secrets) == ["item"]

    def test_a_closed_writer_reads_no_more_but_can_still_write(self) -> None:
        self.vault.set("item", "s3cret")
        writer = self.create(self.protector, ["item"])
        writer.pull_secrets()
        writer.close()

        with pytest.raises(ObjectClosedError):
            writer.pull_secrets()
        with pytest.raises(ObjectClosedError):
            run(writer.pull_secrets_async())
        writer.close()

    @pytest.mark.parametrize("secret_name", ["ConnectionStrings:Admin", "../escape", ".hidden", "a//b"])
    def test_a_name_that_isnt_a_path_is_refused(self, secret_name: str) -> None:
        with pytest.raises(ValueError):
            self.create(self.protector, [secret_name])

    def test_a_path_longer_than_vault_reads_is_refused(self) -> None:
        writer = HashiCorpVaultSecretPipelineWriter
        assert writer.is_valid_secret_name("a" * writer.MAX_SECRET_NAME_LENGTH)
        assert not writer.is_valid_secret_name("a" * (writer.MAX_SECRET_NAME_LENGTH + 1))
        assert not writer.is_valid_secret_name(None)

    def test_the_constructor_checks_the_address_token_source_and_options(self) -> None:
        with pytest.raises(TypeError):
            HashiCorpVaultSecretPipelineWriter(self.vault.address, None, self.protector, ["item"])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            HashiCorpVaultSecretPipelineWriter(None, self.token, self.protector, ["item"])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            HashiCorpVaultSecretPipelineWriter(self.vault.address, object(), self.protector, ["item"])  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="https"):
            HashiCorpVaultSecretPipelineWriter("http://vault.example.com", self.token, self.protector, ["item"])
        with pytest.raises(TypeError):
            self.create(self.protector, ["item"], HashiCorpVaultPipelineOptions(kv_version=3))  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            HashiCorpVaultSecretPipelineWriter(self.vault.address, self.token, self.protector, ["item"], options=object())  # type: ignore[arg-type]
        for invalid in (replace(HashiCorpVaultPipelineOptions(), default_key=""), replace(HashiCorpVaultPipelineOptions(), default_key="a#b"),
                        replace(HashiCorpVaultPipelineOptions(), default_key="has space"), replace(HashiCorpVaultPipelineOptions(), mount_path="../x"),
                        replace(HashiCorpVaultPipelineOptions(), retry_count=2), replace(HashiCorpVaultPipelineOptions(), timeout=timedelta(0))):
            with pytest.raises(ValueError):
                self.create(self.protector, ["item"], invalid)
        assert HashiCorpVaultPipelineOptions.MAX_RETRY_DELAY == MAX_RETRY_DELAY

        with HashiCorpVaultSecretPipelineWriter(self.vault.address, self.token, self.protector, ["item"]):
            pass
