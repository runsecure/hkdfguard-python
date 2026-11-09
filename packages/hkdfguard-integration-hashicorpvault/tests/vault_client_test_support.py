"""What VaultClient's tests share: a fake Vault on loopback, a key wrapper revealing a fixed key, and decrypting tokens."""

from __future__ import annotations

import os
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from hkdfguard.abstractions import DataProtector, KeyWrapper, WritableBuffer
from hkdfguard.integration.hashicorpvault import StaticVaultToken, VaultClient

TOKEN = "hvs.CAESIFakeTokenForTests"


@dataclass
class Answer:
    """A status, a body ("" for none) and any extra headers; a status of -1 drops the connection."""

    status: int
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)


DROP = Answer(-1)


@dataclass
class Received:
    """A request as it arrived."""

    method: str
    target: str
    headers: dict[str, list[str]]
    body: bytes

    def header(self, name: str) -> str | None:
        """The header's values joined with ","; None if it wasn't sent."""
        values = self.headers.get(name.lower())
        return None if values is None else ",".join(values)

    @property
    def path(self) -> str:
        return urlsplit(self.target).path

    @property
    def body_text(self) -> str | None:
        return self.body.decode() if self.body else None


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _handle(self) -> None:
        vault = self.server.vault
        headers: dict[str, list[str]] = {}
        for name, value in self.headers.items():
            headers.setdefault(name.lower(), []).append(value)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        received = Received(self.command, self.path, headers, body)
        vault.requests.append(received)
        if vault.delay:
            time.sleep(vault.delay)
        with vault.lock:
            responder = vault.queued.pop(0) if vault.queued else vault.respond
        answer = responder(received)
        if answer.status < 0:
            self.close_connection = True
            self.connection.close()
            return
        data = answer.body.encode()
        self.send_response(answer.status)
        for name, value in answer.headers.items():
            self.send_header(name, value)
        if data:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle  # noqa: N815 - http.server's names


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, vault: FakeVault) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.vault = vault

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # A client that gave up mid-answer.


class FakeVault:
    """Vault's HTTP API on 127.0.0.1 (http, which the client allows on loopback; or https given a
    server context): every request is recorded as it arrives, then answered by the next queued
    responder, or by :attr:`respond` once the queue is empty."""

    def __init__(self, context: ssl.SSLContext | None = None) -> None:
        self.requests: list[Received] = []
        self.queued: list[Callable[[Received], Answer]] = []
        self.lock = threading.Lock()
        self.respond: Callable[[Received], Answer] = lambda _: Answer(200, '{"data":{}}')
        self.delay = 0.0
        self._server = _Server(self)
        self.https = context is not None
        if context is not None:
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        threading.Thread(target=self._server.serve_forever, args=(0.05,), daemon=True).start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def address(self) -> str:
        return f"{'https' if self.https else 'http'}://127.0.0.1:{self.port}"

    def then(self, status: int | Callable[[Received], Answer], body: str = "", **headers: str) -> FakeVault:
        """Queues an answer: a status, body and headers (underscores in names become dashes), or a responder."""
        if callable(status):
            self.queued.append(status)
        else:
            answer = Answer(status, body, {name.replace("_", "-"): value for name, value in headers.items()})
            self.queued.append(lambda _: answer)
        return self

    def single(self) -> Received:
        assert len(self.requests) == 1, self.requests
        return self.requests[0]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class FixedKeyWrapper(KeyWrapper):
    """A KeyWrapper that always reveals the same fixed key."""

    def __init__(self, key: bytes) -> None:
        self.key = key

    def wrap(self, plaintext: Any, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Any, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


def decrypt(protector: DataProtector, protected: str | StaticVaultToken) -> str:
    """What a protected token decrypts to."""
    text = protected.get_token() if isinstance(protected, StaticVaultToken) else protected
    result = bytearray(protector.get_max_decrypted_length(text))
    return result[:protector.decrypt(text, result)].decode()


type MakeClient = Callable[..., VaultClient]
"""Makes a client of the fake; keyword arguments replace its options."""


@dataclass
class Tls:
    """A CA, a server certificate it issued for 127.0.0.1 and localhost, and contexts serving it."""

    ca_pem: bytes
    server_context: ssl.SSLContext
