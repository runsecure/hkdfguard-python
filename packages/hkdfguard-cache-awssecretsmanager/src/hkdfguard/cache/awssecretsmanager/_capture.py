"""Takes one GetSecretValue's secret out of its response body, before botocore parses it."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Final

from hkdfguard.cache import SecretJsonBody, SecretValueSink

TEXT_PROPERTY: Final = "SecretString"
BINARY_PROPERTY: Final = "SecretBinary"

EVENT_NAME: Final = "before-parse.secrets-manager.GetSecretValue"
"""The botocore event the capture handles: emitted by the endpoint once per attempt, after the body
has been read and before the response parser turns it into a dict."""

HANDLER_ID: Final = "hkdfguard.cache.awssecretsmanager.capture"
"""The handler's unique id on a client's event system, so it is registered there only once however
many caches share the client."""


class SecretCapture:
    """The capture of one GetSecretValue call: hands its secret to :attr:`sink` and records whether
    a successful response passed through it, and why one was refused. Active only while
    :func:`active` holds it, in the thread (or task) making the call."""

    def __init__(self, sink: SecretValueSink) -> None:
        self.sink = sink
        self._lock = threading.Lock()
        self._captured = False
        self._failure: Exception | None = None

    @property
    def captured(self) -> bool:
        """Whether a successful response's body reached :meth:`capture`."""
        with self._lock:
            return self._captured

    @property
    def failure(self) -> Exception | None:
        """Why a response body was refused; the first reason wins. ``None`` if none was."""
        with self._lock:
            return self._failure

    def capture(self, body: Any) -> bytes:
        """Hands the secret in ``body`` to the sink and returns the body with it replaced by ``""``."""
        with self._lock:
            self._captured = True
        try:
            return SecretJsonBody.capture(body, self.sink, TEXT_PROPERTY, BINARY_PROPERTY)
        except Exception as error:
            with self._lock:
                if self._failure is None:
                    self._failure = error
            raise


# The capture of the GetSecretValue call the current thread (or task) is making, if this library
# is making one. A ContextVar, so concurrent calls through one shared client - from other threads,
# or asyncio.to_thread workers, each with a context of its own - never see each other's.
_ACTIVE: Final[ContextVar[SecretCapture | None]] = ContextVar("hkdfguard_aws_secrets_manager_capture", default=None)


@contextmanager
def active(capture: SecretCapture) -> Iterator[None]:
    """Makes ``capture`` the one :func:`redact_response` uses, for calls made in this context until exit."""
    token = _ACTIVE.set(capture)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def redact_response(response_dict: dict[str, Any] | None = None, **_: Any) -> None:
    """The ``before-parse`` handler: when this context is making a capturing call and the response
    succeeded, replaces the body botocore is about to parse with the redacted one; otherwise -
    the application's own calls on the client, error responses - leaves it as it is."""
    capture = _ACTIVE.get()
    if capture is None or response_dict is None:
        return
    status = response_dict.get("status_code")
    if not isinstance(status, int) or status >= 300:
        return
    response_dict["body"] = capture.capture(response_dict.get("body"))
