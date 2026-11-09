"""Where a pipeline writes to a process's standard input: a binary file-like object, or an asyncio stream."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Protocol


class BinaryDestination(Protocol):
    """A binary file-like object written to and flushed - .NET's ``Stream`` for the blocking
    pipeline writes: ``subprocess.Popen(..., stdin=subprocess.PIPE).stdin``, a file opened ``"wb"``,
    an ``io.BytesIO``. Only ``write`` and ``flush`` are called; it is never closed.

    A buffered object (Popen's default ``bufsize``, a file opened with buffering) copies what is
    written into a buffer of its own, which this library can't zero: for the key, open the pipe
    unbuffered (``bufsize=0``)."""

    def write(self, data: bytearray, /) -> object:
        """Writes ``data``, all of it - as a buffered writer, or a blocking raw one, does."""
        ...

    def flush(self) -> object:
        """Hands on whatever ``write`` buffered."""
        ...


class AsyncBinaryDestination(Protocol):
    """An asyncio stream written to and drained - .NET's ``Stream`` for the asynchronous pipeline
    writes: an :class:`asyncio.StreamWriter`, such as
    ``(await asyncio.create_subprocess_exec(..., stdin=asyncio.subprocess.PIPE)).stdin``. Only
    ``write`` and ``drain`` are called; it is never closed.

    The transport behind the stream copies what is written into a buffer of its own until it is
    sent (on Windows, an immutable ``bytes``), which this library can't zero."""

    def write(self, data: bytearray, /) -> object:
        """Queues ``data`` for sending, all of it."""
        ...

    def drain(self) -> Awaitable[object]:
        """Waits until what is queued has been handed on - the flush."""
        ...
