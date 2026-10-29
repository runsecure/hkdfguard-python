"""The response bodies SecretJsonBody and ErrorResponseBody read: a buffer, or a stream read into a
bytearray of the library's own."""

from __future__ import annotations

from collections.abc import Buffer
from typing import Protocol, runtime_checkable


@runtime_checkable
class ReadableBody(Protocol):
    """A blocking binary stream that reads into a caller's buffer - ``io.RawIOBase``,
    ``io.BufferedIOBase`` (``io.BytesIO``, a file opened ``"rb"``), urllib3's ``HTTPResponse``. Read
    through ``readinto``, never ``read``, so the body lands only in a bytearray HkdfGuard zeroes."""

    def readinto(self, buffer: memoryview, /) -> int | None:
        """Reads up to ``len(buffer)`` bytes into ``buffer``; 0 (or ``None``) at the end."""


type ResponseBody = Buffer | ReadableBody
"""A whole body already read (``bytes``, ``bytearray``, ``memoryview``), or a stream to read it from."""
