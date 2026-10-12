"""Buffers holding secrets, and the UTF-8 rules every port shares."""

from __future__ import annotations

import ctypes
import hmac
import re
from collections.abc import Buffer

type WritableBuffer = bytearray | memoryview
"""A buffer HkdfGuard may write to - and, for plaintext it consumes, zero."""

_SURROGATE = re.compile("[\ud800-\udfff]")


class ArrayUtility:
    """Helpers for buffers holding secrets.

    Python's ``bytes`` and ``str`` are immutable and can't be zeroed, so every secret HkdfGuard
    handles - keys, plaintext - travels in a ``bytearray`` (or a ``memoryview`` over one), which is
    zeroed as soon as it is no longer needed. That erases the live copy of a secret; a ``str`` the
    caller passed in, or a temporary the interpreter made while encoding one, is beyond reach.
    """

    @staticmethod
    def is_null_or_empty(data: Buffer | None) -> bool:
        """True if ``data`` is ``None``, empty, or every byte is zero. Never short-circuits on the
        first non-zero byte, so its time depends on the length, not on where the key material is."""
        if data is None:
            return True
        view = memoryview(data).cast("B")
        return len(view) == 0 or hmac.compare_digest(view, bytes(len(view)))

    @staticmethod
    def overlaps(first: WritableBuffer, second: WritableBuffer) -> bool:
        """True if the two buffers share any memory - the same bytearray, or views over overlapping
        parts of one. An empty buffer overlaps nothing."""
        a = memoryview(first).cast("B")
        b = memoryview(second).cast("B")
        if len(a) == 0 or len(b) == 0:
            return False
        start_a, start_b = ArrayUtility._address(a), ArrayUtility._address(b)
        return start_a < start_b + len(b) and start_b < start_a + len(a)

    @staticmethod
    def _address(view: memoryview) -> int:
        # The ctypes object holds a buffer export only until it is released here.
        return ctypes.addressof(ctypes.c_char.from_buffer(view))

    @staticmethod
    def zero_memory(buffer: WritableBuffer | None) -> None:
        """Zeroes every byte of ``buffer``; ``None`` is ignored."""
        if buffer is None:
            return
        view = memoryview(buffer).cast("B")
        view[:] = bytes(len(view))


class Utf8:
    """UTF-8 encoding exactly as every HkdfGuard port does it.

    Text is read as the .NET and Java ports read theirs - as UTF-16 - so a surrogate pair held in a
    ``str`` (as two code points) encodes as the single character it stands for. :meth:`encode`
    substitutes U+FFFD for an unpaired surrogate, as .NET's Encoding.UTF8 does; :meth:`encode_strict`
    refuses one instead, for AADs and other identifiers, where a substitution would give two
    different names the same bytes.
    """

    @staticmethod
    def encode(text: str) -> bytearray:
        """``text`` as UTF-8, substituting U+FFFD for an unpaired surrogate. The caller owns the
        result and should zero it once done."""
        return bytearray(Utf8._normalize(text, "replace"), "utf-8")

    @staticmethod
    def encode_strict(text: str) -> bytearray:
        """``text`` as UTF-8.

        :raises ValueError: ``text`` holds an unpaired surrogate (it is not valid UTF-16)
        """
        return bytearray(Utf8._normalize(text, "strict"), "utf-8")

    @staticmethod
    def require_well_formed(text: str) -> None:
        """:raises ValueError: ``text`` holds an unpaired surrogate"""
        Utf8._normalize(text, "strict")

    @staticmethod
    def _normalize(text: str, errors: str) -> str:
        if _SURROGATE.search(text) is None:
            return text
        # Round-trip through UTF-16 so a pair joins into one character and a lone surrogate either
        # becomes U+FFFD (replace) or raises (strict).
        try:
            return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", errors)
        except UnicodeDecodeError as error:
            raise ValueError(f"The text is not valid UTF-16: it has an unpaired surrogate near index {error.start // 2}.") from None
