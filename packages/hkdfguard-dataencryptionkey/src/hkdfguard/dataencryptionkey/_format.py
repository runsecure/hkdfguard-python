"""Base64 rules and the ``enc::v{version}::{base64}`` wire format."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Buffer
from typing import Final

from hkdfguard.abstractions import EncryptedFormatError, EncryptedFormatProvider, KeyTrackingValue, WritableBuffer
from hkdfguard.diagnostics import AttributeNames, HkdfGuardTelemetry, SpanNames

_BASE64: Final = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", re.ASCII)
_VERSION: Final = re.compile(r"-?[0-9]+", re.ASCII)


class Base64ConversionUtility:
    """Base64 (RFC 4648, standard alphabet, padded) checks and conversions, with the same strictness
    on every port: valid only when the length is a multiple of 4, every character is in the alphabet,
    and '=' appears only as one or two trailing padding characters."""

    @staticmethod
    def is_base64(text: str | Buffer) -> bool:
        """True if ``text`` (a ``str``, or ASCII bytes) is valid base64; an empty input is."""
        if not isinstance(text, str):
            try:
                text = bytes(text).decode("ascii")
            except UnicodeDecodeError:
                return False
        return _BASE64.fullmatch(text) is not None

    @staticmethod
    def get_binary_length(text: str) -> int:
        """The decoded length of base64 text.

        :raises EncryptedFormatError: the length is not a multiple of 4
        """
        if not text:
            return 0
        if len(text) % 4:
            raise EncryptedFormatError("Base64 input length must be a multiple of 4.")
        return len(text) // 4 * 3 - (text[-1] == "=") - (text[-2] == "=")

    @staticmethod
    def get_base64_length(data: Buffer) -> int:
        length = len(memoryview(data))
        return 0 if length == 0 else (length + 2) // 3 * 4

    @staticmethod
    def from_base64(text: str, destination: WritableBuffer) -> int:
        """Decodes ``text`` into ``destination``.

        :returns: the number of bytes written
        :raises EncryptedFormatError: ``text`` is not valid base64, or ``destination`` is too small
        """
        view = memoryview(destination).cast("B")
        if not Base64ConversionUtility.is_base64(text) or Base64ConversionUtility.get_binary_length(text) > len(view):
            raise EncryptedFormatError("Input is not valid base64, or the destination buffer is too small.")
        decoded = base64.b64decode(text, validate=True)
        view[: len(decoded)] = decoded
        return len(decoded)

    @staticmethod
    def to_base64_string(data: Buffer) -> str:
        return binascii.b2a_base64(data, newline=False).decode("ascii")


class DefaultFormatProvider(EncryptedFormatProvider):
    """The ``enc::v{version}::{base64}`` wire format, identical on every port. Formatted values are
    capped at :attr:`max_encrypted_length` characters (4096 by default, room for about 3 KB of UTF-8
    plaintext): parse rejects anything longer before decoding it, and format refuses to produce a
    value parse would reject."""

    DEFAULT_MAX_ENCRYPTED_LENGTH: Final = 4096

    _PREFIX: Final = "enc"
    _DELIMITER: Final = "::"
    _MALFORMED: Final = "Invalid encrypted format. Expected 'enc::v<version>::<base64>'."

    def __init__(self, max_encrypted_length: int = DEFAULT_MAX_ENCRYPTED_LENGTH) -> None:
        """:raises ValueError: ``max_encrypted_length`` is not positive"""
        if max_encrypted_length <= 0:
            raise ValueError(f"max_encrypted_length must be positive; it is {max_encrypted_length}.")
        self.max_encrypted_length: Final = max_encrypted_length

    def format(self, value: KeyTrackingValue) -> str:
        """:raises ValueError: the formatted value would exceed the limit"""
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.FORMAT_PROVIDER_FORMAT) as span:
            if value is None:
                raise TypeError("value must not be None.")
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.FORMAT_PROVIDER_FORMAT,
                                                  {AttributeNames.KEY_VERSION: value.key_version, AttributeNames.VALUE_LENGTH: len(value.value)})

            prefix = f"{self._PREFIX}{self._DELIMITER}v{value.key_version}{self._DELIMITER}"
            length = len(prefix) + Base64ConversionUtility.get_base64_length(value.value)
            if length > self.max_encrypted_length:
                raise ValueError(f"The formatted value would be {length} characters, over the {self.max_encrypted_length}-character limit.")
            return prefix + Base64ConversionUtility.to_base64_string(value.value)

    def parse(self, encrypted: str) -> KeyTrackingValue:
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.FORMAT_PROVIDER_PARSE) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.FORMAT_PROVIDER_PARSE, {AttributeNames.ENCRYPTED_LENGTH: len(encrypted)})

            version, text = self._segments(encrypted)
            value = bytearray(Base64ConversionUtility.get_binary_length(text))
            Base64ConversionUtility.from_base64(text, value)
            return KeyTrackingValue(version, bytes(value))

    def get_max_decrypted_length(self, encrypted: str) -> int:
        telemetry = HkdfGuardTelemetry.DATA_PROTECTION
        with telemetry.start_span(SpanNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH) as span:
            if telemetry.sensitive_logging_enabled:
                telemetry.log_sensitive_operation(span, SpanNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH,
                                                  {AttributeNames.ENCRYPTED_LENGTH: len(encrypted)})
            return Base64ConversionUtility.get_binary_length(self._segments(encrypted)[1])

    def _segments(self, encrypted: str) -> tuple[int, str]:
        """Shared by parse and get_max_decrypted_length, so both agree on exactly what is well-formed:
        only the canonical form format writes - ASCII digits with an optional '-', no whitespace."""
        if encrypted is None:
            raise TypeError("encrypted must not be None.")
        if len(encrypted) > self.max_encrypted_length:
            raise EncryptedFormatError(f"Encrypted value is {len(encrypted)} characters, over the {self.max_encrypted_length}-character limit.")

        parts = encrypted.split(self._DELIMITER, 2)
        if len(parts) != 3 or parts[0] != self._PREFIX or not parts[1].startswith("v"):
            raise EncryptedFormatError(self._MALFORMED)

        digits = parts[1][1:]
        if _VERSION.fullmatch(digits) is None or not -(2**31) <= int(digits) < 2**31:
            raise EncryptedFormatError(self._MALFORMED)

        if not Base64ConversionUtility.is_base64(parts[2]):
            raise EncryptedFormatError("Encrypted value is not valid base64.")
        return int(digits), parts[2]
