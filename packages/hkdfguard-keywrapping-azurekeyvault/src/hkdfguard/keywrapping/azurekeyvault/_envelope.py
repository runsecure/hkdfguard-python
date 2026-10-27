"""The wrapped-DEK format :class:`AzureKeyVaultKeyWrapper` writes and reads, byte for byte the .NET
AzureKeyVaultKeyWrapper's and the Java AzureKeyVaultKeyWrapperImpl's::

    offset  length  field
    0       4       magic "HGKV"
    4       1       format version (1)
    5       16      wrapping key version (Key Vault's 32 hex digits, as bytes)
    21      2       n, the RSA-OAEP-256 ciphertext's length (big-endian)
    23      n       the DEK, wrapped under that version of the wrapping key
    23+n    16      signing key version
    39+n    64      ES256 signature (r || s) by that version of the signing key

Only key versions are stored: the vault and key names are the wrapper's own, so a key file can never
point it at another key. The signature covers :func:`signed_data`: a domain string, the wrapper's
context, and every byte before the signing key version."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from hkdfguard.abstractions import CryptographicError, WritableBuffer

MAGIC: Final = b"HGKV"
FORMAT_VERSION: Final = 1
KEY_VERSION_LENGTH: Final = 16
SIGNATURE_LENGTH: Final = 64

HEADER_LENGTH: Final = 4 + 1 + KEY_VERSION_LENGTH + 2
"""Magic, format version, wrapping key version and ciphertext length."""

OVERHEAD: Final = HEADER_LENGTH + KEY_VERSION_LENGTH + SIGNATURE_LENGTH
"""Everything besides the RSA ciphertext."""

_MAX_FIELD_LENGTH: Final = 0xFFFF
_DOMAIN: Final = b"HkdfGuard-AzureKeyVault-wrap-v1\0"
_HEX_VERSION: Final = re.compile(r"[0-9A-Fa-f]{32}")


@dataclass(frozen=True)
class Parts:
    """A parsed envelope: the parts, and where the signed part ends."""

    wrapping_key_version: str
    wrapped_dek: bytes
    signing_key_version: str
    signature: bytes
    unsigned_length: int


def build_unsigned(wrapping_key_version: str | None, wrapped_dek: bytes) -> bytes:
    """The header and ciphertext: everything the signature covers besides the domain and context.

    :raises CryptographicError: the version isn't Key Vault's form, or the ciphertext is empty or too
        long to encode
    """
    if not 0 < len(wrapped_dek) <= _MAX_FIELD_LENGTH:
        raise CryptographicError(f"Azure Key Vault returned a {len(wrapped_dek)}-byte wrapped key.")
    return (MAGIC + bytes([FORMAT_VERSION]) + _version_bytes(wrapping_key_version) + len(wrapped_dek).to_bytes(2, "big")
            + bytes(wrapped_dek))


def signed_data(unsigned: bytes, context: bytes) -> bytes:
    """What the signing key signs: the domain, the length-prefixed context, then ``unsigned``."""
    return _DOMAIN + len(context).to_bytes(2, "big") + context + unsigned


def write(unsigned: bytes, signing_key_version: str | None, signature: bytes, result: WritableBuffer) -> int:
    """Writes the complete envelope into ``result``.

    :returns: the number of bytes written
    :raises ValueError: ``result`` is too small
    :raises CryptographicError: the version or signature isn't the expected form
    """
    if len(signature) != SIGNATURE_LENGTH:
        raise CryptographicError(f"Azure Key Vault returned a {len(signature)}-byte signature; an ES256 signature is {SIGNATURE_LENGTH}. "
                                 "The signing key must be an EC P-256 key.")

    # Checked before anything is written, so a refused version leaves result as it was.
    envelope = unsigned + _version_bytes(signing_key_version) + bytes(signature)
    with memoryview(result) as raw, raw.cast("B") as target:
        if len(envelope) > len(target):
            raise ValueError(f"The wrapped DEK is {len(envelope)} bytes; result holds {len(target)}.")
        target[:len(envelope)] = envelope
    return len(envelope)


def parse(envelope: bytes) -> Parts:
    """Splits an envelope into its parts, refusing anything that isn't exactly one.

    :raises CryptographicError: it isn't
    """
    if len(envelope) < OVERHEAD + 1 or not envelope.startswith(MAGIC):
        raise CryptographicError("This is not a wrapped DEK written by AzureKeyVaultKeyWrapper.")
    if envelope[4] != FORMAT_VERSION:
        raise CryptographicError(f"This wrapped DEK is format version {envelope[4]}; only version {FORMAT_VERSION} is supported.")

    wrapped_length = int.from_bytes(envelope[21:23], "big")
    if wrapped_length == 0 or len(envelope) != OVERHEAD + wrapped_length:
        raise CryptographicError(f"This wrapped DEK is {len(envelope)} bytes, but its header describes {OVERHEAD + wrapped_length}.")

    unsigned_length = HEADER_LENGTH + wrapped_length
    return Parts(envelope[5:5 + KEY_VERSION_LENGTH].hex(),
                 envelope[HEADER_LENGTH:unsigned_length],
                 envelope[unsigned_length:unsigned_length + KEY_VERSION_LENGTH].hex(),
                 envelope[unsigned_length + KEY_VERSION_LENGTH:],
                 unsigned_length)


def encode_context(context: str | None) -> bytes:
    """The UTF-8 bytes of a context, refusing one too long to length-prefix, or one that isn't
    well-formed text (a lone surrogate), which .NET would encode differently.

    :raises ValueError: it is
    :raises TypeError: it isn't a ``str``
    """
    if context is None:
        return b""
    if not isinstance(context, str):
        raise TypeError("context must be a str.")
    try:
        encoded = context.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("The context isn't well-formed text: it holds a lone surrogate.") from error
    if len(encoded) > _MAX_FIELD_LENGTH:
        raise ValueError(f"The context is {len(encoded)} bytes in UTF-8; at most {_MAX_FIELD_LENGTH} are allowed.")
    return encoded


# Key Vault key versions are 32 hex digits; stored as the 16 bytes they spell.
def _version_bytes(version: str | None) -> bytes:
    if not isinstance(version, str) or not _HEX_VERSION.fullmatch(version):
        raise CryptographicError(f"Azure Key Vault returned key version {version!r}, not 32 hex digits.")
    return bytes.fromhex(version)
