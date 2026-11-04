"""What a private key operation asks for, checked once for every kind of key: the digest to sign
and how, or the padding to decrypt with, read from ``cryptography``'s own padding objects."""

from __future__ import annotations

from collections.abc import Buffer
from dataclasses import dataclass
from typing import Literal, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from hkdfguard.options.certificate._errors import UnsupportedCertificateError

type PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


@dataclass(frozen=True)
class RsaSignature:
    """An RSA signature scheme: PKCS #1 v1.5, or PSS with MGF1 over the same hash and a salt length."""

    scheme: Literal["pkcs1", "pss"]
    salt_length: int = 0


@dataclass(frozen=True)
class RsaDecryption:
    """An RSA decryption padding: PKCS #1 v1.5, or OAEP with MGF1 over its hash and a label."""

    scheme: Literal["pkcs1", "oaep"]
    hash: hashes.HashAlgorithm | None = None
    label: bytes = b""


class OsKey(Protocol):
    """A private key the operating system holds: every operation is a call into it."""

    def sign_digest(self, digest: bytes, algorithm: hashes.HashAlgorithm, scheme: RsaSignature | None) -> bytes:
        """Signs ``digest``: RSA with ``scheme``, or ECDSA (``scheme`` ``None``) as DER."""
        ...

    def decrypt(self, ciphertext: bytes, scheme: RsaDecryption) -> bytearray:
        """Decrypts with an RSA key, into a buffer the caller wipes."""
        ...

    def close(self) -> None:
        """Releases the handle to the key."""
        ...


def digest(data: Buffer, algorithm: hashes.HashAlgorithm | Prehashed) -> tuple[bytes, hashes.HashAlgorithm]:
    """``data`` hashed with ``algorithm`` - or, for :class:`Prehashed`, ``data`` itself, checked to be
    its digest's length - and the hash."""
    if isinstance(algorithm, Prehashed):
        hash_algorithm = algorithm._algorithm
        value = bytes(memoryview(data).cast("B"))
        if len(value) != hash_algorithm.digest_size:
            raise ValueError(f"The digest is {len(value)} bytes, not {hash_algorithm.name}'s {hash_algorithm.digest_size}.")
        return value, hash_algorithm
    if not isinstance(algorithm, hashes.HashAlgorithm):
        raise TypeError("algorithm must be a hash algorithm, or Prehashed.")
    hasher = hashes.Hash(algorithm)
    hasher.update(memoryview(data).cast("B"))
    return hasher.finalize(), algorithm


def rsa_signature(scheme: padding.AsymmetricPadding | None, algorithm: hashes.HashAlgorithm, public_key: rsa.RSAPublicKey) -> RsaSignature:
    """The RSA signature scheme ``scheme`` names, with PSS's salt length resolved."""
    if isinstance(scheme, padding.PKCS1v15):
        return RsaSignature("pkcs1")
    if isinstance(scheme, padding.PSS):
        _check_mgf(scheme.mgf, algorithm, "PSS")
        salt = scheme._salt_length
        if isinstance(salt, padding._DigestLength):
            length = algorithm.digest_size
        elif isinstance(salt, padding._MaxLength):
            length = padding.calculate_max_pss_salt_length(public_key, algorithm)
        elif isinstance(salt, int):
            length = salt
        else:
            raise ValueError("PSS.AUTO is only for verifying: sign with PSS.DIGEST_LENGTH, PSS.MAX_LENGTH or a length.")
        if length < 0 or length > padding.calculate_max_pss_salt_length(public_key, algorithm):
            raise ValueError(f"A PSS salt of {length} bytes doesn't fit this key with {algorithm.name}.")
        return RsaSignature("pss", length)
    raise TypeError("An RSA key signs with padding.PKCS1v15() or padding.PSS(...).")


def rsa_decryption(scheme: padding.AsymmetricPadding) -> RsaDecryption:
    """The RSA decryption padding ``scheme`` names."""
    if isinstance(scheme, padding.PKCS1v15):
        return RsaDecryption("pkcs1")
    if isinstance(scheme, padding.OAEP):
        _check_mgf(scheme.mgf, scheme.algorithm, "OAEP")
        return RsaDecryption("oaep", scheme.algorithm, bytes(scheme._label or b""))
    raise TypeError("An RSA key decrypts with padding.PKCS1v15() or padding.OAEP(...).")


def _check_mgf(mgf: padding.MGF, algorithm: hashes.HashAlgorithm, what: str) -> None:
    if not isinstance(mgf, padding.MGF1) or mgf._algorithm.name != algorithm.name:
        raise UnsupportedCertificateError(f"{what} with an operating system key needs MGF1 over the same hash as the signature's.")
