"""Reading certificate and key files: PEM blocks, certificates, and keys - every key file read into a
``bytearray`` that is wiped once used."""

from __future__ import annotations

import binascii
import os
import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm as UnsupportedError
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key
from hkdfguard.options.certificate import _pbe, _pkcs12
from hkdfguard.options.certificate._errors import InvalidCertificateFileError, UnsupportedCertificateError

_MAX_FILE_SIZE = 4 * 1024 * 1024  # far beyond any certificate, chain or key file
_BEGIN = re.compile(rb"-----BEGIN ([A-Z0-9 #]+)-----")
_PLAIN_KEYS = frozenset({"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"})


def read_file(path: str) -> bytearray:
    """A whole file, read into a new ``bytearray`` sized once - so a key file is never copied into
    memory that can't be wiped.

    :raises OSError: it can't be read
    :raises InvalidCertificateFileError: it is far larger than any certificate or key file
    """
    with open(path, "rb", buffering=0) as file:
        size = os.fstat(file.fileno()).st_size
        if size > _MAX_FILE_SIZE:
            raise InvalidCertificateFileError(f"'{path}' is {size} bytes: too large to be a certificate or key file.")
        data = bytearray(size)
        view = memoryview(data)
        read = 0
        while read < size:
            count = file.readinto(view[read:])
            if not count:
                break
            read += count
        if read != size:
            data[:] = bytes(size)
            raise InvalidCertificateFileError(f"'{path}' changed while it was read.")
        return data


@dataclass(frozen=True)
class PemBlock:
    """One PEM block: its label, its headers, and where its base64 body lies in the data."""

    label: str
    headers: dict[str, str]
    body: memoryview


def pem_blocks(data: bytearray) -> list[PemBlock]:
    """Every PEM block in ``data``, in order; the bodies are views of ``data``, not copies."""
    view = memoryview(data)
    blocks = []
    position = 0
    while (begin := _BEGIN.search(data, position)) is not None:
        label = begin.group(1).decode("ascii")
        end_marker = b"-----END " + begin.group(1) + b"-----"
        end = data.find(end_marker, begin.end())
        if end < 0:
            raise InvalidCertificateFileError(f"A PEM {label} block has no END line.")
        start = begin.end()
        headers: dict[str, str] = {}
        # RFC 1421 headers, as legacy OpenSSL-encrypted keys carry: "Name: value" lines, then a blank line.
        lines_end = data.find(b"\n\n", start, end)
        if lines_end < 0:
            lines_end = data.find(b"\r\n\r\n", start, end)
        if lines_end >= 0 and b":" in data[start:lines_end]:
            for line in bytes(data[start:lines_end]).decode("ascii", "replace").splitlines():
                name, _, value = line.partition(":")
                if name.strip():
                    headers[name.strip()] = value.strip()
            start = lines_end
        blocks.append(PemBlock(label, headers, view[start:end]))
        position = end + len(end_marker)
    return blocks


def decode_body(block: PemBlock) -> bytearray:
    """A block's body, base64-decoded. For ciphertext and certificates: the decoder's own output is
    an immutable ``bytes``, copied here into a buffer the caller may wipe."""
    try:
        return bytearray(binascii.a2b_base64(block.body, strict_mode=False))
    except binascii.Error as error:
        raise InvalidCertificateFileError(f"A PEM {block.label} block isn't base64: {error}") from None


def parse_certificates(data: bytearray, path: str) -> list[x509.Certificate]:
    """Every certificate in a PEM file, in file order, or the one DER certificate a file holds.

    :raises InvalidCertificateFileError: it holds no certificate, or one that isn't
    """
    if b"-----BEGIN" not in data:
        try:
            return [x509.load_der_x509_certificate(bytes(data))]
        except ValueError as error:
            raise InvalidCertificateFileError(f"'{path}' isn't a PEM or DER certificate: {error}") from None
    certificates = []
    for block in pem_blocks(data):
        if block.label != "CERTIFICATE":
            continue
        try:
            certificates.append(x509.load_der_x509_certificate(bytes(decode_body(block))))
        except ValueError as error:
            raise InvalidCertificateFileError(f"A certificate in '{path}' isn't one: {error}") from None
    if not certificates:
        raise InvalidCertificateFileError(f"'{path}' holds no CERTIFICATE.")
    return certificates


def encrypted_pkcs8_from_pem(data: bytearray, path: str) -> bytearray:
    """The EncryptedPrivateKeyInfo, DER, of the ``ENCRYPTED PRIVATE KEY`` in a PEM key file - only
    ciphertext and its parameters.

    :raises UnsupportedCertificateError: a legacy OpenSSL-encrypted PEM key (Proc-Type)
    :raises InvalidCertificateFileError: there is none, or the key is plaintext
    """
    for block in pem_blocks(data):
        if "Proc-Type" in block.headers:
            raise UnsupportedCertificateError(f"'{path}' holds a legacy OpenSSL-encrypted PEM key (Proc-Type); convert it to encrypted "
                                              "PKCS#8: openssl pkcs8 -topk8 -v2 aes-256-cbc.")
        if block.label == "ENCRYPTED PRIVATE KEY":
            return decode_body(block)
        if block.label in _PLAIN_KEYS:
            raise InvalidCertificateFileError(f"The key in '{path}' isn't encrypted, but File.PasswordSecretName names a password for it; "
                                              "encrypt it, or leave PasswordSecretName unset and set AllowUnprotectedPrivateKey.")
    raise InvalidCertificateFileError(f"'{path}' holds no ENCRYPTED PRIVATE KEY.")


def plain_pem_key(data: bytearray, path: str) -> PrivateKeyTypes:
    """The plaintext key in a PEM key file - PKCS#8, PKCS#1 or SEC 1 - parsed where it lies.

    :raises InvalidCertificateFileError: there is none, or it is encrypted
    """
    for block in pem_blocks(data):
        if "Proc-Type" in block.headers or block.label == "ENCRYPTED PRIVATE KEY":
            raise InvalidCertificateFileError(f"The key in '{path}' is encrypted, but no File.PasswordSecretName names its password.")
        if block.label in _PLAIN_KEYS:
            try:
                return load_pem_private_key(data, password=None)
            except (ValueError, TypeError, UnsupportedError) as error:
                raise InvalidCertificateFileError(f"The key in '{path}' isn't one: {error}") from None
    raise InvalidCertificateFileError(f"'{path}' holds no PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY.")


def decrypt_pem_key(data: bytearray, password: bytearray, path: str) -> bytearray:
    """The PrivateKeyInfo, DER, the ``ENCRYPTED PRIVATE KEY`` in a PEM key file decrypts to, in a new
    buffer the caller wipes."""
    encrypted = encrypted_pkcs8_from_pem(data, path)
    return _pkcs12.decrypt_pkcs8(encrypted, password, _pbe.IterationBudget())


def private_key_of(private_key_info: bytearray) -> PrivateKeyTypes:
    """A PrivateKeyInfo, parsed by ``cryptography`` where it lies, into a key OpenSSL holds.

    :raises InvalidCertificateFileError: it isn't a key cryptography can parse
    """
    try:
        return load_der_private_key(private_key_info, password=None)
    except (ValueError, TypeError, UnsupportedError) as error:
        raise InvalidCertificateFileError(f"The private key isn't one: {error}") from None


def leaf_first(certificates: list[x509.Certificate], public_key: PublicKeyTypes) -> list[x509.Certificate] | None:
    """``certificates`` with the first whose public key is ``public_key`` first - as .NET chooses the
    certificate - and the rest after it in their order; ``None`` if none is its."""
    for index, certificate in enumerate(certificates):
        if certificate.public_key() == public_key:
            return [certificate, *certificates[:index], *certificates[index + 1:]]
    return None

