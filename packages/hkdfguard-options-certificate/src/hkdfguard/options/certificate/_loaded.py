"""LoadedCertificate: an opened certificate, its chain, and - when it has one - what reaches its key."""

from __future__ import annotations

import base64
import os
import ssl
import threading
from abc import ABC, abstractmethod
from collections.abc import Buffer, Iterator
from contextlib import contextmanager
from types import TracebackType
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding
from hkdfguard.abstractions import ArrayUtility, ObjectClosedError
from hkdfguard.options.certificate import _files, _keys, _openssl_provider, _pbe, _pkcs12, _private_files
from hkdfguard.options.certificate._dn import describe
from hkdfguard.options.certificate._errors import NativeProviderRequiredError, NoPrivateKeyError, UnsupportedCertificateError

type HashChoice = hashes.HashAlgorithm | Prehashed


class _KeySource(ABC):
    """Where a certificate's private key is, and how each use of it reaches it."""

    description: str

    @abstractmethod
    def load_tls(self, context: ssl.SSLContext, directory: _private_files.PrivateDirectory, chain_file: str) -> None:
        """Loads the certificate chain and this key into ``context``."""

    @abstractmethod
    def sign(self, data: Buffer, algorithm: HashChoice, scheme: AsymmetricPadding | None, public_key: _keys.PublicKey) -> bytes: ...

    @abstractmethod
    def decrypt(self, ciphertext: Buffer, scheme: AsymmetricPadding, public_key: _keys.PublicKey) -> bytearray: ...

    def close(self) -> None:  # noqa: B027 - most sources hold nothing to release
        """Releases what the source holds."""


class OsKeySource(_KeySource):
    """A key an operating system store holds: every use is a call into it, and it is never exported -
    so Python's ``ssl`` module, which takes a key only from a file, can't use it."""

    def __init__(self, key: _keys.OsKey, description: str) -> None:
        self._key = key
        self.description = description

    def load_tls(self, context: ssl.SSLContext, directory: _private_files.PrivateDirectory, chain_file: str) -> None:
        raise NativeProviderRequiredError(
            f"The certificate's private key is held by {self.description}, and Python's ssl module can only take a key from a file, which "
            "the store's key is never exported to. A TLS context for it needs a native provider (not yet available). Use sign() and "
            "decrypt(), which call the store, or a File or Linux source for TLS.")

    def sign(self, data: Buffer, algorithm: HashChoice, scheme: AsymmetricPadding | None, public_key: _keys.PublicKey) -> bytes:
        digest, hash_algorithm = _keys.digest(data, algorithm)
        if isinstance(public_key, rsa.RSAPublicKey):
            return self._key.sign_digest(digest, hash_algorithm, _keys.rsa_signature(scheme, hash_algorithm, public_key))
        if scheme is not None:
            raise TypeError("An ECDSA key signs with no padding: pass padding=None.")
        return self._key.sign_digest(digest, hash_algorithm, None)

    def decrypt(self, ciphertext: Buffer, scheme: AsymmetricPadding, public_key: _keys.PublicKey) -> bytearray:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise UnsupportedCertificateError("Only an RSA key decrypts.")
        return self._key.decrypt(bytes(memoryview(ciphertext).cast("B")), _keys.rsa_decryption(scheme))

    def close(self) -> None:
        self._key.close()


class EncryptedKeySource(_KeySource):
    """A key read from a file, held encrypted: its PKCS#8 encrypted under a random throwaway password,
    both in memory, wiped on close. Each TLS context decrypts it through ``ssl`` from a private
    temporary file, written encrypted and deleted at once; each signature or decryption decrypts it
    into a buffer wiped straight after."""

    description = "a key file"

    def __init__(self, private_key_info: bytearray) -> None:
        """Encrypts ``private_key_info``; the caller still wipes it."""
        self._password = _throwaway_password()
        self._encrypted = bytearray(_pbe.encrypt_pkcs8(private_key_info, self._password))

    def _pem(self) -> bytes:
        body = base64.encodebytes(self._encrypted).decode("ascii")
        return f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{body}-----END ENCRYPTED PRIVATE KEY-----\n".encode("ascii")

    def load_tls(self, context: ssl.SSLContext, directory: _private_files.PrivateDirectory, chain_file: str) -> None:
        key_file = directory.write("key.pem", self._pem())
        # ssl copies what the callback returns: the copy holds only the throwaway password, of a key file deleted when this returns.
        context.load_cert_chain(chain_file, key_file, password=lambda: self._password)

    @contextmanager
    def _key(self) -> Iterator[object]:
        plaintext = _pkcs12.decrypt_pkcs8(self._encrypted, self._password, _pbe.IterationBudget())
        try:
            yield _files.private_key_of(plaintext)
        finally:
            ArrayUtility.zero_memory(plaintext)

    def sign(self, data: Buffer, algorithm: HashChoice, scheme: AsymmetricPadding | None, public_key: _keys.PublicKey) -> bytes:
        with self._key() as key:
            return _sign_with(key, data, algorithm, scheme)

    def decrypt(self, ciphertext: Buffer, scheme: AsymmetricPadding, public_key: _keys.PublicKey) -> bytearray:
        with self._key() as key:
            return _decrypt_with(key, ciphertext, scheme)

    def close(self) -> None:
        ArrayUtility.zero_memory(self._password)
        ArrayUtility.zero_memory(self._encrypted)


def _throwaway_password() -> bytearray:
    """32 random bytes as 64 hex digits - printable, as OpenSSL's PEM reader takes a password - written
    into a ``bytearray`` digit by digit. The random bytes themselves come from ``os.urandom`` as an
    immutable ``bytes``; they are useless once :meth:`EncryptedKeySource.close` wipes the key they
    encrypt."""
    digits = b"0123456789abcdef"
    password = bytearray(64)
    for index, value in enumerate(os.urandom(32)):
        password[2 * index] = digits[value >> 4]
        password[2 * index + 1] = digits[value & 0x0F]
    return password


class PlainKeyFileSource(EncryptedKeySource):
    """An unprotected key file, allowed for development: read once, when the certificate is loaded and
    its key checked against it, then held as :class:`EncryptedKeySource` holds any key - so a file
    replaced afterwards can't change the key the certificate signs and decrypts with."""

    description = "an unprotected key file"


class ProviderKeySource(_KeySource):
    """A key an OpenSSL provider holds, opened by ``ssl`` through the provider's decoder from a key
    file - the TSS2 key file named, or a private temporary file holding a ``pkcs11:`` URI."""

    def __init__(self, provider: str, key_file: str | None, uri_pem: bytes | None) -> None:
        self._provider = provider
        self._key_file = key_file
        self._uri_pem = uri_pem
        self.description = f"the OpenSSL provider '{provider}'"

    def load_tls(self, context: ssl.SSLContext, directory: _private_files.PrivateDirectory, chain_file: str) -> None:
        _openssl_provider.ensure_loaded(self._provider)
        key_file = self._key_file if self._key_file is not None else directory.write("key-uri.pem", self._uri_pem or b"")
        try:
            context.load_cert_chain(chain_file, key_file)
        except ssl.SSLError as error:
            raise UnsupportedCertificateError(
                f"The OpenSSL provider '{self._provider}' didn't give the key ({error}): check the key is there, that the provider is "
                "configured to reach it (its module, token, PIN or TCTI), and that it is the certificate's.") from error

    def sign(self, data: Buffer, algorithm: HashChoice, scheme: AsymmetricPadding | None, public_key: _keys.PublicKey) -> bytes:
        raise UnsupportedCertificateError(f"A key held by {self.description} is used through create_ssl_context(); Python has no API to sign "
                                          "with it directly.")

    def decrypt(self, ciphertext: Buffer, scheme: AsymmetricPadding, public_key: _keys.PublicKey) -> bytearray:
        raise UnsupportedCertificateError(f"A key held by {self.description} is used through create_ssl_context(); Python has no API to "
                                          "decrypt with it directly.")


def _sign_with(key: object, data: Buffer, algorithm: HashChoice, scheme: AsymmetricPadding | None) -> bytes:
    payload = bytes(memoryview(data).cast("B"))
    if isinstance(key, rsa.RSAPrivateKey):
        if scheme is None:
            raise TypeError("An RSA key signs with padding.PKCS1v15() or padding.PSS(...).")
        return key.sign(payload, scheme, algorithm)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if scheme is not None:
            raise TypeError("An ECDSA key signs with no padding: pass padding=None.")
        return key.sign(payload, ec.ECDSA(algorithm))
    raise UnsupportedCertificateError("Only RSA and ECDSA keys sign here.")


def _decrypt_with(key: object, ciphertext: Buffer, scheme: AsymmetricPadding) -> bytearray:
    if not isinstance(key, rsa.RSAPrivateKey):
        raise UnsupportedCertificateError("Only an RSA key decrypts.")
    return bytearray(key.decrypt(bytes(memoryview(ciphertext).cast("B")), scheme))


class LoadedCertificate:
    """An opened certificate: :attr:`certificate`, the chain its source gave with it, and - when it
    came with its private key - the way to that key, which stays where its source keeps it:

    * a Windows store's key in CNG and a macOS keychain's in the keychain - :meth:`sign` and
      :meth:`decrypt` are calls into the store, and :meth:`create_ssl_context` refuses, since
      Python's ``ssl`` can only take a key from a file;
    * an OpenSSL provider's key in the provider - :meth:`create_ssl_context` gives a context whose
      TLS signatures it makes; :meth:`sign` and :meth:`decrypt` refuse, as Python has no API for them;
    * a key file's key encrypted in memory, under a random throwaway password - both wiped by
      :meth:`close` - for :meth:`create_ssl_context`, :meth:`sign` and :meth:`decrypt`.

    Close it - or use it as a context manager - to release the store's handles and wipe what is held;
    every use of the key after that raises :class:`~hkdfguard.abstractions.ObjectClosedError`, and
    :meth:`close` waits for uses in flight. Safe for concurrent use.
    """

    def __init__(self, certificates: list[x509.Certificate], key: _KeySource | None, releases: list[object] | None = None) -> None:
        self._certificate = certificates[0]
        self._chain = tuple(certificates[1:])
        self._key = key
        self._releases = releases or []
        self._condition = threading.Condition()
        self._in_flight = 0
        self._closed = False

    @property
    def certificate(self) -> x509.Certificate:
        """The certificate itself."""
        return self._certificate

    @property
    def der(self) -> bytes:
        """The certificate, DER-encoded."""
        return self._certificate.public_bytes(Encoding.DER)

    @property
    def chain(self) -> tuple[x509.Certificate, ...]:
        """The other certificates its source gave with it - a PKCS#12 file's or PEM file's after the
        certificate itself, in file order; none from a store."""
        return self._chain

    @property
    def has_private_key(self) -> bool:
        """Whether it came with its private key."""
        return self._key is not None

    @property
    def key_location(self) -> str | None:
        """Where its private key is, as messages name it; ``None`` without one."""
        return self._key.description if self._key is not None else None

    def public_key(self) -> _keys.PublicKey:
        """The certificate's public key."""
        key = self._certificate.public_key()
        if not isinstance(key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            raise UnsupportedCertificateError("The certificate's key isn't RSA or ECDSA.")
        return key

    def sign(self, data: Buffer, algorithm: HashChoice, padding: AsymmetricPadding | None = None) -> bytes:
        """Signs ``data`` - or, with ``Prehashed(algorithm)``, the digest ``data`` is - with the
        private key: an RSA key with ``padding`` - ``padding.PKCS1v15()`` or ``padding.PSS(...)``
        (MGF1 over the same hash) - an ECDSA key with ``padding`` ``None``, giving a DER signature,
        as ``cryptography``'s own keys do.

        :raises NoPrivateKeyError: it came without one
        :raises UnsupportedCertificateError: the key's source can't sign this way
        :raises ObjectClosedError: it has been closed
        """
        with self._use() as key:
            return key.sign(data, algorithm, padding, self.public_key())

    def decrypt(self, ciphertext: Buffer, padding: AsymmetricPadding) -> bytearray:
        """Decrypts ``ciphertext`` with the RSA private key: ``padding.PKCS1v15()`` or
        ``padding.OAEP(...)``. A new buffer the caller wipes once used.

        :raises NoPrivateKeyError: it came without one
        :raises UnsupportedCertificateError: not an RSA key, or a source that can't decrypt this way
        :raises ObjectClosedError: it has been closed
        """
        with self._use() as key:
            return key.decrypt(ciphertext, padding, self.public_key())

    def create_ssl_context(self, purpose: ssl.Purpose) -> ssl.SSLContext:
        """A new ``ssl.SSLContext`` from ``ssl.create_default_context(purpose)``:

        * with the private key, presenting this certificate and its chain -
          ``ssl.Purpose.CLIENT_AUTH`` for a server's context, ``ssl.Purpose.SERVER_AUTH`` for a
          client's that authenticates with it;
        * without it (``RequirePrivateKey`` false), trusting this certificate and its chain alone, in
          place of the system's roots - for a client that pins its server's CA, say.

        The context holds its own copy of the key, in OpenSSL, from then on; it outlives :meth:`close`.

        :raises NativeProviderRequiredError: the key is a Windows or macOS store's
        :raises UnsupportedCertificateError: an OpenSSL provider this Python can't reach
        :raises ObjectClosedError: it has been closed
        """
        pem = b"".join(certificate.public_bytes(Encoding.PEM) for certificate in (self._certificate, *self._chain))
        if self._key is None:
            with self._condition:
                if self._closed:
                    raise ObjectClosedError("The certificate has been closed.")
            return ssl.create_default_context(purpose, cadata=pem.decode("ascii"))
        with self._use() as key:
            context = ssl.create_default_context(purpose)
            with _private_files.private_directory() as directory:
                chain_file = directory.write("chain.pem", pem)
                key.load_tls(context, directory, chain_file)
            return context

    @contextmanager
    def _use(self) -> Iterator[_KeySource]:
        with self._condition:
            if self._closed:
                raise ObjectClosedError("The certificate has been closed.")
            if self._key is None:
                raise NoPrivateKeyError("The certificate came without its private key.")
            self._in_flight += 1
            key = self._key
        try:
            yield key
        finally:
            with self._condition:
                self._in_flight -= 1
                self._condition.notify_all()

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` has been called."""
        return self._closed

    def close(self) -> None:
        """Waits for uses of the key in flight, then wipes a key file's key and releases a store's
        handles. Safe to call more than once."""
        with self._condition:
            if self._closed:
                return
            self._closed = True
            while self._in_flight:
                self._condition.wait()
        if self._key is not None:
            self._key.close()
        for release in self._releases:
            close = getattr(release, "close", None)
            if close is not None:
                close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, kind: type[BaseException] | None, error: BaseException | None, traceback: TracebackType | None) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"LoadedCertificate(subject={describe(self._certificate.subject)!r}, has_private_key={self.has_private_key})"
