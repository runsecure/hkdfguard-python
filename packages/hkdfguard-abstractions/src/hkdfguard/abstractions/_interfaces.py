"""The interfaces every HkdfGuard component is written against."""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Buffer
from dataclasses import dataclass
from types import TracebackType
from typing import NamedTuple, Self

from hkdfguard.abstractions._buffers import WritableBuffer
from hkdfguard.abstractions._rules import RefreshFailurePolicy
from hkdfguard.abstractions._wrapped_key_file import WrappedKeyFile


class _Closable(ABC):
    """Something that owns resources: close it, or use it in a ``with`` block."""

    @abstractmethod
    def close(self) -> None:
        """Releases what this object holds. Safe to call more than once."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class KeyTrackingValue:
    """An encrypted value together with the key ring version it was encrypted under - what an
    :class:`EncryptedFormatProvider` formats into, and parses back out of, the stored string."""

    key_version: int
    value: bytes


class VersionedKey(NamedTuple):
    """A key ring version together with its key - what :meth:`KeyRing.get_current` returns."""

    version: int
    key: DataEncryptionKey


class KeyWrapper(ABC):
    """Protects (:meth:`wrap`) and reveals (:meth:`unwrap`) an encryption key against a single,
    implicitly identified KEK - a native KMS-backed key identified by service name, or a remote
    KMS/HSM key. unwrap takes the wrapped payload on every call, so one instance can reveal any
    number of wrapped keys sharing the KEK. Calls block until the KEK answers."""

    @abstractmethod
    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        """Protects an encryption key, writing the wrapped key to ``result``.

        :returns: the number of bytes written
        """

    @abstractmethod
    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        """Reveals a previously wrapped key into ``result``. Must write the complete key and report
        its exact length - consumers reject any other count - must fail (never reveal
        unauthenticated bytes) when ``wrapped`` was tampered with, and should zero ``result`` on
        failure.

        :returns: the number of bytes written
        """

    @abstractmethod
    def generate_and_wrap(self, result: WritableBuffer) -> int:
        """Generates a fresh key and immediately wraps it under this instance's KEK - the plaintext
        key never crosses this call.

        :returns: the number of bytes of wrapped key written to ``result``
        """

    def read_key_file(self, path: str | os.PathLike[str], *, verify_permissions: bool = True,
                      logger: logging.Logger | None = None) -> bytearray:
        """Reads a key file holding a key this instance wrapped, returning its bytes still wrapped -
        ready for :meth:`unwrap`. KeyRingBuilder reads every key file through its key wrapper, so a
        wrapper backed by a native KMS can read through that KMS's own checks (the native library
        refuses a file another account could have replaced, or one holding what looks like an
        unwrapped key). The default reads it with ordinary file I/O (:meth:`WrappedKeyFile.read`),
        applying the POSIX permission rule unless ``verify_permissions`` is off, and logging to
        ``logger`` where there is no such rule; a wrapper whose own checks can't be turned off ignores
        both.

        :returns: the wrapped key the file holds; the caller owns it
        :raises FileNotFoundError: the file, or a folder in its path, does not exist
        :raises PermissionError: this account may not read the file, or the key wrapper doesn't trust
            where it lives
        :raises InvalidKeyFileError: the file isn't a wrapped key - empty, the wrong size, or not a
            valid payload (an ``OSError``)
        :raises OSError: the file can't be read for another reason
        """
        return WrappedKeyFile.read(path, verify_permissions=verify_permissions, logger=logger)


class CryptoProvider(_Closable):
    """Owns one revealed DEK - how it is revealed, refreshed and eventually zeroed - and performs
    the AEAD encrypt/decrypt with it.

    **Implementations must zero** ``plaintext`` **in every encrypt**, before returning and on every
    failure path - including when the key is unavailable and the call fails before any encryption
    happens. :class:`DataEncryptionKey` promises its callers exactly this. Decrypt never modifies
    its ciphertext.
    """

    @abstractmethod
    def encrypt(self, plaintext: WritableBuffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        """Encrypts ``plaintext`` (zeroed before this returns or raises), bound to ``aad``.

        :param result: receives the encrypted data; at least :meth:`get_encrypted_allocation_length` bytes
        :returns: the number of bytes written to ``result``
        """

    @abstractmethod
    def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        """Decrypts and authenticates ``ciphertext`` encrypted with ``aad``.

        :returns: the number of bytes written to ``result``
        """

    @abstractmethod
    def get_encrypted_allocation_length(self, length: int) -> int:
        """The buffer length encrypt needs for a plaintext of ``length`` bytes."""

    @abstractmethod
    def get_decrypted_allocation_length(self, length: int) -> int:
        """The buffer length decrypt needs for a ciphertext of ``length`` bytes; never negative."""


class CryptoProviderFactory(ABC):
    """Creates :class:`CryptoProvider` instances for a key ring. Every provider refreshes its revealed
    key every ``expiry_seconds``; ``max_refresh_failures`` is the refresh-failure policy - after that
    many consecutive failed refreshes the provider fails closed (zeroes its key and refuses every
    operation until a refresh succeeds), while ``None`` keeps serving on the last good key (fail
    open). Invalid arguments raise ``ValueError`` before any key wrapper call."""

    @abstractmethod
    def create(self, wrapper: KeyWrapper, wrapped: bytearray, expiry_seconds: int,
               max_refresh_failures: int | None = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES) -> CryptoProvider:
        """A provider revealing ``wrapped`` (e.g. a key file's bytes) through ``wrapper``. The
        provider owns ``wrapped`` from here on and zeroes it when closed."""

    @abstractmethod
    def create_ephemeral(self, wrapper: KeyWrapper, expiry_seconds: int,
                         max_refresh_failures: int | None = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES) -> CryptoProvider:
        """A provider around a fresh DEK that ``wrapper`` generates and wraps, then reveals."""


class DataEncryptionKey(ABC):
    """One data encryption key (DEK): AEAD-encrypts and decrypts byte payloads under it.

    **Encrypt consumes its plaintext.** The ``plaintext`` buffer is zeroed before encrypt returns,
    and also when it raises, so a secret handed in is never left behind in the caller's buffer.
    Decrypt never modifies its ciphertext.
    """

    @abstractmethod
    def encrypt(self, plaintext: WritableBuffer, *, aad: Buffer = b"") -> bytes:
        """Encrypts ``plaintext`` (zeroed before this returns or raises), bound to ``aad``.

        :returns: the ciphertext, ready to be stored
        """

    @abstractmethod
    def decrypt(self, ciphertext: Buffer, result: WritableBuffer, *, aad: Buffer = b"") -> int:
        """Decrypts and authenticates ``ciphertext``, encrypted with the same ``aad``, into
        ``result``, which the caller owns and should zero once done.

        :returns: the number of bytes written to ``result``
        """


class KeyRing(ABC):
    """Data encryption keys tracked by version, one of which is current. Anything that encrypts asks
    for the current key on every operation, so it follows rotation; anything that decrypts asks for
    the exact version the value was encrypted under, so older values still decrypt."""

    @property
    @abstractmethod
    def current_version(self) -> int:
        """The version new values are encrypted under - the highest registered.

        :raises RuntimeError: no key has been registered yet
        """

    @abstractmethod
    def get_current(self) -> VersionedKey:
        """The current version together with its key, read atomically.

        :raises RuntimeError: no key has been registered yet
        """

    @abstractmethod
    def get(self, version: int) -> DataEncryptionKey:
        """The key registered for ``version``.

        :raises KeyNotFoundError: no key is registered for this version
        """

    @abstractmethod
    def find(self, version: int) -> DataEncryptionKey | None:
        """The key registered for ``version``, or ``None``."""


class EncryptedFormatProvider(ABC):
    """Formats an encrypted value and its key version into the stored string, and parses it back."""

    @abstractmethod
    def format(self, value: KeyTrackingValue) -> str:
        """``value`` in its stored form."""

    @abstractmethod
    def parse(self, encrypted: str) -> KeyTrackingValue:
        """:raises EncryptedFormatError: ``encrypted`` is malformed"""

    @abstractmethod
    def get_max_decrypted_length(self, encrypted: str) -> int:
        """An upper bound on the decrypted plaintext's UTF-8 length, from the payload's length alone,
        without decoding it - always safe to size a result buffer to.

        :raises EncryptedFormatError: ``encrypted`` is malformed
        """


class DataProtector(ABC):
    """A named, string-level protector: its name is the Additional Authenticated Data for every
    encrypt/decrypt, binding a protected value to the purpose it was protected for. Keys come from a
    :class:`KeyRing` on every call."""

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypts ``plaintext`` and formats the result. The ``bytearray`` this call encodes it into is
        zeroed, but ``plaintext`` itself and the temporary ``bytes`` CPython makes while encoding it are
        immutable and are not. Callers who need the secret erased should hold it in a buffer instead."""

    @abstractmethod
    def decrypt(self, encrypted: str, result: WritableBuffer) -> int:
        """Parses and decrypts ``encrypted``, writing the plaintext's UTF-8 bytes to ``result`` -
        never materializing it as a ``str``.

        :returns: the number of bytes written
        """

    @abstractmethod
    def decrypt_to_str(self, encrypted: str) -> str:
        """Parses and decrypts ``encrypted`` into a ``str``. A ``str`` can't be zeroed; prefer
        :meth:`decrypt` for secrets that should not linger."""

    @abstractmethod
    def get_max_decrypted_length(self, encrypted: str) -> int:
        """An upper bound on the number of bytes :meth:`decrypt` will write."""


class PipelineDataProtector(_Closable):
    """A short-lived protector for a pipeline that must encrypt secrets before a durable KEK exists.
    Every encrypt/decrypt names the secret it protects - its full configuration key, e.g.
    ``"ConnectionStrings:Admin"`` - which is bound in as AAD via :class:`ProtectedConfigurationPurpose`,
    so once this key is wrapped and registered at :attr:`key_version`, reading that configuration key
    reveals the value, and a value copied under any other key fails authentication. It owns a single
    in-memory key for its whole lifetime and exposes it at the end so it can be wrapped."""

    @property
    @abstractmethod
    def key_version(self) -> int:
        """The version stamped on every value - the version this key will be registered under."""

    @abstractmethod
    def encrypt(self, plaintext: str, secret_identifier: str) -> str:
        """:raises ValueError: ``secret_identifier`` is empty or not valid UTF-16"""

    @abstractmethod
    def decrypt(self, encrypted: str, secret_identifier: str, result: WritableBuffer) -> int:
        """Decrypts into ``result`` as UTF-8, verifying ``encrypted`` was protected for ``secret_identifier``.

        :returns: the number of bytes written
        """

    @abstractmethod
    def decrypt_to_str(self, encrypted: str, secret_identifier: str) -> str:
        """:meth:`decrypt` into a ``str``, which can't be zeroed."""

    @abstractmethod
    def get_max_decrypted_length(self, encrypted: str) -> int:
        """An upper bound on the number of bytes :meth:`decrypt` will write."""

    @abstractmethod
    def get_key_as_base64(self) -> memoryview:
        """The key, base64-encoded as ASCII, for handing to the native platform's wrap process: a
        read-only view of a buffer the protector zeroes on close. Pass it on standard input
        (``--dek-stdin``), never as a command-line argument or environment variable."""


class ProtectedReadOnlyCache(ABC):
    """Read surface of a concurrent name -> encrypted-value cache. Names match ignoring ASCII case
    only ("Item" and "ITEM" are one name; "café" and "CAFÉ" are two), and each value is bound to its
    name, so it can only be revealed under the name it was stored for. A missing name reads as 0
    bytes rather than raising."""

    @abstractmethod
    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """Decrypts the value stored under ``name`` into ``result``.

        :returns: the number of bytes written, or 0 if nothing is stored under ``name``
        """

    @abstractmethod
    def decrypt_to_str(self, name: str) -> str | None:
        """The value stored under ``name``, decoded as UTF-8; ``None`` if nothing is stored. A
        ``str`` can't be zeroed; prefer :meth:`decrypt` for secrets that should not linger."""

    @abstractmethod
    def find_max_decrypted_length(self, name: str) -> int | None:
        """An upper bound on the bytes :meth:`decrypt` will write for ``name``; ``None`` if nothing
        is stored under it."""


class ProtectedCache(ProtectedReadOnlyCache):
    """Read/write surface of a concurrent name -> encrypted-value cache. Nothing here holds
    plaintext beyond a single call - only the encrypted bytes are retained."""

    @abstractmethod
    def add(self, name: str, plaintext: WritableBuffer | str) -> None:
        """Encrypts ``plaintext`` and stores it under ``name``. A buffer is zeroed as a side effect;
        a ``str`` can't be, and neither can the temporary ``bytes`` made while encoding it; the
        ``bytearray`` it is encoded into is.

        :raises ValueError: a value is already stored under this name
        """

    @abstractmethod
    def add_or_update(self, name: str, plaintext: WritableBuffer | str) -> None:
        """Encrypts ``plaintext`` and stores it under ``name``, replacing any value stored there."""
