"""The interfaces every HkdfGuard component is written against."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from collections.abc import Buffer, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import NamedTuple, Self

from hkdfguard.abstractions._buffers import WritableBuffer
from hkdfguard.abstractions._rules import RefreshFailurePolicy
from hkdfguard.abstractions._streams import AsyncBinaryDestination, BinaryDestination


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

    @abstractmethod
    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        """Reads a key file holding a key this instance wrapped, returning its bytes still wrapped -
        ready for :meth:`unwrap`. KeyRingBuilder reads every key file through its key wrapper.

        Whoever can replace a key file chooses the DEK the application encrypts new data under, so
        an implementation must refuse a file that another account could have written or replaced -
        the file, and every folder on its path - and should refuse one that holds what looks like an
        unwrapped key. There is deliberately no default: a key wrapper decides how it trusts a file.
        The native key wrapper reads through the native library's ``hkdfguard_open_file``, which
        makes these checks the way only the platform can.

        :returns: the wrapped key the file holds; the caller owns it
        :raises FileNotFoundError: the file, or a folder in its path, does not exist
        :raises PermissionError: this account may not read the file, or the key wrapper doesn't trust
            where it lives
        :raises InvalidKeyFileError: the file isn't a wrapped key - empty, the wrong size, or not a
            valid payload (an ``OSError``)
        :raises OSError: the file can't be read for another reason
        """


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
    def encrypt(self, plaintext: str | Buffer, secret_identifier: str) -> str:
        """Encrypts ``plaintext`` bound to ``secret_identifier`` and formats the result.

        :param plaintext: the secret to protect: a ``str``, or its UTF-8 bytes in a buffer
            (``bytes``, ``bytearray``, ``memoryview``) - checked to be well-formed UTF-8 where it
            lies, never decoded into a ``str``, so a secret that must not become one can be
            encrypted. Read, never written: the caller owns it, and should zero a writable buffer
            once done (the copy encrypted from inside this call is zeroed). A ``str`` can't be
            zeroed, nor can the temporary ``bytes`` CPython makes while encoding it; an unpaired
            surrogate in it becomes U+FFFD, as everywhere else.
        :param secret_identifier: the configuration key the value will be stored under (full
            path, e.g. ``"ConnectionStrings:Admin"``); :meth:`decrypt` must name the same secret
        :returns: the formatted, encrypted value
        :raises TypeError: ``plaintext`` is neither a ``str`` nor a buffer
        :raises ValueError: ``secret_identifier`` is empty or not valid UTF-16, or a buffer
            ``plaintext`` isn't well-formed UTF-8
        """

    @abstractmethod
    def decrypt(self, encrypted: str, secret_identifier: str, result: WritableBuffer) -> int:
        """Decrypts into ``result`` as UTF-8, verifying ``encrypted`` was protected for ``secret_identifier``.

        :returns: the number of bytes written
        """

    @abstractmethod
    def get_max_decrypted_length(self, encrypted: str) -> int:
        """An upper bound on the number of bytes :meth:`decrypt` will write."""

    @abstractmethod
    def get_key_as_base64(self) -> memoryview:
        """The key, base64-encoded as ASCII, for handing to the native platform's wrap process: a
        read-only view of a buffer the protector zeroes on close. Pass it on standard input
        (``--dek-stdin``), never as a command-line argument or environment variable."""

    @abstractmethod
    def write_dek(self, destination: BinaryDestination) -> None:
        """Writes the key to ``destination`` exactly as the wrap tool's ``--dek-stdin`` reads it -
        its base64 form as ASCII, with no line ending - and flushes it. For the wrap tool's standard
        input, local or remote: the stdin of ``hkdfguard wrap ... --dek-stdin``, or of
        ``ssh -T host sudo -n hkdfguard wrap ... --dek-stdin``, from :class:`subprocess.Popen`. The
        bytes are written from a ``bytearray`` zeroed once the write and flush complete, or fail; no
        ``str`` is ever made of them. ``destination`` is left open: close it afterwards, so the tool
        sees the end of its input. Blocks until the write and flush return.

        :param destination: where to write the key: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises ObjectClosedError: the protector has been closed; nothing is written
        """

    @abstractmethod
    async def write_dek_async(self, destination: AsyncBinaryDestination) -> None:
        """:meth:`write_dek` to an asyncio stream - the stdin of
        :func:`asyncio.create_subprocess_exec` - drained rather than flushed, without blocking the
        event loop (.NET's ``WriteDekAsync``). Cancelling the awaiting task stops the drain; the
        buffer is zeroed all the same.

        :param destination: where to write the key: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises ObjectClosedError: the protector has been closed; nothing is written
        """


class SecretPipelineWriter(_Closable):
    """The end of a provisioning pipeline that delivers secrets from a secret store as one encrypted
    file per secret - the folder layout ``FilePerSecretCache`` reads at runtime - before a durable KEK
    exists. An implementation is given the secrets to pull and a :class:`PipelineDataProtector` when
    it is created; :meth:`pull_secrets` reads each secret and encrypts it at once, bound to its file
    name, keeping only the encrypted value; :meth:`write_protected_secret_files` then writes one
    file per secret, or :meth:`write_json_secrets` one JSON file of them all - each also to a
    process's standard input, as a tar archive of the files or as the JSON. No key ring is involved: the protector's key is the only one, and it is handed
    to the native platform's wrap process once the files are written.

    The protector belongs to the caller and is never closed by the writer. Closing the writer (or
    leaving its ``with`` block) releases its connection to the secret store.
    """

    @property
    @abstractmethod
    def protected_secrets(self) -> Mapping[str, str]:
        """Every secret pulled, by file name: its value encrypted by the protector and formatted, as
        its file will hold it. Empty until :meth:`pull_secrets` (or :meth:`pull_secrets_async`)
        completes. A read-only view, which a later pull changes."""

    @abstractmethod
    def pull_secrets(self) -> None:
        """Reads every secret the writer was created with and encrypts each value, keeping it in
        :attr:`protected_secrets` - replacing whatever an earlier pull kept. Blocks the calling
        thread until the store has answered every read.

        :raises KeyNotFoundError: a secret has no value; every other secret is kept
        """

    async def pull_secrets_async(self) -> None:
        """:meth:`pull_secrets` without blocking the event loop. The default runs pull_secrets in a
        worker thread (:func:`asyncio.to_thread`); a writer with an asyncio-capable client overrides
        it. Cancel it by cancelling the task awaiting it: nothing is kept then.

        :raises KeyNotFoundError: a secret has no value; every other secret is kept
        """
        await asyncio.to_thread(self.pull_secrets)

    @abstractmethod
    def write_protected_secret_files(self, folder_path: str | os.PathLike[str]) -> None:
        """Writes every secret in :attr:`protected_secrets` as a file in ``folder_path``, creating the
        folder if it doesn't exist: the file named for it, holding its encrypted, formatted value as
        UTF-8.

        :param folder_path: the folder to write to, absolute or relative to the working directory
        :raises TypeError: ``folder_path`` is ``None``
        :raises ValueError: ``folder_path`` is empty
        :raises RuntimeError: no pull has completed
        """

    @abstractmethod
    def write_json_secrets(self, file_path: str | os.PathLike[str]) -> None:
        """Writes every secret in :attr:`protected_secrets` to one JSON file at ``file_path``,
        creating its folder if it doesn't exist: a single object with a member per secret, its file
        name mapped to its encrypted, formatted value. A file already there is replaced.

        :param file_path: the file to write, absolute or relative to the working directory
        :raises TypeError: ``file_path`` is ``None``
        :raises ValueError: ``file_path`` is empty
        :raises RuntimeError: no pull has completed
        """

    @abstractmethod
    def write_protected_secret_files_to_stream(self, destination: BinaryDestination) -> None:
        """Writes every secret in :attr:`protected_secrets` to ``destination`` as a tar archive of
        the files :meth:`write_protected_secret_files` would write - for a remote tar to unpack, e.g.
        the stdin of ``ssh -T host sudo -n tar -x --no-same-owner -f - -C folder``. ``destination`` is
        flushed and left open: close it afterwards, so tar sees the end of its input.

        :param destination: where to write the archive: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """

    @abstractmethod
    async def write_protected_secret_files_async(self, destination: AsyncBinaryDestination) -> None:
        """:meth:`write_protected_secret_files_to_stream` to an asyncio stream, drained rather than
        flushed, without blocking the event loop (.NET's ``WriteProtectedSecretFilesAsync``).
        Cancelling the awaiting task stops the drain.

        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """

    @abstractmethod
    def write_json_secrets_to_stream(self, destination: BinaryDestination) -> None:
        """Writes every secret in :attr:`protected_secrets` to ``destination`` as the JSON object
        :meth:`write_json_secrets` would write - for a remote command to store, e.g. the stdin of
        ``ssh -T host sudo -n tee /etc/app/secrets.json``. ``destination`` is flushed and left open:
        close it afterwards, so the remote command sees the end of its input.

        :param destination: where to write the JSON: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """

    @abstractmethod
    async def write_json_secrets_async(self, destination: AsyncBinaryDestination) -> None:
        """:meth:`write_json_secrets_to_stream` to an asyncio stream, drained rather than flushed,
        without blocking the event loop (.NET's ``WriteJsonSecretsAsync``). Cancelling the awaiting
        task stops the drain.

        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """


class ProtectedReadOnlyCache(ABC):
    """Read surface of a concurrent name -> encrypted-value cache. Names match ignoring ASCII case
    only ("Item" and "ITEM" are one name; "café" and "CAFÉ" are two), and each value is bound to its
    name, so it can only be revealed under the name it was stored for. A missing name reads as 0
    bytes rather than raising.

    A cache that may have to fetch a value over the network on a miss (a remote secret store) does
    that I/O without blocking the event loop in :meth:`decrypt_async` and
    :meth:`find_max_decrypted_length_async`, where the synchronous members block the calling thread
    until it completes. Their default implementations call the synchronous members, which is all an
    in-memory cache needs. Failures raise from the ``await``; cancelling the awaiting task stops it
    waiting for a fetch. Zero ``result`` once the value is used, as with any buffer holding plaintext.
    """

    @abstractmethod
    def decrypt(self, name: str, result: WritableBuffer) -> int:
        """Decrypts the value stored under ``name`` into ``result``.

        :returns: the number of bytes written, or 0 if nothing is stored under ``name``
        """

    @abstractmethod
    def find_max_decrypted_length(self, name: str) -> int | None:
        """An upper bound on the bytes :meth:`decrypt` will write for ``name``; ``None`` if nothing
        is stored under it."""

    async def decrypt_async(self, name: str, result: WritableBuffer) -> int:
        """Decrypts the value stored under ``name`` into ``result``, as :meth:`decrypt` does,
        fetching it without blocking the event loop first if the cache must. The default calls
        :meth:`decrypt`.

        :returns: the number of bytes written, or 0 if nothing is stored under ``name``
        """
        return self.decrypt(name, result)

    async def find_max_decrypted_length_async(self, name: str) -> int | None:
        """:meth:`find_max_decrypted_length`, fetching the value without blocking the event loop
        first if the cache must. The default calls :meth:`find_max_decrypted_length`.

        :returns: the upper bound, or ``None`` if nothing is stored under ``name``
        """
        return self.find_max_decrypted_length(name)


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
