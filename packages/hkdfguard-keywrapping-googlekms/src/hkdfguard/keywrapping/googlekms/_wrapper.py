"""The key wrapper over one symmetric Google Cloud KMS key."""

from __future__ import annotations

import os
import re
from collections.abc import Buffer, Callable
from typing import Any, Final, Protocol

from google.api_core.exceptions import GoogleAPICallError
from google.cloud.kms_v1 import DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse
from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, WrappedKeyLimits, WritableBuffer
from hkdfguard.securefile import KeyFileTrust, TrustedKeyFile


class CloudKmsClient(Protocol):
    """The two calls :class:`GoogleKmsKeyWrapper` makes on a Cloud KMS client, each given its request
    as ``request=``: a ``google.cloud.kms.KeyManagementServiceClient`` is one, over gRPC or REST."""

    def encrypt(self, *args: Any, **kwargs: Any) -> EncryptResponse: ...

    def decrypt(self, *args: Any, **kwargs: Any) -> DecryptResponse: ...


# A key's resource name, every part present and none a path of its own: a key version's name, which
# Decrypt doesn't take, doesn't match.
_KEY_NAME: Final = re.compile(r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+")

# Prefixed to every wrapped DEK's additional authenticated data. Changing it makes every existing key
# file unreadable.
_AAD_LABEL: Final = b"HkdfGuard-GoogleKms-wrap-v1\0"


def _crc32c_table() -> tuple[int, ...]:
    table = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC32C_TABLE: Final = _crc32c_table()


def crc32c(data: Buffer) -> int:
    """CRC32C (Castagnoli), as Cloud KMS checksums requests and responses. Computed here: the standard
    library has none, and what is checksummed - a key, the context, a wrapped key - is small."""
    crc = 0xFFFFFFFF
    with memoryview(data) as raw, raw.cast("B") as source:
        for byte in source:
            crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


class GoogleKmsKeyWrapper(KeyWrapper):
    """Protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric Google Cloud KMS key (purpose
    ENCRYPT_DECRYPT). The KEK never enters this process; every call is a network round trip, authorized
    by the caller's Google credential through IAM and recorded in Cloud Audit Logs.

    The key is pinned: Decrypt is always called against the key given at construction, and Cloud KMS
    refuses a ciphertext made under any other key, so a substituted key file wrapped under another key
    this principal may use is never revealed. A ciphertext names the key version that made it, so Cloud
    KMS's own key rotation is transparent here - each key file keeps decrypting under its version, which
    must stay enabled while the file is in use. Wrapped DEKs are byte for byte those of the .NET
    GoogleKmsKeyWrapper and the Java GoogleKmsKeyWrapperImpl, so a key file made by any of them is read
    by the others, given the same key and context.

    Every wrapped DEK is bound, as additional authenticated data, to a fixed HkdfGuard label and the
    optional context: Decrypt fails unless both are presented again exactly. The label stops a ciphertext
    the same key made for some other purpose being accepted as a DEK; the context stops a key file made
    for one application being used by another that shares the key. Neither is secret.

    Symmetric encryption needs no secret beyond permission to use the key, so anyone allowed
    ``cloudkms.cryptoKeyVersions.useToEncrypt`` can make a key file this wrapper accepts. Give the
    application decrypt only (``roles/cloudkms.cryptoKeyDecrypter``) and the pipeline that creates key
    files encrypt only; and key files are read only from where an untrusted account can't have written
    or replaced them (see :meth:`read_key_file` and :class:`KeyFileTrust`).

    Every request and response carries a CRC32C checksum, as Google recommends, so data corrupted in
    transit is refused rather than stored or used. Cloud KMS has no "generate data key", so
    :meth:`generate_and_wrap` generates the DEK in this process and wraps it.

    The caller's ``result`` buffer is zeroed whenever an unwrap fails. Unlike the .NET and Java ports,
    this one can't zero its copy of a key it wraps: the client's request messages take only an immutable
    ``bytes``. So the key :meth:`wrap` is given is copied once into a ``bytes``, and
    :meth:`generate_and_wrap` hands over the ``bytes`` ``os.urandom`` returns; each lives until
    collected. So does the revealed key, which the client decodes from the Decrypt response into a
    ``bytes`` - copied into ``result``, but no one can zero it. Process hardening
    (``hkdfguard-keywrapping-v1``'s ``NativeProcessHardening``) is what keeps such copies out of reach of
    a debugger or a crash dump.

    The client is the application's: it creates it (credentials, transport, retries), keeps it for as
    long as anything uses this wrapper - a key ring's background refresh included - and closes it. This
    wrapper never closes it. Every call blocks until Cloud KMS answers, the client's own retries
    included. Argument errors raise ``ValueError`` or ``TypeError``; a Cloud KMS refusal, an unreachable
    service or a credential that can't get a token raises :class:`CryptographicError` naming the
    operation, the key, and the gRPC status (``INVALID_ARGUMENT: Decryption failed.``), with the client's
    exception as its ``__cause__``.
    """

    GENERATED_KEY_LENGTH: Final = 32
    """The length of the DEK :meth:`generate_and_wrap` generates: 32 bytes (AES-256)."""

    MAX_PLAINTEXT_LENGTH: Final = 64 * 1024
    """The largest plaintext Cloud KMS's Encrypt accepts, in bytes."""

    MAX_CONTEXT_LENGTH: Final = 64 * 1024 - 32
    """The longest context, in UTF-8 bytes: what Cloud KMS's additional authenticated data allows, less
    the HkdfGuard label."""

    def __init__(self, client: CloudKmsClient, key_name: str, context: str | None = None, key_file_trust: KeyFileTrust | None = None) -> None:
        """A wrapper over one key. No call is made until it is used.

        :param client: the Cloud KMS client every call is made through, e.g.
            ``google.cloud.kms.KeyManagementServiceClient()``. Not closed by this wrapper; its owner
            (typically the application) closes it.
        :param key_name: the symmetric key that wraps every DEK, as its resource name:
            ``projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}``. Not a key
            version: Decrypt takes the key, and Encrypt uses its primary version.
        :param context: bound into every wrapped DEK and required again to reveal it; ``None`` or empty
            binds none. Not secret.
        :param key_file_trust: who besides the operating system's administrators may have written a key
            file :meth:`read_key_file` reads; ``None`` trusts administrators only
            (:attr:`KeyFileTrust.ADMINISTRATORS_ONLY`)
        :raises TypeError: ``client`` or ``key_name`` is ``None``, or an argument is of the wrong type
        :raises ValueError: ``key_name`` isn't a Cloud KMS key's resource name, or the context is over
            :attr:`MAX_CONTEXT_LENGTH` bytes or not well-formed text (a lone surrogate)
        """
        if client is None:
            raise TypeError("client must not be None.")
        if key_name is None:
            raise TypeError("key_name must not be None.")
        if not isinstance(key_name, str):
            raise TypeError("key_name must be a str.")
        if not _KEY_NAME.fullmatch(key_name):
            raise ValueError(f"'{key_name}' isn't a Cloud KMS key's resource name: "
                             "projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}, without a key version.")
        if key_file_trust is not None and not isinstance(key_file_trust, KeyFileTrust):
            raise TypeError("key_file_trust must be a KeyFileTrust.")

        self._client = client
        self._key_name = key_name
        self._aad = _AAD_LABEL + self._encode_context(context)
        self._aad_crc32c = crc32c(self._aad)
        self._key_file_trust = key_file_trust if key_file_trust is not None else KeyFileTrust.ADMINISTRATORS_ONLY

    @classmethod
    def _encode_context(cls, context: str | None) -> bytes:
        # Refuses a lone surrogate, which .NET would encode differently (as U+FFFD).
        if context is None:
            return b""
        if not isinstance(context, str):
            raise TypeError("context must be a str.")
        try:
            encoded = context.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("The context isn't well-formed text: it holds a lone surrogate.") from error
        if len(encoded) > cls.MAX_CONTEXT_LENGTH:
            raise ValueError(f"The context is {len(encoded)} bytes in UTF-8; at most {cls.MAX_CONTEXT_LENGTH} are allowed.")
        return encoded

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        """Protects a DEK with Cloud KMS's Encrypt, writing the ciphertext to ``result``.

        :param plaintext: the key, 1 to :attr:`MAX_PLAINTEXT_LENGTH` bytes; not modified - it is the
            caller's to zero (this wrapper's own copy can't be; see the class comment)
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``plaintext`` is empty or over :attr:`MAX_PLAINTEXT_LENGTH` bytes, or
            ``result`` is too small for the wrapped DEK
        :raises CryptographicError: Cloud KMS refused the request or could not be reached (the client's
            exception is the ``__cause__``), the request or response was corrupted in transit, it
            answered for a key other than this one, or the wrapped DEK is over
            :attr:`WrappedKeyLimits.MAX_BYTES`
        """
        with memoryview(plaintext) as raw, raw.cast("B") as source:
            if len(source) == 0 or len(source) > self.MAX_PLAINTEXT_LENGTH:
                raise ValueError(f"Cloud KMS wraps 1-{self.MAX_PLAINTEXT_LENGTH} bytes; got {len(source)}.")
            # The request takes only bytes: an immutable copy, which lives until collected (see the
            # class comment). Being immutable, it is also what the client resends if it retries.
            key = bytes(source)
        return self._wrap(key, result)

    def _wrap(self, key: bytes, result: WritableBuffer) -> int:
        request = EncryptRequest(name=self._key_name, plaintext=key, plaintext_crc32c=crc32c(key),
                                 additional_authenticated_data=self._aad, additional_authenticated_data_crc32c=self._aad_crc32c)
        response = self._call(lambda: self._client.encrypt(request=request), "wrap")

        # The version that made it must be one of this key's: a response for any other key would
        # produce a key file this wrapper can't read back.
        name = response.name
        prefix = f"{self._key_name}/cryptoKeyVersions/"
        if not isinstance(name, str) or not name.startswith(prefix) or not name[len(prefix):] or "/" in name[len(prefix):]:
            raise CryptographicError(f"Cloud KMS wrap for key '{self._key_name}' reported key version '{name}' instead.")

        if response.verified_plaintext_crc32c is not True or response.verified_additional_authenticated_data_crc32c is not True:
            raise CryptographicError(f"Cloud KMS wrap for key '{self._key_name}' didn't verify the request's checksums: it was corrupted in transit.")

        ciphertext = response.ciphertext
        if not ciphertext:
            raise CryptographicError(f"Cloud KMS wrap for key '{self._key_name}' returned no ciphertext.")
        if _checksum(response.ciphertext_crc32c) != crc32c(ciphertext):
            raise CryptographicError(f"Cloud KMS wrap for key '{self._key_name}' returned a ciphertext that doesn't match its checksum: it was "
                                     "corrupted in transit.")

        # A key file over the limit would be refused when read back, so refuse to produce one.
        if len(ciphertext) > WrappedKeyLimits.MAX_BYTES:
            raise CryptographicError(f"Cloud KMS wrap for key '{self._key_name}' returned {len(ciphertext)} bytes; a wrapped DEK is at most "
                                     f"{WrappedKeyLimits.MAX_BYTES}.")
        return self._copy_into(ciphertext, result, "The wrapped DEK")

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        """Reveals a DEK with Cloud KMS's Decrypt, the key pinned, into ``result``. On any failure
        ``result`` is zeroed.

        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the revealed key
        :raises CryptographicError: ``wrapped`` is empty or over :attr:`WrappedKeyLimits.MAX_BYTES`
            (refused without calling Cloud KMS), or Cloud KMS refused it - tampered with, wrapped under
            another key, or under a different context - or could not be reached (the client's exception
            is the ``__cause__``), or the response was corrupted in transit
        """
        try:
            with memoryview(wrapped) as raw, raw.cast("B") as source:
                # Refused locally: no ciphertext this wrapper produced is outside these bounds.
                if len(source) == 0 or len(source) > WrappedKeyLimits.MAX_BYTES:
                    raise CryptographicError(f"A wrapped DEK is 1-{WrappedKeyLimits.MAX_BYTES} bytes; got {len(source)}.")
                ciphertext = bytes(source)

            request = DecryptRequest(name=self._key_name, ciphertext=ciphertext, ciphertext_crc32c=crc32c(ciphertext),
                                     additional_authenticated_data=self._aad, additional_authenticated_data_crc32c=self._aad_crc32c)
            response = self._call(lambda: self._client.decrypt(request=request), "unwrap")

            # Immutable bytes from the client: copied into result, but it can't be zeroed (see the class comment).
            revealed = response.plaintext
            if not revealed:
                raise CryptographicError(f"Cloud KMS unwrap for key '{self._key_name}' returned no plaintext.")
            if _checksum(response.plaintext_crc32c) != crc32c(revealed):
                raise CryptographicError(f"Cloud KMS unwrap for key '{self._key_name}' returned a plaintext that doesn't match its checksum: it was "
                                         "corrupted in transit.")
            return self._copy_into(revealed, result, "The revealed key")
        except BaseException:
            # Whatever a failed call left in the DEK buffer is erased.
            ArrayUtility.zero_memory(result)
            raise

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        """Generates a fresh :attr:`GENERATED_KEY_LENGTH`-byte DEK in this process and wraps it - it is
        never returned.

        :param result: receives the wrapped key
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the wrapped DEK
        :raises CryptographicError: as :meth:`wrap`
        """
        # The bytes os.urandom returns go to the request as they are: the only copy, immutable (see the class comment).
        return self._wrap(os.urandom(self.GENERATED_KEY_LENGTH), result)

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        """Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than
        the operating system's administrators and the :class:`KeyFileTrust` given at construction could
        have written or replaced - the Python equivalent of the native library's checks
        (:class:`TrustedKeyFile`). On Windows the file must be on a local fixed drive, reached through
        real folders (no symbolic link, junction or substituted drive), and it and every folder above it
        must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and every
        directory above it must be owned by root or a trusted user and writable by nobody else (by its
        group only if that group is trusted), and only symbolic links a trusted user owns are followed.
        It is also refused if it is empty, over :attr:`WrappedKeyLimits.MAX_BYTES`, or looks like an
        unwrapped key. No Cloud KMS call is made.

        :returns: the file's contents, still wrapped; the caller owns them
        :raises FileNotFoundError: the file, or a folder in its path, doesn't exist
        :raises PermissionError: this account may not read the file, or it isn't somewhere only trusted
            principals can modify
        :raises InvalidKeyFileError: the file is empty, too long, or holds what looks like an unwrapped
            key (an ``OSError``)
        :raises OSError: the file can't be read, or another process has it open for writing
        :raises ValueError: the path is empty, or the :class:`KeyFileTrust` names a principal that can't be trusted
        :raises TypeError: the path is ``None``
        """
        return TrustedKeyFile.read(path, self._key_file_trust)

    def _call[T](self, call: Callable[[], T | None], operation: str) -> T:
        # Turns Cloud KMS failures - service refusals and transport failures (GoogleAPICallError, over
        # gRPC or REST) and client-side ones such as a credential that can't get a token or retries that
        # ran out of time (RetryError) - into the CryptographicError every KeyWrapper fails with, naming
        # the gRPC status. KeyboardInterrupt and the like are left as they are.
        try:
            response = call()
        except CryptographicError:
            raise
        except GoogleAPICallError as error:
            if error.grpc_status_code is not None:
                status = error.grpc_status_code.name
            elif error.code is not None:
                status = f"HTTP {error.code}"
            else:
                status = type(error).__name__
            raise CryptographicError(f"Cloud KMS {operation} failed for key '{self._key_name}': {status}: {error.message}") from error
        except Exception as error:
            raise CryptographicError(f"Cloud KMS {operation} failed for key '{self._key_name}': {error}") from error
        if response is None:
            raise CryptographicError(f"Cloud KMS {operation} for key '{self._key_name}' returned no response.")
        return response

    @staticmethod
    def _copy_into(data: bytes, result: WritableBuffer, what: str) -> int:
        with memoryview(result) as target_raw, target_raw.cast("B") as target:
            if len(data) > len(target):
                raise ValueError(f"{what} is {len(data)} bytes; result holds {len(target)}.")
            target[:len(data)] = data
            return len(data)


def _checksum(value: object) -> int | None:
    # The client gives an Int64Value checksum field as an int, or None when it is missing.
    return value if isinstance(value, int) else None
