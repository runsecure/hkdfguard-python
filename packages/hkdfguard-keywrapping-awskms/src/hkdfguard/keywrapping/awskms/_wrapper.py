"""The key wrapper over one symmetric AWS KMS key."""

from __future__ import annotations

import os
from collections.abc import Buffer, Callable, Mapping
from typing import Any, Final, Protocol

from botocore.exceptions import BotoCoreError, ClientError
from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, WrappedKeyLimits, WritableBuffer
from hkdfguard.securefile import KeyFileTrust, TrustedKeyFile


class KmsClient(Protocol):
    """The three calls :class:`AwsKmsKeyWrapper` makes on a KMS client, each with keyword arguments
    named as the KMS API names them, returning the response as a dict. A botocore client
    (``boto3.client("kms")``, or ``botocore.session.get_session().create_client("kms")``) is one; so is
    a typed ``mypy_boto3_kms.KMSClient``, for an application that uses those stubs."""

    def encrypt(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]: ...

    def decrypt(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]: ...

    def generate_data_key_without_plaintext(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]: ...


class AwsKmsKeyWrapper(KeyWrapper):
    """Protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric AWS KMS key, and generates
    fresh DEKs with GenerateDataKeyWithoutPlaintext - so on that path the plaintext DEK never leaves
    KMS. The KEK never enters this process; every call is a network round trip, authorized by the
    caller's IAM credentials and recorded in CloudTrail.

    The key is pinned on every Decrypt. A symmetric ciphertext blob names its own key and KMS would
    otherwise decrypt it under whichever key it names, so a substituted key file wrapped under any
    other key this principal may use would be revealed. With the key pinned KMS refuses it
    (IncorrectKeyException). Prefer a key ARN to an alias: Decrypt resolves an alias when it is called,
    so re-pointing the alias at a new key makes every DEK wrapped under the old one unreadable. KMS's
    own automatic key rotation keeps the key ARN and is transparent here.

    The encryption context, if any, is bound into every wrapped DEK as authenticated data: Decrypt
    fails unless it is presented again exactly, and key policies can require it
    (``kms:EncryptionContext:*``). It is logged in plaintext by CloudTrail, so it must not hold secrets.

    Key files are read only from where an untrusted account can't have written or replaced them (see
    :meth:`read_key_file` and :class:`KeyFileTrust`). Pinning the key stops a key file wrapped under
    another key; this stops one wrapped under this key by anyone who may call kms:Encrypt, which would
    otherwise choose the DEK new data is encrypted under.

    Plaintext key bytes this class owns are zeroed once used: its ``bytearray`` copy of the key sent to
    Encrypt, zeroed once the call has returned (botocore serializes the request inside the call), and
    the caller's ``result`` buffer whenever an unwrap fails. Two kinds of copy are beyond its reach and
    live until collected: botocore base64-encodes the key sent to Encrypt into the JSON request body,
    and decodes Decrypt's response from JSON base64 text into an immutable ``bytes`` - the
    ``Plaintext`` it returns, which this class copies into ``result`` but which, being immutable, no
    one can zero. Process hardening (``hkdfguard-keywrapping-v1``'s ``NativeProcessHardening``) is
    what keeps such copies out of reach of a debugger or a crash dump.

    The client is the application's: it creates it (credentials, region, retries), keeps it for as
    long as anything uses this wrapper - a key ring's background refresh included - and closes it.
    This wrapper never closes it. Every call blocks until KMS answers. Argument errors raise
    ``ValueError`` or ``TypeError``; a KMS refusal or an unreachable KMS raises
    :class:`CryptographicError` naming the operation, the key, and KMS's error code and HTTP status,
    with the botocore exception as its ``__cause__``.
    """

    GENERATED_KEY_LENGTH: Final = 32
    """The length of the DEK :meth:`generate_and_wrap` generates: 32 bytes (AES-256)."""

    MAX_PLAINTEXT_LENGTH: Final = 4096
    """The largest plaintext KMS's Encrypt accepts, in bytes."""

    def __init__(self, client: KmsClient, key_id: str, encryption_context: Mapping[str, str] | None = None,
                 key_file_trust: KeyFileTrust | None = None) -> None:
        """:param client: the KMS client every call is made through. Not closed by this wrapper; its
            owner (typically the application) closes it.
        :param key_id: the symmetric KMS key that wraps every DEK: a key ARN (preferred), key ID, alias
            name (``"alias/..."``) or alias ARN
        :param encryption_context: bound into every wrapped DEK and required again to reveal it. Copied
            at construction; ``None`` or empty binds none.
        :param key_file_trust: who besides the operating system's administrators may have written a key
            file :meth:`read_key_file` reads; ``None`` trusts administrators only
            (:attr:`KeyFileTrust.ADMINISTRATORS_ONLY`)
        :raises TypeError: ``client`` or ``key_id`` is ``None``, ``key_id`` is not a ``str``, the context
            is not a mapping of ``str`` to ``str``, or ``key_file_trust`` is not a :class:`KeyFileTrust`
        :raises ValueError: ``key_id`` is empty or whitespace, or the context holds an empty key
        """
        if client is None:
            raise TypeError("client must not be None.")
        if key_id is None:
            raise TypeError("key_id must not be None.")
        if not isinstance(key_id, str):
            raise TypeError("key_id must be a str.")
        if not key_id.strip():
            raise ValueError("key_id must not be empty or whitespace.")
        if key_file_trust is not None and not isinstance(key_file_trust, KeyFileTrust):
            raise TypeError("key_file_trust must be a KeyFileTrust.")

        self._client = client
        self._key_id = key_id
        self._key_file_trust = key_file_trust if key_file_trust is not None else KeyFileTrust.ADMINISTRATORS_ONLY
        self._encryption_context = self._copy_context(encryption_context)

    @staticmethod
    def _copy_context(encryption_context: Mapping[str, str] | None) -> dict[str, str] | None:
        if encryption_context is None:
            return None
        if not isinstance(encryption_context, Mapping):
            raise TypeError("encryption_context must be a mapping of str to str.")
        if not encryption_context:
            return None

        copy: dict[str, str] = {}
        for key, value in encryption_context.items():
            if key is None or key == "":
                raise ValueError("Encryption context keys must not be empty.")
            if not isinstance(key, str):
                raise TypeError(f"Encryption context keys must be str; {key!r} is not.")
            if value is None:
                raise TypeError(f'encryption_context["{key}"] must not be None.')
            if not isinstance(value, str):
                raise TypeError(f'encryption_context["{key}"] must be a str.')
            copy[key] = value
        # Sorted by key (str order is ordinal), so every request lists it the same way.
        return dict(sorted(copy.items()))

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        """Protects a DEK with KMS's Encrypt, writing the ciphertext blob to ``result``.

        :param plaintext: the key, 1 to :attr:`MAX_PLAINTEXT_LENGTH` bytes; not modified - it is the
            caller's to zero
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``plaintext`` is empty or over :attr:`MAX_PLAINTEXT_LENGTH` bytes, or
            ``result`` is too small for the wrapped DEK
        :raises CryptographicError: KMS refused the request or could not be reached (the botocore
            exception is the ``__cause__``), or returned a wrapped DEK over :attr:`WrappedKeyLimits.MAX_BYTES`
        """
        with memoryview(plaintext) as raw, raw.cast("B") as source:
            if len(source) == 0 or len(source) > self.MAX_PLAINTEXT_LENGTH:
                raise ValueError(f"KMS wraps 1-{self.MAX_PLAINTEXT_LENGTH} bytes; got {len(source)}.")
            # A copy this wrapper owns, so it can be zeroed whatever the caller passed (even bytes).
            # botocore accepts a bytearray for a blob, so no immutable copy is made here.
            buffer = bytearray(source)

        try:
            response = self._call(lambda: self._client.encrypt(**self._request(KeyId=self._key_id, Plaintext=buffer,
                                                                               EncryptionAlgorithm="SYMMETRIC_DEFAULT")), "wrap")
            return self._copy_wrapped(response.get("CiphertextBlob"), result, "wrap")
        finally:
            # botocore serializes the request inside the call, so it has been sent by now.
            ArrayUtility.zero_memory(buffer)

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        """Reveals a DEK with KMS's Decrypt, the key pinned, into ``result``. On any failure ``result``
        is zeroed.

        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the revealed key
        :raises CryptographicError: ``wrapped`` is empty or over :attr:`WrappedKeyLimits.MAX_BYTES`
            (refused without calling KMS), or KMS refused it - tampered with, wrapped under another key,
            or under a different encryption context - or could not be reached (the botocore exception
            is the ``__cause__``), or returned no plaintext
        """
        try:
            with memoryview(wrapped) as raw, raw.cast("B") as source:
                # Refused locally: no ciphertext this wrapper produced is outside these bounds.
                if len(source) == 0 or len(source) > WrappedKeyLimits.MAX_BYTES:
                    raise CryptographicError(f"A wrapped DEK is 1-{WrappedKeyLimits.MAX_BYTES} bytes; got {len(source)}.")
                ciphertext = bytes(source)

            response = self._call(lambda: self._client.decrypt(**self._request(KeyId=self._key_id, CiphertextBlob=ciphertext,
                                                                               EncryptionAlgorithm="SYMMETRIC_DEFAULT")), "unwrap")
            # Immutable bytes from botocore: copied into result, but it can't be zeroed (see the class comment).
            revealed = response.get("Plaintext")
            if revealed is None:
                raise CryptographicError(f"AWS KMS unwrap for key '{self._key_id}' returned no plaintext.")
            return self._copy_revealed(revealed, result)
        except BaseException:
            # Whatever a failed call left in the DEK buffer is erased.
            ArrayUtility.zero_memory(result)
            raise

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        """Has KMS generate a fresh :attr:`GENERATED_KEY_LENGTH`-byte DEK and return it wrapped only
        (GenerateDataKeyWithoutPlaintext) - the plaintext DEK never leaves KMS on this call.

        :param result: receives the wrapped key
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the wrapped DEK
        :raises CryptographicError: KMS refused the request or could not be reached (the botocore
            exception is the ``__cause__``), or returned a wrapped DEK over :attr:`WrappedKeyLimits.MAX_BYTES`
        """
        response = self._call(lambda: self._client.generate_data_key_without_plaintext(**self._request(KeyId=self._key_id, KeySpec="AES_256")),
                              "generate-and-wrap")
        return self._copy_wrapped(response.get("CiphertextBlob"), result, "generate-and-wrap")

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
        unwrapped key. No KMS call is made.

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

    def _request(self, **parameters: str | bytes | bytearray) -> dict[str, Any]:
        # A fresh context per request, so nothing botocore (or an event handler registered on the
        # client) does to a request can change what later requests bind. None is left out entirely,
        # as the other ports leave it out, rather than sent empty.
        request: dict[str, Any] = dict(parameters)
        if self._encryption_context is not None:
            request["EncryptionContext"] = dict(self._encryption_context)
        return request

    def _call(self, call: Callable[[], Mapping[str, Any]], operation: str) -> Mapping[str, Any]:
        # Turns botocore failures - service refusals (ClientError) and client-side ones such as
        # unresolvable credentials or an unreachable endpoint (BotoCoreError) - into the
        # CryptographicError every KeyWrapper fails with, naming KMS's error code and the HTTP status.
        # Anything else (KeyboardInterrupt, a programming error) is left as it is.
        try:
            response = call()
        except ClientError as error:
            details = error.response or {}
            code = details.get("Error", {}).get("Code") or type(error).__name__
            status = details.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown")
            raise CryptographicError(f"AWS KMS {operation} failed for key '{self._key_id}': {code} (HTTP {status}).") from error
        except BotoCoreError as error:
            raise CryptographicError(f"AWS KMS {operation} failed for key '{self._key_id}': {error}") from error
        if not isinstance(response, Mapping):
            raise CryptographicError(f"AWS KMS {operation} for key '{self._key_id}' returned no response.")
        return response

    def _copy_wrapped(self, ciphertext: Buffer | None, result: WritableBuffer, operation: str) -> int:
        length = 0 if ciphertext is None else memoryview(ciphertext).nbytes
        if length == 0 or ciphertext is None:
            raise CryptographicError(f"AWS KMS {operation} for key '{self._key_id}' returned no ciphertext.")

        # A key file over the limit would be refused when read back, so refuse to produce one.
        if length > WrappedKeyLimits.MAX_BYTES:
            raise CryptographicError(f"AWS KMS {operation} for key '{self._key_id}' returned {length} bytes; a wrapped DEK is at most "
                                     f"{WrappedKeyLimits.MAX_BYTES}.")

        return self._copy_into(ciphertext, result, "The wrapped DEK")

    @staticmethod
    def _copy_revealed(plaintext: Buffer, result: WritableBuffer) -> int:
        return AwsKmsKeyWrapper._copy_into(plaintext, result, "The revealed key")

    @staticmethod
    def _copy_into(data: Buffer, result: WritableBuffer, what: str) -> int:
        with memoryview(data) as raw, raw.cast("B") as source, memoryview(result) as target_raw, target_raw.cast("B") as target:
            if len(source) > len(target):
                raise ValueError(f"{what} is {len(source)} bytes; result holds {len(target)}.")
            target[:len(source)] = source
            return len(source)
