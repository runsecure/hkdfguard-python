"""The key wrapper over an RSA wrapping key and an EC P-256 signing key in Azure Key Vault."""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Buffer, Callable, Mapping
from types import TracebackType
from typing import Any, Final, Protocol, Self

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.keyvault.keys.crypto import (
    CryptographyClient,
    KeyWrapAlgorithm,
    SignatureAlgorithm,
    SignResult,
    UnwrapResult,
    VerifyResult,
    WrapResult,
)
from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, WrappedKeyLimits, WritableBuffer
from hkdfguard.keywrapping.azurekeyvault import _envelope
from hkdfguard.keywrapping.azurekeyvault._key_id import KeyVaultKeyId
from hkdfguard.securefile import KeyFileTrust, TrustedKeyFile


class KeyVaultCryptoClient(Protocol):
    """The calls :class:`AzureKeyVaultKeyWrapper` makes on a Key Vault client for one key version: an
    ``azure.keyvault.keys.crypto.CryptographyClient`` is one."""

    def wrap_key(self, algorithm: KeyWrapAlgorithm, key: bytes, **kwargs: Any) -> WrapResult: ...

    def unwrap_key(self, algorithm: KeyWrapAlgorithm, encrypted_key: bytes, **kwargs: Any) -> UnwrapResult: ...

    def sign(self, algorithm: SignatureAlgorithm, digest: bytes, **kwargs: Any) -> SignResult: ...

    def verify(self, algorithm: SignatureAlgorithm, digest: bytes, signature: bytes, **kwargs: Any) -> VerifyResult: ...

    def close(self) -> None: ...


class AzureKeyVaultKeyWrapper(KeyWrapper):
    """Protects (wraps) and reveals (unwraps) a DEK under an RSA key in Azure Key Vault, and signs every
    wrapped DEK with a second, EC P-256 key in the vault. The private keys never enter this process;
    unwrapping and signing are calls to Key Vault, authorized by the caller's Azure credential.

    Why two keys: RSA-OAEP wrapping needs only the public key, which isn't secret, so without the
    signature anyone could produce a wrapped DEK this wrapper would accept - holding a DEK they chose,
    which the application would then encrypt new data under. Signing needs the signing key's private
    half, held in Key Vault and usable only by principals granted ``sign``. Unwrap checks the signature
    before it unwraps anything, so a wrapped DEK proves it was made by a principal allowed to sign: give
    that permission to the pipeline that creates key files, never to the application. Each key does one
    job; the wrapper refuses the same key for both.

    Both keys are pinned: a wrapped DEK records only the key versions it was made with, and the vault
    and key names always come from the constructor. Rotating either key in Key Vault therefore needs
    nothing here - existing key files keep naming the version that made them, which must stay enabled
    while they're in use. Wrapped DEKs are byte for byte those of the .NET AzureKeyVaultKeyWrapper and
    the Java AzureKeyVaultKeyWrapperImpl, so a key file made by any of them is read by the others, given
    the same keys and context.

    The optional context is bound into the signature, and must be given again, exactly, to reveal the
    DEK: a key file made for one application can't be used by another that shares the keys. Key Vault
    has no "generate data key", so :meth:`generate_and_wrap` generates the DEK in this process and
    wraps it.

    The Key Vault client fetches each key's public half on first use (it needs ``get`` on both keys)
    and then wraps and verifies in this process, with ``cryptography``; unwrapping and signing are
    always calls to Key Vault. Without ``get``, every operation is a call, and a key identifier given
    without a version can't be used: the client then can't learn which version it used, and a wrapped
    DEK must record it.

    The caller's ``result`` buffer is zeroed whenever an unwrap fails. Unlike the other ports, this one
    can't zero its copy of a key it wraps: the SDK wraps with ``cryptography``'s RSA, which takes only
    an immutable ``bytes`` (given a ``bytearray`` it falls back to sending the key to Key Vault, in a
    request body no one can zero either). So the key :meth:`wrap` is given is copied once into a
    ``bytes``, and :meth:`generate_and_wrap` hands over the ``bytes`` ``os.urandom`` returns; each lives
    until collected. So does the revealed key, which the SDK decodes from the unwrap response into a
    ``bytes`` - copied into ``result``, but no one can zero it. Process hardening
    (``hkdfguard-keywrapping-v1``'s ``NativeProcessHardening``) is what keeps such copies out of reach
    of a debugger or a crash dump.

    The wrapper creates one Key Vault client per key version it uses, and keeps it: each caches the
    public key it works with, and a key ring's refresh unwraps under the same versions every interval.
    :meth:`close` closes them; the wrapper is a context manager. Every call blocks until Key Vault
    answers. Argument errors raise ``ValueError`` or ``TypeError``; a Key Vault refusal, an unreachable
    vault or a credential that can't get a token raises :class:`CryptographicError` naming the
    operation, the key, and Key Vault's error code and HTTP status, with the Azure exception as its
    ``__cause__``.
    """

    GENERATED_KEY_LENGTH: Final = 32
    """The length of the DEK :meth:`generate_and_wrap` generates: 32 bytes (AES-256)."""

    MAX_PLAINTEXT_LENGTH: Final = 190
    """The largest plaintext RSA-OAEP-256 wraps under a 2048-bit key, in bytes."""

    def __init__(self, wrapping_key_id: str, signing_key_id: str, credential: TokenCredential, context: str | None = None,
                 key_file_trust: KeyFileTrust | None = None, *, client_options: Mapping[str, Any] | None = None) -> None:
        """A wrapper over an RSA wrapping key and an EC P-256 signing key. No call is made until it is used.

        :param wrapping_key_id: the RSA key that wraps every DEK (2048 or 3072 bits), as its key
            identifier: ``https://{vault}.vault.azure.net/keys/{name}``, optionally with ``/{version}``
            to wrap under that version rather than the current one
        :param signing_key_id: the EC P-256 key that signs every wrapped DEK, in the same form
        :param credential: authenticates every call to Key Vault, e.g. a managed identity
            (``azure.identity.ManagedIdentityCredential``, or ``DefaultAzureCredential``, which finds it)
        :param context: bound into every wrapped DEK's signature and required again to reveal it;
            ``None`` binds none. Not secret.
        :param key_file_trust: who besides the operating system's administrators may have written a key
            file :meth:`read_key_file` reads; ``None`` trusts administrators only
            (:attr:`KeyFileTrust.ADMINISTRATORS_ONLY`)
        :param client_options: (keyword only) keyword arguments for each Key Vault ``CryptographyClient`` - its
            ``api_version``, ``transport``, retry and logging options; copied at construction. The
            wrapper gives each client its key and the credential itself.
        :raises TypeError: a key identifier or the credential is ``None``, or an argument is of the wrong type
        :raises ValueError: a key identifier isn't a Key Vault key's, both name the same key, the context
            is too long or not well-formed text, or ``client_options`` names ``key`` or ``credential``
        """
        if credential is None:
            raise TypeError("credential must not be None.")
        if client_options is not None and not isinstance(client_options, Mapping):
            raise TypeError("client_options must be a mapping of keyword arguments.")
        options = dict(client_options or {})
        if "key" in options or "credential" in options:
            raise ValueError("client_options must not name key or credential: the wrapper gives each client its own.")

        def create(key_id: str) -> KeyVaultCryptoClient:
            return CryptographyClient(key_id, credential, **options)

        self._setup(wrapping_key_id, signing_key_id, create, context, key_file_trust)

    @classmethod
    def _over(cls, wrapping_key_id: str, signing_key_id: str, client_factory: Callable[[str], KeyVaultCryptoClient],
              context: str | None = None, key_file_trust: KeyFileTrust | None = None) -> Self:
        """A wrapper whose Key Vault clients come from ``client_factory``, given each key version's identifier (for tests)."""
        wrapper = cls.__new__(cls)
        wrapper._setup(wrapping_key_id, signing_key_id, client_factory, context, key_file_trust)
        return wrapper

    def _setup(self, wrapping_key_id: str, signing_key_id: str, client_factory: Callable[[str], KeyVaultCryptoClient],
               context: str | None, key_file_trust: KeyFileTrust | None) -> None:
        for name, value in (("wrapping_key_id", wrapping_key_id), ("signing_key_id", signing_key_id)):
            if value is None:
                raise TypeError(f"{name} must not be None.")
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a str.")
        if key_file_trust is not None and not isinstance(key_file_trust, KeyFileTrust):
            raise TypeError("key_file_trust must be a KeyFileTrust.")

        self._wrapping_key = KeyVaultKeyId.parse(wrapping_key_id)
        self._signing_key = KeyVaultKeyId.parse(signing_key_id)
        if self._wrapping_key.same_key(self._signing_key):
            raise ValueError(f"The wrapping and signing keys are both '{self._wrapping_key.name}'; use an RSA key to wrap and a separate EC P-256 key "
                             "to sign.")

        self._context = _envelope.encode_context(context)
        self._key_file_trust = key_file_trust if key_file_trust is not None else KeyFileTrust.ADMINISTRATORS_ONLY
        self._client_factory = client_factory
        self._clients: dict[str, KeyVaultCryptoClient] = {}
        self._lock = threading.Lock()
        self._closed = False

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        """Wraps a DEK under the wrapping key (RSA-OAEP-256), then has the signing key sign the result
        (ES256), writing the wrapped DEK to ``result``.

        :param plaintext: the key, 1 to :attr:`MAX_PLAINTEXT_LENGTH` bytes; not modified - it is the
            caller's to zero (this wrapper's own copy can't be; see the class comment)
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``plaintext`` is empty or over :attr:`MAX_PLAINTEXT_LENGTH` bytes, or
            ``result`` is too small for the wrapped DEK
        :raises CryptographicError: Key Vault refused a request or could not be reached (the Azure
            exception is the ``__cause__``), answered for a key other than the one asked, or the wrapped
            DEK would be over :attr:`WrappedKeyLimits.MAX_BYTES` (an RSA key over 3072 bits) or its
            signature isn't ES256's
        """
        with memoryview(plaintext) as raw, raw.cast("B") as source:
            if len(source) == 0 or len(source) > self.MAX_PLAINTEXT_LENGTH:
                raise ValueError(f"Azure Key Vault wraps 1-{self.MAX_PLAINTEXT_LENGTH} bytes; got {len(source)}.")
            # The SDK wraps with cryptography's RSA, which takes only bytes: an immutable copy, which
            # lives until collected (see the class comment).
            key = bytes(source)
        return self._wrap(key, result)

    def _wrap(self, key: bytes, result: WritableBuffer) -> int:
        wrapped = self._call(lambda client: client.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, key), "wrap", self._wrapping_key)
        unsigned = _envelope.build_unsigned(self._version_of(wrapped.key_id, self._wrapping_key, "wrap"), wrapped.encrypted_key)
        length = len(unsigned) + _envelope.KEY_VERSION_LENGTH + _envelope.SIGNATURE_LENGTH
        if length > WrappedKeyLimits.MAX_BYTES:
            raise CryptographicError(f"The wrapped DEK would be {length} bytes; a wrapped DEK is at most {WrappedKeyLimits.MAX_BYTES}. Use a 2048- or "
                                     f"3072-bit RSA key for '{self._wrapping_key.name}'.")

        # ES256 signs the SHA-256 digest of the data, which the SDK takes already computed.
        digest = hashlib.sha256(_envelope.signed_data(unsigned, self._context)).digest()
        signature = self._call(lambda client: client.sign(SignatureAlgorithm.es256, digest), "sign", self._signing_key)
        return _envelope.write(unsigned, self._version_of(signature.key_id, self._signing_key, "sign"), signature.signature, result)

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        """Verifies the wrapped DEK's signature under the signing key version it records, and only then
        unwraps it under the recorded wrapping key version, into ``result``. On any failure ``result``
        is zeroed.

        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the revealed key
        :raises CryptographicError: ``wrapped`` isn't a wrapped DEK this wrapper wrote, its signature
            doesn't verify (forged, tampered with, or under a different context), Key Vault refused it,
            or Key Vault could not be reached (the Azure exception is the ``__cause__``)
        """
        try:
            with memoryview(wrapped) as raw, raw.cast("B") as source:
                envelope = bytes(source)
            parts = _envelope.parse(envelope)

            # The signature first: nothing reaches unwrap_key that a principal allowed to sign didn't make.
            digest = hashlib.sha256(_envelope.signed_data(envelope[:parts.unsigned_length], self._context)).digest()
            signed_by = self._signing_key.with_version(parts.signing_key_version)
            verify = self._call(lambda client: client.verify(SignatureAlgorithm.es256, digest, parts.signature), "verify", signed_by)
            if verify.is_valid is not True:
                raise CryptographicError(f"The wrapped DEK's signature doesn't verify under '{self._signing_key.name}' version "
                                         f"{parts.signing_key_version}: it was tampered with, wrapped under a different context, or not made by "
                                         "a principal allowed to sign.")

            wrapped_by = self._wrapping_key.with_version(parts.wrapping_key_version)
            unwrapped = self._call(lambda client: client.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, parts.wrapped_dek), "unwrap", wrapped_by)
            # Immutable bytes from the SDK: copied into result, but it can't be zeroed (see the class comment).
            revealed = unwrapped.key
            if not revealed:
                raise CryptographicError(f"Azure Key Vault unwrap for key '{self._wrapping_key.name}' returned no key.")
            with memoryview(revealed) as source, memoryview(result) as target_raw, target_raw.cast("B") as target:
                if len(source) > len(target):
                    raise ValueError(f"The revealed key is {len(source)} bytes; result holds {len(target)}.")
                target[:len(source)] = source
                return len(source)
        except BaseException:
            # Whatever a failed call left in the DEK buffer is erased.
            ArrayUtility.zero_memory(result)
            raise

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        """Generates a fresh :attr:`GENERATED_KEY_LENGTH`-byte DEK in this process, and wraps and signs
        it - it is never returned.

        :param result: receives the wrapped key
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the wrapped DEK
        :raises CryptographicError: as :meth:`wrap`
        """
        # The bytes os.urandom returns go to the SDK as they are: the only copy, immutable (see the class comment).
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
        unwrapped key. No Key Vault call is made.

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

    def close(self) -> None:
        """Closes every Key Vault client the wrapper created. Later calls raise :class:`CryptographicError`;
        closing again does nothing."""
        with self._lock:
            self._closed = True
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None) -> None:
        self.close()

    def _client(self, key: KeyVaultKeyId) -> KeyVaultCryptoClient:
        # One client per key version, kept: each caches the public key it works with.
        with self._lock:
            if self._closed:
                raise CryptographicError("This AzureKeyVaultKeyWrapper is closed.")
            key_id = str(key)
            client = self._clients.get(key_id)
            if client is None:
                client = self._clients[key_id] = self._client_factory(key_id)
            return client

    def _call[T](self, call: Callable[[KeyVaultCryptoClient], T], operation: str, key: KeyVaultKeyId) -> T:
        # Turns Azure failures - service refusals (HttpResponseError with a response) and client-side
        # ones such as a credential that can't get a token, an unreachable vault or a local key the SDK
        # refuses to use - into the CryptographicError every KeyWrapper fails with, naming Key Vault's
        # error code and the HTTP status. KeyboardInterrupt and the like are left as they are.
        client = self._client(key)
        try:
            return call(client)
        except CryptographicError:
            raise
        except HttpResponseError as error:
            if error.response is None:
                raise CryptographicError(f"Azure Key Vault {operation} failed for key '{key.name}': {error.message}") from error
            code = error.error.code if error.error is not None and error.error.code else "error"
            raise CryptographicError(f"Azure Key Vault {operation} failed for key '{key.name}': {code} (HTTP {error.status_code}).") from error
        except Exception as error:
            raise CryptographicError(f"Azure Key Vault {operation} failed for key '{key.name}': {error}") from error

    @staticmethod
    def _version_of(key_id: str | None, expected: KeyVaultKeyId, operation: str) -> str:
        # The version of the key Key Vault reports having used, refusing an answer from any other key.
        try:
            used = KeyVaultKeyId.parse(key_id)  # type: ignore[arg-type]  # None is refused as not a str
        except ValueError as error:
            raise CryptographicError(f"Azure Key Vault {operation} for key '{expected.name}' reported key {key_id!r}, which isn't a key identifier.") \
                from error

        if not used.same_key(expected):
            raise CryptographicError(f"Azure Key Vault {operation} for key '{expected.name}' reported key '{key_id}' instead.")
        if used.version is None:
            raise CryptographicError(f"Azure Key Vault {operation} for key '{expected.name}' didn't report which version it used: give the identity "
                                     "get on the key, or name a version in its key identifier.")
        return used.version
