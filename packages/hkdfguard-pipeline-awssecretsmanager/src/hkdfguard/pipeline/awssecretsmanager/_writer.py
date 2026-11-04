"""The secret pipeline writer over AWS Secrets Manager."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any, Final, Protocol

import botocore.session
from botocore.exceptions import ClientError
from hkdfguard.abstractions import PipelineDataProtector
from hkdfguard.cache import ResponseBody, SecretJsonBody
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest
from hkdfguard.pipeline.awssecretsmanager import _capture

_NAME_PUNCTUATION: Final = frozenset("/_+=.@-")
_NOT_FOUND: Final = "ResourceNotFoundException"
_TEXT_PROPERTY: Final = "SecretString"
_BINARY_PROPERTY: Final = "SecretBinary"


class SecretsManagerClient(Protocol):
    """What :class:`AwsSecretsManagerSecretPipelineWriter` uses of a Secrets Manager client:
    GetSecretValue, with keyword arguments named as the API names them, returning the parsed response
    as a dict, and ``meta.events``, the client's botocore event system, to register its capture on. A
    botocore client (``boto3.client("secretsmanager")``, or
    ``botocore.session.get_session().create_client("secretsmanager")``) is one; so is a typed
    ``mypy_boto3_secretsmanager.SecretsManagerClient``."""

    def get_secret_value(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]: ...

    @property
    def meta(self) -> Any: ...


class AwsSecretsManagerSecretPipelineWriter(SecretPipelineWriter):
    """The end of a provisioning pipeline: pulls a fixed list of secrets from AWS Secrets Manager,
    encrypts each with a :class:`~hkdfguard.abstractions.PipelineDataProtector` as soon as it is
    read, and writes them out as one file per secret - the folder layout
    :class:`~hkdfguard.cache.FilePerSecretCache` reads at runtime. It is independent of
    ``hkdfguard-cache-awssecretsmanager``'s runtime cache, and of any key ring. Naming, encrypting,
    keeping and writing are :class:`~hkdfguard.pipeline.SecretPipelineWriter`'s::

        with AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector:
            with AwsSecretsManagerSecretPipelineWriter(protector, ["prod/app#username", "prod/app#password", "prod/api-key"]) as writer:
                writer.pull_secrets()
                writer.write_protected_secret_files(r"C:\\HkdfGuardSecrets\\myapp")
            # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.

    A secret name is a Secrets Manager secret name, optionally with a key after ``#``:
    ``"prod/api-key"`` reads the secret's whole SecretString, and ``"prod/app#password"`` the password
    member of a key/value secret - a SecretString holding a JSON object, as the console stores one
    (written as prod__api-key and prod__app__password). A member's string is read as its text; a
    number, true or false as its JSON text. Each secret's current version (AWSCURRENT) is read with
    GetSecretValue, so the principal needs only ``secretsmanager:GetSecretValue`` on them (and
    ``kms:Decrypt`` on a customer managed key that encrypts them). A name holding ``+``, ``=`` or
    ``@``, which no file name can, is refused. A SecretBinary is refused with
    :class:`~hkdfguard.cache.InvalidSecretDataError`: the protector encrypts text.

    A secret that doesn't exist (ResourceNotFoundException) or is empty is reported missing. Any
    other failure (access denied, a secret scheduled for deletion, a decryption failure, AWS
    unreachable, no credentials) raises botocore's exception - a ``ClientError`` (or the client's
    modeled subclass of it) for an error response, a ``BotoCoreError`` otherwise - and a response body
    that can't be trusted as Secrets Manager's raises :class:`~hkdfguard.cache.InvalidSecretDataError`.

    **The secret never becomes a str.** As ``hkdfguard-cache-awssecretsmanager`` does, the writer
    registers one handler on the client's event system (``before-parse.secrets-manager.GetSecretValue``,
    ahead of every handler registered before it), which takes the SecretString out of a successful
    response's body (:class:`~hkdfguard.cache.SecretJsonBody`), encrypts it, and hands botocore's
    parser the body with SecretString and SecretBinary replaced by ``""`` - so the parsed response,
    botocore's debug log of the body it parses, and every later handler hold nothing secret. The
    handler acts only on the calls this writer makes, and only in the thread making each one (a
    ``ContextVar``). Every bytearray of this library's that held the value is zeroed. Out of reach:
    botocore reads the whole body into an immutable ``bytes`` before any hook runs, and that copy
    lives until it is collected. Timeouts and retries are the client's.

    botocore is synchronous: :meth:`pull_secrets` blocks the calling thread, and
    :meth:`pull_secrets_async` makes each call in a worker thread.
    """

    MAX_SECRET_NAME_LENGTH: Final = 512
    """The longest name Secrets Manager accepts for a secret."""

    def __init__(self, protector: PipelineDataProtector, secret_names: Sequence[str], client: SecretsManagerClient | None = None) -> None:
        """:param protector: encrypts every value read. Owned by the caller: the writer never closes it.
        :param secret_names: the secrets to pull, each a secret name with the key to read after
            ``#`` if any. Copied: a later change to the sequence isn't seen.
        :param client: the Secrets Manager client every call is made through - configured with its
            region, credentials, timeouts and retries - which the caller keeps and closes; ``None``
            for a client of the writer's own, which :meth:`close` closes: botocore's defaults, which
            take the region and credentials from the environment or profile (and IRSA or EKS Pod
            Identity on EKS). Credentials are resolved when a call is made, not here.
        :raises TypeError: ``protector`` or ``secret_names`` is ``None``, or ``client`` has no
            botocore event system (``meta.events``) to register the capture on
        :raises ValueError: ``secret_names`` is empty, or holds ``None``, a name Secrets Manager can't
            hold (with a key), one whose file name isn't one FilePerSecretCache can read, or two with
            the same file name, in any case
        :raises botocore.exceptions.NoRegionError: no client was given, and no region is configured
        """
        super().__init__(protector, secret_names, self.is_valid_secret_name)
        owns_client = client is None
        if client is None:
            client = botocore.session.get_session().create_client("secretsmanager")
        events = getattr(getattr(client, "meta", None), "events", None)
        if events is None or not callable(getattr(events, "register_first", None)):
            raise TypeError("client must be a botocore client: it has no meta.events to take the secret out of each response on.")
        self._client = client
        self._owns_client = owns_client
        # Ahead of every handler already registered, so none of them sees the body before it is redacted.
        events.register_first(_capture.EVENT_NAME, _capture.redact_response, unique_id=_capture.HANDLER_ID)

    @classmethod
    def is_valid_secret_name(cls, name: str | None) -> bool:
        """Whether Secrets Manager accepts ``name`` as a secret name: 1-512 ASCII letters, digits and
        ``/_+=.@-``. ``None`` is not one."""
        if not isinstance(name, str) or not 0 < len(name) <= cls.MAX_SECRET_NAME_LENGTH:
            return False
        return all(("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c in _NAME_PUNCTUATION for c in name)

    @property
    def client(self) -> SecretsManagerClient:
        """The client every call is made through: the caller's, or the writer's own."""
        return self._client

    def close(self) -> None:
        """Closes the writer's own client; a client the caller gave is left open. Safe to call more than once."""
        close = getattr(self._client, "close", None) if self._owns_client else None
        if callable(close):
            close()

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """:raises botocore.exceptions.ClientError: any AWS failure but ResourceNotFoundException
        :raises InvalidSecretDataError: the secret is a SecretBinary, the response isn't Secrets
            Manager's JSON, or a key/value secret holds a key twice or a value that isn't UTF-8 text
        """
        # Filled by the capture, from the body in a bytearray zeroed once it returns, on each
        # attempt that succeeded; the response botocore parses holds the value as "", so it isn't read here.
        read: dict[str, str] = {}

        def take(body: ResponseBody) -> bytes:
            read.clear()
            return SecretJsonBody.capture(body, self._receiver(requests, read, binary=_BINARY_PROPERTY), _TEXT_PROPERTY, _BINARY_PROPERTY)

        capture = _capture.SecretCapture(take)
        refused: Exception | None = None
        try:
            with _capture.active(capture):
                self._client.get_secret_value(SecretId=name)
        except ClientError as error:
            refused = capture.failure
            if refused is None:
                if error.response.get("Error", {}).get("Code") == _NOT_FOUND:
                    # Missing: nothing handed over.
                    return
                raise
        except Exception:
            # A body the capture refused fails the call with the capture's own exception; report that
            # one, whatever wrapped it.
            refused = capture.failure
            if refused is None:
                raise
        if refused is not None:
            # Raised here, outside the except block, so nothing is chained to it.
            raise refused

        # A successful response whose body never passed through the capture held the secret as a
        # str already; refuse it rather than report the secret missing.
        if not capture.captured:
            raise RuntimeError("The GetSecretValue response wasn't captured: the client never emitted "
                               f"{_capture.EVENT_NAME} (a stubbed client, or the handler was unregistered).")
        values.update(read)
