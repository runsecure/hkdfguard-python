"""The protected read-only cache over AWS Secrets Manager."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Final, Protocol

from botocore.exceptions import ClientError
from hkdfguard.abstractions import KeyRing
from hkdfguard.cache import RemoteSecretCache, SecretNameMatching, SecretValueSink
from hkdfguard.cache.awssecretsmanager import _capture

_NAME_PUNCTUATION: Final = frozenset("/_+=.@-")
_NOT_FOUND: Final = "ResourceNotFoundException"


class SecretsManagerClient(Protocol):
    """What :class:`AwsSecretsManagerSecretCache` uses of a Secrets Manager client: GetSecretValue,
    with keyword arguments named as the API names them, returning the parsed response as a dict, and
    ``meta.events``, the client's botocore event system, to register its capture on. A botocore
    client (``boto3.client("secretsmanager")``, or
    ``botocore.session.get_session().create_client("secretsmanager")``) is one; so is a typed
    ``mypy_boto3_secretsmanager.SecretsManagerClient``, for an application that uses those stubs."""

    def get_secret_value(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]: ...

    @property
    def meta(self) -> Any: ...


class AwsSecretsManagerSecretCache(RemoteSecretCache):
    """A :class:`~hkdfguard.abstractions.ProtectedReadOnlyCache` over the secrets in AWS Secrets
    Manager. The first lookup of a name that isn't cached yet reads that one secret's current version
    (AWSCURRENT) with GetSecretValue; fetching, encryption, caching and telemetry are
    :class:`~hkdfguard.cache.RemoteSecretCache`'s. This class never lists secrets (ListSecrets,
    BatchGetSecretValue), so the principal needs only ``secretsmanager:GetSecretValue`` on the
    secrets it reads (and ``kms:Decrypt`` on a customer managed key that encrypts them).

    Names are matched exactly, as Secrets Manager matches them: ``"prod/Db"`` and ``"prod/db"`` are
    two secrets and two entries. A name Secrets Manager can't hold - anything but 1-512 ASCII
    letters, digits and ``/_+=.@-``, such as the configuration path ``"ConnectionStrings:Admin"`` - is
    reported missing without a call. ARNs aren't accepted (``:`` isn't a name character): look
    secrets up by name.

    A secret that doesn't exist (ResourceNotFoundException) or whose value is empty is reported
    missing. Any other failure (access denied, a secret scheduled for deletion, a decryption failure,
    AWS unreachable, no credentials) raises botocore's exception - a ``ClientError`` (or the client's
    modeled subclass of it) for an error response, a ``BotoCoreError`` otherwise - and a response
    body that can't be trusted as Secrets Manager's raises
    :class:`~hkdfguard.cache.InvalidSecretDataError`. A SecretString is cached as its UTF-8 bytes; a
    SecretBinary as its bytes.

    A key/value secret - a SecretString holding a JSON object, as the console stores one - is cached
    whole under its name and each member under ``"name#key"`` - ``"prod/app#password"`` - all from
    one GetSecretValue (see :class:`~hkdfguard.cache.RemoteSecretCache`). A SecretBinary is never
    split.

    **The secret never becomes a str.** The cache registers one handler on the client's event system
    (``before-parse.secrets-manager.GetSecretValue``, ahead of every handler registered before it),
    which takes SecretString or SecretBinary out of a successful response's body
    (:class:`~hkdfguard.cache.SecretJsonBody`) and hands botocore's parser the body with both replaced
    by ``""`` - so the parsed response, botocore's debug log of the body it parses, and every later
    handler hold nothing secret. The handler acts only on the calls this cache makes, and only in the
    thread making each one (a ``ContextVar``): the application's own calls on the client, and this
    cache's concurrent calls from other threads, each see only their own response. Every bytearray of
    this library's that held the value is zeroed. What can't be zeroed is below the hook: botocore
    reads the whole body into an immutable ``bytes`` (its ``AWSResponse.content``) before any hook
    runs, from urllib3's own ``bytes`` chunks, and those stay in memory until collected - unparsed,
    held only by botocore's response object for the length of the call, but visible to a
    ``response-received`` or ``after-call`` handler the application registers (which see that
    response), and to botocore's history recorder if something enables it.

    The client is the application's: it creates it (credentials, region, retries, timeouts), keeps
    it for as long as anything uses this cache, and closes it. This cache never closes it, and changes
    nothing on it but registering that handler, once per client however many caches share it.
    botocore is synchronous, so :meth:`decrypt` and :meth:`find_max_decrypted_length` block the
    calling thread until AWS answers, and their ``_async`` forms run the call in a worker thread
    (:func:`asyncio.to_thread`); cancelling one stops it waiting, but the call runs on to its end,
    and whatever it reads is then refused rather than cached.
    """

    MAX_SECRET_NAME_LENGTH: Final = 512
    """The longest name Secrets Manager accepts for a secret."""

    def __init__(self, client: SecretsManagerClient, key_ring: KeyRing, logger: logging.Logger | None = None) -> None:
        """:param client: the Secrets Manager client every call is made through. Not closed by this
            cache; its owner (typically the application) closes it.
        :param key_ring: supplies the key every fetched secret is encrypted under; owned by the
            caller - the cache never closes keys
        :param logger: see :class:`~hkdfguard.cache.RemoteSecretCache`; ``None`` for the
            ``hkdfguard.cache`` logger
        :raises TypeError: ``client`` or ``key_ring`` is ``None``, or ``client`` has no botocore
            event system (``meta.events``) to register the capture on
        """
        if client is None:
            raise TypeError("client must not be None.")
        events = getattr(getattr(client, "meta", None), "events", None)
        if events is None or not callable(getattr(events, "register_first", None)):
            raise TypeError("client must be a botocore client: it has no meta.events to take the secret out of each response on.")
        super().__init__(key_ring, SecretNameMatching.EXACT, logger)
        self._client = client
        # Ahead of every handler already registered, so none of them sees the body before it is redacted.
        events.register_first(_capture.EVENT_NAME, _capture.redact_response, unique_id=_capture.HANDLER_ID)

    @staticmethod
    def is_valid_secret_name(name: str | None) -> bool:
        """Whether Secrets Manager accepts ``name`` as a secret name: 1-512 ASCII letters, digits and
        ``/_+=.@-``. ``None`` is not one."""
        if not isinstance(name, str) or not 0 < len(name) <= AwsSecretsManagerSecretCache.MAX_SECRET_NAME_LENGTH:
            return False
        return all(("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c in _NAME_PUNCTUATION for c in name)

    def _is_valid_name(self, name: str) -> bool:
        return self.is_valid_secret_name(name)

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        # The value reaches the sink through the capture; the response holds it as "", so it isn't read here.
        capture = _capture.SecretCapture(value)
        refused: Exception | None = None
        try:
            with _capture.active(capture):
                self._client.get_secret_value(SecretId=name)
        except ClientError as error:
            refused = capture.failure
            if refused is None:
                if error.response.get("Error", {}).get("Code") == _NOT_FOUND:
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

        # A successful response whose body never passed through the capture held the secret, and
        # nothing was cached; refuse it rather than report the secret missing.
        if not capture.captured:
            raise RuntimeError("The GetSecretValue response wasn't captured: the client never emitted "
                               f"{_capture.EVENT_NAME} (a stubbed client, or the handler was unregistered).")
