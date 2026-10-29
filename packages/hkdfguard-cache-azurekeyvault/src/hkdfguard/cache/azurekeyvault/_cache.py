"""A protected read-only cache over the secrets in one Azure Key Vault."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from types import TracebackType
from typing import Any, ClassVar, Final, Self

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.keyvault.secrets import SecretClient
from hkdfguard.abstractions import KeyRing
from hkdfguard.cache import RemoteSecretCache, SecretNameMatching, SecretValueSink
from hkdfguard.cache.azurekeyvault._capture import CAPTURE_OPTION, Capture, SecretCapturePolicy

_POLICY: Final = SecretCapturePolicy()

# Client options that would put a policy of the application's closer to the network than the capture
# policy - where it would see every secret's value - or replace the pipeline the policy is in, or are
# the cache's own to set.
_REFUSED_OPTIONS: Final = {
    "vault_url": "the cache passes the vault URL itself",
    "credential": "the cache passes the credential itself",
    "policies": "it replaces the pipeline, the capture policy with it",
    "generated_client": "it replaces the client, the capture policy with it",
    "authentication_policy": "it runs closer to the network than the capture policy, and would see every secret's value",
    "custom_hook_policy": "it runs closer to the network than the capture policy, and would see every secret's value",
    "raw_response_hook": "it runs closer to the network than the capture policy, and would see every secret's value",
    "logging_policy": "it runs closer to the network than the capture policy, and could log every secret's value",
    "http_logging_policy": "it runs closer to the network than the capture policy, and could log every secret's value",
}

_ASCII_LETTERS_DIGITS_HYPHEN: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


class AzureKeyVaultSecretCache(RemoteSecretCache):
    """A :class:`~hkdfguard.abstractions.ProtectedReadOnlyCache` over the secrets in one Azure Key
    Vault. The first lookup of a name that isn't cached yet reads that one secret (its current
    version) with Get Secret; fetching, encryption, caching and telemetry are
    :class:`~hkdfguard.cache.RemoteSecretCache`'s. This class never lists the vault's secrets, so the
    identity needs only ``get`` on secrets (the Key Vault Secrets User role), never ``list``.

    Key Vault secret names are 1-:attr:`MAX_SECRET_NAME_LENGTH` ASCII letters, digits and hyphens,
    compared ignoring case, so ``"Db-Password"`` and ``"DB-PASSWORD"`` are one entry and one secret.
    Any other name (a configuration path such as ``"ConnectionStrings:Admin"``, say) is reported
    missing without a call - and is never spliced into a request URL, so the cache can sit in a
    :class:`~hkdfguard.cache.ProtectedCacheCollection` beside sources with other naming rules.

    A secret whose value is a JSON object, such as ``{"username":"app","password":"..."}``, is cached
    whole under its name and each member under ``"name#key"`` - ``"Db-Login#password"`` - all from
    one call (see RemoteSecretCache). Keys are matched exactly, though secret names aren't. The
    secret's content type isn't consulted: any value that isn't one JSON object is cached whole only.

    A secret that doesn't exist (HTTP 404) or whose value is empty is reported missing. Any other
    failure (access denied, a disabled secret, the vault unreachable, a credential that can't get a
    token) propagates as the Azure SDK's exception - an ``HttpResponseError`` (``status_code`` says
    which), ``ClientAuthenticationError`` or ``ServiceRequestError``.

    The secret never becomes a ``str``. The cache builds its own ``SecretClient`` with a pipeline
    policy that reads the response body into a bytearray of the library's own, takes the value out of
    it, and hands SecretClient the body with the value blanked; every bytearray holding the value is
    zeroed. What can't be zeroed: the immutable ``bytes`` chunks the HTTP stack (requests and urllib3,
    by default) reads the body in, which are copied out and dropped, and the stack's own buffers (TLS
    decryption, socket reads). The sink travels with each request, never on the client, so concurrent
    fetches - from any threads, through the one client - each capture their own response.

    decrypt_async and find_max_decrypted_length_async fetch through the same synchronous client in a
    worker thread (RemoteSecretCache's default ``_fetch_async``), so they work from any event loop
    with no asyncio HTTP library installed; cancelling the lookup stops it waiting, but the request
    runs on to its end and what it hands over is refused, never cached.

    Close the cache (or use it as a context manager) to close its client's HTTP session.
    """

    MAX_SECRET_NAME_LENGTH: ClassVar[int] = 127
    """The longest name Key Vault accepts for a secret."""

    def __init__(self, vault_url: str, credential: TokenCredential, key_ring: KeyRing, logger: logging.Logger | None = None, *,
                 client_options: Mapping[str, Any] | None = None) -> None:
        """A cache over the vault at ``vault_url``. No call is made until a secret is requested.

        :param vault_url: the vault to read secrets from: ``https://{vault}.vault.azure.net/``
        :param credential: authenticates every call to Key Vault, e.g. a managed identity
            (``azure.identity.ManagedIdentityCredential``, or ``DefaultAzureCredential``, which finds it)
        :param key_ring: supplies the key every fetched secret is encrypted under; owned by the caller
            - the cache never closes keys
        :param logger: optional; see :class:`~hkdfguard.cache.RemoteSecretCache`
        :param client_options: (keyword only) keyword arguments for the cache's ``SecretClient`` - its
            ``api_version``, ``transport``, retry options, ``per_call_policies`` and
            ``per_retry_policies``; copied at construction, so the caller's mapping (and any list in
            it) is left as it is. The capture policy is added after the application's per-retry
            policies, so they see only redacted bodies. ``logging_enable`` is safe: the logging
            policy never sees a captured body (see ``SecretCapturePolicy``). Options that would put a
            policy of the application's closer to the network than the capture policy, or replace the
            pipeline, are refused: ``policies``, ``generated_client``, ``authentication_policy``,
            ``custom_hook_policy``, ``raw_response_hook``, ``logging_policy`` and
            ``http_logging_policy``.
        :raises TypeError: ``vault_url``, ``credential`` or ``key_ring`` is ``None``, or
            ``client_options`` isn't a mapping
        :raises ValueError: ``vault_url`` is empty, or ``client_options`` names an option the cache
            refuses
        """
        super().__init__(key_ring, SecretNameMatching.IGNORE_ASCII_CASE, logger)
        if vault_url is None:
            raise TypeError("vault_url must not be None.")
        if credential is None:
            raise TypeError("credential must not be None.")
        if client_options is not None and not isinstance(client_options, Mapping):
            raise TypeError("client_options must be a mapping of keyword arguments.")

        options = dict(client_options or {})
        for name, reason in _REFUSED_OPTIONS.items():
            if name in options:
                raise ValueError(f"client_options must not set {name}: {reason}.")

        per_retry = options.pop("per_retry_policies", None)
        policies: list[Any] = [] if per_retry is None else list(per_retry) if isinstance(per_retry, Iterable) else [per_retry]
        self._client = SecretClient(vault_url, credential, per_retry_policies=[*policies, _POLICY], **options)

    @classmethod
    def is_valid_secret_name(cls, name: str | None) -> bool:
        """Whether Key Vault accepts ``name`` as a secret name: 1-127 ASCII letters, digits and hyphens."""
        return (isinstance(name, str) and 0 < len(name) <= cls.MAX_SECRET_NAME_LENGTH
                and all(c in _ASCII_LETTERS_DIGITS_HYPHEN for c in name))

    def _is_valid_name(self, name: str) -> bool:
        return self.is_valid_secret_name(name)

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        # The value reaches the sink through the capture policy; what SecretClient returns holds it
        # blanked, so it isn't read here.
        capture = Capture(value)
        options: dict[str, Any] = {CAPTURE_OPTION: capture}
        try:
            self._client.get_secret(name, **options)
        except HttpResponseError as error:
            if error.status_code == 404:
                return
            raise

        if not capture.captured:
            raise RuntimeError("Key Vault's response didn't pass through the cache's capture policy.")

    def close(self) -> None:
        """Closes the cache's Key Vault client and its HTTP session. Values already cached stay readable."""
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None) -> None:
        self.close()
