"""The secret pipeline writer over one Azure Key Vault."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from typing import Any, ClassVar, Final

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.keyvault.secrets import SecretClient
from hkdfguard.abstractions import PipelineDataProtector
from hkdfguard.cache import ResponseBody, SecretJsonBody
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest
from hkdfguard.pipeline.azurekeyvault._capture import CAPTURE_OPTION, Capture, SecretCapturePolicy

_POLICY: Final = SecretCapturePolicy()
_VALUE_PROPERTY: Final = "value"

# Client options that would put a policy of the application's closer to the network than the capture
# policy - where it would see every secret's value - or replace the pipeline the policy is in, or are
# the writer's own to set.
_REFUSED_OPTIONS: Final = {
    "vault_url": "the writer passes the vault URL itself",
    "credential": "the writer passes the credential itself",
    "policies": "it replaces the pipeline, the capture policy with it",
    "generated_client": "it replaces the client, the capture policy with it",
    "authentication_policy": "it runs closer to the network than the capture policy, and would see every secret's value",
    "custom_hook_policy": "it runs closer to the network than the capture policy, and would see every secret's value",
    "raw_response_hook": "it runs closer to the network than the capture policy, and would see every secret's value",
    "logging_policy": "it runs closer to the network than the capture policy, and could log every secret's value",
    "http_logging_policy": "it runs closer to the network than the capture policy, and could log every secret's value",
}

_ASCII_LETTERS_DIGITS_HYPHEN: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


class AzureKeyVaultSecretPipelineWriter(SecretPipelineWriter):
    """The end of a provisioning pipeline: pulls a fixed list of secrets from one Azure Key Vault,
    encrypts each with a :class:`~hkdfguard.abstractions.PipelineDataProtector` as soon as it is
    read, and writes them out as one file per secret - the folder layout
    :class:`~hkdfguard.cache.FilePerSecretCache` reads at runtime. It is independent of
    ``hkdfguard-cache-azurekeyvault``'s runtime cache, and of any key ring, with its own
    ``SecretClient``. Naming, encrypting, keeping and writing are
    :class:`~hkdfguard.pipeline.SecretPipelineWriter`'s::

        with AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector:
            with AzureKeyVaultSecretPipelineWriter(vault_url, DefaultAzureCredential(), protector,
                                                   ["Db-Login#username", "Db-Login#password", "Api-Key"]) as writer:
                writer.pull_secrets()
                writer.write_protected_secret_files(r"C:\\HkdfGuardSecrets\\myapp")
            # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.

    A secret name is a Key Vault secret name - 1-127 ASCII letters, digits and hyphens - optionally
    with a key after ``#``: ``"Api-Key"`` reads the secret's whole value, and ``"Db-Login#password"``
    the password member of a secret whose value is a JSON object (written as Api-Key and
    Db-Login__password). A member's string is read as its text; a number, true or false as its JSON
    text. Each secret's current version is read with Get Secret, so the principal needs only ``get``
    on secrets (the Key Vault Secrets User role), never ``list``. Key Vault compares names ignoring
    case; so do file names, so two names differing only in case are refused.

    A secret that doesn't exist (HTTP 404) or whose value is empty is reported missing. Any other
    failure (access denied, a disabled secret, the vault unreachable, a credential that can't get a
    token) propagates as the Azure SDK's exception - an ``HttpResponseError`` (``status_code`` says
    which), ``ClientAuthenticationError`` or ``ServiceRequestError`` - and a response body that can't
    be trusted as Key Vault's raises :class:`~hkdfguard.cache.InvalidSecretDataError`.

    **The secret never becomes a str.** As ``hkdfguard-cache-azurekeyvault`` does, the writer's
    ``SecretClient`` has a pipeline policy that reads the response body into a bytearray of the
    library's own, takes the value out of it and encrypts it, and hands SecretClient the body with the
    value blanked; every bytearray holding the value is zeroed. What can't be zeroed: the immutable
    ``bytes`` chunks the HTTP stack reads the body in, and the stack's own buffers. Retries and
    timeouts are the client options'. On AKS, Microsoft Entra Workload Identity supplies the
    credential through ``DefaultAzureCredential`` or ``WorkloadIdentityCredential``.

    The client is synchronous: :meth:`pull_secrets` blocks the calling thread, and
    :meth:`pull_secrets_async` makes each call in a worker thread. Close the writer (or use it as a
    context manager) to close its client's HTTP session.
    """

    MAX_SECRET_NAME_LENGTH: ClassVar[int] = 127
    """The longest name Key Vault accepts for a secret."""

    def __init__(self, vault_url: str, credential: TokenCredential, protector: PipelineDataProtector, secret_names: Sequence[str], *,
                 client_options: Mapping[str, Any] | None = None) -> None:
        """A writer over the vault at ``vault_url``. No call is made until the secrets are pulled.

        :param vault_url: the vault to read secrets from: ``https://{vault}.vault.azure.net/``
        :param credential: authenticates every call to Key Vault, e.g. a managed or workload identity
        :param protector: encrypts every value read. Owned by the caller: the writer never closes it.
        :param secret_names: the secrets to pull, each a secret name with the key to read after
            ``#`` if any. Copied: a later change to the sequence isn't seen.
        :param client_options: (keyword only) keyword arguments for the writer's ``SecretClient`` -
            its ``api_version``, ``transport``, retry options, ``per_call_policies`` and
            ``per_retry_policies``; copied, so the caller's mapping (and any list in it) is left as it
            is. The capture policy is added after the application's per-retry policies, so they see
            only redacted bodies. Options that would put a policy of the application's closer to the
            network than the capture policy, or replace the pipeline, are refused: ``policies``,
            ``generated_client``, ``authentication_policy``, ``custom_hook_policy``,
            ``raw_response_hook``, ``logging_policy`` and ``http_logging_policy``.
        :raises TypeError: ``vault_url``, ``credential``, ``protector`` or ``secret_names`` is
            ``None``, or ``client_options`` isn't a mapping
        :raises ValueError: ``secret_names`` is empty, or holds ``None``, a name Key Vault can't hold
            (with a key), one whose file name isn't one FilePerSecretCache can read, or two with the
            same file name, in any case; or ``vault_url`` is empty, or ``client_options`` names an
            option the writer refuses
        """
        if vault_url is None:
            raise TypeError("vault_url must not be None.")
        if credential is None:
            raise TypeError("credential must not be None.")
        if client_options is not None and not isinstance(client_options, Mapping):
            raise TypeError("client_options must be a mapping of keyword arguments.")
        super().__init__(protector, secret_names, self.is_valid_secret_name)

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

    def close(self) -> None:
        """Closes the writer's Key Vault client and its HTTP session. Safe to call more than once."""
        self._client.close()

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """:raises azure.core.exceptions.HttpResponseError: any Key Vault failure but 404
        :raises InvalidSecretDataError: the response isn't Key Vault's JSON, or a JSON object value
            holds a key twice, or a value isn't UTF-8 text
        """
        # Filled by the capture policy, from the body in a bytearray zeroed once it returns, once per
        # attempt; what SecretClient returns holds the value blanked, so it isn't read here.
        read: dict[str, str] = {}

        def take(body: ResponseBody) -> bytes:
            read.clear()
            return SecretJsonBody.capture(body, self._receiver(requests, read), _VALUE_PROPERTY)

        capture = Capture(take)
        options: dict[str, Any] = {CAPTURE_OPTION: capture}
        try:
            self._client.get_secret(name, **options)
        except HttpResponseError as error:
            if error.status_code == 404:
                # Missing: nothing handed over.
                return
            raise

        if not capture.captured:
            raise RuntimeError("Key Vault's response didn't pass through the writer's capture policy.")
        values.update(read)
