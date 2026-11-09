"""The secret pipeline writer over one HashiCorp Vault KV secrets engine."""

from __future__ import annotations

import asyncio
import http.client
from collections.abc import MutableMapping, Sequence
from typing import ClassVar

from hkdfguard.abstractions import ArrayUtility, ObjectClosedError, PipelineDataProtector
from hkdfguard.cache import RemoteSecretCache, SecretJsonBody
from hkdfguard.integration.hashicorpvault import (
    MAX_TOKEN_LENGTH,
    VaultRequestError,
    VaultTokenSource,
    api_base,
    check_connection_options,
    copy_token_within,
    is_valid_path,
    is_valid_token,
)
from hkdfguard.integration.hashicorpvault._errors import MAX_ERROR_BODY_LENGTH, describe_status, read_errors
from hkdfguard.integration.hashicorpvault._http import Abandon, DeadlineBody, VaultConnector, exchange, put_token, read_body, with_retries
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest
from hkdfguard.pipeline.hashicorpvault._options import HashiCorpVaultPipelineOptions, VaultKvVersion


class HashiCorpVaultSecretPipelineWriter(SecretPipelineWriter):
    """The end of a provisioning pipeline: pulls a fixed list of secrets from one HashiCorp Vault KV
    secrets engine, encrypts each with a :class:`~hkdfguard.abstractions.PipelineDataProtector` as
    soon as it is read, and writes them out as one file per secret - the folder layout
    :class:`~hkdfguard.cache.FilePerSecretCache` reads at runtime. It is independent of
    ``hkdfguard-cache-hashicorpvault``'s runtime cache, and of any key ring. Naming, encrypting,
    keeping and writing are :class:`~hkdfguard.pipeline.SecretPipelineWriter`'s::

        with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector,
              StaticVaultTokenSource(os.environ["VAULT_TOKEN"]) as token,
              HashiCorpVaultSecretPipelineWriter(address, token, protector, ["myapp/db#username", "myapp/db#password", "myapp/api"]) as writer):
            writer.pull_secrets()
            writer.write_protected_secret_files(r"C:\\HkdfGuardSecrets\\myapp")
            # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.

    A secret name is a path within the engine, with the key to read after ``#``:
    ``"myapp/db#password"`` reads the password key of the secret at myapp/db, and ``"myapp/db"``
    reads its :attr:`~HashiCorpVaultPipelineOptions.default_key` (written as myapp__db__password and
    myapp__db). A string is read as its text; a number, true or false as its JSON text. Each secret
    is read once (GET on its path; for KV version 2, its latest version), so the token's policy needs
    only ``read`` on the paths it reads, never ``list``. A path that isn't one - segments of ASCII
    letters, digits, ``-``, ``_`` and ``.``, no segment ``.`` or ``..``, at most
    :attr:`MAX_SECRET_NAME_LENGTH` characters - is refused.

    A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
    deleted or destroyed, or that has no such key, or whose value there is empty or isn't a value, is
    reported missing. Any other answer (403 for a token that is invalid or not allowed to read the
    path, a 404 naming an error such as a mount that doesn't exist, a redirect, Vault sealed) raises
    :class:`~hkdfguard.integration.hashicorpvault.VaultRequestError` carrying Vault's status and
    errors. A request that fails transiently - no answer, a connection lost mid-response, a timed-out
    attempt, 429 or a 5xx other than 501 - is retried as the options say; once the retries are spent,
    a failure without an answer raises its ``OSError`` (``TimeoutError`` for a timed-out attempt), or
    the ``http.client.HTTPException`` of an answer that isn't HTTP. A response that isn't Vault's JSON
    raises :class:`~hkdfguard.cache.InvalidSecretDataError`.

    The token comes from a :class:`~hkdfguard.integration.hashicorpvault.VaultTokenSource`, as the
    transit key wrapper's does - in plaintext, since a pipeline has no key ring to protect it with -
    copied into a bytearray for each secret's read and zeroed once its requests have been sent (a
    source's failure isn't retried; one that supplies no token, or one that isn't a token, fails the
    pull with ``RuntimeError`` without a request). ``http.client`` copies each header into ``bytes``
    of its own, which Python can't zero. Requests go to ``/v1/`` under Vault's address, which must be
    https except on loopback, through ``http.client``, each on a connection of its own: no proxy, and
    no redirect is ever followed, which would carry the token elsewhere.

    The response body is read straight off the socket into a bytearray of the library's own, and
    each value unescaped into another and encrypted from there
    (:class:`~hkdfguard.cache.SecretJsonBody`); every bytearray holding it is zeroed. What can't be
    zeroed is below that: the socket's and OpenSSL's buffers, and ``http.client``'s own for a chunked
    response. :meth:`pull_secrets` blocks the calling thread; :meth:`pull_secrets_async` makes each
    read in a worker thread, and cancelling it abandons the read in flight (its socket is shut down,
    and no retry follows).
    """

    MAX_SECRET_NAME_LENGTH: ClassVar[int] = 512
    """The longest secret path read."""

    def __init__(self, address: str, token_source: VaultTokenSource, protector: PipelineDataProtector, secret_names: Sequence[str], *,
                 options: HashiCorpVaultPipelineOptions | None = None) -> None:
        """:param address: Vault's address, e.g. ``https://vault.example.com:8200`` - the same value
            as VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev
            server). A path, if any, is kept as a prefix (Vault behind a reverse proxy).
        :param token_source: supplies the token every read is made with. Owned by the caller: the
            writer never closes it.
        :param protector: encrypts every value read. Owned by the caller: the writer never closes it.
        :param secret_names: the secrets to pull, each a path with the key to read after ``#`` if
            any. Copied: a later change to the sequence isn't seen.
        :param options: the KV engine read and how to reach it; ``None`` for KV version 2 at
            ``secret``, reading the key ``value``
        :raises TypeError: ``address``, ``token_source``, ``protector`` or ``secret_names`` is
            ``None``, or an option is of the wrong type (a KV version that isn't a
            :class:`VaultKvVersion` among them)
        :raises ValueError: ``secret_names`` is empty, or holds ``None``, a name that isn't a path
            (with a key), one whose file name isn't one FilePerSecretCache can read, or two with the
            same file name, in any case; ``address`` isn't https (or http on loopback), or holds
            credentials, a query or a fragment; or the mount path, default key or namespace isn't
            one, the timeout isn't positive, the retry count isn't 3-10, the retry delay isn't zero
            to 10 seconds, or the TLS options can't be read
        """
        if address is None:
            raise TypeError("address must not be None.")
        if token_source is None:
            raise TypeError("token_source must not be None.")
        if not isinstance(token_source, VaultTokenSource):
            raise TypeError("token_source must be a VaultTokenSource.")
        if options is None:
            options = HashiCorpVaultPipelineOptions()
        if not isinstance(options, HashiCorpVaultPipelineOptions):
            raise TypeError("options must be HashiCorpVaultPipelineOptions.")
        super().__init__(protector, secret_names, self.is_valid_secret_name, options.default_key)
        https, host, port, v1_path = api_base(address)
        _check(options)

        self._token_source = token_source
        self._timeout = options.timeout
        self._retry_count = options.retry_count
        self._retry_delay = options.retry_delay
        self._namespace = options.namespace
        if options.kv_version is VaultKvVersion.V2:
            self._read_base = f"{v1_path}{options.mount_path}/data/"
            self._data_path: tuple[str, ...] = ("data", "data")
        else:
            self._read_base = f"{v1_path}{options.mount_path}/"
            self._data_path = ("data",)
        # Follows no redirects: one would carry X-Vault-Token wherever it points.
        self._connector = VaultConnector(https, host, port, options.timeout, options.ssl_context, options.tls)
        self._closed = False

    @classmethod
    def is_valid_secret_name(cls, name: str | None) -> bool:
        """Whether ``name`` is a secret's path, as Vault takes it: ``/``-separated segments of ASCII
        letters, digits, ``-``, ``_`` and ``.``, no segment ``.`` or ``..``, at most
        :attr:`MAX_SECRET_NAME_LENGTH` characters."""
        return name is not None and 0 < len(name) <= cls.MAX_SECRET_NAME_LENGTH and is_valid_path(name)

    def close(self) -> None:
        """Stops the writer reading Vault: a pull afterwards fails with
        :class:`~hkdfguard.abstractions.ObjectClosedError`. What was pulled can still be written.
        Every request has a connection of its own, closed as it completes, so there is nothing else
        to release; the token source isn't closed."""
        self._closed = True

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """:raises VaultRequestError: Vault refused the read
        :raises OSError: Vault couldn't be reached, or the read timed out
        :raises InvalidSecretDataError: the response isn't Vault's JSON, or holds a key twice or a
            value that isn't UTF-8 text
        :raises RuntimeError: the token source supplied no token
        """
        self._read_secret_within(name, requests, values, _abandon())

    async def _read_secret_async(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        abandon = _abandon()
        read: dict[str, str] = {}
        try:
            await asyncio.to_thread(self._read_secret_within, name, requests, read, abandon)
        except asyncio.CancelledError:
            # The thread can't be stopped, but its socket can be shut down, and it retries no more.
            abandon.abandon()
            raise
        values.update(read)

    def _read_secret_within(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str], abandon: Abandon) -> None:
        if self._closed:
            raise ObjectClosedError("This HashiCorp Vault secret pipeline writer has been closed.")
        token = bytearray(MAX_TOKEN_LENGTH)
        try:
            # Asked for once per secret; a source's failure is its own to retry, so isn't retried here.
            token_length = copy_token_within(self._token_source, token, self._timeout)
            if not 0 < token_length <= MAX_TOKEN_LENGTH or not is_valid_token(memoryview(token)[:token_length]):
                raise RuntimeError("The Vault token source supplied no token, or one that isn't a token: printable ASCII, with no spaces.")
            token_view = memoryview(token)[:token_length]

            # An attempt encrypts nothing until it has read the whole body, and a parse failure isn't
            # transient, so a failed attempt hands nothing over.
            read = with_retries(lambda: self._read(name, token_view, requests, abandon), self._retry_count, self._retry_delay,
                                stopped=lambda: abandon.abandoned or self._closed, wait=abandon.wait)
            values.update(read)
        finally:
            ArrayUtility.zero_memory(token)

    def _read(self, path: str, token: memoryview, requests: Sequence[SecretRequest], abandon: Abandon) -> dict[str, str]:
        # One attempt: one request, with the token - checked printable ASCII, so handed over as it is;
        # http.client copies it into the header line - and Vault's whole response, within the
        # attempt's timeout.
        def headers(connection: http.client.HTTPConnection) -> None:
            put_token(connection, token)

        with exchange(self._connector, "GET", self._read_base + path, self._namespace, self._timeout, headers=headers,
                      abandon=abandon, description=f"the read of '{path}'") as (status, body):
            return self._read_response(path, status, body, requests)

    def _read_response(self, path: str, status: int, body: DeadlineBody, requests: Sequence[SecretRequest]) -> dict[str, str]:
        values: dict[str, str] = {}
        if 200 <= status < 300:
            SecretJsonBody.capture_keys(body, self._receiver(requests, values), self._data_path)
            return values

        # A refusal holds no secret: read whole, up to the limit, and its errors made str.
        buffer = bytearray(MAX_ERROR_BODY_LENGTH)
        errors = read_errors(memoryview(buffer)[:read_body(body, buffer)])

        # Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        # secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        # (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
        if status == 404 and errors == []:
            return values

        raise VaultRequestError(f"Vault refused to read '{path}': {describe_status(status, errors)}", status)


def _abandon() -> Abandon:
    return Abandon("The read from Vault was abandoned: the pull that started it was cancelled.")


def _check(options: HashiCorpVaultPipelineOptions) -> None:
    if not isinstance(options.kv_version, VaultKvVersion):
        raise TypeError("kv_version must be a VaultKvVersion.")
    check_connection_options(options)
    # A key SecretJsonBody hands over: one a JSON member name can be, as a runtime cache reads it.
    if not RemoteSecretCache.is_valid_key(options.default_key):
        raise ValueError(f"The default key '{options.default_key}' isn't a key: 1-{RemoteSecretCache.MAX_KEY_LENGTH} printable ASCII "
                         "characters other than space, '!' and '#'.")
