"""Which KV secrets engine a HashiCorpVaultSecretCache reads, and how it connects."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import ClassVar

from hkdfguard.hashicorpvault.common import MAX_RETRY_COUNT, MAX_RETRY_DELAY, MIN_RETRY_COUNT


class VaultKvVersion(Enum):
    """The version of a KV secrets engine, which decides its read path and response shape."""

    V1 = 1
    """KV version 1: one unversioned value per path, read at ``{mount}/{path}``."""

    V2 = 2
    """KV version 2: versioned secrets, read at ``{mount}/data/{path}``; the latest version is read."""


@dataclass(frozen=True, slots=True)
class HashiCorpVaultSecretCacheOptions:
    """Which KV secrets engine a :class:`HashiCorpVaultSecretCache` reads, and how it connects.
    Immutable; change some values with :func:`dataclasses.replace`. The values are checked by the
    cache's constructor, not here."""

    MIN_RETRY_COUNT: ClassVar[int] = MIN_RETRY_COUNT
    """The fewest retries :attr:`retry_count` allows."""

    MAX_RETRY_COUNT: ClassVar[int] = MAX_RETRY_COUNT
    """The most retries :attr:`retry_count` allows."""

    MAX_RETRY_DELAY: ClassVar[timedelta] = MAX_RETRY_DELAY
    """The longest wait between retries, before the random 0-100 ms each adds."""

    mount_path: str = "secret"
    """Where the KV secrets engine is mounted, e.g. ``"secret"`` (the default) or ``"kv/team-a"``."""

    kv_version: VaultKvVersion = VaultKvVersion.V2
    """The engine's version."""

    default_key: str = "value"
    """The key read from a secret looked up without one: ``"myapp/db"`` reads this key of the secret
    at myapp/db, while ``"myapp/db#password"`` reads its password key."""

    namespace: str | None = None
    """The Vault Enterprise namespace every read is made in, e.g. ``"team-a/prod"``; ``None`` (the
    default) for the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is."""

    timeout: timedelta = timedelta(seconds=30)
    """How long one attempt may take: getting the token, or one request and Vault's whole response.
    A fetch that keeps failing transiently makes up to :attr:`retry_count` + 1 attempts, with the
    waits between them."""

    retry_count: int = MIN_RETRY_COUNT
    """How many times a request that failed transiently is retried: one that got no answer
    (connection refused or reset, DNS), lost its connection mid-response, timed out, or was answered
    429 or a 5xx other than 501 (Vault answers 503 while sealed or electing a leader). Anything else -
    403, a 404 naming an error, a token provider's failure, the caller's cancellation - isn't retried.
    :attr:`MIN_RETRY_COUNT`-:attr:`MAX_RETRY_COUNT`."""

    retry_delay: timedelta = timedelta(milliseconds=200)
    """The wait before the first retry, doubling before each retry after it, up to
    :attr:`MAX_RETRY_DELAY`. Every wait also adds a random 0-100 ms, so many clients reconnecting at
    once don't all retry together. Zero to :attr:`MAX_RETRY_DELAY`."""

    ssl_context: ssl.SSLContext | None = None
    """The TLS settings of every https request, e.g. a context trusting a private CA
    (``ssl.create_default_context(cafile=...)``) or presenting a client certificate. ``None`` (the
    default) for ``ssl.create_default_context()``: the system's trust store, with certificate and host
    name verification. Unused for an http address."""
