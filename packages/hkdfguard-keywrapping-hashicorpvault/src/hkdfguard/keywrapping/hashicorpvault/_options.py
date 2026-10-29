"""Which transit secrets engine a HashiCorpVaultTransitKeyWrapper calls, and how it connects."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from datetime import timedelta
from typing import ClassVar


@dataclass(frozen=True, slots=True)
class HashiCorpVaultTransitKeyWrapperOptions:
    """Which transit secrets engine a :class:`HashiCorpVaultTransitKeyWrapper` calls, and how it
    connects. Immutable; change some values with :func:`dataclasses.replace`. The values are checked
    by the wrapper's constructor, not here."""

    MIN_RETRY_COUNT: ClassVar[int] = 3
    """The fewest retries :attr:`retry_count` allows."""

    MAX_RETRY_COUNT: ClassVar[int] = 10
    """The most retries :attr:`retry_count` allows."""

    MAX_RETRY_DELAY: ClassVar[timedelta] = timedelta(seconds=10)
    """The longest wait between retries, before the random 0-100 ms each adds."""

    mount_path: str = "transit"
    """Where the transit secrets engine is mounted, e.g. ``"transit"`` (the default) or
    ``"transit/team-a"``."""

    namespace: str | None = None
    """The Vault Enterprise namespace every request is made in, e.g. ``"team-a/prod"``; ``None`` (the
    default) for the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is."""

    timeout: timedelta = timedelta(seconds=30)
    """How long one attempt may take: getting the token, or one request and Vault's whole response.
    A call that keeps failing transiently makes up to :attr:`retry_count` + 1 attempts, with the
    waits between them."""

    retry_count: int = MIN_RETRY_COUNT
    """How many times a request that failed transiently is retried: one that got no answer
    (connection refused or reset, DNS), lost its connection mid-response, timed out, or was answered
    429 or a 5xx other than 501 (Vault answers 503 while sealed or electing a leader). Anything else -
    400 for a ciphertext that doesn't authenticate, 403, a token source's failure - isn't retried.
    Every transit call the wrapper makes is safe to repeat.
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
