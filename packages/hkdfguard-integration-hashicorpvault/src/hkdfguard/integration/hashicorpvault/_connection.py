"""How every Vault integration checks where it connects and what it sends, and how it retries."""

from __future__ import annotations

import ipaddress
import re
import ssl
from collections.abc import Buffer
from dataclasses import dataclass
from datetime import timedelta
from typing import ClassVar, Final
from urllib.parse import urlsplit

from hkdfguard.integration.hashicorpvault._tls import VaultTlsOptions, check_tls_options

TOKEN_HEADER: Final = "X-Vault-Token"  # noqa: S105 - a header name
"""The header every request carries its token in."""

MIN_RETRY_COUNT: Final = 3
"""The fewest retries of a transient failure an integration's options allow."""

MAX_RETRY_COUNT: Final = 10
"""The most retries of a transient failure an integration's options allow."""

MAX_RETRY_DELAY: Final = timedelta(seconds=10)
"""The longest wait between retries, before the random 0-100 ms each adds."""

_IPV4_LITERAL: Final = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_PATH_SEGMENT: Final = re.compile(r"[A-Za-z0-9._-]+")


@dataclass(frozen=True, slots=True, kw_only=True)
class VaultConnectionOptions:
    """What every Vault integration's options hold - the mount and namespace it calls, and how it
    connects - and their limits: the base of the transit key wrapper's and the secret cache's options,
    which add their own. Immutable; change some values with :func:`dataclasses.replace`. The values
    are checked by :func:`check_connection_options`, which the integration's constructor calls, not
    here."""

    MIN_RETRY_COUNT: ClassVar[int] = MIN_RETRY_COUNT
    """The fewest retries :attr:`retry_count` allows."""

    MAX_RETRY_COUNT: ClassVar[int] = MAX_RETRY_COUNT
    """The most retries :attr:`retry_count` allows."""

    MAX_RETRY_DELAY: ClassVar[timedelta] = MAX_RETRY_DELAY
    """The longest wait between retries, before the random 0-100 ms each adds."""

    mount_path: str
    """Where the secrets engine is mounted, e.g. ``"transit/team-a"``; each integration's options
    default it to their engine's usual mount."""

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
    a 400 or 403, a 404 naming an error, a token source's or provider's failure, the caller's
    cancellation - isn't retried. :attr:`MIN_RETRY_COUNT`-:attr:`MAX_RETRY_COUNT`."""

    retry_delay: timedelta = timedelta(milliseconds=200)
    """The wait before the first retry, doubling before each retry after it, up to
    :attr:`MAX_RETRY_DELAY`. Every wait also adds a random 0-100 ms, so many clients reconnecting at
    once don't all retry together. Zero to :attr:`MAX_RETRY_DELAY`."""

    ssl_context: ssl.SSLContext | None = None
    """The TLS settings of every https request, e.g. a context trusting a private CA
    (``ssl.create_default_context(cafile=...)``) or presenting a client certificate. ``None`` (the
    default) for ``ssl.create_default_context()``: the system's trust store, with certificate and host
    name verification. Unused for an http address. Not with :attr:`tls`."""

    tls: VaultTlsOptions | None = None
    """The TLS settings of every https request as the other ports and Vault's own variables give
    them: a CA bundle or PKCS#12 trust store, a client certificate and key from PEM or a PKCS#12 key
    store whose password is protected by the key ring, a server name. Read once, by the
    integration's constructor. ``None`` (the default) for :attr:`ssl_context`'s default. Not with
    :attr:`ssl_context`."""


def check_connection_options(options: VaultConnectionOptions) -> None:
    """Refuses connection options no integration accepts.

    :raises TypeError: ``options`` isn't :class:`VaultConnectionOptions`, or holds a value of the
        wrong type
    :raises ValueError: a mount path or namespace that isn't a Vault path (:func:`is_valid_path`), a
        timeout that isn't positive, a retry count or delay out of range, or both ``ssl_context`` and
        ``tls``
    """
    if not isinstance(options, VaultConnectionOptions):
        raise TypeError("options must be VaultConnectionOptions.")
    if not isinstance(options.timeout, timedelta) or not isinstance(options.retry_delay, timedelta):
        raise TypeError("timeout and retry_delay must be timedeltas.")
    if not isinstance(options.retry_count, int) or isinstance(options.retry_count, bool):
        raise TypeError("retry_count must be an int.")
    check_tls_options(options.ssl_context, options.tls)
    if not is_valid_path(options.mount_path):
        raise ValueError(f"The mount path '{options.mount_path}' isn't a Vault path.")
    if options.namespace is not None and not is_valid_path(options.namespace):
        raise ValueError(f"The namespace '{options.namespace}' isn't a Vault path.")
    if options.timeout <= timedelta(0):
        raise ValueError(f"The timeout must be positive; it is {options.timeout}.")
    if not MIN_RETRY_COUNT <= options.retry_count <= MAX_RETRY_COUNT:
        raise ValueError(f"The retry count must be {MIN_RETRY_COUNT}-{MAX_RETRY_COUNT}; it is {options.retry_count}.")
    if not timedelta(0) <= options.retry_delay <= MAX_RETRY_DELAY:
        raise ValueError(f"The retry delay must be zero to {MAX_RETRY_DELAY}; it is {options.retry_delay}.")


def api_base(address: str) -> tuple[bool, str, int | None, str]:
    """Whether Vault's address is https, its host and port, and the path of /v1/ under it.

    :raises TypeError: ``address`` isn't a ``str``
    :raises ValueError: see :func:`parse_address`
    """
    https, host, port, prefix = parse_address(address)
    return https, host, port, prefix + "/v1/"


def parse_address(address: str, *, allow_unencrypted_http: bool | None = None) -> tuple[bool, str, int | None, str]:
    """Whether Vault's address is https, its host and port, and its path with no trailing '/' - the
    prefix of every request's path (Vault behind a reverse proxy).

    :param allow_unencrypted_http: ``True`` allows http anywhere, not only on loopback; ``None`` for
        a caller with no such option, which the refusal then doesn't mention
    :raises TypeError: ``address`` isn't a ``str``
    :raises ValueError: ``address`` is a unix socket or isn't absolute, would send tokens in the
        clear (http anywhere but loopback, unless allowed), or holds credentials, a query or a fragment
    """
    if not isinstance(address, str):
        raise TypeError("address must be a str.")
    parts = urlsplit(address)
    scheme = parts.scheme.lower()
    if scheme == "unix":
        raise ValueError(f"Vault's address '{address}' is a unix socket, which can't be connected to here: reach Vault (or its agent) "
                         "over https, or http on loopback.")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        host, port = None, None
    if not scheme or not parts.netloc or not host:
        raise ValueError(f"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.")

    if scheme != "https" and not (scheme == "http" and (allow_unencrypted_http or is_loopback(host))):
        option = "" if allow_unencrypted_http is None else ", or with allow_unencrypted_http"
        raise ValueError(f"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or "
                         f"dev server){option}, since every request carries a token.")
    if "@" in parts.netloc or "?" in address or "#" in address:
        raise ValueError(f"Vault's address '{address}' must not hold credentials, a query or a fragment.")

    return scheme == "https", host, port, parts.path.rstrip("/")


def is_valid_path(path: object) -> bool:
    """Whether ``path`` is '/'-separated segments, each :func:`is_valid_segment`: a path that stays
    where it's put."""
    return isinstance(path, str) and all(is_valid_segment(segment) for segment in path.split("/"))


def is_valid_segment(segment: str) -> bool:
    """Whether ``segment`` is letters, digits, '.', '_' and '-', and neither "." nor ".."."""
    return _PATH_SEGMENT.fullmatch(segment) is not None and segment not in {".", ".."}


def is_valid_token(token: Buffer) -> bool:
    """Whether ``token`` can go in a header: non-empty printable ASCII, with no spaces."""
    view = memoryview(token).cast("B")
    return len(view) > 0 and all(0x21 <= b <= 0x7E for b in view)


def retry_delay(base_delay: timedelta, retry: int, jitter_millis: int) -> timedelta:
    """The wait before retry number ``retry`` (0 for the first): ``base_delay``, doubled for each
    retry before it, at most :data:`MAX_RETRY_DELAY` - plus ``jitter_millis``."""
    backoff = MAX_RETRY_DELAY if retry >= 30 else base_delay * (1 << retry)
    return min(backoff, MAX_RETRY_DELAY) + timedelta(milliseconds=jitter_millis)


def is_loopback(host: str) -> bool:
    """Whether ``host`` is localhost or an IP literal on the loopback network. Only literals are
    parsed, so no name is ever resolved."""
    if host.lower() == "localhost":
        return True
    if ":" not in host and not _IPV4_LITERAL.fullmatch(host):
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
