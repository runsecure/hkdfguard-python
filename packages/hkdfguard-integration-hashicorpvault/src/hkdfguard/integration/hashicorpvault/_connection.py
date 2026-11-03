"""How every Vault integration checks where it connects and what it sends, and how it retries."""

from __future__ import annotations

import ipaddress
import re
import ssl
from collections.abc import Buffer
from datetime import timedelta
from typing import Final, Protocol
from urllib.parse import urlsplit

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


class VaultConnectionOptions(Protocol):
    """The options every Vault integration has: which mount and namespace it calls, and how it
    connects."""

    @property
    def mount_path(self) -> str: ...

    @property
    def namespace(self) -> str | None: ...

    @property
    def timeout(self) -> timedelta: ...

    @property
    def retry_count(self) -> int: ...

    @property
    def retry_delay(self) -> timedelta: ...

    @property
    def ssl_context(self) -> ssl.SSLContext | None: ...


def check_connection_options(options: VaultConnectionOptions) -> None:
    """Refuses connection options no integration accepts.

    :raises TypeError: a value of the wrong type
    :raises ValueError: a mount path or namespace that isn't a Vault path (:func:`is_valid_path`), a
        timeout that isn't positive, or a retry count or delay out of range
    """
    if not isinstance(options.timeout, timedelta) or not isinstance(options.retry_delay, timedelta):
        raise TypeError("timeout and retry_delay must be timedeltas.")
    if not isinstance(options.retry_count, int) or isinstance(options.retry_count, bool):
        raise TypeError("retry_count must be an int.")
    if options.ssl_context is not None and not isinstance(options.ssl_context, ssl.SSLContext):
        raise TypeError("ssl_context must be an ssl.SSLContext.")
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
    :raises ValueError: ``address`` isn't absolute, would send tokens in the clear (http anywhere
        but loopback), or holds credentials, a query or a fragment
    """
    if not isinstance(address, str):
        raise TypeError("address must be a str.")
    parts = urlsplit(address)
    host = parts.hostname
    if not parts.scheme or not parts.netloc or not host:
        raise ValueError(f"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.")

    scheme = parts.scheme.lower()
    if scheme != "https" and not (scheme == "http" and _is_loopback(host, parts.netloc)):
        raise ValueError(f"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or "
                         "dev server), since every request carries a token.")
    if "@" in parts.netloc or "?" in address or "#" in address:
        raise ValueError(f"Vault's address '{address}' must not hold credentials, a query or a fragment.")

    return scheme == "https", host, parts.port, parts.path.rstrip("/") + "/v1/"


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


def _is_loopback(host: str, netloc: str) -> bool:
    # localhost, or an IP literal on the loopback network. Only literals are parsed, so no name is
    # ever resolved.
    if host.lower() == "localhost":
        return True
    if not netloc.rsplit("@", maxsplit=1)[-1].startswith("[") and not _IPV4_LITERAL.fullmatch(host):
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
