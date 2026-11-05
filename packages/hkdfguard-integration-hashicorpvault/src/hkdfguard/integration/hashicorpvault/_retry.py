"""When and how often a VaultClient retries, and how fast it may send: vault-client-go's
RetryConfiguration and rate limiter."""

from __future__ import annotations

import math
import secrets
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

type RetryPolicy = Callable[[int, BaseException | None], bool]
"""Whether to retry an attempt: called with the status Vault answered with (0 if no answer came)
and what the attempt failed with when no answer came (``None`` otherwise)."""

type Backoff = Callable[[timedelta, timedelta, int, int], timedelta]
"""How long to wait before a retry: called with :attr:`VaultRetryOptions.retry_wait_min` and
:attr:`~VaultRetryOptions.retry_wait_max`, the attempt that failed (0 for the first) and the status
it was answered with (0 if none)."""


def default_retry_policy(status_code: int, failure: BaseException | None) -> bool:
    """go-retryablehttp's default policy, plus 412 (which Vault answers when an X-Vault-Index state
    isn't there yet): retry when no answer came - unless the server's certificate was refused, which
    another attempt would meet again - and on 412, 429, and any 5xx but 501."""
    if failure is not None:
        return not _is_certificate_failure(failure)
    return status_code in {0, 412, 429} or (status_code >= 500 and status_code != 501)


def linear_jitter_backoff(minimum: timedelta, maximum: timedelta, attempt: int, status_code: int) -> timedelta:
    """go-retryablehttp's LinearJitterBackoff: a random wait between ``minimum`` and ``maximum``,
    times the number of attempts made so far - spread out so clients retrying together don't all
    arrive together."""
    attempts = attempt + 1
    if maximum <= minimum:
        return minimum * attempts
    span = (maximum - minimum) // timedelta(microseconds=1)
    return (minimum + timedelta(microseconds=secrets.randbelow(span))) * attempts


@dataclass(frozen=True, kw_only=True, slots=True)
class VaultRetryOptions:
    """When and how often a :class:`VaultClient` retries a failed request: vault-client-go's
    RetryConfiguration (its go-retryablehttp client). Retries happen within the request's timeout,
    and the request is sent whole each time - its body is held in memory for that."""

    retry_wait_min: timedelta = timedelta(seconds=1)
    """The least time to wait before a retry - VAULT_RETRY_WAIT_MIN."""
    retry_wait_max: timedelta = timedelta(milliseconds=1500)
    """The most time to wait before a retry - VAULT_RETRY_WAIT_MAX."""
    retry_max: int = 2
    """How many times to retry - VAULT_MAX_RETRIES. Zero or less for none. Default 2: three tries in all."""
    check_retry: RetryPolicy | None = None
    """Whether to retry; ``None`` for :func:`default_retry_policy`."""
    backoff: Backoff | None = None
    """How long to wait before a retry; ``None`` for :func:`linear_jitter_backoff`."""


class VaultRateLimiter:
    """A token bucket, as Go's rate.Limiter: up to :attr:`burst` requests at once, then
    :attr:`requests_per_second`. A request waits for its turn rather than failing. Thread-safe;
    several clients may share one."""

    __slots__ = ("_burst", "_lock", "_requests_per_second", "_tokens", "_updated")

    def __init__(self, requests_per_second: float, burst: int) -> None:
        """:param requests_per_second: how many requests a second, once the burst is spent; may be fractional
        :param burst: how many requests may go at once
        :raises ValueError: ``requests_per_second`` isn't a positive number, or ``burst`` isn't positive
        """
        if isinstance(requests_per_second, bool) or not isinstance(requests_per_second, (int, float)) \
                or not math.isfinite(requests_per_second) or requests_per_second <= 0:
            raise ValueError(f"The rate must be a positive number; it is {requests_per_second}.")
        if isinstance(burst, bool) or not isinstance(burst, int) or burst < 1:
            raise ValueError(f"The burst must be at least 1; it is {burst}.")
        self._requests_per_second = float(requests_per_second)
        self._burst = burst
        self._tokens = float(burst)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    @property
    def requests_per_second(self) -> float:
        """Requests a second, once the burst is spent."""
        return self._requests_per_second

    @property
    def burst(self) -> int:
        """Requests that may go at once."""
        return self._burst

    def acquire(self, max_wait: float, wait: Callable[[float], bool]) -> bool:
        """Waits until a request may be sent, and counts it - unless the wait would take longer than
        ``max_wait`` seconds, when it returns ``False`` at once without counting it.

        :param wait: waits the seconds given, returning ``True`` if the request was abandoned
            meanwhile - when its turn is given back and ``False`` returned
        """
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self._burst, self._tokens + (now - self._updated) * self._requests_per_second)
            self._updated = now
            delay = 0.0 if self._tokens >= 1 else (1 - self._tokens) / self._requests_per_second
            if delay > max_wait:
                return False
            # Reserved now, waited for after: a request behind it waits for its own turn as well.
            self._tokens -= 1

        if delay <= 0 or not wait(delay):
            return True
        # The request won't be sent: give its turn back.
        with self._lock:
            self._tokens = min(self._burst, self._tokens + 1)
        return False


def _is_certificate_failure(failure: BaseException) -> bool:
    error: BaseException | None = failure
    while error is not None:
        if isinstance(error, ssl.SSLCertVerificationError):
            return True
        error = error.__cause__ or error.__context__
    return False
