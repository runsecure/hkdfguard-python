"""The exception Vault's refusals are reported as."""

from __future__ import annotations


class VaultRequestError(Exception):
    """Vault answered a request with a status it doesn't treat as success: 400 for a transit
    ciphertext that doesn't authenticate or a key that doesn't exist, 403 for a token that is invalid
    or not allowed the path, a KV 404 naming an error (no such mount), 503 while Vault is sealed, a
    redirect, and so on - the counterpart of Java's VaultRequestException and .NET's
    HttpRequestException. A cache raises it as is; a key wrapper raises it as the ``__cause__`` of its
    :class:`~hkdfguard.abstractions.CryptographicError`. Its message holds the status and the errors
    Vault listed, never the token, a secret or a DEK."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self._status_code = status_code

    @property
    def status_code(self) -> int:
        """The HTTP status Vault answered with."""
        return self._status_code

    @property
    def is_transient(self) -> bool:
        """Whether another attempt may be answered differently: 429 (rate limited) or a 5xx other
        than 501 (Vault answers 503 while sealed or electing a leader)."""
        return self._status_code == 429 or (self._status_code >= 500 and self._status_code != 501)
