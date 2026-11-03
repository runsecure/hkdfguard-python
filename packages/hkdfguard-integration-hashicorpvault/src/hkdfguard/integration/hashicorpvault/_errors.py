"""The exceptions Vault's refusals, and answers that aren't what was expected, are reported as."""

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


class VaultResponseError(VaultRequestError):
    """Vault answered a :class:`~hkdfguard.integration.hashicorpvault.VaultClient` request with a
    status outside 200-399 - vault-client-go's ResponseError. A request that gets no answer (Vault
    unreachable, say) fails with the ``OSError`` the connection raised instead."""

    def __init__(self, message: str, status_code: int, errors: list[str], raw_response_bytes: bytes | None, request_method: str,  # noqa: PLR0917 - mirrors the other ports
                 request_url: str) -> None:
        super().__init__(message, status_code)
        self._errors = tuple(errors)
        self._raw_response_bytes = raw_response_bytes
        self._request_method = request_method
        self._request_url = request_url

    @property
    def errors(self) -> list[str]:
        """The errors Vault listed in its response; empty if it listed none."""
        return list(self._errors)

    @property
    def raw_response_bytes(self) -> bytes | None:
        """The response body, when it held no errors to list; ``None`` otherwise."""
        return self._raw_response_bytes

    @property
    def request_method(self) -> str:
        """The method of the request Vault refused."""
        return self._request_method

    @property
    def request_url(self) -> str:
        """The URL of the request Vault refused, without its token (which is never in a URL)."""
        return self._request_url


class VaultRedirectError(VaultRequestError):
    """Vault answered a :class:`~hkdfguard.integration.hashicorpvault.VaultClient` request with a
    redirect (301, 302 or 307) the client wouldn't follow: redirects are off
    (:attr:`~hkdfguard.integration.hashicorpvault.VaultClientOptions.follow_redirects`), it was the
    request's second, it would go from https to http, or its location couldn't be read -
    vault-client-go's RedirectError."""

    def __init__(self, status_code: int, reason: str, redirect_location: str | None, request_method: str, request_url: str) -> None:
        super().__init__(f"{status_code}: redirect error: {reason}", status_code)
        self._reason = reason
        self._redirect_location = redirect_location
        self._request_method = request_method
        self._request_url = request_url

    @property
    def reason(self) -> str:
        """Why the redirect wasn't followed."""
        return self._reason

    @property
    def redirect_location(self) -> str | None:
        """Where the redirect pointed, if that could be read; ``None`` otherwise."""
        return self._redirect_location

    @property
    def request_method(self) -> str:
        """The method of the redirected request."""
        return self._request_method

    @property
    def request_url(self) -> str:
        """The URL of the redirected request."""
        return self._request_url


class VaultJsonError(ValueError):
    """A response Vault returned isn't the JSON a
    :class:`~hkdfguard.integration.hashicorpvault.VaultClient` method reads: malformed, or a value of
    another type where a model expects an object, a number or a date-time. Its message never quotes
    the response, which may hold a secret."""
