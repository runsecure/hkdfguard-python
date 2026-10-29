"""The exception a HashiCorpVaultSecretCache raises for Vault's refusals."""


class VaultRequestError(Exception):
    """Vault answered a read with a status other than success or "nothing at this path": 403 for a
    token that is invalid or not allowed to read the path, a 404 naming an error (no such mount), 503
    while Vault is sealed, a redirect, and so on - the counterpart of Java's VaultRequestException
    and the HttpRequestException .NET's cache raises. Its message holds the path read, the status and
    the errors Vault listed, never the token."""

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
