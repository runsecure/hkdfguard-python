"""The Vault token a HashiCorpVaultSecretCache reads with, handed over protected."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Buffer

from hkdfguard.abstractions import DataProtector


class VaultTokenProvider(ABC):
    """Supplies the Vault token every read is made with, protected: as the cache's token protector
    encrypted it (``token_protector.encrypt(token)``), never the token itself. Getting that token -
    logging in with AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires
    - is the provider's job, not the cache's, so any auth method can sit behind the cache.
    :class:`StaticVaultToken` is a token you already hold.

    Asked once per fetch; the cache never keeps the token, and decrypts it only to put it in that
    fetch's requests. A token that isn't protected so fails the fetch. The cache waits at most its
    :attr:`~HashiCorpVaultSecretCacheOptions.timeout` for the provider; one that takes longer fails
    the fetch with ``TimeoutError``. A provider's failure fails the fetch as it is, and isn't retried:
    retrying a login is the provider's own business.
    """

    @abstractmethod
    def get_token(self) -> str:
        """The token to make the next read with, protected by the cache's token protector. Called
        by decrypt and find_max_decrypted_length's fetches, on a thread of its own."""

    async def get_token_async(self) -> str:
        """:meth:`get_token` without blocking the event loop, for decrypt_async's fetches; cancelled
        if it hasn't returned within the timeout, or the lookup that started the fetch is cancelled.
        The default runs get_token in a worker thread; a provider with an asyncio client overrides it."""
        return await asyncio.to_thread(self.get_token)


class StaticVaultToken(VaultTokenProvider):
    """A token issued elsewhere - VAULT_TOKEN, say - held only in protected form. Nothing renews or
    replaces it, so once it expires or is revoked every fetch fails with 403."""

    __slots__ = ("_protected_token",)

    def __init__(self, protected_token: str) -> None:
        """:param protected_token: the token as the cache's token protector protected it
            (``token_protector.encrypt(token)``), never the token itself; see :meth:`protect`
        :raises TypeError: ``protected_token`` is ``None``
        :raises ValueError: ``protected_token`` is empty or whitespace
        """
        if protected_token is None:
            raise TypeError("protected_token must not be None.")
        if not protected_token.strip():
            raise ValueError("The protected token must not be empty or whitespace.")
        self._protected_token = protected_token

    @staticmethod
    def protect(token_protector: DataProtector, token: str) -> StaticVaultToken:
        """Protects ``token`` with ``token_protector`` - the protector the cache is given - and holds
        only the result. ``token`` is a ``str``, which Python can't erase: read it from the
        environment once, here, and keep no other reference to it.

        :raises TypeError: ``token_protector`` or ``token`` is ``None``
        :raises ValueError: ``token`` is empty, or isn't printable ASCII without spaces
        """
        if token_protector is None:
            raise TypeError("token_protector must not be None.")
        if token is None:
            raise TypeError("token must not be None.")
        if not token or not all("!" <= c <= "~" for c in token):
            raise ValueError("A Vault token is printable ASCII, with no spaces.")
        return StaticVaultToken(token_protector.encrypt(token))

    def get_token(self) -> str:
        return self._protected_token

    async def get_token_async(self) -> str:
        return self._protected_token


def is_valid_token(token: Buffer) -> bool:
    """Whether ``token`` can go in a header: non-empty printable ASCII, with no spaces."""
    view = memoryview(token).cast("B")
    return len(view) > 0 and all(0x21 <= b <= 0x7E for b in view)
