"""The Vault token a HashiCorpVaultTransitKeyWrapper makes its requests with, copied into memory the
wrapper zeroes."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Buffer
from datetime import timedelta
from types import TracebackType
from typing import Final, Self

from hkdfguard.abstractions import ArrayUtility
from hkdfguard.hashicorpvault.common import is_valid_token

MAX_TOKEN_LENGTH: Final = 2048
"""The longest token a :class:`VaultTokenSource` may supply, in bytes."""


class VaultTokenSource(ABC):
    """Supplies the Vault token every transit request is made with. Getting that token - logging in
    with AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires - is the
    source's job, not the wrapper's, so any auth method can sit behind it.
    :class:`StaticVaultTokenSource` is a token you already hold.

    The token is copied into a bytearray the wrapper owns and zeroes once the request has been sent,
    rather than returned as a ``str`` that would live until collected. (The cache's
    ``VaultTokenProvider`` hands its token over protected by the key ring instead; a key wrapper
    can't, since it runs before there is a key ring.)

    Asked once per wrap, unwrap or generate - not per retry - on a thread of its own. The wrapper waits
    at most its :attr:`~HashiCorpVaultTransitKeyWrapperOptions.timeout` for it; a source that takes
    longer fails the call with ``TimeoutError``, and whatever it copies afterwards is zeroed rather
    than used. A source's failure fails the call as it is, and isn't retried: retrying a login is the
    source's own business.
    """

    @abstractmethod
    def copy_token(self, destination: memoryview) -> int:
        """Copies the token to make the next request with into ``destination``. A token that is empty,
        over :data:`MAX_TOKEN_LENGTH` bytes, or isn't printable ASCII without spaces fails the call.

        :param destination: where to write the token: a writable view of :data:`MAX_TOKEN_LENGTH` bytes
        :returns: the number of bytes written
        """


class StaticVaultTokenSource(VaultTokenSource):
    """A token issued elsewhere - VAULT_TOKEN, say - held in a bytearray and zeroed on :meth:`close`.
    Nothing renews or replaces it, so once it expires or is revoked every request fails with 403.
    A context manager that closes."""

    __slots__ = ("_lock", "_token")

    def __init__(self, token: str | Buffer) -> None:
        """:param token: the token, copied. A ``str`` can't be erased: read it from the environment
            once, here, and keep no other reference to it. A buffer the caller owns isn't zeroed by
            this source: clear it once this returns.
        :raises TypeError: ``token`` is ``None``, or neither a ``str`` nor a buffer
        :raises ValueError: ``token`` is empty, longer than :data:`MAX_TOKEN_LENGTH`, or isn't
            printable ASCII without spaces
        """
        if token is None:
            raise TypeError("token must not be None.")
        if isinstance(token, str):
            if not 0 < len(token) <= MAX_TOKEN_LENGTH or not all("!" <= c <= "~" for c in token):
                raise ValueError(f"A Vault token is 1-{MAX_TOKEN_LENGTH} printable ASCII characters, with no spaces.")
            # Encoded straight into a bytearray: every character is ASCII, so each is its own byte.
            copied = bytearray(len(token))
            for i, c in enumerate(token):
                copied[i] = ord(c)
        else:
            if not isinstance(token, Buffer):
                raise TypeError("token must be a str or a buffer.")
            copied = bytearray(memoryview(token).cast("B"))
            if len(copied) > MAX_TOKEN_LENGTH or not is_valid_token(copied):
                ArrayUtility.zero_memory(copied)
                raise ValueError(f"A Vault token is 1-{MAX_TOKEN_LENGTH} printable ASCII characters, with no spaces.")
        self._token = copied
        self._lock = threading.Lock()

    def copy_token(self, destination: memoryview) -> int:
        """:raises ValueError: ``destination`` is too small for the token"""
        with self._lock:
            target = memoryview(destination).cast("B")
            if len(target) < len(self._token):
                raise ValueError(f"The token is {len(self._token)} bytes; destination holds {len(target)}.")
            target[:len(self._token)] = self._token
            return len(self._token)

    def close(self) -> None:
        """Zeroes the token. A request made afterwards fails, its token no longer one."""
        with self._lock:
            ArrayUtility.zero_memory(self._token)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


def copy_token_within(source: VaultTokenSource, destination: bytearray, timeout: timedelta) -> int:
    """Asks ``source`` for the token on a thread of its own, waiting at most ``timeout``, and returns
    its length in ``destination``. The source writes into a scratch bytearray, zeroed as the thread
    ends, and the token reaches ``destination`` only if the wait hasn't been given up: a source that
    answers after the timeout leaves nothing behind. A source's failure is re-raised as it is."""
    done = threading.Event()
    lock = threading.Lock()
    abandoned = False
    outcome: list[tuple[int, BaseException | None]] = []

    def run() -> None:
        scratch = bytearray(len(destination))
        try:
            length = source.copy_token(memoryview(scratch))
            with lock:
                if not abandoned and isinstance(length, int) and not isinstance(length, bool) and 0 < length <= len(scratch):
                    destination[:length] = memoryview(scratch)[:length]
                outcome.append((length if isinstance(length, int) and not isinstance(length, bool) else -1, None))
        except BaseException as error:  # re-raised on the calling thread
            outcome.append((-1, error))
        finally:
            ArrayUtility.zero_memory(scratch)
            done.set()

    threading.Thread(target=run, name="hkdfguard-vault-token", daemon=True).start()
    if not done.wait(timeout.total_seconds()):
        with lock:
            abandoned = True
        raise TimeoutError(f"The Vault token source returned no token within {timeout}.")
    length, error = outcome[0]
    if error is not None:
        raise error
    return length
