"""What hkdfguard-integration-configurationresolver's cache tests share: a real key ring, a source
over plain text that counts what it is asked, a remote cache over a dict, and a provider of settings."""

from __future__ import annotations

import os
import threading
from collections.abc import Buffer, Callable, Iterator
from contextlib import contextmanager

from hkdfguard.abstractions import KeyWrapper, ProtectedReadOnlyCache, WritableBuffer
from hkdfguard.cache import ProtectedCache, RemoteSecretCache, SecretNameMatching, SecretValueSink
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider, KeyRing
from hkdfguard.integration.configurationresolver import ValueProviderBase, ValueStatus


class FixedKeyWrapper(KeyWrapper):
    """A key wrapper that always reveals the same key."""

    def __init__(self, key: bytes) -> None:
        self.key = key

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


@contextmanager
def new_ring() -> Iterator[KeyRing]:
    """A ring holding one real AES-256-GCM key as version 1, its current version."""
    with KeyRing(DefaultFormatProvider()) as ring:
        ring.add(1, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(os.urandom(32)), b"wrapped", 60)))
        yield ring


def new_cache(ring: KeyRing, **values: str) -> ProtectedCache:
    """A ProtectedCache holding ``values``."""
    cache = ProtectedCache(ring)
    for name, value in values.items():
        cache.add(name, value)
    return cache


def decrypt_text(cache: ProtectedReadOnlyCache, name: str) -> str:
    """Sizes a buffer with find_max_decrypted_length, as a caller would, and decrypts ``name``."""
    max_length = cache.find_max_decrypted_length(name)
    assert max_length is not None, name
    result = bytearray(max_length)
    return result[: cache.decrypt(name, result)].decode()


async def decrypt_text_async(cache: ProtectedReadOnlyCache, name: str) -> str:
    max_length = await cache.find_max_decrypted_length_async(name)
    assert max_length is not None, name
    result = bytearray(max_length)
    return result[: await cache.decrypt_async(name, result)].decode()


class PlainSource(ProtectedReadOnlyCache):
    """A ProtectedReadOnlyCache over plain strings, names matched exactly, that counts every lookup
    by name and can run a callback the first time it decrypts a name. A real cache never holds
    plaintext like this."""

    def __init__(self, **values: str) -> None:
        self._values: dict[str, str] = dict(values)
        self.decrypts: dict[str, int] = {}
        self.length_lookups: dict[str, int] = {}
        self.on_first_decrypt: tuple[str, Callable[[], object]] | None = None
        self._lock = threading.Lock()

    def __setitem__(self, name: str, value: str) -> None:
        self._values[name] = value

    def decrypt_count(self, name: str) -> int:
        return self.decrypts.get(name, 0)

    def length_lookup_count(self, name: str) -> int:
        return self.length_lookups.get(name, 0)

    def decrypt(self, name: str, result: WritableBuffer) -> int:
        with self._lock:
            self.decrypts[name] = self.decrypts.get(name, 0) + 1
            hook = self.on_first_decrypt
            if hook is not None and hook[0] == name:
                self.on_first_decrypt = None
            else:
                hook = None
        if hook is not None:
            hook[1]()

        value = self._values.get(name)
        if value is None:
            return 0
        encoded = value.encode()
        view = memoryview(result).cast("B")
        if len(encoded) > len(view):
            raise ValueError("The result is too small.")
        view[: len(encoded)] = encoded
        return len(encoded)

    def find_max_decrypted_length(self, name: str) -> int | None:
        with self._lock:
            self.length_lookups[name] = self.length_lookups.get(name, 0) + 1
        value = self._values.get(name)
        return None if value is None else len(value.encode())


class FakeRemoteSecretCache(RemoteSecretCache):
    """A RemoteSecretCache over a dict, matching names exactly, that records how each secret was
    fetched: :attr:`fetches` by the blocking path, :attr:`async_fetches` without blocking. A value
    holding a JSON object is handed over with its keys too."""

    def __init__(self, ring: KeyRing, **secrets: str) -> None:
        super().__init__(ring, SecretNameMatching.EXACT)
        self.secrets = dict(secrets)
        self.fetches: list[str] = []
        self.async_fetches: list[str] = []

    def _is_valid_name(self, name: str) -> bool:
        return bool(name)

    def _hand_over(self, name: str, value: SecretValueSink) -> None:
        secret = self.secrets.get(name)
        if secret is not None:
            value.set_bytes_with_json_keys(bytearray(secret.encode()))

    def _fetch(self, name: str, value: SecretValueSink) -> None:
        self.fetches.append(name)
        self._hand_over(name, value)

    async def _fetch_async(self, name: str, value: SecretValueSink) -> None:
        self.async_fetches.append(name)
        self._hand_over(name, value)


class SettingsProvider(ValueProviderBase):
    """A value provider over plain strings, as an application's provider of settings that aren't
    secret would be."""

    def __init__(self, **values: str) -> None:
        self._values = values

    def try_get_bytes(self, key: str, destination: WritableBuffer) -> tuple[ValueStatus, int]:
        value = self._values.get(key)
        if value is None:
            return ValueStatus.NOT_FOUND, 0
        encoded = value.encode()
        view = memoryview(destination).cast("B")
        if len(encoded) > len(view):
            return ValueStatus.DESTINATION_TOO_SMALL, 0
        view[: len(encoded)] = encoded
        return ValueStatus.FOUND, len(encoded)

    def _find_byte_count(self, key: str) -> int | None:
        value = self._values.get(key)
        return None if value is None else len(value.encode())
