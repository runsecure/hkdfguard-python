"""A protected read-only cache over HashiCorp Vault's KV secrets engine: each secret is read on its
first lookup, taken out of the response before it can become a str, encrypted under the key ring's
current key and cached only as ciphertext."""

from hkdfguard.cache.hashicorpvault._cache import HashiCorpVaultSecretCache
from hkdfguard.cache.hashicorpvault._errors import VaultRequestError
from hkdfguard.cache.hashicorpvault._options import HashiCorpVaultSecretCacheOptions, VaultKvVersion
from hkdfguard.cache.hashicorpvault._token import StaticVaultToken, VaultTokenProvider

__all__ = [
    "HashiCorpVaultSecretCache",
    "HashiCorpVaultSecretCacheOptions",
    "StaticVaultToken",
    "VaultKvVersion",
    "VaultRequestError",
    "VaultTokenProvider",
]
