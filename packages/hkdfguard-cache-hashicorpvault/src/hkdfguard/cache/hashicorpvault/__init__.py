"""A protected read-only cache over HashiCorp Vault's KV secrets engine: each secret is read on its
first lookup, taken out of the response before it can become a str, encrypted under the key ring's
current key and cached only as ciphertext. The token providers, TLS options and the error Vault's
refusals are reported as are ``hkdfguard-integration-hashicorpvault``'s."""

from hkdfguard.cache.hashicorpvault._cache import HashiCorpVaultSecretCache
from hkdfguard.cache.hashicorpvault._options import HashiCorpVaultSecretCacheOptions, VaultKvVersion

__all__ = [
    "HashiCorpVaultSecretCache",
    "HashiCorpVaultSecretCacheOptions",
    "VaultKvVersion",
]
