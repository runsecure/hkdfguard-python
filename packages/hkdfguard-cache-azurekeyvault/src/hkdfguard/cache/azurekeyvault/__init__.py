"""A protected read-only cache over Azure Key Vault secrets: each secret is read on its first lookup,
taken out of the response before the SDK can make it a ``str``, encrypted under the key ring's
current key and cached only as ciphertext."""

from hkdfguard.cache.azurekeyvault._cache import AzureKeyVaultSecretCache

__all__ = ["AzureKeyVaultSecretCache"]
