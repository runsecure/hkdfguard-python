"""A protected read-only cache over Google Cloud Secret Manager: each secret is read on its first
lookup, taken out of the response before the client can parse it, encrypted under the key ring's
current key and cached only as ciphertext."""

from hkdfguard.cache.googlesecretmanager._cache import GoogleSecretManagerSecretCache

__all__ = ["GoogleSecretManagerSecretCache"]
