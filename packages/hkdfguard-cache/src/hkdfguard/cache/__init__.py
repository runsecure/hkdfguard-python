"""Concurrent name-to-encrypted-value caches: :class:`ProtectedCache` encrypts every value under a
key ring's current key, bound to its name, and :class:`ProtectedCacheCollection` reads through
several caches in order."""

from hkdfguard.cache._cache import ProtectedCache, ProtectedCacheCollection

__all__ = ["ProtectedCache", "ProtectedCacheCollection"]
