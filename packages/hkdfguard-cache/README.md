# hkdfguard-cache

Concurrent name-to-encrypted-value caches that follow key ring rotation and bind every value to its name.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-cache
```

```python
import hkdfguard.cache
```

## Caching secrets from a secret store

`RemoteSecretCache` is the base of the caches that read secrets from a remote store on demand (the
`hkdfguard-cache-*` distributions). Nothing is fetched up front: the first `decrypt` or
`find_max_decrypted_length` for a name reads that one secret, encrypts it under the ring's current
key bound to its name, and caches only the ciphertext; later lookups never call the store, and a
cached value is never replaced. A secret that doesn't exist, or is empty, returns 0 and is looked up
again next time; any other failure raises the client's exception. A name the store can't hold, such
as the configuration path `ConnectionStrings:Admin`, returns 0 without a call, so a cache can go last
in a `ProtectedCacheCollection` behind other sources.

A name may name one key of a secret holding a JSON object, as `secret#key`: the first lookup of any
key fetches the secret once and caches its whole value and every key, each encrypted on its own. A
string member is cached as its UTF-8 bytes; a number, `true` or `false` as its JSON text; anything
else, or a member whose name isn't a key (1-256 printable ASCII characters other than space, `!` and
`#`), is left out. An object naming a member twice is refused with `InvalidSecretDataError`. Keys
match exactly, whatever the store's matching.

Every `ProtectedReadOnlyCache` also has `decrypt_async` and `find_max_decrypted_length_async`. On a
`RemoteSecretCache` they fetch a missing secret without blocking the event loop - through
`_fetch_async`, which by default runs `_fetch` in a worker thread - while `decrypt` blocks the calling
thread (so don't call it from a coroutine). Synchronous and asynchronous lookups of the same uncached
secret, from any thread or event loop, share one fetch. Cancelling a lookup's task stops it waiting,
and cancels the fetch itself only if that lookup started it; a lookup whose fetch was cancelled by
another starts a new one. `ProtectedCacheCollection` asks each source in turn the same way.

**A secret never becomes a `str`.** A store's cache takes the value out of the raw response body
before any SDK can parse it: `SecretJsonBody.capture` reads the body into a bytearray of its own,
unescapes the value into another, hands it to the cache, and returns the body with the value blanked
for the SDK to parse. Every bytearray that held the value is zeroed. Out of reach, as everywhere in
Python: a body the HTTP stack already holds as `bytes`, and the stack's own buffers.

Another store needs only a subclass:

```python
from hkdfguard.abstractions import KeyRing
from hkdfguard.cache import RemoteSecretCache, SecretJsonBody, SecretNameMatching, SecretValueSink


class MySecretStoreCache(RemoteSecretCache):
    def __init__(self, client: MyClient, ring: KeyRing) -> None:
        super().__init__(ring, SecretNameMatching.EXACT)
        self._client = client

    def _is_valid_name(self, name: str) -> bool:
        return name.isascii() and name.isalnum()

    # Hand the value to the sink, or return without doing so if the secret doesn't exist.
    def _fetch(self, name: str, value: SecretValueSink) -> None:
        response = self._client.get_raw(name)  # the raw JSON body, unparsed
        if response.status == 404:
            return
        response.raise_for_status()            # any other failure raises
        SecretJsonBody.capture(response, value, "value")  # {"value":"..."}; zeroed once encrypted
```

Override `_fetch_async` too if the client is asyncio-based; without it, `decrypt_async` runs `_fetch`
in a worker thread.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
