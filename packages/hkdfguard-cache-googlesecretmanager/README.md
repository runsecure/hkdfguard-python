# hkdfguard-cache-googlesecretmanager

A protected read-only cache over one Google Cloud project's Secret Manager: each secret is read on its first lookup, taken out of the response before the client can parse it, encrypted under the key ring's current key and cached only as ciphertext.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-cache-googlesecretmanager
```

```python
from google.cloud import secretmanager
from hkdfguard.cache.googlesecretmanager import GoogleSecretManagerSecretCache

client = secretmanager.SecretManagerServiceClient()  # Application Default Credentials, over gRPC
secrets = GoogleSecretManagerSecretCache(client, "my-project", ring)

buffer = bytearray(256)
written = secrets.decrypt("Db-Password", buffer)  # 0 if the secret doesn't exist
```

Or let the cache make, and close, a client of its own:

```python
with GoogleSecretManagerSecretCache.create("my-project", ring) as secrets:  # ADC, the global endpoint
    written = secrets.decrypt("Db-Password", buffer)
```

`create` also takes `credentials=` and `client_options=` (a regional endpoint, say) for that client.

## What it reads

`AccessSecretVersion` reads the secret's `latest` version; the application needs only the **Secret
Manager Secret Accessor** role (`secretmanager.versions.access`) on the secrets it reads - the cache
never lists secrets or versions. Nothing is fetched up front: the first `decrypt` or
`find_max_decrypted_length` for a name reads that one secret, encrypts it under the ring's current key
bound to its name, and caches only the ciphertext; later lookups never call Google. A cached value
isn't refreshed: a new secret version is picked up by a new cache.

Secret IDs match exactly, as Secret Manager's do: `Db-Password` and `db-password` are two secrets.
Anything but 1-255 ASCII letters, digits, hyphens and underscores - such as the configuration path
`ConnectionStrings:Admin` - returns 0 without a call, so the cache can go last in a
`ProtectedCacheCollection` behind other sources. A payload holding a JSON object is also cached by
key: `secrets.decrypt("Db-Login#password", buffer)` (see hkdfguard-cache's README).

A secret that doesn't exist or has no versions (`NOT_FOUND`), or whose payload is empty, returns 0
and is looked up again next time. Any other failure - permission denied, a disabled or destroyed
latest version, Google unreachable, the timeout passing - raises the client's
`google.api_core.exceptions.GoogleAPICallError`. A payload whose CRC32C doesn't match the checksum
Google returns, or a response naming another secret, is refused with `CryptographicError`.

## The payload never becomes `bytes`

The client would parse each response into a protobuf message holding the payload as an immutable
`bytes`, which nothing can zero, and its debug logging would write the whole response, payload
included, to the `google` logger. So the cache doesn't call the client's `access_secret_version`: it
makes the call itself on the client's gRPC channel, with a response deserializer of its own that reads
the response's few fields straight from the message gRPC received, copying the payload into a
`bytearray`. That is checked against its CRC32C, encrypted, and zeroed - whether it was accepted or
refused, and even when it arrives after the lookup was cancelled. Out of reach, as everywhere in
Python: the message itself, which gRPC hands the deserializer as `bytes`, and the transport's buffers
below it (HTTP/2, TLS decryption).

So the client must use the gRPC transport (the default); a REST client is refused with `ValueError`.
Only the client's channel - its credentials, endpoint and channel options - is used: each fetch is
retried as the client retries `AccessSecretVersion` by default (`RESOURCE_EXHAUSTED` and
`UNAVAILABLE`, with exponential backoff from 2 s), all within `timeout` (60 seconds by default; pass
`timeout=` to change it).

## Reading asynchronously

`decrypt_async` and `find_max_decrypted_length_async` fetch a missing secret through a gRPC future on
the same channel, so a miss blocks neither the event loop nor a worker thread, and they work from any
event loop - no asyncio client is needed. Cancelling the lookup that started a fetch cancels the call.

## Closing

A client passed in is the application's: it keeps it for as long as the cache is used, and closes
it. A cache made by `create` owns its client, so close the cache (or use it in a `with` block).

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes, and
[Run the Google Secret Manager cache integration tests](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/run-google-secret-manager-cache-integration-tests.md)
to try it against a real secret.

Licensed under the Mozilla Public License 2.0.
