# hkdfguard-cache-hashicorpvault

A protected read-only cache over HashiCorp Vault's KV secrets engine: each secret is read on its first lookup, taken out of the response before it can become a str, encrypted under the key ring's current key and cached only as ciphertext.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-cache-hashicorpvault
```

```python
import os

from hkdfguard.cache.hashicorpvault import HashiCorpVaultSecretCache, HashiCorpVaultSecretCacheOptions, StaticVaultToken

token_protector = ring.create_protector(HashiCorpVaultSecretCache.TOKEN_PURPOSE)
with HashiCorpVaultSecretCache(
        "https://vault.example.com:8200",
        StaticVaultToken.protect(token_protector, os.environ["VAULT_TOKEN"]),  # held encrypted
        token_protector,
        ring,
        options=HashiCorpVaultSecretCacheOptions(mount_path="secret")) as secrets:  # KV version 2 unless kv_version=V1
    buffer = bytearray(256)
    written = secrets.decrypt("myapp/db#password", buffer)  # 0 if there's no such secret or key
```

The package has no HTTP dependency: requests go through the standard library's `http.client`.

**Names.** A Vault secret holds several keys, so a name is the secret's path within the engine with
the key after `#`; a name without one reads `default_key` (`value` unless set). The first lookup of
any key reads the secret once and caches every key it holds, each encrypted on its own and bound to
its own name; a string is cached as its UTF-8 bytes, a number, `true` or `false` as its JSON text,
and anything else is left out. Paths and keys match exactly, as Vault matches them. A name that
isn't a path - `/`-separated segments of ASCII letters, digits, `-`, `_` and `.`, no `.` or `..`
segment, at most 512 characters - such as `ConnectionStrings:Admin`, returns 0 without a call, so
the cache can go last in a `ProtectedCacheCollection`. The token's policy needs only `read` on the
paths it reads; the cache never lists.

**Answers.** A secret that doesn't exist (404 with no errors), or whose latest version is deleted,
returns 0 and is looked up again next time. Any other failure raises `VaultRequestError` with
Vault's status and errors, never the token: 403, a 404 naming an error (no such mount), a redirect,
which is never followed. Transient failures (no answer, a connection lost mid-response, a timed-out
attempt, 429, a 5xx other than 501) are retried `retry_count` times (3-10), backing off from
`retry_delay` up to 10 seconds plus a random 0-100 ms; once the retries are spent, a failure without
an answer raises its `OSError` (`TimeoutError` for a timed-out attempt). `timeout` (30 seconds)
bounds each attempt: the connection, the response's headers and its whole body.

**The token.** Authentication is left to a `VaultTokenProvider`, asked on every fetch - `get_token`
for `decrypt`, `get_token_async` for `decrypt_async` - so a provider can log in (AppRole,
Kubernetes, a certificate) and renew however it likes; `StaticVaultToken` holds a token you already
have. A provider hands the token over encrypted by the token protector
(`ring.create_protector(TOKEN_PURPOSE)`), and a fetch given anything else fails with `RuntimeError`
without calling Vault, quoting or chaining nothing. A provider's failure propagates as it is and
isn't retried; one slower than the timeout fails the fetch with `TimeoutError`. The token is
decrypted into a bytearray for each request and zeroed once its headers are sent, so it never
becomes a `str` in the cache; `http.client` copies each header line into `bytes` of its own, which
Python can't zero, and drops it once the request is sent.

**The address** must be https, except on a loopback address (`localhost`, `127.0.0.0/8`, `[::1]`:
a local Vault Agent or dev server), and must not hold credentials, a query or a fragment; a path is
kept as a prefix (Vault behind a reverse proxy). Set `ssl_context` to trust a private CA
(`ssl.create_default_context(cafile="vault-ca.pem")`) or present a client certificate; otherwise the
system's trust store verifies the certificate and host name. Every request has a connection of its
own, through no proxy. `namespace` sends `X-Vault-Namespace` (Vault Enterprise).

**The secret never becomes a `str`.** The response body is read straight off the socket into a
bytearray of the library's own, and each key's value is unescaped into another and encrypted from
there (`SecretJsonBody.capture_keys`); every bytearray holding it is zeroed. Out of reach: the
socket's and OpenSSL's buffers, and `http.client`'s own for a chunked response.

`decrypt` blocks the calling thread until Vault answers. `decrypt_async` awaits the provider's
`get_token_async` and makes the requests in a worker thread, so the event loop never blocks;
cancelling the lookup that started a fetch cancels the provider's coroutine, or shuts down the
request's socket, and no retry follows. Close the cache (or use it as a context manager) to stop it
reading Vault; cached secrets can still be read.

| Option | Default | |
|---|---|---|
| `mount_path` | `"secret"` | where the KV engine is mounted, e.g. `"kv/team-a"` |
| `kv_version` | `VaultKvVersion.V2` | `V1` reads `{mount}/{path}`, `V2` the latest version at `{mount}/data/{path}` |
| `default_key` | `"value"` | the key a name without `#key` reads |
| `namespace` | `None` | the Vault Enterprise namespace, e.g. `"team-a/prod"` |
| `timeout` | 30 seconds | one attempt: getting the token, or one request and its whole response |
| `retry_count` | 3 | retries of a transient failure, 3-10 |
| `retry_delay` | 200 ms | the first wait, doubling up to 10 seconds, plus 0-100 ms |
| `ssl_context` | `None` | TLS settings for https; `None` for `ssl.create_default_context()` |

Unlike the Java module, there is no HTTP client option: `http.client` never follows redirects, so
there is nothing to refuse, and `ssl_context` covers what a supplied client is for there.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes, and
[Run the HashiCorp Vault cache integration tests](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/run-hashicorp-vault-cache-integration-tests.md)
to read a real Vault.

Licensed under the Mozilla Public License 2.0.
