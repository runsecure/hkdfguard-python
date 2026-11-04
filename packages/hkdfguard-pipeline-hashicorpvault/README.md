# hkdfguard-pipeline-hashicorpvault

The end of a provisioning pipeline over HashiCorp Vault's KV secrets engine: pulls a fixed list of secrets, taking each out of the response before it can become a str, encrypts it at once with a pipeline data protector and writes one encrypted file per secret.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-pipeline-hashicorpvault hkdfguard-cryptoprovider-aesgcm256 hkdfguard-dataencryptionkey
```

```python
import os

from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider
from hkdfguard.integration.hashicorpvault import StaticVaultTokenSource
from hkdfguard.pipeline.hashicorpvault import HashiCorpVaultPipelineOptions, HashiCorpVaultSecretPipelineWriter

options = HashiCorpVaultPipelineOptions(mount_path="secret")  # KV version 2, reading "value" from a name without a key
with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector,
      StaticVaultTokenSource(os.environ["VAULT_TOKEN"]) as token,
      HashiCorpVaultSecretPipelineWriter(os.environ["VAULT_ADDR"], token, protector,
                                         ["myapp/db#username", "myapp/db#password", "myapp/api"], options=options) as writer):
    writer.pull_secrets()                                    # or: await writer.pull_secrets_async()
    writer.write_protected_secret_files("/etc/myapp/secrets")  # myapp__db__username, myapp__db__password, myapp__api
    # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.
```

No key ring is involved, and the writer is independent of `hkdfguard-cache-hashicorpvault`. Naming,
encrypting, keeping and writing are `SecretPipelineWriter`'s (`hkdfguard-pipeline`); this package
only reads.

- **Names.** A name is a secret's path within the engine, with the key to read after `#`:
  `myapp/db#password` reads the `password` key of the secret at `myapp/db`, and `myapp/db` reads its
  `default_key` (`value` unless the options say otherwise). Each secret is read once, with GET on its
  path (for KV version 2, its latest version), so the token's policy needs only `read` on the paths
  it reads, never `list`. A path that isn't one - segments of ASCII letters, digits, `-`, `_` and
  `.`, no segment `.` or `..`, at most 512 characters, such as `ConnectionStrings:Admin` - is refused
  with `ValueError` when the writer is made.
- **Answers.** A secret that doesn't exist (404 with no errors), whose latest version is deleted, or
  that has no such key, is reported missing. Any other answer raises `VaultRequestError` with Vault's
  status and errors, never the token: 403, a 404 naming an error (no such mount), a redirect, which
  is never followed. Transient failures (no answer, a connection lost mid-response, a timed-out
  attempt, 429, a 5xx other than 501) are retried `retry_count` times (3-10), backing off from
  `retry_delay` up to 10 seconds plus a random 0-100 ms; once the retries are spent, a failure
  without an answer raises its `OSError`. A response that isn't Vault's JSON raises
  `InvalidSecretDataError`. Nothing is kept from a failed pull.
- **The token** comes from a `VaultTokenSource` - `StaticVaultTokenSource` for one you hold - as the
  transit key wrapper's does: in plaintext, since a pipeline has no key ring to protect it with. It
  is asked for once per secret, copied into a bytearray, and zeroed once that secret's requests have
  been sent; a source's failure propagates unretried, and one that supplies no token, or one that
  isn't printable ASCII without spaces, fails the pull with `RuntimeError` before any request.
  `http.client` copies each header line into `bytes` of its own, which Python can't zero.
- **The address** must be https, except on a loopback address (a local Vault Agent or dev server);
  a path is kept as a prefix. Set `tls` (a `VaultTlsOptions` from PEM files: a password-protected
  PKCS#12 key store needs a key ring) or `ssl_context` to trust a private CA or present a client
  certificate. Every request has a connection of its own, through no proxy.

**The secret never becomes a `str`.** As `hkdfguard-cache-hashicorpvault` does, the response body
is read straight off the socket into a bytearray of the library's own, and each key's value is
unescaped into another and encrypted from there (`SecretJsonBody.capture_keys`); every bytearray
holding it is zeroed. Out of reach: the socket's and OpenSSL's buffers, and `http.client`'s own for
a chunked response.

`pull_secrets` blocks the calling thread; `pull_secrets_async` makes each read in a worker thread,
and cancelling it shuts down the request's socket, with no retry after. `close()` stops the writer
reading Vault; what it pulled can still be written.

| Option | Default | |
|---|---|---|
| `mount_path` | `"secret"` | where the KV engine is mounted, e.g. `"kv/team-a"` |
| `kv_version` | `VaultKvVersion.V2` | `V1` reads `{mount}/{path}`, `V2` the latest version at `{mount}/data/{path}` |
| `default_key` | `"value"` | the key a name without `#key` reads |
| `namespace` | `None` | the Vault Enterprise namespace, e.g. `"team-a/prod"` |
| `timeout` | 30 seconds | one attempt: getting the token, or one request and its whole response |
| `retry_count` | 3 | retries of a transient failure, 3-10 |
| `retry_delay` | 200 ms | the first wait, doubling up to 10 seconds, plus 0-100 ms |
| `ssl_context` | `None` | TLS settings for https; `None` for `ssl.create_default_context()`; not with `tls` |
| `tls` | `None` | `VaultTlsOptions`: PEM trust and client keys, a server name; not with `ssl_context` |

The token sources, `VaultTlsOptions`, `VaultRequestError` and the options' base,
`VaultConnectionOptions`, are
[hkdfguard-integration-hashicorpvault](https://pypi.org/project/hkdfguard-integration-hashicorpvault/)'s,
which makes and reads each request the same way for this writer, the runtime cache, the transit key
wrapper and the Vault client.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
