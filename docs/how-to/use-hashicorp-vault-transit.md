# Wrap keys with HashiCorp Vault transit

This page sets up a key in a HashiCorp Vault transit secrets engine as HkdfGuard's KEK and uses it
from Python with `HashiCorpVaultTransitKeyWrapper`, in place of the native TPM, Secure Enclave or
Platform Crypto Provider KEK.

Use it when your applications already authenticate to Vault, or run somewhere a cloud KMS isn't
available, and you want key access controlled by Vault policy and recorded in Vault's audit log
rather than tied to one machine's TPM.

To run the transit integration tests against a Vault dev server, see
[Run the HashiCorp Vault transit integration tests](run-hashicorp-vault-transit-integration-tests.md).

## How it differs from the native wrapper

| | Native (`NativeHkdfKeyWrapperV1`) | Vault transit (`HashiCorpVaultTransitKeyWrapper`) |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or Platform Crypto Provider | An `aes256-gcm96` transit key |
| Identified by | A service name | Vault's address and the key's name |
| Who may wrap and unwrap | Local accounts and groups the native library allows | Tokens whose policy grants `update` on the key's `encrypt`, `decrypt` and `datakey/wrapped` paths |
| Each call | Local, synchronous | A request to Vault's HTTP API, recorded in Vault's audit log; blocks until Vault answers |
| Key file reads | Through the native library, which refuses files another account could have replaced | The same rules, checked in Python by `hkdfguard-securefile`; who else is trusted is set with `KeyFileTrust` |
| Install | The native package | Nothing beyond the distribution: it talks to Vault's HTTP API through the standard library |

Wrapped DEKs aren't interchangeable between wrappers. A key file wrapped by one wrapper can't be
unwrapped by another, so each DEK belongs to the wrapper type that created it. A transit-wrapped DEK
is Vault's ciphertext as it returns it, `vault:v1:...`, about 89 bytes of ASCII. It is byte for byte
what the .NET `HashiCorpVaultTransitKeyWrapper` and the other ports produce, so each reads the
others' key files, given the same key and context.

## 1. Create the transit key

As a Vault operator, enable the engine (once) and create the key:

```bash
vault secrets enable transit
vault write -f transit/keys/myapp-kek type=aes256-gcm96
```

| Setting | Choose | Why |
|---|---|---|
| `type` | `aes256-gcm96` (the default), `aes128-gcm96` or `chacha20-poly1305` | The wrapper needs an AEAD key for its context (associated data) |
| `derived` | `false` (the default) | A derived key needs a `context` on every request, which the wrapper doesn't send. Worse, a key that *isn't* derived silently ignores one, so the wrapper binds its context as `associated_data` instead |
| `exportable` | `false` (the default) | Nothing here needs the key material out of Vault |
| `deletion_allowed` | `false` (the default) | Deleting the key makes every DEK wrapped under it unreadable, for good |

Rotate it with `vault write -f transit/keys/myapp-kek/rotate`. New DEKs are wrapped under the latest
version; existing key files keep revealing as long as their version is at or above the key's
`min_decryption_version`, so don't raise that until every key file is rewrapped.

## 2. Grant each role only what it calls

Give `update`, and never `create`, on exactly the paths each role uses. `transit/encrypt/{name}`
creates a key that doesn't exist yet when the token has `create`, so with it a mistyped key name
would quietly wrap DEKs under a brand-new key.

A release pipeline that creates key files:

```hcl
path "transit/encrypt/myapp-kek"         { capabilities = ["update"] }
path "transit/datakey/wrapped/myapp-kek" { capabilities = ["update"] }
```

The application, which only reads existing key files:

```hcl
path "transit/decrypt/myapp-kek" { capabilities = ["update"] }
```

Add `transit/encrypt/myapp-kek` (and `transit/datakey/wrapped/myapp-kek`) to the application only
if it generates ephemeral keys at startup.

```bash
vault policy write myapp-kek-pipeline pipeline.hcl
vault policy write myapp-kek-app app.hcl
```

Then bind each policy to the auth method its role logs in with (AppRole, Kubernetes, a certificate,
a cloud IAM role).

> **Security:** anyone whose policy allows `encrypt` on the key can create a key file the
> application accepts, holding a DEK of their choosing. Keep `encrypt` with the pipeline.

## 3. Give the process a token

Every request is made with a token from a `VaultTokenSource`. Logging in, renewing and replacing
the token is the source's job, so any auth method can sit behind the wrapper. The source copies the
token into a bytearray the wrapper owns and zeroes once the request has been sent, rather than
handing it over as a `str`.

`StaticVaultTokenSource` holds a token you already have, such as one a Vault Agent wrote to a sink
file. Nothing renews it, so once it expires every request fails with 403. It keeps the token in a
bytearray, zeroed by `close()` (it is a context manager):

```python
import os

from hkdfguard.keywrapping.hashicorpvault import StaticVaultTokenSource

token = StaticVaultTokenSource(os.environ["VAULT_TOKEN"])
```

A `str` can't be erased, so read it once, there, and keep no other reference; a token read into a
`bytearray` (from a sink file opened `"rb"`, say) can be passed instead, and zeroed by you once the
source has copied it.

For a long-running service, prefer a Vault Agent on loopback with `use_auto_auth_token`, which
renews the token itself, or subclass `VaultTokenSource` over your auth method: implement
`copy_token(destination)`, which writes the token into `destination` (a writable `memoryview` of
`MAX_TOKEN_LENGTH`, 2048, bytes) and returns its length. It is asked once per call, on a thread of
its own, and given at most the wrapper's timeout; a source that answers later fails the call with
`TimeoutError`, and what it writes then is zeroed rather than used. Its own exceptions propagate as
they are.

> **Note:** this is not the cache's `VaultTokenProvider` (`hkdfguard-cache-hashicorpvault`). That
> one hands over a token protected by the key ring; a key wrapper runs before there is a key ring,
> so it can't.

## 4. Create the wrapper

```
pip install hkdfguard-keywrapping-hashicorpvault
```

> **TODO (maintainer):** confirm the install command once the distribution is published.

The distribution depends only on `hkdfguard-abstractions` and `hkdfguard-securefile`: HashiCorp
ships no Python SDK, and the community one (`hvac`) decodes every response into a `str`, which would
leave each revealed DEK where nothing can zero it. Requests go through the standard library's
`http.client`.

```python
from hkdfguard.keywrapping.hashicorpvault import HashiCorpVaultTransitKeyWrapper

wrapper = HashiCorpVaultTransitKeyWrapper(
    "https://vault.example.com:8200",
    "myapp-kek",
    token,
    "com.example.myapp")   # the context
```

- **The address must be https**, except on a loopback address (a local Vault Agent or dev server):
  every request carries a token, and wrap and unwrap carry plaintext DEKs. It must not hold
  credentials, a query or a fragment. A path is kept as a prefix, for Vault behind a reverse proxy.
  Requests go through no proxy, and no redirect is ever followed: it would carry the token
  elsewhere, and Vault's standbys forward requests to the active node themselves.
- **The context** is bound into every wrapped DEK as Vault's `associated_data` and must be given
  again, exactly, to reveal it; `None` and `""` are the same. Use the same value on every wrapper
  that handles one application's key files. It isn't a secret and must not hold one.
- **With a context, `generate_and_wrap` generates the DEK in your process** and wraps it with
  `encrypt`, because `datakey/wrapped` ignores `associated_data`. Without one, Vault generates it
  and returns it wrapped only, so the plaintext DEK never leaves Vault on that call. Choose a context
  for the binding, or none for generation in Vault.
- **Old Vaults are refused, not trusted.** If Vault answers that it ignored a parameter, as one
  too old for `associated_data` does, the call fails rather than return a DEK bound to no context.
- **Calls block** until Vault answers or the retries are spent. The wrapper is synchronous, like
  every key wrapper in this library, and safe to share between threads: each request has a
  connection of its own.
- **`close()`** (or `with wrapper:`) stops it calling Vault, but only close it once nothing uses it,
  including a key ring's background refresh. It doesn't close the token source.

`HashiCorpVaultTransitKeyWrapperOptions`, passed as `options=`, sets a mount other than `transit`, a
Vault Enterprise namespace, the per-attempt timeout (30 seconds, covering the connection, the
response's headers and its whole body), and retries: a request that gets no answer, loses its
connection, times out, or is answered 429 or a 5xx other than 501 is retried 3 times by default
(`retry_count`, 3-10), waiting 200 ms (`retry_delay`) and doubling up to 10 seconds, plus up to
100 ms of jitter. The token is asked for once per call, not per retry. To trust a private CA, or
present a client certificate, give an `ssl_context`:

```python
import ssl

from hkdfguard.keywrapping.hashicorpvault import HashiCorpVaultTransitKeyWrapperOptions

options = HashiCorpVaultTransitKeyWrapperOptions(
    mount_path="transit/team-a",
    namespace="team-a/prod",
    ssl_context=ssl.create_default_context(cafile="vault-ca.pem"))
wrapper = HashiCorpVaultTransitKeyWrapper("https://vault.example.com:8200", "myapp-kek", token,
                                          "com.example.myapp", options=options)
```

Without one, the system's trust store verifies the certificate and host name. There is no HTTP
client or handler option, as there is in .NET: `http.client` never follows redirects, so there is
nothing to refuse, and `ssl_context` covers what a supplied handler is for there.

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere:

```python
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.dataencryptionkey import KeyRingBuilder

with (KeyRingBuilder()
        .with_service_name("com.example.myapp")
        .with_key_wrapper(wrapper)
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .with_key_refresh_interval(300)
        .with_ephemeral_key(1)
        .build()) as ring:
    ...
```

Everything encrypted under an ephemeral key is lost when the process exits. Data you store needs a
key file.

## 6. Create a key file

The release pipeline creates key files with the wrapper itself, logged in as the pipeline role from
step 2:

```python
from pathlib import Path
from hkdfguard.abstractions import WrappedKeyLimits

wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
length = wrapper.generate_and_wrap(wrapped)
Path(r"C:\HkdfGuardKeys\myapp\v1.key").write_bytes(wrapped[:length])
```

To wrap a key the pipeline already holds, such as an `AesGcmPipelineDataProtector`'s, call `wrap`
with it and zero your copy afterwards, as [Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file)
shows. `wrap` takes 1 to 256 bytes.

Key files are read only from where no untrusted account could have written or replaced them: anyone
who can replace a key file *and* call `encrypt` on the key could otherwise choose your application's
DEK. The rules, the folder setup and `KeyFileTrust` for a deployer account are the same as for AWS
KMS; see [Where key files can live](use-aws-kms.md#where-key-files-can-live). Pass the
`KeyFileTrust` as the wrapper's `key_file_trust=` argument.

## 7. Use the key file

```python
with (KeyRingBuilder()
        .with_service_name("com.example.myapp")
        .with_key_wrapper(wrapper)
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .with_key_refresh_interval(300)
        .with_key_file(1, r"C:\HkdfGuardKeys\myapp\v1.key")
        .build()) as ring:
    ...
```

`build()` calls `decrypt` once per key, so the application fails to start if Vault can't be reached
or refuses the key. Each key then calls `decrypt` once per `with_key_refresh_interval`: at 300
seconds, 8,640 requests per key per process every 30 days, each one in the audit log. See
[Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the trade-off.

## What stays in memory

The wrapper zeroes every plaintext key byte it owns once used: the request body `encrypt` is sent
(the DEK, base64-encoded straight into a bytearray and sent from it, never through `base64`'s
immutable `bytes`), the response `decrypt` answers with (read off the socket into a bytearray of
the wrapper's own, at most 16 KiB), the base64 value read out of it, and the DEK decoded from that.
The caller's buffer is zeroed when an unwrap fails. The token is copied by its source into a
bytearray zeroed once the request is sent; it never becomes a `str` in the wrapper.

What it can't zero is below that. `http.client` copies each header line, the token's among them,
into `bytes` of its own and joins them into the request head, which nothing references once it is
sent but which stays in memory until it is reused. It reads the response through a buffered reader
whose buffer holds the body bytes that arrived with the headers. Then there are the socket's buffers
and, over TLS, OpenSSL's. With a context, `generate_and_wrap` takes its DEK from `os.urandom`, whose
`bytes` is copied into a bytearray and dropped. [Process hardening](../../README.md#process-hardening)
is what keeps such copies out of reach of a debugger or a crash dump.

## If something goes wrong

Every Vault failure is a `CryptographicError` whose message names the operation, the key, and
Vault's status and errors; a `VaultRequestError` (with `status_code`), `OSError` or
`http.client.HTTPException` is its `__cause__`. A failed unwrap zeroes the caller's buffer. A token
source's own failure propagates as it is; a source that supplies no token, or one that isn't a
token, raises `RuntimeError` without a request. Argument errors raise `ValueError` or `TypeError`.

| The message names | Cause | Fix |
|---|---|---|
| `403 Forbidden` ... `permission denied` | The token's policy doesn't grant `update` on this path, or the token is invalid or expired | Step 2's paths; renew or replace the token |
| `400 Bad Request` ... `encryption key not found` | No key by that name in this mount (or namespace) | Check the key name, `mount_path` and `namespace` |
| `400 Bad Request` ... `cipher: message authentication failed` | The key file was altered, wrapped under another key, or with a different context | Restore the file; use the key and context it was created with |
| `400 Bad Request` ... `missing 'context' for key derivation` | The key is derived | Create a key with `derived=false` and rewrap |
| `400 Bad Request` ... `disallowed by policy (too old)` | The file's key version is below `min_decryption_version` | Lower it, or rewrap the file under the current version |
| `ignored a parameter` | This Vault doesn't support `associated_data` | Upgrade Vault (the integration tests run against 1.19) |
| `503 Service Unavailable` | Vault is sealed, or electing a leader, beyond the retries | Unseal Vault; check its HA status |
| `no answer within` | No answer within the timeout, on every attempt | Check the address and network path |
| `Vault answered 307 Temporary Redirect` | A load balancer or standby redirected the request, which is never followed | Point the address at the active node or a load balancer that forwards |
| `must be https` (`ValueError`) | The address isn't loopback and isn't https | Use https, or a local Vault Agent on `127.0.0.1` |
| `RuntimeError` ... `token source` | The token source supplied no token, or one with spaces or non-ASCII characters | Check what the source reads |
| `TimeoutError` ... `token source` | The token source took longer than the timeout | Check the source's login |

Reading a key file fails before Vault is called; see
[Wrap keys with AWS KMS](use-aws-kms.md#if-something-goes-wrong) for those errors.
