# hkdfguard-cache-azurekeyvault

A protected read-only cache over Azure Key Vault secrets: each secret is read on its first lookup, taken out of the response before the SDK can make it a str, encrypted under the key ring's current key and cached only as ciphertext.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java. Every distribution installs one subpackage of the
shared `hkdfguard` namespace package.

```
pip install hkdfguard-cache-azurekeyvault azure-identity
```

```python
from azure.identity import DefaultAzureCredential
from hkdfguard.cache.azurekeyvault import AzureKeyVaultSecretCache

with AzureKeyVaultSecretCache("https://myvault.vault.azure.net/", DefaultAzureCredential(), ring) as secrets:
    buffer = bytearray(256)
    written = secrets.decrypt("Db-Password", buffer)  # 0 if the secret doesn't exist
```

Get Secret reads the secret's current version; the application needs only the **Key Vault Secrets
User** role (`get`), never `list`. Names are 1-127 ASCII letters, digits and hyphens, compared
ignoring case as Key Vault compares them; any other name, such as the configuration path
`ConnectionStrings:Admin`, returns 0 without a call, so the cache can go last in a
`ProtectedCacheCollection` behind other sources. A secret that doesn't exist (404), or is empty,
returns 0 and is looked up again next time; any other failure raises the Azure SDK's exception
(`HttpResponseError`, with its `status_code`, `ClientAuthenticationError`, ...).

A secret holding a JSON object is read whole as `name` and member by member as `name#key`, all from
one call:

```python
written = secrets.decrypt("App-Login#password", buffer)
written = secrets.decrypt("app-login#port", buffer)  # "5432": secret names ignore case, keys don't
written = secrets.decrypt("App-Login", buffer)       # the whole JSON text
```

**The secret never becomes a `str`.** The cache builds its own `SecretClient` with a pipeline policy
that asks the transport for the Get Secret response unread, reads the body into a bytearray of its
own, hands the value to the cache as bytes, and gives `SecretClient` the body with the value
blanked; every bytearray that held the value is zeroed. The policy carries each fetch's sink in that
request's own pipeline context, so one client serves concurrent fetches from any threads. Out of
reach, as everywhere in Python: the immutable `bytes` chunks requests and urllib3 read the body in
(copied out and dropped, not zeroed), a body a transport buffers regardless, and the HTTP stack's
own buffers.

Pass `client_options=` for the `SecretClient`'s `transport`, `api_version`, retry options,
`per_call_policies` and `per_retry_policies`; the mapping is copied, and the capture policy goes
after your per-retry policies, so they see only redacted bodies. `logging_enable` is safe: a
captured response is streamed, which azure-core's logging policy logs as "Body is streamable".
Options that would put one of your policies closer to the network than the capture, or replace its
pipeline, are refused with `ValueError`: `policies`, `generated_client`, `authentication_policy`,
`custom_hook_policy`, `raw_response_hook`, `logging_policy` and `http_logging_policy`.

`decrypt_async` and `find_max_decrypted_length_async` run the same synchronous client in a worker
thread, so they never block the event loop, work from any event loop, and need no asyncio HTTP
library; cancelling a lookup stops it waiting, while the request runs on and its value is refused,
never cached. Close the cache, or use it as a context manager, to close the client's HTTP session.

The package depends on `azure-keyvault-secrets`; the credential comes from `azure-identity`, which
the application adds.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) and the `hkdfguard-cache`
README ("Caching secrets from a secret store") for how the caches fetch, encrypt and share lookups,
and [Run the Azure Key Vault secret cache integration tests](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/run-azure-key-vault-secret-cache-integration-tests.md)
to test against a real vault.

Licensed under the Mozilla Public License 2.0.
