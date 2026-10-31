# hkdfguard-keywrapping-hashicorpvault

Wraps DEKs under one key in a HashiCorp Vault transit secrets engine, through the standard library's HTTP client, reading key files only from where no untrusted account could have replaced them.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others, and a key file made by any port's Vault transit wrapper is read by the others. Every
distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-keywrapping-hashicorpvault
```

```python
import os

from hkdfguard.keywrapping.hashicorpvault import HashiCorpVaultTransitKeyWrapper, StaticVaultTokenSource

token = StaticVaultTokenSource(os.environ["VAULT_TOKEN"])  # copied into a bytearray, zeroed on close
wrapper = HashiCorpVaultTransitKeyWrapper("https://vault.example.com:8200", "myapp-kek", token,
                                          "com.example.myapp")  # the context, bound as associated_data
```

The package has no HTTP dependency: requests go through the standard library's `http.client`, and
HashiCorp ships no Python SDK. `wrap` calls `transit/encrypt/{key}`, `unwrap` calls
`transit/decrypt/{key}`, and `generate_and_wrap` calls `transit/datakey/wrapped/{key}` - or, with a
context, which that endpoint ignores, generates the DEK here and calls encrypt. A wrapped DEK is
Vault's ciphertext, `vault:v{n}:...`, in ASCII.

The token comes from a `VaultTokenSource`, which copies it into a bytearray the wrapper zeroes once
the request is sent; the DEKs sent and revealed, and Vault's answers, are held only in bytearrays
the wrapper zeroes. Options (`HashiCorpVaultTransitKeyWrapperOptions`) set the mount (`transit`), a
Vault Enterprise namespace, the per-attempt timeout (30 seconds), the retries of transient failures
(3, backing off from 200 ms) and an `ssl_context` for a private CA. The address must be https, except
on loopback; no redirect is ever followed.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) ("Wrapping under HashiCorp
Vault transit instead") and [Wrap keys with HashiCorp Vault transit](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/use-hashicorp-vault-transit.md)
for the key, policies, tokens and key files.

Licensed under the Mozilla Public License 2.0.
