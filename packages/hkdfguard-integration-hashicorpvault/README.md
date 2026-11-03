# hkdfguard-integration-hashicorpvault

The Vault client library, and what every HkdfGuard integration with HashiCorp Vault shares: the TLS
settings (`VaultTlsOptions`), the token sources, the address, path and token checks, the retry limits
and backoff, and the error Vault's refusals are reported as.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java. Every distribution installs one subpackage of the
shared `hkdfguard` namespace package.

## VaultClient

`VaultClient` is a port of HashiCorp's [vault-client-go](https://github.com/hashicorp/vault-client-go):
generic `read`, `write`, `list` and `delete` for any path, and typed methods generated from Vault's
OpenAPI spec - logins and tokens (`vault.auth`), the KV, cubbyhole and transit engines
(`vault.secrets`) and a few system endpoints (`vault.system`), each with an `_async` counterpart.
Tokens are held only protected, by a protector on your key ring created for
`VaultClient.TOKEN_PURPOSE`; a login's token is protected as the response is read.

```python
from hkdfguard.integration.hashicorpvault import VaultClient, VaultClientOptions
from hkdfguard.integration.hashicorpvault.schema import AppRoleLoginRequest

with VaultClient(key_ring.create_protector(VaultClient.TOKEN_PURPOSE), VaultClientOptions(address="https://vault.example.com:8200")) as vault:
    vault.set_token(vault.auth.app_role_login(AppRoleLoginRequest(role_id=role_id, secret_id=secret_id)).auth.client_token)
    config = vault.secrets.kv_v2_read("myapp/config")
```

See [Call Vault's API with the HashiCorp Vault client](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/use-hashicorp-vault-client.md).

## What the other Vault integrations share

[hkdfguard-cache-hashicorpvault](https://pypi.org/project/hkdfguard-cache-hashicorpvault/) and
[hkdfguard-keywrapping-hashicorpvault](https://pypi.org/project/hkdfguard-keywrapping-hashicorpvault/)
depend on this distribution - though not on the client itself, since each makes its few requests its
own way, never holding a secret in a `str` - so the two refuse the same addresses, paths and tokens, retry the same way and connect the same way.
The names you meet through them are `VaultRequestError` and `VaultTlsOptions`, which both re-export,
and the token sources.

`VaultTlsOptions` takes CA certificates from PEM (a file, bytes or a directory) or a PKCS#12 trust
store, and a client certificate and key from PEM or a PKCS#12 key store - choosing the key by
`client_key_store_alias` when the store holds several. A store's password is held only protected:
`VaultTlsOptions.protect_password(protector, password)`, with
`key_ring.create_protector(VaultTlsOptions.PASSWORD_PURPOSE)` as `password_protector`; it is
decrypted into a bytearray only while the store is read, and zeroed. JKS stores are refused: convert
one with `keytool -importkeystore -deststoretype PKCS12`. Python's `ssl` loads a client key only from
a file, so the key is written PEM-encrypted under a one-time password held only in memory to a
temporary file, loaded, and deleted at once; it never reaches the disk in the clear.

An address must be https, except on loopback (a local Vault Agent or dev server), and must not hold
credentials, a query or a fragment. A path is `/`-separated segments of letters, digits, `.`, `_` and
`-`, none `.` or `..`. A request that fails transiently is retried 3-10 times, waiting from the
configured delay and doubling up to 10 seconds, plus a random 0-100 ms.

Requires Python 3.12 or later. Licensed under the Mozilla Public License 2.0.
