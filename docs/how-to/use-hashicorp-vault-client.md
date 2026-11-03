# Call Vault's API with the HashiCorp Vault client

This page uses `VaultClient`, from the distribution `hkdfguard-integration-hashicorpvault`, to call
HashiCorp Vault's HTTP API from Python. It covers logging in, managing tokens, the KV and cubbyhole
secrets engines and the transit engine. Generic methods reach anything else Vault exposes.

`VaultClient` is a port of HashiCorp's
[vault-client-go](https://github.com/hashicorp/vault-client-go). It's generated from the same
OpenAPI spec, but only for the endpoints HkdfGuard needs. It's the Python counterpart of .NET's
`HkdfGuard.Integration.HashiCorpVault` and Java's `hkdfguard-integration-hashicorpvault`. Like the
rest of HkdfGuard, it holds Vault tokens only in protected form.

To read secrets into memory your application uses, prefer `HashiCorpVaultSecretCache` (distribution
`hkdfguard-cache-hashicorpvault`). It reads each secret straight into a buffer of its own and keeps
it encrypted. `VaultClient` returns response data as ordinary `str`s and `JsonValue`s, like any
other API client.

## 1. Install the distribution

```bash
pip install hkdfguard-integration-hashicorpvault
```

It needs Python 3.12 or later. Requests go through the standard library's `http.client`. Its only
third-party dependency is `cryptography`, used to read PKCS#12 key stores for TLS. The package is
`hkdfguard.integration.hashicorpvault`, and its models are in
`hkdfguard.integration.hashicorpvault.schema`.

## 2. Create a client

A client needs a token protector: a protector on your application's key ring, created for
`VaultClient.TOKEN_PURPOSE`. Every token the client holds is encrypted with it.

```python
from hkdfguard.integration.hashicorpvault import VaultClient, VaultClientOptions

# key_ring is your application's KeyRing; see the README's example.
token_protector = key_ring.create_protector(VaultClient.TOKEN_PURPOSE)

vault = VaultClient(token_protector, VaultClientOptions(address="https://vault.example.com:8200"))
```

Or take every setting from the environment variables vault-client-go and the `vault` CLI read
(`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT` and the rest):

```python
vault = VaultClient(token_protector, VaultClientOptions.from_environment(token_protector))
```

`from_environment` protects `VAULT_TOKEN` with the protector you pass. Given `None`, it ignores
`VAULT_TOKEN`. The options are a frozen dataclass: change what it read with `dataclasses.replace`.

The client is a context manager. Close it when you're done with it. Each request opens a connection
of its own and closes it once Vault has answered.

To trust a private CA or present a client certificate, set `tls` to a `VaultTlsOptions`. It takes
PEM, as vault-client-go does, or a password-protected PKCS#12 trust store (`trust_store_file`) and
client key store (`client_key_store_file`). JKS isn't read.

A store's password is given encrypted, by a protector on your key ring created for
`VaultTlsOptions.PASSWORD_PURPOSE` (`VaultTlsOptions.protect_password`). It's decrypted only while
the store is read. To supply your own `ssl.SSLContext` instead, set `ssl_context`. You can't combine
the two.

The transit key wrapper and the secret cache take the same `VaultTlsOptions` through their own
`tls` option.

> **Security:** The address must be `https`. Plain `http` is allowed only on a loopback address (a
> local Vault Agent or dev server), or when you set `allow_unencrypted_http`, because every request
> carries a token.

## 3. Authenticate

Log in with any auth method. The `auth` methods are generated, one per endpoint. The token in the
response is protected as the response is read, so it's a `str` only for the protector's own call.
Hand it straight to the client:

```python
from hkdfguard.integration.hashicorpvault.schema import AppRoleLoginRequest

login = vault.auth.app_role_login(AppRoleLoginRequest(role_id=role_id, secret_id=secret_id))
vault.set_token(login.auth.client_token)
```

For a token you already hold, `vault.set_token(token)` protects it and keeps only the protected
form. Python can't erase a `str`, so read the token once and keep no other reference to it.

To log in, renew and replace tokens on your own schedule, implement `VaultTokenProvider`. The client
asks it for a protected token on every request.

These are the same token types `HashiCorpVaultSecretCache` takes. A protected token only works for
the protector it was protected with, though. The cache's purpose
(`HashiCorpVaultSecretCache.TOKEN_PURPOSE`) isn't the client's, so protect a token separately for
each. The transit key wrapper takes a `VaultTokenSource` instead, because it runs before there is a
key ring.

## 4. Call Vault

The generated methods are grouped as vault-client-go groups them. Only a subset of Vault's API is
generated: the endpoints listed in `generator.json`.

| Group | What it has |
|---|---|
| `vault.auth` | Every auth method's login (`app_role_login`, `kubernetes_login`, `aws_login`, `cert_login`, `jwt_login`, ...), the JWT/OIDC browser flow and Okta push verification, and creating, looking up, renewing and revoking tokens |
| `vault.secrets` | The KV version 2 and 1 engines, cubbyhole, and the whole transit engine (encrypt, decrypt, rewrap, data keys, sign, verify, HMAC, random bytes, and creating, rotating, configuring and trimming keys) |
| `vault.system` | Health, seal status, leader status, the list of mounts, and wrapping (wrap, unwrap, rewrap, lookup) |

Configuring auth methods and other secrets engines, policies, identity and the rest of `sys/` aren't
generated. Use the generic methods below, or add the endpoints to `generator.json` and regenerate.

Each generated method is named after the endpoint's operation ID: `kv-v2-read` is `kv_v2_read`. It
takes:
- the path's parameters, then a typed request body;
- the query parameters, as keyword arguments;
- `options`, a `VaultRequestOptions` for that request.

It returns a `VaultResponse` whose `data` is a typed model from `schema`. Where Vault's spec
doesn't type the response, `data` is a `dict[str, JsonValue]`. Every method has an `_async`
counterpart (`kv_v2_read_async`) for asyncio.

```python
from hkdfguard.integration.hashicorpvault import VaultRequestOptions
from hkdfguard.integration.hashicorpvault.schema import KvV2WriteRequest

# The engine's default mount is "kv-v2"; a dev server mounts KV version 2 at "secret".
kv = VaultRequestOptions(mount_path="secret")

vault.secrets.kv_v2_write("myapp/config", KvV2WriteRequest(data={"feature": "on"}), options=kv)

config = vault.secrets.kv_v2_read("myapp/config", options=kv)
feature = config.data.data["feature"].as_str()

mounts = vault.system.mounts_list_secrets_engines()
```

The generic methods reach any path, typed or not:

```python
raw = vault.read("sys/mounts")
vault.write("secret/data/myapp/flags", {"data": {"beta": True}})
keys = vault.list("secret/metadata/myapp")
vault.delete("secret/metadata/myapp/flags")
```

A request body is written as JSON from a `Mapping`, `list`, `tuple`, `str`, number, `bool`, aware
`datetime`, model or `JsonValue`. A UTF-8 `bytearray` is written as a string without becoming a
`str`. The body is held in a bytearray that is zeroed once the request is done.

`write_from_bytes` and `write_from_stream` send a body you've already encoded. `read_raw` returns
Vault's response unparsed, as a `VaultRawResponse` whose body you read and close.

`VaultRequestOptions` sets things for one request:
- another token, or a namespace;
- extra headers or query parameters;
- MFA credentials or response wrapping;
- callbacks, or a forwarding mode.

The client's own `set_...` methods set the same things for every later request. A request's
settings win over the client's.

A request callback is handed a `VaultRequest` before the token is added, and can add headers to
it. A response callback gets that request (still without its token), the status and the response's
headers.

Each method blocks until Vault answers. Its `_async` counterpart runs the request on a thread of its
own. Cancelling the awaiting task abandons the request and shuts its connection down.

### Wrap and unwrap a response

```python
from dataclasses import replace
from datetime import timedelta

from hkdfguard.integration.hashicorpvault.schema import KvV2ReadResponse

wrapped = vault.secrets.kv_v2_read("myapp/config", options=replace(kv, response_wrapping_ttl=timedelta(minutes=5)))
unwrapped = vault.unwrap(wrapped.wrap_info.token, KvV2ReadResponse.from_json)
```

The wrapping token is protected by this client's protector. A process with a different key ring
can't use it as it is.

### Handle errors

A request fails with `VaultResponseError` when Vault refuses it, carrying Vault's status and error
messages. A redirect the client won't follow fails with `VaultRedirectError`. Both are a
`VaultRequestError`, which the cache and the transit key wrapper fail with too.

A request that gets no answer fails with the `OSError` or `http.client.HTTPException` the
connection raised. One that outlives `request_timeout` (60 seconds by default) fails with
`TimeoutError`. An answer that isn't the JSON expected fails with `VaultJsonError`.

```python
from hkdfguard.integration.hashicorpvault import VaultResponseError

try:
    vault.secrets.kv_v2_read("myapp/missing", options=kv)
except VaultResponseError as error:
    if error.status_code != 404:
        raise
    # No such secret.
```

## How it differs from vault-client-go

| | vault-client-go | `VaultClient` |
|---|---|---|
| Tokens | Plain strings (`SetToken(string)`) | Protected by the token protector; decrypted only into the request's header |
| Login and wrapping tokens in responses | Strings | Protected as they're read (`StaticVaultToken`) |
| Address | Any scheme | `https`, or `http` on loopback; any other `http` needs `allow_unencrypted_http` |
| Unix domain sockets | Yes | No |
| Redirects | Follows one, never `https` to `http` | Refused (`VaultRedirectError`) unless `follow_redirects` is set; then as vault-client-go |
| Address with a path | Path dropped | Kept as a prefix, for Vault behind a reverse proxy |
| Free-form values | `map[string]interface{}` | `dict[str, object]` sent, `dict[str, JsonValue]` returned |
| Optional fields | Zero values left out (`omitempty`) | `None` by default and left out, so `False` and `0` can be sent |
| Response fields Vault types differently from its spec | Decoding fails | A number where the spec says string is read as its text |
| Rate limiting | `rate.Limiter` | `VaultRateLimiter`, the same token bucket |
| Retries, MFA, namespaces, replication, callbacks, TLS | Yes | Yes, as vault-client-go |
| Every request | | Sends `X-Vault-Request: true`, as the `vault` CLI does |
| Typed endpoints | All 907 | The 103 `generator.json` names: logins and tokens, KV, cubbyhole, transit, and a few of `sys/` |

### Where Python can't keep a token out of a `str`

Unlike the .NET and Java clients, a token Vault returns becomes a `str` for one call: Python's
`DataProtector.encrypt` takes only a `str`. The token is otherwise unescaped into a bytearray that
is zeroed once it's protected.

Going the other way, a token is decrypted into a bytearray and handed to `http.client` as a view. It
is never a `str`. `http.client` copies it into the request's header line, an immutable `bytes` the
garbage collector frees once the request is sent.

## Regenerate from a newer spec, or for other endpoints

The `_generated` subpackage of `hkdfguard.integration.hashicorpvault` is produced by
`scripts/generate-vault-client.py` from the distribution's `openapi.json`. That file is
vault-client-go's spec (Vault API 1.15.0), the same one the .NET and Java libraries are generated
from.

As in vault-client-go, some operations are left out, along with their schemas:
- those whose ID ends in `2`, `3` or `4`, which are alternative paths to the same endpoint;
- those whose ID starts with `enterprise-stub`.

`generator.json`, beside the spec, narrows that to the endpoints HkdfGuard needs. Its `include`
list holds regular expressions matched against operation names in PascalCase, as .NET names its
methods (`"^KvV2"`, `"^AppRoleLogin$"`). Only the operations they match are generated, with only
the schemas those operations use.

Each expression must match at least one operation. A typo, or an endpoint a newer spec has dropped,
stops the generator instead of quietly generating less. To generate another endpoint, add a pattern
and regenerate. To generate everything vault-client-go does, delete the file.

To update:

1. Replace `packages/hkdfguard-integration-hashicorpvault/openapi.json` with the newer spec. The
   generator doesn't fetch it: pull it yourself. The simplest source is vault-client-go's own
   `openapi.json`. A spec read from your own Vault must use generic mount paths
   (`{kv_v2_mount_path}` and so on), as vault-client-go's does. The generator turns those into
   `VaultRequestOptions.mount_path` and needs a default for each.
2. From `hkdfguard-python`, run the generator. It uses only the standard library:

   ```bash
   uv run python scripts/generate-vault-client.py
   ```

   It reads `generator.json` beside the spec, or the file `--settings` names. It rewrites only the
   files that changed, and deletes `.py` files it no longer produces. `--spec` and `--output`
   choose other files.
3. Run the tests. `test_the_generated_code_is_what_the_spec_generates` fails whenever the
   checked-in code isn't what the spec and `generator.json` generate, so a hand edit to
   `_generated` doesn't survive. `test_the_generated_api_is_the_subset_generator_json_names` pins
   the subset itself; update it when you change `generator.json` on purpose.

Keep the .NET and Java libraries' `openapi.json` and `generator.json` the same as these, so the
clients keep the same endpoints and models.

The generator may meet something it doesn't handle, such as an inline object with its own
properties or a header parameter. If it does, it stops with a `ValueError` naming the operation or
schema. Extend the generator rather than editing its output.
