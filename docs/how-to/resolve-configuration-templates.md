# Resolve configuration templates from protected caches

This page fills the `${name}` items in a template, such as a connection string or a configuration
file, with secrets from HkdfGuard's protected caches. Everything it uses is in one distribution,
`hkdfguard-integration-configurationresolver`. That distribution is the Python port of .NET's
`HkdfGuard.Integration.ConfigurationResolver`, together with the parts of
[ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) that it needs:
the token, the reader, the resolver and the value-provider contract.

Any `ProtectedReadOnlyCache` can supply the values:

- a `ProtectedCache`, a `ProtectedCacheCollection` or a `FilePerSecretCache`
- a remote secret store's cache: `AwsSecretsManagerSecretCache`, `AzureKeyVaultSecretCache`,
  `GoogleSecretManagerSecretCache` or `HashiCorpVaultSecretCache`

## 1. Install

```
pip install hkdfguard-integration-configurationresolver
```

Add the distribution for your cache too, such as `hkdfguard-cache-hashicorpvault`. Everything below
is imported from `hkdfguard.integration.configurationresolver`.

## 2. Resolve a template

A template's key is the cache's name for the value, unchanged. For a remote cache that includes the
`secret#key` form, so `${app-config#password}` is the `password` key of the secret `app-config`.

```python
from hkdfguard.abstractions import ArrayUtility
from hkdfguard.integration.configurationresolver import ConfigurationItemReader, ConfigurationResolverBuilder, DefaultToken

# secrets is any ProtectedReadOnlyCache, such as a HashiCorpVaultSecretCache.
template = "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"

token = DefaultToken()
reader = ConfigurationItemReader(token)
reader.read_keys(template)

resolver = ConfigurationResolverBuilder().with_token(token).with_reader(reader).add_protected_cache(secrets).build()

connection_string = bytearray(1024)
try:
    length = resolver.resolve(template, connection_string)
    ...  # use memoryview(connection_string)[:length]
finally:
    ArrayUtility.zero_memory(connection_string)
```

The resolver looks up only the keys the reader read from the template. Read the template from a
trusted source, since it decides which secrets are revealed. Write `$${name}` for the literal text
`${name}`.

A missing value raises `ConfigurationKeyError` with `error` set to `ConfigurationKeyErrorCode.NOT_FOUND`,
and a destination that is too small raises `DestinationTooSmallError`. A cache's own exception, such
as a remote store refusing access, propagates unchanged.

> **Security:** Each value is decrypted straight into the destination, or into a `bytearray` that is
> zeroed once the value is copied out. It never becomes a `str`. If resolving fails, the resolver
> zeroes the whole destination. The template itself, when you pass a `str`, is immutable and can't
> be zeroed; pass a `bytearray` for a template that holds secrets.

### Why prefetch

Value providers are synchronous. The first time a remote cache is asked for a secret, it fetches it,
and a synchronous lookup blocks the thread until the fetch returns. `prefetch_async` asks the cache
for each of the reader's keys without blocking the event loop. The cache keeps every value it
fetches, encrypted, so `resolve` then reads only from memory:

```python
from hkdfguard.integration.configurationresolver import ConfigurationItemResolver, ProtectedCacheValueProvider

provider = ProtectedCacheValueProvider(secrets)
await provider.prefetch_async(reader)
resolver = ConfigurationItemResolver(token, reader, provider)
```

Prefetching asks for each key once. A key the cache doesn't have is skipped then, and reported by
`resolve`. For a local cache, prefetching does nothing and you can leave it out.

## 3. Combine it with other providers

Pass several providers, highest priority first. The first one that has a key supplies its value.
Any `ValueProvider` works. For one over your own settings that aren't secret, subclass
`ValueProviderBase` and implement `try_get_bytes` and `_find_byte_count`:

```python
resolver = ConfigurationItemResolver(token, reader, ProtectedCacheValueProvider(secrets), my_settings_provider)
```

## 4. Keep templates in the caches themselves

`ResolvingProtectedCacheCollection` resolves templates for you, on lookup. It works like
`ProtectedCacheCollection`: you add sources, and it checks them in order. When the value it finds
holds items, it resolves them from the same sources, encrypts the result under your key ring, and
caches it. Later lookups only decrypt the cached result. A value without items is answered by its
source, unchanged.

Because the collection is itself a `ProtectedReadOnlyCache`, anything that reads a cache can read
resolved templates without knowing they were templates:

```python
from hkdfguard.integration.configurationresolver import ResolvingProtectedCacheCollection

# key_ring is your application's KeyRing. local holds, say, the encrypted value
# "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"
# under the name "orders.connection-string"; vault is a HashiCorpVaultSecretCache.
secrets = ResolvingProtectedCacheCollection(key_ring).add(local).add(vault)

max_length = await secrets.find_max_decrypted_length_async("orders.connection-string")
connection_string = bytearray(max_length or 0)
length = await secrets.decrypt_async("orders.connection-string", connection_string)
```

The async members look up the template and every value it names through each source's async
members, so a remote source doesn't block the event loop. Items can also come from value providers
that are asked after every source, for values that aren't secret:

```python
secrets = ResolvingProtectedCacheCollection(key_ring).add(local).add(vault).add_value_provider(my_settings_provider)
```

> **Security:** Any value in any source that holds `${...}` is a template, and a template can name
> any value in any source. Add only sources you trust as much as the secrets they can reach.

Some things to know:

- **Resolved values are kept until you invalidate them.** A value a template uses can change, for
  example through an `add_or_update` or a rotated remote secret. When it does, call
  `invalidate(name)` with the template's name, or `clear()`. The next lookup resolves it again. A
  resolution already under way when you call either doesn't cache its result.
- **Items are resolved one level deep.** An item whose value is itself a template inserts that
  template's text unresolved.
- **A template that names a missing value raises** `ConfigurationKeyError` on lookup, rather than
  reporting the template's name missing. A template that resolves to nothing is reported missing, as
  an empty value can't be cached.
- **Names match exactly**, as the sources' own names may. The collection keeps `Db` and `db` apart,
  even though HkdfGuard's caches otherwise ignore ASCII case.
- **Resolved values are capped** at `max_resolved_length` bytes, 1 MiB by default. A longer one
  raises `RuntimeError`. Set it, and the token, with the keyword arguments
  `ResolvingProtectedCacheCollection(key_ring, token=..., max_resolved_length=...)`.

## Values as strings

`ValueProvider.try_get_value` returns a value as a `str`, which can't be zeroed. The resolver never
calls it, and `ProtectedCacheValueProvider` raises `RuntimeError` if anything else does. When a
caller truly needs strings, opt in:

```python
provider = ProtectedCacheValueProvider(secrets, allow_string_values=True)
```

## Differences from .NET

- **UTF-8 only.** Python has no mutable char buffer, so values are written as UTF-8 into a
  `bytearray` or `memoryview`, and there is one `resolve`. A source may be a `str`, which is
  encoded, or UTF-8 bytes. `TryGetChar` is `try_get_bytes`, and an item's `source_index` is a byte
  index into the UTF-8 source.
- **Tuples, not out parameters.** `try_get_bytes` returns `(ValueStatus, written)`, and
  `try_get_value` returns `(ValueStatus, value)`. `ValueProviderBase`'s `TryGetByteCount` is
  `_find_byte_count`, returning the count or `None`.
- **Exceptions are named as Python names them.** `ConfigurationKeyException` is
  `ConfigurationKeyError`, and its `ConfigurationKeyError` enum is `ConfigurationKeyErrorCode`,
  whose values are the .NET names, so messages read as .NET's do. The destination's
  `ArgumentException` is `DestinationTooSmallError`, a `ValueError`. `ArgumentNullException` is
  `TypeError`, and `InvalidOperationException` is `RuntimeError`.
- **Python names.** Methods are snake_case, and `init` properties are keyword-only arguments. The
  resolver needs only a reader's keys, the `KeyReader` base class; `ConfigurationItemReader` reads
  them with `read_keys`, `read_keys_from` (a binary stream, with an optional encoding and byte order
  mark detection) and `read_keys_all`. `AddProtectedCache` is a method of the builder, and
  `PrefetchAsync` is `prefetch_async`, taking a reader or the keys.
- Only the parts of ConfigurationResolver this integration uses are ported. The file-secret,
  environment-variable and dictionary providers, `StringValueProviderBase`, `SecretBuffer`, and the
  Microsoft.Extensions.Configuration support are not.
