# hkdfguard-integration-configurationresolver

Resolves the `${name}` items in a template - a connection string, a configuration file - with
secrets from HkdfGuard's protected caches, and caches resolved templates encrypted.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.
This one is the port of .NET's `HkdfGuard.Integration.ConfigurationResolver`, together with the parts
of [ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) it uses: the
token, the reader, the resolver and the value-provider contract.

```
pip install hkdfguard-integration-configurationresolver
```

```python
import hkdfguard.integration.configurationresolver
```

## Resolve a template

A template's key is the cache's name for the value, unchanged; for a remote cache that includes the
`secret#key` form. Any `ProtectedReadOnlyCache` can supply the values.

```python
from hkdfguard.abstractions import ArrayUtility
from hkdfguard.integration.configurationresolver import ConfigurationItemReader, ConfigurationResolverBuilder, DefaultToken

template = "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"

token = DefaultToken()
reader = ConfigurationItemReader(token)
reader.read_keys(template)  # only the keys of this trusted template may be resolved

resolver = ConfigurationResolverBuilder().with_token(token).with_reader(reader).add_protected_cache(secrets).build()

connection_string = bytearray(1024)
try:
    length = resolver.resolve(template, connection_string)
    ...  # use connection_string[:length]
finally:
    ArrayUtility.zero_memory(connection_string)
```

Each value is decrypted straight into the destination, or into a `bytearray` that is zeroed once it
is copied out, and never becomes a `str`. If resolving fails, the destination is zeroed. Write
`$${name}` for the literal text `${name}`.

For a remote cache, `await ProtectedCacheValueProvider(secrets).prefetch_async(reader)` first, so
resolving reads only from memory instead of blocking on a fetch.

## Keep templates in the caches themselves

`ResolvingProtectedCacheCollection` is a `ProtectedReadOnlyCache` over several sources, checked in
order. A value holding items is resolved on its first lookup, from those same sources (then any
value providers added with `add_value_provider`), encrypted under the key ring, and kept until
`invalidate(name)` or `clear()`. A value without items is answered by its source.

```python
from hkdfguard.integration.configurationresolver import ResolvingProtectedCacheCollection

secrets = ResolvingProtectedCacheCollection(ring).add(local).add(vault)
max_length = await secrets.find_max_decrypted_length_async("orders.connection-string")
```

Any value in any source that holds `${...}` is a template, and a template can name any value in any
source: add only sources you trust as much as the secrets they can reach. Items are resolved one
level deep, names match exactly, and resolved values are capped at `max_resolved_length` bytes.
