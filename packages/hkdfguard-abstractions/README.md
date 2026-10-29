# hkdfguard-abstractions

The interfaces, shared rules and base classes every HkdfGuard component builds on.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-abstractions
```

```python
import hkdfguard.abstractions
```

Every `ProtectedReadOnlyCache` has `decrypt_async` and `find_max_decrypted_length_async` alongside
`decrypt` and `find_max_decrypted_length`. Their defaults call the synchronous members, so an existing
implementation keeps working; a cache that fetches over the network overrides them so a miss doesn't
block the event loop. `ProtectedCacheBase` falls back to `_try_populate_async` on an asynchronous miss,
which calls `_try_populate` unless it is overridden too. Cancel a lookup by cancelling the task
awaiting it.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
