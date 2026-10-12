# hkdfguard-cryptoprovider-aesgcm256

AES-256-GCM crypto provider with background key refresh and a fail-closed refresh-failure policy.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-cryptoprovider-aesgcm256
```

```python
import hkdfguard.cryptoprovider.aesgcm256
```

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
