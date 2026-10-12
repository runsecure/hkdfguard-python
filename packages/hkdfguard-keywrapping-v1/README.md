# hkdfguard-keywrapping-v1

Wraps DEKs under a KEK held by the platform's native HkdfGuard KMS library (TPM, Platform Crypto Provider, Secure Enclave).

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-keywrapping-v1
```

```python
import hkdfguard.keywrapping.v1
```

**The native HkdfGuard KMS library is not part of this package.** It is installed separately, and is loaded
only from its verified install location (see the repository README, "Native access").

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
