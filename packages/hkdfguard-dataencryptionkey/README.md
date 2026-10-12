# hkdfguard-dataencryptionkey

Versioned key rings of data encryption keys, string data protectors, and the enc::v{version}::{base64} format.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-dataencryptionkey
```

```python
import hkdfguard.dataencryptionkey
```

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
