# hkdfguard-securefile

Reads a wrapped-key file only from where no untrusted account could have written or replaced it: the native library's key-file checks, in Python.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-securefile
```

```python
from hkdfguard.securefile import KeyFileTrust, TrustedKeyFile
```

`TrustedKeyFile.read` is what a key wrapper with no native library to read through - a network KMS's,
such as `hkdfguard-keywrapping-awskms` - uses for `KeyWrapper.read_key_file`. It runs on Windows,
Linux and Apple silicon Macs, with no native HkdfGuard library installed: the checks are system calls
made through `ctypes` (Windows) and `os.lstat` (Linux and macOS).

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
