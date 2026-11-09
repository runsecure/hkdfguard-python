# hkdfguard-securefile

Reads a wrapped-key file only from where no untrusted account could have written or replaced it: the native library's key-file checks, in Python.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-securefile
```

```python
from hkdfguard.securefile import FileTooLargeError, KeyFileTrust, TrustedFile, TrustedKeyFile
```

`TrustedKeyFile.read` is what a key wrapper with no native library to read through - a network KMS's,
such as `hkdfguard-keywrapping-awskms` - uses for `KeyWrapper.read_key_file`. It runs on Windows,
Linux and Apple silicon Macs, with no native HkdfGuard library installed: the checks are system calls
made through `ctypes` (Windows) and `os.lstat` (Linux and macOS).

`TrustedFile` reads any other file by the same location rules - the same symbolic-link, ownership
and permission checks, with the same `KeyFileTrust` - but none of a key file's rules about its
contents, for secret files, certificates and anything else that must not have been planted. The
caller bounds its size: `TrustedFile.read(path, trust, max_bytes)` reads at most one byte past
`max_bytes`, refusing a longer file with `FileTooLargeError` (an `OSError`), and returns the
contents, which may be empty, in a bytearray. `TrustedFile.read_with(path, trust, max_bytes, parse)`
hands a read-only view of the contents to `parse` and zeroes the buffer once it returns or raises,
for contents that are themselves secret. A missing file raises `FileNotFoundError`, and an untrusted
location `PermissionError`, as for a key file.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
