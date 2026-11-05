# hkdfguard-cache-jsonsecretsfile

A protected read-only cache over one JSON file holding every secret, already encrypted, as a secret pipeline writes it: read through TrustedFile on the first lookup, every value authenticated under its name, and kept still encrypted.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-cache-jsonsecretsfile
```

```python
from hkdfguard.cache.jsonsecretsfile import JsonSecretsFileReadOnlyCache
from hkdfguard.dataencryptionkey import DefaultFormatProvider
from hkdfguard.securefile import KeyFileTrust

deployers = KeyFileTrust(unix_user_ids=[1001])  # the account that deploys secrets
secrets = JsonSecretsFileReadOnlyCache("/etc/myapp/secrets.json", deployers, key_ring, DefaultFormatProvider())

result = bytearray(secrets.find_max_decrypted_length("db-password") or 0)
written = secrets.decrypt("db-password", result)  # 0 if the file holds no such secret; or: await secrets.decrypt_async(...)
```

The file is a single JSON object mapping each secret's name to its value, encrypted and formatted
(`enc::v3::...`) - what `SecretPipelineWriter.write_json_secrets` (`hkdfguard-pipeline`, and .NET's
`WriteJsonSecrets`) writes, or `write_json_secrets_async` to the stdin of
`ssh -T host sudo -n tee /etc/myapp/secrets.json`:

```json
{
  "api-key": "enc::v3::...",
  "db-password": "enc::v3::..."
}
```

- **Loaded as one.** Nothing is read up front. The first lookup reads the whole file through
  `TrustedFile` (`hkdfguard-securefile`) and authenticates every value in it under its name; then
  every lookup is served from memory, the values still encrypted as the file holds them. A changed
  file is picked up by a new cache instance.
- **Trusted location.** The file is refused with `PermissionError` unless it and every folder above
  it are owned and modifiable only by the operating system's administrators and the principals the
  `KeyFileTrust` adds. Add the account that deploys secrets, never the one the application runs as.
- **Bound to its name.** Each value must be encrypted with the purpose
  `ProtectedConfigurationPurpose.for_key(name)`, as `AesGcmPipelineDataProtector.encrypt(value, name)`
  writes it. A value moved under another name fails the whole load with
  `AuthenticationTagMismatchError`, and one under a key version the ring doesn't hold with
  `KeyNotFoundError`; nothing is kept, so the file is read again on the next lookup.
- **Exactly that object.** Each name must be a `FilePerSecretCache` name (1-255 ASCII letters,
  digits, `-`, `_` and `.`, not starting with `.`), no name twice ignoring case, and each value a
  non-empty string, in strict JSON with nothing after the object; anything else is refused with
  `InvalidSecretDataError` (`hkdfguard-cache`), and a value that isn't a formatted value with
  `EncryptedFormatError`. A file longer than `max_file_length` (1 MiB by default) raises
  `FileTooLargeError`, an `OSError`.
- **Names.** Looked up ignoring ASCII case, as the values are bound. A name that couldn't be one
  (for example `ConnectionStrings:Admin`) returns 0, as does every name while the file, or a folder
  above it, is missing - which isn't remembered - so the cache can sit in a `ProtectedCacheCollection`
  beside other sources.
- **Threads and asyncio.** `decrypt` loads the file on the calling thread; `decrypt_async` in a
  worker thread, so the event loop isn't blocked. One load runs at a time, and lookups made meanwhile
  are served from it.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
