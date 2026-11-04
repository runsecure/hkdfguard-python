# hkdfguard-pipeline

The shared base of the secret pipeline writers: pull a fixed list of secrets, encrypt each at once with a pipeline data protector bound to its file name, and write one encrypted file per secret, the layout `FilePerSecretCache` reads.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-pipeline
```

```python
import hkdfguard.pipeline
```

A provisioning pipeline runs before a durable KEK exists. It reads the secrets an application needs
from a secret store, encrypts each one at once with an `AesGcmPipelineDataProtector` (one in-memory
key, no key ring), keeps only the ciphertext, and writes one file per secret into a folder - the
folder `FilePerSecretCache` (`hkdfguard-cache`) reads at runtime. The protector's key is then handed
to the native platform's wrap process (`get_key_as_base64()`, on standard input) and registered on
the application's key ring at the protector's version.

`SecretPipelineWriter` is the shared base of the store writers - `hkdfguard-pipeline-awssecretsmanager`,
`-azurekeyvault`, `-googlesecretmanager` and `-hashicorpvault` - which never depend on the runtime
caches:

- **Names.** A secret name is the store's name for a secret, optionally followed by `#` and a key
  it holds: `prod/app#password` is the `password` member of the JSON object the secret `prod/app`
  holds. A name without a key reads the store's default key, if it has one (HashiCorp Vault's
  `value`), or else the secret's whole value. The names are grouped by secret, so each secret is
  read once however many of its keys are listed.
- **Files.** A secret's file name is its name with every `/` and `#` replaced by `__`
  (`SecretPipelineWriter.get_file_name`): `prod/app#password` is written as `prod__app__password`.
  Each value is encrypted bound to its file name - the name `FilePerSecretCache` decrypts it under,
  so a renamed file fails authentication. A name whose file name `FilePerSecretCache` couldn't read
  (1-255 ASCII letters, digits, `-`, `_` and `.`, not starting with `.`), or two names whose file
  names differ only in case, are refused with `ValueError` when the writer is made.
- **Values.** A string member is read as its text; a number, `true` or `false` as its JSON text; a
  null, object, array or empty value is missing. A value that isn't UTF-8 text is refused with
  `InvalidSecretDataError`, since the protector encrypts text, as is a JSON object naming a key twice.
- **Pulling.** `pull_secrets()` reads every secret, then reports every missing one at once with
  `KeyNotFoundError`, keeping the rest; a pull again replaces what the last kept. Any other failure
  propagates, and nothing is kept. `pull_secrets_async()` does the same without blocking the event
  loop. `protected_secrets` maps each file name (found ignoring case) to its encrypted value.
- **Writing.** `write_protected_secret_files(folder)` creates the folder if need be and writes each
  value as UTF-8, with no byte order mark, replacing a file of the same name and leaving every other
  file alone; before a pull it raises `RuntimeError`. Write where the deployment can make the folder
  and files modifiable only by administrators and the principals `FilePerSecretCache` trusts.

**A secret never becomes a `str`.** A store's writer takes the value out of the raw response with
`SecretJsonBody` (from `hkdfguard-cache`), as the runtime caches do, into a bytearray it zeroes; a
JSON object's keys are unescaped one by one into bytearrays of their own, also zeroed; and the bytes
go to `PipelineDataProtector.encrypt`, which checks they are UTF-8 where they lie and encrypts from a
copy of its own that it zeroes. The protector is the caller's and is never closed by a writer; closing
the writer (or leaving its `with` block) releases its connection to the store. A writer isn't
thread-safe.

Another store needs only a subclass, whose `_read_secret` reads one secret and hands its values over:

```python
from collections.abc import MutableMapping, Sequence

from hkdfguard.abstractions import ArrayUtility, PipelineDataProtector
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest


class InMemoryStore:
    def __init__(self, secrets: dict[str, bytes]) -> None:
        self.secrets = secrets

    def read(self, name: str) -> bytearray | None:
        value = self.secrets.get(name)
        return None if value is None else bytearray(value)


class InMemorySecretPipelineWriter(SecretPipelineWriter):
    def __init__(self, store: InMemoryStore, protector: PipelineDataProtector, secret_names: Sequence[str]) -> None:
        super().__init__(protector, secret_names, lambda name: name.isascii() and name.replace("-", "").isalnum())
        self._store = store

    # Hand the values over, or return without doing so if the secret doesn't exist; raise on any other failure.
    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        secret = self._store.read(name)
        if secret is None:
            return
        try:
            self._protect_secret(secret, requests, values)  # the whole value, and the keys asked for
        finally:
            ArrayUtility.zero_memory(secret)
```

For a response body, hand `SecretJsonBody.capture(body, self._receiver(requests, values), "value")`
the body instead, as the store writers do. Override `_read_secret_async` too if the client is
asyncio-based; without it, `pull_secrets_async` runs `_read_secret` in a worker thread.

```python
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider

store = InMemoryStore({"db-login": b'{"username":"app","password":"s3cret"}', "api-key": b"k3y"})
with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector,
      InMemorySecretPipelineWriter(store, protector, ["db-login#username", "db-login#password", "api-key"]) as writer):
    writer.pull_secrets()
    writer.write_protected_secret_files("secrets")  # secrets/db-login__username, db-login__password, api-key
    # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.
```

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
