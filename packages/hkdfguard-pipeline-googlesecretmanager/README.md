# hkdfguard-pipeline-googlesecretmanager

The end of a provisioning pipeline over Google Cloud Secret Manager: pulls a fixed list of secrets, taking each payload out of the response before the client can parse it, encrypts it at once with a pipeline data protector and writes one encrypted file per secret.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-pipeline-googlesecretmanager hkdfguard-cryptoprovider-aesgcm256 hkdfguard-dataencryptionkey
```

```python
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider
from hkdfguard.pipeline.googlesecretmanager import GoogleSecretManagerSecretPipelineWriter

# A client of the writer's own, signed in with Application Default Credentials (Workload Identity on GKE).
with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector,
      GoogleSecretManagerSecretPipelineWriter.create("my-project", protector, ["db-login#username", "db-login#password", "api-key"]) as writer):
    writer.pull_secrets()                                    # or: await writer.pull_secrets_async()
    writer.write_protected_secret_files("/etc/myapp/secrets")  # db-login__username, db-login__password, api-key
    # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.
```

No key ring is involved, and the writer is independent of `hkdfguard-cache-googlesecretmanager`.
Naming, encrypting, keeping and writing are `SecretPipelineWriter`'s (`hkdfguard-pipeline`); this
package only reads.

- **Names.** `id` reads the latest version's whole payload; `id#key` the `key` member of a payload
  holding a JSON object, from the same single call. Each secret's latest version is read with
  `AccessSecretVersion`, so the principal needs only `secretmanager.versions.access` (the Secret
  Manager Secret Accessor role), never a list permission. IDs are 1-255 ASCII letters, digits,
  hyphens and underscores; any other is refused with `ValueError` when the writer is made.
- **Answers.** A secret that doesn't exist or has no versions (`NOT_FOUND`), or whose payload is
  empty, is reported missing. A payload that isn't UTF-8 text is refused with
  `InvalidSecretDataError`: the protector encrypts text. A payload whose CRC32C doesn't match the
  checksum Google returns, or a response naming a different secret, is refused with
  `CryptographicError`. Any other failure raises the client's `GoogleAPICallError` (or
  google-auth's exception for a credential that can't get a token), and nothing is kept.
- **The client.** `create(project_id, protector, secret_names, credentials=None, client_options=None)`
  makes a gRPC client of the writer's own, which `close()` closes; the constructor takes a
  `SecretManagerServiceClient` of yours instead, whose transport must be gRPC (the default) and which
  is left open. Only its channel is used: every call is retried as the client retries
  `AccessSecretVersion` by default (`RESOURCE_EXHAUSTED` and `UNAVAILABLE`, with exponential
  backoff), all within `timeout` (60 seconds). `pull_secrets_async` reads through a future on the
  same channel, blocking neither the event loop nor a thread; cancelling it cancels the call.

**The payload never becomes `bytes`.** As `hkdfguard-cache-googlesecretmanager` does, the writer
makes `AccessSecretVersion` on the client's channel with a response deserializer of its own, which
reads the response straight from the message gRPC received and copies the payload into a bytearray.
That bytearray is encrypted from - whole, and each JSON key unescaped into one of its own - and then
zeroed, refused or not; the client's protobuf message, which would hold the payload in an immutable
`bytes`, is never built. Out of reach: the message itself, which gRPC hands the deserializer as
`bytes`, and the transport's buffers below it.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
