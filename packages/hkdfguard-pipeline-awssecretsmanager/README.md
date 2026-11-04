# hkdfguard-pipeline-awssecretsmanager

The end of a provisioning pipeline over AWS Secrets Manager: pulls a fixed list of secrets, taking each out of the response before botocore can make it a str, encrypts it at once with a pipeline data protector and writes one encrypted file per secret.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-pipeline-awssecretsmanager hkdfguard-cryptoprovider-aesgcm256 hkdfguard-dataencryptionkey
```

```python
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider
from hkdfguard.pipeline.awssecretsmanager import AwsSecretsManagerSecretPipelineWriter

with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector,
      AwsSecretsManagerSecretPipelineWriter(protector, ["prod/app#username", "prod/app#password", "prod/api-key"]) as writer):
    writer.pull_secrets()                                    # or: await writer.pull_secrets_async()
    writer.write_protected_secret_files("/etc/myapp/secrets")  # prod__app__username, prod__app__password, prod__api-key
    # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.
```

No key ring is involved, and the writer is independent of `hkdfguard-cache-awssecretsmanager`.
Naming, encrypting, keeping and writing are `SecretPipelineWriter`'s (`hkdfguard-pipeline`); this
package only reads.

- **Names.** `name` reads a secret's whole `SecretString`; `name#key` the `key` member of a
  key/value secret (a `SecretString` holding a JSON object, as the console stores one), from the same
  single call. Each secret's `AWSCURRENT` version is read with `GetSecretValue`, so the principal
  needs only `secretsmanager:GetSecretValue` on them (and `kms:Decrypt` on a customer managed key
  that encrypts them); the writer never lists secrets. A name Secrets Manager can't hold - anything
  but 1-512 ASCII letters, digits and `/_+=.@-` - or holding `+`, `=` or `@`, which no file name can,
  is refused with `ValueError` when the writer is made.
- **Values.** A `SecretBinary` is refused with `InvalidSecretDataError`: the protector encrypts text.
  A secret that doesn't exist (`ResourceNotFoundException`) or is empty is reported missing.
- **Failures.** Anything else - access denied, a secret scheduled for deletion, AWS unreachable, no
  credentials - raises botocore's exception (`ClientError`, or the client's modeled subclass, or a
  `BotoCoreError`), and nothing is kept; a response body that can't be trusted as Secrets Manager's
  raises `InvalidSecretDataError`.
- **The client.** Without one, the writer makes its own -
  `botocore.session.get_session().create_client("secretsmanager")`, with the region and credentials
  from the environment or profile (IRSA or EKS Pod Identity on EKS) - and closes it on `close()`.
  Pass `client=` to use your own (`boto3.client("secretsmanager", region_name=...)`), configured with
  its own timeouts and retries; the writer leaves it open. botocore is synchronous, so
  `pull_secrets_async` makes each call in a worker thread.

**A secret never becomes a `str`.** As `hkdfguard-cache-awssecretsmanager` does, the writer
registers one handler on the client's event system, `before-parse.secrets-manager.GetSecretValue`,
ahead of any registered before it. For the writer's own calls only - tracked per thread with a
`ContextVar` - it takes the `SecretString` out of a successful response's body with `SecretJsonBody`,
encrypts it, and hands botocore's parser the body with `SecretString` and `SecretBinary` replaced by
`""`. Every bytearray of HkdfGuard's that held the value is zeroed. Out of reach: botocore reads the
whole body into an immutable `bytes` before any hook runs, and that copy lives until it is collected.
A client whose responses never reach the endpoint - a `botocore.stub.Stubber`, say - is refused with
`RuntimeError` rather than read, since its value would already be a `str`.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
