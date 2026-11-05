# hkdfguard-pipeline-azurekeyvault

The end of a provisioning pipeline over Azure Key Vault secrets: pulls a fixed list of secrets, taking each out of the response before the SDK can make it a str, encrypts it at once with a pipeline data protector and writes one encrypted file per secret.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others. Every distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-pipeline-azurekeyvault hkdfguard-cryptoprovider-aesgcm256 hkdfguard-dataencryptionkey azure-identity
```

```python
from azure.identity import DefaultAzureCredential
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider
from hkdfguard.pipeline.azurekeyvault import AzureKeyVaultSecretPipelineWriter

with (AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector,
      AzureKeyVaultSecretPipelineWriter("https://myvault.vault.azure.net/", DefaultAzureCredential(), protector,
                                        ["Db-Login#username", "Db-Login#password", "Api-Key"]) as writer):
    writer.pull_secrets()                                    # or: await writer.pull_secrets_async()
    writer.write_protected_secret_files("/etc/myapp/secrets")  # Db-Login__username, Db-Login__password, Api-Key
    # Then hand protector.get_key_as_base64() to the wrap tool, and register the key at version 3.
```

No key ring is involved, and the writer is independent of `hkdfguard-cache-azurekeyvault`. Naming,
encrypting, keeping and writing are `SecretPipelineWriter`'s (`hkdfguard-pipeline`); this package
only reads.

- **Names.** `name` reads a secret's whole value; `name#key` the `key` member of a secret whose
  value is a JSON object, from the same single call. Each secret's current version is read with Get
  Secret, so the principal needs only the **Key Vault Secrets User** role (`get`), never `list`.
  Names are 1-127 ASCII letters, digits and hyphens; any other is refused with `ValueError` when the
  writer is made. Key Vault compares names ignoring case, and so do file names, so two names
  differing only in case are refused too.
- **Answers.** A secret that doesn't exist (404) or is empty is reported missing. Any other failure
  raises the Azure SDK's exception - `HttpResponseError` (with its `status_code`),
  `ClientAuthenticationError`, `ServiceRequestError` - and nothing is kept; a response body that
  can't be trusted as Key Vault's raises `InvalidSecretDataError`.
- **The client.** The writer builds its own `SecretClient`, which `close()` closes. `client_options`
  passes keyword arguments to it (`api_version`, `transport`, retries, `per_call_policies`,
  `per_retry_policies`), copied, so the caller's mapping is left as it is. Options that would put a
  policy closer to the network than the writer's capture policy, or replace the pipeline, are refused:
  `policies`, `generated_client`, `authentication_policy`, `custom_hook_policy`, `raw_response_hook`,
  `logging_policy` and `http_logging_policy`. On AKS, Microsoft Entra Workload Identity supplies the
  credential through `DefaultAzureCredential` or `WorkloadIdentityCredential`. The client is
  synchronous, so `pull_secrets_async` makes each call in a worker thread.

**A secret never becomes a `str`.** As `hkdfguard-cache-azurekeyvault` does, the writer's
`SecretClient` has a per-retry pipeline policy, after any of the application's, that asks the
transport for the Get Secret response unread, reads the body into a bytearray of its own with
`SecretJsonBody`, takes the `value` out and encrypts it, and hands `SecretClient` the body with
`value` blanked. azure-core's network trace logging, closer to the network, logs "Body is
streamable" rather than the body, even with `logging_enable`. Every bytearray that held the value is
zeroed. Out of reach: the immutable `bytes` chunks the HTTP stack (requests and urllib3, by default)
reads the body in, and the stack's own buffers.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) for the full package list,
an example, configuration, the differences from the .NET library, and the security notes.

Licensed under the Mozilla Public License 2.0.
