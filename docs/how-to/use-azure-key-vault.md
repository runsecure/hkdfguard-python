# Wrap keys with Azure Key Vault

This page sets up two Azure Key Vault keys as HkdfGuard's KEK and uses them from Python with
`AzureKeyVaultKeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider
KEK.

## Why two keys

A Key Vault (Standard or Premium) offers RSA and EC keys. Only RSA keys can wrap; EC keys can only
sign and verify. RSA-OAEP wrapping needs nothing but the public key, which isn't secret, so on its
own anyone could produce a wrapped DEK holding a key *they* chose, and your application would encrypt
new data under it.

So `AzureKeyVaultKeyWrapper` uses:

- an **RSA key** (2048 or 3072 bits) to wrap and unwrap each DEK, with RSA-OAEP-256;
- a separate **EC P-256 key** to sign each wrapped DEK, with ES256.

Signing happens inside Key Vault and needs the `sign` permission. Unwrap checks the signature
before it unwraps anything. So a key file the application accepts proves it was made by a principal
allowed to sign: give that permission to the pipeline that creates key files, never to the
application.

| | AWS KMS | Azure Key Vault |
|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key |
| Context binding | Encryption context (AAD) | A context string bound into the signature |
| New DEKs | Generated inside KMS | Generated in the process, then wrapped |

Wrapped DEKs aren't interchangeable between wrappers: a key file belongs to the kind of wrapper that
made it. Between languages they are: a key file made by the .NET `AzureKeyVaultKeyWrapper` or the
Java `AzureKeyVaultKeyWrapperImpl` is read by `AzureKeyVaultKeyWrapper`, and the other way round,
given the same two keys and context.

## 1. Create the keys

Create a vault, or use an existing one, with **purge protection** turned on. Deleting a key makes
every DEK wrapped under it, and all data encrypted under those DEKs, permanently unrecoverable;
purge protection keeps a deleted key recoverable for its retention period.

Create the two keys, each allowed only the operations it needs:

```bash
az keyvault key create --vault-name myvault --name myapp-wrap --kty RSA --size 3072 --ops wrapKey unwrapKey
az keyvault key create --vault-name myvault --name myapp-sign --kty EC --curve P-256 --ops sign verify
```

In the portal: **Keys**, **Generate/Import**, then for the first choose **RSA** and 2048 or 3072
bits, and for the second **EC** and **P-256**. After creating each, open its version and clear every
permitted operation except the two above.

Use 2048 or 3072 bits for the RSA key. A 4096-bit key's wrapped DEK is too large for a key file
(`WrappedKeyLimits.MAX_BYTES`, 512 bytes), and wrapping under one is refused.

Copy each key's **key identifier** without the version, for example
`https://myvault.vault.azure.net/keys/myapp-wrap`.

## 2. Grant each identity only what it calls

With Azure RBAC, assign roles on each **key**, not the vault:

| Identity | On the RSA key | On the EC key |
|---|---|---|
| Release pipeline that creates key files | Key Vault Crypto Service Encryption User | Key Vault Crypto User |
| Application | Key Vault Crypto Service Encryption User | Key Vault Crypto Service Encryption User |

Every role here includes reading the key (`get`), which the wrapper needs: the Azure SDK fetches
each key's public half, then wraps under the RSA key and verifies with the EC key in the process.
The application's role on the EC key doesn't include `sign`.

```bash
az role assignment create --assignee <app-principal-id> --role "Key Vault Crypto Service Encryption User" \
  --scope "$(az keyvault show -n myvault --query id -o tsv)/keys/myapp-wrap"
```

With vault access policies instead, which apply to the whole vault: the pipeline gets **Get**,
**Wrap Key** and **Sign**; the application **Get**, **Unwrap Key** and **Verify**.

> **Security:** never give the application `sign` on the EC key (Key Vault Crypto User, Crypto
> Officer, or the Sign access policy). With it, anyone controlling the application, and able to
> replace a key file, could choose its DEK.

If an identity can't have **Get**, every operation becomes a Key Vault call, and each key
identifier you give the wrapper must name a version (`.../keys/myapp-wrap/<version>`): without
`get` the SDK can't report which version it used, and the wrapper refuses to write a key file that
doesn't record it.

## 3. Give the process a credential

Every call is authorized by an Azure `TokenCredential`. Deployed, use a **managed identity**
(`ManagedIdentityCredential()`, or `DefaultAzureCredential()`, which finds it); on a developer
machine, `DefaultAzureCredential` uses your `az login`. Don't give a deployed process a client
secret.

## 4. Create the wrapper

```
pip install hkdfguard-keywrapping-azurekeyvault azure-identity
```

> **TODO (maintainer):** confirm the install command once the distribution is published.

```python
from azure.identity import DefaultAzureCredential
from hkdfguard.keywrapping.azurekeyvault import AzureKeyVaultKeyWrapper

credential = DefaultAzureCredential()
wrapper = AzureKeyVaultKeyWrapper("https://myvault.vault.azure.net/keys/myapp-wrap",
                                  "https://myvault.vault.azure.net/keys/myapp-sign",
                                  credential,
                                  "com.example.myapp")
```

- **Give key identifiers without a version.** New key files then use each key's current version,
  and every key file records the versions it was made with, so both keys can be rotated in Key
  Vault with no change here. Keep an old version enabled for as long as key files made with it are
  in use.
- **The context** is bound into every key file's signature and must be given again, exactly, to
  reveal it. Use one value per application, so a key file made for one can't be used by another
  that shares the keys. It isn't secret.
- **Client options.** The keyword-only `client_options` are passed to each Key Vault
  `CryptographyClient`: `api_version`, `transport`, retry and logging options, for example
  `client_options={"retry_total": 3}`. The wrapper gives each client its key and the credential
  itself.
- **Close it.** The wrapper creates a client for each key version it uses and keeps it for as long
  as the wrapper lives, so a key ring's refresh doesn't fetch the public keys again. Close the
  wrapper (`wrapper.close()`, or `with AzureKeyVaultKeyWrapper(...) as wrapper:`) once nothing uses
  it - after the key ring is closed - and close the credential after that.

Use it exactly as any other key wrapper: `KeyRingBuilder().with_key_wrapper(wrapper)`, with
ephemeral keys or key files, as in [Wrap keys with AWS KMS](use-aws-kms.md#5-build-a-key-ring-with-an-ephemeral-key).

## 5. Create and use key files

The release pipeline creates key files with the wrapper itself, running as the pipeline identity
from step 2:

```python
from pathlib import Path
from hkdfguard.abstractions import WrappedKeyLimits

wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
length = wrapper.generate_and_wrap(wrapped)
Path(r"C:\HkdfGuardKeys\myapp\v1.key").write_bytes(wrapped[:length])
```

`generate_and_wrap` generates the DEK in the pipeline's process, since Key Vault has no "generate
data key". To wrap the key of an `AesGcmPipelineDataProtector`, use `wrap` as in
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file). An RSA-2048 key's key file is 359
bytes, an RSA-3072 key's 487.

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live),
and pass a `KeyFileTrust` as the wrapper's `key_file_trust` argument if the pipeline writes key
files as an account of its own. Then use the key file as in
[Use the key file](use-aws-kms.md#7-use-the-key-file).

## What stays in memory

The caller's buffer is zeroed when an unwrap fails. Beyond that, Python can zero less here than .NET
and Java can. The Azure SDK wraps with `cryptography`'s RSA, which takes only an immutable `bytes` -
given a `bytearray`, the SDK quietly sends the key to Key Vault to be wrapped there instead - so
`wrap` copies its key into one `bytes`, and `generate_and_wrap` hands over the `bytes` `os.urandom`
returns. The revealed key comes back from the SDK as a `bytes` as well. Each lives until it is
collected. [Process hardening](../../README.md#process-hardening) is what keeps such copies out of
reach of a debugger or a crash dump.

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `with_key_refresh_interval`: a verify, which the SDK
does in the process once it has the public key, and an unwrap call to Key Vault. See
[Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the trade-off, and
[Key Vault pricing](https://azure.microsoft.com/pricing/details/key-vault/) for what each operation
costs: RSA 3072 and EC keys are billed at a higher rate than RSA 2048.

## Run the integration tests

`test_azurekeyvault_integration.py` makes real calls. Its tests are reported as skipped, never
passed, until both keys are named in `azure.test.properties` (or the environment).
[Run the Azure Key Vault integration tests](run-azure-key-vault-integration-tests.md) sets up a test
vault and both keys, and runs them.

## If something goes wrong

Every failure raises a `CryptographicError`; for a Key Vault refusal the message names its error
code and HTTP status, and the Azure exception is its `__cause__`. A failed unwrap zeroes the
caller's buffer. Argument errors - a key identifier that isn't one, included - raise `ValueError`
or `TypeError`. Reading a key file fails as described for
[AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `Forbidden (HTTP 403)` or `ForbiddenByRbac` | The identity lacks the operation on that key | Step 2 |
| `KeyNotFound (HTTP 404)` | The identifier is wrong, or the key version a key file names was purged | Check the identifier; restore the version |
| `didn't report which version it used` | The identity can't `get` the key, and its identifier names no version | Step 2: grant `get`, or name a version |
| `signature doesn't verify` | The key file was altered, made under another context, or not signed by a principal allowed to sign | Restore it; use the same context |
| `not a wrapped DEK written by AzureKeyVaultKeyWrapper` | The file isn't one of this wrapper's key files | Check the path and wrapper |
| `Use a 2048- or 3072-bit RSA key` | The wrapping key is 4096 bits | Create a smaller RSA key |
| `The signing key must be an EC P-256 key` | The signing key is another curve, or RSA | Create an EC P-256 key |
| `reported key ... instead` | Key Vault answered for a different key | Check both identifiers |
| `is closed` | The wrapper was closed while something, such as a key ring, still used it | Close the wrapper after the key ring |
| `isn't a Key Vault key identifier` (`ValueError`) | An identifier isn't `https://{vault}/keys/{name}`, with an optional version | Copy the key identifier again |
| `DefaultAzureCredential failed to retrieve a token` (a `ClientAuthenticationError` cause) | No credential could get a token | Step 3 |
