# Wrap keys with AWS KMS

This page sets up an AWS KMS key as HkdfGuard's KEK and uses it from Python with
`AwsKmsKeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider KEK.

Use it when your application runs on AWS, or anywhere it can reach KMS, and you want key access
controlled by IAM and recorded in CloudTrail rather than tied to one machine's TPM.

To run the AWS KMS integration tests against a key of your own, see
[Run the AWS KMS integration tests](run-aws-kms-integration-tests.md).

## How it differs from the native wrapper

| | Native (`NativeHkdfKeyWrapperV1`) | AWS KMS (`AwsKmsKeyWrapper`) |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or Platform Crypto Provider | A symmetric AES-256 KMS key |
| Identified by | A service name | A key ARN |
| Who may wrap and unwrap | Local accounts and groups the native library allows | IAM principals the key policy and IAM policies allow |
| Each call | Local | A KMS request over the network, logged in CloudTrail |
| Key file reads | Through the native library, which refuses files another account could have replaced | The same rules, checked in Python by `hkdfguard-securefile`; who else is trusted is set with `KeyFileTrust` |
| Install | The native package | Nothing beyond the Python distributions (`botocore` comes with them) |
| Platforms | Windows, Linux, macOS | Anywhere botocore runs; key files are read on Windows, Linux and Apple silicon Macs |

Wrapped DEKs aren't interchangeable. A key file wrapped by one wrapper can't be unwrapped by the
other, so each DEK belongs to the wrapper that created it. A key file wrapped by the .NET
`AwsKmsKeyWrapper` or the Java `AwsKmsKeyWrapperImpl` under the same key and encryption context
unwraps here, and the reverse: all three send KMS the same requests.

## 1. Create the KMS key

In the AWS console, open **Key Management Service**, choose **Customer managed keys**, then
**Create key**. Choose the region your application runs in; a key is used from its own region.

| Setting | Choose | Why |
|---|---|---|
| Key type | **Symmetric** | `AwsKmsKeyWrapper` calls `Encrypt`, `Decrypt` and `GenerateDataKeyWithoutPlaintext` with `SYMMETRIC_DEFAULT`, which only a symmetric key accepts |
| Key usage | **Encrypt and decrypt** | Not HMAC, and not key agreement |
| Key material origin | KMS | The default |
| Regionality | Single-Region | Choose multi-Region only if you need to unwrap in another region |
| Alias | Optional, e.g. `alias/myapp-kek` | For finding the key; the wrapper should still be given the ARN |

**Key administrators:** choose the people or role who manage keys, not your application's or
pipeline's role. Administrators can rewrite the key policy, and so grant themselves `Decrypt`.
If your account has no suitable role yet, choose no one: the key policy's *Enable IAM User
Permissions* statement lets IAM policies grant access later.

**Clear "Allow key administrators to delete this key".** Deleting the KMS key makes every DEK
wrapped under it, and all data encrypted under those DEKs, permanently unrecoverable. To retire a
key, disable it instead; that can be undone.

**Key usage permissions:** choose no one. The console's usage statement grants more actions than
HkdfGuard uses; grant exactly what each role needs in step 2 instead.

When the key is created, copy its **ARN** from the key's page. It looks like
`arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`.

> **Security:** never remove the key policy's *Enable IAM User Permissions* statement (the one
> naming `arn:aws:iam::<account-id>:root`). Without it IAM policies stop working for the key, and
> if no other statement grants administration, only AWS Support can recover it.

## 2. Grant each role only what it calls

| Principal | Actions on the key |
|---|---|
| Release pipeline that creates key files | `kms:Encrypt`, `kms:GenerateDataKeyWithoutPlaintext` |
| Application that only reads key files | `kms:Decrypt` |
| Application that also uses ephemeral keys | `kms:Decrypt`, `kms:GenerateDataKeyWithoutPlaintext` |

Attach an IAM policy like this to each role, with the actions from the table and your key's ARN as
`Resource`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Decrypt"],
    "Resource": "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    "Condition": {
      "StringEquals": { "kms:EncryptionContext:purpose": "com.example.myapp" }
    }
  }]
}
```

The condition requires the encryption context the wrapper is given in step 4. A role limited to
`com.example.myapp` can't reveal a DEK wrapped for another application under the same key. Leave
the condition out only if you don't pass an encryption context.

> **Security:** give the application `kms:Decrypt` without `kms:Encrypt`. `AwsKmsKeyWrapper` pins
> the key on every `Decrypt`, so a key file wrapped under any *other* key is refused. But anyone who
> can call `Encrypt` on *this* key, with the same encryption context, can produce a key file your
> application accepts, holding a DEK they chose. Keep `Encrypt` with the pipeline.

## 3. Give the process credentials

`boto3.client("kms")` (or `botocore.session.get_session().create_client("kms")`) finds credentials
and a region through botocore's default chain. Where it runs decides what that should be:

| Where the process runs | Use | What the process holds |
|---|---|---|
| ECS or Fargate | A task role | Nothing; botocore fetches short-lived credentials |
| EKS | EKS Pod Identity, or IAM roles for service accounts | A token AWS rotates |
| EC2 | An instance profile (IMDSv2) | Nothing |
| Outside AWS | IAM Roles Anywhere, through `credential_process` | A certificate and private key, which can be kept in a TPM or PKCS#11 token |
| A developer machine | A profile in `~/.aws/credentials` (`%USERPROFILE%\.aws\credentials` on Windows; `aws configure`) | A long-lived access key for a low-privilege IAM user |

> **Security:** don't give a deployed process a long-lived access key, whether in environment
> variables, a mounted file or configuration. Use one of the roles above. An access key is for a
> developer machine only, belongs to an IAM user that can use nothing but this key, and is never
> committed.

The client's region must be the key's region. Set it in the profile, the environment
(`AWS_REGION` or `AWS_DEFAULT_REGION`), or the client itself (`boto3.client("kms", region_name="us-east-2")`).

## 4. Create the wrapper

Install the distribution. It brings `hkdfguard-securefile` and `botocore`; add `boto3` only if you
create clients with it:

```
pip install hkdfguard-keywrapping-awskms hkdfguard-cryptoprovider-aesgcm256 hkdfguard-dataencryptionkey boto3
```

> **TODO (maintainer):** confirm the install command once the distributions are published.

```python
import boto3
from hkdfguard.keywrapping.awskms import AwsKmsKeyWrapper

kms = boto3.client("kms")
wrapper = AwsKmsKeyWrapper(kms,
                           "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
                           {"purpose": "com.example.myapp"})
```

- **Use the key ARN, not an alias.** `Decrypt` resolves an alias when it's called, so pointing the
  alias at another key makes every DEK wrapped under the old key unreadable. KMS's automatic key
  rotation keeps the ARN, so you can turn it on without changing anything here.
- **The encryption context** is bound into every wrapped DEK and must be given again, exactly, to
  reveal it. Use the same value on every wrapper that handles one application's key files.
  CloudTrail logs it in plaintext, so it must never hold a secret.
- **The wrapper doesn't close the client.** Keep the client for as long as anything uses the
  wrapper, including a `KeyRing`'s background refresh, and close it (`kms.close()`) after the ring.
- **Retries and timeouts are the client's.** botocore retries throttling and transient errors by
  its retry mode; set `botocore.config.Config(retries=..., connect_timeout=..., read_timeout=...)`
  when you create the client if startup or a refresh must not wait long for an unreachable KMS.

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere. KMS generates it with
`GenerateDataKeyWithoutPlaintext`, so the plaintext DEK isn't returned on that call:

```python
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.dataencryptionkey import KeyRingBuilder

with (KeyRingBuilder()
        .with_service_name("com.example.myapp")
        .with_key_wrapper(wrapper)
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .with_key_refresh_interval(300)
        .with_ephemeral_key(1)
        .build()) as ring:
    protector = ring.create_protector("customer-notes")
    encrypted = protector.encrypt("The launch code is 0000")
```

Everything encrypted under an ephemeral key is lost when the process exits. Data you store needs a
key file.

## 6. Create a key file

There's no `hkdfguard wrap` for KMS: the release pipeline creates key files with the wrapper
itself, running as the pipeline role from step 2.

If the pipeline only needs a fresh key, have KMS generate it. The plaintext DEK never reaches the
pipeline:

```python
from pathlib import Path
from hkdfguard.abstractions import WrappedKeyLimits

wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
length = wrapper.generate_and_wrap(wrapped)
Path(r"C:\HkdfGuardKeys\myapp\v1.key").write_bytes(wrapped[:length])
```

If the pipeline also encrypts configuration secrets under the new key with
`AesGcmPipelineDataProtector`, wrap that protector's key instead, and zero the copy:

```python
import base64
from pathlib import Path
from hkdfguard.abstractions import ArrayUtility, WrappedKeyLimits
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider

with AesGcmPipelineDataProtector(DefaultFormatProvider(), 1) as protector:
    # ... protector.encrypt(value, "ConnectionStrings:Admin") for each configuration secret ...

    dek = bytearray(32)
    try:
        # binascii decodes into a temporary bytes, which can't be zeroed; the DEK buffer is.
        dek[:] = base64.b64decode(protector.get_key_as_base64(), validate=True)
        if len(dek) != 32:
            raise RuntimeError("The pipeline key isn't 32 bytes.")

        wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
        length = wrapper.wrap(dek, wrapped)
        Path(r"C:\HkdfGuardKeys\myapp\v1.key").write_bytes(wrapped[:length])
    finally:
        ArrayUtility.zero_memory(dek)
```

A KMS-wrapped DEK is about 184 bytes, well inside `WrappedKeyLimits.MAX_BYTES`. Unlike the native
wrapper, KMS can wrap anywhere the pipeline role has credentials; it doesn't have to run on the
host that uses the key.

### Where key files can live

Anyone who can replace a key file *and* call `Encrypt` on the key can choose your application's
DEK. Step 2 keeps `Encrypt` with the pipeline; `AwsKmsKeyWrapper` keeps the other half by refusing
to read a key file that anyone untrusted could have written or replaced. It applies the native
library's rules, through `TrustedKeyFile` in `hkdfguard-securefile`:

- **Windows:** the file is on a local fixed drive, not a UNC path or network drive, and its path
  runs through no symbolic link, junction or substituted drive. The file and every folder above it
  are owned by SYSTEM, Administrators or TrustedInstaller, and grant no one else the right to write,
  delete, rename, change permissions or take ownership. For a folder that includes creating files
  in it. The drive root is held only to renaming and deleting what's beneath it. So nothing under
  `C:\ProgramData`, your user profile or `%TEMP%` is trusted, nor a folder made directly under `C:\`
  with its default permissions.
- **Linux and macOS:** the file and every directory above it, up to `/`, are owned by root and
  writable by neither their group nor others. A symbolic link is followed only if root owns it. So
  nothing under `/tmp`, `/var/tmp` or a home directory is trusted. macOS is supported on Apple
  silicon only.
- **Everywhere:** a file that is empty, over 512 bytes, exactly 32 bytes, or a 32-byte key written
  as hex or base64 is refused. Those last ones are probably a plaintext key: treat it as exposed.

Prepare the folder once, as an administrator. On Windows, give it its own permissions, with
inheritance removed:

```powershell
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T
```

Create the folder that way, not with Python's `os.mkdir(path, 0o700)` or `tempfile.mkdtemp()`: on
Windows those give it a DACL with an entry for OWNER RIGHTS, which the checks refuse like any other
principal they don't trust.

On Linux:

```bash
sudo install -d -o root -g myapp -m 0750 /etc/hkdfguard/keys/myapp
```

Then write key files as an administrator (elevated on Windows, so Administrators owns the file; as
root on Linux and macOS), and let the application's account only read them: on Linux,
`sudo install -o root -g myapp -m 0640 v1.key /etc/hkdfguard/keys/myapp/`.

If the pipeline writes key files as an account of its own instead, trust it explicitly:

```python
from hkdfguard.keywrapping.awskms import AwsKmsKeyWrapper, KeyFileTrust

wrapper = AwsKmsKeyWrapper(kms, key_arn, encryption_context, KeyFileTrust(
    # Windows: the deployer account, which owns the files it creates, and any group granted Modify
    # on the folder. SIDs, not names: Get-LocalUser deployer | Select-Object SID
    windows_principals=["S-1-5-21-1111111111-2222222222-3333333333-1005"],
    # Linux and macOS: the deployer's uid, and a group allowed to write (id deployer).
    unix_user_ids=[1001],
    unix_group_ids=[2001],
))
```

> **Security:** never trust the account the application itself runs as, except on a developer
> machine. An application that can rewrite its own key files can be made to switch to an older,
> still-valid one. Everyone, Authenticated Users, Users, Interactive and Anonymous are refused if
> listed.

## 7. Use the key file

```python
with (KeyRingBuilder()
        .with_service_name("com.example.myapp")
        .with_key_wrapper(wrapper)
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .with_key_refresh_interval(300)
        .with_key_file(1, r"C:\HkdfGuardKeys\myapp\v1.key")
        .build()) as ring:
    ...
kms.close()
```

With `hkdfguard-options`, the configuration file describes the ring and the application supplies
the wrapper:

```python
with (options.apply_to(KeyRingBuilder())
        .with_key_wrapper(wrapper)
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .build()) as ring:
    ...
```

```toml
[hkdfguard]
service_name = "com.example.myapp"
key_refresh_interval = 300
key_files = [{ version = 1, path = 'C:\HkdfGuardKeys\myapp\v1.key' }]
```

`build()` calls KMS once per key, so the application fails to start if KMS can't be reached or
refuses the key.

## Choosing a refresh interval

Every key in the ring calls `Decrypt` once per `with_key_refresh_interval` to confirm the KEK is
still available. After three failed refreshes in a row (by default) the ring suspends encryption
and decryption until KMS answers again. So the interval trades how quickly a revoked grant stops
the process against the number of KMS requests:

| Interval | `Decrypt` calls per key, per process, per 30 days | Revocation stops the process within |
|---|---|---|
| 60 seconds | 43,200 | about 3 minutes |
| 300 seconds (the maximum) | 8,640 | about 15 minutes |

Multiply by the number of registered keys and running processes. The AWS free tier covers 20,000
KMS requests a month, and a customer managed key costs about $1 a month on top of its requests;
see [AWS KMS pricing](https://aws.amazon.com/kms/pricing/). The default of three failures also
sets how long a KMS outage is ridden out; change it with `with_max_refresh_failures`.

## If something goes wrong

Every KMS failure raises a `CryptographicError` whose message names the operation, the key, KMS's
error code and the HTTP status; botocore's exception is its `__cause__`. A failed unwrap zeroes the
caller's buffer.

| The message names | Cause | Fix |
|---|---|---|
| `AccessDeniedException` | The principal has no IAM permission for this action on this key, or the encryption context doesn't satisfy the policy condition | Step 2: check the action, the `Resource` ARN and the condition |
| `NotFoundException` | The ARN is wrong, or the client is in a different region from the key | Copy the ARN again; set the client's region to the key's |
| `IncorrectKeyException` | The key file was wrapped under a different KMS key | Use the key the file was created with |
| `InvalidCiphertextException` | The key file was altered, or the encryption context differs from the one it was wrapped with | Restore the file; use the same encryption context |
| `DisabledException` | The key is disabled | Re-enable it, or restore the key that wrapped the file |
| `KMSInvalidStateException` | The key is pending deletion | Cancel the deletion right away, within its waiting period |
| `Unable to locate credentials` | botocore found no credentials | Step 3 |
| `Could not connect to the endpoint URL` | KMS can't be reached: no network route, a proxy, or a wrong region | Check the network path to `kms.<region>.amazonaws.com` |
| `ThrottlingException` | Too many requests for the account's KMS quota | Lengthen the key refresh interval, or ask AWS for a higher quota |

`NoRegionError: You must specify a region` when the client is created means botocore found no
region: set one (step 3).

Reading a key file fails before KMS is called:

| You see | Cause | Fix |
|---|---|---|
| `PermissionError` ... `is not trusted` | The file or a folder above it is owned, or modifiable, by an account that isn't trusted; the message names it | [Where key files can live](#where-key-files-can-live): fix the folder's permissions, or trust the deployer with `KeyFileTrust` |
| `PermissionError` ... `OWNER RIGHTS` | The folder was made with `os.mkdir(path, 0o700)` or `tempfile.mkdtemp()` on Windows | Create it as in [Where key files can live](#where-key-files-can-live) |
| `PermissionError` ... `UNC or device path` or `drive` | The file isn't on a local fixed drive | Move it to a local drive |
| `PermissionError` ... `it opens` | The path runs through a link, junction or substituted drive | Configure the full, real path |
| `InvalidKeyFileError` ... `unwrapped` | The file holds what looks like a plaintext key | Treat the key as exposed: replace it, and write the file with `AwsKmsKeyWrapper` |
| `InvalidKeyFileError` ... `empty` or `larger than` | It isn't a key file | Check the path |
| `FileNotFoundError` | The file, or a folder on its path, doesn't exist | Check the path |
| `OSError` ... `open for writing` | Another process has the file open for writing | Let the deployment finish writing it |
| `ValueError` naming `KeyFileTrust` | A listed SID isn't valid, or is a group everyone is in | List the deployer's own account or group |
| `NotImplementedError` | Not Windows, Linux or an Apple silicon Mac | Read key files on a supported platform |
