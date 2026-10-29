# hkdfguard-python

HkdfGuard Key Wrapping and Secrets Protection library for Python - the Python port of
[hkdfguard-dotnet](https://github.com/runsecure/hkdfguard-dotnet), alongside
[hkdfguard-java](https://github.com/runsecure/hkdfguard-java). Values encrypted by any of the three
decrypt with the others: the wire format, AAD rules, AES-GCM layout, span/metric names and log
event ids are identical.

Requires **Python 3.12** or later. Cryptography is [`cryptography`](https://cryptography.io);
telemetry is the OpenTelemetry API; logging is the standard `logging` module; native KMS calls, and
the Windows key-file checks, use `ctypes`; AWS KMS calls go through `botocore`, Azure Key Vault calls
through `azure-keyvault-keys`, and Google Cloud KMS calls through `google-cloud-kms`.

## Packages

Each distribution installs one subpackage of the `hkdfguard` namespace package.

| Distribution                          | Import                                  | .NET assembly                        | Contents |
|---------------------------------------|-----------------------------------------|--------------------------------------|----------|
| `hkdfguard-diagnostics`               | `hkdfguard.diagnostics`                 | HkdfGuard.Diagnostics                | `HkdfGuardTelemetry`, `CacheMetrics`, span/attribute/event/metric names, `HkdfGuardLog` |
| `hkdfguard-abstractions`              | `hkdfguard.abstractions`                | HkdfGuard.Abstractions               | `CryptoProvider`, `KeyWrapper`, `KeyRing`, `DataProtector`, ... ; `ProtectedCacheBase`, `ServiceNames`, `ProtectedConfigurationPurpose`, the exception types |
| `hkdfguard-cryptoprovider-aesgcm256`  | `hkdfguard.cryptoprovider.aesgcm256`    | HkdfGuard.CryptoProvider.AesGcm256   | `AesGcmCryptoProvider`, `AesGcmCryptoProviderFactory`, `AesGcmPipelineDataProtector` |
| `hkdfguard-keywrapping-v1`            | `hkdfguard.keywrapping.v1`              | HkdfGuard.KeyWrapping.V1             | `NativeHkdfKeyWrapperV1` over the native KMS library |
| `hkdfguard-securefile`                | `hkdfguard.securefile`                  | HkdfGuard.SecureFile                 | `TrustedKeyFile`, `KeyFileTrust`: the native library's key-file location and content checks, in Python |
| `hkdfguard-keywrapping-awskms`        | `hkdfguard.keywrapping.awskms`          | HkdfGuard.KeyWrapping.AwsKms         | `AwsKmsKeyWrapper` over one symmetric AWS KMS key, through a botocore client |
| `hkdfguard-keywrapping-azurekeyvault` | `hkdfguard.keywrapping.azurekeyvault`   | HkdfGuard.KeyWrapping.AzureKeyVault  | `AzureKeyVaultKeyWrapper` over an RSA wrapping key and an EC P-256 signing key in Azure Key Vault |
| `hkdfguard-keywrapping-googlekms`     | `hkdfguard.keywrapping.googlekms`       | HkdfGuard.KeyWrapping.GoogleKms      | `GoogleKmsKeyWrapper` over one symmetric Google Cloud KMS key, through a Cloud KMS client |
| `hkdfguard-dataencryptionkey`         | `hkdfguard.dataencryptionkey`           | HkdfGuard.DataEncryptionKey          | `KeyRing`, `KeyRingBuilder`, `DataEncryptionKey`, `DefaultFormatProvider` |
| `hkdfguard-cache`                     | `hkdfguard.cache`                       | HkdfGuard.Cache                      | `ProtectedCache`, `ProtectedCacheCollection`; `RemoteSecretCache`, `SecretValueSink`, `SecretJsonBody` for caches over a secret store |
| `hkdfguard-cache-awssecretsmanager`   | `hkdfguard.cache.awssecretsmanager`     | HkdfGuard.Cache.AwsSecretsManager    | `AwsSecretsManagerSecretCache` over AWS Secrets Manager, through a botocore client |
| `hkdfguard-cache-azurekeyvault`       | `hkdfguard.cache.azurekeyvault`         | HkdfGuard.Cache.AzureKeyVault        | `AzureKeyVaultSecretCache` over Azure Key Vault secrets |
| `hkdfguard-cache-googlesecretmanager` | `hkdfguard.cache.googlesecretmanager`   | HkdfGuard.Cache.GoogleSecretManager  | `GoogleSecretManagerSecretCache` over Google Cloud Secret Manager, through a gRPC Secret Manager client |
| `hkdfguard-cache-hashicorpvault`      | `hkdfguard.cache.hashicorpvault`        | HkdfGuard.Cache.HashiCorpVault       | `HashiCorpVaultSecretCache` over HashiCorp Vault's KV secrets engine, through the standard library's HTTP client |
| `hkdfguard-options`                   | `hkdfguard.options`                     | HkdfGuard.Options                    | `HkdfGuardOptions`, `KeyFileOptions`, `OptionsValidationError` |

Naming: abstract base classes drop the .NET `I` prefix (`ICryptoProvider` -> `CryptoProvider`), and
concrete classes keep their descriptive .NET names (`AesGcmCryptoProvider`). Where an implementation
shares its ABC's name (`KeyRing`, `DataEncryptionKey`, `ProtectedCache`), the package tells them
apart: `hkdfguard.abstractions.KeyRing` is the ABC, `hkdfguard.dataencryptionkey.KeyRing` the
implementation. Methods and properties are snake_case.

## Example

```python
from hkdfguard.abstractions import ProtectedConfigurationPurpose
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory
from hkdfguard.dataencryptionkey import KeyRingBuilder
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1

with (KeyRingBuilder()
        .with_service_name("com.example.orders")
        .with_key_wrapper(NativeHkdfKeyWrapperV1("com.example.orders"))
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .with_key_refresh_interval(60)
        .with_key_file(3, "/etc/myapp/wrapped-dek-v3.bin")
        .with_ephemeral_key(100)
        .build()) as ring:
    protector = ring.create_protector(ProtectedConfigurationPurpose.for_key("ConnectionStrings:Admin"))
    result = bytearray(protector.get_max_decrypted_length(encrypted))
    length = protector.decrypt(encrypted, result)
    ...  # use result[:length], then zero it
```

## Encryption budget

With random 96-bit nonces, AES-GCM is safe for about 2^32 encryptions under one key (NIST
SP 800-38D). Each crypto provider counts the encryptions under its key, warns at 2^28, and
refuses to encrypt past 2^31 (`AesGcmCryptoProvider.MAX_ENCRYPTIONS_PER_KEY`). Decryption is never limited.

That count is kept per process, by design. It is exact for the key an application should encrypt
with at runtime: an ephemeral key, generated at startup and held only in that process's memory, so
no other process or restart ever adds to its use. Key files are different. They carry what the
deployment pipeline encrypted and are meant to be decrypted at runtime; every process that loads a
key file, and every restart, starts a fresh count for it.

**For encrypt operations, add an ephemeral key** at a version above every key file
(`KeyRingBuilder.with_ephemeral_key(2)` beside `with_key_file(1, ...)`). New values are then encrypted under it, while the pipeline's values still decrypt
under their key files. A value encrypted under an ephemeral key can't be decrypted once the process
exits, which suits caches and other in-process data; never persist it.

If an application does encrypt values that must outlive the process under a key file, its
encryptions under that file are not counted together across instances and restarts. Bound them by
deploying a new key file at a higher version regularly.

## Configuration

`hkdfguard-options` lets a configuration file describe the ring. `HkdfGuardOptions.from_mapping`
reads a parsed section (JSON, TOML, YAML), matching keys ignoring case and underscores, so a .NET
`appsettings.json` `HkdfGuard` section reads unchanged. `require_valid()` reports every problem at
once, and `apply_to` copies the settings onto a builder:

```python
import tomllib
from hkdfguard.options import HkdfGuardOptions

with open("/etc/myapp/config.toml", "rb") as file:
    options = HkdfGuardOptions.from_mapping(tomllib.load(file)["hkdfguard"]).require_valid()

with (options.apply_to(KeyRingBuilder())
        .with_key_wrapper(NativeHkdfKeyWrapperV1(options.service_name))
        .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
        .build()) as ring:
    ...
```

```toml
[hkdfguard]
service_name = "com.example.orders"
key_refresh_interval = 60
key_files = [{ version = 3, path = "/etc/myapp/wrapped-dek-v3.bin" }]
ephemeral_keys = [100]
```

Unlike .NET's binder, an unknown key is an error rather than ignored, so a misspelt setting can't
silently fall back to a default.

## Differences from .NET, by design

- **Synchronous API, except cache reads.** Every .NET `...Async` method is a blocking call
  (`build()`, `create(...)`, `wrap(...)`); there is no `CancellationToken`. Background key refresh
  and ephemeral key rotation run on daemon threads. The one exception is the read surface of a
  cache: `ProtectedReadOnlyCache` has `decrypt_async` and `find_max_decrypted_length_async`
  coroutines (asyncio), which a cache over a secret store uses so a miss doesn't block the event
  loop. Cancelling the awaiting task takes the place of the `CancellationToken`.
- **Disposal** is `close()`, and every disposable type is a context manager. `KeyRing.close()`
  never waits for a rotation blocked in the KMS: a key that rotation creates after the ring closed
  is closed instead of added.
- **Buffers.** Secrets travel in writable buffers (`bytearray` or `memoryview`) so they can be
  zeroed; immutable `bytes` are refused wherever a plaintext would need zeroing. AES-GCM reads
  and writes the caller's buffers directly (`encrypt_into`/`decrypt_into`) rather than through
  immutable copies. The plaintext and result buffers of an encrypt must not overlap: it is refused
  with `ValueError`, since encrypting in place would destroy the plaintext. Decrypt writes UTF-8 bytes into the caller's buffer and returns the count; as in
  every other port, nothing decrypts to an immutable `str`, so decode only what you must. AAD is the keyword-only argument `aad=`. A `str`
  plaintext is encoded into a `bytearray` that is zeroed, but the `str` itself and the temporary
  `bytes` CPython builds while encoding it can't be: hold a secret in a buffer from the start if
  it must not linger.
- **`TryGet...(out ...)`** becomes `find...` returning a value or `None`.
- **Exceptions:**
  - `ArgumentException` -> `ValueError`, and `ArgumentNullException` -> `TypeError`.
  - `ObjectDisposedException` -> `ObjectClosedError` (a `RuntimeError`), and
    `InvalidOperationException` -> `RuntimeError`.
  - `KeyNotFoundException` -> `KeyNotFoundError` (a `LookupError`).
  - `FormatException` -> `EncryptedFormatError` (a `ValueError`).
  - A refused native library is a `PermissionError`, and a missing one is a
    `NativeLibraryNotFoundError` (an `OSError`).
  - Reading a key file (`KeyWrapper.read_key_file`, .NET's `ReadKeyFileAsync`):
    `FileNotFoundException` -> `FileNotFoundError`, `UnauthorizedAccessException` ->
    `PermissionError`, `InvalidDataException` -> `InvalidKeyFileError` (an `OSError`, so code that
    catches `OSError` for every way a key file can fail still catches it), `IOException` ->
    `OSError`. The native library's refusals map by status: -32 `FileNotFoundError`; -33 and -39
    `PermissionError`; -35, -36, -37 and -38 `InvalidKeyFileError`; -1 `ValueError`; -34 and any
    other status `OSError`. An empty path is a `ValueError` (and `None` a `TypeError`) before
    anything is read. `TrustedKeyFile` (`hkdfguard-securefile`) raises the same types for the same
    refusals, and a `KeyFileTrust` naming a principal that can't be trusted is a `ValueError`
    (.NET's `ArgumentException`).
  - `PlatformNotSupportedException` -> `NotImplementedError`, as `NativeHkdfKeyWrapperV1` reports a
    platform with no native library.
  - `CryptographicException` and `AuthenticationTagMismatchException` become `CryptographicError`
    and `AuthenticationTagMismatchError`.
- **Memory hygiene:** CPython has no pinned or stack allocation, so zeroing erases the live copy of
  a secret but not copies the allocator may have left; `str` values can never be zeroed, and
  encoding a `str` always passes through a temporary immutable `bytes`. `cryptography`'s `AESGCM`
  also keeps its own copy of the key for as long as the cipher object exists - for a session, until
  its next refresh retires it - and zeroing this library's key buffer doesn't reach that copy; the
  session releases the cipher when it closes, and whether the copy is wiped then is up to
  `cryptography`. The same goes for the encryption budget: each new session (every reveal or
  refresh, unless a budget is passed in) looks up its key's shared budget by an HMAC-SHA256 of the
  DEK under a per-process random key (`EncryptionBudget.for_key`), which feeds the DEK into
  `cryptography`'s HMAC context. This library can't zero that context's copy of it either; whether
  it is wiped when the context is finalized and freed is up to `cryptography` and OpenSSL. Likewise
  `AwsKmsKeyWrapper`: botocore returns Decrypt's plaintext as an immutable `bytes`, which is copied
  into the caller's buffer but can't be zeroed (see *Wrapping under AWS KMS instead*), and
  `AzureKeyVaultKeyWrapper` hands the Azure SDK, and gets back from it, keys as immutable `bytes`
  (see *Wrapping under Azure Key Vault instead*), as `GoogleKmsKeyWrapper` does with the Cloud KMS
  client (see *Wrapping under Google Cloud KMS instead*). Process
  hardening, which blocks core dumps and debugger attachment, is what keeps such copies out of
  reach.
- **Logging:** a `None` logger means the package's own logger (e.g. `hkdfguard.cache`). The event id
  travels as the `hkdfguard_event_id` record attribute, a plain `int`; compare it with the members of
  `hkdfguard.diagnostics.HkdfGuardEventId` (for example `HkdfGuardEventId.KEY_REFRESH_FAILED`) to
  filter on one entry. .NET's Critical is `logging.CRITICAL`.
- **Telemetry** goes to OpenTelemetry's global providers, or to those given to
  `HkdfGuardTelemetry.set_tracer_provider` / `set_meter_provider`.

## Native access

`hkdfguard-keywrapping-v1` calls the native KMS library through `ctypes`. The library is installed
separately and loaded only from its verified location, exactly as in .NET and Java: path ACLs,
Authenticode signer, root and EKU, and PE checks on Windows, then that the module Windows mapped is
the verified file; ownership, code signature and dyld
checks on macOS; root ownership, dynamic-linker environment and dependency checks on Linux, where
the library is not content-pinned and a release's authenticity is verified with Sigstore/cosign when
the package is installed.

| Platform | Library                                                                 | Command-line tool                              |
|----------|-------------------------------------------------------------------------|------------------------------------------------|
| Windows  | `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll`                             | `%ProgramFiles%\HkdfGuard\v1\hkdfguard.exe`    |
| Linux    | `/usr/lib/<multiarch>/libhkdfguard.so.1`, or `/usr/lib64/libhkdfguard.so.1`, from the `libhkdfguard1` package (`hkdfguard-libs` on RPM distributions); x64 and arm64 | `/usr/bin/hkdfguard` |
| macOS    | `/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib`, or `~/.hkdfguard/v1/libhkdfguard.dylib` | `hkdfguard` |

On **macOS** the per-user location is used only when there is no system install. Its home folder
comes from the account database (`pwd.getpwuid`), never `$HOME`, so setting the environment can't
move it. Either install must be version 0.9.0 or later - the library's `LC_ID_DYLIB` current
version, which its signature covers - so an older signed release can't be planted in its place.
On **Windows** the same 0.9.0 floor applies to `HkdfGuard.dll`'s signed version resource, and a DLL
with none is refused.

Certificate revocation: on Windows, once the signature and its pins have passed, the loader asks
WinVerifyTrust once more, now checking revocation across the signing chain and allowed to fetch
revocation data over the network. It refuses the library only when a certificate is definitely
revoked; if revocation can't be determined (offline, no data), it loads. A host whose network
silently drops traffic, rather than refusing it, may stall once, on the first load, until that
lookup times out. On macOS revocation isn't checked: the defences are the Developer ID and Team ID
pins, the admin-only system install, and the minimum library version. A compromised signing
identity is answered by a new release and a raised minimum version.

On **Linux**, `LinuxNativeLibraryLoader` uses the package's file in the Debian multiarch directory
(`/usr/lib/x86_64-linux-gnu` or `/usr/lib/aarch64-linux-gnu`, by the interpreter's architecture) if
it is there, otherwise the one in `/usr/lib64`. Only "nothing is there" moves on; a location that
can't be examined is refused. It is loaded with `ctypes.CDLL` of that absolute path, never of a bare
name. Before loading, it requires all of the following:
- Every directory on the path, every symbolic link followed, and the file itself are owned by root,
  and no directory or file is writable by its group or by others. Links are followed one component
  at a time and each target is checked where it lies, so `/lib -> usr/lib` passes and a link into a
  user's directory does not.
- The dynamic linker's environment is checked. `dlopen` of an absolute path is
  never searched for, but the library's dependencies are found by name - and `libtss2-esys`
  receives every ECDH shared secret. So every `LD_LIBRARY_PATH` directory, and every path-named
  `LD_PRELOAD` or `LD_AUDIT` object, must pass the same path checks, and none may be relative,
  empty (the working directory) or use `$ORIGIN`-style tokens. Both the environment the process
  started with (`/proc/self/environ`) and the current one (`os.environ`) are checked.
  This check catches a misconfigured environment. It can't stop someone who controls the
  service's environment: whatever `LD_PRELOAD` or `LD_AUDIT` loads runs when the process starts,
  before the check, and can hide from it. Protect the service's environment (its unit file,
  container spec or launch configuration) as carefully as its binaries.

On macOS the loader also refuses while `DYLD_INSERT_LIBRARIES`, `DYLD_FRAMEWORK_PATH`,
`DYLD_VERSIONED_LIBRARY_PATH`, `DYLD_VERSIONED_FRAMEWORK_PATH` or `DYLD_IMAGE_SUFFIX` is set: each
makes dyld inject code or substitute a library the native library calls with every DEK. The same
limit applies - dyld acts on them at process start - and the real protection is a host signed with
the Hardened Runtime, which makes dyld ignore them.

On Linux, before loading, the process's own dynamic linker is asked in list mode (`ld.so --list`,
what `ldd` uses) where it would find every library `libhkdfguard.so.1` pulls in, under the
`LD_LIBRARY_PATH` and `LD_PRELOAD` the process started with; each must pass the same path checks,
so a dependency found somewhere writable is refused before any of its code runs. (This is the
package's only child process: the verified linker, run without a shell, in an environment holding
just those two variables.) After loading, `dladdr` must place the library's export in the verified
file, and every object in its dependency closure, read from each file's `DT_NEEDED` entries, must
be bound to a file that passes the path checks. That catches a dependency the process had already
loaded from somewhere else under the same name; the library is then unloaded and the load refused. Any failed check
raises `PermissionError`; a library that isn't installed raises `NativeLibraryNotFoundError`, and an
interpreter that is neither x64 nor arm64 an `OSError` with errno `ENOTSUP`. There is no fallback
and no override. Two things are outside the loader's reach: the TPM transport module tpm2-tss loads
at the first TPM call, which only the environment check covers, and Python's own injection points
(`PYTHONPATH`, `sitecustomize`, `.pth` files), which need a protected service environment on every
platform.

**Status codes** are shared, number for number, by the Windows, Linux and macOS libraries (the
`HKDFGUARD_ERR_*` table in each platform's `hkdfguard.h`), so they are defined once, on
`AbstractHkdfGuardKmsLibrary`, with one shared description each; a platform adds only what to do
about a code there (the `HkdfGuardUsers` group and HKLM policy on Windows,
`/etc/hkdfguard/policy.toml` on Linux, the keychain and Secure Enclave on macOS). A failed call
names the status and its meaning, e.g. `status -17 (no KEK is provisioned for this service; run
hkdfguard provision)`.

| Codes      | Meaning                                                                                       |
|------------|-----------------------------------------------------------------------------------------------|
| 0          | OK                                                                                            |
| -1 .. -6   | invalid argument, buffer too small, provider unavailable, provider error, crypto error, internal error |
| -8, -9     | invalid service name, invalid machine policy                                                  |
| -10 .. -12 | wrapped payload malformed, failed authentication, unsupported version                         |
| -16 .. -20 | KEK fingerprint mismatch, KEK not found, KEK access denied, KEK invalid, process hardening failed |
| -32 .. -39 | key file not found, access denied, I/O, too short, too long, plaintext key, malformed, untrusted |
| -64        | Windows: an invalid `KeyUseGroups` policy entry                                               |
| -96 .. -100 | macOS: access control creation, key generation, keychain write, KEK verification, keychain read failed |

Every other code (-7, -13 .. -15, -21 .. -31, -40 .. -63, ...) is reserved.

**Key files are read through the key wrapper.** `KeyRingBuilder.build` reads every key file with
`KeyWrapper.read_key_file`. `NativeHkdfKeyWrapperV1` reads it through the native library's
`hkdfguard_open_file`, which returns the file's bytes still wrapped - it never unwraps or touches a
KEK - after checks only the platform can make. It refuses a missing (-32) or unreadable (-33) file,
anything but a regular file (-34), a file of the wrong size (-35, -36), one holding what looks like
an unwrapped DEK - 32 raw bytes, or 64 hex digits or base64, with optional whitespace (-37, treat it
as a key exposure) - a right-size file that isn't a valid wrapped payload (-38), and an untrusted
path (-39): a symbolic link, junction or other reparse point, an 8.3 short name, a UNC, mapped or
SUBST path, or a file or folder another account could write or replace. These checks can't be
turned off. `read_key_file` has no default implementation: a custom key wrapper must read key
files itself, and must refuse a file another account could have written or replaced, since whoever
can replace a key file chooses the key new data is encrypted under. A key wrapper with no native
library to read through can use `TrustedKeyFile.read` from `hkdfguard-securefile`, which makes the
same location and content checks in Python, as `AwsKmsKeyWrapper`, `AzureKeyVaultKeyWrapper` and
`GoogleKmsKeyWrapper` do.

### Process hardening

DEKs pass through your process's memory, so a crash dump, or another process of the same user
attaching a debugger or reading that memory, could recover them. `NativeProcessHardening.apply()`
calls the native library's `hkdfguard_harden_process_with_flags` to close that off, on every
platform:

| Platform | What it does |
|---|---|
| Windows | Crash reports leave out the heap, and the process's and its threads' access lists are replaced so only SYSTEM can read or write its memory, inject threads or duplicate its handles. Its own account keeps only query, synchronize and terminate. |
| Linux | Core dumps off (hard limit included), and the process marked non-dumpable, which also stops ptrace and `/proc/<pid>/mem` access by the same user. |
| macOS | Core dumps off and debugger attachment denied. Whether code can be injected depends on the host executable's code signature, which the library checks but can't change. |

Neither the native library nor any machine policy does this for you: it changes process-wide
state your application owns, so it is opt-in. Call it once, early in startup - before starting
worker threads on Windows, and after any privilege drop on Linux:

```python
from hkdfguard.keywrapping.v1 import NativeProcessHardening

NativeProcessHardening.apply()   # raises RuntimeError if it fails: don't start
```

Debuggers, `py-spy` and crash dumps stop working for the process. It is a same-user barrier: it
does not stop administrators, root, SYSTEM, `SeDebugPrivilege`, `CAP_SYS_PTRACE` or the kernel, and
it does not keep memory out of swap, the page file or hibernation files. An option the library
doesn't define raises `ValueError` before the native call.

`NativeProcessHardening.apply(ProcessHardeningOptions.REQUIRE_PROTECTED_SIGNATURE)` is the strict
form the native command-line tools use: it fails unless no other process of the same user can
debug or inject into this one.

- **Windows:** it also closes threads started later, and everything else the process creates
  afterwards without its own security descriptor (child processes, named pipes, named events), to
  its own account. Use it in a service that shares no objects with other processes by name.
- **macOS:** it fails unless the host executable is signed with the Hardened Runtime and without
  the `get-task-allow` or `DYLD_*` entitlements, so unsigned hosts - a python.org, Homebrew or
  virtual-environment `python` - can't use it. Without it, a weak signature is only logged.
- **Linux:** it adds nothing; the plain call already guarantees it.

**Python on Windows:** the plain call closes the threads that exist when it runs, and threads
started later keep the default access, which lets other processes of the same user read and change
their registers. CPython starts no threads of its own, so calling it first thing covers the
process, until something starts one: `threading`, `concurrent.futures`, asyncio's default executor
(`run_in_executor`, `asyncio.to_thread`), or a library's background thread (a metrics exporter, a
gRPC or database driver). A long-running program almost always does, so **use
`REQUIRE_PROTECTED_SIGNATURE` for a Windows service**: it closes later threads too.

## Wrapping under AWS KMS instead

`AwsKmsKeyWrapper` (distribution `hkdfguard-keywrapping-awskms`) is a `KeyWrapper` over one
symmetric AWS KMS key. Use it in place of `NativeHkdfKeyWrapperV1` wherever a wrapper is taken.
Every call is a KMS request, authorized by the process's IAM credentials and recorded in CloudTrail:

```python
import boto3
from hkdfguard.keywrapping.awskms import AwsKmsKeyWrapper

# The application creates the client, keeps it while anything uses the wrapper, and closes it.
kms = boto3.client("kms")                                # default credential and region chain
wrapper = AwsKmsKeyWrapper(kms,
                           "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
                           {"purpose": "my.service"})
```

- `generate_and_wrap` calls `GenerateDataKeyWithoutPlaintext` for an AES-256 key, so the plaintext
  DEK never leaves KMS on that call. `wrap` calls `Encrypt` and `unwrap` calls `Decrypt`.
- The key is pinned on every `Decrypt`. A symmetric ciphertext names its own key, and without the pin
  a substituted key file wrapped under any other key the principal may use would still be revealed.
  Prefer a key ARN to an alias: `Decrypt` resolves an alias when it is called, so re-pointing the
  alias makes DEKs wrapped under the old key unreadable. KMS's automatic key rotation keeps the
  ARN and needs nothing here.
- The optional encryption context is KMS's AAD. It is bound into every wrapped DEK, required again
  to reveal it, and can be required by the key policy (`kms:EncryptionContext:purpose`). CloudTrail
  logs it in plaintext, so it must never hold a secret.
- Calls block until KMS answers (botocore is synchronous; there is nothing to cancel). Failures raise
  `CryptographicError` naming the operation, the key, KMS's error code (for example
  `AccessDeniedException` or `InvalidCiphertextException`) and the HTTP status, with botocore's
  `ClientError` as its `__cause__`; a client-side failure (`BotoCoreError`: no credentials, an
  unreachable endpoint) raises `CryptographicError` with botocore's message. Argument errors raise
  `ValueError` or `TypeError`. A failed unwrap zeroes the caller's buffer.
- Key files are read only from where no untrusted account could have written or replaced them, by
  the native library's rules, checked in Python by `hkdfguard-securefile`: on Windows, a local fixed
  drive, reached through no link, junction or substituted drive, with the file and every folder
  above it owned and modifiable only by SYSTEM, Administrators or TrustedInstaller; on Linux and
  macOS (Apple silicon), the file and every directory above it owned by root and writable by no one
  else, following only root-owned links. A `KeyFileTrust` passed to the constructor adds the
  deployment's own account or group. A file that looks like an unwrapped key is refused too. A KMS
  ciphertext is about 184 bytes, well inside `WrappedKeyLimits.MAX_BYTES`.
- Plaintext the wrapper owns is zeroed: its `bytearray` copy of the key sent to `Encrypt` (passed to
  botocore as is, never turned into `bytes`), once the call has returned, and the caller's buffer
  when an unwrap fails. botocore base64-encodes that key into the JSON request body, and returns
  `Decrypt`'s plaintext as an immutable `bytes` decoded from the response's base64; neither is
  exposed to be zeroed, and both live until collected.
- The principal needs `kms:Encrypt`, `kms:Decrypt` and `kms:GenerateDataKeyWithoutPlaintext` on the key.
  A process that only reads existing key files needs only `kms:Decrypt`.

**Dependencies.** The distribution depends on `botocore` (with its own `jmespath`,
`python-dateutil` and `urllib3`), not on `boto3`: the wrapper makes three calls on a client, and the
client is a botocore client whether the application creates it with `boto3.client("kms")` or
`botocore.session.get_session().create_client("kms")`, so `boto3`'s resource layer and `s3transfer`
would be dead weight for an application that doesn't already use them. The client is typed with
`KmsClient`, a `Protocol` of those three calls, rather than with a stub package: botocore ships no
type information, and a typed `mypy_boto3_kms.KMSClient` satisfies `KmsClient` too. There is no
configuration integration for it (as in .NET, whose dependency-injection package doesn't wire AWS
either): create the wrapper and pass it to `KeyRingBuilder.with_key_wrapper`.

[Wrap keys with AWS KMS](docs/how-to/use-aws-kms.md) walks through creating the key, the IAM
permissions for each role, credentials, and creating key files.
[Run the AWS KMS integration tests](docs/how-to/run-aws-kms-integration-tests.md) sets up a key of
your own for `test_awskms_integration.py`, which is otherwise reported as skipped.

## Wrapping under Azure Key Vault instead

`AzureKeyVaultKeyWrapper` (distribution `hkdfguard-keywrapping-azurekeyvault`) is a `KeyWrapper`
over two Azure Key Vault keys: an RSA key (2048 or 3072 bits) that wraps each DEK with RSA-OAEP-256,
and a separate EC P-256 key that signs each wrapped DEK with ES256. Use it in place of
`NativeHkdfKeyWrapperV1` wherever a wrapper is taken:

```python
from azure.identity import DefaultAzureCredential
from hkdfguard.keywrapping.azurekeyvault import AzureKeyVaultKeyWrapper

wrapper = AzureKeyVaultKeyWrapper("https://myvault.vault.azure.net/keys/myapp-wrap",
                                  "https://myvault.vault.azure.net/keys/myapp-sign",
                                  DefaultAzureCredential(),            # a managed identity, deployed
                                  "com.example.myapp")                 # the context
```

- **Why two keys.** RSA-OAEP wrapping needs only the public key, so on its own anyone could make a
  wrapped DEK holding a key they chose. Signing needs the signing key's private half, which never
  leaves Key Vault, and `unwrap` verifies the signature before it unwraps anything. Give `sign` to
  the pipeline that creates key files, never to the application. The wrapper refuses the same key
  for both jobs.
- **Both keys are pinned.** A wrapped DEK records only the two key versions it was made with; the
  vault and key names always come from the constructor. Rotating either key needs nothing here, as
  long as the versions existing key files name stay enabled. Give identifiers without a version so
  new key files use the current ones.
- **The context** is bound into every signature and must be given again, exactly, to reveal a DEK;
  `None` and `""` are the same. It isn't secret.
- **Key files are interchangeable between ports**, byte for byte: one made by the .NET
  `AzureKeyVaultKeyWrapper` or the Java `AzureKeyVaultKeyWrapperImpl` is read by this wrapper, and
  the other way round, given the same keys and context. They aren't interchangeable with other kinds
  of wrapper. An RSA-2048 key's wrapped DEK is 359 bytes and an RSA-3072 key's 487, inside
  `WrappedKeyLimits.MAX_BYTES`; a 4096-bit key's wouldn't fit, and wrapping under one is refused.
- **What is local.** The Azure SDK's `CryptographyClient` reads each key's public half once (the
  identity needs `get` on both keys), then wraps and verifies in this process; signing and
  unwrapping are always Key Vault calls. Without `get`, every operation is a call, and a key
  identifier must then name its version: the SDK can't report which version it used otherwise, and
  a wrapped DEK must record it.
- `generate_and_wrap` generates the DEK in this process, since Key Vault has no "generate data key".
- **Memory.** The caller's buffer is zeroed when an unwrap fails. The SDK wraps with
  `cryptography`'s RSA, which takes only an immutable `bytes` (given a `bytearray`, the SDK sends the
  key to Key Vault instead), so `wrap` copies the key into one `bytes`, which lives until collected;
  `generate_and_wrap` hands over `os.urandom`'s. The revealed key comes back from the SDK as a
  `bytes` too, copied into the caller's buffer but never zeroed. This is less than the .NET and Java
  wrappers can zero; process hardening is what keeps these copies out of reach.
- Calls block until Key Vault answers. Failures raise `CryptographicError` naming the operation,
  the key, Key Vault's error code (for example `Forbidden` or `KeyNotFound`) and the HTTP status,
  with the SDK's `HttpResponseError` as its `__cause__`; a client-side failure (a credential that
  can't get a token, an unreachable vault) raises `CryptographicError` with its message. Argument
  errors raise `ValueError` or `TypeError`.
- **Clients.** The wrapper creates one `CryptographyClient` per key version it uses and keeps it, so
  a key ring's refresh doesn't fetch the public keys again. `close()` closes them; the wrapper is a
  context manager. The keyword-only `client_options` are passed to each client (`api_version`,
  `transport`, retry and logging options).
- Key files are read through `hkdfguard-securefile` by the same rules as `AwsKmsKeyWrapper`'s, with
  a `KeyFileTrust` for the deployment's own account or group.

**Dependencies.** The distribution depends on `azure-keyvault-keys` (with `azure-core`, `isodate`
and `cryptography`). The credential is the application's: `azure-identity` provides
`DefaultAzureCredential` and `ManagedIdentityCredential`, and is not a dependency, since any
`TokenCredential` will do.

[Wrap keys with Azure Key Vault](docs/how-to/use-azure-key-vault.md) walks through creating the two
keys, the permissions for each identity, credentials, and creating key files.
[Run the Azure Key Vault integration tests](docs/how-to/run-azure-key-vault-integration-tests.md)
sets up a test vault for `test_azurekeyvault_integration.py`, which is otherwise reported as skipped.

## Wrapping under Google Cloud KMS instead

`GoogleKmsKeyWrapper` (distribution `hkdfguard-keywrapping-googlekms`) is a `KeyWrapper` over one
symmetric Google Cloud KMS key (purpose `ENCRYPT_DECRYPT`). Use it in place of
`NativeHkdfKeyWrapperV1` wherever a wrapper is taken. Every call is a Cloud KMS request, authorized by
the process's Google credential through IAM and recorded in Cloud Audit Logs:

```python
from google.cloud import kms
from hkdfguard.keywrapping.googlekms import GoogleKmsKeyWrapper

# The application creates the client, keeps it while anything uses the wrapper, and closes it.
client = kms.KeyManagementServiceClient()                # Application Default Credentials
wrapper = GoogleKmsKeyWrapper(client,
                              "projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
                              "com.example.myapp")       # the context
```

- `wrap` calls `Encrypt` and `unwrap` calls `Decrypt`. Cloud KMS has no "generate data key", so
  `generate_and_wrap` generates the DEK in this process and wraps it.
- **The key is pinned.** `Decrypt` is always called against the key given at construction, and Cloud
  KMS refuses a ciphertext made under any other key. The key name must be a key's, not a key
  version's. A ciphertext records the version that made it, so rotating the key needs nothing here,
  as long as the versions existing key files were made with stay enabled.
- **The context** is bound into every wrapped DEK as additional authenticated data, after a fixed
  HkdfGuard label, and must be given again, exactly, to reveal it; `None` and `""` are the same. The
  label stops a ciphertext the key made for another purpose being taken for a DEK. Neither is secret.
- **Checksums.** Every request and response carries a CRC32C checksum, as Google recommends, so data
  corrupted in transit is refused rather than stored or used. A response naming a version of any
  other key is refused too.
- **Key files are interchangeable between ports**, byte for byte: one made by the .NET
  `GoogleKmsKeyWrapper` or the Java `GoogleKmsKeyWrapperImpl` is read by this wrapper, and the other
  way round, given the same key and context. A wrapped DEK is about 113 bytes, inside
  `WrappedKeyLimits.MAX_BYTES`.
- **Anyone allowed to encrypt can make a key file.** Symmetric encryption needs no secret beyond
  permission to use the key, so give the application decrypt only
  (`roles/cloudkms.cryptoKeyDecrypter`) and the pipeline that creates key files encrypt only
  (`roles/cloudkms.cryptoKeyEncrypter`). Key files are read through `hkdfguard-securefile` by the
  same rules as `AwsKmsKeyWrapper`'s, with a `KeyFileTrust` for the deployment's own account or group.
- **Memory.** The caller's buffer is zeroed when an unwrap fails. The client's request messages take
  only an immutable `bytes`, so `wrap` copies the key into one `bytes`, which lives until collected;
  `generate_and_wrap` hands over `os.urandom`'s. The revealed key comes back from the client as a
  `bytes` too, copied into the caller's buffer but never zeroed. This is less than the .NET and Java
  wrappers can zero; process hardening is what keeps these copies out of reach. The gRPC client
  starts threads of its own, so on Windows use `REQUIRE_PROTECTED_SIGNATURE` (see *Process
  hardening*).
- Calls block until Cloud KMS answers, the client's own retries included (by default it retries
  `UNAVAILABLE` and `DEADLINE_EXCEEDED` for up to 60 seconds; a retry resends the same bytes).
  Failures raise `CryptographicError` naming the operation, the key and the gRPC status, for example
  `INVALID_ARGUMENT: Decryption failed.` for a key file that was tampered with or made under another
  key or context, with the client's `GoogleAPICallError` as its `__cause__`. Over the REST transport
  the HTTP status is named instead. A client-side failure (no credentials, retries that ran out of
  time) raises `CryptographicError` with its message. Argument errors raise `ValueError` or
  `TypeError`.

**Dependencies.** The distribution depends on `google-cloud-kms` (with `google-api-core`,
`google-auth`, `grpcio`, `proto-plus` and `protobuf`). The client is typed with `CloudKmsClient`, a
`Protocol` of the two calls the wrapper makes, which `KeyManagementServiceClient` satisfies over
gRPC or REST (`KeyManagementServiceClient(transport="rest")`). CRC32C is computed in Python, so
`google-crc32c` isn't needed. There is no configuration integration for it: create the wrapper and
pass it to `KeyRingBuilder.with_key_wrapper`.

[Wrap keys with Google Cloud KMS](docs/how-to/use-google-kms.md) walks through creating the key, the
IAM roles for each principal, credentials, and creating key files.
[Run the Google Cloud KMS integration tests](docs/how-to/run-google-kms-integration-tests.md) sets up
a key of your own for `test_googlekms_integration.py`, which is otherwise reported as skipped.

## Caching secrets from a secret store

The four `hkdfguard-cache-*` distributions are `ProtectedReadOnlyCache`s over a secret store. Each
one fetches a secret the first time it is looked up, encrypts it under the key ring's current key,
bound to its name, and from then on holds only the ciphertext. Nothing is listed or fetched up front.
A name is a secret's name, optionally followed by `#` and a key: `app-config#api-key` is the
`api-key` member of the JSON object the secret `app-config` holds, and `app-config` is the whole
value. One fetch caches the whole value and every key, and concurrent lookups of one secret, from
threads or event loops, share that fetch. A missing secret reads as 0 bytes and isn't remembered.

The response body is taken out of the SDK's response before the SDK parses it, so the secret never
becomes a `str`; the SDK parses a copy with the value blanked out. What Python can't zero (the
immutable `bytes` the HTTP or gRPC stack read the body into) is described in each package's
README.

```python
import boto3
from hkdfguard.cache import ProtectedCacheCollection
from hkdfguard.cache.awssecretsmanager import AwsSecretsManagerSecretCache

client = boto3.client("secretsmanager")  # the application creates, configures and owns the client
secrets = AwsSecretsManagerSecretCache(client, key_ring)
caches = ProtectedCacheCollection().add(local_cache).add(secrets)

result = bytearray(caches.find_max_decrypted_length("prod/app-config#api-key") or 0)
written = caches.decrypt("prod/app-config#api-key", result)  # or: await caches.decrypt_async(...)
```

| Store | Distribution | How the body is captured |
|---|---|---|
| AWS Secrets Manager | `hkdfguard-cache-awssecretsmanager` | a botocore `before-parse` handler, active only for the cache's own calls |
| Azure Key Vault | `hkdfguard-cache-azurekeyvault` | a per-retry azure-core pipeline policy reading the body as a stream |
| Google Cloud Secret Manager | `hkdfguard-cache-googlesecretmanager` | the gRPC call made with the cache's own response deserializer, so no protobuf message holds the payload |
| HashiCorp Vault | `hkdfguard-cache-hashicorpvault` | the HTTP response streamed straight into the parser |

Each package's README covers its names, options and errors.

## Building

Uses a [uv](https://docs.astral.sh/uv/) workspace:

```
uv sync                 # create .venv with every package (editable) and the dev tools
uv run pytest           # all tests
uv run ruff check packages
uv run mypy packages    # strict
uv build --all-packages --build-constraints build-constraints.txt --require-hashes # wheels and sdists into dist/
```

## Releasing

`.github/workflows/ci.yml` tests every push and pull request on Linux, Windows and macOS with Python
3.12 to 3.14, lints, and builds and checks the packages. `.github/workflows/release.yml` publishes all
fifteen distributions together as a GitHub Release, with Sigstore-signed build provenance and no stored
token. Nothing is published to PyPI yet.

To release: set the same version in every `packages/*/pyproject.toml`, merge to `main`, then push a tag
`v<version>` (for example `v1.0.0`). The workflow refuses a tag that is not on `main` or that differs
from any package's version. Running it by hand from the Actions tab builds and checks only.
Verify a downloaded file with `gh attestation verify <file> --repo runsecure/hkdfguard-python`.

`python scripts/check-dist.py dist --tag v1.0.0` runs the same checks locally after the `uv build` above.

The build backend, hatchling, and everything it installs are pinned by version and hash in
`build-constraints.txt`; CI and the release build with `--build-constraints build-constraints.txt
--require-hashes`, so the wheels that are attested and published come from a known backend, not
whatever PyPI serves that day (`uv.lock` doesn't cover the isolated build environment). The file's
header says how to regenerate it for a newer hatchling.

One-time setup, before the first release:

In the GitHub repository settings, create the environment `github-release`. Add required reviewers, so
a pushed tag still waits for a person before the release is created.

## Native integration tests

The native tests make real calls into this platform's KMS library: the integration tests in
`test_keywrapping.py` and the end-to-end tests in `test_dataencryptionkey.py`. Every platform's
library refuses to create a KEK while wrapping or unwrapping, so these tests run only
against a service provisioned beforehand. Without one they are reported as skipped, never as
passed. Once a service is chosen, a missing or failing library is a test failure. The tests of the
native library's key-file refusals need no KEK, so on Windows they run wherever the library is
installed; they make their files under the long form of the temporary folder, since
`hkdfguard_open_file` refuses an 8.3 short name and `%TEMP%` can be one (`C:\Users\RUNNER~1\...`).
On Linux the library refuses a key file under any directory its group or other users can write,
sticky or not, so nothing under `/tmp`, `/var/tmp` or `/dev/shm` (where pytest's `tmp_path` is):
there the key-file tests write to a new 0700 directory under `$XDG_RUNTIME_DIR/hkdfguard-tests`,
or `~/.cache/hkdfguard-tests` without a trusted one, and are skipped, saying why, when neither will
do. What the native tests share - the default test service, how it is chosen, these directories and
the macOS deadline below - is in `packages/hkdfguard-keywrapping-v1/tests/hkdfguard_test_support.py`.

Each platform also has its own native suite, matching the other HkdfGuard ports. Every test in them
is skipped, with the reason, where its platform, library or service isn't there:

| Suite | Runs on | Gated on |
| --- | --- | --- |
| Windows: the installed-library, `hkdfguard_kek_exists`, key-file and process-hardening tests in `test_keywrapping.py` and `test_process_hardening.py` | Windows | `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll` (and `hkdfguard.exe`) installed; the KEK round trips also need the provisioned test KEK or `HKDFGUARD_TEST_SERVICE` |
| Linux: `test_linux_loader.py` (loader against the real filesystem and dynamic linker) and `test_linux_native.py` (the library's contract against the real KEK provider) | Linux | the system tests need only Linux; the installed-library tests need the `libhkdfguard1` package; `test_linux_native.py` also needs `HKDFGUARD_TEST_SERVICE`, and some tests `HKDFGUARD_TEST_SERVICE_OTHER`, `tpm.require_pinned_names = true` in `/etc/hkdfguard/policy.toml`, or `/usr/bin/hkdfguard` |
| macOS: `test_macos_native.py` (loader against the real filesystem and Security framework, and the provisioning tool) | macOS | the installed `libhkdfguard.dylib` (system-wide or per user) and `hkdfguard` beside it, where a test needs them; the KEK round trips (here and in the shared tests) also need the provisioned test KEK or `HKDFGUARD_TEST_SERVICE` |

On a Linux TPM host, provision the test services once with `sudo scripts/provision-linux-test-key.sh`,
run from the account that runs the tests (`--remove` removes the policy it wrote), then run with the
variables it prints:

```bash
HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 uv run pytest
```

**Windows.** Install the HkdfGuard native package, then provision the test KEK
`com.hkdfguard.integration.test.221` once, from an elevated PowerShell at the repository root:

```powershell
./scripts/provision-windows-test-key.ps1
```

The script runs the installed `hkdfguard.exe provision`, after checking it is the signed
tool from its fixed install location (the same publisher, pinned root and Artifact Signing profile
the library's own loader requires). It is safe to re-run: an existing KEK is re-verified, not
replaced. It also retires the legacy per-platform test KEK `com.hkdfguard.native.windows.test`,
which no test uses any more, after asking (`-KeepLegacyKey` keeps it). `-Remove` retires the test
KEKs instead, each only after `hkdfguard status` confirms its fingerprint; `-WhatIf` shows what
either would delete. Afterwards the tests find the KEK on their own:

```powershell
uv run pytest
```

If the KEK exists but your account may not use it, add the account to the `HkdfGuardUsers` group
(then sign out and in), or run the tests elevated.

**macOS.** Provision `com.hkdfguard.integration.test.221` with the installed
`hkdfguard provision --service-name com.hkdfguard.integration.test.221`; the tests
then find it on their own, asking that tool (which never prompts) whether it is provisioned. The
first call from Python into a KEK the tool created can show a keychain dialog: click "Always
Allow". That first call is made with a 60-second deadline, so a dialog nobody answers fails the
run, saying so, rather than hanging it; in a session with no UI the library reports
`KEK_ACCESS_DENIED` (-18) instead, so run the tests from a logged-in session.

**Any platform.** Every platform's default test service is `com.hkdfguard.integration.test.221`.
Name another provisioned service in `HKDFGUARD_TEST_SERVICE`; it always wins over the default,
and setting it means the native tests must run. Set `HKDFGUARD_TEST_SERVICE_OTHER`
to a second provisioned service to test cross-service isolation against a different KEK (otherwise
that test uses a service that is never provisioned):

```bash
hkdfguard provision --service-name hkdfguard.integrationtest   # elevated on Windows
HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest uv run pytest
```

The tests only ever use a provisioned KEK: they never create or delete one.

**Process hardening.** `NativeProcessHardening.apply()` hardens the whole test process, so its tests
in `test_process_hardening.py` (Windows and Linux) run only with `HKDFGUARD_TEST_PROCESS_HARDENING=1`,
and only where the platform's native library is installed. Run them in their own pytest process:

```bash
HKDFGUARD_TEST_PROCESS_HARDENING=1 uv run pytest -k "apply_on_windows or apply_on_linux"
```

## AWS KMS integration tests

`test_awskms_integration.py` in `hkdfguard-keywrapping-awskms` makes real calls against a symmetric
KMS key. Its tests are reported as skipped, never passed, unless `HKDFGUARD_TEST_AWS_KMS_KEY_ID`
names one - the same variable the .NET and Java integration tests read. Credentials and region come
from botocore's usual chain. The tests never create, alter or delete a key:

```bash
HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:111122223333:key/... AWS_REGION=us-east-1 \
uv run pytest packages/hkdfguard-keywrapping-awskms
```

[Run the AWS KMS integration tests](docs/how-to/run-aws-kms-integration-tests.md) sets up a test
key and a low-privilege IAM user for them. Every other AWS KMS test runs against an in-process fake
KMS, or a real botocore client whose responses are stubbed, and sends nothing to AWS.

## Azure Key Vault integration tests

`test_azurekeyvault_integration.py` in `hkdfguard-keywrapping-azurekeyvault` makes real calls
against an RSA wrapping key and an EC P-256 signing key. Its tests are reported as skipped, never
passed, until both are named by `HKDFGUARD_TEST_AZURE_WRAP_KEY_ID` and
`HKDFGUARD_TEST_AZURE_SIGN_KEY_ID` - the variables the .NET and Java integration tests read - in the
environment or in `azure.test.properties` at the repository root, this repository's counterpart of
hkdfguard-dotnet's `azure.runsettings`. The file names keys only, never a credential, and `.gitignore`
excludes it:

```properties
HKDFGUARD_TEST_AZURE_WRAP_KEY_ID=https://<key vault name>.vault.azure.net/keys/hkdfguard-test-wrap
HKDFGUARD_TEST_AZURE_SIGN_KEY_ID=https://<key vault name>.vault.azure.net/keys/hkdfguard-test-sign
```

`DefaultAzureCredential` signs in with your `az login`. The tests never create, change or delete a
key:

```bash
uv run pytest packages/hkdfguard-keywrapping-azurekeyvault
```

[Run the Azure Key Vault integration tests](docs/how-to/run-azure-key-vault-integration-tests.md)
sets up a test vault and both keys. Every other Azure Key Vault test runs against an in-process fake
vault, or the Azure SDK's own client over a stubbed HTTP transport, and sends nothing to Azure.

## Google Cloud KMS integration tests

`test_googlekms_integration.py` in `hkdfguard-keywrapping-googlekms` makes real calls against a
symmetric Cloud KMS key. Its tests are reported as skipped, never passed, until
`HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME` - the variable the .NET and Java integration tests read - names
it, in the environment or in `google.test.properties` at the repository root, this repository's
counterpart of hkdfguard-dotnet's `google.runsettings`. The file names the key only, never a
credential, and `.gitignore` excludes it:

```properties
HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME=projects/<project>/locations/<location>/keyRings/hkdfguard-test/cryptoKeys/hkdfguard-test-wrap
```

Application Default Credentials sign in with your `gcloud auth application-default login`. The
tests never create, change or destroy a key:

```bash
uv run pytest packages/hkdfguard-keywrapping-googlekms
```

[Run the Google Cloud KMS integration tests](docs/how-to/run-google-kms-integration-tests.md) sets up
a test key and its permissions. Every other Google Cloud KMS test runs against a fake Cloud KMS on
the loopback address, reached through Google's own client, and sends nothing to Google.

## Secret cache integration tests

Each `hkdfguard-cache-*` distribution has an integration test that reads a real secret. It is
reported as skipped, never passed, until the secret is named. Set the matching `..._SECRET_JSON`
variable to the JSON object the secret holds, and the tests also compare the whole value and every
key with it. The variables are the ones the .NET and Java tests read, from the environment or the
settings file. A settings file names secrets and test values only, never a credential, and
`.gitignore` excludes it.

| Store | Variables | Settings file | Signs in with |
|---|---|---|---|
| AWS Secrets Manager | `HKDFGUARD_TEST_AWS_SECRET_NAME`, `HKDFGUARD_TEST_AWS_SECRET_JSON` | `aws.test.properties` | the access keys in the environment, else `~/.aws/credentials` only |
| Azure Key Vault | `HKDFGUARD_TEST_AZURE_SECRET_ID`, `HKDFGUARD_TEST_AZURE_SECRET_JSON`, `HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS` | `azure.test.properties` | `DefaultAzureCredential` |
| Google Cloud Secret Manager | `HKDFGUARD_TEST_GOOGLE_SECRET_NAME`, `HKDFGUARD_TEST_GOOGLE_SECRET_JSON` | `google.test.properties` | Application Default Credentials |
| HashiCorp Vault | `HKDFGUARD_TEST_VAULT_ADDR`, `HKDFGUARD_TEST_VAULT_TOKEN` (environment only), `HKDFGUARD_TEST_VAULT_SECRET_NAME`, `HKDFGUARD_TEST_VAULT_SECRET_JSON` (environment only), `HKDFGUARD_TEST_VAULT_CACERT` | `vault.test.properties` | the token |

```bash
uv run pytest packages/hkdfguard-cache-awssecretsmanager packages/hkdfguard-cache-azurekeyvault \
              packages/hkdfguard-cache-googlesecretmanager packages/hkdfguard-cache-hashicorpvault
```

The how-to guides set up each store:

- [AWS Secrets Manager](docs/how-to/run-aws-secrets-manager-cache-integration-tests.md)
- [Azure Key Vault](docs/how-to/run-azure-key-vault-secret-cache-integration-tests.md)
- [Google Cloud Secret Manager](docs/how-to/run-google-secret-manager-cache-integration-tests.md)
- [HashiCorp Vault](docs/how-to/run-hashicorp-vault-cache-integration-tests.md)

Every other secret cache test runs against a fake store, reached through the store's own client
where it has one, and sends nothing over the network.
