# hkdfguard-python

HkdfGuard Key Wrapping and Secrets Protection library for Python - the Python port of
[hkdfguard-dotnet](https://github.com/runsecure/hkdfguard-dotnet), alongside
[hkdfguard-java](https://github.com/runsecure/hkdfguard-java). Values encrypted by any of the three
decrypt with the others: the wire format, AAD rules, AES-GCM layout, span/metric names and log
event ids are identical.

Requires **Python 3.12** or later. Cryptography is [`cryptography`](https://cryptography.io);
telemetry is the OpenTelemetry API; logging is the standard `logging` module; native KMS calls use
`ctypes`.

## Packages

Each distribution installs one subpackage of the `hkdfguard` namespace package.

| Distribution                          | Import                                  | .NET assembly                        | Contents |
|---------------------------------------|-----------------------------------------|--------------------------------------|----------|
| `hkdfguard-diagnostics`               | `hkdfguard.diagnostics`                 | HkdfGuard.Diagnostics                | `HkdfGuardTelemetry`, `CacheMetrics`, span/attribute/event/metric names, `HkdfGuardLog` |
| `hkdfguard-abstractions`              | `hkdfguard.abstractions`                | HkdfGuard.Abstractions               | `CryptoProvider`, `KeyWrapper`, `KeyRing`, `DataProtector`, ... ; `ProtectedCacheBase`, `ServiceNames`, `ProtectedConfigurationPurpose`, the exception types |
| `hkdfguard-cryptoprovider-aesgcm256`  | `hkdfguard.cryptoprovider.aesgcm256`    | HkdfGuard.CryptoProvider.AesGcm256   | `AesGcmCryptoProvider`, `AesGcmCryptoProviderFactory`, `AesGcmPipelineDataProtector` |
| `hkdfguard-keywrapping-v1`            | `hkdfguard.keywrapping.v1`              | HkdfGuard.KeyWrapping.V1             | `NativeHkdfKeyWrapperV1` over the native KMS library |
| `hkdfguard-dataencryptionkey`         | `hkdfguard.dataencryptionkey`           | HkdfGuard.DataEncryptionKey          | `KeyRing`, `KeyRingBuilder`, `DataEncryptionKey`, `DefaultFormatProvider` |
| `hkdfguard-cache`                     | `hkdfguard.cache`                       | HkdfGuard.Cache                      | `ProtectedCache`, `ProtectedCacheCollection` |
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

- **Synchronous API.** Every .NET `...Async` method is a blocking call (`build()`, `create(...)`,
  `wrap(...)`); there is no `CancellationToken`. Background key refresh and ephemeral key rotation
  run on daemon threads.
- **Disposal** is `close()`, and every disposable type is a context manager. `KeyRing.close()`
  never waits for a rotation blocked in the KMS: a key that rotation creates after the ring closed
  is closed instead of added.
- **Buffers.** Secrets travel in writable buffers (`bytearray` or `memoryview`) so they can be
  zeroed; immutable `bytes` are refused wherever a plaintext would need zeroing. AES-GCM reads
  and writes the caller's buffers directly (`encrypt_into`/`decrypt_into`) rather than through
  immutable copies. The plaintext and result buffers of an encrypt must not overlap: it is refused
  with `ValueError`, since encrypting in place would destroy the plaintext. Decrypt writes UTF-8 bytes and returns the count; `decrypt_to_str` is a convenience
  for when an immutable `str` is acceptable. AAD is the keyword-only argument `aad=`. A `str`
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
    anything is read.
  - `CryptographicException` and `AuthenticationTagMismatchException` become `CryptographicError`
    and `AuthenticationTagMismatchError`.
- **Memory hygiene:** CPython has no pinned or stack allocation, so zeroing erases the live copy of
  a secret but not copies the allocator may have left; `str` values can never be zeroed, and
  encoding a `str` always passes through a temporary immutable `bytes`. What a library such as
  `cryptography` keeps inside a call is outside this library's control.
- **Logging:** a `None` logger means the package's own logger (e.g. `hkdfguard.cache`). The event id
  travels as the `hkdfguard_event_id` record attribute; .NET's Critical is `logging.CRITICAL`.
- **Telemetry** goes to OpenTelemetry's global providers, or to those given to
  `HkdfGuardTelemetry.set_tracer_provider` / `set_meter_provider`.

## Native access

`hkdfguard-keywrapping-v1` calls the native KMS library through `ctypes`. The library is installed
separately and loaded only from its verified location, exactly as in .NET and Java: path ACLs,
Authenticode signer, root and EKU, and PE checks on Windows; ownership, code signature and dyld
checks on macOS.

| Platform | Library                                                                 | Command-line tool                              |
|----------|-------------------------------------------------------------------------|------------------------------------------------|
| Windows  | `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll`                             | `%ProgramFiles%\HkdfGuard\v1\hkdfguard.exe`    |
| Linux    | `libHkdfGuardKeyProtectionLinux.so`, by the dynamic linker's search     | `/usr/bin/hkdfguard`                           |
| macOS    | `/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib`, or `~/.hkdfguard/v1/libhkdfguard_v1.dylib` | `hkdfguard-v1-initialize` |

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
turned off; `without_key_file_permission_checks()` only affects a key wrapper that keeps the default
`read_key_file`, `WrappedKeyFile.read` (ordinary file I/O, refusing empty files and files over
`WrappedKeyLimits.MAX_BYTES`, plus the POSIX ownership rule).

## Building

Uses a [uv](https://docs.astral.sh/uv/) workspace:

```
uv sync                 # create .venv with every package (editable) and the dev tools
uv run pytest           # all tests
uv run ruff check packages
uv run mypy packages    # strict
uv build --all-packages # wheels and sdists into dist/
```

## Releasing

`.github/workflows/ci.yml` tests every push and pull request on Linux, Windows and macOS with Python
3.12 to 3.14, lints, and builds and checks the packages. `.github/workflows/release.yml` publishes all
seven distributions together to PyPI, with no stored token (PyPI trusted publishing).

To release: set the same version in every `packages/*/pyproject.toml`, merge to `main`, then push a tag
`v<version>` (for example `v1.0.0`). The workflow refuses a tag that is not on `main` or that differs
from any package's version. Running it by hand from the Actions tab publishes to TestPyPI instead.

`python scripts/check-dist.py dist --tag v1.0.0` runs the same checks locally after `uv build --all-packages`.

One-time setup, before the first release:

1. On PyPI and TestPyPI, add a trusted publisher to each of the seven projects (a *pending*
   publisher, for a project that does not exist yet): owner `runsecure`, repository
   `hkdfguard-python`, workflow `release.yml`, environment `pypi` (PyPI) or `testpypi` (TestPyPI).
2. In the GitHub repository settings, create the environments `pypi` and `testpypi`. Add required
   reviewers to `pypi`, so a pushed tag still waits for a person before anything is published.

## Native integration tests

The native tests make real calls into this platform's KMS library: the integration tests in
`test_keywrapping.py` and the end-to-end tests in `test_dataencryptionkey.py`. Every platform's
library refuses to create a KEK while wrapping or unwrapping, so these tests run only
against a service provisioned beforehand. Without one they are reported as skipped, never as
passed. Once a service is chosen, a missing or failing library is a test failure. The tests of the
native library's key-file refusals need no KEK, so on Windows they run wherever the library is
installed; they make their files under the long form of the temporary folder, since
`hkdfguard_open_file` refuses an 8.3 short name and `%TEMP%` can be one (`C:\Users\RUNNER~1\...`).

**Windows.** Install the HkdfGuard native package, then provision the test KEK
`com.hkdfguard.native.windows.test` once, from an elevated PowerShell at the repository root:

```powershell
./scripts/provision-windows-test-key.ps1
```

The script runs the installed `hkdfguard.exe provision`, after checking it is the signed
tool from its fixed install location (the same publisher, pinned root and Artifact Signing profile
the library's own loader requires). It is safe to re-run: an existing KEK is re-verified, not
replaced. Afterwards the tests find the KEK on their own:

```powershell
uv run pytest
```

If the KEK exists but your account may not use it, add the account to the `HkdfGuardUsers` group
(then sign out and in), or run the tests elevated.

**Any platform.** Name a provisioned service in `HKDFGUARD_TEST_SERVICE`; it always wins over the
Windows default, and setting it means the native tests must run. Set `HKDFGUARD_TEST_SERVICE_OTHER`
to a second provisioned service to test cross-service isolation against a different KEK (otherwise
that test uses a service that is never provisioned):

```bash
hkdfguard provision --service-name hkdfguard.integrationtest   # elevated on Windows; hkdfguard-v1-initialize on macOS
HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest uv run pytest
```

The tests only ever use a provisioned KEK: they never create or delete one.
