# hkdfguard-options-certificate

Plain-data, validated options naming one X.509 certificate - in the Windows store, a macOS keychain,
an OpenSSL provider or a password-protected file - and the loader that opens it without exporting an
OS-held key.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java. Every distribution installs one subpackage of the
shared `hkdfguard` namespace package; this one installs `hkdfguard.options.certificate`, the port of
.NET's `HkdfGuard.Options.Certificate`.

```
pip install hkdfguard-options-certificate
```

Requires Python 3.12 or later and `cryptography` 47 or later. Store access is `ctypes` only: crypt32
and ncrypt from System32 on Windows, the Security framework by its absolute path on macOS.

## Options

`CertificateOptions` names exactly one source, with the .NET configuration keys, so the same
`appsettings.json` section binds through `CertificateOptions.from_mapping` (keys match ignoring case
and underscores; enums by name, ignoring case, or by .NET's number; an unknown key is an error):

```json
"Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
"Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } }
"Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=tls;object=api;type=private", "CertificateFile": "/etc/myapp/tls.crt" } }
"Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
```

`RequirePrivateKey` defaults to true; set it false for a certificate only to be trusted. A file's
password never appears in configuration: `PasswordSecretName` names a secret in a
`ProtectedReadOnlyCache` (a `FilePerSecretCache`, a remote secret cache), which the loader decrypts
into a `bytearray` and zeroes as soon as the key is read. An unprotected key file is refused unless
`AllowUnprotectedPrivateKey` is set, for development. With `PasswordSecretName` set, a PKCS#12 file
must be protected by that password: one without an integrity MAC (`openssl pkcs12 -nomac`), or holding
its key outside encrypted contents (`-keypbe NONE`), is refused rather than loaded unchecked.

A store certificate is found by its subject distinguished name, compared whole and decoded, ignoring
case - `"CN=api"` never matches `"CN=api.example.com"`. Of the certificates with that subject, the one
valid now (and with its private key, when one is required) that expires last is chosen, so a renewal
under the same subject is picked up with no configuration change. Matching by subject trusts whoever
can write the store: use one only administrators can, such as LocalMachine's My.

```python
import ssl
from hkdfguard.options.certificate import CertificateOptions, CertificateOptionsLoader

options = CertificateOptions.from_mapping(config["Certificate"])
loader = CertificateOptionsLoader(passwords)  # passwords: a ProtectedReadOnlyCache; None if no file has one
with loader.load(options, "tls") as certificate:  # or: await loader.load_async(options, "tls")
    context = certificate.create_ssl_context(ssl.Purpose.CLIENT_AUTH)  # a server's TLS context (File and Linux sources)
    signature = certificate.sign(data, hashes.SHA256(), padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH))
```

`CertificateOptionsValidator` (also `options.validate()` / `options.require_valid()`) reports every
failure at once; the loader validates first and raises `CertificateOptionsValidationError` (an
`hkdfguard.options.OptionsValidationError`) listing them.

## What each source gives

| Source | Key stays in | `sign` / `decrypt` | `create_ssl_context` |
|---|---|---|---|
| Windows store | CNG (or the TPM through the Platform Crypto Provider): acquired with `CryptAcquireCertificatePrivateKey`, CNG only and silently | `NCryptSignHash` (RSA PKCS #1 v1.5 and PSS, ECDSA) and `NCryptDecrypt` (PKCS #1 v1.5, OAEP) | Raises `NativeProviderRequiredError` |
| macOS keychain (My only) | The keychain: the identity's `SecKeyRef` | `SecKeyCreateSignature`, `SecKeyCreateDecryptedData` | Raises `NativeProviderRequiredError` |
| Linux OpenSSL provider | The provider (TPM, token) | Raise `UnsupportedCertificateError` | Yes: `ssl` decodes the key through the provider |
| File (PKCS#12, PEM + encrypted PKCS#8) | Process memory, encrypted under a random throwaway password, wiped on `close()` | Yes, through `cryptography` | Yes |

Without its private key (`RequirePrivateKey` false), any source's certificate gives a
`create_ssl_context` that trusts it - and its chain - alone, in place of the system's roots; the DER
is `certificate.der` for `load_verify_locations(cadata=...)` into a context of your own.

`LoadedCertificate` has `certificate` (a `cryptography.x509.Certificate`), `der`, `chain` (the other
certificates a PKCS#12 or PEM file held, in file order), `has_private_key`, `key_location`,
`public_key()`, `sign(data, algorithm, padding=None)` - `Prehashed(...)` for a digest; an RSA key
needs `padding.PKCS1v15()` or `padding.PSS(...)`, an ECDSA key none and returns DER - and
`decrypt(ciphertext, padding)`, returning a `bytearray` to zero once used. `close()` (or `with`)
waits for operations in flight, releases store handles and wipes what it holds; every later use raises
`ObjectClosedError`. A TLS context keeps its own copy of a file key in OpenSSL and outlives `close()`.

### Files

The PKCS#12 and PBES2 decryption is this package's own, as in the Go port: PBES2 (PBKDF2 with
HMAC-SHA-1/224/256/384/512, AES-128/192/256-CBC or 3DES-CBC), PKCS#12's own 3DES, HMAC-SHA-1/2
integrity MACs, BER as well as DER. Legacy RC2 and RC4 files (`openssl pkcs12 -legacy`) are refused
with a hint to re-export with AES, as are PBMAC1 and public-key-protected files; key derivations are
capped at 1,000,000 iterations each and 4,000,000 per file. PBKDF2 runs in `cryptography`'s
`derive_into` and every decryption in `update_into`, so the password, the derived key and the
decrypted key are all in `bytearray`s that are zeroed. Python's `ssl` takes a key only from a file:
the decrypted PKCS#8 is at once re-encrypted (PBES2, AES-256-CBC) under a random 32-byte throwaway
password, and each `create_ssl_context` writes that ciphertext to a private temporary directory (mode
0700 with a 0600 file on Unix; on Windows a protected DACL granting only the account itself), loads it
through the password callback and deletes it. The key is never written to disk unencrypted.

Why not `cryptography`'s `pkcs12.load_key_and_certificates`: its Rust bindings copy the password into
a buffer they free without zeroing, it reads RC2/RC4 files (the legacy provider is loaded), and its
key can only be re-encrypted for `ssl` under an immutable `bytes` password. What remains beyond reach
here: PKCS#12's own key derivation (Windows' default 3DES export, and every integrity MAC) hashes with
`hashlib`, whose intermediate digests are immutable `bytes`; `ssl` copies the throwaway password - never
yours - into a buffer it frees without zeroing; and `cryptography` parses the key into OpenSSL memory
for the moment it is matched to its certificate, signed or decrypted with.

### Linux OpenSSL providers

Python's `ssl.SSLContext.load_cert_chain` reads its key file through OpenSSL 3's decoders, so a key a
provider holds is used in place - every TLS signature is the TPM's or the token's. `KeyUri` is either
a `pkcs11:` URI, which is written for pkcs11-provider into the private temporary directory as a
`PKCS#11 PROVIDER URI` PEM, or the absolute path of a key file the provider decodes, such as the
`TSS2 PRIVATE KEY` PEM that `openssl genpkey -provider tpm2 ...` writes. A persistent TPM handle
(`handle:0x81000001`) has no such file and is refused by the validator. The loader loads the provider
into the libcrypto `ssl` itself uses (found among the process's mappings, and checked against
`ssl.OPENSSL_VERSION_NUMBER`) with `OSSL_PROVIDER_load`, and opens the key once at load time so a
missing or mismatched key fails there. That needs a Python linked against the system's OpenSSL 3 -
the distribution's own `python3`; a Python with OpenSSL built in (python-build-standalone, which uv
installs by default) is refused with that explanation. The provider's own settings - `TPM2OPENSSL_TCTI`,
`PKCS11_PROVIDER_MODULE`, a token PIN (prefer `pin-source=file:...` in the URI, or the provider's
configuration, to `pin-value`) - come from its environment or `openssl.cnf`.

## Differences from .NET

- **Store keys and TLS.** .NET's `X509Certificate2` from a store goes straight into `SslStream`.
  Python's `ssl` can only read a key from a file, and a store's key is never exported to make one, so
  `create_ssl_context` raises `NativeProviderRequiredError` for a Windows or macOS store key; phase 2
  may add an OpenSSL provider for them. `sign` and `decrypt` call the store directly.
- **Linux providers.** .NET opens `KeyUri` through `SafeEvpPKeyHandle.OpenKeyFromProvider` (an
  `OSSL_STORE` URI). Here it is a `pkcs11:` URI or a key-file path read through the provider's decoder;
  a TPM `handle:` is refused. A provider key is used for TLS only: Python has no API to sign or
  decrypt with an `ssl` key. It needs a Python linked to the system OpenSSL 3.
- **macOS stores.** Only My - the login keychain for CurrentUser, the System keychain for
  LocalMachine - is read, as in the Go port; the validator refuses any other store name on macOS
  (.NET also maps Root and others to trust settings). Root is deliberately not offered: reading the
  SystemRootCertificates keychain without applying the trust settings that distrust a root would
  hand back roots macOS no longer trusts.
- **What a load returns.** A `LoadedCertificate`, not an `X509Certificate2`: the certificate as a
  `cryptography` object, the rest of a PKCS#12 or PEM file's certificates as `chain` (.NET drops
  them), and the key's operations as methods. A file's key is held encrypted under a throwaway
  password, where .NET imports it as a non-exportable, non-persisted key.
- **Legacy files.** RC2/RC4 PKCS#12 files, PBMAC1 and public-key-protected PKCS#12 contents, and
  legacy OpenSSL-encrypted PEM keys (`Proc-Type`) are refused; .NET on Windows reads RC2/RC4.
  Iteration counts are capped (1,000,000 per derivation, 4,000,000 per file).
- **Certificates `cryptography` won't parse** can't be loaded - for instance one whose ECDSA
  signature algorithm carries NULL parameters, as tpm2-openssl's `openssl req -x509` writes. In a
  store such a certificate is skipped, as Go skips what it can't parse.
- **Subject matching.** Compared attribute by attribute, decoded, each multi-valued RDN's attributes
  as a set (as the Java port does) rather than .NET's comparison of the rendered strings; case is
  ignored character by character, as `OrdinalIgnoreCase` does.
- **Store keys' algorithms.** SHA-1, SHA-256, SHA-384 and SHA-512 with CNG (SHA-224 too on macOS);
  PSS and OAEP with MGF1 over the same hash; on macOS a PSS salt of the hash's length only and OAEP
  with no label. Windows keys from the Microsoft CryptoAPI providers are opened through CNG's own
  interop, as with any CNG key; a key CNG can't open silently - a third-party CSP without a KSP, or one
  that would show a dialog - is refused.
- **Configuration and errors.** `from_mapping` refuses unknown keys (.NET's binder ignores them).
  Failures are typed exceptions - `CertificateNotFoundError`, `CertificateNotValidNowError`,
  `NoPrivateKeyError`, `NoPasswordSourceError`, `PasswordNotFoundError` (a `KeyNotFoundError`),
  `InvalidCertificateFileError` and `WrongPasswordError` (`CryptographicError`s),
  `UnsupportedCertificateError` - where .NET throws `InvalidOperationException`,
  `CryptographicException` and `KeyNotFoundException`. The validator also refuses, where the source is
  otherwise usable, a macOS store other than My and a Linux `KeyUri` that is neither a `pkcs11:` URI
  nor an absolute path.

## Tests

The unit tests run everywhere, against certificates they make and the Go port's fixtures (OpenSSL-
and .NET-written PKCS#12 and PKCS#8 files). Three opt-in suites touch real key storage:

- `HKDFGUARD_TEST_WINDOWS_CERT_STORE=1`: makes throwaway non-exportable RSA and ECDSA certificates in
  CurrentUser\My with `New-SelfSignedCertificate`, signs and decrypts through CNG, verifies with the
  public key, and removes them with their keys.
- `HKDFGUARD_TEST_MACOS_KEYCHAIN=1`: imports throwaway identities into the login keychain and deletes
  them. **Not yet run on a Mac**; the keychain code is untested.
- `HKDFGUARD_TEST_OPENSSL_PROVIDER=<provider>` with `HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI` and
  `HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE`: a TLS handshake through a real provider key, under a
  system Python. See [the how-to](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/use-certificate-options.md).

Licensed under the Mozilla Public License 2.0.
