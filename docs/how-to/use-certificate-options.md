# Open a certificate from a store, a provider or a file

`hkdfguard-options-certificate` opens one certificate - and its private key - from where
configuration says it is. This guide sets up each source and runs its opt-in tests. The package
README describes the API and the differences from .NET.

## Windows certificate store

Put the certificate in a store only administrators can write - LocalMachine\My - with a CNG key,
non-exportable:

```powershell
$c = Import-PfxCertificate -FilePath api.pfx -CertStoreLocation Cert:\LocalMachine\My -Password $pw
# or, for a test: New-SelfSignedCertificate -Subject 'CN=api.example.com' -CertStoreLocation Cert:\LocalMachine\My `
#   -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider'
```

Grant the service's account read access to the key (certlm.msc, *Manage Private Keys*), and configure:

```json
"Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
```

`certificate.sign(...)` and `certificate.decrypt(...)` call CNG; `create_ssl_context` refuses, since
Python's `ssl` can't use a key it can't read from a file.

Run the round trip - it makes and removes throwaway certificates in CurrentUser\My:

```powershell
$env:HKDFGUARD_TEST_WINDOWS_CERT_STORE = "1"
uv run pytest packages/hkdfguard-options-certificate/tests/test_certificate_windows_store.py
Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -like '*hkdfguard-python-test*'   # nothing is left
```

## macOS keychain

Import the identity into the System keychain (LocalMachine) or the login keychain (CurrentUser), and
use `"MacOS"` in place of `"Windows"`; only the My store is read. To run the round trip, which
imports throwaway identities into the login keychain and deletes them:

```sh
HKDFGUARD_TEST_MACOS_KEYCHAIN=1 uv run pytest packages/hkdfguard-options-certificate/tests/test_certificate_macos_keychain.py
```

## Linux: a key in a PKCS#11 token (pkcs11-provider)

Use the distribution's Python - it links the system OpenSSL 3, which the provider loads into - in a
virtual environment, not one uv downloaded. With SoftHSM standing in for the token (Ubuntu):

```sh
sudo apt-get install pkcs11-provider softhsm2 opensc python3-venv
export SOFTHSM2_CONF=$PWD/softhsm2.conf PKCS11_PROVIDER_MODULE=/usr/lib/softhsm/libsofthsm2.so
mkdir tokens && printf 'directories.tokendir = %s/tokens\n' "$PWD" > softhsm2.conf
softhsm2-util --init-token --free --label hkdfguard --pin 1234 --so-pin 5678
pkcs11-tool --module $PKCS11_PROVIDER_MODULE --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label tls --id 01
URI='pkcs11:token=hkdfguard;object=tls;type=private?pin-value=1234'   # or pin-source=file:/path/to/pin
openssl req -provider pkcs11 -provider default -new -x509 -key "$URI" -subj /CN=api.example.com -days 30 -out tls.crt
```

```json
"Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=hkdfguard;object=tls;type=private?pin-value=1234", "CertificateFile": "/path/tls.crt" } }
```

```sh
HKDFGUARD_TEST_OPENSSL_PROVIDER=pkcs11 HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI="$URI" \
HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE=$PWD/tls.crt \
  python -m pytest packages/hkdfguard-options-certificate/tests/test_certificate_linux_provider.py
```

## Linux: a key in the TPM (tpm2-openssl)

With swtpm standing in for the TPM:

```sh
sudo apt-get install tpm2-openssl swtpm
mkdir state && swtpm socket --tpm2 --tpmstate dir=state --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear --daemon
export TPM2OPENSSL_TCTI=swtpm:host=127.0.0.1,port=2321      # unset on a host with a real TPM, which uses /dev/tpmrm0
openssl genpkey -provider tpm2 -provider default -algorithm RSA -pkeyopt bits:2048 -out tls-key.pem   # a TSS2 PRIVATE KEY
openssl req -provider tpm2 -provider default -new -x509 -key tls-key.pem -subj /CN=api.example.com -days 30 -out tls.crt
```

`KeyUri` is the path of `tls-key.pem` - a key blob only that TPM can load, not the key itself. A
persistent handle (`handle:0x81000001`) can't be read by Python's `ssl` and is refused. For an EC key,
have the certificate issued by a CA from a CSR (`openssl req -new ... -out tls.csr`, then
`openssl x509 -req -CA ...`): tpm2-openssl writes a self-signed ECDSA certificate's signature
algorithm with NULL parameters, which `cryptography` refuses to parse. Run the test as for pkcs11,
with `HKDFGUARD_TEST_OPENSSL_PROVIDER=tpm2` and the key file's path as the key URI.

## A file

```json
"Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
"Certificate": { "File": { "Path": "/etc/myapp/tls.crt", "Format": "Pem", "KeyPath": "/etc/myapp/tls.key", "PasswordSecretName": "tls-key-password" } }
```

The password is a secret in the `ProtectedReadOnlyCache` given to the loader - a file in a
`FilePerSecretCache` folder named `tls-pfx-password`, say. A PEM key must be encrypted PKCS#8
(`openssl pkcs8 -topk8 -v2 aes-256-cbc`); re-export a legacy RC2/RC4 PKCS#12 with
`openssl pkcs12 -export` (without `-legacy`).
