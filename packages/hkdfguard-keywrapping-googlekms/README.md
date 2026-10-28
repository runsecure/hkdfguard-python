# hkdfguard-keywrapping-googlekms

Wraps DEKs under one symmetric Google Cloud KMS key, reading key files only from where no untrusted account could have replaced them.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others, and a key file made by any port's Google Cloud KMS wrapper is read by the others. Every
distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-keywrapping-googlekms
```

```python
from google.cloud import kms
from hkdfguard.keywrapping.googlekms import GoogleKmsKeyWrapper

client = kms.KeyManagementServiceClient()  # Application Default Credentials
wrapper = GoogleKmsKeyWrapper(client, "projects/my-project/locations/europe-west1/keyRings/myapp/cryptoKeys/dek-wrap",
                              "com.example.myapp")
```

The package depends on `google-cloud-kms`, which brings `google-auth` for the credentials. The client
is the application's: it creates it, and closes it once nothing uses the wrapper.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) ("Wrapping under Google Cloud
KMS instead") and [Wrap keys with Google Cloud KMS](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/use-google-kms.md)
for the key, permissions, credentials and key files.

Licensed under the Mozilla Public License 2.0.
