# hkdfguard-keywrapping-azurekeyvault

Wraps DEKs under an RSA key in Azure Key Vault and signs them with an EC P-256 key there, reading key files only from where no untrusted account could have replaced them.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java: values encrypted by any of the three decrypt with
the others, and a key file made by any port's Azure Key Vault wrapper is read by the others. Every
distribution installs one subpackage of the shared `hkdfguard` namespace package.

```
pip install hkdfguard-keywrapping-azurekeyvault azure-identity
```

```python
from azure.identity import DefaultAzureCredential
from hkdfguard.keywrapping.azurekeyvault import AzureKeyVaultKeyWrapper

wrapper = AzureKeyVaultKeyWrapper("https://myvault.vault.azure.net/keys/myapp-wrap",
                                  "https://myvault.vault.azure.net/keys/myapp-sign",
                                  DefaultAzureCredential(), "com.example.myapp")
```

The package depends on `azure-keyvault-keys`; the credential comes from `azure-identity`, which the
application adds.

Requires Python 3.12 or later. See the
[repository README](https://github.com/runsecure/hkdfguard-python#readme) ("Wrapping under Azure Key
Vault instead") and [Wrap keys with Azure Key Vault](https://github.com/runsecure/hkdfguard-python/blob/main/docs/how-to/use-azure-key-vault.md)
for the keys, permissions, credentials and key files.

Licensed under the Mozilla Public License 2.0.
