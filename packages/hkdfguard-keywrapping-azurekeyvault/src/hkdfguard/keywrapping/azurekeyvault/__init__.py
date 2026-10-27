"""Wraps and reveals DEKs under an RSA key in Azure Key Vault (RSA-OAEP-256), signing every wrapped DEK
with a second, EC P-256 key there (ES256) and verifying it before anything is unwrapped, through the
Azure SDK's ``CryptographyClient`` - and reads key files only from where no untrusted account could
have written or replaced them (``hkdfguard-securefile``)."""

from hkdfguard.keywrapping.azurekeyvault._wrapper import AzureKeyVaultKeyWrapper, KeyVaultCryptoClient
from hkdfguard.securefile import KeyFileTrust

__all__ = ["AzureKeyVaultKeyWrapper", "KeyFileTrust", "KeyVaultCryptoClient"]
