"""The end of a provisioning pipeline over Azure Key Vault: pulls a fixed list of secrets through the
writer's own SecretClient, taking each out of the response body before the SDK can make it a
``str``, encrypts it at once with a pipeline data protector bound to its file name, and writes one
encrypted file per secret."""

from hkdfguard.pipeline.azurekeyvault._writer import AzureKeyVaultSecretPipelineWriter

__all__ = ["AzureKeyVaultSecretPipelineWriter"]
