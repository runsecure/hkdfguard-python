"""The end of a provisioning pipeline over HashiCorp Vault's KV secrets engine: pulls a fixed list of
secrets through the standard library's HTTP client, taking each out of the response before it can
become a ``str``, encrypts it at once with a pipeline data protector bound to its file name, and
writes one encrypted file per secret. The token sources, TLS options and the error Vault's refusals
are reported as are ``hkdfguard-integration-hashicorpvault``'s."""

from hkdfguard.pipeline.hashicorpvault._options import HashiCorpVaultPipelineOptions, VaultKvVersion
from hkdfguard.pipeline.hashicorpvault._writer import HashiCorpVaultSecretPipelineWriter

__all__ = [
    "HashiCorpVaultPipelineOptions",
    "HashiCorpVaultSecretPipelineWriter",
    "VaultKvVersion",
]
