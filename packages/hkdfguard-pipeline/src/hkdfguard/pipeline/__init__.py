"""The end of a provisioning pipeline: :class:`SecretPipelineWriter` is the shared base of the
secret stores' :class:`~hkdfguard.abstractions.SecretPipelineWriter` s, which pull a fixed list of
secrets, encrypt each at once with a :class:`~hkdfguard.abstractions.PipelineDataProtector` bound to
its file name, keep only the ciphertext, and write one file per secret - the folder layout
:class:`~hkdfguard.cache.FilePerSecretCache` reads at runtime. No key ring is involved."""

from pkgutil import extend_path

# The hkdfguard-pipeline-* store distributions install subpackages of hkdfguard.pipeline
# (hkdfguard.pipeline.awssecretsmanager, ...). Installed wheels share one directory, but editable
# installs keep each distribution's src separate, so every one of them is searched.
__path__ = extend_path(__path__, __name__)

from hkdfguard.pipeline._writer import SecretPipelineWriter, SecretRequest

__all__ = ["SecretPipelineWriter", "SecretRequest"]
