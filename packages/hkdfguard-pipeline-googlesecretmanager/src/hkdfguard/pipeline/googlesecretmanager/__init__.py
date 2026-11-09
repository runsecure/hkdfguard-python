"""The end of a provisioning pipeline over Google Cloud Secret Manager: pulls a fixed list of secrets
on a gRPC channel, taking each payload out of the response before the client can parse it, encrypts
it at once with a pipeline data protector bound to its file name, and writes one encrypted file per
secret."""

from hkdfguard.pipeline.googlesecretmanager._writer import GoogleSecretManagerSecretPipelineWriter

__all__ = ["GoogleSecretManagerSecretPipelineWriter"]
