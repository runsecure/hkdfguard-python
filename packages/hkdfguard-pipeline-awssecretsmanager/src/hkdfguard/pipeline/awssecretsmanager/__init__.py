"""The end of a provisioning pipeline over AWS Secrets Manager: pulls a fixed list of secrets through
a botocore client, taking each out of the response body before botocore can make it a ``str``,
encrypts it at once with a pipeline data protector bound to its file name, and writes one encrypted
file per secret."""

from hkdfguard.pipeline.awssecretsmanager._writer import AwsSecretsManagerSecretPipelineWriter, SecretsManagerClient

__all__ = ["AwsSecretsManagerSecretPipelineWriter", "SecretsManagerClient"]
