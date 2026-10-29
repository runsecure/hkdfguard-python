"""A protected read-only cache over AWS Secrets Manager, through a botocore client the application
owns: each secret is read with GetSecretValue on its first lookup, taken out of the response body
before botocore can make it a ``str``, encrypted under the key ring's current key and cached only as
ciphertext."""

from hkdfguard.cache.awssecretsmanager._cache import AwsSecretsManagerSecretCache, SecretsManagerClient

__all__ = ["AwsSecretsManagerSecretCache", "SecretsManagerClient"]
