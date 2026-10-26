"""Wraps and reveals DEKs under one symmetric AWS KMS key - Encrypt, Decrypt (the key pinned) and
GenerateDataKeyWithoutPlaintext, through a botocore client the application owns - and reads key files
only from where no untrusted account could have written or replaced them (``hkdfguard-securefile``)."""

from hkdfguard.keywrapping.awskms._wrapper import AwsKmsKeyWrapper, KmsClient
from hkdfguard.securefile import KeyFileTrust

__all__ = ["AwsKmsKeyWrapper", "KeyFileTrust", "KmsClient"]
