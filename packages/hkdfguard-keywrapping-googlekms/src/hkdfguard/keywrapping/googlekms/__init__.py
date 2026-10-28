"""Wraps and reveals DEKs under one symmetric Google Cloud KMS key - Encrypt and Decrypt (the key
pinned), every request and response checksummed, through a Cloud KMS client the application owns - and
reads key files only from where no untrusted account could have written or replaced them
(``hkdfguard-securefile``)."""

from hkdfguard.keywrapping.googlekms._wrapper import CloudKmsClient, GoogleKmsKeyWrapper
from hkdfguard.securefile import KeyFileTrust

__all__ = ["CloudKmsClient", "GoogleKmsKeyWrapper", "KeyFileTrust"]
