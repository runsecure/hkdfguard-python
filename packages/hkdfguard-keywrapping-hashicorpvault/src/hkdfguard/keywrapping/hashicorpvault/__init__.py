"""Wraps and reveals DEKs under one key in a HashiCorp Vault transit secrets engine - encrypt, decrypt
and datakey/wrapped (the key pinned by its path), through the standard library's ``http.client`` with
no third-party dependency - and reads key files only from where no untrusted account could have
written or replaced them (``hkdfguard-securefile``)."""

from hkdfguard.keywrapping.hashicorpvault._errors import VaultRequestError
from hkdfguard.keywrapping.hashicorpvault._options import HashiCorpVaultTransitKeyWrapperOptions
from hkdfguard.keywrapping.hashicorpvault._token import StaticVaultTokenSource, VaultTokenSource
from hkdfguard.keywrapping.hashicorpvault._wrapper import HashiCorpVaultTransitKeyWrapper
from hkdfguard.securefile import KeyFileTrust

__all__ = [
    "HashiCorpVaultTransitKeyWrapper",
    "HashiCorpVaultTransitKeyWrapperOptions",
    "KeyFileTrust",
    "StaticVaultTokenSource",
    "VaultRequestError",
    "VaultTokenSource",
]
