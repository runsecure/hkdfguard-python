"""Reads a wrapped-key file only from where no untrusted account could have written or replaced it -
the native library's ``hkdfguard_open_file`` checks, made in Python - for a key wrapper with no native
library to read through. :class:`TrustedKeyFile` reads; :class:`KeyFileTrust` says who, besides the
operating system's administrators, may have written the file."""

from hkdfguard.securefile._trust import KeyFileTrust
from hkdfguard.securefile._trusted_key_file import TrustedKeyFile

__all__ = ["KeyFileTrust", "TrustedKeyFile"]
