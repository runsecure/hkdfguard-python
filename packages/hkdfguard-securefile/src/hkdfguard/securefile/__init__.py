"""Reads a wrapped-key file, or any other file that must not have been planted, only from where no
untrusted account could have written or replaced it - the native library's ``hkdfguard_open_file``
checks, made in Python - for a key wrapper with no native library to read through.
:class:`TrustedKeyFile` reads a key file and holds its contents to a key file's rules;
:class:`TrustedFile` reads any file, of a size the caller bounds, by the same location rules;
:class:`KeyFileTrust` says who, besides the operating system's administrators, may have written it."""

from hkdfguard.securefile._trust import KeyFileTrust
from hkdfguard.securefile._trusted_file import FileTooLargeError, TrustedFile
from hkdfguard.securefile._trusted_key_file import TrustedKeyFile

__all__ = ["FileTooLargeError", "KeyFileTrust", "TrustedFile", "TrustedKeyFile"]
