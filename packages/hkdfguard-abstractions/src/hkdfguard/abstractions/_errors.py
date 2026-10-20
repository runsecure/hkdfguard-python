"""The exceptions every HkdfGuard component raises beyond the built-in ones."""


class CryptographicError(Exception):
    """A cryptographic operation failed: a key wrapper could not reveal a key, a key is suspended or
    over its encryption limit, or a native KMS call returned an error."""


class AuthenticationTagMismatchError(CryptographicError):
    """AEAD decryption failed authentication: the ciphertext was altered, was encrypted under another
    key, or is being decrypted with different Additional Authenticated Data than it was encrypted
    with (e.g. under another name or configuration key). No plaintext is ever returned."""

    def __init__(self, message: str = "The computed authentication tag did not match the input authentication tag.") -> None:
        super().__init__(message)


class EncryptedFormatError(ValueError):
    """A formatted encrypted value is malformed - raised by EncryptedFormatProvider implementations."""


class InvalidKeyFileError(OSError):
    """A key file was read, but does not hold a wrapped key: it is empty, too short or too long, holds
    what looks like an unwrapped key, or is the right size but not a valid wrapped payload - .NET's
    ``InvalidDataException`` from ``ReadKeyFileAsync``. An ``OSError``, so code that handles every way
    a key file can fail to load still catches it."""


class ObjectClosedError(RuntimeError):
    """The object has been closed; it can't be used any more."""


class KeyNotFoundError(LookupError):
    """No key is registered for the requested key ring version."""
