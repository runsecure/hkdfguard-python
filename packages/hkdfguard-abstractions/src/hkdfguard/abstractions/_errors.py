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


class ObjectClosedError(RuntimeError):
    """The object has been closed; it can't be used any more."""


class KeyNotFoundError(LookupError):
    """No key is registered for the requested key ring version."""
