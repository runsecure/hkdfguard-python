"""The exceptions hkdfguard.cache raises beyond the built-in ones."""


class InvalidSecretDataError(ValueError):
    """A secret, or a secret store's response holding one, can't be trusted as it was read: a body
    that isn't the JSON expected, is too large, or holds more than one value, or a secret's JSON
    object naming a key twice - .NET's ``InvalidDataException`` and Java's
    ``InvalidSecretDataException`` for secrets. Its message says where, never what: no part of a
    secret is ever quoted, nor is any exception chained (``__cause__`` or ``__context__``) that
    could. A ``ValueError``, since it is the data that is wrong, so it passes through a fetch
    unchanged like any other failure."""
