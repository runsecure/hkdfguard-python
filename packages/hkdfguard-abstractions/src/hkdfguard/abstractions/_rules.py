"""The rules every HkdfGuard port implements identically."""

from __future__ import annotations

from typing import Final

from hkdfguard.abstractions._buffers import Utf8

_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def ascii_upper(text: str) -> str:
    """``text`` with only the ASCII letters a-z upper-cased - every other character unchanged."""
    return text.translate(_ASCII_UPPER)


class RefreshFailurePolicy:
    """The refresh-failure policy's shared default: after this many consecutive failed attempts to
    re-reveal a key, a provider fails closed - zeroes the key and refuses every operation until a
    refresh succeeds - so revoking the KEK reaches a running process. ``None`` opts into failing open."""

    DEFAULT_MAX_REFRESH_FAILURES: Final = 3


class WrappedKeyLimits:
    """Size limits for a wrapped DEK - the bytes a key file holds and a key wrapper produces."""

    MAX_BYTES: Final = 512


class ServiceNames:
    """The rule for a service name - the identity of a KEK in the native KMS library: 1 to
    :attr:`MAX_LENGTH` characters, each an ASCII letter, digit or '.', not starting with '.' and
    never containing "..". Typically reverse-DNS, e.g. ``"com.example.orders"``. Enforced before any
    native call, so a bad name fails with a clear message and never crosses the boundary."""

    MAX_LENGTH: Final = 128

    @staticmethod
    def is_valid(name: str | None) -> bool:
        return ServiceNames.get_problem(name) is None

    @staticmethod
    def get_problem(name: str | None) -> str | None:
        """Why ``name`` is not a valid service name, or ``None`` if it is."""
        if not name:
            return "A service name is required."

        if len(name) > ServiceNames.MAX_LENGTH:
            return f"A service name is at most {ServiceNames.MAX_LENGTH} characters; this one is {len(name)}."

        if name[0] == ".":
            return "A service name can't start with '.'."

        for i, c in enumerate(name):
            if c == ".":
                if i > 0 and name[i - 1] == ".":
                    return "A service name can't contain '..'."
            elif not (c.isascii() and c.isalnum()):
                return f"A service name may contain only ASCII letters, digits and '.'; it has U+{ord(c):04X} at position {i}."

        return None

    @staticmethod
    def require_valid(name: str | None, param_name: str) -> None:
        """:raises TypeError: ``name`` is ``None``
        :raises ValueError: ``name`` breaks a rule; the message says which"""
        if name is None:
            raise TypeError(f"{param_name} must not be None.")

        problem = ServiceNames.get_problem(name)
        if problem is not None:
            raise ValueError(f"{param_name}: {problem}")


class ProtectedConfigurationPurpose:
    """The single rule binding an encrypted configuration value to the configuration key it's stored
    under. Whoever writes a value (e.g. a pipeline) and whoever reads it must derive the same
    purpose, so a value copied to a different key fails authentication.

    The rule, identical in every port: the purpose is ``"HkdfGuard.EncryptedConfiguration:" + key``
    with the ASCII letters a-z upper-cased and every other character left as it is; the AAD is the
    purpose's UTF-8 bytes. A key holding an unpaired surrogate is rejected. Keys differing only in
    ASCII case share a purpose; keys differing any other way - including non-ASCII case, such as
    "café" and "CAFÉ" - never do.
    """

    PREFIX: Final = "HkdfGuard.EncryptedConfiguration"

    @staticmethod
    def for_key(configuration_key: str) -> str:
        """The purpose name for a configuration key - pass to a key ring's create_protector.

        :raises TypeError: ``configuration_key`` is ``None``
        :raises ValueError: ``configuration_key`` is empty or not valid UTF-16
        """
        ProtectedConfigurationPurpose._require_key(configuration_key)
        Utf8.require_well_formed(configuration_key)
        return f"{ProtectedConfigurationPurpose.PREFIX}:{ascii_upper(configuration_key)}"

    @staticmethod
    def aad_for(configuration_key: str) -> bytes:
        """The purpose's UTF-8 bytes - the AAD a value stored under ``configuration_key`` is encrypted with.

        :raises TypeError: ``configuration_key`` is ``None``
        :raises ValueError: ``configuration_key`` is empty or not valid UTF-16
        """
        ProtectedConfigurationPurpose._require_key(configuration_key)
        return bytes(Utf8.encode_strict(f"{ProtectedConfigurationPurpose.PREFIX}:{ascii_upper(configuration_key)}"))

    @staticmethod
    def _require_key(configuration_key: str) -> None:
        if configuration_key is None:
            raise TypeError("configuration_key must not be None.")
        if not configuration_key:
            raise ValueError("The configuration key must not be empty.")
