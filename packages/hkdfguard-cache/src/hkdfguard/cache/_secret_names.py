"""The rules for a key within a secret's name ("app-config#api-key"), and the case-escaped spelling
names and keys are stored under."""

from __future__ import annotations

from typing import Final

KEY_SEPARATOR: Final = "#"
"""Separates a secret's name from a key it holds: ``"app-config#api-key"``."""

MAX_KEY_LENGTH: Final = 256
"""The longest key a name can hold."""

UPPER_CASE_MARKER: Final = "!"

_ESCAPE = str.maketrans({chr(c): UPPER_CASE_MARKER + chr(c + 32) for c in range(ord("A"), ord("Z") + 1)})


def is_valid_key(key: str | None) -> bool:
    """Whether ``key`` can follow :data:`KEY_SEPARATOR` in a name: 1-:data:`MAX_KEY_LENGTH`
    printable ASCII characters other than space, ``!`` and ``#``."""
    if not key or len(key) > MAX_KEY_LENGTH:
        return False
    return all(" " < c <= "~" and c not in (UPPER_CASE_MARKER, KEY_SEPARATOR) for c in key)


def entry_name(secret_name: str) -> str:
    """The case-escaped spelling of a name or key: each upper-case ASCII letter becomes ``!`` and its
    lower-case form, so the result holds no upper-case letters and matching it ignoring ASCII case
    is matching it exactly. ``"prod/Db"`` is ``"prod/!db"``; ``"prod/db"`` stays as it is."""
    return secret_name.translate(_ESCAPE)


def secret_name(escaped: str) -> str:
    """The name :func:`entry_name` made ``escaped`` from."""
    parts = escaped.split(UPPER_CASE_MARKER)
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])
