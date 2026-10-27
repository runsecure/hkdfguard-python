"""Key Vault key identifiers, parsed strictly."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Final
from urllib.parse import urlsplit

# Key Vault's own rules: names are 1-127 letters, digits and dashes; versions are 32 hex digits in Key
# Vault and Managed HSM alike, but only their characters are checked here: a version recorded in a
# wrapped DEK must be exactly 32 (see _envelope).
_NAME: Final = re.compile(r"[0-9A-Za-z-]{1,127}")
_VERSION: Final = re.compile(r"[0-9A-Za-z]{1,64}")
# A DNS host name: Key Vault is never reached by an IP literal.
_HOST: Final = re.compile(r"[0-9A-Za-z](?:[0-9A-Za-z.-]*[0-9A-Za-z])?")
# Printable ASCII, no space: urlsplit would otherwise quietly strip surrounding whitespace and drop
# tabs and newlines, accepting what the other ports refuse.
_PRINTABLE: Final = re.compile(r"[\x21-\x7e]+")


@dataclass(frozen=True)
class KeyVaultKeyId:
    """A Key Vault key identifier, ``https://{vault}/keys/{name}[/{version}]``, parsed strictly: the
    SDK's own ``parse_key_vault_id`` accepts any two- or three-segment path (a secret's, say), and
    this one decides which keys a wrapper is pinned to."""

    vault: str
    """The vault's URL - scheme, host and any port - without a trailing slash; the host in lower case."""
    name: str
    """The key's name."""
    version: str | None
    """The key's version, or ``None`` for its current one."""

    @staticmethod
    def parse(key_id: str) -> KeyVaultKeyId:
        """Parses a key identifier.

        :raises ValueError: it isn't a Key Vault key's
        """
        if not isinstance(key_id, str) or not _PRINTABLE.fullmatch(key_id) or "?" in key_id or "#" in key_id:
            raise _invalid(key_id)
        try:
            parts = urlsplit(key_id)
            port = parts.port
        except ValueError as error:
            raise _invalid(key_id) from error
        host = parts.hostname
        if parts.scheme.lower() != "https" or host is None or not _HOST.fullmatch(host) or "@" in parts.netloc:
            raise _invalid(key_id)

        segments = parts.path.removesuffix("/").split("/")
        if (len(segments) not in (3, 4) or segments[0] != "" or segments[1] != "keys" or not _NAME.fullmatch(segments[2])
                or (len(segments) == 4 and not _VERSION.fullmatch(segments[3]))):
            raise _invalid(key_id)

        vault = f"https://{host}" + ("" if port is None else f":{port}")
        return KeyVaultKeyId(vault, segments[2], segments[3] if len(segments) == 4 else None)

    def with_version(self, version: str) -> KeyVaultKeyId:
        """The same key, at ``version``."""
        return replace(self, version=version)

    def same_key(self, other: KeyVaultKeyId) -> bool:
        """Whether ``other`` names the same key, in any version: Key Vault's host and key names ignore case."""
        return self.vault == other.vault and self.name.lower() == other.name.lower()

    def __str__(self) -> str:
        """The identifier, as the Key Vault clients are given it."""
        return f"{self.vault}/keys/{self.name}" + ("" if self.version is None else f"/{self.version}")


def _invalid(key_id: object) -> ValueError:
    return ValueError(f"{key_id!r} isn't a Key Vault key identifier: https://{{vault}}.vault.azure.net/keys/{{name}}, optionally followed by "
                      "/{version}.")
