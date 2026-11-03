"""Which KV secrets engine a HashiCorpVaultSecretCache reads, and how it connects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from hkdfguard.integration.hashicorpvault import VaultConnectionOptions


class VaultKvVersion(Enum):
    """The version of a KV secrets engine, which decides its read path and response shape."""

    V1 = 1
    """KV version 1: one unversioned value per path, read at ``{mount}/{path}``."""

    V2 = 2
    """KV version 2: versioned secrets, read at ``{mount}/data/{path}``; the latest version is read."""


@dataclass(frozen=True, slots=True, kw_only=True)
class HashiCorpVaultSecretCacheOptions(VaultConnectionOptions):
    """Which KV secrets engine a :class:`HashiCorpVaultSecretCache` reads, and how it connects:
    :class:`VaultConnectionOptions`, with the engine at ``secret`` by default, plus its version and
    the key read from a secret looked up without one. Immutable; change some values with
    :func:`dataclasses.replace`. The values are checked by the cache's constructor, not here."""

    mount_path: str = "secret"
    """Where the KV secrets engine is mounted, e.g. ``"secret"`` (the default) or ``"kv/team-a"``."""

    kv_version: VaultKvVersion = VaultKvVersion.V2
    """The engine's version."""

    default_key: str = "value"
    """The key read from a secret looked up without one: ``"myapp/db"`` reads this key of the secret
    at myapp/db, while ``"myapp/db#password"`` reads its password key."""
