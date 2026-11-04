"""Which KV secrets engine a HashiCorpVaultSecretPipelineWriter reads, and how it connects."""

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
class HashiCorpVaultPipelineOptions(VaultConnectionOptions):
    """Which KV secrets engine a :class:`HashiCorpVaultSecretPipelineWriter` reads, and how it
    connects: :class:`~hkdfguard.integration.hashicorpvault.VaultConnectionOptions` - the namespace,
    the timeout of one attempt, the retries of a transient failure, and TLS - with the engine at
    ``secret`` by default, plus its version and the key read from a secret named without one.
    Immutable; change some values with :func:`dataclasses.replace`. The values are checked by the
    writer's constructor, not here.

    For mutual TLS, give :attr:`tls` a PEM certificate and key, or :attr:`ssl_context` a context
    presenting one: a password-protected PKCS#12 key store needs a protector on a key ring, which a
    pipeline doesn't have yet.
    """

    mount_path: str = "secret"
    """Where the KV secrets engine is mounted, e.g. ``"secret"`` (the default) or ``"kv/team-a"``."""

    kv_version: VaultKvVersion = VaultKvVersion.V2
    """The engine's version."""

    default_key: str = "value"
    """The key read from a secret named without one: ``"myapp/db"`` reads this key of the secret at
    myapp/db, while ``"myapp/db#password"`` reads its password key."""
