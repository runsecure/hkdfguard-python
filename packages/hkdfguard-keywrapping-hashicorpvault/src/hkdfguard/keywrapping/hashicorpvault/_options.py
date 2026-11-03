"""Which transit secrets engine a HashiCorpVaultTransitKeyWrapper calls, and how it connects."""

from __future__ import annotations

from dataclasses import dataclass

from hkdfguard.integration.hashicorpvault import VaultConnectionOptions


@dataclass(frozen=True, slots=True, kw_only=True)
class HashiCorpVaultTransitKeyWrapperOptions(VaultConnectionOptions):
    """Which transit secrets engine a :class:`HashiCorpVaultTransitKeyWrapper` calls, and how it
    connects: :class:`VaultConnectionOptions`, with the engine at ``transit`` by default. Every
    transit call the wrapper makes is safe to repeat, so each is retried as
    :attr:`~VaultConnectionOptions.retry_count` says; 400 for a ciphertext that doesn't authenticate
    isn't retried. Immutable; change some values with :func:`dataclasses.replace`. The values are
    checked by the wrapper's constructor, not here."""

    mount_path: str = "transit"
    """Where the transit secrets engine is mounted, e.g. ``"transit"`` (the default) or
    ``"transit/team-a"``."""
