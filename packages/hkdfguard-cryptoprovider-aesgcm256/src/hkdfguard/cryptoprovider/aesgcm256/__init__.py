"""An AES-256-GCM crypto provider: revealed keys are refreshed in the background, every key's
encryption count is capped below the NIST random-nonce limit, and key access fails closed when
the KEK goes away."""

from hkdfguard.cryptoprovider.aesgcm256._pipeline import AesGcmPipelineDataProtector
from hkdfguard.cryptoprovider.aesgcm256._provider import AesGcmCryptoProvider, AesGcmCryptoProviderFactory
from hkdfguard.cryptoprovider.aesgcm256._session import AesGcmCryptoSession, EncryptionBudget

__all__ = [
    "AesGcmCryptoProvider",
    "AesGcmCryptoProviderFactory",
    "AesGcmCryptoSession",
    "AesGcmPipelineDataProtector",
    "EncryptionBudget",
]
