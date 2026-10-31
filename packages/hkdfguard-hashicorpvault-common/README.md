# hkdfguard-hashicorpvault-common

What every HkdfGuard integration with HashiCorp Vault shares: the address, path and token checks, the retry limits and backoff, and the error Vault's refusals are reported as.

This is one distribution of [HkdfGuard for Python](https://github.com/runsecure/hkdfguard-python), the
Python port of hkdfguard-dotnet and hkdfguard-java. Every distribution installs one subpackage of the
shared `hkdfguard` namespace package.

You don't install this directly: it is a dependency of
[hkdfguard-cache-hashicorpvault](https://pypi.org/project/hkdfguard-cache-hashicorpvault/) and
[hkdfguard-keywrapping-hashicorpvault](https://pypi.org/project/hkdfguard-keywrapping-hashicorpvault/),
so the two refuse the same addresses, paths and tokens and retry the same way. The one name you may
meet is `VaultRequestError`, which both re-export.

An address must be https, except on loopback (a local Vault Agent or dev server), and must not hold
credentials, a query or a fragment. A path is `/`-separated segments of letters, digits, `.`, `_` and
`-`, none `.` or `..`. A request that fails transiently is retried 3-10 times, waiting from the
configured delay and doubling up to 10 seconds, plus a random 0-100 ms.

Requires Python 3.12 or later. Licensed under the Mozilla Public License 2.0.
