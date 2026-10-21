"""Builds a key ring from wrapped key files and ephemeral keys."""

from __future__ import annotations

import logging
import os
from datetime import timedelta
from typing import Final, Self

from hkdfguard import abstractions
from hkdfguard.abstractions import (
    CryptoProvider,
    CryptoProviderFactory,
    EncryptedFormatProvider,
    KeyVersions,
    KeyWrapper,
    RefreshFailurePolicy,
    ServiceNames,
)
from hkdfguard.dataencryptionkey._format import DefaultFormatProvider
from hkdfguard.dataencryptionkey._ring import DataEncryptionKey, KeyRing

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.dataencryptionkey")


class KeyRingBuilder:
    """Builds a :class:`KeyRing` from wrapped-DEK files and/or ephemeral keys. One :class:`KeyWrapper`
    serves every key - it's bound to a KEK, not to a payload. For each key file, build asks the
    :class:`CryptoProviderFactory` for a provider over that file's wrapped bytes; for each ephemeral
    version, for one around a fresh DEK. Every provider is wrapped in a :class:`DataEncryptionKey`
    owned by the ring.

    Key files are rotated by deployment: each release brings its own. Ephemeral keys are rotated
    here: a ring with any ephemeral key adds a fresh one as its current version every
    :attr:`ephemeral_key_rotation_interval` (24 hours unless configured otherwise). Each rotation
    lands above whatever is current, so while rotation is on, build refuses a key file registered
    above every ephemeral version: the first rotation would replace it as the current version.
    """

    DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL: Final = timedelta(hours=24)
    MIN_EPHEMERAL_KEY_ROTATION_INTERVAL: Final = timedelta(hours=1)
    """Rotating faster than this buys no security and only loads the KMS."""
    MAX_EPHEMERAL_KEY_ROTATION_INTERVAL: Final = timedelta(milliseconds=0xFFFFFFFF - 1)
    """About 49.7 days, as on every port."""
    DEFAULT_EPHEMERAL_KEY_RETENTION: Final = timedelta(hours=24)
    MIN_EPHEMERAL_KEY_RETENTION: Final = timedelta(minutes=1)
    DEFAULT_MAX_REFRESH_FAILURES: Final = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES

    def __init__(self) -> None:
        self._key_files: dict[int, str] = {}
        self._ephemeral_versions: list[int] = []
        self._key_wrapper: KeyWrapper | None = None
        self._factory: CryptoProviderFactory | None = None
        self._format_provider: EncryptedFormatProvider = DefaultFormatProvider()
        self._verify_key_file_permissions = True
        self._logger: logging.Logger | None = None
        self.service_name: str | None = None
        """The service name identifying this ring's KEK, if one was given."""
        self.key_refresh_interval: int | None = None
        """Seconds between re-reveals of each key through the KEK; ``None`` until set."""
        self.max_refresh_failures: int | None = self.DEFAULT_MAX_REFRESH_FAILURES
        """Consecutive failed refreshes tolerated before failing closed; ``None`` only after fail-open."""
        self.ephemeral_key_rotation_interval: timedelta | None = self.DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL
        """How often a ring with ephemeral keys adds a fresh one; ``None`` only after turning rotation off."""
        self.ephemeral_key_retention: timedelta = self.DEFAULT_EPHEMERAL_KEY_RETENTION
        """How long a superseded ephemeral key stays registered for decryption."""

    def with_ephemeral_key_rotation(self, interval: timedelta) -> Self:
        """:raises ValueError: ``interval`` is outside the minimum to maximum range"""
        if not self.MIN_EPHEMERAL_KEY_ROTATION_INTERVAL <= interval <= self.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL:
            raise ValueError(f"The ephemeral key rotation interval must be between {self.MIN_EPHEMERAL_KEY_ROTATION_INTERVAL} and "
                             f"{self.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL}; it is {interval}.")
        self.ephemeral_key_rotation_interval = interval
        return self

    def without_ephemeral_key_rotation(self) -> Self:
        """The startup ephemeral key stays current until the process restarts. Also lets a key file be
        registered above every ephemeral version, which build otherwise refuses."""
        self.ephemeral_key_rotation_interval = None
        return self

    def _with_ephemeral_key_rotation_for_testing(self, interval: timedelta) -> Self:
        self.ephemeral_key_rotation_interval = interval
        return self

    def with_ephemeral_key_retention(self, retention: timedelta) -> Self:
        """:raises ValueError: ``retention`` is below the one-minute minimum"""
        if retention < self.MIN_EPHEMERAL_KEY_RETENTION:
            raise ValueError(f"The ephemeral key retention must be at least {self.MIN_EPHEMERAL_KEY_RETENTION}; it is {retention}.")
        self.ephemeral_key_retention = retention
        return self

    def _with_ephemeral_key_retention_for_testing(self, retention: timedelta) -> Self:
        self.ephemeral_key_retention = retention
        return self

    def with_logger(self, logger: logging.Logger | None) -> Self:
        """Receives an info entry per rotation and retirement and an error per failed one; ``None`` for
        the ``hkdfguard.dataencryptionkey`` logger."""
        self._logger = logger
        return self

    def with_service_name(self, service_name: str) -> Self:
        """:raises TypeError: ``service_name`` is ``None``
        :raises ValueError: ``service_name`` breaks a ServiceNames rule"""
        ServiceNames.require_valid(service_name, "service_name")
        self.service_name = service_name
        return self

    def with_key_refresh_interval(self, key_refresh_interval: int) -> Self:
        """Seconds between re-reveals of each key through the KEK, 1-300 - a revocation check, not a
        limit on how long the DEK is in memory.

        :raises ValueError: not between 1 and 300
        """
        if not 1 <= key_refresh_interval <= 300:
            raise ValueError(f"key_refresh_interval must be between 1 and 300 seconds; it is {key_refresh_interval}.")
        self.key_refresh_interval = key_refresh_interval
        return self

    def with_max_refresh_failures(self, max_refresh_failures: int) -> Self:
        """:raises ValueError: below 1"""
        if max_refresh_failures < 1:
            raise ValueError(f"max_refresh_failures must be at least 1; it is {max_refresh_failures}.")
        self.max_refresh_failures = max_refresh_failures
        return self

    def with_fail_open_on_refresh_failure(self) -> Self:
        """Keeps serving on the last good key however many refreshes fail, so losing the KEK never
        stops a running process. Keep the provider's error log visible: it's the only sign."""
        self.max_refresh_failures = None
        return self

    def with_key_wrapper(self, key_wrapper: KeyWrapper) -> Self:
        self._key_wrapper = key_wrapper
        return self

    def with_crypto_provider_factory(self, factory: CryptoProviderFactory) -> Self:
        """e.g. ``AesGcmCryptoProviderFactory()``."""
        self._factory = factory
        return self

    def with_format_provider(self, format_provider: EncryptedFormatProvider) -> Self:
        if format_provider is None:
            raise TypeError("format_provider must not be None.")
        self._format_provider = format_provider
        return self

    def with_key_file(self, version: int, path: str | os.PathLike[str]) -> Self:
        """Registers a version whose wrapped DEK is read from ``path`` at build.

        :raises ValueError: ``version`` is outside the signed 32-bit range, or a key file is already
            registered for it
        """
        KeyVersions.require_valid(version)
        if version in self._key_files:
            raise ValueError(f"A key file is already registered for version {version}.")
        self._key_files[version] = os.fspath(path)
        return self

    def without_key_file_permission_checks(self) -> Self:
        """Reads key files without checking who owns them and who can write them. Key files are read
        through the key wrapper (:meth:`KeyWrapper.read_key_file`), and this only reaches a wrapper
        that reads with ordinary file I/O (the default, :meth:`WrappedKeyFile.read`): there, on a POSIX
        system, a key file and every directory above its real path must be owned by root or the
        current user and writable by no one else (a sticky directory such as /tmp excepted), since
        whoever can replace the file chooses the DEK the process encrypts under; Windows is not checked
        that way. Turn this off only where permissions are enforced some other way. The native key
        wrapper reads through the native library's own checks, which can't be turned off."""
        self._verify_key_file_permissions = False
        return self

    def with_ephemeral_key(self, version: int) -> Self:
        """Registers a version whose DEK is generated at build time and never written to disk.

        :raises ValueError: ``version`` is outside the signed 32-bit range
        """
        KeyVersions.require_valid(version)
        self._ephemeral_versions.append(version)
        return self

    def build(self) -> KeyRing:
        """Reads every key file, creates every ephemeral key, and returns a populated ring. If anything
        fails partway, every provider created so far is closed.

        Every key file is read through the key wrapper (:meth:`KeyWrapper.read_key_file`), so a native
        KMS reads its own key files, with its own checks on who could have written them.

        :raises RuntimeError: no key wrapper, factory, key refresh interval, or keys were configured,
            or rotation is on and a key file is registered above every ephemeral version
        :raises FileNotFoundError: a key file, or a folder in its path, does not exist
        :raises PermissionError: a key file may not be read, or it or a directory above it fails the
            key wrapper's permission check
        :raises InvalidKeyFileError: a key file is not a wrapped key - empty, larger than
            WrappedKeyLimits.MAX_BYTES, or (read natively) the wrong size, a plaintext key, or malformed
        :raises OSError: a key file can't be read for another reason
        """
        if self._key_wrapper is None:
            raise RuntimeError("A key wrapper is required - call with_key_wrapper first.")
        if self._factory is None:
            raise RuntimeError("A crypto provider factory is required - call with_crypto_provider_factory first.")
        if not self._key_files and not self._ephemeral_versions:
            raise RuntimeError("At least one key file or ephemeral key is required - call with_key_file or with_ephemeral_key first.")
        if self.key_refresh_interval is None:
            raise RuntimeError("A key refresh interval is required - call with_key_refresh_interval first.")
        if self._key_files and self._ephemeral_versions and self.ephemeral_key_rotation_interval is not None:
            # Rotation adds each key at the current version + 1, so the first one would supersede a key
            # file above every ephemeral version, and everything encrypted after it would be lost on restart.
            highest_key_file = max(self._key_files)
            if highest_key_file > max(self._ephemeral_versions):
                raise RuntimeError(f"Key file version {highest_key_file} is above every ephemeral version, so the first scheduled rotation "
                                   "would supersede it as the current version and new values would be encrypted under a key that does not "
                                   "survive a restart. Register the ephemeral key at a version above every key file, or call "
                                   "without_ephemeral_key_rotation().")

        wrapper, factory, interval, failures = self._key_wrapper, self._factory, self.key_refresh_interval, self.max_refresh_failures
        ring = KeyRing(self._format_provider)
        try:
            for version in sorted(self._key_files):
                # Read through the key wrapper: a native KMS reads its own key files, with its own
                # checks on who could have written them.
                wrapped = wrapper.read_key_file(self._key_files[version], verify_permissions=self._verify_key_file_permissions,
                                                logger=self._logger or _DEFAULT_LOGGER)
                provider = factory.create(wrapper, wrapped, interval, failures)
                _add_owned(ring, version, provider)

            for version in self._ephemeral_versions:
                _add_owned(ring, version, factory.create_ephemeral(wrapper, interval, failures))

            if self._ephemeral_versions and self.ephemeral_key_rotation_interval is not None:
                # Each rotation creates its key exactly as an ephemeral version above was created.
                ring._configure_ephemeral_key_retention(self.ephemeral_key_retention, list(self._ephemeral_versions))
                ring._start_ephemeral_key_rotation(
                    self.ephemeral_key_rotation_interval,
                    lambda: DataEncryptionKey(factory.create_ephemeral(wrapper, interval, failures)),
                    self._logger if self._logger is not None else _DEFAULT_LOGGER)
            return ring
        except BaseException:
            ring.close()
            raise


def _add_owned(ring: KeyRing, version: int, provider: CryptoProvider) -> None:
    key: abstractions.DataEncryptionKey = DataEncryptionKey(provider)
    try:
        ring.add(version, key)
    except BaseException:
        provider.close()
        raise
