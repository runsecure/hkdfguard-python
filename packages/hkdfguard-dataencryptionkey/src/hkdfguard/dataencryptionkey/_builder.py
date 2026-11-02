"""Builds a key ring from wrapped key files and ephemeral keys."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Final, Self

from hkdfguard import abstractions
from hkdfguard.abstractions import (
    CryptoProvider,
    CryptoProviderFactory,
    EncryptedFormatProvider,
    InvalidKeyFileError,
    KeyVersions,
    KeyWrapper,
    RefreshFailurePolicy,
    ServiceNames,
    WrappedKeyLimits,
)
from hkdfguard.dataencryptionkey._format import DefaultFormatProvider
from hkdfguard.dataencryptionkey._ring import DataEncryptionKey, EncryptionDeadline, KeyRing
from hkdfguard.diagnostics import HkdfGuardLog

_DEFAULT_LOGGER: Final = logging.getLogger("hkdfguard.dataencryptionkey")
_DAY_SECONDS: Final = 24 * 60 * 60


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

    A key file also stops encrypting :attr:`key_file_max_age_days` after it was last written (365
    days unless configured otherwise); see :meth:`with_key_file_max_age_days`.
    """

    DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL: Final = timedelta(hours=24)
    MIN_EPHEMERAL_KEY_ROTATION_INTERVAL: Final = timedelta(hours=1)
    """Rotating faster than this buys no security and only loads the KMS."""
    MAX_EPHEMERAL_KEY_ROTATION_INTERVAL: Final = timedelta(milliseconds=0xFFFFFFFF - 1)
    """About 49.7 days, as on every port."""
    DEFAULT_EPHEMERAL_KEY_RETENTION: Final = timedelta(hours=24)
    MIN_EPHEMERAL_KEY_RETENTION: Final = timedelta(minutes=1)
    DEFAULT_MAX_REFRESH_FAILURES: Final = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES
    DEFAULT_KEY_FILE_MAX_AGE_DAYS: Final = 365
    """How many days after it was last written a key file stops encrypting, unless configured otherwise.
    AES-GCM with random nonces is safe for about 2^32 encryptions under one key in total, and a key
    file outlives the process that counts them, so it is bounded by age instead: rotate key files by
    deploying a new one at a higher version. Decryption under an old key file never stops."""
    MIN_KEY_FILE_MAX_AGE_DAYS: Final = 1
    MAX_KEY_FILE_MAX_AGE_DAYS: Final = 3650
    """The longest key-file age accepted, in days."""
    KEY_FILE_AGE_WARNING_FRACTION: Final = 0.9
    """The fraction of the maximum age after which a warning is logged: 90%, about five weeks of a year."""

    def __init__(self) -> None:
        self._key_files: dict[int, str] = {}
        self._ephemeral_versions: list[int] = []
        self._key_wrapper: KeyWrapper | None = None
        self._factory: CryptoProviderFactory | None = None
        self._format_provider: EncryptedFormatProvider = DefaultFormatProvider()
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
        self.key_file_max_age_days: int = self.DEFAULT_KEY_FILE_MAX_AGE_DAYS
        """Days after a key file was last written that it stops encrypting."""

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

    def with_key_file_max_age_days(self, days: int) -> Self:
        """Days (1-3650) after a key file was last written that it stops encrypting; 365 unless set.
        Its age is its modification time, so copy key files with their timestamps preserved (``cp -p``,
        ``rsync -t``); a plain copy resets the clock. A warning is logged at 90% of the age; past it,
        encrypt raises :class:`~hkdfguard.abstractions.EncryptionLimitReachedError`, and decryption
        still works. Only the current version ever encrypts, so only it is reported.

        :raises ValueError: not a whole number of days between 1 and 3650
        """
        low, high = self.MIN_KEY_FILE_MAX_AGE_DAYS, self.MAX_KEY_FILE_MAX_AGE_DAYS
        if isinstance(days, bool) or not isinstance(days, int) or not low <= days <= high:
            raise ValueError(f"key_file_max_age_days must be between {low} and {high}; it is {days}.")
        self.key_file_max_age_days = days
        return self

    def with_logger(self, logger: logging.Logger | None) -> Self:
        """Receives an info entry per rotation and retirement and an error per failed one, and a
        warning or critical entry for a current key file nearing or past its maximum age; ``None`` for
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

        It is also each refresh's deadline: a reveal that takes longer than one interval counts as a
        failed refresh, so a hung key wrapper can't keep a revoked KEK's key in use. A short interval
        is therefore a short deadline. A TPM-backed KEK can take more than a second to answer, longer
        while other processes share the TPM, and a locked macOS keychain stalls the call; under the
        default fail-closed policy, that many slow answers in a row suspend the key though the KEK is
        healthy. Keep it at 10 seconds or more for TPM-backed keys.

        :raises ValueError: not between 1 and 300
        """
        if not 1 <= key_refresh_interval <= 300:
            raise ValueError(f"key_refresh_interval must be between 1 and 300 seconds; it is {key_refresh_interval}.")
        self.key_refresh_interval = key_refresh_interval
        return self

    def with_max_refresh_failures(self, max_refresh_failures: int) -> Self:
        """:raises ValueError: not between 1 and :attr:`RefreshFailurePolicy.MAX_ALLOWED_REFRESH_FAILURES` (100)"""
        limit = RefreshFailurePolicy.MAX_ALLOWED_REFRESH_FAILURES
        if not 1 <= max_refresh_failures <= limit:
            raise ValueError(f"max_refresh_failures must be between 1 and {limit}; it is {max_refresh_failures}.")
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

        Each key file's modification time, taken right after it is read, starts its age (see
        :meth:`with_key_file_max_age_days`). The current version is checked once the ring is built, so
        a current key file already nearing or past its age is logged now, not at its first encrypt.

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
        logger = self._logger if self._logger is not None else _DEFAULT_LOGGER
        ring = KeyRing(self._format_provider)
        try:
            for version in sorted(self._key_files):
                # Read through the key wrapper: a native KMS reads its own key files, with its own
                # checks on who could have written them.
                path = self._key_files[version]
                wrapped = wrapper.read_key_file(path)
                modified = os.stat(path).st_mtime  # the key file's age starts here
                # Whatever the key wrapper, a wrapped key is never empty and never over the limit.
                if not wrapped:
                    raise InvalidKeyFileError(f"Key file '{path}' is empty.")
                if len(wrapped) > WrappedKeyLimits.MAX_BYTES:
                    raise InvalidKeyFileError(f"Key file '{path}' is larger than {WrappedKeyLimits.MAX_BYTES} bytes "
                                              "(WrappedKeyLimits.MAX_BYTES); a wrapped key never is.")
                provider = factory.create(wrapper, wrapped, interval, failures)
                _add_owned(ring, version, provider, _key_file_deadline(version, path, modified, self.key_file_max_age_days, logger))

            for version in self._ephemeral_versions:
                _add_owned(ring, version, factory.create_ephemeral(wrapper, interval, failures))

            _report_current_key_file_age(ring)

            if self._ephemeral_versions and self.ephemeral_key_rotation_interval is not None:
                # Each rotation creates its key exactly as an ephemeral version above was created.
                ring._configure_ephemeral_key_retention(self.ephemeral_key_retention, list(self._ephemeral_versions))
                ring._start_ephemeral_key_rotation(
                    self.ephemeral_key_rotation_interval,
                    lambda: DataEncryptionKey(factory.create_ephemeral(wrapper, interval, failures)),
                    logger)
            return ring
        except BaseException:
            ring.close()
            raise


def _add_owned(ring: KeyRing, version: int, provider: CryptoProvider, deadline: EncryptionDeadline | None = None) -> None:
    key: abstractions.DataEncryptionKey = DataEncryptionKey(provider, deadline)
    try:
        ring.add(version, key)
    except BaseException:
        provider.close()
        raise


def _report_current_key_file_age(ring: KeyRing) -> None:
    """Reports a current key file already nearing or past its age now, not at its first encrypt. A
    superseded key file never encrypts, so it is never reported; an ephemeral key has no deadline."""
    current = ring.find(ring.current_version)
    if isinstance(current, DataEncryptionKey):
        current.check_deadline()


def _key_file_deadline(version: int, path: str, modified: float, max_age_days: int, logger: logging.Logger) -> EncryptionDeadline:
    """When the key file at ``path``, last written at ``modified`` (seconds since the epoch), stops
    encrypting, and who hears about it."""
    refuse_at = modified + max_age_days * _DAY_SECONDS
    written = datetime.fromtimestamp(modified, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return EncryptionDeadline(
        warn_at=modified + max_age_days * _DAY_SECONDS * KeyRingBuilder.KEY_FILE_AGE_WARNING_FRACTION,
        refuse_at=refuse_at,
        reason=f"Key file '{path}' (version {version}) was last written {written}, more than {max_age_days} days ago (key_file_max_age_days), "
               "so it no longer encrypts: AES-GCM is only safe for a bounded number of encryptions under one key. Deploy a new key file at a "
               "higher version; values under this one still decrypt.",
        on_warning=lambda: HkdfGuardLog.key_file_age_warning(logger, version, path, datetime.fromtimestamp(refuse_at, UTC)),
        on_expired=lambda: HkdfGuardLog.key_file_expired(logger, version, path),
    )
