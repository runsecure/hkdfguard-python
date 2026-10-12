"""The log messages every HkdfGuard component shares, with the same event ids as every port."""

from __future__ import annotations

import logging
from typing import Final


class HkdfGuardLog:
    """Shared log entries. Each carries its event id as the ``hkdfguard_event_id`` attribute of
    the log record (``extra``), so a structured handler can filter on it exactly as on a .NET
    EventId. A ``None`` logger is accepted and ignored.

    :meth:`sensitive_operation_logged` is only worth calling while sensitive logging is enabled;
    failures are always worth logging.
    """

    EVENT_ID_KEY: Final = "hkdfguard_event_id"

    SENSITIVE_OPERATION_LOGGED: Final = 1
    OPERATION_FAILED: Final = 2
    KEY_REFRESH_FAILED: Final = 3
    KEY_ACCESS_SUSPENDED: Final = 4
    KEY_ACCESS_RESUMED: Final = 5
    EPHEMERAL_KEY_ROTATED: Final = 6
    EPHEMERAL_KEY_ROTATION_FAILED: Final = 7
    EPHEMERAL_KEY_RETIRED: Final = 8
    EPHEMERAL_KEY_RETIREMENT_FAILED: Final = 9
    ENCRYPTION_BUDGET_WARNING: Final = 10

    @staticmethod
    def _log(logger: logging.Logger | None, level: int, event_id: int, message: str, *args: object,
             exception: BaseException | None = None) -> None:
        if logger is None or not logger.isEnabledFor(level):
            return
        exc_info = (type(exception), exception, exception.__traceback__) if exception is not None else None
        logger.log(level, message, *args, exc_info=exc_info, extra={HkdfGuardLog.EVENT_ID_KEY: event_id}, stacklevel=3)

    @staticmethod
    def sensitive_operation_logged(logger: logging.Logger | None, operation_name: str, name: str | None) -> None:
        """Debug: an operation completed, named for the value it touched."""
        HkdfGuardLog._log(logger, logging.DEBUG, HkdfGuardLog.SENSITIVE_OPERATION_LOGGED, "%s completed for %s.", operation_name, name)

    @staticmethod
    def operation_failed(logger: logging.Logger | None, operation_name: str, exception: BaseException) -> None:
        """Error: an operation failed."""
        HkdfGuardLog._log(logger, logging.ERROR, HkdfGuardLog.OPERATION_FAILED, "%s failed.", operation_name, exception=exception)

    @staticmethod
    def key_refresh_failed(logger: logging.Logger | None, consecutive_failures: int, refresh_failure_policy: str,
                           exception: BaseException) -> None:
        """Error: a background attempt to re-reveal a key through its key wrapper failed - the KEK
        may have been revoked or become unreachable. Logged on every failure, whatever the policy,
        since under fail-open this is the only sign the KEK is gone."""
        HkdfGuardLog._log(logger, logging.ERROR, HkdfGuardLog.KEY_REFRESH_FAILED,
                          "Background key refresh failed (%d consecutive). Policy: %s.", consecutive_failures, refresh_failure_policy,
                          exception=exception)

    @staticmethod
    def key_access_suspended(logger: logging.Logger | None, consecutive_failures: int) -> None:
        """Critical: the refresh-failure limit was reached; the key has been zeroed and every
        operation under it fails until a refresh succeeds."""
        HkdfGuardLog._log(logger, logging.CRITICAL, HkdfGuardLog.KEY_ACCESS_SUSPENDED,
                          "Key access suspended after %d consecutive failed refreshes; the key has been zeroed and every operation "
                          "under it fails until a refresh succeeds.", consecutive_failures)

    @staticmethod
    def key_access_resumed(logger: logging.Logger | None, consecutive_failures: int) -> None:
        """Info: a refresh succeeded after key access had been suspended; operations resume."""
        HkdfGuardLog._log(logger, logging.INFO, HkdfGuardLog.KEY_ACCESS_RESUMED,
                          "Key access resumed: a background refresh succeeded after %d consecutive failures.", consecutive_failures)

    @staticmethod
    def ephemeral_key_rotated(logger: logging.Logger | None, key_version: int) -> None:
        """Info: a scheduled rotation added a fresh ephemeral key, which is now current."""
        HkdfGuardLog._log(logger, logging.INFO, HkdfGuardLog.EPHEMERAL_KEY_ROTATED, "Ephemeral key rotated: version %d is now current.",
                          key_version)

    @staticmethod
    def ephemeral_key_rotation_failed(logger: logging.Logger | None, key_version: int, exception: BaseException) -> None:
        """Error: a scheduled rotation could not add a new key; the current version stays in use."""
        HkdfGuardLog._log(logger, logging.ERROR, HkdfGuardLog.EPHEMERAL_KEY_ROTATION_FAILED,
                          "Ephemeral key rotation failed; version %d stays current until the next attempt.", key_version,
                          exception=exception)

    @staticmethod
    def ephemeral_key_retired(logger: logging.Logger | None, key_version: int) -> None:
        """Info: a superseded ephemeral key's retention ran out; it has been removed and closed."""
        HkdfGuardLog._log(logger, logging.INFO, HkdfGuardLog.EPHEMERAL_KEY_RETIRED,
                          "Ephemeral key retired: version %d has been removed and its key zeroed; values encrypted under it no longer decrypt.",
                          key_version)

    @staticmethod
    def ephemeral_key_retirement_failed(logger: logging.Logger | None, key_version: int, exception: BaseException) -> None:
        """Error: a retired ephemeral key was removed from the ring but closing it failed."""
        HkdfGuardLog._log(logger, logging.ERROR, HkdfGuardLog.EPHEMERAL_KEY_RETIREMENT_FAILED,
                          "Ephemeral key version %d was removed from the ring, but disposing it failed.", key_version, exception=exception)

    @staticmethod
    def encryption_budget_warning(logger: logging.Logger | None, encryption_count: int, encryption_limit: int) -> None:
        """Warning: a key crossed the warning threshold of its AES-GCM budget; rotate it before the limit."""
        HkdfGuardLog._log(logger, logging.WARNING, HkdfGuardLog.ENCRYPTION_BUDGET_WARNING,
                          "This key has performed %d encryptions of its %d AES-GCM limit; rotate it before the limit, when it stops encrypting.",
                          encryption_count, encryption_limit)
