"""Key ring settings as plain data: read from configuration, validated, then applied to a builder."""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import ClassVar, Self

from hkdfguard.abstractions import ServiceNames
from hkdfguard.dataencryptionkey import KeyRingBuilder

_INTEGER: re.Pattern[str] = re.compile(r"[+-]?\d+")


@dataclass(frozen=True)
class KeyFileOptions:
    """One :meth:`KeyRingBuilder.with_key_file` registration: a version paired with the path to its
    wrapped DEK file on disk."""

    version: int
    path: str | os.PathLike[str]


class OptionsValidationError(ValueError):
    """:class:`HkdfGuardOptions` that break one or more rules. :attr:`failures` lists every one."""

    def __init__(self, failures: Sequence[str]) -> None:
        self.failures: tuple[str, ...] = tuple(failures)
        super().__init__("HkdfGuard options are invalid: " + " ".join(self.failures))


@dataclass
class HkdfGuardOptions:
    """Plain-data mirror of the settings :class:`KeyRingBuilder` itself exposes: the service name, key
    refresh interval, refresh-failure policy, ephemeral key rotation and retention, key files and
    ephemeral keys. It carries no behavior: the key wrapper, crypto provider factory and format
    provider a real ring needs still come from the caller - :meth:`apply_to` copies this data onto
    a builder the caller finishes and builds.

    Typically read from a configuration file with :meth:`from_mapping`, checked with
    :meth:`require_valid`, then applied::

        options = HkdfGuardOptions.from_mapping(config["HkdfGuard"]).require_valid()
        ring = (options.apply_to(KeyRingBuilder())
                .with_key_wrapper(NativeHkdfKeyWrapperV1(options.service_name))
                .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
                .build())
    """

    MAX_EPHEMERAL_KEY_ROTATION_HOURS: ClassVar[int] = 1193
    """The largest :attr:`ephemeral_key_rotation_hours`: the longest rotation interval
    :class:`KeyRingBuilder` accepts, in whole hours."""

    service_name: str | None = None
    """The service name identifying this ring's KEK to the native KMS library."""

    key_refresh_interval: int | None = None
    """How often, in seconds (1-300), each key is re-revealed through the KEK to confirm the KEK is
    still available. A revocation check, not a limit on how long the DEK stays in memory. Together
    with :attr:`max_refresh_failures` it sets how quickly a revoked KEK stops a running process -
    about max_refresh_failures x key_refresh_interval."""

    max_refresh_failures: int | None = None
    """How many consecutive failed refreshes are tolerated before a key's provider fails closed -
    zeroing the key and refusing every operation until a refresh succeeds. At least 1. ``None`` keeps
    :attr:`KeyRingBuilder.DEFAULT_MAX_REFRESH_FAILURES`."""

    fail_open_on_refresh_failure: bool = False
    """True opts out of failing closed: the last good key stays in use however many refreshes fail,
    so revoking the KEK never stops a running process. Can't be combined with
    :attr:`max_refresh_failures`."""

    ephemeral_key_rotation_hours: int | None = None
    """Hours between scheduled ephemeral key rotations, 1 to :attr:`MAX_EPHEMERAL_KEY_ROTATION_HOURS`.
    ``None`` keeps the builder's 24-hour default. Applies only with ephemeral keys; can't be
    combined with :attr:`disable_ephemeral_key_rotation`."""

    disable_ephemeral_key_rotation: bool = False
    """True turns scheduled rotation off: the startup ephemeral key stays current until restart."""

    ephemeral_key_retention_hours: int | None = None
    """Hours a superseded ephemeral key stays registered for decryption after a rotation replaces
    it. At least 1. ``None`` keeps the builder's 24-hour default."""

    key_files: list[KeyFileOptions] = field(default_factory=list)
    """Versions whose wrapped DEK is read from a file on disk."""

    ephemeral_keys: list[int] = field(default_factory=list)
    """Versions whose key is generated fresh in memory at build and never persisted."""

    @classmethod
    def from_mapping(cls, settings: Mapping[str, object]) -> Self:
        """Reads options from a parsed configuration section - a dict from JSON, TOML or YAML.

        Keys match a field ignoring case and underscores, so a .NET ``appsettings.json`` section
        (``"ServiceName"``, ``"KeyFiles": [{"Version": 1, "Path": "..."}]``) and snake_case
        (``"service_name"``) both read. Integers and booleans may also be given as strings, as an
        INI file or environment variable supplies them. A ``None`` value leaves its field unset. The
        result is not validated: call :meth:`require_valid` or :meth:`validate`.

        :raises TypeError: ``settings`` or a key file entry is not a mapping
        :raises ValueError: an unknown key (a likely typo, never silently ignored), a key given
            twice, or a value of the wrong type
        """
        reader = _Reader(settings, "settings", _FIELDS)
        return cls(
            service_name=reader.read("service_name", _string),
            key_refresh_interval=reader.read("key_refresh_interval", _integer),
            max_refresh_failures=reader.read("max_refresh_failures", _integer),
            fail_open_on_refresh_failure=reader.read("fail_open_on_refresh_failure", _boolean) or False,
            ephemeral_key_rotation_hours=reader.read("ephemeral_key_rotation_hours", _integer),
            disable_ephemeral_key_rotation=reader.read("disable_ephemeral_key_rotation", _boolean) or False,
            ephemeral_key_retention_hours=reader.read("ephemeral_key_retention_hours", _integer),
            key_files=reader.read("key_files", _list_of(_key_file)) or [],
            ephemeral_keys=reader.read("ephemeral_keys", _list_of(_integer)) or [],
        )

    def validate(self) -> list[str]:
        """Checks these options against the constraints :class:`KeyRingBuilder` enforces, plus what
        :meth:`apply_to` and build need: a valid service name, every key file having a path, and
        versions that don't collide across key files and ephemeral keys - caught here, at
        configuration time, with a much clearer message than a failure deep inside build.

        :returns: every failure, or an empty list if these options are valid
        """
        failures: list[str] = []

        service_name_problem = ServiceNames.get_problem(self.service_name)
        if service_name_problem is not None:
            failures.append(f"service_name is invalid: {service_name_problem}")

        if self.key_refresh_interval is not None and not 1 <= self.key_refresh_interval <= 300:
            failures.append("key_refresh_interval must be between 1 and 300 seconds.")

        if self.max_refresh_failures is not None and self.max_refresh_failures < 1:
            failures.append("max_refresh_failures must be at least 1.")

        if self.ephemeral_key_rotation_hours is not None and not 1 <= self.ephemeral_key_rotation_hours <= self.MAX_EPHEMERAL_KEY_ROTATION_HOURS:
            failures.append(f"ephemeral_key_rotation_hours must be between 1 and {self.MAX_EPHEMERAL_KEY_ROTATION_HOURS}.")

        if self.ephemeral_key_retention_hours is not None and self.ephemeral_key_retention_hours < 1:
            failures.append("ephemeral_key_retention_hours must be at least 1.")

        if self.disable_ephemeral_key_rotation and self.ephemeral_key_rotation_hours is not None:
            failures.append("disable_ephemeral_key_rotation and ephemeral_key_rotation_hours can't both be set: "
                            "one turns rotation off, the other schedules it.")

        if self.fail_open_on_refresh_failure and self.max_refresh_failures is not None:
            failures.append("fail_open_on_refresh_failure and max_refresh_failures can't both be set: one fails open, the other fails closed.")

        if not self.key_files and not self.ephemeral_keys:
            failures.append("At least one key file or ephemeral key is required.")

        failures.extend(f"key_files version {key_file.version} is missing a path."
                        for key_file in self.key_files if not os.fspath(key_file.path).strip())

        versions = Counter([key_file.version for key_file in self.key_files] + list(self.ephemeral_keys))
        failures.extend(f"Version {version} is registered more than once across key_files/ephemeral_keys."
                        for version, count in versions.items() if count > 1)

        return failures

    def require_valid(self) -> Self:
        """:returns: these same options, for chaining into :meth:`apply_to`
        :raises OptionsValidationError: any rule is broken; it lists every failure
        """
        failures = self.validate()
        if failures:
            raise OptionsValidationError(failures)
        return self

    def apply_to(self, builder: KeyRingBuilder) -> KeyRingBuilder:
        """Copies every set option onto ``builder``; unset ones leave the builder's defaults in place.
        The caller still supplies the key wrapper, crypto provider factory and (optionally) format
        provider, and calls build - those are behavior, not something options carry as data. Doesn't
        validate: call :meth:`require_valid` first for one clear report of every problem.

        :returns: ``builder``, for chaining
        :raises ValueError: an option the builder itself rejects
        """
        if self.service_name is not None:
            builder.with_service_name(self.service_name)

        if self.key_refresh_interval is not None:
            builder.with_key_refresh_interval(self.key_refresh_interval)

        if self.max_refresh_failures is not None:
            builder.with_max_refresh_failures(self.max_refresh_failures)

        if self.fail_open_on_refresh_failure:
            builder.with_fail_open_on_refresh_failure()

        if self.ephemeral_key_rotation_hours is not None:
            builder.with_ephemeral_key_rotation(timedelta(hours=self.ephemeral_key_rotation_hours))

        if self.disable_ephemeral_key_rotation:
            builder.without_ephemeral_key_rotation()

        if self.ephemeral_key_retention_hours is not None:
            builder.with_ephemeral_key_retention(timedelta(hours=self.ephemeral_key_retention_hours))

        for key_file in self.key_files:
            builder.with_key_file(key_file.version, key_file.path)

        for version in self.ephemeral_keys:
            builder.with_ephemeral_key(version)

        return builder


# --- Reading configuration -------------------------------------------------------------------

_FIELDS: tuple[str, ...] = (
    "service_name", "key_refresh_interval", "max_refresh_failures", "fail_open_on_refresh_failure", "ephemeral_key_rotation_hours",
    "disable_ephemeral_key_rotation", "ephemeral_key_retention_hours", "key_files", "ephemeral_keys",
)
_KEY_FILE_FIELDS: tuple[str, ...] = ("version", "path")


def _normalize(key: str) -> str:
    return key.replace("_", "").casefold()


class _Reader:
    """A configuration section's values by field name, matched ignoring case and underscores."""

    def __init__(self, settings: object, where: str, fields: tuple[str, ...]) -> None:
        if not isinstance(settings, Mapping):
            raise TypeError(f"{where} must be a mapping; it is {type(settings).__name__}.")
        known = {_normalize(name): name for name in fields}
        self._values: dict[str, object] = {}
        self._where = where
        for key, value in settings.items():
            if not isinstance(key, str):
                raise ValueError(f"{where} has a key that is not a string: {key!r}.")
            name = known.get(_normalize(key))
            if name is None:
                raise ValueError(f"{where} has an unknown key '{key}'. Known keys: {', '.join(fields)}.")
            if name in self._values:
                raise ValueError(f"{where} gives '{name}' more than once.")
            self._values[name] = value

    def read[T](self, name: str, convert: Callable[[object, str], T]) -> T | None:
        value = self._values.get(name)
        return None if value is None else convert(value, f"{self._where}.{name}")


def _string(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be a string; it is {type(value).__name__}.")
    return value


def _integer(value: object, where: str) -> int:
    # bool is an int subclass, but true is never a sensible version or interval.
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and _INTEGER.fullmatch(value.strip()):
        return int(value.strip())
    raise ValueError(f"{where} must be an integer; it is {value!r}.")


def _boolean(value: object, where: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().casefold() in ("true", "false"):
        return value.strip().casefold() == "true"
    raise ValueError(f"{where} must be true or false; it is {value!r}.")


def _path(value: object, where: str) -> str | os.PathLike[str]:
    if isinstance(value, str | os.PathLike):
        return value
    raise ValueError(f"{where} must be a path; it is {type(value).__name__}.")


def _key_file(value: object, where: str) -> KeyFileOptions:
    if isinstance(value, KeyFileOptions):
        return value
    reader = _Reader(value, where, _KEY_FILE_FIELDS)
    version = reader.read("version", _integer)
    if version is None:
        raise ValueError(f"{where} is missing its version.")
    return KeyFileOptions(version, reader.read("path", _path) or "")


def _list_of[T](convert: Callable[[object, str], T]) -> Callable[[object, str], list[T]]:
    def read_list(value: object, where: str) -> list[T]:
        if isinstance(value, str | bytes) or not isinstance(value, Sequence):
            raise ValueError(f"{where} must be a list; it is {type(value).__name__}.")
        return [convert(item, f"{where}[{index}]") for index, item in enumerate(value)]

    return read_list
