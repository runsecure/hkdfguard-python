"""Go's duration syntax - "1h30m", "300ms", "2.5s" - which Vault and its environment variables use."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from typing import Final

_NANOS_PER_UNIT: Final = {"ns": 1, "us": 1_000, "µs": 1_000, "μs": 1_000, "ms": 1_000_000, "s": 1_000_000_000, "m": 60_000_000_000,
                          "h": 3_600_000_000_000}
# What a timedelta holds, in nanoseconds.
_MAX_NANOS: Final = (timedelta.max.days * 86_400 + timedelta.max.seconds) * 1_000_000_000 + timedelta.max.microseconds * 1_000


def parse_go_duration(value: str) -> timedelta:
    """time.ParseDuration: an optional sign, then one or more decimal numbers each with a unit (ns,
    us, µs, ms, s, m, h); "0" alone needs none. Nanoseconds are truncated to microseconds, which is
    all a ``timedelta`` holds.

    :raises ValueError: ``value`` isn't a duration, or is longer than a ``timedelta`` holds
    """
    s = value
    negative = False
    if s[:1] in {"-", "+"}:
        negative = s[0] == "-"
        s = s[1:]

    if s == "0":
        return timedelta(0)
    if not s:
        raise ValueError(f"Invalid duration '{value}'.")

    nanoseconds = Decimal(0)
    i = 0
    while i < len(s):
        start = i
        while i < len(s) and ((s[i].isascii() and s[i].isdigit()) or s[i] == "."):
            i += 1
        number = s[start:i]
        if not number or number == "." or number.count(".") > 1:
            raise ValueError(f"Invalid duration '{value}'.")

        unit_start = i
        while i < len(s) and not (s[i].isascii() and s[i].isdigit()) and s[i] != ".":
            i += 1
        unit = s[unit_start:i]
        if not unit:
            raise ValueError(f"Missing unit in duration '{value}'.")
        per_unit = _NANOS_PER_UNIT.get(unit)
        if per_unit is None:
            raise ValueError(f"Unknown unit '{unit}' in duration '{value}'.")
        nanoseconds += Decimal("0" + number if number.startswith(".") else number) * per_unit

    nanos = int(nanoseconds)
    if nanos > _MAX_NANOS:
        raise ValueError(f"The duration '{value}' is too long.")
    duration = timedelta(microseconds=nanos // 1_000)
    return -duration if negative else duration


def format_go_duration(duration: timedelta) -> str:
    """Duration.String: "1h2m3.5s", "5m0s", "1.5ms", "0s"."""
    if not duration:
        return "0s"

    sign = "-" if duration < timedelta(0) else ""
    nanoseconds = abs((duration.days * 86_400 + duration.seconds) * 1_000_000_000 + duration.microseconds * 1_000)

    if nanoseconds < 1_000_000_000:
        if nanoseconds < 1_000:
            return f"{sign}{nanoseconds}ns"
        if nanoseconds < 1_000_000:
            return f"{sign}{_fraction(nanoseconds, 1_000)}µs"
        return f"{sign}{_fraction(nanoseconds, 1_000_000)}ms"

    minutes, rest = divmod(nanoseconds, 60_000_000_000)
    hours = minutes // 60
    text = sign
    if hours:
        text += f"{hours}h"
    if minutes:
        text += f"{minutes % 60}m"
    return f"{text}{_fraction(rest, 1_000_000_000)}s"


def _fraction(value: int, unit: int) -> str:
    # value / unit, with as many fractional digits as it needs.
    whole, fraction = divmod(value, unit)
    if not fraction:
        return str(whole)
    digits = f"{fraction:0{len(str(unit)) - 1}d}".rstrip("0")
    return f"{whole}.{digits}"
