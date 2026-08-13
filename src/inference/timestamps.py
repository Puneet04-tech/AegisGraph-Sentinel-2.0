"""
Timestamp normalisation for the inference path.

The scorer accepted timestamps in four different forms and handled each
differently. Numeric timestamps went through ``datetime.fromtimestamp(value)``
with no ``tz`` argument, which returns a **naive local-time** datetime — so the
hour used to evaluate the 02:00-04:00 fraud window depended on the host's
``TZ``, and the same transaction scored 0.6 or 0.2 according to which region a
worker happened to run in.

This module resolves every supported form to a single aware UTC datetime, so
downstream logic has one representation to reason about and two workers in
different regions agree.
"""

from __future__ import annotations

from datetime import date, datetime, timezone, timedelta, tzinfo
from typing import Optional

# Epoch seconds do not reach 1e11 until the year 5138, so a magnitude at or
# above that is milliseconds rather than seconds.
_MILLISECOND_THRESHOLD = 1e11

# Guards against a value so far outside any plausible range that treating it as
# a timestamp would be meaningless. Roughly year 1 to year 9999 in seconds.
_MIN_EPOCH_SECONDS = -62_135_596_800.0
_MAX_EPOCH_SECONDS = 253_402_300_799.0


def to_utc(value) -> Optional[datetime]:
    """Normalise a timestamp of any supported form to an aware UTC datetime.

    Accepts epoch seconds, epoch milliseconds, ``datetime``, ``date`` and ISO
    8601 strings (including a trailing ``Z``).

    A **naive** input is interpreted as UTC rather than as local time. That is
    a deliberate choice: the rest of the platform stores aware UTC via
    ``datetime.now(timezone.utc)``, so treating naive input as local would make
    the same stored value mean different instants on different hosts.

    Returns:
        An aware UTC datetime, or ``None`` when the value cannot be interpreted.
    """
    if value is None:
        return None

    # bool is a subclass of int, and a boolean is never a timestamp.
    if isinstance(value, bool):
        return None

    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(
            tzinfo=timezone.utc
        )

    # date must be checked after datetime, which is a subclass of it.
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    if isinstance(value, (int, float)):
        return _from_epoch(float(value))

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None

        # A bare numeric string is an epoch value, not an ISO date.
        try:
            return _from_epoch(float(text))
        except ValueError:
            pass

        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(
            tzinfo=timezone.utc
        )

    # Duck-typed objects exposing isoformat() (e.g. pandas Timestamp).
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        try:
            return to_utc(isoformat())
        except Exception:
            return None

    return None


def _from_epoch(seconds: float) -> Optional[datetime]:
    """Build an aware UTC datetime from epoch seconds or milliseconds."""
    if seconds != seconds:  # NaN
        return None
    if seconds in (float("inf"), float("-inf")):
        return None

    if abs(seconds) >= _MILLISECOND_THRESHOLD:
        seconds = seconds / 1000.0

    if not (_MIN_EPOCH_SECONDS <= seconds <= _MAX_EPOCH_SECONDS):
        return None

    try:
        # Arithmetic instead of ``datetime.fromtimestamp``: Windows cannot
        # represent pre-1970 negative epochs via ``fromtimestamp`` and raises
        # ``OSError: [Errno 22]``, so deriving the instant from the epoch
        # directly keeps pre-1970 values working on every platform.
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    except (OverflowError, OSError, ValueError):
        return None


def hour_in_zone(value, zone: Optional[tzinfo] = None) -> Optional[int]:
    """Return the hour-of-day of a timestamp in a specific timezone.

    The reference zone is explicit and defaults to UTC, so the hour a scoring
    rule sees never depends on the host's ``TZ``.
    """
    moment = to_utc(value)
    if moment is None:
        return None
    if zone is not None:
        moment = moment.astimezone(zone)
    return moment.hour
