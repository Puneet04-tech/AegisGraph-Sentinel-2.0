"""
Device risk computation.

The scorer previously represented device risk with the literal ``0.2``, under a
comment listing the three checks it was supposed to perform — registration age,
links to known fraud, and impossible geographic movement — none of which were
implemented. Device takeover is one of the two dominant fraud entry paths this
platform exists to catch, so its dedicated risk component being inert meant a
first-ever device in a different country scored exactly like the account
holder's daily phone.

This module maintains a bounded device registry and scores four sub-signals
against it.
"""

from __future__ import annotations

import math
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Set, Tuple

# A device only just seen for the first time carries the most uncertainty; risk
# decays to nothing once it has been around long enough to be established.
DEFAULT_NEW_DEVICE_WINDOW_SECONDS = 7 * 86400

# One device legitimately serves a household; one device serving dozens of
# accounts is a mule-farm signature.
DEFAULT_ACCOUNT_FANOUT_CEILING = 8

# Commercial flight cruising speed with generous headroom, in km/h. Movement
# faster than this between two sightings is not travel.
DEFAULT_MAX_PLAUSIBLE_SPEED_KMH = 1000.0

# Below this elapsed time, two sightings in different places say more about
# clock resolution than about movement, so geo-velocity is not scored.
DEFAULT_MIN_ELAPSED_SECONDS = 60.0

# Weights across the four sub-signals. Known-bad dominates because it is a
# recorded fact rather than an inference.
DEFAULT_WEIGHTS = {
    "known_bad": 1.0,
    "geo_velocity": 0.9,
    "fanout": 0.7,
    "age": 0.4,
}

# Returned when a transaction carries no device information at all: neither
# trusted nor condemned.
DEFAULT_UNKNOWN_DEVICE_RISK = 0.2

DEFAULT_MAX_DEVICES = 200_000
EARTH_RADIUS_KM = 6371.0


def _to_epoch_seconds(value) -> Optional[float]:
    """Normalise a timestamp to epoch seconds, treating naive input as UTC."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if abs(seconds) >= 1e11:
            seconds /= 1000.0
        return seconds
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    return None


def _coordinate(value) -> Optional[float]:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres.

    Used rather than a naive coordinate difference so the antimeridian and
    converging meridians near the poles are handled correctly.
    """
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


@dataclass
class _DeviceRecord:
    first_seen: float
    last_seen: float
    accounts: Set[str] = field(default_factory=set)
    last_location: Optional[Tuple[float, float]] = None
    last_location_at: Optional[float] = None


class DeviceRiskCalculator:
    """Thread-safe device risk scoring backed by a bounded device registry."""

    def __init__(
        self,
        new_device_window_seconds: int = DEFAULT_NEW_DEVICE_WINDOW_SECONDS,
        account_fanout_ceiling: int = DEFAULT_ACCOUNT_FANOUT_CEILING,
        max_plausible_speed_kmh: float = DEFAULT_MAX_PLAUSIBLE_SPEED_KMH,
        min_elapsed_seconds: float = DEFAULT_MIN_ELAPSED_SECONDS,
        unknown_device_risk: float = DEFAULT_UNKNOWN_DEVICE_RISK,
        max_devices: int = DEFAULT_MAX_DEVICES,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        self.new_device_window_seconds = max(1, int(new_device_window_seconds))
        self.account_fanout_ceiling = max(1, int(account_fanout_ceiling))
        self.max_plausible_speed_kmh = max(1.0, float(max_plausible_speed_kmh))
        self.min_elapsed_seconds = max(0.0, float(min_elapsed_seconds))
        self.unknown_device_risk = min(1.0, max(0.0, float(unknown_device_risk)))
        self.max_devices = max(1, int(max_devices))
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)

        self._lock = threading.RLock()
        self._devices: "OrderedDict[str, _DeviceRecord]" = OrderedDict()
        self._known_bad: Set[str] = set()

    # ------------------------------------------------------------------
    # Registry maintenance
    # ------------------------------------------------------------------

    def mark_known_bad(self, device_id: str) -> None:
        """Record a device as linked to confirmed fraud."""
        if device_id:
            with self._lock:
                self._known_bad.add(device_id)

    def clear_known_bad(self, device_id: str) -> None:
        with self._lock:
            self._known_bad.discard(device_id)

    def record(
        self,
        device_id: str,
        account_id: Optional[str] = None,
        timestamp=None,
        latitude=None,
        longitude=None,
    ) -> bool:
        """Record a device sighting. Returns False if there is nothing to record."""
        if not device_id:
            return False

        moment = _to_epoch_seconds(timestamp)
        if moment is None:
            moment = datetime.now(timezone.utc).timestamp()

        lat = _coordinate(latitude)
        lon = _coordinate(longitude)
        # Out-of-range coordinates are discarded rather than trusted; a bad
        # fix would otherwise register as impossible travel.
        has_location = (
            lat is not None
            and lon is not None
            and -90.0 <= lat <= 90.0
            and -180.0 <= lon <= 180.0
        )

        with self._lock:
            record = self._devices.get(device_id)
            if record is None:
                record = _DeviceRecord(first_seen=moment, last_seen=moment)
                self._devices[device_id] = record
                while len(self._devices) > self.max_devices:
                    self._devices.popitem(last=False)
            self._devices.move_to_end(device_id)

            record.first_seen = min(record.first_seen, moment)
            record.last_seen = max(record.last_seen, moment)
            if account_id:
                record.accounts.add(str(account_id))
            if has_location:
                # Only advance the location if this sighting is not older than
                # the one already stored, so out-of-order arrivals do not
                # rewrite history backwards.
                if record.last_location_at is None or moment >= record.last_location_at:
                    record.last_location = (float(lat), float(lon))
                    record.last_location_at = moment

            return True

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(
        self,
        device_id: Optional[str],
        account_id: Optional[str] = None,
        timestamp=None,
        latitude=None,
        longitude=None,
    ) -> float:
        """Return device risk in [0, 1]."""
        if not device_id:
            return self.unknown_device_risk

        now = _to_epoch_seconds(timestamp)
        if now is None:
            now = datetime.now(timezone.utc).timestamp()

        with self._lock:
            if device_id in self._known_bad:
                return 1.0

            record = self._devices.get(device_id)
            if record is None:
                # Never seen before: maximally new, nothing else measurable.
                return min(1.0, self.weights["age"] * 1.0 + self.unknown_device_risk)

            age_score = self._age_score(record, now)
            fanout_score = self._fanout_score(record, account_id)
            geo_score = self._geo_velocity_score(record, now, latitude, longitude)

        weighted = max(
            self.weights["age"] * age_score,
            self.weights["fanout"] * fanout_score,
            self.weights["geo_velocity"] * geo_score,
        )
        return float(min(1.0, max(0.0, weighted)))

    def _age_score(self, record: _DeviceRecord, now: float) -> float:
        """1.0 for a device first seen just now, decaying to 0.0 once established."""
        age = max(0.0, now - record.first_seen)
        if age >= self.new_device_window_seconds:
            return 0.0
        return 1.0 - (age / self.new_device_window_seconds)

    def _fanout_score(
        self, record: _DeviceRecord, account_id: Optional[str]
    ) -> float:
        """How many distinct accounts this device has been used with."""
        accounts = set(record.accounts)
        if account_id:
            accounts.add(str(account_id))
        # One account is normal and scores zero; the ceiling saturates.
        excess = max(0, len(accounts) - 1)
        return min(1.0, excess / self.account_fanout_ceiling)

    def _geo_velocity_score(
        self,
        record: _DeviceRecord,
        now: float,
        latitude,
        longitude,
    ) -> float:
        """Implied travel speed between the last sighting and this one."""
        lat = _coordinate(latitude)
        lon = _coordinate(longitude)
        if lat is None or lon is None:
            return 0.0
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            return 0.0
        if record.last_location is None or record.last_location_at is None:
            return 0.0

        elapsed = now - record.last_location_at
        if elapsed < self.min_elapsed_seconds:
            # Too short to distinguish movement from clock resolution.
            return 0.0

        distance = haversine_km(
            record.last_location[0], record.last_location[1], lat, lon
        )
        if distance <= 0:
            return 0.0

        speed_kmh = distance / (elapsed / 3600.0)
        if speed_kmh <= self.max_plausible_speed_kmh:
            return 0.0
        # Anything above the plausible ceiling is impossible travel; scale so
        # twice the ceiling saturates.
        return min(1.0, (speed_kmh - self.max_plausible_speed_kmh) / self.max_plausible_speed_kmh)

    def score_and_record(
        self,
        device_id: Optional[str],
        account_id: Optional[str] = None,
        timestamp=None,
        latitude=None,
        longitude=None,
    ) -> float:
        """Score a device, then record this sighting.

        Scoring precedes recording so a sighting is never compared against
        itself — otherwise geo-velocity would always be zero and every device
        would look established the instant it was seen.
        """
        risk = self.score(device_id, account_id, timestamp, latitude, longitude)
        if device_id:
            self.record(device_id, account_id, timestamp, latitude, longitude)
        return risk

    def tracked_devices(self) -> int:
        with self._lock:
            return len(self._devices)

    def reset(self) -> None:
        with self._lock:
            self._devices.clear()
            self._known_bad.clear()


_default_calculator: Optional[DeviceRiskCalculator] = None
_default_lock = threading.Lock()


def get_device_calculator() -> DeviceRiskCalculator:
    """Process-wide calculator, so the registry accumulates across calls."""
    global _default_calculator
    with _default_lock:
        if _default_calculator is None:
            _default_calculator = DeviceRiskCalculator()
        return _default_calculator


def reset_device_calculator() -> None:
    """Drop the registry (used by tests)."""
    global _default_calculator
    with _default_lock:
        _default_calculator = None
