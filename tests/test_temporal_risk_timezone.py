"""Temporal risk must not depend on the host's timezone.

`_compute_temporal_risk` classified a transaction as high risk when its hour
fell in the 02:00-04:00 window, but derived that hour from a naive datetime:
numeric timestamps went through `datetime.fromtimestamp(value)` with no `tz`
argument, which returns **local** time. The same transaction therefore scored
0.6 or 0.2 depending purely on the host's `TZ`, and a deployment moved between
regions silently re-classified its entire traffic profile.
"""

from __future__ import annotations

import os
import time
from datetime import date, datetime, timedelta, timezone

import pytest

from src.inference.production_scorer import ProductionRiskScorer
from src.inference.timestamps import hour_in_zone, to_utc

# 03:00 UTC -- inside the 02:00-04:00 high-risk window.
FRAUD_WINDOW = datetime(2026, 5, 1, 3, 0, 0, tzinfo=timezone.utc)
# 14:00 UTC -- ordinary business hours.
BUSINESS_HOURS = datetime(2026, 5, 1, 14, 0, 0, tzinfo=timezone.utc)


def scorer(zone=None) -> ProductionRiskScorer:
    """A scorer instance without constructing the model or executor."""
    instance = ProductionRiskScorer.__new__(ProductionRiskScorer)
    instance.temporal_reference_zone = zone or timezone.utc
    return instance


class _TZ:
    """Temporarily set the process timezone, as a deployment region would."""

    def __init__(self, name):
        self.name = name
        self._previous = None

    def __enter__(self):
        self._previous = os.environ.get("TZ")
        os.environ["TZ"] = self.name
        if hasattr(time, "tzset"):
            time.tzset()
        return self

    def __exit__(self, *exc):
        if self._previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self._previous
        if hasattr(time, "tzset"):
            time.tzset()
        return False


ZONES = ["UTC", "Asia/Kolkata", "America/New_York", "Pacific/Auckland"]


class TestHostTimezoneIndependence:
    """The defect this PR exists for."""

    @pytest.mark.parametrize("tz_name", ZONES)
    def test_epoch_timestamps_score_identically_in_every_region(self, tz_name):
        epoch = FRAUD_WINDOW.timestamp()
        with _TZ(tz_name):
            assert scorer()._compute_temporal_risk({"timestamp": epoch}) == 0.6

    @pytest.mark.parametrize("tz_name", ZONES)
    def test_business_hours_score_identically_in_every_region(self, tz_name):
        epoch = BUSINESS_HOURS.timestamp()
        with _TZ(tz_name):
            assert scorer()._compute_temporal_risk({"timestamp": epoch}) == 0.2

    def test_every_region_agrees_with_every_other(self):
        """Two workers in different regions must not disagree."""
        epoch = FRAUD_WINDOW.timestamp()
        results = set()
        for tz_name in ZONES:
            with _TZ(tz_name):
                results.add(scorer()._compute_temporal_risk({"timestamp": epoch}))
        assert len(results) == 1, f"region-dependent scores: {results}"

    @pytest.mark.parametrize("tz_name", ZONES)
    def test_every_timestamp_form_agrees_within_a_region(self, tz_name):
        with _TZ(tz_name):
            instance = scorer()
            forms = [
                FRAUD_WINDOW,
                FRAUD_WINDOW.timestamp(),
                FRAUD_WINDOW.timestamp() * 1000,
                FRAUD_WINDOW.isoformat(),
                FRAUD_WINDOW.isoformat().replace("+00:00", "Z"),
            ]
            scores = {
                instance._compute_temporal_risk({"timestamp": form}) for form in forms
            }
            assert scores == {0.6}


class TestReferenceZone:
    def test_an_explicit_zone_shifts_the_window(self):
        """03:00 UTC is 08:30 in Kolkata -- outside the fraud window."""
        from zoneinfo import ZoneInfo

        utc_scorer = scorer(timezone.utc)
        ist_scorer = scorer(ZoneInfo("Asia/Kolkata"))

        payload = {"timestamp": FRAUD_WINDOW.isoformat()}
        assert utc_scorer._compute_temporal_risk(payload) == 0.6
        assert ist_scorer._compute_temporal_risk(payload) == 0.2

    def test_the_default_zone_is_utc(self):
        instance = ProductionRiskScorer.__new__(ProductionRiskScorer)
        instance.temporal_reference_zone = timezone.utc
        assert instance.temporal_reference_zone == timezone.utc


class TestBandBoundaries:
    @pytest.mark.parametrize(
        "hour,expected",
        [
            (0, 0.4), (1, 0.4), (2, 0.6), (3, 0.6), (4, 0.6),
            (5, 0.2), (12, 0.2), (22, 0.2), (23, 0.4),
        ],
    )
    def test_each_hour_lands_in_the_documented_band(self, hour, expected):
        moment = FRAUD_WINDOW.replace(hour=hour)
        assert scorer()._compute_temporal_risk({"timestamp": moment}) == expected

    def test_the_bands_wrap_midnight_correctly(self):
        instance = scorer()
        for hour in (23, 0, 1):
            moment = FRAUD_WINDOW.replace(hour=hour)
            assert instance._compute_temporal_risk({"timestamp": moment}) == 0.4


class TestMalformedInput:
    @pytest.mark.parametrize(
        "value",
        [None, "", "   ", "not-a-date", object(), True, False, float("nan"), float("inf")],
    )
    def test_uninterpretable_values_return_the_neutral_default(self, value):
        result = scorer()._compute_temporal_risk({"timestamp": value})
        assert result == ProductionRiskScorer.UNPARSEABLE_TEMPORAL_RISK

    def test_a_missing_timestamp_key_returns_the_default(self):
        assert scorer()._compute_temporal_risk({}) == (
            ProductionRiskScorer.UNPARSEABLE_TEMPORAL_RISK
        )


class TestToUtc:
    def test_aware_datetimes_are_converted_not_relabelled(self):
        from zoneinfo import ZoneInfo

        ist = FRAUD_WINDOW.astimezone(ZoneInfo("Asia/Kolkata"))
        assert to_utc(ist) == FRAUD_WINDOW

    def test_naive_datetimes_are_treated_as_utc(self):
        naive = FRAUD_WINDOW.replace(tzinfo=None)
        assert to_utc(naive) == FRAUD_WINDOW

    def test_epoch_seconds_and_milliseconds_agree(self):
        seconds = FRAUD_WINDOW.timestamp()
        assert to_utc(seconds) == to_utc(seconds * 1000) == FRAUD_WINDOW

    def test_iso_strings_with_and_without_z_agree(self):
        iso = FRAUD_WINDOW.isoformat()
        assert to_utc(iso) == to_utc(iso.replace("+00:00", "Z")) == FRAUD_WINDOW

    def test_iso_strings_with_a_non_utc_offset_are_converted(self):
        assert to_utc("2026-05-01T08:30:00+05:30") == FRAUD_WINDOW

    def test_a_bare_numeric_string_is_read_as_epoch(self):
        assert to_utc(str(FRAUD_WINDOW.timestamp())) == FRAUD_WINDOW

    def test_a_date_becomes_midnight_utc(self):
        assert to_utc(date(2026, 5, 1)) == datetime(
            2026, 5, 1, 0, 0, tzinfo=timezone.utc
        )

    def test_booleans_are_rejected(self):
        """bool subclasses int, but a boolean is never a timestamp."""
        assert to_utc(True) is None
        assert to_utc(False) is None

    def test_non_finite_values_are_rejected(self):
        assert to_utc(float("nan")) is None
        assert to_utc(float("inf")) is None
        assert to_utc(float("-inf")) is None

    def test_absurd_epoch_values_are_rejected(self):
        assert to_utc(1e30) is None
        assert to_utc(-1e30) is None

    def test_a_negative_epoch_before_1970_is_accepted(self):
        assert to_utc(-86400).year == 1969

    def test_unsupported_types_return_none(self):
        assert to_utc(object()) is None
        assert to_utc([1, 2, 3]) is None
        assert to_utc({"a": 1}) is None

    def test_duck_typed_isoformat_objects_are_accepted(self):
        class Stamp:
            def isoformat(self):
                return FRAUD_WINDOW.isoformat()

        assert to_utc(Stamp()) == FRAUD_WINDOW

    def test_a_broken_isoformat_returns_none(self):
        class Broken:
            def isoformat(self):
                raise RuntimeError("boom")

        assert to_utc(Broken()) is None

    def test_every_result_is_timezone_aware(self):
        for value in [FRAUD_WINDOW, FRAUD_WINDOW.timestamp(), FRAUD_WINDOW.isoformat()]:
            result = to_utc(value)
            assert result is not None and result.tzinfo is not None


class TestHourInZone:
    def test_utc_hour(self):
        assert hour_in_zone(FRAUD_WINDOW) == 3

    def test_hour_in_another_zone(self):
        from zoneinfo import ZoneInfo

        assert hour_in_zone(FRAUD_WINDOW, ZoneInfo("Asia/Kolkata")) == 8

    def test_uninterpretable_input_returns_none(self):
        assert hour_in_zone("garbage") is None

    @pytest.mark.parametrize("tz_name", ZONES)
    def test_the_hour_does_not_depend_on_the_host_timezone(self, tz_name):
        with _TZ(tz_name):
            assert hour_in_zone(FRAUD_WINDOW.timestamp()) == 3


class TestDaylightSaving:
    def test_a_dst_transition_does_not_shift_the_utc_hour(self):
        """US DST began 2026-03-08; the UTC hour is unaffected either side."""
        before = datetime(2026, 3, 7, 3, 0, tzinfo=timezone.utc)
        after = datetime(2026, 3, 9, 3, 0, tzinfo=timezone.utc)

        with _TZ("America/New_York"):
            instance = scorer()
            assert instance._compute_temporal_risk({"timestamp": before.timestamp()}) == 0.6
            assert instance._compute_temporal_risk({"timestamp": after.timestamp()}) == 0.6

    def test_an_hour_that_does_not_exist_locally_still_resolves(self):
        """02:30 local does not exist on a spring-forward date."""
        moment = datetime(2026, 3, 8, 7, 30, tzinfo=timezone.utc)
        with _TZ("America/New_York"):
            assert to_utc(moment.timestamp()) == moment
