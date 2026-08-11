"""Device risk computation.

`ProductionRiskScorer._compute_device_risk` returned the literal `0.2` under a
comment listing three checks it was supposed to perform -- registration age,
links to confirmed fraud, and impossible geographic movement -- none of which
were implemented. The `transaction` argument was never read, so a first-ever
device in a different country scored identically to the account's daily phone.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from src.inference.device_risk import (
    DEFAULT_UNKNOWN_DEVICE_RISK,
    DeviceRiskCalculator,
    haversine_km,
)

BASE = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

# Real coordinates, so the distances in these tests are checkable.
MUMBAI = (19.0760, 72.8777)
DELHI = (28.7041, 77.1025)
LONDON = (51.5074, -0.1278)


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


@pytest.fixture
def calc() -> DeviceRiskCalculator:
    return DeviceRiskCalculator()


class TestHaversine:
    def test_zero_distance(self):
        assert haversine_km(*MUMBAI, *MUMBAI) == pytest.approx(0.0)

    def test_known_distance_mumbai_to_delhi(self):
        # Great-circle distance is roughly 1150 km.
        assert haversine_km(*MUMBAI, *DELHI) == pytest.approx(1150, abs=40)

    def test_known_distance_mumbai_to_london(self):
        assert haversine_km(*MUMBAI, *LONDON) == pytest.approx(7200, abs=150)

    def test_antimeridian_is_handled_as_a_short_hop(self):
        """A naive coordinate difference would call this half the planet."""
        near = haversine_km(0.0, 179.9, 0.0, -179.9)
        assert near < 30

    def test_poles(self):
        assert haversine_km(90.0, 0.0, -90.0, 0.0) == pytest.approx(20015, abs=50)


class TestDeviceAge:
    def test_an_unseen_device_scores_above_an_established_one(self, calc):
        calc.record("known", "ACC1", at(-30 * 86400), *MUMBAI)
        established = calc.score("known", "ACC1", at(0), *MUMBAI)
        brand_new = calc.score("never-seen", "ACC1", at(0), *MUMBAI)

        assert brand_new > established

    def test_age_risk_decays_as_a_device_becomes_established(self, calc):
        calc.record("dev", "ACC1", at(0), *MUMBAI)
        fresh = calc.score("dev", "ACC1", at(60), *MUMBAI)
        later = calc.score("dev", "ACC1", at(3 * 86400), *MUMBAI)
        established = calc.score("dev", "ACC1", at(30 * 86400), *MUMBAI)

        assert fresh > later > established
        assert established == pytest.approx(0.0)

    def test_a_device_older_than_the_window_carries_no_age_risk(self, calc):
        calc.record("dev", "ACC1", at(0), *MUMBAI)
        assert calc._age_score(calc._devices["dev"], at(365 * 86400).timestamp()) == 0.0


class TestKnownBad:
    def test_a_known_bad_device_scores_maximally(self, calc):
        calc.record("bad", "ACC1", at(-30 * 86400), *MUMBAI)
        calc.mark_known_bad("bad")

        assert calc.score("bad", "ACC1", at(0), *MUMBAI) == pytest.approx(1.0)

    def test_known_bad_overrides_an_otherwise_clean_device(self, calc):
        for i in range(10):
            calc.record("dev", "ACC1", at(-30 * 86400 + i), *MUMBAI)
        assert calc.score("dev", "ACC1", at(0), *MUMBAI) < 0.2

        calc.mark_known_bad("dev")
        assert calc.score("dev", "ACC1", at(0), *MUMBAI) == pytest.approx(1.0)

    def test_clearing_known_bad_restores_the_normal_score(self, calc):
        calc.record("dev", "ACC1", at(-30 * 86400), *MUMBAI)
        calc.mark_known_bad("dev")
        calc.clear_known_bad("dev")

        assert calc.score("dev", "ACC1", at(0), *MUMBAI) < 1.0

    def test_marking_an_empty_id_is_a_no_op(self, calc):
        calc.mark_known_bad("")
        assert "" not in calc._known_bad


class TestAccountFanout:
    def test_one_account_carries_no_fanout_risk(self, calc):
        calc.record("dev", "ACC1", at(-30 * 86400), *MUMBAI)
        assert calc._fanout_score(calc._devices["dev"], "ACC1") == 0.0

    def test_fanout_risk_rises_with_distinct_accounts(self, calc):
        scores = []
        for i in range(9):
            calc.record("dev", f"ACC{i}", at(-30 * 86400 + i), *MUMBAI)
            scores.append(calc._fanout_score(calc._devices["dev"], None))

        assert scores == sorted(scores)
        assert scores[-1] == pytest.approx(1.0)

    def test_a_mule_farm_device_outscores_a_household_device(self, calc):
        for i in range(20):
            calc.record("farm", f"ACC{i}", at(-30 * 86400), *MUMBAI)
        calc.record("household", "ACC_A", at(-30 * 86400), *MUMBAI)
        calc.record("household", "ACC_B", at(-30 * 86400), *MUMBAI)

        assert calc.score("farm", "ACC_X", at(0), *MUMBAI) > calc.score(
            "household", "ACC_A", at(0), *MUMBAI
        )

    def test_the_account_being_scored_counts_towards_fanout(self, calc):
        calc.record("dev", "ACC1", at(-30 * 86400), *MUMBAI)
        without = calc._fanout_score(calc._devices["dev"], "ACC1")
        with_new = calc._fanout_score(calc._devices["dev"], "ACC_NEW")

        assert with_new > without


class TestGeoVelocity:
    def test_impossible_travel_is_flagged(self, calc):
        """Mumbai to London in ten minutes is not travel."""
        calc.record("dev", "ACC1", at(-30 * 86400), *MUMBAI)
        calc.record("dev", "ACC1", at(0), *MUMBAI)

        assert calc.score("dev", "ACC1", at(600), *LONDON) > 0.5

    def test_plausible_travel_is_not_flagged(self, calc):
        """Mumbai to Delhi over four hours is an ordinary flight."""
        calc.record("dev", "ACC1", at(-30 * 86400), *MUMBAI)
        calc.record("dev", "ACC1", at(0), *MUMBAI)

        assert calc._geo_velocity_score(
            calc._devices["dev"], at(4 * 3600).timestamp(), *DELHI
        ) == 0.0

    def test_staying_put_is_not_flagged(self, calc):
        calc.record("dev", "ACC1", at(0), *MUMBAI)
        assert calc._geo_velocity_score(
            calc._devices["dev"], at(3600).timestamp(), *MUMBAI
        ) == 0.0

    def test_sightings_too_close_in_time_are_not_scored(self, calc):
        """Below the minimum elapsed time this measures clock resolution."""
        calc.record("dev", "ACC1", at(0), *MUMBAI)
        assert calc._geo_velocity_score(
            calc._devices["dev"], at(5).timestamp(), *LONDON
        ) == 0.0

    def test_no_prior_location_cannot_be_scored(self, calc):
        calc.record("dev", "ACC1", at(0))
        assert calc._geo_velocity_score(
            calc._devices["dev"], at(3600).timestamp(), *LONDON
        ) == 0.0

    def test_missing_coordinates_are_not_scored(self, calc):
        calc.record("dev", "ACC1", at(0), *MUMBAI)
        record = calc._devices["dev"]
        now = at(3600).timestamp()

        assert calc._geo_velocity_score(record, now, None, None) == 0.0
        assert calc._geo_velocity_score(record, now, 19.0, None) == 0.0

    def test_out_of_range_coordinates_are_rejected(self, calc):
        calc.record("dev", "ACC1", at(0), *MUMBAI)
        record = calc._devices["dev"]
        now = at(3600).timestamp()

        assert calc._geo_velocity_score(record, now, 200.0, 0.0) == 0.0
        assert calc._geo_velocity_score(record, now, 0.0, 400.0) == 0.0

    def test_out_of_range_coordinates_are_not_stored(self, calc):
        calc.record("dev", "ACC1", at(0), 999.0, 999.0)
        assert calc._devices["dev"].last_location is None

    def test_non_finite_coordinates_are_rejected(self, calc):
        calc.record("dev", "ACC1", at(0), float("nan"), float("inf"))
        assert calc._devices["dev"].last_location is None

    def test_out_of_order_sightings_do_not_rewrite_location_backwards(self, calc):
        calc.record("dev", "ACC1", at(1000), *LONDON)
        calc.record("dev", "ACC1", at(0), *MUMBAI)

        assert calc._devices["dev"].last_location == pytest.approx(LONDON)


class TestUnknownAndMalformed:
    def test_no_device_id_returns_the_documented_default(self, calc):
        assert calc.score(None, "ACC1", at(0)) == pytest.approx(
            DEFAULT_UNKNOWN_DEVICE_RISK
        )
        assert calc.score("", "ACC1", at(0)) == pytest.approx(
            DEFAULT_UNKNOWN_DEVICE_RISK
        )

    def test_recording_without_a_device_id_is_rejected(self, calc):
        assert calc.record("", "ACC1", at(0)) is False

    def test_an_unparseable_timestamp_falls_back_to_now(self, calc):
        assert calc.record("dev", "ACC1", "not-a-date") is True

    def test_scores_never_leave_the_unit_range(self, calc):
        for i in range(30):
            calc.record("dev", f"ACC{i}", at(i), *MUMBAI)
            score = calc.score("dev", f"ACC{i}", at(i + 3600), *LONDON)
            assert 0.0 <= score <= 1.0


class TestScoreAndRecord:
    def test_scoring_precedes_recording(self, calc):
        """A sighting must never be compared against itself."""
        first = calc.score_and_record("dev", "ACC1", at(0), *MUMBAI)
        # The device was unknown when scored, so it carries new-device risk.
        assert first > 0.0
        assert "dev" in calc._devices

    def test_a_second_sighting_sees_the_first(self, calc):
        calc.score_and_record("dev", "ACC1", at(0), *MUMBAI)
        second = calc.score_and_record("dev", "ACC1", at(600), *LONDON)

        # Impossible travel between the two recorded sightings.
        assert second > 0.5

    def test_score_and_record_with_no_device_records_nothing(self, calc):
        calc.score_and_record(None, "ACC1", at(0))
        assert calc.tracked_devices() == 0


class TestBounds:
    def test_tracked_devices_are_capped(self):
        calc = DeviceRiskCalculator(max_devices=10)
        for i in range(50):
            calc.record(f"dev{i}", "ACC1", at(i), *MUMBAI)
        assert calc.tracked_devices() == 10

    def test_the_oldest_device_is_evicted_first(self):
        calc = DeviceRiskCalculator(max_devices=3)
        for name in ("a", "b", "c"):
            calc.record(name, "ACC1", at(0), *MUMBAI)
        calc.record("d", "ACC1", at(1), *MUMBAI)

        assert "a" not in calc._devices
        assert "d" in calc._devices

    def test_reset_clears_the_registry_and_known_bad(self, calc):
        calc.record("dev", "ACC1", at(0), *MUMBAI)
        calc.mark_known_bad("dev")
        calc.reset()

        assert calc.tracked_devices() == 0
        assert calc._known_bad == set()


class TestConcurrency:
    def test_concurrent_recording_is_safe(self, calc):
        errors = []

        def writer(offset: int) -> None:
            try:
                for i in range(100):
                    calc.record(f"dev{i % 10}", f"ACC{offset}", at(offset * 100 + i), *MUMBAI)
            except Exception as exc:  # pragma: no cover - surfaced by assertion
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(o,)) for o in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert calc.tracked_devices() == 10
        for record in calc._devices.values():
            assert len(record.accounts) == 6


class TestScorerIntegration:
    """The component must no longer be a constant in the composite score."""

    def _fake_scorer(self, calc):
        from src.inference.production_scorer import ProductionRiskScorer

        scorer = ProductionRiskScorer.__new__(ProductionRiskScorer)
        scorer.device_calculator = calc
        return scorer

    def test_device_risk_varies_across_transactions(self, calc):
        scorer = self._fake_scorer(calc)
        scores = []
        for i in range(6):
            scores.append(
                scorer._compute_device_risk(
                    {
                        "source_device_id": f"DEV{i}",
                        "source_account": "ACC1",
                        "timestamp": at(i * 600).isoformat(),
                        "latitude": MUMBAI[0],
                        "longitude": MUMBAI[1],
                    }
                )
            )
        # Same device, moving impossibly.
        scores.append(
            scorer._compute_device_risk(
                {
                    "source_device_id": "DEV0",
                    "source_account": "ACC1",
                    "timestamp": at(3600).isoformat(),
                    "latitude": LONDON[0],
                    "longitude": LONDON[1],
                }
            )
        )

        assert len(set(round(s, 6) for s in scores)) > 1, "still behaving like a constant"
        assert scores != [0.2] * len(scores)

    def test_a_transaction_without_a_device_falls_back(self, calc):
        scorer = self._fake_scorer(calc)
        assert scorer._compute_device_risk({"source_account": "ACC1"}) == pytest.approx(
            DEFAULT_UNKNOWN_DEVICE_RISK
        )

    def test_both_device_field_names_are_accepted(self, calc):
        scorer = self._fake_scorer(calc)
        for field_name in ("source_device_id", "device_id"):
            result = scorer._compute_device_risk(
                {
                    field_name: f"DEV_{field_name}",
                    "source_account": "ACC1",
                    "timestamp": at(0).isoformat(),
                }
            )
            assert 0.0 <= result <= 1.0
        assert calc.tracked_devices() == 2

    def test_a_known_bad_device_blocks_through_the_scorer(self, calc):
        scorer = self._fake_scorer(calc)
        calc.mark_known_bad("DEV_BAD")

        result = scorer._compute_device_risk(
            {
                "source_device_id": "DEV_BAD",
                "source_account": "ACC1",
                "timestamp": at(0).isoformat(),
            }
        )
        assert result == pytest.approx(1.0)
