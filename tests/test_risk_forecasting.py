"""A forecast must follow the entity's history, not a random walk.

`predict_risk_trend` chose its direction with `random.random()` against fixed
0.3/0.7 cut-offs. Neither `entity_id` nor `current_risk` influenced the result,
so the same entity was reported DECREASING on one call and INCREASING on the
next, and `time_to_peak` was `random.randint(1, 14)` days regardless of how fast
risk was actually moving.

`forecast_risk` computed `current_risk + current_risk * multiplier *
random.uniform(0.5, 1.5)`. Every term is positive, so it could only ever
forecast risk going up: an entity whose risk was steadily falling was still
forecast to rise.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.predictive_intelligence.forecasting import RiskForecaster
from src.predictive_intelligence.models import ForecastPeriod
from src.predictive_intelligence.store import PredictiveStore


def recent_base(count: int) -> datetime:
    """Start timestamp placing `count` hourly observations just before now.

    `predict_risk_trend` and `forecast_risk` append the caller's current risk at
    the present instant, so fixtures must sit on the same timescale; history
    parked months in the past would flatten every slope toward zero.
    """
    return datetime.now(timezone.utc) - timedelta(hours=count)


BASE = recent_base(6)


def seed(store, series, entity_id="E1"):
    base = recent_base(len(series))
    for hour, risk in enumerate(series):
        store.record_risk_observation(entity_id, risk, base + timedelta(hours=hour))
    return store


def forecaster(series=None, entity_id="E1"):
    """Build a forecaster whose store holds `series` as hourly observations."""
    store = PredictiveStore()
    if series:
        seed(store, series, entity_id)
    return RiskForecaster(store=store)


RISING = [0.1, 0.2, 0.3, 0.4, 0.5]
FALLING = [0.9, 0.8, 0.7, 0.6, 0.5]
FLAT = [0.5, 0.5, 0.5, 0.5, 0.5]


class TestDeterminism:
    """The defect this PR exists for."""

    def test_the_trend_is_stable_across_calls(self):
        instance = forecaster(FALLING)
        trends = {instance.predict_risk_trend("E1", 0.5).risk_trend for _ in range(50)}
        assert len(trends) == 1, f"trend still non-deterministic: {trends}"

    def test_the_module_no_longer_imports_random(self):
        import src.predictive_intelligence.forecasting as module

        assert not hasattr(module, "random")


class TestTrendDirection:
    def test_a_falling_entity_is_reported_decreasing(self):
        """Previously this was DECREASING only about 30% of the time."""
        assert forecaster(FALLING).predict_risk_trend("E1", 0.5).risk_trend == "DECREASING"

    def test_a_rising_entity_is_reported_increasing(self):
        assert forecaster(RISING).predict_risk_trend("E1", 0.5).risk_trend == "INCREASING"

    def test_a_flat_entity_is_reported_stable(self):
        assert forecaster(FLAT).predict_risk_trend("E1", 0.5).risk_trend == "STABLE"

    def test_insufficient_history_is_reported_unknown_not_guessed(self):
        assert forecaster([0.5]).predict_risk_trend("E1", 0.5).risk_trend == "UNKNOWN"

    def test_noise_below_the_stable_threshold_is_not_a_trend(self):
        barely = [0.5, 0.5001, 0.5, 0.5001, 0.5]
        assert forecaster(barely).predict_risk_trend("E1", 0.5).risk_trend == "STABLE"


class TestForecastDirection:
    def test_a_falling_entity_can_forecast_downward(self):
        """The original arithmetic could only ever forecast an increase."""
        result = forecaster(FALLING).forecast_risk("E1", 0.5, ForecastPeriod.DAY_1)
        assert result.risk_score < 0.5

    def test_a_rising_entity_forecasts_upward(self):
        result = forecaster(RISING).forecast_risk("E1", 0.5, ForecastPeriod.DAY_1)
        assert result.risk_score > 0.5

    def test_a_flat_entity_forecasts_flat(self):
        result = forecaster(FLAT).forecast_risk("E1", 0.5, ForecastPeriod.DAY_1)
        assert result.risk_score == pytest.approx(0.5, abs=0.01)

    def test_a_longer_horizon_extrapolates_further(self):
        instance = forecaster(RISING)
        short = instance.forecast_risk("E1", 0.5, ForecastPeriod.HOUR_1).risk_score
        long = forecaster(RISING).forecast_risk("E1", 0.5, ForecastPeriod.DAYS_7).risk_score
        assert long > short

    def test_no_history_forecasts_the_present_value(self):
        result = forecaster().forecast_risk("NEW", 0.4, ForecastPeriod.DAY_1)
        assert result.risk_score == 0.4


class TestBounds:
    def test_forecast_never_exceeds_one(self):
        steep = [0.5, 0.7, 0.9, 0.95, 0.99]
        result = forecaster(steep).forecast_risk("E1", 0.99, ForecastPeriod.DAYS_30)
        assert result.risk_score <= 1.0

    def test_forecast_never_falls_below_zero(self):
        steep = [0.5, 0.3, 0.2, 0.1, 0.05]
        result = forecaster(steep).forecast_risk("E1", 0.05, ForecastPeriod.DAYS_30)
        assert result.risk_score >= 0.0

    def test_trend_prediction_is_bounded(self):
        steep = [0.1, 0.4, 0.7, 0.9, 0.99]
        forecast = forecaster(steep).predict_risk_trend("E1", 0.99)
        assert 0.0 <= forecast.predicted_risk <= 1.0


class TestConfidence:
    def test_no_history_scores_low(self):
        result = forecaster().forecast_risk("NEW", 0.4, ForecastPeriod.DAY_1)
        assert result.confidence == RiskForecaster.NO_HISTORY_CONFIDENCE

    def test_a_clean_trend_outscores_a_noisy_one(self):
        clean = forecaster([0.1, 0.2, 0.3, 0.4, 0.5])
        noisy = forecaster([0.1, 0.9, 0.2, 0.8, 0.3])
        assert (
            clean.forecast_risk("E1", 0.5, ForecastPeriod.DAY_1).confidence
            > noisy.forecast_risk("E1", 0.3, ForecastPeriod.DAY_1).confidence
        )

    def test_more_history_raises_confidence(self):
        short = forecaster([0.1, 0.2, 0.3])
        long = forecaster([round(0.1 + 0.01 * i, 3) for i in range(30)])
        assert (
            long.forecast_risk("E1", 0.4, ForecastPeriod.DAY_1).confidence
            > short.forecast_risk("E1", 0.3, ForecastPeriod.DAY_1).confidence
        )

    def test_confidence_never_exceeds_the_cap(self):
        series = [round(0.01 * i, 4) for i in range(60)]
        result = forecaster(series).forecast_risk("E1", 0.6, ForecastPeriod.DAY_1)
        assert result.confidence <= 0.95


class TestTimeToPeak:
    def test_a_rising_trend_reports_a_derived_horizon(self):
        forecast = forecaster(RISING).predict_risk_trend("E1", 0.5)
        assert forecast.time_to_peak is not None

    def test_a_falling_trend_has_no_peak(self):
        assert forecaster(FALLING).predict_risk_trend("E1", 0.5).time_to_peak is None

    def test_a_stable_trend_has_no_peak(self):
        assert forecaster(FLAT).predict_risk_trend("E1", 0.5).time_to_peak is None

    def test_a_faster_climb_peaks_sooner(self):
        """`random.randint(1, 14)` days bore no relation to the climb rate."""
        slow = forecaster([0.10, 0.11, 0.12, 0.13, 0.14]).predict_risk_trend("E1", 0.14)
        fast = forecaster([0.10, 0.30, 0.50, 0.70, 0.90]).predict_risk_trend("E1", 0.90)
        assert slow.time_to_peak != fast.time_to_peak

    def test_an_entity_already_at_peak_says_so(self):
        series = [0.96, 0.97, 0.98, 0.99, 1.0]
        assert forecaster(series).predict_risk_trend("E1", 1.0).time_to_peak == "already at peak"


class TestFactors:
    def test_factors_describe_the_actual_movement(self):
        result = forecaster(FALLING).forecast_risk("E1", 0.5, ForecastPeriod.DAY_1)
        trend_factor = result.factors[0]
        assert trend_factor["factor"] == "historical_risk_trend"
        assert trend_factor["direction"] == "DECREASING"
        assert trend_factor["contribution"] < 0

    def test_factors_state_insufficient_history_when_that_is_the_case(self):
        result = forecaster().forecast_risk("NEW", 0.4, ForecastPeriod.DAY_1)
        assert result.factors[0]["factor"] == "insufficient_history"

    def test_metadata_exposes_the_fit(self):
        result = forecaster(RISING).forecast_risk("E1", 0.5, ForecastPeriod.DAY_1)
        assert result.metadata["slope_per_hour"] > 0
        assert result.metadata["observation_count"] >= len(RISING)
        assert 0.0 <= result.metadata["r_squared"] <= 1.0

    def test_volatility_reflects_the_residual_spread(self):
        clean = forecaster([0.1, 0.2, 0.3, 0.4, 0.5]).forecast_risk(
            "E1", 0.5, ForecastPeriod.DAY_1
        )
        noisy = forecaster([0.1, 0.9, 0.2, 0.8, 0.3]).forecast_risk(
            "E1", 0.3, ForecastPeriod.DAY_1
        )
        assert noisy.metadata["volatility"] > clean.metadata["volatility"]


class TestObservationStore:
    def test_observations_are_recorded_in_order(self):
        store = seed(PredictiveStore(), [0.1, 0.2, 0.3])

        assert [risk for _, risk in store.get_risk_observations("E1")] == [0.1, 0.2, 0.3]

    def test_an_unknown_entity_has_no_observations(self):
        assert PredictiveStore().get_risk_observations("NOBODY") == []

    def test_risk_values_are_clamped(self):
        store = PredictiveStore()
        store.record_risk_observation("E1", 5.0)
        store.record_risk_observation("E1", -2.0)

        assert [risk for _, risk in store.get_risk_observations("E1")] == [1.0, 0.0]

    def test_naive_timestamps_are_treated_as_utc(self):
        store = PredictiveStore()
        store.record_risk_observation("E1", 0.5, datetime(2026, 1, 1, 12, 0, 0))

        assert store.get_risk_observations("E1")[0][0].tzinfo is not None

    def test_history_is_bounded_per_entity(self):
        store = PredictiveStore()
        limit = PredictiveStore.MAX_OBSERVATIONS_PER_ENTITY
        for i in range(limit + 50):
            store.record_risk_observation("E1", 0.5, BASE + timedelta(minutes=i))

        assert len(store.get_risk_observations("E1")) == limit

    def test_observations_returned_are_a_copy(self):
        store = PredictiveStore()
        store.record_risk_observation("E1", 0.5)

        store.get_risk_observations("E1").clear()

        assert store.get_risk_observations("E1")

    def test_recording_through_the_forecaster_feeds_the_fit(self):
        instance = RiskForecaster(store=PredictiveStore())
        base = recent_base(len(FALLING))
        for hour, risk in enumerate(FALLING):
            instance.record_observation("E1", risk, base + timedelta(hours=hour))

        assert instance.predict_risk_trend("E1", 0.5).risk_trend == "DECREASING"


class TestDegenerateSeries:
    def test_observations_sharing_one_timestamp_yield_no_trend(self):
        instant = datetime.now(timezone.utc)
        observations = [(instant, 0.2), (instant, 0.5), (instant, 0.8)]

        slope, _, _ = RiskForecaster(store=PredictiveStore())._fit_trend(observations)

        assert slope is None

    def test_two_observations_are_below_the_fitting_threshold(self):
        now = datetime.now(timezone.utc)
        observations = [(now - timedelta(hours=1), 0.2), (now, 0.8)]

        slope, _, _ = RiskForecaster(store=PredictiveStore())._fit_trend(observations)

        assert slope is None

    def test_every_declared_period_has_a_horizon(self):
        for period in ForecastPeriod:
            assert RiskForecaster.PERIOD_HOURS[period] > 0
