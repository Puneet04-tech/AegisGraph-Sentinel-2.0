"""Velocity risk computation.

`ProductionRiskScorer._compute_velocity_risk` returned the literal `0.3` for
every transaction, so a burst of transfers from one account and a single
monthly payment contributed identically to the composite score, and the
component could never move a transaction across a decision threshold.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from src.inference.velocity_risk import (
    DEFAULT_COLD_START_RISK,
    VelocityRiskCalculator,
    _to_epoch_seconds,
    get_velocity_calculator,
    reset_velocity_calculator,
)

BASE = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


@pytest.fixture
def calc() -> VelocityRiskCalculator:
    return VelocityRiskCalculator(min_baseline_samples=1000)


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_velocity_calculator()
    yield
    reset_velocity_calculator()


class TestBurstDetection:
    def test_a_burst_scores_higher_than_a_trickle(self, calc):
        for i in range(9):
            calc.record("burst", 1000.0, at(i), f"b{i}")
        calc.record("trickle", 1000.0, at(0), "t0")

        assert calc.score("burst", at(9)) > calc.score("trickle", at(9))

    def test_score_rises_with_transaction_count(self, calc):
        scores = []
        for i in range(10):
            calc.record("acct", 100.0, at(i), f"t{i}")
            scores.append(calc.score("acct", at(i)))

        assert scores == sorted(scores), "velocity should be monotonic in a burst"
        assert scores[-1] > scores[0]

    def test_a_large_amount_raises_risk_even_at_low_count(self, calc):
        calc.record("small", 10.0, at(0), "s0")
        calc.record("large", 500_000.0, at(0), "l0")

        assert calc.score("large", at(1)) > calc.score("small", at(1))

    def test_the_component_can_reach_the_top_of_its_range(self, calc):
        """The constant 0.3 could never approach 1.0."""
        for i in range(40):
            calc.record("hot", 100_000.0, at(i * 0.1), f"h{i}")

        assert calc.score("hot", at(4.0)) == pytest.approx(1.0)

    def test_scores_never_leave_the_unit_range(self, calc):
        for i in range(200):
            calc.record("acct", 10_000_000.0, at(i * 0.01), f"x{i}")
            assert 0.0 <= calc.score("acct", at(i * 0.01)) <= 1.0


class TestWindows:
    def test_events_outside_the_long_window_stop_counting(self, calc):
        for i in range(9):
            calc.record("acct", 1000.0, at(i), f"t{i}")
        hot = calc.score("acct", at(9))

        # Two hours later, everything has aged out of both windows.
        cold = calc.score("acct", at(7200))
        assert cold < hot

    def test_the_short_window_decays_before_the_long_one(self, calc):
        for i in range(9):
            calc.record("acct", 1000.0, at(i), f"t{i}")

        immediate = calc.score("acct", at(9))
        after_short_window = calc.score("acct", at(120))
        assert after_short_window < immediate

    def test_future_dated_events_do_not_count_towards_now(self, calc):
        """Clock skew must not let a future event inflate the current window."""
        for i in range(9):
            calc.record("acct", 1000.0, at(3600 + i), f"f{i}")

        assert calc.score("acct", at(0)) == pytest.approx(DEFAULT_COLD_START_RISK)


class TestColdStart:
    def test_an_unknown_account_returns_the_documented_default(self, calc):
        assert calc.score("never-seen", at(0)) == pytest.approx(DEFAULT_COLD_START_RISK)

    def test_an_empty_account_id_returns_the_default(self, calc):
        assert calc.score("", at(0)) == pytest.approx(DEFAULT_COLD_START_RISK)

    def test_a_single_transaction_is_low_risk(self, calc):
        calc.record("acct", 100.0, at(0), "t0")
        assert calc.score("acct", at(1)) < 0.3

    def test_a_transaction_does_not_raise_its_own_score(self, calc):
        """score_and_record must score before recording."""
        first = calc.score_and_record("acct", 100.0, at(0), "t0")
        assert first == pytest.approx(DEFAULT_COLD_START_RISK)


class TestBaselineRelativeScoring:
    def test_an_established_busy_account_is_not_punished_for_its_norm(self):
        """A merchant transacting at its usual rate should not saturate."""
        calc = VelocityRiskCalculator(min_baseline_samples=20)
        # 60 transactions spread over 2 hours: a steady, established rate.
        for i in range(60):
            calc.record("merchant", 100.0, at(i * 120), f"m{i}")

        steady = calc.score("merchant", at(60 * 120))
        assert steady < 0.5

    def test_a_spike_above_an_established_baseline_is_flagged(self):
        calc = VelocityRiskCalculator(min_baseline_samples=20)
        for i in range(60):
            calc.record("acct", 100.0, at(i * 120), f"m{i}")
        steady = calc.score("acct", at(60 * 120))

        # Now a sudden burst well above that established rate.
        start = 60 * 120
        for i in range(30):
            calc.record("acct", 100.0, at(start + i), f"burst{i}")

        assert calc.score("acct", at(start + 30)) > steady

    def test_baseline_is_ignored_until_enough_samples_exist(self, calc):
        """calc has min_baseline_samples=1000, so no baseline applies."""
        for i in range(5):
            calc.record("acct", 100.0, at(i * 600), f"t{i}")
        assert calc._baseline_rate(calc._accounts["acct"], at(3000).timestamp()) is None


class TestDeduplicationAndOrdering:
    def test_a_replayed_transaction_id_is_ignored(self, calc):
        assert calc.record("acct", 100.0, at(0), "same") is True
        assert calc.record("acct", 100.0, at(1), "same") is False
        assert len(calc._accounts["acct"].events) == 1

    def test_events_without_ids_are_all_recorded(self, calc):
        for i in range(5):
            calc.record("acct", 100.0, at(i))
        assert len(calc._accounts["acct"].events) == 5

    def test_out_of_order_timestamps_are_sorted(self, calc):
        calc.record("acct", 100.0, at(10), "a")
        calc.record("acct", 100.0, at(5), "b")
        calc.record("acct", 100.0, at(7), "c")

        moments = [m for m, _ in calc._accounts["acct"].events]
        assert moments == sorted(moments)

    def test_out_of_order_events_still_score_within_the_window(self, calc):
        for i in reversed(range(9)):
            calc.record("acct", 1000.0, at(i), f"t{i}")
        assert calc.score("acct", at(9)) > DEFAULT_COLD_START_RISK


class TestMalformedInput:
    def test_a_missing_account_is_rejected(self, calc):
        assert calc.record("", 100.0, at(0)) is False

    def test_a_negative_amount_is_treated_as_magnitude(self, calc):
        calc.record("neg", -5000.0, at(0), "n0")
        calc.record("pos", 5000.0, at(0), "p0")
        assert calc.score("neg", at(1)) == pytest.approx(calc.score("pos", at(1)))

    def test_a_zero_amount_is_still_counted(self, calc):
        for i in range(9):
            calc.record("acct", 0.0, at(i), f"z{i}")
        assert calc.score("acct", at(9)) > DEFAULT_COLD_START_RISK

    def test_an_unparseable_amount_falls_back_to_zero(self, calc):
        assert calc.record("acct", "not-a-number", at(0), "x") is True
        assert calc._accounts["acct"].events[0][1] == 0.0

    def test_an_unparseable_timestamp_falls_back_to_now(self, calc):
        assert calc.record("acct", 100.0, "not-a-date", "x") is True
        assert len(calc._accounts["acct"].events) == 1


class TestTimestampNormalisation:
    def test_every_form_resolves_to_the_same_instant(self):
        expected = BASE.timestamp()
        assert _to_epoch_seconds(BASE) == pytest.approx(expected)
        assert _to_epoch_seconds(expected) == pytest.approx(expected)
        assert _to_epoch_seconds(expected * 1000) == pytest.approx(expected)
        assert _to_epoch_seconds(BASE.isoformat()) == pytest.approx(expected)
        assert _to_epoch_seconds(
            BASE.isoformat().replace("+00:00", "Z")
        ) == pytest.approx(expected)

    def test_a_naive_datetime_is_treated_as_utc_not_local(self):
        naive = BASE.replace(tzinfo=None)
        assert _to_epoch_seconds(naive) == pytest.approx(BASE.timestamp())

    def test_unsupported_and_empty_values_return_none(self):
        assert _to_epoch_seconds(None) is None
        assert _to_epoch_seconds("") is None
        assert _to_epoch_seconds("garbage") is None
        assert _to_epoch_seconds(object()) is None


class TestBounds:
    def test_tracked_accounts_are_capped(self):
        calc = VelocityRiskCalculator(max_accounts=10)
        for i in range(50):
            calc.record(f"acct{i}", 100.0, at(i), f"t{i}")
        assert calc.tracked_accounts() == 10

    def test_events_per_account_are_capped(self):
        calc = VelocityRiskCalculator(max_events_per_account=20)
        for i in range(100):
            calc.record("acct", 100.0, at(i), f"t{i}")
        assert len(calc._accounts["acct"].events) == 20

    def test_the_oldest_account_is_evicted_first(self):
        calc = VelocityRiskCalculator(max_accounts=3)
        for name in ("a", "b", "c"):
            calc.record(name, 100.0, at(0), f"{name}0")
        calc.record("d", 100.0, at(1), "d0")

        assert "a" not in calc._accounts
        assert "d" in calc._accounts

    def test_reset_clears_history(self, calc):
        calc.record("acct", 100.0, at(0), "t0")
        calc.reset()
        assert calc.tracked_accounts() == 0


class TestConcurrency:
    def test_concurrent_recording_loses_nothing(self, calc):
        def writer(offset: int) -> None:
            for i in range(100):
                calc.record("shared", 100.0, at(offset * 100 + i), f"w{offset}_{i}")

        threads = [threading.Thread(target=writer, args=(o,)) for o in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        history = calc._accounts["shared"]
        assert history.total_events == 600
        moments = [m for m, _ in history.events]
        assert moments == sorted(moments)

    def test_concurrent_scoring_is_safe(self, calc):
        for i in range(50):
            calc.record("acct", 100.0, at(i), f"t{i}")
        errors = []

        def reader():
            try:
                for i in range(200):
                    assert 0.0 <= calc.score("acct", at(i)) <= 1.0
            except Exception as exc:  # pragma: no cover - surfaced by assertion
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


class TestSharedCalculator:
    def test_the_singleton_is_stable(self):
        assert get_velocity_calculator() is get_velocity_calculator()

    def test_reset_replaces_the_singleton(self):
        first = get_velocity_calculator()
        reset_velocity_calculator()
        assert get_velocity_calculator() is not first


class TestScorerIntegration:
    """The component must no longer be a constant in the composite score."""

    def _fake_scorer(self, calc):
        from src.inference.production_scorer import ProductionRiskScorer

        scorer = ProductionRiskScorer.__new__(ProductionRiskScorer)
        scorer.velocity_calculator = calc
        return scorer

    def test_velocity_varies_across_transactions(self, calc):
        scorer = self._fake_scorer(calc)
        scores = []
        for i in range(10):
            scores.append(
                scorer._compute_velocity_risk(
                    {
                        "source_account": "ACC1",
                        "amount": 1000.0,
                        "timestamp": at(i).isoformat(),
                        "transaction_id": f"T{i}",
                    }
                )
            )

        assert len(set(round(s, 6) for s in scores)) > 1, "still behaving like a constant"
        assert scores != [0.3] * 10

    def test_a_missing_account_falls_back_to_cold_start(self, calc):
        scorer = self._fake_scorer(calc)
        assert scorer._compute_velocity_risk({"amount": 100.0}) == pytest.approx(
            DEFAULT_COLD_START_RISK
        )

    def test_alternative_account_field_names_are_accepted(self, calc):
        scorer = self._fake_scorer(calc)
        for field in ("source_account", "from_account", "account_id"):
            result = scorer._compute_velocity_risk(
                {field: f"ACC_{field}", "amount": 100.0, "timestamp": at(0).isoformat()}
            )
            assert 0.0 <= result <= 1.0
        assert calc.tracked_accounts() == 3
