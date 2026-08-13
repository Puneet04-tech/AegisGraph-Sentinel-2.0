"""Honeypot statistics must not be seeded with pilot-study figures (Issue #3509).

A fresh ``HoneypotEscrowManager`` used to report fabricated operational
metrics (38 activated, 27 arrests, 4.7 crore recovered, 12-minute average
response time) from the HDFC Mumbai pilot study, corrupting SOC reports and
anchoring the running average to phantom prior arrests. These tests pin the
zero-based statistics and the true-mean running average.
"""

from datetime import datetime, timedelta

import pytest

from src.features.honeypot_escrow import HoneypotEscrowManager


def _activate_withdraw_and_arrest(manager, index: int, response_minutes: float):
    hp = manager.activate_honeypot(
        transaction_id=f"TXN-{index}",
        source_account=f"SRC-{index}",
        target_account=f"MULE-{index}",
        amount=100.0,
        currency="USD",
        risk_score=0.95,
        fraud_indicators=["mule_to_mule"],
    )
    manager.record_withdrawal_attempt(
        f"MULE-{index}", "ATM", 50.0, {"address": "122 Main St"}
    )
    attempt_time = datetime.now() - timedelta(minutes=response_minutes)
    hp.withdrawal_attempts[0]["timestamp"] = attempt_time.isoformat()
    arrest_time = (attempt_time + timedelta(minutes=response_minutes)).isoformat()
    manager.record_arrest(hp.honeypot_id, {"arrest_time": arrest_time})


class TestZeroSeededStatistics:
    def test_fresh_manager_reports_zeroed_stats(self):
        stats = HoneypotEscrowManager().get_statistics()
        assert stats["total_activated"] == 0
        assert stats["total_arrests"] == 0
        assert stats["networks_dismantled"] == 0
        assert stats["total_recovered"] == 0
        assert stats["false_positives"] == 0
        assert stats["avg_time_to_arrest_minutes"] == 0

    def test_first_arrest_seeds_average(self):
        manager = HoneypotEscrowManager()
        _activate_withdraw_and_arrest(manager, 0, response_minutes=10.0)
        stats = manager.get_statistics()
        assert stats["total_arrests"] == 1
        assert stats["avg_time_to_arrest_minutes"] == pytest.approx(10.0)

    def test_average_after_arrests_equals_true_mean(self):
        manager = HoneypotEscrowManager()
        response_times = [10.0, 20.0, 30.0]
        for i, response_minutes in enumerate(response_times):
            _activate_withdraw_and_arrest(manager, i, response_minutes)

        stats = manager.get_statistics()
        assert stats["total_arrests"] == 3
        expected = sum(response_times) / len(response_times)
        assert stats["avg_time_to_arrest_minutes"] == pytest.approx(expected)

    def test_pilot_figures_live_only_in_reference_field(self):
        manager = HoneypotEscrowManager()
        assert manager.pilot_study_reference["total_arrests"] == 27
        # The reference is never merged into live statistics.
        assert manager.stats["total_arrests"] == 0
        assert manager.stats["total_activated"] == 0
