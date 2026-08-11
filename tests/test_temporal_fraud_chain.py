"""Regression tests for temporal fraud chain detection in FraudPatternDetector."""

from datetime import datetime, timezone, timedelta

import pytest

from src.features.fraud_pattern_detector import FraudPatternDetector

REFERENCE_TIME = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)


def _txn(source, target, timestamp, amount=100.0):
    return {
        "source_account": source,
        "target_account": target,
        "amount": amount,
        "timestamp": timestamp,
    }


def _iso(dt):
    return dt.isoformat()


class TestRapidBurstDetection:
    """Maximal rapid-transfer bursts must be detected regardless of where the
    burst starts in the account's timeline."""

    def test_burst_after_slow_first_gap_is_detected(self):
        """A 3-transfer burst occurring after a long pause must be flagged."""
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(hours=3))),
            _txn("A", "X3", _iso(t0 + timedelta(hours=3, minutes=10))),
            _txn("A", "X4", _iso(t0 + timedelta(hours=3, minutes=20))),
        ]

        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
        chain = chains[0]
        assert chain["account"] == "A"
        assert chain["num_rapid_transfers"] == 2
        assert chain["timespan_hours"] == pytest.approx(20 / 60)

    def test_chain_starting_at_first_transaction_detected(self):
        """The original happy path: first gap is already rapid."""
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(minutes=10))),
            _txn("A", "X3", _iso(t0 + timedelta(minutes=20))),
        ]

        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
        assert chains[0]["num_rapid_transfers"] == 2
        assert chains[0]["timespan_hours"] == pytest.approx(20 / 60)

    def test_slow_tail_chain_not_flagged(self):
        """A chain whose later gaps exceed the window must not be reported."""
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("B", "X1", _iso(t0)),
            _txn("B", "X2", _iso(t0 + timedelta(minutes=10))),
            _txn("B", "X3", _iso(t0 + timedelta(hours=5))),
        ]

        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert chains == []

    def test_only_slow_transfers_not_flagged(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(hours=2))),
            _txn("A", "X3", _iso(t0 + timedelta(hours=4))),
        ]
        assert detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME) == []

    def test_two_separate_bursts_reported_separately(self):
        """A single account with two disjoint bursts yields two chains."""
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("C", "X1", _iso(t0)),
            _txn("C", "X2", _iso(t0 + timedelta(minutes=5))),
            _txn("C", "X3", _iso(t0 + timedelta(minutes=10))),
            _txn("C", "X4", _iso(t0 + timedelta(hours=6))),
            _txn("C", "X5", _iso(t0 + timedelta(hours=6, minutes=5))),
            _txn("C", "X6", _iso(t0 + timedelta(hours=6, minutes=10))),
        ]

        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 2
        for chain in chains:
            assert chain["num_rapid_transfers"] == 2
            assert chain["timespan_hours"] == pytest.approx(10 / 60)

    def test_reported_timespan_covers_full_burst(self):
        """timespan_hours spans first-to-last transfer of the burst."""
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(minutes=10))),
            _txn("A", "X3", _iso(t0 + timedelta(minutes=10))),
            _txn("A", "X4", _iso(t0 + timedelta(minutes=50))),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
        assert chains[0]["num_rapid_transfers"] == 3
        assert chains[0]["timespan_hours"] == pytest.approx(50 / 60)

    def test_risk_score_scales_with_burst_size(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", f"X{i}", _iso(t0 + timedelta(minutes=i)))
            for i in range(10)
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
        assert chains[0]["num_rapid_transfers"] == 9
        assert chains[0]["risk_score"] == pytest.approx(1.0)

    def test_detected_at_reference_time_set(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(minutes=5))),
            _txn("A", "X3", _iso(t0 + timedelta(minutes=10))),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert chains[0]["detected_at"] == REFERENCE_TIME


class TestBurstBoundaries:
    """Burst splitting must respect the rapid-transfer window exactly."""

    def test_gap_exactly_at_window_is_a_boundary(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(minutes=10))),
            _txn("A", "X3", _iso(t0 + timedelta(hours=1, minutes=10))),
            _txn("A", "X4", _iso(t0 + timedelta(hours=1, minutes=20))),
            _txn("A", "X5", _iso(t0 + timedelta(hours=1, minutes=30))),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        # txn2->txn3 gap is exactly 1.0h -> treated as a split; only the
        # 3-transfer tail burst (X3,X4,X5) qualifies.
        assert len(chains) == 1
        assert chains[0]["account"] == "A"
        assert chains[0]["num_rapid_transfers"] == 2

    def test_burst_of_two_not_flagged(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(minutes=5))),
            _txn("A", "X3", _iso(t0 + timedelta(hours=2))),
            _txn("A", "X4", _iso(t0 + timedelta(hours=3))),
        ]
        assert detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME) == []

    def test_min_chain_length_config_respected(self):
        detector = FraudPatternDetector(min_chain_length=4)
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", f"X{i}", _iso(t0 + timedelta(minutes=i * 5)))
            for i in range(3)
        ]
        # 3-transfer burst is below min_chain_length=4.
        assert detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME) == []


class TestInputHandling:
    """Robustness against missing and malformed inputs."""

    def test_empty_transactions(self):
        detector = FraudPatternDetector()
        assert detector.detect_temporal_fraud_chains([], REFERENCE_TIME) == []

    def test_single_transaction(self):
        detector = FraudPatternDetector()
        txns = [_txn("A", "X1", _iso(REFERENCE_TIME))]
        assert detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME) == []

    def test_missing_timestamp_skipped(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", None),
            _txn("A", "X2", _iso(t0)),
            _txn("A", "X3", _iso(t0 + timedelta(minutes=5))),
            _txn("A", "X4", _iso(t0 + timedelta(minutes=10))),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
        assert chains[0]["num_rapid_transfers"] == 2

    def test_epoch_float_timestamps_supported(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        epoch_secs = t0.timestamp()
        txns = [
            _txn("A", "X1", epoch_secs),
            _txn("A", "X2", epoch_secs + 600),
            _txn("A", "X3", epoch_secs + 1200),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1

    def test_unsorted_input_detected(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X3", _iso(t0 + timedelta(minutes=20))),
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(minutes=10))),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
        assert chains[0]["num_rapid_transfers"] == 2

    def test_multiple_accounts_isolated(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", _iso(t0)),
            _txn("A", "X2", _iso(t0 + timedelta(minutes=5))),
            _txn("A", "X3", _iso(t0 + timedelta(minutes=10))),
            _txn("B", "Y1", _iso(t0)),
            _txn("B", "Y2", _iso(t0 + timedelta(hours=9))),
            _txn("B", "Y3", _iso(t0 + timedelta(hours=18))),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
        assert chains[0]["account"] == "A"

    def test_missing_source_ignored(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            {"target_account": "X1", "amount": 100.0, "timestamp": _iso(t0)},
            {"target_account": "X2", "amount": 100.0, "timestamp": _iso(t0 + timedelta(minutes=5))},
            {"target_account": "X3", "amount": 100.0, "timestamp": _iso(t0 + timedelta(minutes=10))},
        ]
        assert detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME) == []


class TestNaiveDatetimeHandling:
    """Naive timestamps are interpreted as UTC, not rejected."""

    def test_naive_datetime_treated_as_utc(self):
        detector = FraudPatternDetector()
        t0 = datetime(2026, 7, 31, 12, 0, 0)
        txns = [
            _txn("A", "X1", t0.isoformat()),
            _txn("A", "X2", (t0 + timedelta(minutes=5)).isoformat()),
            _txn("A", "X3", (t0 + timedelta(minutes=10)).isoformat()),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1

    def test_timestamp_with_z_suffix(self):
        detector = FraudPatternDetector()
        t0 = REFERENCE_TIME
        txns = [
            _txn("A", "X1", t0.isoformat().replace("+00:00", "Z")),
            _txn("A", "X2", (t0 + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")),
            _txn("A", "X3", (t0 + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")),
        ]
        chains = detector.detect_temporal_fraud_chains(txns, REFERENCE_TIME)
        assert len(chains) == 1
