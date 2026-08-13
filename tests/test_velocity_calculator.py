"""
Tests for VelocityCalculator chain velocity metrics and core features.

Regression coverage for:
    - `calculate_chain_velocity` returning `float('inf')` when two
      transactions share the same timestamp (zero elapsed time), which
      is inconsistent with `compute_chain_velocity` (returns 0.0) and
      produces non-JSON-serializable values downstream.
    - `avg_hop_time` off-by-one: N transactions span N-1 hops, but the
      code divided total time by N, under-reporting average hop time.
"""

import json
import math

import networkx as nx
import pytest

from src.features.velocity_calculator import (
    VelocityCalculator,
    Transaction,
    compute_transaction_velocity_score,
)


@pytest.fixture
def calculator():
    return VelocityCalculator()


@pytest.fixture
def chain_graph():
    graph = nx.Graph()
    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "D")
    graph.add_edge("D", "E")
    return graph


def make_tx(source, target, amount, timestamp, txn_id):
    return Transaction(
        source=source,
        target=target,
        amount=amount,
        timestamp=timestamp,
        txn_id=txn_id,
    )


class TestZeroElapsedTime:
    """calculate_chain_velocity must not return infinity."""

    def test_simultaneous_transactions_return_zero(self, calculator):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
        ]
        assert calculator.calculate_chain_velocity(txs) == 0.0

    def test_result_is_json_serializable(self, calculator):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
        ]
        value = calculator.calculate_chain_velocity(txs)
        assert json.dumps({"velocity": value}) == '{"velocity": 0.0}'

    def test_result_is_not_infinite(self, calculator):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
        ]
        assert not math.isinf(calculator.calculate_chain_velocity(txs))

    def test_single_transaction_returns_zero(self, calculator):
        txs = [make_tx("A", "B", 100, 1000.0, "t1")]
        assert calculator.calculate_chain_velocity(txs) == 0.0

    def test_empty_transactions_returns_zero(self, calculator):
        assert calculator.calculate_chain_velocity([]) == 0.0

    def test_none_transactions_returns_zero(self, calculator):
        assert calculator.calculate_chain_velocity(None) == 0.0

    def test_graph_path_zero_time_returns_zero(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["chain_velocity"] == 0.0
        assert features["total_time"] == 0.0

    def test_score_pipeline_handles_simultaneous_chain(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
        ]
        score = compute_transaction_velocity_score(txs, 2000.0, chain_graph)
        assert 0.0 <= score <= 1.0


class TestChainVelocityNoGraph:
    """Legacy scalar chain velocity without a graph."""

    def test_sequential_velocity_formula(self, calculator):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1100.0, "t2"),
            make_tx("C", "D", 25, 1200.0, "t3"),
        ]
        assert calculator.calculate_chain_velocity(txs) == pytest.approx(2.0 / 200.0)

    def test_velocity_scales_with_frequency(self, calculator):
        fast = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1001.0, "t2"),
        ]
        slow = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1100.0, "t2"),
        ]
        assert calculator.calculate_chain_velocity(fast) > calculator.calculate_chain_velocity(slow)

    def test_normalizes_dict_input(self, calculator):
        raw = [
            {"from": "A", "to": "B", "amount": 100, "timestamp": 1000.0, "txn_id": "t1"},
            {"from": "B", "to": "C", "amount": 50, "timestamp": 1010.0, "txn_id": "t2"},
        ]
        assert calculator.calculate_chain_velocity(raw) == pytest.approx(1.0 / 10.0)

    def test_unsorted_input_is_sorted(self, calculator):
        txs = [
            make_tx("A", "B", 100, 1100.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
        ]
        assert calculator.calculate_chain_velocity(txs) == pytest.approx(1.0 / 100.0)


class TestAvgHopTime:
    """avg_hop_time must divide by the number of hops, not transactions."""

    def test_two_transactions_one_hop(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1100.0, "t2"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["avg_hop_time"] == pytest.approx(100.0)

    def test_three_transactions_two_hops(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1100.0, "t2"),
            make_tx("C", "D", 25, 1200.0, "t3"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["avg_hop_time"] == pytest.approx(100.0)

    def test_uneven_hops_average(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1005.0, "t2"),
            make_tx("C", "D", 25, 1015.0, "t3"),
            make_tx("D", "E", 12, 1045.0, "t4"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["avg_hop_time"] == pytest.approx(45.0 / 3.0)

    def test_hop_time_matches_manual_sum(self, calculator, chain_graph):
        timestamps = [1000.0, 1030.0, 1031.0]
        txs = [
            make_tx("A", "B", 100, timestamps[0], "t1"),
            make_tx("B", "C", 50, timestamps[1], "t2"),
            make_tx("C", "D", 25, timestamps[2], "t3"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        hops = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]
        assert features["avg_hop_time"] == pytest.approx(sum(hops) / len(hops))

    def test_single_transaction_hop_time_zero(self, calculator, chain_graph):
        txs = [make_tx("A", "B", 100, 1000.0, "t1")]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["avg_hop_time"] == 0.0

    def test_zero_elapsed_time_hop_time_zero(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["avg_hop_time"] == 0.0


class TestChainVelocityMetrics:
    """Other chain velocity output metrics."""

    def test_velocity_is_distance_over_time(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1005.0, "t2"),
            make_tx("C", "D", 25, 1010.0, "t3"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["chain_velocity"] == pytest.approx(features["total_distance"] / 10.0)

    def test_total_time_spans_first_to_last(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1005.0, "t2"),
            make_tx("C", "D", 25, 1035.0, "t3"),
        ]
        features = calculator.compute_chain_velocity(txs, chain_graph)
        assert features["total_time"] == pytest.approx(35.0)

    def test_missing_edge_uses_chain_length_proxy(self, calculator):
        graph = nx.Graph()
        graph.add_edge("X", "Y")
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1010.0, "t2"),
        ]
        features = calculator.compute_chain_velocity(txs, graph)
        assert features["total_distance"] == 2

    def test_missing_source_node_does_not_raise(self, calculator):
        graph = nx.Graph()
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1010.0, "t2"),
        ]
        features = calculator.compute_chain_velocity(txs, graph)
        assert features["total_distance"] == 2


class TestKineticEnergy:
    """Kinetic energy feature."""

    def test_single_transaction_zero(self, calculator):
        txs = [make_tx("A", "B", 100, 1000.0, "t1")]
        assert calculator.compute_kinetic_energy(txs) == 0.0

    def test_rapid_transfers_spike_energy(self, calculator):
        rapid = [
            make_tx("A", "B", 1000, 1000.0, "t1"),
            make_tx("B", "C", 1000, 1001.0, "t2"),
        ]
        slow = [
            make_tx("A", "B", 1000, 1000.0, "t1"),
            make_tx("B", "C", 1000, 1100.0, "t2"),
        ]
        assert calculator.compute_kinetic_energy(rapid) > calculator.compute_kinetic_energy(slow)

    def test_energy_uses_squared_amount(self, calculator):
        txs = [
            make_tx("A", "B", 10, 1000.0, "t1"),
            make_tx("B", "C", 20, 1010.0, "t2"),
        ]
        assert calculator.compute_kinetic_energy(txs) == pytest.approx(400.0 / 10.0)

    def test_sorted_chronologically(self, calculator):
        txs = [
            make_tx("A", "B", 10, 1010.0, "t1"),
            make_tx("B", "C", 20, 1000.0, "t2"),
        ]
        assert calculator.compute_kinetic_energy(txs) == pytest.approx(100.0 / 10.0)


class TestBurstDetection:
    """Burst detection feature."""

    def test_no_transactions_no_burst(self, calculator):
        features = calculator.detect_burst([], 2000.0)
        assert features["burst_count"] == 0
        assert features["burst_score"] == 0.0

    def test_burst_in_window_raises_score(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
            make_tx("C", "D", 25, 20.0, "t3"),
        ]
        burst = calculator.detect_burst(txs, 30.0)
        baseline = calculator.detect_burst(txs, 4000.0)
        assert burst["burst_score"] > baseline["burst_score"]

    def test_burst_amount_summed(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
            make_tx("C", "D", 25, 2000.0, "t3"),
        ]
        features = calculator.detect_burst(txs, 30.0)
        assert features["burst_amount"] == pytest.approx(150.0)

    def test_past_beyond_window_excluded_from_recent(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
            make_tx("C", "D", 25, 2000.0, "t3"),
        ]
        features = calculator.detect_burst(txs, 30.0)
        assert features["burst_count"] == 2

    def test_future_transactions_excluded_from_recent(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 4000.0, "t2"),
        ]
        features = calculator.detect_burst(txs, 30.0)
        assert features["burst_count"] == 1

    def test_baseline_excludes_old_transactions(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
            make_tx("C", "D", 25, 20000.0, "t3"),
        ]
        features = calculator.detect_burst(txs, 30.0)
        assert features["avg_baseline_amount"] == pytest.approx(75.0)
        assert features["baseline_rate"] == pytest.approx(2.0 / 3600.0)

    def test_burst_score_uses_correct_recent_window(self, calculator):
        old = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
            make_tx("C", "D", 25, 2000.0, "t3"),
        ]
        clean = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
        ]
        old_features = calculator.detect_burst(old, 30.0)
        clean_features = calculator.detect_burst(clean, 30.0)
        assert old_features["burst_count"] == clean_features["burst_count"]
        assert old_features["burst_amount"] == clean_features["burst_amount"]

    def test_transaction_inside_burst_window_counted(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 299.0, "t2"),
            make_tx("C", "D", 25, 300.0, "t3"),
        ]
        features = calculator.detect_burst(txs, 300.0)
        assert features["burst_count"] == 3


class TestAcceleration:
    """Acceleration feature."""

    def test_short_sequence_zero(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
        ]
        assert calculator.compute_acceleration(txs) == 0.0

    def test_finite_acceleration(self, calculator):
        txs = [
            make_tx("A", "B", 100, 0.0, "t1"),
            make_tx("B", "C", 50, 10.0, "t2"),
            make_tx("C", "D", 25, 20.0, "t3"),
            make_tx("D", "E", 12, 30.0, "t4"),
        ]
        acceleration = calculator.compute_acceleration(txs)
        assert isinstance(acceleration, float)
        assert not math.isnan(acceleration)

    def test_zero_total_time_returns_zero(self, calculator):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1000.0, "t2"),
            make_tx("C", "D", 25, 1000.0, "t3"),
        ]
        assert calculator.compute_acceleration(txs) == 0.0

    def test_unsorted_input_sequence_sorted_before_acceleration(self, calculator):
        unsorted_txs = [
            make_tx("C", "D", 25, 40.0, "t3"),
            make_tx("A", "B", 100, 10.0, "t1"),
            make_tx("B", "C", 50, 20.0, "t2"),
        ]
        sorted_txs = [
            make_tx("A", "B", 100, 10.0, "t1"),
            make_tx("B", "C", 50, 20.0, "t2"),
            make_tx("C", "D", 25, 40.0, "t3"),
        ]
        acc_unsorted = calculator.compute_acceleration(unsorted_txs)
        acc_sorted = calculator.compute_acceleration(sorted_txs)
        assert acc_unsorted == pytest.approx(acc_sorted)

    def test_even_length_transaction_sequence_no_overlap(self, calculator):
        # 4 transactions: index 2 should not be shared in first_half
        txs = [
            make_tx("A", "B", 100, 10.0, "t1"),
            make_tx("B", "C", 100, 20.0, "t2"),
            make_tx("C", "D", 500, 30.0, "t3"),
            make_tx("D", "E", 100, 40.0, "t4"),
        ]
        # v1: first 2 txs [10, 20] -> total_amount=200, time=10 -> v1=20.0
        # v2: last 2 txs [30, 40] -> total_amount=600, time=10 -> v2=60.0
        # t1=10, t2=10 -> total_time=20
        # acceleration = (60 - 20) / 20 = 2.0
        acc = calculator.compute_acceleration(txs)
        assert acc == pytest.approx(2.0)

    def test_odd_length_transaction_sequence_bounds(self, calculator):
        txs = [
            make_tx("A", "B", 100, 10.0, "t1"),
            make_tx("B", "C", 100, 20.0, "t2"),
            make_tx("C", "D", 200, 30.0, "t3"),
            make_tx("D", "E", 200, 40.0, "t4"),
            make_tx("E", "F", 300, 50.0, "t5"),
        ]
        acc = calculator.compute_acceleration(txs)
        assert isinstance(acc, float)
        assert not math.isnan(acc)


class TestComputeAllFeatures:
    """Aggregate feature computation and risk score."""

    def test_full_feature_set(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1010.0, "t2"),
            make_tx("C", "D", 25, 1020.0, "t3"),
        ]
        features = calculator.compute_all_features(txs, 2000.0, chain_graph)
        assert "kinetic_energy" in features
        assert "chain_chain_velocity" in features
        assert "burst_burst_score" in features
        assert "acceleration" in features
        assert features["num_transactions"] == 3

    def test_no_graph_omits_chain_features(self, calculator):
        txs = [
            make_tx("A", "B", 100, 1000.0, "t1"),
            make_tx("B", "C", 50, 1010.0, "t2"),
        ]
        features = calculator.compute_all_features(txs, 2000.0)
        assert "chain_chain_velocity" not in features

    def test_empty_input_features(self, calculator):
        features = calculator.compute_all_features([], 2000.0)
        assert features["kinetic_energy"] == 0.0
        assert features["acceleration"] == 0.0

    def test_score_in_unit_range(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 1000, 1000.0, "t1"),
            make_tx("B", "C", 1000, 1001.0, "t2"),
            make_tx("C", "D", 1000, 1002.0, "t3"),
            make_tx("D", "E", 1000, 1003.0, "t4"),
        ]
        score = compute_transaction_velocity_score(txs, 2000.0, chain_graph)
        assert 0.0 <= score <= 1.0

    def test_risk_score_never_exceeds_one(self, calculator, chain_graph):
        txs = [
            make_tx("A", "B", 1e9, 1000.0, "t1"),
            make_tx("B", "C", 1e9, 1000.001, "t2"),
        ]
        score = compute_transaction_velocity_score(txs, 2000.0, chain_graph)
        assert score <= 1.0
