"""Tests for inference latency measurement and optimization.

Timing is measured through an injected fake clock so percentiles are
exact and the suite never depends on wall-clock speed.
"""
from __future__ import annotations

import os

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# Handle optional torch dependency
try:
    import torch
    import torch.nn as nn
    from src.inference.optimization import (
        LatencyReport,
        benchmark_latency,
        cap_subgraph_edges,
        count_quantizable_modules,
        percentile,
        quantize_model_dynamic,
    )
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


class FakeClock:
    """Clock advancing by a scripted sequence of durations (seconds)."""

    def __init__(self, durations):
        self._durations = list(durations)
        self._now = 0.0
        self._pending = None

    def __call__(self) -> float:
        if self._pending is None:
            # Start of a measured interval
            self._pending = self._durations.pop(0) if self._durations else 0.0
            return self._now
        # End of the interval: advance by the scripted duration
        self._now += self._pending
        self._pending = None
        return self._now


def _subgraph(n_edges: int, n_nodes: int = 6):
    return {
        "x": torch.ones(n_nodes, 3),
        "edge_index": torch.arange(2 * n_edges).reshape(2, n_edges) % n_nodes,
        "edge_type": torch.zeros(n_edges, dtype=torch.long),
        "edge_attr": torch.ones(n_edges, 2),
        "node_type": torch.zeros(n_nodes, dtype=torch.long),
        "num_nodes": n_nodes,
    }


class TestPercentile:
    def test_p99_of_hundred_is_the_ninety_ninth_value(self):
        # Nearest rank: p99 of 1..100 is 99, NOT the maximum
        assert percentile(list(range(1, 101)), 99) == 99.0

    @pytest.mark.parametrize(
        ("q", "expected"),
        [(0, 1.0), (50, 50.0), (95, 95.0), (99, 99.0), (100, 100.0)],
    )
    def test_known_quantiles_over_one_to_hundred(self, q, expected):
        assert percentile(list(range(1, 101)), q) == expected

    def test_reported_value_was_actually_observed(self):
        values = [10.0, 20.0, 30.0]

        assert percentile(values, 99) in values
        assert percentile(values, 50) in values

    def test_input_order_does_not_matter(self):
        assert percentile([5.0, 1.0, 3.0], 50) == percentile([1.0, 3.0, 5.0], 50)

    def test_single_value(self):
        assert percentile([7.5], 99) == 7.5

    def test_empty_values_rejected(self):
        with pytest.raises(ValueError):
            percentile([], 50)

    @pytest.mark.parametrize("bad_q", [-1, 101, 250])
    def test_out_of_range_quantile_rejected(self, bad_q):
        with pytest.raises(ValueError):
            percentile([1.0, 2.0], bad_q)


class TestBenchmarkLatency:
    def test_reports_exact_distribution_from_scripted_timings(self):
        # 10 runs of 1ms..10ms
        durations = [i / 1000.0 for i in range(1, 11)]
        report = benchmark_latency(
            lambda: None, n_runs=10, n_warmup=0, timer=FakeClock(durations)
        )

        assert isinstance(report, LatencyReport)
        assert report.n_runs == 10
        assert report.min_ms == pytest.approx(1.0)
        assert report.max_ms == pytest.approx(10.0)
        assert report.mean_ms == pytest.approx(5.5)
        assert report.p50_ms == pytest.approx(5.0)
        assert report.p99_ms == pytest.approx(10.0)

    def test_warmup_runs_are_executed_but_not_measured(self):
        calls = []
        durations = [0.001] * 10
        report = benchmark_latency(
            lambda: calls.append(1),
            n_runs=4,
            n_warmup=6,
            timer=FakeClock(durations),
        )

        assert len(calls) == 10  # 6 warmup + 4 measured
        assert report.n_runs == 4

    def test_meets_budget_compares_p99(self):
        durations = [0.05] * 5
        report = benchmark_latency(
            lambda: None, n_runs=5, n_warmup=0, timer=FakeClock(durations)
        )

        assert report.meets_budget(200.0) is True
        assert report.meets_budget(10.0) is False

    def test_to_dict_exposes_all_percentiles(self):
        report = benchmark_latency(
            lambda: None, n_runs=2, n_warmup=0, timer=FakeClock([0.001, 0.002])
        )

        assert set(report.to_dict()) == {
            "n_runs", "mean_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms",
        }

    def test_real_clock_produces_sane_numbers(self):
        report = benchmark_latency(lambda: sum(range(100)), n_runs=20, n_warmup=2)

        assert report.n_runs == 20
        assert report.min_ms <= report.p50_ms <= report.p99_ms <= report.max_ms
        assert report.min_ms >= 0.0

    @pytest.mark.parametrize(("n_runs", "n_warmup"), [(0, 0), (-1, 0), (5, -1)])
    def test_invalid_counts_rejected(self, n_runs, n_warmup):
        with pytest.raises(ValueError):
            benchmark_latency(lambda: None, n_runs=n_runs, n_warmup=n_warmup)


class TestQuantization:
    def test_counts_linear_layers(self):
        model = nn.Sequential(nn.Linear(4, 4), nn.ReLU(), nn.Linear(4, 1))

        assert count_quantizable_modules(model) == 2
        assert count_quantizable_modules(nn.ReLU()) == 0

    def test_quantizes_linear_layers_and_preserves_output_shape(self):
        model = nn.Sequential(nn.Linear(8, 8), nn.ReLU(), nn.Linear(8, 1))
        model.eval()
        x = torch.randn(3, 8)
        original = model(x)

        quantized, n_quantized = quantize_model_dynamic(model)

        assert n_quantized == 2
        assert quantized(x).shape == original.shape

    def test_quantized_output_stays_close_to_original(self):
        torch.manual_seed(0)
        model = nn.Sequential(nn.Linear(16, 16), nn.ReLU(), nn.Linear(16, 1))
        model.eval()
        x = torch.randn(4, 16)
        expected = model(x)

        quantized, _ = quantize_model_dynamic(model)

        # INT8 trades a little precision for speed; it must not change
        # predictions in any way that would move a decision
        assert torch.allclose(quantized(x), expected, atol=0.1)

    def test_model_without_linear_layers_is_returned_unchanged(self):
        model = nn.Sequential(nn.ReLU())

        returned, n_quantized = quantize_model_dynamic(model)

        assert returned is model
        assert n_quantized == 0

    def test_failure_degrades_to_original_model(self, monkeypatch):
        model = nn.Sequential(nn.Linear(4, 1))

        def boom(*args, **kwargs):
            raise RuntimeError("no quantization backend")

        monkeypatch.setattr("torch.ao.quantization.quantize_dynamic", boom)

        returned, n_quantized = quantize_model_dynamic(model)

        # Serving unquantized beats failing to serve
        assert returned is model
        assert n_quantized == 0


class TestSubgraphEdgeCap:
    def test_truncates_edges_and_aligned_tensors(self):
        capped = cap_subgraph_edges(_subgraph(n_edges=50), max_edges=10)

        assert capped["edge_index"].size(1) == 10
        assert capped["edge_type"].size(0) == 10
        assert capped["edge_attr"].size(0) == 10

    def test_node_features_are_left_intact(self):
        original = _subgraph(n_edges=50)
        capped = cap_subgraph_edges(original, max_edges=5)

        assert torch.equal(capped["x"], original["x"])
        assert capped["num_nodes"] == original["num_nodes"]

    def test_edge_index_stays_within_node_range(self):
        capped = cap_subgraph_edges(_subgraph(n_edges=40, n_nodes=6), max_edges=7)

        assert int(capped["edge_index"].max()) < capped["num_nodes"]

    def test_input_is_not_mutated(self):
        original = _subgraph(n_edges=30)
        cap_subgraph_edges(original, max_edges=4)

        assert original["edge_index"].size(1) == 30

    def test_subgraph_under_budget_is_returned_unchanged(self):
        original = _subgraph(n_edges=3)
        capped = cap_subgraph_edges(original, max_edges=10)

        assert capped is original

    def test_none_budget_disables_capping(self):
        original = _subgraph(n_edges=1000)

        assert cap_subgraph_edges(original, None) is original

    def test_empty_edge_set_is_handled(self):
        empty = dict(_subgraph(n_edges=0), edge_index=torch.zeros(2, 0, dtype=torch.long))

        assert cap_subgraph_edges(empty, max_edges=5) is empty

    def test_negative_budget_rejected(self):
        with pytest.raises(ValueError):
            cap_subgraph_edges(_subgraph(n_edges=5), max_edges=-1)
