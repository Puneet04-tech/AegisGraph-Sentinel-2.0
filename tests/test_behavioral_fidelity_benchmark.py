
import pandas as pd
import pytest

from src.data.behavioral_fidelity_benchmark import (
    FidelityConfig,
    benchmark_behavioral_fidelity,
    build_transaction_graph,
)


def sample_transactions():
    return pd.DataFrame(
        {
            "source_account": [
                "A", "A", "A", "B", "C", "D", "E", "F", "G", "H"
            ],
            "target_account": [
                "B", "C", "D", "A", "A", "A", "F", "G", "E", "A"
            ],
            "amount": [
                5000, 4000, 3000, 2000, 1000, 500, 700, 800, 900, 12000
            ],
            "timestamp": pd.to_datetime(
                [
                    "2026-01-01 10:00:00",
                    "2026-01-01 10:03:00",
                    "2026-01-01 10:06:00",
                    "2026-01-01 10:20:00",
                    "2026-01-01 10:25:00",
                    "2026-01-01 10:30:00",
                    "2026-01-01 11:00:00",
                    "2026-01-01 11:05:00",
                    "2026-01-01 11:10:00",
                    "2026-01-01 11:15:00",
                ]
            ),
        }
    )


def test_benchmark_returns_expected_metric_keys():
    result = benchmark_behavioral_fidelity(sample_transactions())

    expected_keys = {
        "inter_event_time_score",
        "burst_pattern_score",
        "fan_in_out_motif_score",
        "circular_flow_count",
        "velocity_trigger_rate",
        "centrality_concentration_score",
        "overall_behavioral_fidelity",
    }

    assert expected_keys.issubset(result.keys())


def test_benchmark_scores_are_bounded():
    result = benchmark_behavioral_fidelity(sample_transactions())

    bounded_score_keys = [
        "inter_event_time_score",
        "burst_pattern_score",
        "fan_in_out_motif_score",
        "velocity_trigger_rate",
        "centrality_concentration_score",
        "overall_behavioral_fidelity",
    ]

    for key in bounded_score_keys:
        assert 0.0 <= result[key] <= 1.0


def test_detects_circular_transaction_flows():
    result = benchmark_behavioral_fidelity(sample_transactions())

    assert result["circular_flow_count"] >= 1


def test_build_transaction_graph_aggregates_duplicate_edges():
    df = pd.DataFrame(
        {
            "source_account": ["A", "A"],
            "target_account": ["B", "B"],
            "amount": [100, 200],
            "timestamp": pd.to_datetime(
                ["2026-01-01 10:00:00", "2026-01-01 10:01:00"]
            ),
        }
    )

    graph = build_transaction_graph(df)

    assert graph["A"]["B"]["weight"] == 300
    assert graph["A"]["B"]["count"] == 2


def test_missing_required_columns_raises_error():
    df = pd.DataFrame({"source_account": ["A"]})

    with pytest.raises(ValueError, match="Missing required transaction columns"):
        benchmark_behavioral_fidelity(df)


def test_custom_config_changes_velocity_behavior():
    df = sample_transactions()

    low_threshold = FidelityConfig(velocity_amount_threshold=1000)
    high_threshold = FidelityConfig(velocity_amount_threshold=999999)

    low_result = benchmark_behavioral_fidelity(df, low_threshold)
    high_result = benchmark_behavioral_fidelity(df, high_threshold)

    assert low_result["velocity_trigger_rate"] >= high_result["velocity_trigger_rate"]
