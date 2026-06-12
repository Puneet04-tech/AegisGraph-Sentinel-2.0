
"""
Behavioral fidelity benchmark for synthetic mule transaction graphs.

This module evaluates whether synthetic transaction data preserves
important temporal and graph-based mule/fraud behavior patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional

import networkx as nx
import numpy as np
import pandas as pd


REQUIRED_COLUMNS = {
    "source_account",
    "target_account",
    "amount",
    "timestamp",
}


@dataclass(frozen=True)
class FidelityConfig:
    burst_window_minutes: int = 10
    burst_min_transactions: int = 3
    velocity_window_minutes: int = 60
    velocity_amount_threshold: float = 10_000.0
    circular_path_max_length: int = 4
    fan_degree_threshold: int = 3


def _validate_transactions(df: pd.DataFrame) -> None:
    missing = REQUIRED_COLUMNS.difference(df.columns)
    if missing:
        raise ValueError(f"Missing required transaction columns: {sorted(missing)}")

    if df.empty:
        raise ValueError("Transaction dataframe cannot be empty")


def _prepare_transactions(df: pd.DataFrame) -> pd.DataFrame:
    _validate_transactions(df)

    prepared = df.copy()
    prepared["timestamp"] = pd.to_datetime(prepared["timestamp"], errors="coerce")

    if prepared["timestamp"].isna().any():
        raise ValueError("Timestamp column contains invalid datetime values")

    prepared["amount"] = pd.to_numeric(prepared["amount"], errors="coerce")

    if prepared["amount"].isna().any():
        raise ValueError("Amount column contains non-numeric values")

    return prepared.sort_values("timestamp").reset_index(drop=True)


def _account_event_times(df: pd.DataFrame) -> pd.DataFrame:
    outgoing = df[["source_account", "timestamp"]].rename(
        columns={"source_account": "account"}
    )
    incoming = df[["target_account", "timestamp"]].rename(
        columns={"target_account": "account"}
    )
    return pd.concat([outgoing, incoming], ignore_index=True).sort_values(
        ["account", "timestamp"]
    )


def inter_event_time_score(df: pd.DataFrame) -> float:
    events = _account_event_times(df)
    diffs = (
        events.groupby("account")["timestamp"]
        .diff()
        .dt.total_seconds()
        .dropna()
    )

    if diffs.empty:
        return 0.0

    median_gap = float(diffs.median())
    mean_gap = float(diffs.mean())

    if mean_gap == 0:
        return 1.0

    score = 1.0 - min(abs(mean_gap - median_gap) / max(mean_gap, 1.0), 1.0)
    return round(float(score), 4)


def burst_pattern_score(df: pd.DataFrame, config: FidelityConfig) -> float:
    events = _account_event_times(df)
    burst_accounts = 0
    total_accounts = events["account"].nunique()

    if total_accounts == 0:
        return 0.0

    window = pd.Timedelta(minutes=config.burst_window_minutes)

    for _, group in events.groupby("account"):
        times = group["timestamp"].sort_values().tolist()
        found_burst = False

        left = 0
        for right, current_time in enumerate(times):
            while current_time - times[left] > window:
                left += 1
            if right - left + 1 >= config.burst_min_transactions:
                found_burst = True
                break

        if found_burst:
            burst_accounts += 1

    return round(burst_accounts / total_accounts, 4)


def velocity_trigger_rate(df: pd.DataFrame, config: FidelityConfig) -> float:
    total_accounts = df["source_account"].nunique()

    if total_accounts == 0:
        return 0.0

    triggered_accounts = 0
    window = f"{config.velocity_window_minutes}min"

    for _, group in df.groupby("source_account"):
        series = (
            group.sort_values("timestamp")
            .set_index("timestamp")["amount"]
            .rolling(window)
            .sum()
        )

        if (series >= config.velocity_amount_threshold).any():
            triggered_accounts += 1

    return round(triggered_accounts / total_accounts, 4)


def build_transaction_graph(df: pd.DataFrame) -> nx.DiGraph:
    graph = nx.DiGraph()

    for row in df.itertuples(index=False):
        if graph.has_edge(row.source_account, row.target_account):
            graph[row.source_account][row.target_account]["weight"] += float(row.amount)
            graph[row.source_account][row.target_account]["count"] += 1
        else:
            graph.add_edge(
                row.source_account,
                row.target_account,
                weight=float(row.amount),
                count=1,
            )

    return graph


def fan_in_out_motif_score(df: pd.DataFrame, config: FidelityConfig) -> float:
    graph = build_transaction_graph(df)

    if graph.number_of_nodes() == 0:
        return 0.0

    motif_nodes = 0

    for node in graph.nodes:
        in_degree = graph.in_degree(node)
        out_degree = graph.out_degree(node)

        if in_degree >= config.fan_degree_threshold or out_degree >= config.fan_degree_threshold:
            motif_nodes += 1

    return round(motif_nodes / graph.number_of_nodes(), 4)


def circular_flow_count(df: pd.DataFrame, config: FidelityConfig) -> int:
    graph = build_transaction_graph(df)
    cycles = nx.simple_cycles(graph)

    count = 0
    for cycle in cycles:
        if 2 <= len(cycle) <= config.circular_path_max_length:
            count += 1

    return count


def centrality_concentration_score(df: pd.DataFrame) -> float:
    graph = build_transaction_graph(df)

    if graph.number_of_nodes() <= 1:
        return 0.0

    centrality = nx.pagerank(graph, weight="weight")
    values = np.array(list(centrality.values()), dtype=float)

    if values.sum() == 0:
        return 0.0

    top_10_count = max(1, int(np.ceil(len(values) * 0.1)))
    score = np.sort(values)[-top_10_count:].sum() / values.sum()

    return round(float(score), 4)


def benchmark_behavioral_fidelity(
    transactions: pd.DataFrame,
    config: Optional[FidelityConfig] = None,
) -> Dict[str, float]:
    """
    Calculate behavioral fidelity metrics for transaction graph data.

    Parameters
    ----------
    transactions:
        DataFrame with columns:
        source_account, target_account, amount, timestamp

    config:
        Optional FidelityConfig for thresholds.

    Returns
    -------
    Dictionary containing temporal, graph motif, velocity, and overall scores.
    """
    config = config or FidelityConfig()
    prepared = _prepare_transactions(transactions)

    metrics = {
        "inter_event_time_score": inter_event_time_score(prepared),
        "burst_pattern_score": burst_pattern_score(prepared, config),
        "fan_in_out_motif_score": fan_in_out_motif_score(prepared, config),
        "circular_flow_count": circular_flow_count(prepared, config),
        "velocity_trigger_rate": velocity_trigger_rate(prepared, config),
        "centrality_concentration_score": centrality_concentration_score(prepared),
    }

    normalized_cycle_score = min(metrics["circular_flow_count"] / 10.0, 1.0)

    score_components = [
        metrics["inter_event_time_score"],
        metrics["burst_pattern_score"],
        metrics["fan_in_out_motif_score"],
        normalized_cycle_score,
        metrics["velocity_trigger_rate"],
        metrics["centrality_concentration_score"],
    ]

    metrics["overall_behavioral_fidelity"] = round(float(np.mean(score_components)), 4)

    return metrics
