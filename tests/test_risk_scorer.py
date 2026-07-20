from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.inference import risk_scorer as risk_mod


class _FakeGraph:
    is_active = False

    def __init__(self):
        self.nodes = {"source": None}

    def number_of_nodes(self):
        return 3

    def number_of_edges(self):
        return 2

    def has_node(self, node):
        return node in self.nodes

    def out_degree(self, node):
        return 1

    def in_degree(self, node):
        return 1

    def subgraph(self, nodes):
        return self


def test_compute_risk_score_reuses_betweenness_centrality(monkeypatch):
    state = SimpleNamespace(
        graph_loaded=True,
        transaction_graph=_FakeGraph(),
        mule_accounts=set(),
        account_profiles={},
        centrality_baseline={},
        centrality_window_size=3,
    )
    monkeypatch.setattr("src.api.main.state", state)
    risk_mod._CENTRALITY_CACHE.clear()

    calls = {"count": 0}

    def fake_betweenness_centrality(graph, k=None):
        calls["count"] += 1
        return {"source": 0.02}

    monkeypatch.setattr(risk_mod.nx, "descendants", lambda graph, node: set())
    monkeypatch.setattr(risk_mod.nx, "is_directed_acyclic_graph", lambda graph: True)
    monkeypatch.setattr(risk_mod.nx, "betweenness_centrality", fake_betweenness_centrality)

    transaction = {
        "source_account": "source",
        "target_account": "target",
        "amount": 10.0,
    }

    first = risk_mod.compute_risk_score(transaction)
    second = risk_mod.compute_risk_score(transaction)

    assert first["breakdown"]["graph"] >= 0.15
    assert second["breakdown"]["graph"] >= 0.15
    assert calls["count"] == 1


class _FailingBaseline(dict):
    def __contains__(self, key):
        raise RuntimeError("lateral boom")


def _make_state(failure_mode="degraded", graph=None, centrality_baseline=None):
    return SimpleNamespace(
        graph_loaded=True,
        transaction_graph=graph,
        mule_accounts=set(),
        account_profiles={},
        centrality_baseline=centrality_baseline if centrality_baseline is not None else {},
        centrality_window_size=3,
        config={},
        settings=SimpleNamespace(runtime=SimpleNamespace(failure_mode=failure_mode)),
    )


class _FailingEntropyGraph(_FakeGraph):
    def descendants(self, node):
        raise RuntimeError("graph boom")


def test_lateral_movement_exception_is_degraded_and_logged(monkeypatch):
    state = _make_state(graph=_FakeGraph(), centrality_baseline=_FailingBaseline())
    monkeypatch.setattr("src.api.main.state", state)
    monkeypatch.setattr(risk_mod, "_get_betweenness_centrality", lambda graph: {"source": 0.02})
    monkeypatch.setattr(risk_mod.logger, "error", MagicMock())

    result = risk_mod.compute_risk_score({"source_account": "source", "target_account": "target", "amount": 10})

    assert result["analysis_degraded"] is True
    assert result["component_status"]["graph"] == "degraded"
    assert any(err["operation"] == "lateral movement analysis" for err in result["analysis_errors"])
    assert risk_mod.logger.error.called


def test_entropy_exception_is_degraded_and_logged(monkeypatch):
    state = _make_state(graph=None)
    monkeypatch.setattr("src.api.main.state", state)
    monkeypatch.setattr(risk_mod.logger, "error", MagicMock())

    result = risk_mod.compute_risk_score(
        {"source_account": "source", "target_account": "target", "amount": 10, "timestamp": "not-a-timestamp"}
    )

    assert result["analysis_degraded"] is True
    assert result["component_status"]["entropy"] == "degraded"
    assert any(err["operation"] == "entropy analysis" for err in result["analysis_errors"])
    assert risk_mod.logger.error.called


def test_fail_fast_mode_raises_on_lateral_movement_failure(monkeypatch):
    state = _make_state(failure_mode="fail_fast", graph=_FakeGraph(), centrality_baseline=_FailingBaseline())
    monkeypatch.setattr("src.api.main.state", state)
    monkeypatch.setattr(risk_mod, "_get_betweenness_centrality", lambda graph: {"source": 0.02})
    monkeypatch.setattr(risk_mod.nx, "descendants", lambda graph, node: set())
    monkeypatch.setattr(risk_mod.nx, "is_directed_acyclic_graph", lambda graph: True)

    with pytest.raises(RuntimeError, match="lateral boom"):
        risk_mod.compute_risk_score({"source_account": "source", "target_account": "target", "amount": 10})


def test_successful_execution_unchanged_and_not_degraded(monkeypatch):
    state = _make_state(graph=_FakeGraph())
    monkeypatch.setattr("src.api.main.state", state)
    monkeypatch.setattr(risk_mod, "_get_betweenness_centrality", lambda graph: {"source": 0.02})
    monkeypatch.setattr(risk_mod.nx, "descendants", lambda graph, node: set())
    monkeypatch.setattr(risk_mod.nx, "is_directed_acyclic_graph", lambda graph: True)

    result = risk_mod.compute_risk_score({"source_account": "source", "target_account": "target", "amount": 10})

    assert result["analysis_degraded"] is False
    assert result["component_status"]["graph"] == "ok"
    assert result["component_status"]["entropy"] == "ok"
    assert set(result.keys()) >= {"risk_score", "decision", "confidence", "breakdown"}


def test_multiple_component_failures_are_reported(monkeypatch):
    state = _make_state(graph=_FailingEntropyGraph())
    monkeypatch.setattr("src.api.main.state", state)
    monkeypatch.setattr(risk_mod.logger, "error", MagicMock())
    monkeypatch.setattr(risk_mod, "_get_betweenness_centrality", lambda graph: {"source": 0.02})

    result = risk_mod.compute_risk_score(
        {"source_account": "source", "target_account": "target", "amount": 10, "timestamp": "not-a-timestamp"}
    )

    assert result["analysis_degraded"] is True
    assert len(result["analysis_errors"]) >= 1
    assert result["component_status"]["graph"] in {"ok", "degraded"}
    assert result["component_status"]["entropy"] == "degraded"
