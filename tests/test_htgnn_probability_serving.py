"""Tests for serving the trained HTGNN checkpoint inside the risk scorer."""

from __future__ import annotations

import numpy as np
import pytest

from src.inference import risk_scorer
from src.inference.htgnn_probability import (
    HTGNNProbabilityModel,
    get_probability_model,
    reset_probability_model_cache,
)


def _score(**kwargs):
    kwargs.setdefault("graph_loaded", False)
    kwargs.setdefault("transaction_graph", None)
    kwargs.setdefault("mule_accounts", set())
    kwargs.setdefault("centrality_baseline", {})
    kwargs.setdefault("account_profiles", {})
    kwargs.setdefault("config", {})
    return risk_scorer.compute_risk_score(
        {"source_account": "ACC1", "target_account": "ACC2", "amount": 1000},
        **kwargs,
    )


class _FakeModel:
    def __init__(self, probability=0.93):
        self.probability = probability
        self.calls = []

    def predict_proba(self, features):
        self.calls.append(features)
        return [self.probability]


class _RaisingModel:
    def predict_proba(self, features):
        raise ValueError("expected 165 features per transaction, got 3")


def test_model_probability_drives_graph_component(monkeypatch):
    fake = _FakeModel(0.93)
    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model", lambda *a, **k: fake
    )

    result = _score(model_features=[0.1, 0.2, 0.3])

    assert result["model_probability"] == pytest.approx(0.93)
    assert result["model_source"] == "htgnn"
    assert result["breakdown"]["graph"] == pytest.approx(0.93)
    assert fake.calls == [[0.1, 0.2, 0.3]]


def test_model_probability_never_lowers_a_rule_signal(monkeypatch):
    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model",
        lambda *a, **k: _FakeModel(0.10),
    )

    # A known mule source contributes 0.6 to the graph component; a confident
    # "not fraud" model must not talk the rule signal down.
    result = _score(model_features=[0.0, 0.0, 0.0], mule_accounts={"ACC1"})

    assert result["model_probability"] == pytest.approx(0.10)
    assert result["breakdown"]["graph"] >= 0.6


def test_model_failure_falls_back_to_rules(monkeypatch):
    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model",
        lambda *a, **k: _RaisingModel(),
    )

    result = _score(model_features=[0.1, 0.2, 0.3])

    assert result["model_probability"] is None
    assert result["model_source"] == "rules:model_error"
    assert result["analysis_degraded"] is not True
    assert any(
        error["operation"] == "htgnn model scoring" for error in result["analysis_errors"]
    )


def test_missing_checkpoint_reports_rule_fallback(monkeypatch):
    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model", lambda *a, **k: None
    )

    result = _score(model_features=[0.1, 0.2, 0.3])

    assert result["model_probability"] is None
    assert result["model_source"] == "rules:checkpoint_unavailable"


def test_no_features_keeps_the_rule_path_untouched():
    result = _score()

    assert result["model_probability"] is None
    assert result["model_source"].startswith("rules")


def test_probability_model_returns_none_without_a_checkpoint(tmp_path):
    reset_probability_model_cache()

    assert get_probability_model(tmp_path / "missing.pt") is None


def test_checkpoint_roundtrip_scores_features(tmp_path, monkeypatch):
    torch = pytest.importorskip("torch")
    import base64

    # Checkpoint encryption needs a key; keep the test hermetic on machines
    # (and CI images) that do not have a .env with one configured.
    monkeypatch.setenv(
        "MODEL_ENCRYPTION_KEY", base64.b64encode(b"aegis-test-key-32-bytes-long!!!!").decode()
    )
    from src.models.htgnn import AegisHTGNN
    from src.utils.encryption import get_encryption_handler

    torch.manual_seed(0)
    model = AegisHTGNN(
        hidden_channels=8,
        heads=2,
        num_layers=2,
        node_channels={"account": 4},
        edge_types=[("account", "transacts", "account")],
    )
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "node_channels": {"account": 4},
        "edge_types": [["account", "transacts", "account"]],
        "hidden_channels": 8,
    }
    path = tmp_path / "checkpoint.pt"
    path.write_bytes(get_encryption_handler().encrypt_checkpoint(checkpoint))

    reset_probability_model_cache()
    served = HTGNNProbabilityModel(path)

    assert served.is_available()
    assert served.feature_dim == 4

    probabilities = served.predict_proba([[0.1, 0.2, 0.3, 0.4], [1.0, -1.0, 0.5, 0.0]])
    assert len(probabilities) == 2
    assert all(0.0 <= value <= 1.0 for value in probabilities)
    # Deterministic for the same weights and inputs.
    assert served.predict_proba([[0.1, 0.2, 0.3, 0.4]]) == pytest.approx(probabilities[:1])

    with pytest.raises(ValueError, match="expected 4 features"):
        served.predict_proba([[0.1, 0.2, 0.3]])


# ---------------------------------------------------------------------------
# Graph context: a transaction is scored with the neighbours visible at its
# own time step, so serving reproduces the training protocol instead of
# scoring every transaction in isolation.
# ---------------------------------------------------------------------------


class _StubGraphModel:
    """Captures what the graph index sends to the network."""

    def __init__(self):
        self.calls = []

    def predict_proba(self, features, edge_index=None):
        features = np.asarray(features)
        edges = np.asarray(edge_index)
        self.calls.append((features.shape, edges.shape))
        return [0.5] * len(features)


def _write_graph(path, *, steps, edges, tx_ids, num_features=2):
    torch = pytest.importorskip("torch")
    from torch_geometric.data import HeteroData

    data = HeteroData()
    count = len(steps)
    data["account"].x = torch.arange(count * num_features, dtype=torch.float32).reshape(
        count, num_features
    )
    data["account"].time = torch.tensor(steps, dtype=torch.long)
    data["account"].tx_id = list(tx_ids)
    data["account", "transacts", "account"].edge_index = torch.tensor(
        edges, dtype=torch.long
    ).reshape(2, -1)
    torch.save(data, path)
    return path


def test_graph_context_scores_the_time_respecting_upstream_neighbourhood(tmp_path):
    from src.inference.htgnn_probability import GraphContextIndex

    # a(6) -> target(7) -> and future(20) -> target: the future edge must be
    # dropped, while the 2-hop past chain must be kept.
    path = _write_graph(
        tmp_path / "graph.pt",
        steps=[5, 6, 7, 20],
        edges=[0, 1, 1, 2, 3, 2],
        tx_ids=["past", "a", "target", "future"],
    )
    stub = _StubGraphModel()
    index = GraphContextIndex(path, stub, window=10)
    assert index.load() is True

    assert index.probabilities_for(["target"]) == {"target": pytest.approx(0.5)}

    # Two hops of incoming messages: target, a, past. The step-20 node is a
    # future neighbour and never enters the pass, nor does its edge.
    features_shape, edges_shape = stub.calls[-1]
    assert features_shape == (3, 2)
    assert edges_shape == (2, 2)


def test_graph_context_lookup_ignores_unknown_transactions(tmp_path):
    from src.inference.htgnn_probability import GraphContextIndex

    path = _write_graph(
        tmp_path / "graph.pt", steps=[1, 1], edges=[0, 1], tx_ids=["known-a", "known-b"]
    )
    index = GraphContextIndex(path, _StubGraphModel(), window=10)
    assert index.load() is True

    resolved = index.probabilities_for(["known-a", "not-in-graph"])

    assert set(resolved) == {"known-a"}
    assert len(index.probabilities_for(["not-in-graph"])) == 0


def test_graph_context_disabled_without_an_artifact(tmp_path):
    served = HTGNNProbabilityModel(
        tmp_path / "missing_checkpoint.pt",
        graph_path=tmp_path / "missing_graph.pt",
    )

    assert served.graph_context_state == "disabled"
    assert served.predict_proba_for_accounts(["a"]) == {}


class _GraphLookupModel:
    graph_context_state = "ready"

    def __init__(self, probabilities):
        self.probabilities = probabilities
        self.calls = []

    def predict_proba_for_accounts(self, accounts):
        self.calls.append(list(accounts))
        return {
            account: self.probabilities[account]
            for account in accounts
            if account in self.probabilities
        }


def test_graph_lookup_drives_the_graph_component(monkeypatch):
    fake = _GraphLookupModel({"ACC1": 0.95})
    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model", lambda *a, **k: fake
    )

    result = _score()

    assert fake.calls == [["ACC1", "ACC2"]]
    assert result["model_probability"] == pytest.approx(0.95)
    assert result["model_source"] == "htgnn"
    assert result["breakdown"]["graph"] == pytest.approx(0.95)


def test_graph_lookup_without_a_match_keeps_the_rule_path(monkeypatch):
    fake = _GraphLookupModel({})
    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model", lambda *a, **k: fake
    )

    result = _score()

    assert result["model_probability"] is None
    assert result["model_source"] == "rules:account_not_in_model_graph"
    assert result["breakdown"]["graph"] == pytest.approx(0.0)


def test_graph_context_loading_still_scores_rules(monkeypatch):
    class _Loading(_GraphLookupModel):
        graph_context_state = "loading"

    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model",
        lambda *a, **k: _Loading({}),
    )

    result = _score()

    assert result["model_probability"] is None
    assert result["model_source"] == "rules:graph_context_loading"


def test_graph_lookup_error_falls_back_to_rules(monkeypatch):
    class _Broken(_GraphLookupModel):
        def predict_proba_for_accounts(self, accounts):
            raise RuntimeError("graph context exploded")

    monkeypatch.setattr(
        "src.inference.htgnn_probability.get_probability_model",
        lambda *a, **k: _Broken({}),
    )

    result = _score()

    assert result["model_probability"] is None
    assert result["model_source"] == "rules:model_error"
    assert any(
        error["operation"] == "htgnn graph context scoring"
        for error in result["analysis_errors"]
    )
