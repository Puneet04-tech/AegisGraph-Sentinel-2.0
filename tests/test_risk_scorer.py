import pytest
from types import SimpleNamespace

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


@pytest.mark.parametrize("amount,min_velocity_risk", [
    (500, 0.0),       # Low amount: no velocity risk
    (50001, 0.3),     # Medium amount (>50000): velocity risk 0.3
    (250000, 0.5),    # High amount (>100000): velocity risk 0.5
])
def test_amount_velocity_risk_regression(monkeypatch, amount, min_velocity_risk):
    """Regression test for amount-velocity risk scoring.

    Verifies that higher transaction amounts result in proportionally higher
    velocity-based risk scores. This prevents reoccurrence of the bug where
    different amounts returned identical risk scores (issue #1644).
    """
    state = SimpleNamespace(
        graph_loaded=False,
        transaction_graph=None,
        mule_accounts=set(),
        account_profiles={},
        centrality_baseline={},
        centrality_window_size=3,
    )
    monkeypatch.setattr("src.api.main.state", state)
    risk_mod._CENTRALITY_CACHE.clear()

    transaction = {
        "source_account": "test_account",
        "target_account": "test_target",
        "amount": amount,
    }

    result = risk_mod.compute_risk_score(transaction)

    assert result["breakdown"]["velocity"] >= min_velocity_risk, \
        f"Amount {amount} should result in velocity risk >= {min_velocity_risk}, got {result['breakdown']['velocity']}"


def test_amount_velocity_risk_order(monkeypatch):
    """Test that risk scores increase monotonically with transaction amount.

    Ensures that amount=500 < amount=50000 < amount=250000 in terms
    of velocity-based risk scoring.
    """
    state = SimpleNamespace(
        graph_loaded=False,
        transaction_graph=None,
        mule_accounts=set(),
        account_profiles={},
        centrality_baseline={},
        centrality_window_size=3,
    )
    monkeypatch.setattr("src.api.main.state", state)
    risk_mod._CENTRALITY_CACHE.clear()

    # Test low amount
    low_amount_result = risk_mod.compute_risk_score({
        "source_account": "test_account",
        "target_account": "test_target",
        "amount": 500,
    })
    low_velocity_risk = low_amount_result["breakdown"]["velocity"]

    # Test medium amount (just above 50000 threshold)
    medium_amount_result = risk_mod.compute_risk_score({
        "source_account": "test_account",
        "target_account": "test_target",
        "amount": 50001,
    })
    medium_velocity_risk = medium_amount_result["breakdown"]["velocity"]

    # Test high amount
    high_amount_result = risk_mod.compute_risk_score({
        "source_account": "test_account",
        "target_account": "test_target",
        "amount": 250000,
    })
    high_velocity_risk = high_amount_result["breakdown"]["velocity"]

    # Verify ordering
    assert low_velocity_risk < medium_velocity_risk, \
        f"Low amount (500) risk {low_velocity_risk} should be < medium amount (50001) risk {medium_velocity_risk}"
    assert medium_velocity_risk < high_velocity_risk, \
        f"Medium amount (50001) risk {medium_velocity_risk} should be < high amount (250000) risk {high_velocity_risk}"

    # Verify high amount meets threshold (0.5 for amounts > 100000)
    assert high_velocity_risk >= 0.5, \
        f"High amount (250000) should have velocity risk >= 0.5, got {high_velocity_risk}"
