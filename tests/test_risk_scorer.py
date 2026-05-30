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
