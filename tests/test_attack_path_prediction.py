"""Attack paths must be traced through the graph, not invented.

`predict_attack_path` extended every path by appending
`f"hop_{len(path)}_{random.randint(1000, 9999)}"` once per requested depth, so
each predicted path named entities that existed in no store. An analyst could
not look up a single hop. Damage was `len(path) * random.uniform(5000, 25000)`
and confidence a flat `random.uniform(0.55, 0.80)`.

`predict_fraud_evolution` drew its growth multiplier, connection rate, risk
escalation and confidence from `random`, so an entirely isolated network was
predicted to expand as aggressively as a densely connected one.
"""

from __future__ import annotations

import pytest

from src.predictive_intelligence.attack_predictor import AttackPathPredictor
from src.predictive_intelligence.store import PredictiveStore


class FakeGraph:
    """Stands in for GraphService over a fixed adjacency map."""

    def __init__(self, adjacency=None, strengths=None, raises=False):
        self._adjacency = adjacency or {}
        self._strengths = strengths or {}
        self._raises = raises

    def get_entity_network(self, entity_id, depth=1):
        if self._raises:
            raise RuntimeError("graph unavailable")
        nodes = list(self._adjacency.get(entity_id, []))
        if not any(n["node_id"] == entity_id for n in nodes):
            nodes.append({"node_id": entity_id, "properties": {}, "risk_score": 0.0})
        return {"nodes": nodes, "edges": []}

    def get_connection_strength(self, a, b):
        if self._raises:
            raise RuntimeError("graph unavailable")
        return self._strengths.get((a, b), self._strengths.get((b, a), 0.0))


def node(node_id, risk=0.0, node_type="account", **properties):
    return {
        "node_id": node_id,
        "risk_score": risk,
        "node_type": node_type,
        "properties": properties,
    }


# A -> B (high risk) -> D, with C a lower-risk alternative from A.
CHAIN = {
    "A": [node("A", 0.1, total_amount=100.0), node("B", 0.9), node("C", 0.2)],
    "B": [node("B", 0.9), node("D", 0.5)],
    "D": [node("D", 0.5)],
    "C": [node("C", 0.2)],
}


def predictor(adjacency=None, strengths=None, raises=False):
    return AttackPathPredictor(
        store=PredictiveStore(),
        graph=FakeGraph(adjacency if adjacency is not None else CHAIN, strengths, raises),
    )


class TestDeterminism:
    """The defect this PR exists for."""

    def test_the_path_is_stable_across_calls(self):
        instance = predictor()
        paths = {tuple(instance.predict_attack_path("A", depth=3).predicted_path) for _ in range(50)}
        assert len(paths) == 1, f"path still non-deterministic: {paths}"

    def test_hops_are_real_entities(self):
        """Previously every hop was `hop_<i>_<random int>`."""
        path = predictor().predict_attack_path("A", depth=3).predicted_path
        assert not any(hop.startswith("hop_") for hop in path)
        assert set(path) <= {"A", "B", "C", "D"}

    def test_the_module_no_longer_imports_random(self):
        import src.predictive_intelligence.attack_predictor as module

        assert not hasattr(module, "random")


class TestPathTracing:
    def test_the_walk_takes_the_highest_risk_neighbour(self):
        path = predictor().predict_attack_path("A", depth=1).predicted_path
        assert path == ["A", "B"]

    def test_the_walk_follows_the_chain(self):
        path = predictor().predict_attack_path("A", depth=2).predicted_path
        assert path == ["A", "B", "D"]

    def test_the_walk_stops_when_the_graph_offers_no_hop(self):
        """A shorter real path is correct; padding it is the defect."""
        path = predictor().predict_attack_path("A", depth=10).predicted_path
        assert path == ["A", "B", "D"]

    def test_entities_are_not_revisited(self):
        loop = {"A": [node("A"), node("B", 0.9)], "B": [node("B", 0.9), node("A", 0.1)]}
        path = predictor(loop).predict_attack_path("A", depth=5).predicted_path
        assert len(path) == len(set(path))

    def test_a_known_path_is_preserved_and_extended(self):
        result = predictor().predict_attack_path("A", known_path=["X", "A"], depth=1)
        assert result.predicted_path[:2] == ["X", "A"]

    def test_an_isolated_source_yields_a_single_entity_path(self):
        assert predictor({}).predict_attack_path("LONE", depth=3).predicted_path == ["LONE"]

    def test_zero_depth_does_not_extend(self):
        assert predictor().predict_attack_path("A", depth=0).predicted_path == ["A"]


class TestProbability:
    def test_probability_compounds_link_strength(self):
        strong = predictor(strengths={("A", "B"): 0.9, ("B", "D"): 0.9})
        weak = predictor(strengths={("A", "B"): 0.2, ("B", "D"): 0.2})
        assert (
            strong.predict_attack_path("A", depth=2).probability
            > weak.predict_attack_path("A", depth=2).probability
        )

    def test_a_longer_path_is_less_probable_than_its_prefix(self):
        instance = predictor(strengths={("A", "B"): 0.8, ("B", "D"): 0.8})
        one = predictor(strengths={("A", "B"): 0.8, ("B", "D"): 0.8})
        assert (
            instance.predict_attack_path("A", depth=2).probability
            < one.predict_attack_path("A", depth=1).probability
        )

    def test_probability_stays_within_bounds(self):
        result = predictor(strengths={("A", "B"): 1.0, ("B", "D"): 1.0}).predict_attack_path(
            "A", depth=2
        )
        assert 0.0 < result.probability <= 1.0

    def test_a_source_with_no_onward_hop_is_certain_to_stay_put(self):
        assert predictor({}).predict_attack_path("LONE", depth=3).probability == 1.0


class TestDamage:
    def test_damage_uses_recorded_exposure_where_present(self):
        adjacency = {"A": [node("A", 0.1, total_amount=1000.0)]}
        result = predictor(adjacency).predict_attack_path("A", depth=0)
        assert result.estimated_damage == 1000.0

    def test_nodes_without_exposure_use_the_fallback(self):
        adjacency = {"A": [node("A", 0.1)]}
        result = predictor(adjacency).predict_attack_path("A", depth=0)
        assert result.estimated_damage == AttackPathPredictor.DEFAULT_NODE_EXPOSURE

    @pytest.mark.parametrize("value", ["nonsense", True, float("nan"), float("inf")])
    def test_unusable_exposure_falls_back(self, value):
        adjacency = {"A": [node("A", 0.1, total_amount=value)]}
        result = predictor(adjacency).predict_attack_path("A", depth=0)
        assert result.estimated_damage == AttackPathPredictor.DEFAULT_NODE_EXPOSURE

    def test_string_amounts_are_accepted(self):
        adjacency = {"A": [node("A", 0.1, total_amount="750.5")]}
        assert predictor(adjacency).predict_attack_path("A", depth=0).estimated_damage == 750.5

    def test_damage_is_stable_across_calls(self):
        instance = predictor()
        amounts = {instance.predict_attack_path("A", depth=2).estimated_damage for _ in range(20)}
        assert len(amounts) == 1


class TestConfidence:
    def test_no_onward_hop_scores_low(self):
        result = predictor({}).predict_attack_path("LONE", depth=3)
        assert result.confidence == AttackPathPredictor.NO_PATH_CONFIDENCE

    def test_full_coverage_outscores_partial(self):
        full = predictor().predict_attack_path("A", depth=2)
        partial = predictor().predict_attack_path("A", depth=6)
        assert full.confidence > partial.confidence

    def test_confidence_is_capped(self):
        assert predictor().predict_attack_path("A", depth=1).confidence <= 0.9


class TestNetworkExpansion:
    def test_a_prediction_is_returned_per_source(self):
        results = predictor().predict_network_expansion(["A", "B"])
        assert [r.source_entity_id for r in results] == ["A", "B"]

    def test_expansion_traces_real_paths(self):
        results = predictor().predict_network_expansion(["A"], expansion_rate=0.6)
        assert set(results[0].predicted_path) <= {"A", "B", "C", "D"}


class TestFraudEvolution:
    def test_growth_is_bounded_by_the_real_frontier(self):
        evolution = predictor().predict_fraud_evolution({"A"})
        # A's neighbours are B and C; both sit outside the network.
        assert evolution["predicted_new_entities"] == 2

    def test_an_isolated_network_is_predicted_not_to_grow(self):
        """Previously growth was random.uniform(1.5, 4.0) regardless."""
        evolution = predictor({}).predict_fraud_evolution({"LONE"})
        assert evolution["predicted_new_entities"] == 0
        assert evolution["risk_escalation"] == 0.0

    def test_entities_already_in_the_network_are_not_counted_as_growth(self):
        evolution = predictor().predict_fraud_evolution({"A", "B", "C", "D"})
        assert evolution["predicted_new_entities"] == 0

    def test_escalation_reflects_frontier_risk(self):
        risky = predictor({"A": [node("A"), node("B", 0.9)], "B": [node("B", 0.9)]})
        calm = predictor({"A": [node("A"), node("B", 0.05)], "B": [node("B", 0.05)]})
        assert (
            risky.predict_fraud_evolution({"A"})["risk_escalation"]
            > calm.predict_fraud_evolution({"A"})["risk_escalation"]
        )

    def test_escalation_stays_within_bounds(self):
        evolution = predictor().predict_fraud_evolution({"A"})
        assert 0.0 <= evolution["risk_escalation"] <= 1.0

    def test_an_empty_network_is_handled(self):
        evolution = predictor().predict_fraud_evolution(set())
        assert evolution["current_entities"] == 0
        assert evolution["predicted_new_entities"] == 0

    def test_isolation_is_a_confident_prediction(self):
        assert predictor({}).predict_fraud_evolution({"LONE"})["confidence"] == 0.7

    def test_patterns_reflect_frontier_node_types(self):
        adjacency = {
            "A": [node("A"), node("DEV1", node_type="device")],
            "DEV1": [node("DEV1", node_type="device"), node("IP1", node_type="ip_address")],
            "IP1": [node("IP1", node_type="ip_address")],
        }
        evolution = predictor(adjacency).predict_fraud_evolution({"A"})
        assert "ip_rotation" in evolution["new_entity_patterns"]

    def test_no_frontier_yields_no_patterns(self):
        assert predictor({}).predict_fraud_evolution({"LONE"})["new_entity_patterns"] == []

    def test_evolution_is_stable_across_calls(self):
        instance = predictor()
        seen = {
            (
                instance.predict_fraud_evolution({"A"})["predicted_new_entities"],
                instance.predict_fraud_evolution({"A"})["risk_escalation"],
            )
            for _ in range(20)
        }
        assert len(seen) == 1


class TestGraphFailureIsSurvivable:
    def test_prediction_degrades_to_the_source(self):
        result = predictor(raises=True).predict_attack_path("A", depth=3)
        assert result.predicted_path == ["A"]
        assert result.confidence == AttackPathPredictor.NO_PATH_CONFIDENCE

    def test_evolution_survives_graph_failure(self):
        evolution = predictor(raises=True).predict_fraud_evolution({"A"})
        assert evolution["predicted_new_entities"] == 0
