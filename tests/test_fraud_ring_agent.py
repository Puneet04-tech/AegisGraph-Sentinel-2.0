"""Fraud ring membership must come from the graph, not from dice.

`_expand_ring_membership` appended between 5 and 20 `member_<random int>`
identifiers to the seed list, so every detected ring named entities that
matched no stored node. `_identify_relationships` then fabricated a ring-shaped
chain over that membership with a random edge type and strength, and the
financial impact, geography, connected campaigns, ring name and confidence were
each drawn at random as well.
"""

from __future__ import annotations

import pytest

from src.multi_agent_soc.fraud_ring_agent import FraudRingAgent
from src.multi_agent_soc.store import SOCStore


class FakeGraph:
    """Stands in for GraphService, returning a fixed network per seed."""

    def __init__(self, networks=None, strengths=None, raises=False):
        self._networks = networks or {}
        self._strengths = strengths or {}
        self._raises = raises

    def get_entity_network(self, entity_id, depth=2):
        if self._raises:
            raise RuntimeError("graph unavailable")
        return self._networks.get(entity_id, {"nodes": [], "edges": []})

    def get_connection_strength(self, a, b):
        if self._raises:
            raise RuntimeError("graph unavailable")
        return self._strengths.get((a, b), self._strengths.get((b, a), 0.0))


def node(node_id, **properties):
    tags = properties.pop("tags", [])
    return {"node_id": node_id, "properties": properties, "tags": tags}


def edge(edge_id, source, target, weight=1.0, edge_type="shared_device"):
    return {
        "edge_id": edge_id,
        "source_id": source,
        "target_id": target,
        "weight": weight,
        "edge_type": edge_type,
    }


def agent(networks=None, strengths=None, raises=False) -> FraudRingAgent:
    return FraudRingAgent(
        store=SOCStore(), graph=FakeGraph(networks, strengths, raises)
    )


# A small ring: three members joined by two real edges.
RING_NETWORK = {
    "ACC1": {
        "nodes": [
            node("ACC1", country="US", total_amount=1000.0),
            node("ACC2", country="GB", total_amount=2000.0),
            node("ACC3", country="us", campaign_id="CAMP_7"),
        ],
        "edges": [
            edge("E1", "ACC1", "ACC2", weight=0.9),
            edge("E2", "ACC2", "ACC3", weight=0.4, edge_type="shared_ip"),
        ],
    }
}


class TestDeterminism:
    """The defect this PR exists for."""

    def test_repeated_detection_of_one_ring_agrees(self):
        instance = agent(RING_NETWORK)
        seen = {
            (
                tuple(sorted(r.member_entities)),
                r.financial_impact,
                r.confidence,
                r.ring_name,
                tuple(r.geographic_footprint),
            )
            for r in (instance.detect_ring(["ACC1"]) for _ in range(50))
        }
        assert len(seen) == 1, f"still non-deterministic: {seen}"

    def test_membership_contains_only_real_entities(self):
        """Previously 5-20 invented `member_XXXX` ids were appended."""
        instance = agent(RING_NETWORK)
        members = instance.detect_ring(["ACC1"]).member_entities
        assert set(members) == {"ACC1", "ACC2", "ACC3"}
        assert not any(m.startswith("member_") for m in members)

    def test_the_module_no_longer_imports_random(self):
        import src.multi_agent_soc.fraud_ring_agent as module

        assert not hasattr(module, "random")


class TestRelationships:
    def test_relationships_are_the_graphs_own_edges(self):
        result = agent(RING_NETWORK).detect_ring(["ACC1"])
        assert [
            (r["from_entity"], r["to_entity"], r["relationship_type"])
            for r in result.relationships
        ] == [("ACC1", "ACC2", "shared_device"), ("ACC2", "ACC3", "shared_ip")]

    def test_relationships_are_ordered_by_descending_strength(self):
        result = agent(RING_NETWORK).detect_ring(["ACC1"])
        strengths = [r["strength"] for r in result.relationships]
        assert strengths == sorted(strengths, reverse=True)

    def test_incidental_edges_are_excluded(self):
        networks = {
            "ACC1": {
                "nodes": [node("ACC1"), node("ACC2")],
                "edges": [edge("E1", "ACC1", "ACC2", weight=0.01)],
            }
        }
        assert agent(networks).detect_ring(["ACC1"]).relationships == []

    def test_edges_to_non_members_are_dropped(self):
        networks = {
            "ACC1": {
                "nodes": [node("ACC1")],
                "edges": [edge("E1", "ACC1", "OUTSIDER", weight=0.9)],
            }
        }
        assert agent(networks).detect_ring(["ACC1"]).relationships == []


class TestFinancialImpact:
    def test_impact_sums_recorded_exposure(self):
        networks = {
            "ACC1": {
                "nodes": [
                    node("ACC1", total_amount=1500.0),
                    node("ACC2", total_amount=2500.0),
                ],
                "edges": [],
            }
        }
        assert agent(networks).detect_ring(["ACC1"]).financial_impact == 4000.0

    def test_members_without_exposure_use_the_fallback(self):
        networks = {"ACC1": {"nodes": [node("ACC1"), node("ACC2")], "edges": []}}
        expected = 2 * FraudRingAgent.DEFAULT_MEMBER_EXPOSURE
        assert agent(networks).detect_ring(["ACC1"]).financial_impact == expected

    @pytest.mark.parametrize("value", ["not-a-number", None, True, float("nan")])
    def test_unusable_exposure_values_fall_back(self, value):
        networks = {"ACC1": {"nodes": [node("ACC1", total_amount=value)], "edges": []}}
        result = agent(networks).detect_ring(["ACC1"])
        assert result.financial_impact == FraudRingAgent.DEFAULT_MEMBER_EXPOSURE

    def test_string_amounts_are_accepted(self):
        networks = {"ACC1": {"nodes": [node("ACC1", total_amount="750.50")], "edges": []}}
        assert agent(networks).detect_ring(["ACC1"]).financial_impact == 750.50

    def test_negative_amounts_count_as_exposure(self):
        networks = {"ACC1": {"nodes": [node("ACC1", total_amount=-900.0)], "edges": []}}
        assert agent(networks).detect_ring(["ACC1"]).financial_impact == 900.0


class TestGeography:
    def test_footprint_is_read_from_members_and_normalised(self):
        result = agent(RING_NETWORK).detect_ring(["ACC1"])
        assert result.geographic_footprint == ["GB", "US"]

    def test_footprint_is_empty_when_no_member_records_a_country(self):
        networks = {"ACC1": {"nodes": [node("ACC1")], "edges": []}}
        assert agent(networks).detect_ring(["ACC1"]).geographic_footprint == []


class TestConnectedCampaigns:
    def test_campaigns_come_from_member_attribution(self):
        assert agent(RING_NETWORK).detect_ring(["ACC1"]).connected_campaigns == ["CAMP_7"]

    def test_campaign_tags_are_recognised(self):
        networks = {
            "ACC1": {"nodes": [node("ACC1", tags=["campaign:CAMP_9", "mule"])], "edges": []}
        }
        assert agent(networks).detect_ring(["ACC1"]).connected_campaigns == ["CAMP_9"]

    def test_no_attribution_yields_no_campaigns(self):
        networks = {"ACC1": {"nodes": [node("ACC1")], "edges": []}}
        assert agent(networks).detect_ring(["ACC1"]).connected_campaigns == []


class TestConfidence:
    def test_an_unsupported_ring_scores_low(self):
        """A seed the graph knows nothing about is not a ring."""
        assert agent({}).detect_ring(["ACC_UNKNOWN"]).confidence == 0.1

    def test_a_dense_evidenced_ring_scores_higher_than_a_sparse_one(self):
        sparse = agent(
            {"ACC1": {"nodes": [node("ACC1"), node("ACC2")], "edges": []}}
        ).detect_ring(["ACC1"])
        dense = agent(RING_NETWORK).detect_ring(["ACC1"])
        assert dense.confidence > sparse.confidence

    def test_confidence_never_exceeds_the_cap(self):
        nodes = [node(f"ACC{i}") for i in range(40)]
        edges = [edge(f"E{i}", "ACC0", f"ACC{i}", weight=1.0) for i in range(1, 40)]
        networks = {"ACC0": {"nodes": nodes, "edges": edges}}
        assert agent(networks).detect_ring(["ACC0"]).confidence <= 0.95


class TestRingName:
    def test_name_is_stable_across_runs(self):
        instance = agent(RING_NETWORK)
        names = {instance.detect_ring(["ACC1"], "money_laundering").ring_name for _ in range(20)}
        assert names == {"Ring_money_laundering_ACC1"}

    def test_name_is_independent_of_seed_ordering(self):
        instance = agent(RING_NETWORK)
        first = instance.detect_ring(["ACC1", "ACC9"], "payment_fraud").ring_name
        second = instance.detect_ring(["ACC9", "ACC1"], "payment_fraud").ring_name
        assert first == second

    def test_an_unseeded_ring_is_still_named(self):
        assert agent({}).detect_ring([]).ring_name == "Ring_unknown_unseeded"


class TestExpansionBounds:
    def test_membership_is_capped(self):
        nodes = [node(f"ACC{i}") for i in range(FraudRingAgent.MAX_RING_MEMBERS + 50)]
        networks = {"ACC0": {"nodes": nodes, "edges": []}}
        result = agent(networks).detect_ring(["ACC0"])
        assert len(result.member_entities) == FraudRingAgent.MAX_RING_MEMBERS

    def test_context_can_override_expansion_depth(self):
        seen = {}

        class DepthRecordingGraph(FakeGraph):
            def get_entity_network(self, entity_id, depth=2):
                seen["depth"] = depth
                return {"nodes": [], "edges": []}

        instance = FraudRingAgent(store=SOCStore(), graph=DepthRecordingGraph())
        instance.detect_ring(["ACC1"], context={"expansion_depth": 4})
        assert seen["depth"] == 4

    def test_duplicate_seeds_do_not_duplicate_membership(self):
        result = agent(RING_NETWORK).detect_ring(["ACC1", "ACC1"])
        assert len(result.member_entities) == len(set(result.member_entities))


class TestGraphFailureIsSurvivable:
    def test_detection_falls_back_to_the_seeds(self):
        """An unavailable graph must not take ring detection down with it."""
        result = agent(RING_NETWORK, raises=True).detect_ring(["ACC1"])
        assert result.member_entities == ["ACC1"]
        assert result.confidence == 0.1

    def test_a_seed_with_no_stored_node_is_still_a_member(self):
        assert agent({}).detect_ring(["ACC_GHOST"]).member_entities == ["ACC_GHOST"]


class TestRingExpansionAnalysis:
    def _ring(self, instance):
        return instance.detect_ring(["ACC1"])

    def test_expansion_uses_real_connection_strength(self):
        instance = agent(RING_NETWORK, strengths={("NEW", "ACC2"): 0.8})
        ring = self._ring(instance)
        result = instance.analyze_ring_expansion(ring.ring_id, "NEW")
        assert result["connection_strength"] == 0.8
        assert result["can_add"] is True
        assert result["recommended_action"] == "investigate"

    def test_an_unconnected_entity_is_rejected(self):
        """Previously a random draw admitted roughly two in three."""
        instance = agent(RING_NETWORK)
        ring = self._ring(instance)
        for _ in range(30):
            result = instance.analyze_ring_expansion(ring.ring_id, "STRANGER")
            assert result["can_add"] is False
            assert result["connection_strength"] == 0.0
            assert result["risk_increase"] == 0

    def test_weak_ties_are_monitored_not_investigated(self):
        instance = agent(RING_NETWORK, strengths={("NEW", "ACC1"): 0.55})
        ring = self._ring(instance)
        result = instance.analyze_ring_expansion(ring.ring_id, "NEW")
        assert result["can_add"] is True
        assert result["recommended_action"] == "monitor"

    def test_risk_increase_scales_with_linked_member_count(self):
        one = agent(RING_NETWORK, strengths={("NEW", "ACC1"): 0.9})
        many = agent(
            RING_NETWORK,
            strengths={
                ("NEW", "ACC1"): 0.9,
                ("NEW", "ACC2"): 0.9,
                ("NEW", "ACC3"): 0.9,
            },
        )
        single = one.analyze_ring_expansion(self._ring(one).ring_id, "NEW")
        multi = many.analyze_ring_expansion(self._ring(many).ring_id, "NEW")
        assert multi["risk_increase"] > single["risk_increase"]
        assert multi["linked_members"] == ["ACC1", "ACC2", "ACC3"]

    def test_an_unknown_ring_reports_an_error(self):
        assert "error" in agent().analyze_ring_expansion("missing", "NEW")

    def test_an_existing_member_is_not_re_added(self):
        instance = agent(RING_NETWORK)
        ring = self._ring(instance)
        result = instance.analyze_ring_expansion(ring.ring_id, "ACC2")
        assert result["can_add"] is False
        assert result["reason"] == "Entity already in ring"

    def test_a_failing_graph_does_not_break_expansion_analysis(self):
        instance = agent(RING_NETWORK)
        ring = self._ring(instance)
        instance._graph = FakeGraph(raises=True)
        result = instance.analyze_ring_expansion(ring.ring_id, "NEW")
        assert result["can_add"] is False
