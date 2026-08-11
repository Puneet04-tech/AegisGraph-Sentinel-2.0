"""
Regression tests for risk propagation strongest-path semantics.

propagate_risk used a visited set that locked in the FIRST path to each node,
so a weaker route arriving first permanently blocked a stronger route to the
same target, understating propagated risk and stored risk scores.
"""

from datetime import datetime, timezone

import pytest

from src.global_intelligence.store import GlobalIntelligenceStore
from src.global_intelligence.models import (
    FederatedEntity,
    EntityType,
    ThreatLevel,
)
from src.global_intelligence.knowledge_graph import KnowledgeGraphEngine
from src.global_intelligence.risk_propagation import (
    PropagationConfig,
    RiskPropagationEngine,
)

NOW = datetime.now(timezone.utc)


def make_entity(entity_id, risk=0.9, level=ThreatLevel.HIGH):
    return FederatedEntity(
        entity_id=entity_id,
        entity_type=EntityType.ACCOUNT,
        federation_id="fed-1",
        partner_id="partner-1",
        external_id=f"ext-{entity_id}",
        risk_score=risk,
        threat_level=level,
        first_seen=NOW,
        last_updated=NOW,
    )


def make_engine(store, **config):
    graph = KnowledgeGraphEngine(store=store)
    return RiskPropagationEngine(
        store=store, graph_engine=graph, config=PropagationConfig(**config)
    )


class TestRiskPropagationMax:
    """The strongest path to a target must win."""

    def setup_method(self):
        self.store = GlobalIntelligenceStore()
        self.kg = KnowledgeGraphEngine(store=self.store)
        self.engine = make_engine(self.store)

    def add_node(self, eid, **kw):
        self.store.store_entity(make_entity(eid, **kw))
        self.kg.add_entity(eid, EntityType.ACCOUNT, {"name": eid})

    def test_stronger_path_beats_weaker_first_path(self):
        for eid, risk in [("S", 0.9), ("A", 0.0), ("B", 0.0), ("T", 0.0)]:
            self.add_node(eid, risk=risk)
        self.kg.add_relationship("S", "A", "linked_to", weight=0.5)
        self.kg.add_relationship("A", "T", "linked_to", weight=1.0)
        self.kg.add_relationship("S", "B", "linked_to", weight=1.0)
        self.kg.add_relationship("B", "T", "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S")

        records = {p.target_entity_id: p.risk_score for p in propagations}
        assert len(records) == 3
        assert records["T"] == pytest.approx(0.9 * 1.0 * 0.8)
        assert self.store.get_entity("T").risk_score == pytest.approx(records["T"])

    def test_one_record_per_target(self):
        for eid, risk in [("S", 0.9), ("A", 0.0), ("B", 0.0), ("T", 0.0)]:
            self.add_node(eid, risk=risk)
        self.kg.add_relationship("S", "A", "linked_to", weight=0.5)
        self.kg.add_relationship("A", "T", "linked_to", weight=1.0)
        self.kg.add_relationship("S", "B", "linked_to", weight=1.0)
        self.kg.add_relationship("B", "T", "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S")

        targets = [p.target_entity_id for p in propagations]
        assert len(targets) == len(set(targets))

    def test_stronger_path_removed_target_record_uses_max(self):
        for eid, risk in [("S", 0.9), ("A", 0.0), ("T", 0.0)]:
            self.add_node(eid, risk=risk)
        self.kg.add_relationship("S", "A", "linked_to", weight=1.0)
        self.kg.add_relationship("A", "T", "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S")

        record = [p for p in propagations if p.target_entity_id == "T"][0]
        assert record.risk_score == pytest.approx(0.9 * 0.8)
        assert record.hop_count == 2
        assert record.propagation_path == ["S", "A", "T"]

    def test_target_risk_score_never_decreases(self):
        for eid, risk in [("S", 0.9), ("A", 0.0), ("T", 0.0)]:
            self.add_node(eid, risk=risk)
        self.kg.add_relationship("S", "A", "linked_to", weight=1.0)
        self.kg.add_relationship("A", "T", "linked_to", weight=1.0)

        self.engine.propagate_risk("S")
        after = self.store.get_entity("T").risk_score
        self.engine.propagate_risk("S")
        assert self.store.get_entity("T").risk_score == after

    def test_direct_neighbor_risk(self):
        self.add_node("S", risk=0.8)
        self.add_node("A", risk=0.0)
        self.kg.add_relationship("S", "A", "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S")

        assert len(propagations) == 1
        assert propagations[0].target_entity_id == "A"
        assert propagations[0].risk_score == pytest.approx(0.8)
        assert propagations[0].hop_count == 1

    def test_edge_weight_scales_propagation(self):
        self.add_node("S", risk=0.8)
        self.add_node("A", risk=0.0)
        self.kg.add_relationship("S", "A", "linked_to", weight=0.5)

        propagations = self.engine.propagate_risk("S")

        assert propagations[0].risk_score == pytest.approx(0.8 * 0.5)

    def test_min_strength_filters_weak_propagation(self):
        self.add_node("S", risk=0.8)
        self.add_node("A", risk=0.0)
        self.add_node("B", risk=0.0)
        self.kg.add_relationship("S", "A", "linked_to", weight=0.05)
        self.kg.add_relationship("S", "B", "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S")

        assert [p.target_entity_id for p in propagations] == ["B"]

    def test_max_hops_limits_propagation(self):
        self.add_node("S", risk=0.9)
        for nid in ["A", "B", "C", "D"]:
            self.add_node(nid, risk=0.0)
        chain = ["S", "A", "B", "C", "D"]
        for i in range(len(chain) - 1):
            self.kg.add_relationship(chain[i], chain[i + 1], "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S", max_hops=2)

        assert {p.target_entity_id for p in propagations} == {"A", "B"}

    def test_cycle_does_not_reenter_source(self):
        self.add_node("S", risk=0.9)
        self.add_node("A", risk=0.0)
        self.kg.add_relationship("S", "A", "linked_to", weight=1.0)
        self.kg.add_relationship("A", "S", "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S")

        assert [p.target_entity_id for p in propagations] == ["A"]
        assert self.store.get_entity("S").risk_score == 0.9

    def test_cross_cycle_terminates(self):
        self.add_node("S", risk=0.9)
        self.add_node("A", risk=0.0)
        self.add_node("B", risk=0.0)
        self.kg.add_relationship("S", "A", "linked_to", weight=1.0)
        self.kg.add_relationship("A", "B", "linked_to", weight=1.0)
        self.kg.add_relationship("B", "A", "linked_to", weight=1.0)

        propagations = self.engine.propagate_risk("S")

        assert len(propagations) == 2
        assert propagations[0].risk_score > propagations[1].risk_score

    def test_unknown_source_returns_empty(self):
        propagations = self.engine.propagate_risk("missing")

        assert propagations == []


class TestRiskTrajectory:
    """Trajectory aggregation reflects max propagation."""

    def setup_method(self):
        self.store = GlobalIntelligenceStore()
        self.kg = KnowledgeGraphEngine(store=self.store)
        self.engine = make_engine(self.store)

    def test_trajectory_avg_uses_single_max_record(self):
        for eid, risk in [("S", 0.9), ("A", 0.0), ("B", 0.0), ("T", 0.0)]:
            self.store.store_entity(make_entity(eid, risk=risk))
            self.kg.add_entity(eid, EntityType.ACCOUNT, {"name": eid})
        self.kg.add_relationship("S", "A", "linked_to", weight=0.5)
        self.kg.add_relationship("A", "T", "linked_to", weight=1.0)
        self.kg.add_relationship("S", "B", "linked_to", weight=1.0)
        self.kg.add_relationship("B", "T", "linked_to", weight=1.0)

        self.engine.propagate_risk("S")
        trajectory = self.engine.get_risk_trajectory("S")

        assert trajectory["affected_entities_count"] == 3
        assert trajectory["max_propagated_risk"] == pytest.approx(0.9)
        assert trajectory["avg_propagated_risk"] == pytest.approx(
            (0.45 + 0.9 + 0.72) / 3
        )

    def test_trajectory_unknown_entity(self):
        trajectory = self.engine.get_risk_trajectory("missing")

        assert trajectory == {"error": "Entity not found"}

    def test_recommendations_for_high_risk(self):
        self.store.store_entity(make_entity("S", risk=0.95))
        self.kg.add_entity("S", EntityType.ACCOUNT, {"name": "S"})
        trajectory = self.engine.get_risk_trajectory("S")

        assert "Consider immediate investigation" in trajectory["recommendations"]


class TestRiskClusters:
    """Cluster identification unaffected by propagation fix."""

    def setup_method(self):
        self.store = GlobalIntelligenceStore()
        self.kg = KnowledgeGraphEngine(store=self.store)
        self.engine = make_engine(self.store)

    def test_high_risk_cluster_detected(self):
        for i, risk in enumerate([0.9, 0.8, 0.7]):
            self.store.store_entity(make_entity(f"N{i}", risk=risk))
            self.kg.add_entity(f"N{i}", EntityType.ACCOUNT, {"name": f"N{i}"})
        for i in range(2):
            self.kg.add_relationship(f"N{i}", f"N{i + 1}", "linked_to", weight=1.0)

        clusters = self.engine.identify_risk_clusters(min_size=3)

        assert clusters == [["N0", "N1", "N2"]]

    def test_low_risk_component_not_clustered(self):
        for i, risk in enumerate([0.1, 0.2, 0.15]):
            self.store.store_entity(make_entity(f"N{i}", risk=risk))
            self.kg.add_entity(f"N{i}", EntityType.ACCOUNT, {"name": f"N{i}"})
        for i in range(2):
            self.kg.add_relationship(f"N{i}", f"N{i + 1}", "linked_to", weight=1.0)

        clusters = self.engine.identify_risk_clusters(min_size=3)

        assert clusters == []
