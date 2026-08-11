"""Investigation findings must come from the graph, not from dice.

`analyze_entity` gated each of its three findings on a `random.random()`
comparison and summed `random.uniform(0.1, 0.3)` into a risk score, then
attached fixed confidences of 0.75, 0.65 and 0.85 to them. The `entity_id`
argument never influenced any finding.
"""

from __future__ import annotations

import pytest

from src.multi_agent_soc.investigation_agent import InvestigationAgent
from src.multi_agent_soc.store import SOCStore


class FakeNode:
    def __init__(self, node_id: str, risk_score: float = 0.0):
        self.node_id = node_id
        self.risk_score = risk_score


class FakeGraph:
    """Stands in for GraphService, returning a fixed neighbourhood."""

    def __init__(self, neighbours=None, raises=False):
        self._neighbours = neighbours or []
        self._raises = raises

    def find_common_neighbors(self, a, b):
        if self._raises:
            raise RuntimeError("graph unavailable")
        return list(self._neighbours)


def agent(neighbours=None, raises=False) -> InvestigationAgent:
    return InvestigationAgent(
        store=SOCStore(), graph=FakeGraph(neighbours, raises)
    )


def neighbours(*risks) -> list:
    return [FakeNode(f"ACC{i}", risk) for i, risk in enumerate(risks)]


class TestDeterminism:
    """The defect this PR exists for."""

    def test_repeated_analysis_of_one_entity_agrees(self):
        instance = agent(neighbours(0.1, 0.2))
        results = {instance.analyze_entity("ACC_X").risk_score for _ in range(50)}
        assert len(results) == 1, f"still non-deterministic: {results}"

    def test_a_clean_entity_yields_no_findings(self):
        """Previously this had ~an even chance of reporting a pattern."""
        instance = agent(neighbours(0.0, 0.1))
        for _ in range(50):
            assert instance.analyze_entity("ACC_CLEAN").findings == []

    def test_the_module_no_longer_imports_random(self):
        import src.multi_agent_soc.investigation_agent as module

        assert not hasattr(module, "random")


class TestDetectorsFireOnRealEvidence:
    def test_high_fanout_is_detected(self):
        instance = agent(neighbours(*([0.0] * 8)))
        result = instance.analyze_entity("ACC_HUB")

        types = {f["type"] for f in result.findings}
        assert "pattern_detection" in types

    def test_fanout_below_the_threshold_stays_silent(self):
        instance = agent(neighbours(0.0, 0.0, 0.0))
        types = {f["type"] for f in instance.analyze_entity("ACC_Q").findings}
        assert "pattern_detection" not in types

    def test_a_high_risk_network_is_detected(self):
        instance = agent(neighbours(0.9, 0.8))
        types = {f["type"] for f in instance.analyze_entity("ACC_R").findings}
        assert "network_risk" in types

    def test_a_low_risk_network_stays_silent(self):
        instance = agent(neighbours(0.1, 0.1))
        types = {f["type"] for f in instance.analyze_entity("ACC_S").findings}
        assert "network_risk" not in types

    def test_links_to_known_risk_are_detected(self):
        instance = agent(neighbours(0.95, 0.0))
        types = {f["type"] for f in instance.analyze_entity("ACC_T").findings}
        assert "known_risk_link" in types


class TestConfidenceReflectsEvidence:
    def test_confidence_varies_with_the_size_of_the_signal(self):
        modest = agent(neighbours(*([0.0] * 7))).analyze_entity("A")
        extreme = agent(neighbours(*([0.0] * 20))).analyze_entity("B")

        modest_conf = [f["confidence"] for f in modest.findings][0]
        extreme_conf = [f["confidence"] for f in extreme.findings][0]
        assert extreme_conf > modest_conf

    def test_confidences_are_not_the_old_fixed_literals(self):
        result = agent(neighbours(0.9, 0.9, 0.9)).analyze_entity("A")
        confidences = {f["confidence"] for f in result.findings}
        assert confidences != {0.75, 0.65, 0.85}

    def test_confidences_stay_within_range(self):
        result = agent(neighbours(*([0.99] * 40))).analyze_entity("A")
        assert all(0.0 <= f["confidence"] <= 1.0 for f in result.findings)

    def test_result_confidence_is_lower_with_no_findings(self):
        clean = agent(neighbours(0.0)).analyze_entity("A")
        risky = agent(neighbours(0.9, 0.9)).analyze_entity("B")
        assert clean.confidence < risky.confidence


class TestRiskScore:
    def test_a_risky_network_scores_above_a_clean_one(self):
        clean = agent(neighbours(0.0, 0.0)).analyze_entity("A")
        risky = agent(neighbours(0.9, 0.9)).analyze_entity("B")
        assert risky.risk_score > clean.risk_score

    def test_risk_stays_within_range(self):
        result = agent(neighbours(*([1.0] * 30))).analyze_entity("A")
        assert 0.0 <= result.risk_score <= 1.0

    def test_evidence_reports_the_real_neighbourhood(self):
        result = agent(neighbours(0.9, 0.1, 0.85)).analyze_entity("A")
        evidence = result.evidence[0]

        assert evidence["count"] == 3
        assert evidence["suspicious_count"] == 2


class TestDegradedBackends:
    def test_an_unknown_entity_yields_no_findings(self):
        result = agent([]).analyze_entity("GHOST")
        assert result.findings == []
        assert result.linked_entities == []

    def test_a_failing_graph_degrades_rather_than_raising(self):
        result = agent(raises=True).analyze_entity("ACC_X")
        assert result.findings == []
        assert result.risk_score == 0.0

    def test_linked_entities_are_real_node_ids(self):
        """Previously these were invented as linked_<entity>_<n>."""
        result = agent(neighbours(0.1, 0.2)).analyze_entity("ACC_X")

        assert result.linked_entities == ["ACC0", "ACC1"]
        assert not any(link.startswith("linked_ACC_X") for link in result.linked_entities)

    def test_the_timeline_is_empty_without_recorded_history(self):
        """Previously 3-10 invented events with random types."""
        assert agent(neighbours(0.1)).analyze_entity("ACC_X").timeline == []
