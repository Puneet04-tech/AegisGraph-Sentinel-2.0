"""Forensic conclusions must follow the evidence, not a coin flip.

`_analyze_artifacts` set every finding's `anomaly_detected` flag with
`random.choice([True, False])` and its significance with `random.choice`, and
`_generate_conclusion` then counted those flags to return CRITICAL, SUSPICIOUS
or CLEAR. The forensic verdict over a single entity therefore differed on every
run. Artifact record counts were `random.randint` draws, the timeline was 5-20
invented events all stamped `datetime.now()`, and both `integrity: "verified"`
and `integrity_verified: True` were asserted without anything being verified.
"""

from __future__ import annotations

import pytest

from src.multi_agent_soc.forensics_agent import ForensicsAgent
from src.multi_agent_soc.store import SOCStore


class FakeGraph:
    """Stands in for GraphService, returning a fixed network."""

    def __init__(self, network=None, raises=False):
        self._network = network or {"nodes": [], "edges": []}
        self._raises = raises

    def get_entity_network(self, entity_id, depth=1):
        if self._raises:
            raise RuntimeError("graph unavailable")
        return self._network


def node(node_id, node_type="account", **properties):
    return {"node_id": node_id, "node_type": node_type, "properties": properties}


def edge(edge_id, source, target, edge_type="sent_to", created_at="2026-01-01T00:00:00+00:00", **properties):
    return {
        "edge_id": edge_id,
        "source_id": source,
        "target_id": target,
        "edge_type": edge_type,
        "created_at": created_at,
        "properties": properties,
    }


def agent(network=None, raises=False) -> ForensicsAgent:
    return ForensicsAgent(store=SOCStore(), graph=FakeGraph(network, raises))


# An entity with two transactions, one access record and a linked device.
NETWORK = {
    "nodes": [
        node("ACC1"),
        node("ACC2"),
        node("DEV1", node_type="device"),
    ],
    "edges": [
        edge("E1", "ACC1", "ACC2", "sent_to", "2026-01-01T00:00:00+00:00"),
        edge("E2", "ACC2", "ACC1", "received_from", "2026-01-02T00:00:00+00:00"),
        edge("E3", "ACC1", "DEV1", "accessed", "2026-01-03T00:00:00+00:00"),
    ],
}


def artifact_of(result, artifact_type):
    return next(a for a in result.artifacts if a["type"] == artifact_type)


class TestDeterminism:
    """The defect this PR exists for."""

    def test_repeated_analysis_of_one_entity_agrees(self):
        instance = agent(NETWORK)
        verdicts = {
            instance.perform_forensics("ACC1", "comprehensive").conclusion
            for _ in range(50)
        }
        assert len(verdicts) == 1, f"verdict still non-deterministic: {verdicts}"

    def test_findings_are_stable_across_runs(self):
        instance = agent(NETWORK)
        seen = {
            tuple(
                (f["artifact_type"], f["significance"], f["anomaly_detected"])
                for f in instance.perform_forensics("ACC1", "comprehensive").findings
            )
            for _ in range(50)
        }
        assert len(seen) == 1

    def test_the_module_no_longer_imports_random(self):
        import src.multi_agent_soc.forensics_agent as module

        assert not hasattr(module, "random")


class TestArtifactCounts:
    def test_counts_are_the_real_record_counts(self):
        result = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        assert artifact_of(result, "transaction_log")["count"] == 2
        assert artifact_of(result, "access_log")["count"] == 1
        assert artifact_of(result, "communication_log")["count"] == 0

    def test_record_ids_are_reported_for_provenance(self):
        result = agent(NETWORK).perform_forensics("ACC1", "transaction")
        assert artifact_of(result, "transaction_log")["record_ids"] == ["E1", "E2"]

    def test_analysis_type_selects_artifact_classes(self):
        result = agent(NETWORK).perform_forensics("ACC1", "access")
        assert [a["type"] for a in result.artifacts if a["type"].endswith("_log")] == [
            "access_log"
        ]

    def test_an_unrecognised_analysis_type_collects_everything(self):
        """Returning no evidence for a typo would look like a clean entity."""
        result = agent(NETWORK).perform_forensics("ACC1", "not-a-real-type")
        assert artifact_of(result, "transaction_log")["count"] == 2

    def test_empty_artifact_classes_are_not_claimed_verified(self):
        result = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        assert artifact_of(result, "communication_log")["integrity"] == "unverified"

    def test_device_fingerprints_come_from_linked_device_nodes(self):
        result = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        prints = [a for a in result.artifacts if a["type"] == "device_fingerprint"]
        assert [p["device_id"] for p in prints] == ["DEV1"]

    def test_no_device_nodes_yields_no_fingerprints(self):
        network = {"nodes": [node("ACC1")], "edges": []}
        result = agent(network).perform_forensics("ACC1", "comprehensive")
        assert not [a for a in result.artifacts if a["type"] == "device_fingerprint"]


class TestTimeline:
    def test_events_are_real_records_in_recorded_order(self):
        result = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        assert [e["timestamp"] for e in result.timeline_events] == [
            "2026-01-01T00:00:00+00:00",
            "2026-01-02T00:00:00+00:00",
            "2026-01-03T00:00:00+00:00",
        ]

    def test_events_carry_their_source_record(self):
        result = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        assert [e["details"]["record_id"] for e in result.timeline_events] == [
            "E1",
            "E2",
            "E3",
        ]

    def test_undated_records_are_excluded(self):
        """An undated record cannot be placed on an evidential timeline."""
        network = {
            "nodes": [node("ACC1")],
            "edges": [
                edge("E1", "ACC1", "ACC2", created_at=""),
                {"edge_id": "E2", "source_id": "ACC1", "target_id": "ACC2"},
            ],
        }
        assert agent(network).perform_forensics("ACC1", "comprehensive").timeline_events == []

    def test_timeline_is_bounded(self):
        edges = [
            edge(f"E{i}", "ACC1", f"ACC{i}", created_at=f"2026-01-01T00:00:{i % 60:02d}+00:00")
            for i in range(ForensicsAgent.MAX_TIMELINE_EVENTS + 100)
        ]
        network = {"nodes": [node("ACC1")], "edges": edges}
        result = agent(network).perform_forensics("ACC1", "comprehensive")
        assert len(result.timeline_events) == ForensicsAgent.MAX_TIMELINE_EVENTS

    def test_ties_are_broken_stably(self):
        edges = [
            edge("E2", "ACC1", "ACC2", created_at="2026-01-01T00:00:00+00:00"),
            edge("E1", "ACC1", "ACC3", created_at="2026-01-01T00:00:00+00:00"),
        ]
        network = {"nodes": [node("ACC1")], "edges": edges}
        result = agent(network).perform_forensics("ACC1", "comprehensive")
        assert [e["details"]["record_id"] for e in result.timeline_events] == ["E1", "E2"]


class TestConclusion:
    def test_no_evidence_is_inconclusive_not_clear(self):
        """Reporting an unexamined entity as CLEAR asserts it is clean."""
        result = agent({"nodes": [], "edges": []}).perform_forensics("ACC1", "comprehensive")
        assert result.conclusion.startswith("INCONCLUSIVE")

    def test_verified_records_with_no_anomalies_are_clear(self):
        result = agent(NETWORK).perform_forensics("ACC1", "transaction")
        assert result.conclusion.startswith("CLEAR")

    def test_unverifiable_records_raise_a_suspicious_verdict(self):
        network = {
            "nodes": [node("ACC1")],
            "edges": [
                {
                    "source_id": "ACC1",
                    "target_id": "ACC2",
                    "edge_type": "sent_to",
                    "created_at": "2026-01-01T00:00:00+00:00",
                }
            ],
        }
        result = agent(network).perform_forensics("ACC1", "transaction")
        assert result.conclusion.startswith("SUSPICIOUS")

    def test_many_unverifiable_classes_escalate_to_critical(self):
        edges = [
            {
                "source_id": "ACC1",
                "target_id": "ACC2",
                "edge_type": edge_type,
                "created_at": "2026-01-01T00:00:00+00:00",
            }
            for edge_type in ("sent_to", "accessed", "communicated_with")
        ]
        network = {"nodes": [node("ACC1")], "edges": edges}
        result = agent(network).perform_forensics("ACC1", "comprehensive")
        assert result.conclusion.startswith("CRITICAL")

    def test_a_device_fingerprint_alone_is_not_a_clean_bill(self):
        network = {"nodes": [node("DEV1", node_type="device")], "edges": []}
        result = agent(network).perform_forensics("ACC1", "comprehensive")
        assert result.conclusion.startswith("INCONCLUSIVE")


class TestEvidenceHash:
    def test_hash_is_reproducible_for_identical_evidence(self):
        first = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        second = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        assert first.evidence_integrity_hash == second.evidence_integrity_hash

    def test_hash_changes_when_evidence_changes(self):
        altered = {
            "nodes": NETWORK["nodes"],
            "edges": NETWORK["edges"] + [edge("E9", "ACC1", "ACC5", "sent_to")],
        }
        first = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        second = agent(altered).perform_forensics("ACC1", "comprehensive")
        assert first.evidence_integrity_hash != second.evidence_integrity_hash

    def test_hash_is_independent_of_record_ordering(self):
        reversed_network = {
            "nodes": list(reversed(NETWORK["nodes"])),
            "edges": list(reversed(NETWORK["edges"])),
        }
        first = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        second = agent(reversed_network).perform_forensics("ACC1", "comprehensive")
        assert first.evidence_integrity_hash == second.evidence_integrity_hash


class TestChainOfCustody:
    def test_the_seal_records_the_hash_it_sealed(self):
        result = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        seal = next(
            c for c in result.chain_of_custody if c["action"] == "evidence_sealed"
        )
        assert seal["evidence_hash"] == result.evidence_integrity_hash

    def test_the_chain_records_the_artifact_count_it_covers(self):
        result = agent(NETWORK).perform_forensics("ACC1", "comprehensive")
        for entry in result.chain_of_custody:
            assert entry["artifact_count"] == len(result.artifacts)


class TestConfidence:
    def test_an_analysis_with_no_evidence_scores_low(self):
        result = agent({"nodes": [], "edges": []}).perform_forensics("ACC1", "comprehensive")
        assert result.confidence == 0.1

    def test_more_evidence_scores_higher(self):
        sparse = agent(
            {"nodes": [node("ACC1")], "edges": [edge("E1", "ACC1", "ACC2")]}
        ).perform_forensics("ACC1", "comprehensive")
        rich = agent(
            {
                "nodes": [node("ACC1")],
                "edges": [edge(f"E{i}", "ACC1", f"ACC{i}") for i in range(30)],
            }
        ).perform_forensics("ACC1", "comprehensive")
        assert rich.confidence > sparse.confidence

    def test_confidence_never_exceeds_the_cap(self):
        network = {
            "nodes": [node("ACC1")],
            "edges": [
                edge(f"E{i}", "ACC1", f"ACC{i}", edge_type)
                for edge_type in ("sent_to", "accessed", "communicated_with")
                for i in range(100)
            ],
        }
        assert agent(network).perform_forensics("ACC1", "comprehensive").confidence <= 0.95


class TestCollectEvidence:
    def test_hash_covers_the_underlying_records(self):
        """The old hash was over entity id and type only, so two different
        bodies of evidence for one entity hashed identically."""
        first = agent(NETWORK).collect_evidence("ACC1", ["transaction_log"])
        altered = {
            "nodes": NETWORK["nodes"],
            "edges": NETWORK["edges"] + [edge("E9", "ACC1", "ACC5", "sent_to")],
        }
        second = agent(altered).collect_evidence("ACC1", ["transaction_log"])
        assert first[0]["hash"] != second[0]["hash"]

    def test_integrity_is_not_claimed_without_records(self):
        items = agent({"nodes": [], "edges": []}).collect_evidence("ACC1", ["transaction_log"])
        assert items[0]["integrity_verified"] is False
        assert items[0]["record_count"] == 0

    def test_integrity_is_claimed_when_records_back_it(self):
        items = agent(NETWORK).collect_evidence("ACC1", ["transaction_log"])
        assert items[0]["integrity_verified"] is True
        assert items[0]["record_ids"] == ["E1", "E2"]

    def test_chain_of_custody_can_be_omitted(self):
        items = agent(NETWORK).collect_evidence("ACC1", ["transaction_log"], preserve_chain=False)
        assert "chain_of_custody" not in items[0]

    def test_chain_hash_matches_the_item_hash(self):
        items = agent(NETWORK).collect_evidence("ACC1", ["transaction_log"])
        assert items[0]["chain_of_custody"]["hash"] == items[0]["hash"]

    def test_an_unknown_evidence_type_yields_no_records(self):
        items = agent(NETWORK).collect_evidence("ACC1", ["nonsense_log"])
        assert items[0]["record_count"] == 0
        assert items[0]["integrity_verified"] is False


class TestVerifyEvidenceIntegrity:
    def test_matching_hashes_verify(self):
        assert agent().verify_evidence_integrity("abc123", "abc123") is True

    def test_differing_hashes_do_not_verify(self):
        assert agent().verify_evidence_integrity("abc123", "def456") is False

    @pytest.mark.parametrize(
        "left,right",
        [("", ""), (None, None), ("abc", ""), ("", "abc"), (None, "abc")],
    )
    def test_absent_hashes_never_verify(self, left, right):
        """Two records with no hash must not verify against each other."""
        assert agent().verify_evidence_integrity(left, right) is False


class TestGraphFailureIsSurvivable:
    def test_analysis_reports_an_absence_of_evidence(self):
        result = agent(NETWORK, raises=True).perform_forensics("ACC1", "comprehensive")
        assert result.conclusion.startswith("INCONCLUSIVE")
        assert result.confidence == 0.1
        assert result.timeline_events == []

    def test_evidence_collection_survives_graph_failure(self):
        items = agent(NETWORK, raises=True).collect_evidence("ACC1", ["transaction_log"])
        assert items[0]["integrity_verified"] is False

    def test_context_can_override_collection_depth(self):
        seen = {}

        class DepthRecordingGraph(FakeGraph):
            def get_entity_network(self, entity_id, depth=1):
                seen["depth"] = depth
                return {"nodes": [], "edges": []}

        instance = ForensicsAgent(store=SOCStore(), graph=DepthRecordingGraph())
        instance.perform_forensics("ACC1", "comprehensive", context={"collection_depth": 3})
        assert seen["depth"] == 3
