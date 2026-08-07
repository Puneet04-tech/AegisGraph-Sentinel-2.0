"""Tests for the Fraud Narrative Generator (src/autonomous_investigation/report_generator.py)."""

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from src.autonomous_investigation.models import (
    CasePriority,
    EvidenceArtifact,
    EvidenceType,
    FraudNarrative,
    InvestigationCase,
    InvestigationStatus,
    InvestigationTimeline,
    SeverityLevel,
)
from src.autonomous_investigation.report_generator import (
    FraudNarrativeGenerator,
    get_report_generator,
)


def _utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def make_case(**overrides):
    defaults = dict(
        case_id="case-1",
        title="Suspicious transfers",
        description="Investigation of suspicious transfers.",
        status=InvestigationStatus.IN_PROGRESS,
        priority=CasePriority.P1_HIGH,
        severity=SeverityLevel.SEVERE,
        alert_ids=["alert-1"],
        entity_ids=["acc-100", "acc-200"],
        evidence_ids=["ev-1", "ev-2"],
        confidence_score=0.75,
        patterns_detected=["money_mule_ring"],
        correlations_found=3,
    )
    defaults.update(overrides)
    return InvestigationCase(**defaults)


def make_evidence(**overrides):
    entity_id = overrides.pop("entity_id", None)
    defaults = dict(
        evidence_id="ev-1",
        evidence_type=EvidenceType.TRANSACTION,
        source_system="payment-gateway",
        source_id="txn-1",
        content={"amount": 500.0},
        collected_at=_utc(2026, 1, 2, 8, 0),
        relevance_score=0.9,
        is_verified=True,
    )
    defaults.update(overrides)
    evidence = EvidenceArtifact(**defaults)
    if entity_id is not None:
        evidence.entity_id = entity_id
    return evidence


def test_generate_summary_with_patterns_and_correlations():
    generator = FraudNarrativeGenerator()
    case = make_case()
    evidence = [make_evidence(), make_evidence(evidence_id="ev-2", content={"amount": 1.0})]

    summary = generator._generate_summary(case, evidence)

    assert "2 pieces of evidence related to 2 entities" in summary
    assert "revealed 1 potential fraud patterns" in summary
    assert "3 entity correlations were identified" in summary
    assert "overall risk assessment is severe" in summary
    assert "confidence score of 75%" in summary


def test_generate_summary_without_patterns_or_correlations():
    generator = FraudNarrativeGenerator()
    case = make_case(patterns_detected=[], correlations_found=0, severity=SeverityLevel.MODERATE, confidence_score=0.5)
    evidence = []

    summary = generator._generate_summary(case, evidence)

    assert "0 pieces of evidence related to 2 entities" in summary
    assert "potential fraud patterns" not in summary
    assert "correlations were identified" not in summary
    assert "risk assessment is moderate" in summary
    assert "confidence score of 50%" in summary


def test_generate_detailed_narrative_includes_background_and_evidence_types():
    generator = FraudNarrativeGenerator()
    case = make_case()
    evidence = [
        make_evidence(),
        make_evidence(evidence_id="ev-2", content={"amount": 1.0}),
        make_evidence(evidence_id="ev-3", evidence_type=EvidenceType.DEVICE, source_system="device-1"),
    ]

    narrative = generator._generate_detailed_narrative(case, evidence, [])

    assert narrative.startswith("## Investigation Details\n\n")
    assert "### Background\nInvestigation of suspicious transfers.\n\n" in narrative
    assert "A total of 3 evidence items were collected and analyzed." in narrative
    assert "- Transaction: 2 items" in narrative
    assert "- Device: 1 items" in narrative
    assert "### Key Findings" not in narrative
    assert "### Detected Patterns\n- money_mule_ring\n" in narrative


def test_generate_detailed_narrative_with_findings():
    generator = FraudNarrativeGenerator()
    case = make_case()
    evidence = [make_evidence()]
    findings = [
        {"description": "Rapid fund dispersal observed"},
        {"description": "Shared device across accounts"},
    ]

    narrative = generator._generate_detailed_narrative(case, evidence, findings)

    assert "### Key Findings\n1. Rapid fund dispersal observed\n2. Shared device across accounts\n" in narrative


def test_generate_timeline_description_full():
    generator = FraudNarrativeGenerator()
    case = make_case(
        started_at=_utc(2026, 1, 1, 10, 0),
        completed_at=_utc(2026, 1, 4, 12, 0),
    )
    evidence = [
        make_evidence(evidence_id="ev-1", collected_at=_utc(2026, 1, 2, 8, 0)),
        make_evidence(evidence_id="ev-2", collected_at=_utc(2026, 1, 3, 9, 30)),
    ]

    timeline = generator._generate_timeline_description(case, evidence)

    assert timeline.startswith("## Event Timeline\n\n")
    assert "Investigation started: 2026-01-01 10:00" in timeline
    assert "Evidence collected from 2026-01-02 08:00 to 2026-01-03 09:30" in timeline
    assert "Investigation completed: 2026-01-04 12:00" in timeline


def test_generate_timeline_description_without_timestamps_or_evidence():
    generator = FraudNarrativeGenerator()
    case = make_case(started_at=None, completed_at=None)

    timeline = generator._generate_timeline_description(case, [])

    assert timeline == "## Event Timeline\n\n"


def test_extract_fraud_indicators_transaction():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(content={"velocity": 6, "amount": 20000, "unusual_pattern": True}),
        make_evidence(evidence_id="ev-2", content={"velocity": 2, "amount": 500}),
    ]

    indicators = generator._extract_fraud_indicators(evidence)

    assert set(indicators) == {
        "High transaction velocity detected",
        "High-value transaction",
        "Unusual transaction pattern",
    }


def test_extract_fraud_indicators_device_and_ip():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(evidence_type=EvidenceType.DEVICE, content={"is_new_device": True, "risk_score": 0.9}),
        make_evidence(evidence_type=EvidenceType.IP_ADDRESS, content={"is_vpn": True}),
        make_evidence(evidence_id="ev-3", evidence_type=EvidenceType.IP_ADDRESS, content={"is_proxy": True}),
        make_evidence(evidence_id="ev-4", evidence_type=EvidenceType.IP_ADDRESS, content={}),
    ]

    indicators = generator._extract_fraud_indicators(evidence)

    assert set(indicators) == {
        "First-time device usage",
        "High-risk device",
        "Anonymous network detected",
    }


def test_extract_fraud_indicators_boundaries():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(content={"velocity": 5, "amount": 10000, "unusual_pattern": False}),
        make_evidence(evidence_id="ev-2", evidence_type=EvidenceType.DEVICE, content={"is_new_device": False, "risk_score": 0.7}),
    ]

    indicators = generator._extract_fraud_indicators(evidence)

    assert indicators == []


def test_extract_fraud_indicators_deduplicates_and_caps_at_ten():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(evidence_id=f"ev-{i}", content={"amount": 20000.0}) for i in range(15)
    ]

    indicators = generator._extract_fraud_indicators(evidence)

    assert len(indicators) <= 10
    assert set(indicators) == {"High-value transaction"}


def test_extract_affected_entities_includes_case_and_evidence():
    generator = FraudNarrativeGenerator()
    case = make_case(entity_ids=["acc-100"])
    evidence = [
        make_evidence(entity_id="acc-100"),
        make_evidence(evidence_id="ev-2", entity_id="acc-200"),
    ]

    entities = generator._extract_affected_entities(case, evidence)

    assert entities == ["acc-100", "acc-200"]


def test_extract_affected_entities_capped_at_twenty():
    generator = FraudNarrativeGenerator()
    case = make_case(entity_ids=[f"acc-{i}" for i in range(15)])
    evidence = [
        make_evidence(evidence_id=f"ev-{i}", entity_id=f"extra-{i}") for i in range(10)
    ]

    entities = generator._extract_affected_entities(case, evidence)

    assert len(entities) == 20
    assert entities[:15] == case.entity_ids
    assert "extra-9" not in entities


def test_estimate_financial_impact_sums_transactions():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(content={"amount": 500.0}),
        make_evidence(evidence_id="ev-2", content={"amount": 1500.5}),
        make_evidence(evidence_id="ev-3", evidence_type=EvidenceType.DEVICE, content={}),
    ]

    impact = generator._estimate_financial_impact(make_case(), evidence)

    assert impact == pytest.approx(2000.5)


def test_estimate_financial_impact_none_when_zero():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(content={"amount": 0}),
        make_evidence(evidence_id="ev-2", evidence_type=EvidenceType.DEVICE, content={}),
    ]

    assert generator._estimate_financial_impact(make_case(), evidence) is None


def test_extract_key_findings_filters_and_formats():
    generator = FraudNarrativeGenerator()
    findings = [
        {"description": "first finding"},
        {"description": ""},
        "plain string finding",
        42,
        {"no_description_key": True},
        {"description": "sixth finding"},
    ]

    key_findings = generator._extract_key_findings(findings)

    assert key_findings == ["first finding", "plain string finding", "42"]


def test_calculate_confidence_no_evidence():
    generator = FraudNarrativeGenerator()

    assert generator._calculate_confidence([], []) == pytest.approx(0.5)


def test_calculate_confidence_scales_with_evidence_and_verification():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(is_verified=True),
        make_evidence(evidence_id="ev-2", is_verified=False),
    ]

    confidence = generator._calculate_confidence(evidence, [])

    assert confidence == pytest.approx(0.66)


def test_calculate_confidence_capped_at_one():
    generator = FraudNarrativeGenerator()
    evidence = [make_evidence(evidence_id=f"ev-{i}", is_verified=True) for i in range(30)]

    assert generator._calculate_confidence(evidence, []) == pytest.approx(1.0)


def test_reconstruct_events_sorted_with_importance():
    generator = FraudNarrativeGenerator()
    evidence = [
        make_evidence(evidence_id="ev-1", collected_at=_utc(2026, 1, 3, 9, 0), relevance_score=0.5),
        make_evidence(evidence_id="ev-2", collected_at=_utc(2026, 1, 1, 7, 0), relevance_score=0.95),
    ]

    events = generator._reconstruct_events(evidence)

    assert [e["timestamp"] for e in events] == ["2026-01-01T07:00:00+00:00", "2026-01-03T09:00:00+00:00"]
    assert events[0]["type"] == "transaction"
    assert events[0]["description"] == "Evidence collected: payment-gateway"
    assert events[0]["importance"] == "high"
    assert events[1]["importance"] == "medium"


def test_build_sequence_numbered():
    generator = FraudNarrativeGenerator()
    events = [
        {"type": "transaction", "timestamp": "2026-01-01T07:00:00+00:00", "importance": "high"},
        {"type": "device", "timestamp": "2026-01-03T09:00:00+00:00", "importance": "medium"},
    ]

    sequence = generator._build_sequence(events)

    assert sequence == [
        "1. transaction at 2026-01-01T07:00:00+00:00",
        "2. device at 2026-01-03T09:00:00+00:00",
    ]


def test_identify_critical_path_high_importance_only():
    generator = FraudNarrativeGenerator()
    events = [
        {"type": "transaction", "timestamp": "2026-01-01T07:00:00+00:00", "importance": "high"},
        {"type": "device", "timestamp": "2026-01-02T07:00:00+00:00", "importance": "medium"},
        {"type": "ip_address", "timestamp": "2026-01-03T07:00:00+00:00", "importance": "high"},
    ]

    assert generator._identify_critical_path(events) == ["transaction", "ip_address"]


def test_detect_timeline_anomalies_empty_and_single_event():
    generator = FraudNarrativeGenerator()

    assert generator._detect_timeline_anomalies([]) == []
    assert generator._detect_timeline_anomalies([{"timestamp": "2026-01-01T07:00:00+00:00"}]) == []


def test_detect_timeline_anomalies_large_gap():
    generator = FraudNarrativeGenerator()
    events = [
        {"type": "transaction", "timestamp": "2026-01-01T00:00:00+00:00", "importance": "high"},
        {"type": "device", "timestamp": "2026-01-02T12:00:00+00:00", "importance": "medium"},
    ]

    anomalies = generator._detect_timeline_anomalies(events)

    assert anomalies == ["Large time gap (36.0 hours) between events"]


def test_detect_timeline_anomalies_no_gap():
    generator = FraudNarrativeGenerator()
    events = [
        {"type": "transaction", "timestamp": "2026-01-01T00:00:00+00:00", "importance": "high"},
        {"type": "device", "timestamp": "2026-01-01T12:00:00+00:00", "importance": "medium"},
    ]

    assert generator._detect_timeline_anomalies(events) == []


def test_generate_narrative(monkeypatch):
    fixed_id = UUID("00000000-0000-0000-0000-0000000000ab")
    monkeypatch.setattr("src.autonomous_investigation.report_generator.uuid.uuid4", lambda: fixed_id)
    generator = FraudNarrativeGenerator()
    case = make_case()
    evidence = [
        make_evidence(content={"amount": 500.0}),
        make_evidence(evidence_id="ev-2", content={"velocity": 6}),
    ]
    findings = [{"description": "Rapid fund dispersal"}]

    narrative = asyncio.run(generator.generate_narrative(case, evidence, findings))

    assert isinstance(narrative, FraudNarrative)
    assert narrative.narrative_id == str(fixed_id)
    assert narrative.case_id == "case-1"
    assert narrative.summary
    assert narrative.detailed_narrative.startswith("## Investigation Details")
    assert narrative.key_findings == ["Rapid fund dispersal"]
    assert narrative.timeline_description.startswith("## Event Timeline")
    assert "High transaction velocity detected" in narrative.fraud_indicators
    assert narrative.affected_entities == ["acc-100", "acc-200"]
    assert narrative.financial_impact == pytest.approx(500.0)
    assert narrative.narrative_type == "full"
    assert narrative.confidence_score == pytest.approx(0.76)
    assert narrative.generated_at.tzinfo is not None


def test_generate_timeline(monkeypatch):
    fixed_id = UUID("00000000-0000-0000-0000-0000000000cd")
    monkeypatch.setattr("src.autonomous_investigation.report_generator.uuid.uuid4", lambda: fixed_id)
    generator = FraudNarrativeGenerator()
    case = make_case()
    evidence = [
        make_evidence(evidence_id="ev-1", collected_at=_utc(2026, 1, 3, 9, 0), relevance_score=0.5),
        make_evidence(evidence_id="ev-2", collected_at=_utc(2026, 1, 1, 7, 0), relevance_score=0.95),
    ]

    timeline = asyncio.run(generator.generate_timeline(case, evidence))

    assert isinstance(timeline, InvestigationTimeline)
    assert timeline.timeline_id == str(fixed_id)
    assert timeline.case_id == "case-1"
    assert len(timeline.events) == 2
    assert timeline.events[0]["timestamp"] == "2026-01-01T07:00:00+00:00"
    assert timeline.reconstructed_sequence == [
        "1. transaction at 2026-01-01T07:00:00+00:00",
        "2. transaction at 2026-01-03T09:00:00+00:00",
    ]
    assert timeline.critical_path == ["transaction"]
    assert timeline.anomalies_detected == [
        "Large time gap (50.0 hours) between events",
    ]


def test_generate_executive_summary():
    generator = FraudNarrativeGenerator()
    case = make_case()
    narrative = FraudNarrative(
        narrative_id="narrative-1",
        case_id=case.case_id,
        summary="Narrative summary text.",
        detailed_narrative="",
        key_findings=["Finding one", "Finding two", "Finding three"],
        timeline_description="",
        fraud_indicators=[],
        affected_entities=[],
    )

    summary = asyncio.run(generator.generate_executive_summary(case, narrative))

    assert summary.startswith("Investigation ID: case-1\n")
    assert "Title: Suspicious transfers" in summary
    assert "Risk Level: SEVERE" in summary
    assert "Priority: P1_HIGH" in summary
    assert "Summary:\nNarrative summary text." in summary
    assert "  1. Finding one" in summary
    assert "  2. Finding two" in summary
    assert "  3. Finding three" in summary
    assert "  - Review evidence within 24 hours" in summary
    assert "  - Determine appropriate action based on risk level" in summary


def test_generate_executive_summary_limits_findings_to_five():
    generator = FraudNarrativeGenerator()
    case = make_case()
    narrative = FraudNarrative(
        narrative_id="narrative-1",
        case_id=case.case_id,
        summary="",
        detailed_narrative="",
        key_findings=[f"Finding {i}" for i in range(1, 8)],
        timeline_description="",
        fraud_indicators=[],
        affected_entities=[],
    )

    summary = asyncio.run(generator.generate_executive_summary(case, narrative))

    assert "  5. Finding 5" in summary
    assert "  6. Finding 6" not in summary


def test_get_report_generator_singleton(monkeypatch):
    import src.autonomous_investigation.report_generator as rg

    monkeypatch.setattr(rg, "_generator", None)

    first = rg.get_report_generator()
    second = rg.get_report_generator()

    assert isinstance(first, FraudNarrativeGenerator)
    assert first is second
