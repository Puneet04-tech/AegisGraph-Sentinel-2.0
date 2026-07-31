"""Unit tests for the AegisOracleExplainer (src/features/aegis_oracle_explainer.py).

Covers explanation generation for every decision type, confidence classification,
causal-factor extraction and ranking, attention-edge parsing across all supported
input shapes, and the blockchain evidence-ID regression fix.
"""

import math

import pytest

from src.features.aegis_oracle_explainer import AegisOracleExplainer


def _make_explainer() -> AegisOracleExplainer:
    return AegisOracleExplainer()


def _base_transaction(**overrides) -> dict:
    transaction = {
        "transaction_id": "TXN-001",
        "source_account": "ACC_SRC",
        "target_account": "ACC_TGT",
        "amount": 75000.0,
        "blockchain_evidence_id": "EVID_ABC123",
    }
    transaction.update(overrides)
    return transaction


def _base_assessment(decision="BLOCK", risk_score=0.92, confidence=0.95) -> dict:
    return {"decision": decision, "risk_score": risk_score, "confidence": confidence}


def _base_breakdown(**overrides) -> dict:
    breakdown = {"graph": 0.6, "velocity": 0.6, "behavior": 0.6, "entropy": 0.6}
    breakdown.update(overrides)
    return breakdown


def test_generate_explanation_block_returns_full_schema() -> None:
    explainer = _make_explainer()
    explanation = explainer.generate_explanation(
        _base_transaction(),
        _base_assessment(),
        break_down=_base_breakdown(),
    )
    assert explanation["decision"] == "BLOCK"
    assert explanation["transaction_id"] == "TXN-001"
    assert explanation["model_version"] == "HTGNN-2.1"
    assert "generated_at" in explanation
    assert explanation["confidence_level"] == "HIGH"
    assert "Transaction BLOCKED" in explanation["main_narrative"]


def test_generate_explanation_review_and_allow() -> None:
    explainer = _make_explainer()
    review = explainer.generate_explanation(
        _base_transaction(),
        _base_assessment(decision="REVIEW", risk_score=0.55, confidence=0.75),
        break_down=_base_breakdown(),
    )
    assert review["decision"] == "REVIEW"
    assert "FLAGGED FOR REVIEW" in review["main_narrative"]
    assert review["confidence_level"] == "MEDIUM"

    allow = explainer.generate_explanation(
        _base_transaction(),
        _base_assessment(decision="ALLOW", risk_score=0.1, confidence=0.6),
        break_down=_base_breakdown(),
    )
    assert allow["decision"] == "ALLOW"
    assert "APPROVED" in allow["main_narrative"]
    assert allow["confidence_level"] == "LOW"


def test_confidence_level_boundaries() -> None:
    explainer = _make_explainer()
    assert explainer._classify_confidence(0.95) == "HIGH"
    assert explainer._classify_confidence(0.90) == "HIGH"
    assert explainer._classify_confidence(0.89) == "MEDIUM"
    assert explainer._classify_confidence(0.70) == "MEDIUM"
    assert explainer._classify_confidence(0.69) == "LOW"


def test_risk_score_and_confidence_formatted_as_percent() -> None:
    explainer = _make_explainer()
    explanation = explainer.generate_explanation(
        _base_transaction(),
        _base_assessment(risk_score=0.92, confidence=0.95),
        break_down=_base_breakdown(),
    )
    assert explanation["risk_score"] == "92.0%"
    assert explanation["confidence"] == "95.0%"


def test_confidence_reasoning_messages() -> None:
    explainer = _make_explainer()
    reasons = explainer._generate_confidence_reasoning(0.95, 0.92, [])
    assert "Model confidence is very strong." in reasons
    assert "Risk score exceeds fraud threshold." in reasons

    moderate = explainer._generate_confidence_reasoning(0.75, 0.5, [])
    assert "Model confidence is moderate." in moderate

    limited = explainer._generate_confidence_reasoning(0.5, 0.1, [])
    assert "Model confidence is limited." in limited


def test_causal_factors_extracted_from_breakdown() -> None:
    explainer = _make_explainer()
    factors = explainer._extract_causal_factors(
        _base_transaction(),
        _base_breakdown(),
        [],
        {},
    )
    types = {factor["type"] for factor in factors}
    assert types == {"GRAPH", "VELOCITY", "BEHAVIORAL", "ENTROPY"}


def test_graph_factor_uses_higher_attention_weight() -> None:
    explainer = _make_explainer()
    factors = explainer._extract_causal_factors(
        _base_transaction(),
        _base_breakdown(graph=0.6),
        [],
        {"edges": [{"source": "A", "target": "B", "weight": 0.95}]},
    )
    graph_factor = next(f for f in factors if f["type"] == "GRAPH")
    assert graph_factor["weight"] == 0.95
    assert graph_factor["attention_edges"][0]["target"] == "B"


def test_attention_edges_capped_at_five() -> None:
    explainer = _make_explainer()
    edges = [
        {"source": f"n{i}", "target": f"m{i}", "weight": (i + 1) / 10}
        for i in range(10)
    ]
    factors = explainer._extract_causal_factors(
        _base_transaction(),
        _base_breakdown(graph=0.6),
        [],
        {"edges": edges},
    )
    graph_factor = next(f for f in factors if f["type"] == "GRAPH")
    assert len(graph_factor["attention_edges"]) == 5


def test_innovation_factors_honeypot_and_stress() -> None:
    explainer = _make_explainer()
    factors = explainer._extract_causal_factors(
        _base_transaction(),
        {},
        ["honeypot_activated", "behavioral_stress_detected"],
        {},
    )
    by_type = {factor["type"]: factor for factor in factors}
    assert by_type["INNOVATION_HONEYPOT"]["impact"] == "CRITICAL"
    assert by_type["INNOVATION_HONEYPOT"]["weight"] == 0.9
    assert by_type["INNOVATION_STRESS"]["impact"] == "HIGH"
    assert factors[0]["type"] == "INNOVATION_HONEYPOT"


def test_blockchain_evidence_id_uses_transaction_evidence_id() -> None:
    # Regression: the evidence string used to echo the literal innovation flag
    # name ("Evidence ID: blockchain_evidence_id") instead of a real ID.
    explainer = _make_explainer()
    factors = explainer._extract_causal_factors(
        _base_transaction(),
        {},
        ["blockchain_evidence_id"],
        {},
    )
    assert len(factors) == 1
    assert factors[0]["type"] == "INNOVATION_BLOCKCHAIN"
    assert factors[0]["evidence"] == "Evidence ID: EVID_ABC123"
    assert "blockchain_evidence_id" not in factors[0]["evidence"]


def test_blockchain_evidence_without_id_uses_generic_message() -> None:
    explainer = _make_explainer()
    factors = explainer._extract_causal_factors(
        _base_transaction(blockchain_evidence_id=None),
        {},
        ["blockchain_evidence_id"],
        {},
    )
    assert factors[0]["evidence"] == (
        "Evidence sealed on-chain; ID available in the evidence chain"
    )
    assert "blockchain_evidence_id" not in factors[0]["evidence"]


def test_factors_sorted_by_impact_then_weight() -> None:
    explainer = _make_explainer()
    factors = explainer._extract_causal_factors(
        _base_transaction(),
        {
            "graph": 0.9,
            "velocity": 0.6,
            "behavior": 0.8,
            "entropy": 0.7,
        },
        [],
        {},
    )
    # Impact order dominates weight: BEHAVIORAL (0.8) still ranks below
    # VELOCITY (0.6) because VELOCITY carries HIGH impact.
    assert [f["type"] for f in factors] == [
        "GRAPH",
        "VELOCITY",
        "BEHAVIORAL",
        "ENTROPY",
    ]


def test_parse_attention_edges_edges_list() -> None:
    explainer = _make_explainer()
    edges = explainer._parse_attention_edges({
        "edges": [
            {"source": "A", "target": "B", "weight": 0.4},
            {"source_node": "C", "target_node": "D", "attention_score": 0.9},
        ]
    })
    assert edges[0] == {"source": "C", "target": "D", "weight": 0.9}
    assert edges[1] == {"source": "A", "target": "B", "weight": 0.4}


def test_parse_attention_edges_top_relationships() -> None:
    explainer = _make_explainer()
    edges = explainer._parse_attention_edges({
        "top_relationships": [
            {"source": "X", "target": "Y", "weight": 0.7},
        ]
    })
    assert edges == [{"source": "X", "target": "Y", "weight": 0.7}]


def test_parse_attention_edges_flat_mapping() -> None:
    explainer = _make_explainer()
    edges = explainer._parse_attention_edges({
        "SRC->TGT": 0.8,
        "A -> B": 0.5,
        "not-an-edge": 1.0,
    })
    assert edges == [
        {"source": "SRC", "target": "TGT", "weight": 0.8},
        {"source": "A", "target": "B", "weight": 0.5},
    ]


def test_parse_attention_edges_malformed_entries_skipped() -> None:
    explainer = _make_explainer()
    edges = explainer._parse_attention_edges({
        "edges": [
            "not-a-dict",
            {"source": "A"},
            {"target": "B"},
            {"source": "A", "target": "B"},
            {"source": "A", "target": "B", "weight": "high"},
            {"source": "A", "target": "B", "weight": True},
            {"source": "A", "target": "B", "weight": 0.6},
        ]
    })
    assert edges == [{"source": "A", "target": "B", "weight": 0.6}]


def test_coerce_attention_weight_multihead_average() -> None:
    assert AegisOracleExplainer._coerce_attention_weight([0.8, 0.9]) == pytest.approx(0.85)
    assert AegisOracleExplainer._coerce_attention_weight((0.6,)) == pytest.approx(0.6)


def test_coerce_attention_weight_rejects_invalid_values() -> None:
    coerce = AegisOracleExplainer._coerce_attention_weight
    assert coerce(True) is None
    assert coerce("0.8") is None
    assert coerce(math.inf) is None
    assert coerce(float("nan")) is None
    assert coerce([]) is None
    assert coerce(0.75) == 0.75


def test_recommend_action_for_every_decision() -> None:
    explainer = _make_explainer()
    block = explainer._recommend_action("BLOCK", 0.9, [])
    assert block["primary"] == "BLOCK_TRANSACTION"
    assert block["tertiary"] == "FREEZE_ACCOUNT"

    review = explainer._recommend_action("REVIEW", 0.6, [])
    assert review["primary"] == "MANUAL_REVIEW"

    allow = explainer._recommend_action("ALLOW", 0.1, [])
    assert allow["primary"] == "ALLOW_TRANSACTION"

    unknown = explainer._recommend_action("UNKNOWN", 0.5, [])
    assert unknown["primary"] == "MANUAL_REVIEW"


def test_regulatory_section_contents() -> None:
    explainer = _make_explainer()
    explanation = explainer.generate_explanation(
        _base_transaction(),
        _base_assessment(),
        break_down=_base_breakdown(),
    )
    regulatory = explanation["regulatory_compliance"]
    assert regulatory["compliance_framework"] == (
        "RBI Master Direction on Fraud Risk Management"
    )
    assert regulatory["decision"] == "BLOCK"
    assert "appeal_process" in regulatory
    assert "legal_admissibility" in regulatory


def test_empty_inputs_do_not_crash() -> None:
    explainer = _make_explainer()
    explanation = explainer.generate_explanation({}, {})
    assert explanation["decision"] == "UNKNOWN"
    assert explanation["causal_factors"] == []
    assert explanation["recommended_action"]["primary"] == "MANUAL_REVIEW"


def test_explanation_templates_initialized() -> None:
    explainer = _make_explainer()
    assert "mule_chain" in explainer.explanation_templates
    assert "velocity_anomaly" in explainer.explanation_templates
    assert len(explainer.explanation_templates) == 6
