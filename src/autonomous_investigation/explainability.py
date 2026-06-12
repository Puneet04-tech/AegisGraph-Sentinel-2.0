"""
Explainability Engine for decision tracing and transparency.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    DecisionRecommendation,
    InvestigationCase,
    EvidenceArtifact,
    AuditRecord,
)


class ExplainabilityEngine:
    """
    Provides explainability and audit trail for AI decisions.

    Handles:
    - Decision tracing
    - Evidence attribution
    - Risk explanation
    - Audit logging
    """

    def __init__(self):
        self._explanation_cache: Dict[str, Any] = {}

    async def explain_decision(
        self,
        decision: DecisionRecommendation,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> Dict[str, Any]:
        """Generate comprehensive explanation for a decision."""
        explanation = {
            "explanation_id": str(uuid.uuid4()),
            "decision_type": decision.decision_type.value,
            "confidence": decision.confidence,
            "summary": self._generate_summary(decision, case),
            "evidence_attribution": self._attribute_evidence(evidence, decision),
            "risk_factors": self._explain_risk_factors(case, evidence),
            "decision_reasoning": self._explain_reasoning(decision, case),
            "confidence_factors": self._explain_confidence(decision, evidence),
            "alternatives": self._explain_alternatives(decision),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Cache explanation
        self._explanation_cache[explanation["explanation_id"]] = explanation

        return explanation

    def get_decision_trace(
        self,
        decision: DecisionRecommendation,
    ) -> List[Dict[str, Any]]:
        """Get trace of decision-making process."""
        trace = []

        # Input collection
        trace.append({
            "step": 1,
            "name": "Input Collection",
            "description": "Collected case data and evidence",
            "factors": ["case_id", "entity_ids", "evidence_count"],
        })

        # Risk assessment
        trace.append({
            "step": 2,
            "name": "Risk Assessment",
            "description": "Calculated overall risk score",
            "factors": ["risk_score", "severity", "patterns"],
        })

        # Evidence analysis
        trace.append({
            "step": 3,
            "name": "Evidence Analysis",
            "description": "Analyzed evidence relevance and patterns",
            "factors": ["evidence_types", "relevance_scores", "findings"],
        })

        # Decision generation
        trace.append({
            "step": 4,
            "name": "Decision Generation",
            "description": f"Generated {decision.decision_type.value} decision",
            "factors": ["decision_type", "confidence", "supporting_evidence"],
        })

        # Human review check
        trace.append({
            "step": 5,
            "name": "Review Determination",
            "description": "Determined if human review required",
            "factors": ["requires_human_review"],
        })

        return trace

    def explain_risk_score(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> Dict[str, Any]:
        """Explain how risk score was calculated."""
        factors = []

        # Case factors
        if case.risk_score > 0:
            factors.append({
                "name": "Base Risk Score",
                "contribution": case.risk_score * 0.4,
                "weight": 0.4,
                "description": "Initial risk score from case creation",
            })

        # Evidence factors
        if evidence:
            avg_relevance = sum(e.relevance_score for e in evidence) / len(evidence)
            factors.append({
                "name": "Evidence Quality",
                "contribution": avg_relevance * 0.3,
                "weight": 0.3,
                "description": f"Average evidence relevance: {avg_relevance:.2f}",
            })

        # Pattern factors
        if case.patterns_detected:
            factors.append({
                "name": "Fraud Patterns",
                "contribution": min(0.2, len(case.patterns_detected) * 0.05),
                "weight": 0.2,
                "description": f"Detected {len(case.patterns_detected)} patterns",
            })

        # Correlation factors
        if case.correlations_found > 0:
            factors.append({
                "name": "Entity Correlations",
                "contribution": min(0.1, case.correlations_found * 0.01),
                "weight": 0.1,
                "description": f"Found {case.correlations_found} correlations",
            })

        return {
            "factors": factors,
            "total_risk_score": case.risk_score,
            "explanation": self._generate_risk_explanation(factors),
        }

    def get_evidence_attribution(
        self,
        evidence: List[EvidenceArtifact],
        decision: DecisionRecommendation,
    ) -> Dict[str, Any]:
        """Attribute decision to specific evidence."""
        attributed_evidence = []
        total_attribution = 0.0

        # Sort by relevance
        sorted_evidence = sorted(
            evidence, key=lambda e: e.relevance_score, reverse=True
        )

        for e in sorted_evidence[:10]:
            attribution_score = e.relevance_score * 0.1
            total_attribution += attribution_score

            attributed_evidence.append({
                "evidence_id": e.evidence_id,
                "evidence_type": e.evidence_type.value,
                "source": e.source_system,
                "attribution_score": attribution_score,
                "contribution": f"Evidence from {e.source_system} "
                                f"contributed {attribution_score:.2f} to decision",
            })

        return {
            "total_attribution": min(1.0, total_attribution),
            "evidence_count": len(attributed_evidence),
            "attributions": attributed_evidence,
        }

    def generate_audit_report(
        self,
        case: InvestigationCase,
        decision: DecisionRecommendation,
    ) -> AuditRecord:
        """Generate audit record for decision."""
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            operation="decision_explanation_generated",
            case_id=case.case_id,
            user_id="system",
            action=f"Generated {decision.decision_type.value} decision explanation",
            details={
                "decision_id": decision.recommendation_id,
                "decision_type": decision.decision_type.value,
                "confidence": decision.confidence,
                "risk_explanation": decision.risk_explanation,
            },
            timestamp=datetime.now(timezone.utc),
        )

        return record

    def _generate_summary(
        self,
        decision: DecisionRecommendation,
        case: InvestigationCase,
    ) -> str:
        """Generate brief summary of decision."""
        summary = f"AI recommends {decision.decision_type.value.upper()} "
        summary += f"with {decision.confidence:.0%} confidence. "

        if decision.requires_human_review:
            summary += "Human review is recommended. "

        summary += f"Based on analysis of {len(decision.supporting_evidence)} "
        summary += "evidence items."

        return summary

    def _attribute_evidence(
        self,
        evidence: List[EvidenceArtifact],
        decision: DecisionRecommendation,
    ) -> List[Dict[str, Any]]:
        """Attribute decision to evidence."""
        attributions = []

        for e in evidence:
            if e.evidence_id in decision.supporting_evidence:
                attributions.append({
                    "evidence_id": e.evidence_id,
                    "type": e.evidence_type.value,
                    "relevance": e.relevance_score,
                    "role": "supporting",
                })

        return attributions

    def _explain_risk_factors(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> List[str]:
        """Explain contributing risk factors."""
        factors = []

        if case.severity.value in ["critical", "severe"]:
            factors.append(f"High severity level: {case.severity.value}")

        if case.risk_score > 0.7:
            factors.append(f"Elevated risk score: {case.risk_score:.2f}")

        if case.patterns_detected:
            factors.append(f"Detected {len(case.patterns_detected)} fraud patterns")

        if case.correlations_found > 0:
            factors.append(f"Found {case.correlations_found} entity correlations")

        # Check evidence for risk factors
        high_risk_evidence = [e for e in evidence if e.relevance_score > 0.8]
        if high_risk_evidence:
            factors.append(
                f"{len(high_risk_evidence)} high-relevance evidence items"
            )

        return factors

    def _explain_reasoning(
        self,
        decision: DecisionRecommendation,
        case: InvestigationCase,
    ) -> str:
        """Explain decision reasoning."""
        reasoning = decision.risk_explanation

        if decision.requires_human_review:
            reasoning += " Human review is recommended due to "
            if decision.confidence < 0.7:
                reasoning += "moderate confidence in the analysis."
            else:
                reasoning += "the high-risk nature of this case."

        return reasoning

    def _explain_confidence(
        self,
        decision: DecisionRecommendation,
        evidence: List[EvidenceArtifact],
    ) -> Dict[str, Any]:
        """Explain confidence level."""
        factors = []

        # Evidence quantity
        factors.append({
            "factor": "Evidence Quantity",
            "impact": "positive" if len(evidence) > 5 else "neutral",
            "description": f"{len(evidence)} evidence items available",
        })

        # Evidence quality
        if evidence:
            avg_relevance = sum(e.relevance_score for e in evidence) / len(evidence)
            factors.append({
                "factor": "Evidence Quality",
                "impact": "positive" if avg_relevance > 0.7 else "neutral",
                "description": f"Average relevance: {avg_relevance:.2f}",
            })

        return {
            "overall_confidence": decision.confidence,
            "confidence_level": self._get_confidence_level(decision.confidence),
            "factors": factors,
        }

    def _explain_alternatives(
        self,
        decision: DecisionRecommendation,
    ) -> List[str]:
        """Explain alternative decisions."""
        alternatives = []

        for alt in decision.alternative_decisions:
            alternatives.append(
                f"{alt['decision_type']}: {alt.get('reason', 'Alternative option')}"
            )

        return alternatives

    def _generate_risk_explanation(
        self,
        factors: List[Dict[str, Any]],
    ) -> str:
        """Generate human-readable risk explanation."""
        if not factors:
            return "No significant risk factors identified."

        explanation = "Risk score is derived from: "
        factor_names = [f["name"] for f in factors]
        explanation += ", ".join(factor_names[:-1])
        if len(factor_names) > 1:
            explanation += f", and {factor_names[-1]}."

        return explanation

    def _get_confidence_level(self, confidence: float) -> str:
        """Get confidence level description."""
        if confidence >= 0.9:
            return "very_high"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "moderate"
        elif confidence >= 0.3:
            return "low"
        else:
            return "very_low"


# Global engine instance
_engine: Optional[ExplainabilityEngine] = None


def get_explainability_engine() -> ExplainabilityEngine:
    """Get the explainability engine instance."""
    global _engine
    if _engine is None:
        _engine = ExplainabilityEngine()
    return _engine