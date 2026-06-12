"""
Decision Intelligence Engine for AI-powered risk-based recommendations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    InvestigationCase,
    EvidenceArtifact,
    RiskAssessment,
    DecisionType,
    DecisionRecommendation,
)


class DecisionIntelligenceEngine:
    """
    Generates AI-powered decision recommendations for investigations.

    Handles:
    - Risk-based decision making
    - Multi-factor analysis
    - Decision confidence scoring
    - Alternative decision generation
    """

    def __init__(self):
        self._decision_rules = self._initialize_rules()

    def _initialize_rules(self) -> Dict[str, Any]:
        """Initialize decision rules."""
        return {
            "critical_risk_threshold": 0.9,
            "high_risk_threshold": 0.7,
            "medium_risk_threshold": 0.5,
            "require_review_threshold": 0.6,
        }

    async def generate_decision(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
        assessment: Optional[RiskAssessment],
    ) -> DecisionRecommendation:
        """Generate decision recommendation for a case."""
        # Calculate decision factors
        risk_score = self._calculate_risk_score(case, evidence, assessment)
        confidence = self._calculate_confidence(case, evidence)
        decision_type = self._determine_decision_type(risk_score, confidence)
        supporting_evidence = self._get_supporting_evidence(evidence, decision_type)
        recommended_actions = self._generate_recommended_actions(
            decision_type, case, evidence
        )
        alternative_decisions = self._generate_alternatives(
            decision_type, risk_score, confidence
        )

        # Generate risk explanation
        risk_explanation = self._generate_risk_explanation(
            risk_score, decision_type, case
        )

        # Determine if human review required
        requires_review = self._requires_human_review(
            decision_type, confidence, risk_score
        )

        recommendation = DecisionRecommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case.case_id,
            decision_type=decision_type,
            confidence=confidence,
            supporting_evidence=supporting_evidence,
            risk_explanation=risk_explanation,
            recommended_actions=recommended_actions,
            alternative_decisions=alternative_decisions,
            decision_date=datetime.now(timezone.utc),
            model_id="decision-intelligence-v1",
            model_confidence=0.95,
            requires_human_review=requires_review,
        )

        return recommendation

    def _calculate_risk_score(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
        assessment: Optional[RiskAssessment],
    ) -> float:
        """Calculate overall risk score."""
        base_score = case.risk_score

        # Adjust based on evidence quality
        if evidence:
            evidence_score = sum(e.relevance_score for e in evidence) / len(evidence)
            base_score = (base_score + evidence_score) / 2

        # Adjust based on assessment
        if assessment:
            base_score = (base_score + assessment.risk_score) / 2

        # Adjust based on severity
        severity_map = {
            "critical": 0.3,
            "severe": 0.2,
            "moderate": 0.0,
            "warning": -0.1,
            "info": -0.2,
        }
        base_score += severity_map.get(case.severity.value, 0.0)

        return max(0.0, min(1.0, base_score))

    def _calculate_confidence(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> float:
        """Calculate decision confidence."""
        confidence = 0.5

        # More evidence = higher confidence
        evidence_factor = min(0.3, len(evidence) * 0.05)
        confidence += evidence_factor

        # More findings = higher confidence
        finding_factor = min(0.2, len(case.findings) * 0.02)
        confidence += finding_factor

        # Time factor
        if case.completed_at and case.started_at:
            duration = (case.completed_at - case.started_at).total_seconds()
            if duration > 3600:  # More than 1 hour = thorough investigation
                confidence += 0.1

        return max(0.0, min(1.0, confidence))

    def _determine_decision_type(
        self, risk_score: float, confidence: float
    ) -> DecisionType:
        """Determine the appropriate decision type."""
        if risk_score >= self._decision_rules["critical_risk_threshold"]:
            if confidence >= 0.8:
                return DecisionType.BLOCK
            return DecisionType.ESCALATE
        elif risk_score >= self._decision_rules["high_risk_threshold"]:
            if confidence >= 0.7:
                return DecisionType.REJECT
            return DecisionType.REVIEW
        elif risk_score >= self._decision_rules["medium_risk_threshold"]:
            return DecisionType.FLAG
        else:
            if confidence >= 0.6:
                return DecisionType.APPROVE
            return DecisionType.REVIEW

    def _get_supporting_evidence(
        self,
        evidence: List[EvidenceArtifact],
        decision_type: DecisionType,
    ) -> List[str]:
        """Get evidence IDs supporting the decision."""
        supporting = []

        # Select most relevant evidence
        sorted_evidence = sorted(
            evidence, key=lambda e: e.relevance_score, reverse=True
        )

        # Include top 5 evidence items
        for e in sorted_evidence[:5]:
            supporting.append(e.evidence_id)

        return supporting

    def _generate_recommended_actions(
        self,
        decision_type: DecisionType,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> List[str]:
        """Generate recommended actions based on decision type."""
        actions = []

        if decision_type == DecisionType.BLOCK:
            actions.extend([
                "Block transaction immediately",
                "Freeze associated accounts",
                "Notify fraud prevention team",
                "Initiate investigation protocol",
            ])
        elif decision_type == DecisionType.REJECT:
            actions.extend([
                "Reject transaction",
                "Flag account for review",
                "Notify customer",
            ])
        elif decision_type == DecisionType.ESCALATE:
            actions.extend([
                "Escalate to senior analyst",
                "Schedule review meeting",
                "Prepare escalation report",
            ])
        elif decision_type == DecisionType.REVIEW:
            actions.extend([
                "Review transaction details",
                "Verify customer identity",
                "Check historical patterns",
            ])
        elif decision_type == DecisionType.FLAG:
            actions.extend([
                "Add to watch list",
                "Monitor for additional activity",
                "Log for pattern analysis",
            ])
        elif decision_type == DecisionType.APPROVE:
            actions.extend([
                "Approve transaction",
                "Continue monitoring",
                "Update risk profile",
            ])

        return actions

    def _generate_alternatives(
        self,
        primary_decision: DecisionType,
        risk_score: float,
        confidence: float,
    ) -> List[Dict[str, Any]]:
        """Generate alternative decision options."""
        alternatives = []

        # Add lower-risk alternative
        if primary_decision in [DecisionType.BLOCK, DecisionType.REJECT]:
            alternatives.append({
                "decision_type": DecisionType.FLAG.value,
                "reason": "Alternative with lower immediate impact",
                "confidence_adjustment": -0.1,
            })

        # Add human review alternative
        if confidence < 0.8:
            alternatives.append({
                "decision_type": DecisionType.REVIEW.value,
                "reason": "Human review recommended due to uncertainty",
                "confidence_adjustment": 0.0,
            })

        # Add escalate alternative
        if primary_decision == DecisionType.APPROVE and risk_score > 0.3:
            alternatives.append({
                "decision_type": DecisionType.FLAG.value,
                "reason": "Caution warranted based on risk factors",
                "confidence_adjustment": -0.05,
            })

        return alternatives

    def _generate_risk_explanation(
        self, risk_score: float, decision_type: DecisionType, case: InvestigationCase
    ) -> str:
        """Generate human-readable risk explanation."""
        risk_level = self._get_risk_level(risk_score)

        explanation = f"Risk Assessment: {risk_level.upper()} (score: {risk_score:.2f}). "
        explanation += f"Recommendation: {decision_type.value.upper()}. "

        if case.patterns_detected:
            explanation += f"Detected {len(case.patterns_detected)} fraud patterns. "

        if case.correlations_found > 0:
            explanation += f"Found {case.correlations_found} entity correlations. "

        if case.findings:
            explanation += f"Key findings include: {'; '.join(case.findings[:3])}. "

        return explanation

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 0.9:
            return "critical"
        elif risk_score >= 0.7:
            return "high"
        elif risk_score >= 0.5:
            return "medium"
        elif risk_score >= 0.3:
            return "low"
        else:
            return "minimal"

    def _requires_human_review(
        self, decision_type: DecisionType, confidence: float, risk_score: float
    ) -> bool:
        """Determine if human review is required."""
        # High-risk decisions always require review
        if decision_type in [DecisionType.BLOCK, DecisionType.ESCALATE]:
            if confidence < 0.95:
                return True

        # Medium-risk with low confidence requires review
        if confidence < self._decision_rules["require_review_threshold"]:
            return True

        # High risk score with low confidence requires review
        if risk_score > 0.7 and confidence < 0.8:
            return True

        return False


# Global engine instance
_engine: Optional[DecisionIntelligenceEngine] = None


def get_decision_engine() -> DecisionIntelligenceEngine:
    """Get the decision intelligence engine instance."""
    global _engine
    if _engine is None:
        _engine = DecisionIntelligenceEngine()
    return _engine