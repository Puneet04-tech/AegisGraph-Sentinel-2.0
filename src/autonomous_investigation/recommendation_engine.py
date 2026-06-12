"""
Recommendation Engine for analyst copilot recommendations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid

from .models import (
    InvestigationCase,
    EvidenceArtifact,
    AnalystRecommendation,
    CasePriority,
)


class RecommendationEngine:
    """
    Generates recommendations for fraud analysts (Copilot).

    Handles:
    - Investigation suggestions
    - Next action recommendations
    - Evidence review priorities
    - Questions to investigate
    """

    def __init__(self):
        self._suggestion_templates = self._initialize_templates()

    def _initialize_templates(self) -> Dict[str, List[str]]:
        """Initialize recommendation templates."""
        return {
            "review_evidence": [
                "Review the most recent transaction for anomalies",
                "Verify device fingerprint matches known devices",
                "Check IP geolocation consistency",
            ],
            "investigate": [
                "Contact customer to verify recent activity",
                "Request additional identity verification",
                "Check for similar cases in history",
            ],
            "take_action": [
                "Approve with standard monitoring",
                "Flag for enhanced due diligence",
                "Block and escalate to fraud team",
            ],
        }

    async def generate_analyst_recommendations(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> List[AnalystRecommendation]:
        """Generate recommendations for the analyst."""
        recommendations = []

        # Evidence review recommendation
        evidence_rec = self._recommend_evidence_review(case, evidence)
        if evidence_rec:
            recommendations.append(evidence_rec)

        # Investigation recommendation
        investigation_rec = self._recommend_investigation_actions(case, evidence)
        if investigation_rec:
            recommendations.append(investigation_rec)

        # Action recommendation
        action_rec = self._recommend_actions(case)
        if action_rec:
            recommendations.append(action_rec)

        # Questions recommendation
        questions_rec = self._generate_questions(case, evidence)
        if questions_rec:
            recommendations.append(questions_rec)

        return recommendations

    async def get_next_action_suggestion(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> str:
        """Get the most appropriate next action."""
        if case.status.value == "created":
            return "Start evidence collection to begin investigation"

        if case.status.value == "evidence_collected":
            return "Review collected evidence and run analysis"

        if case.status.value == "analyzing":
            return "Analysis in progress - wait for results"

        if case.status.value == "decision_pending":
            return "Review AI decision recommendation and take action"

        return "Complete investigation and document findings"

    def _recommend_evidence_review(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> Optional[AnalystRecommendation]:
        """Generate evidence review recommendation."""
        if not evidence:
            return None

        # Sort by relevance
        sorted_evidence = sorted(
            evidence, key=lambda e: e.relevance_score, reverse=True
        )

        suggestions = [
            f"Review evidence item: {e.evidence_id[:8]}... "
            f"(relevance: {e.relevance_score:.0%})"
            for e in sorted_evidence[:3]
        ]

        return AnalystRecommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case.case_id,
            recommendation_type="evidence_review",
            description="Review the following high-relevance evidence items",
            priority=self._map_priority(case.priority),
            suggested_actions=suggestions,
            related_evidence=[e.evidence_id for e in sorted_evidence[:3]],
            generated_at=datetime.now(timezone.utc),
        )

    def _recommend_investigation_actions(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> Optional[AnalystRecommendation]:
        """Generate investigation action recommendation."""
        actions = []

        # Based on evidence types
        evidence_types = set(e.evidence_type.value for e in evidence)

        if "transaction" in evidence_types:
            actions.append("Verify transaction legitimacy")
            actions.append("Check for velocity anomalies")

        if "device" in evidence_types:
            actions.append("Review device fingerprinting")
            actions.append("Check device history")

        if "ip_address" in evidence_types:
            actions.append("Analyze IP reputation")
            actions.append("Check geolocation")

        if not actions:
            return None

        return AnalystRecommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case.case_id,
            recommendation_type="investigation",
            description="Recommended investigation actions based on evidence",
            priority=self._map_priority(case.priority),
            suggested_actions=actions,
            generated_at=datetime.now(timezone.utc),
        )

    def _recommend_actions(
        self,
        case: InvestigationCase,
    ) -> Optional[AnalystRecommendation]:
        """Generate action recommendation."""
        if case.risk_score >= 0.8:
            actions = [
                "Block transaction immediately",
                "Freeze account pending review",
                "Escalate to senior analyst",
            ]
            priority = CasePriority.P0_CRITICAL
        elif case.risk_score >= 0.6:
            actions = [
                "Flag for enhanced review",
                "Request additional verification",
                "Monitor closely for 24 hours",
            ]
            priority = CasePriority.P1_HIGH
        elif case.risk_score >= 0.4:
            actions = [
                "Add to watch list",
                "Continue standard monitoring",
                "Review in next batch",
            ]
            priority = CasePriority.P2_MEDIUM
        else:
            actions = [
                "Approve transaction",
                "Log for pattern analysis",
                "Close investigation",
            ]
            priority = CasePriority.P3_LOW

        return AnalystRecommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case.case_id,
            recommendation_type="action",
            description="AI-recommended actions based on risk assessment",
            priority=priority,
            suggested_actions=actions,
            generated_at=datetime.now(timezone.utc),
        )

    def _generate_questions(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> Optional[AnalystRecommendation]:
        """Generate questions the analyst should investigate."""
        questions = []

        # Based on findings
        if case.patterns_detected:
            questions.append(
                f"What fraud pattern is indicated by: {', '.join(case.patterns_detected[:2])}?"
            )

        # Based on correlations
        if case.correlations_found > 0:
            questions.append(
                f"Investigate the {case.correlations_found} entity correlations found"
            )

        # Based on risk
        if case.risk_score > 0.7:
            questions.append("Is this transaction consistent with customer's normal behavior?")
            questions.append("Can customer verify this transaction?")

        # Based on evidence
        for e in evidence[:2]:
            questions.append(
                f"Does evidence from {e.source_system} support the risk assessment?"
            )

        if not questions:
            return None

        return AnalystRecommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case.case_id,
            recommendation_type="questions",
            description="Key questions to investigate",
            priority=self._map_priority(case.priority),
            suggested_actions=[],
            questions_to_answer=questions,
            generated_at=datetime.now(timezone.utc),
        )

    def _map_priority(self, case_priority: CasePriority) -> CasePriority:
        """Map case priority to recommendation priority."""
        return case_priority

    def get_case_summary_prompt(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> str:
        """Generate AI copilot summary prompt."""
        prompt = f"Case Summary for Investigation {case.case_id}:\n\n"
        prompt += f"Title: {case.title}\n"
        prompt += f"Risk Level: {case.severity.value}\n"
        prompt += f"Priority: {case.priority.value}\n"
        prompt += f"Description: {case.description}\n\n"

        prompt += "Evidence Summary:\n"
        for e in evidence[:5]:
            prompt += f"- {e.evidence_type.value}: {e.source_system} "
            prompt += f"(relevance: {e.relevance_score:.0%})\n"

        prompt += f"\nFindings: {len(case.findings)} items\n"
        prompt += f"Patterns Detected: {len(case.patterns_detected)}\n"
        prompt += f"Correlations Found: {case.correlations_found}\n"

        return prompt


# Global engine instance
_engine: Optional[RecommendationEngine] = None


def get_recommendation_engine() -> RecommendationEngine:
    """Get the recommendation engine instance."""
    global _engine
    if _engine is None:
        _engine = RecommendationEngine()
    return _engine