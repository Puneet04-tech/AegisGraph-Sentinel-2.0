"""
Risk Prioritization Engine.

Prioritizes financial crime cases based on risk factors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


from .models import CaseStatus, CrimeCase, CrimeType, ThreatLevel
from .store import FinancialCrimeStore, get_financial_crime_store


@dataclass
class PriorityScore:
    """Priority score breakdown."""
    case_id: str
    total_score: float
    threat_component: float
    financial_component: float
    urgency_component: float
    complexity_component: float
    factors: List[str] = field(default_factory=list)


@dataclass
class PrioritizationResult:
    """Result of prioritization analysis."""
    case_id: str
    priority_score: float
    priority_rank: int
    recommended_action: str
    assigned_urgency: str
    estimated_resolution_time: float


class RiskPrioritizationEngine:
    """Engine for risk-based case prioritization."""

    def __init__(self, store: Optional[FinancialCrimeStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_financial_crime_store()

    def calculate_priority_score(self, case: CrimeCase) -> PriorityScore:
        """Calculate comprehensive priority score for a case."""
        threat_score = self._calculate_threat_component(case)
        financial_score = self._calculate_financial_component(case)
        urgency_score = self._calculate_urgency_component(case)
        complexity_score = self._calculate_complexity_component(case)
        
        total = (
            threat_score * 0.35 +
            financial_score * 0.30 +
            urgency_score * 0.20 +
            complexity_score * 0.15
        )
        
        factors = []
        if threat_score > 0.7:
            factors.append("High threat level")
        if financial_score > 0.8:
            factors.append("High financial impact")
        if urgency_score > 0.6:
            factors.append("Time-sensitive")
        if complexity_score > 0.5:
            factors.append("Complex investigation required")
        
        return PriorityScore(
            case_id=case.case_id,
            total_score=min(1.0, total),
            threat_component=threat_score,
            financial_component=financial_score,
            urgency_component=urgency_score,
            complexity_component=complexity_score,
            factors=factors,
        )

    def _calculate_threat_component(self, case: CrimeCase) -> float:
        """Calculate threat component score."""
        threat_scores = {
            ThreatLevel.SEVERE: 1.0,
            ThreatLevel.CRITICAL: 0.85,
            ThreatLevel.HIGH: 0.65,
            ThreatLevel.MEDIUM: 0.4,
            ThreatLevel.LOW: 0.2,
        }
        return threat_scores.get(case.threat_level, 0.3)

    def _calculate_financial_component(self, case: CrimeCase) -> float:
        """Calculate financial impact component."""
        score = 0.0
        if case.financial_impact:
            if case.financial_impact > 1000000:
                score = 1.0
            elif case.financial_impact > 100000:
                score = 0.8
            elif case.financial_impact > 10000:
                score = 0.5
            else:
                score = 0.2
        return score

    def _calculate_urgency_component(self, case: CrimeCase) -> float:
        """Calculate urgency component."""
        score = 0.5
        
        age_hours = (datetime.now(timezone.utc) - case.created_at).total_seconds() / 3600
        
        if case.status == CaseStatus.ESCALATED:
            score += 0.3
        elif case.status == CaseStatus.IN_PROGRESS:
            score += 0.1
        
        if age_hours > 72:
            score += 0.2
        elif age_hours > 48:
            score += 0.1
        
        if len(case.linked_cases) > 5:
            score += 0.2
        
        return min(1.0, score)

    def _calculate_complexity_component(self, case: CrimeCase) -> float:
        """Calculate investigation complexity component."""
        score = 0.3
        
        if len(case.entity_ids) > 10:
            score += 0.2
        elif len(case.entity_ids) > 5:
            score += 0.1
        
        if len(case.risk_indicators) > 5:
            score += 0.2
        elif len(case.risk_indicators) > 2:
            score += 0.1
        
        if case.crime_type in [CrimeType.MONEY_LAUNDERING, CrimeType.TERRORIST_FINANCING]:
            score += 0.3
        
        return min(1.0, score)

    def prioritize_queue(
        self,
        cases: Optional[List[CrimeCase]] = None,
    ) -> List[PrioritizationResult]:
        """Prioritize a queue of cases."""
        if cases is None:
            cases = [
                c for c in self.store._cases.values()
                if c.status not in [CaseStatus.CLOSED, CaseStatus.DISMISSED]
            ]
        
        scored_cases = []
        for case in cases:
            priority = self.calculate_priority_score(case)
            scored_cases.append((case, priority))
        
        scored_cases.sort(key=lambda x: x[1].total_score, reverse=True)
        
        results = []
        for rank, (case, priority) in enumerate(scored_cases, 1):
            result = PrioritizationResult(
                case_id=case.case_id,
                priority_score=priority.total_score,
                priority_rank=rank,
                recommended_action=self._get_action(priority.total_score),
                assigned_urgency=self._get_urgency(priority.total_score),
                estimated_resolution_time=self._estimate_time(case),
            )
            results.append(result)
            
            # Update case priority score
            case.priority_score = priority.total_score
        
        return results

    def _get_action(self, score: float) -> str:
        """Get recommended action based on score."""
        if score >= 0.8:
            return "Immediate escalation required"
        elif score >= 0.6:
            return "High priority - assign senior analyst"
        elif score >= 0.4:
            return "Standard priority"
        else:
            return "Low priority - batch processing"

    def _get_urgency(self, score: float) -> str:
        """Get urgency level based on score."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"

    def _estimate_time(self, case: CrimeCase) -> float:
        """Estimate resolution time in hours."""
        base_time = 24.0
        
        if case.threat_level == ThreatLevel.SEVERE:
            base_time = 4.0
        elif case.threat_level == ThreatLevel.CRITICAL:
            base_time = 12.0
        elif case.threat_level == ThreatLevel.HIGH:
            base_time = 24.0
        else:
            base_time = 48.0
        
        if case.financial_impact and case.financial_impact > 100000:
            base_time *= 1.5
        
        return base_time

    def get_priority_breakdown(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed priority breakdown for a case."""
        case = self.store.get_case(case_id)
        if not case:
            return None
        
        score = self.calculate_priority_score(case)
        return {
            "case_id": case.case_id,
            "total_score": score.total_score,
            "components": {
                "threat": score.threat_component,
                "financial": score.financial_component,
                "urgency": score.urgency_component,
                "complexity": score.complexity_component,
            },
            "factors": score.factors,
            "urgency": self._get_urgency(score.total_score),
            "recommended_action": self._get_action(score.total_score),
            "estimated_time_hours": self._estimate_time(case),
        }


# Singleton instance
_engine: Optional[RiskPrioritizationEngine] = None


def get_risk_prioritization_engine() -> RiskPrioritizationEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = RiskPrioritizationEngine()
    return _engine


def reset_risk_prioritization_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None