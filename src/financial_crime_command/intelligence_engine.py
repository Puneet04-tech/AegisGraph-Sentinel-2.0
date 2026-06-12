"""
Crime Intelligence Engine.

Analyzes and monitors financial crime patterns and trends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid


from .models import (
    Alert,
    AlertStatus,
    CaseStatus,
    CrimeCase,
    CrimeType,
    ThreatIndicator,
    ThreatLevel,
)
from .store import FinancialCrimeStore, get_financial_crime_store


@dataclass
class CrimePattern:
    """Identified crime pattern."""
    pattern_id: str
    pattern_type: str
    description: str
    confidence: float
    associated_cases: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    mitigation_suggestions: List[str] = field(default_factory=list)


class CrimeIntelligenceEngine:
    """Engine for financial crime intelligence analysis."""

    def __init__(self, store: Optional[FinancialCrimeStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_financial_crime_store()

    async def analyze_case(self, case: CrimeCase) -> Dict[str, Any]:
        """Analyze a case for intelligence insights."""
        risk_factors = []
        patterns = []
        
        # Check for high-risk indicators
        if case.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.SEVERE]:
            risk_factors.append("Critical threat level detected")
            patterns.append("High-severity threat pattern")
        
        if case.priority_score > 0.8:
            risk_factors.append("Very high priority score")
            patterns.append("Critical priority pattern")
        
        if len(case.linked_cases) > 3:
            risk_factors.append("Multiple linked cases")
            patterns.append("Network fraud pattern")
        
        if case.financial_impact and case.financial_impact > 100000:
            risk_factors.append("High financial impact")
            patterns.append("Large-scale fraud pattern")
        
        return {
            "case_id": case.case_id,
            "risk_factors": risk_factors,
            "patterns": patterns,
            "confidence": case.confidence if hasattr(case, 'confidence') else 0.5,
            "recommendations": self._generate_recommendations(risk_factors),
        }

    def _generate_recommendations(self, risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on risk factors."""
        recommendations = []
        if any("high-severity" in rf.lower() for rf in risk_factors):
            recommendations.append("Escalate to senior analyst immediately")
            recommendations.append("Notify compliance team")
        if any("network" in rf.lower() for rf in risk_factors):
            recommendations.append("Conduct network analysis")
            recommendations.append("Check for additional linked accounts")
        if any("financial impact" in rf.lower() for rf in risk_factors):
            recommendations.append("Freeze affected accounts")
            recommendations.append("Coordinate with fraud prevention team")
        if not recommendations:
            recommendations.append("Continue standard investigation process")
        return recommendations

    def detect_crime_patterns(self, days: int = 7) -> List[CrimePattern]:
        """Detect crime patterns from recent cases."""
        patterns = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        cases = [
            c for c in self.store._cases.values()
            if c.created_at >= cutoff
        ]
        
        # Group by crime type
        type_groups: Dict[CrimeType, List[CrimeCase]] = {}
        for case in cases:
            type_groups.setdefault(case.crime_type, []).append(case)
        
        for crime_type, type_cases in type_groups.items():
            if len(type_cases) >= 3:
                pattern = CrimePattern(
                    pattern_id=str(uuid.uuid4()),
                    pattern_type=f"Multi-case {crime_type.value} pattern",
                    description=f"Detected {len(type_cases)} cases of {crime_type.value} in last {days} days",
                    confidence=min(0.9, 0.5 + (len(type_cases) * 0.1)),
                    associated_cases=[c.case_id for c in type_cases],
                    risk_factors=[f"{len(type_cases)} cases in {days} days"],
                    mitigation_suggestions=[
                        f"Increase monitoring for {crime_type.value} transactions",
                        "Review recent policy changes",
                    ],
                )
                patterns.append(pattern)
        
        return patterns

    def assess_risk_level(
        self,
        case: CrimeCase,
        historical_data: Optional[Dict[str, Any]] = None,
    ) -> ThreatLevel:
        """Assess risk level for a case."""
        score = case.priority_score
        
        if len(case.linked_cases) > 5:
            score += 0.2
        if case.threat_level == ThreatLevel.CRITICAL:
            score += 0.3
        
        if historical_data:
            if historical_data.get("similar_cases", 0) > 10:
                score += 0.1
            if historical_data.get("trend", "stable") == "increasing":
                score += 0.15
        
        if score >= 0.9:
            return ThreatLevel.SEVERE
        elif score >= 0.7:
            return ThreatLevel.CRITICAL
        elif score >= 0.5:
            return ThreatLevel.HIGH
        elif score >= 0.3:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def generate_intelligence_report(
        self,
        crime_type: Optional[CrimeType] = None,
    ) -> Dict[str, Any]:
        """Generate intelligence report."""
        if crime_type:
            cases = self.store.get_cases_by_type(crime_type)
        else:
            cases = list(self.store._cases.values())
        
        patterns = self.detect_crime_patterns()
        
        return {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "crime_type": crime_type.value if crime_type else "all",
            "total_cases": len(cases),
            "patterns_detected": len(patterns),
            "pattern_summary": [
                {"type": p.pattern_type, "confidence": p.confidence}
                for p in patterns
            ],
            "threat_indicators": self._get_threat_indicators(cases),
        }

    def _get_threat_indicators(self, cases: List[CrimeCase]) -> List[str]:
        """Get threat indicators from cases."""
        indicators = []
        if any(c.threat_level == ThreatLevel.CRITICAL for c in cases):
            indicators.append("Critical threats present")
        if any(c.priority_score > 0.8 for c in cases):
            indicators.append("High-priority cases detected")
        if any(len(c.linked_cases) > 0 for c in cases):
            indicators.append("Case correlations detected")
        return indicators


# Singleton instance
_engine: Optional[CrimeIntelligenceEngine] = None


def get_crime_intelligence_engine() -> CrimeIntelligenceEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = CrimeIntelligenceEngine()
    return _engine


def reset_crime_intelligence_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None