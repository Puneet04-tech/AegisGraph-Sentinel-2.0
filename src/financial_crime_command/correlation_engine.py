"""
Case Correlation Engine.

Identifies and links related financial crime cases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from .models import CaseStatus, CorrelationLink, CrimeCase, CrimeType
from .store import FinancialCrimeStore, get_financial_crime_store


@dataclass
class CorrelationResult:
    """Result of correlation analysis."""
    source_case_id: str
    target_case_id: str
    correlation_score: float
    correlation_factors: List[str] = field(default_factory=list)
    shared_entities: List[str] = field(default_factory=list)
    recommended_action: str = "review"


class CaseCorrelationEngine:
    """Engine for correlating financial crime cases."""

    def __init__(self, store: Optional[FinancialCrimeStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_financial_crime_store()

    def find_correlations(self, case_id: str) -> List[CorrelationResult]:
        """Find correlations for a case."""
        case = self.store.get_case(case_id)
        if not case:
            return []
        
        correlations: List[CorrelationResult] = []
        all_cases = [c for c in self.store._cases.values() if c.case_id != case_id]
        
        for other_case in all_cases:
            result = self._analyze_correlation(case, other_case)
            if result and result.correlation_score > 0.3:
                correlations.append(result)
        
        return sorted(correlations, key=lambda x: x.correlation_score, reverse=True)

    def _analyze_correlation(
        self,
        case1: CrimeCase,
        case2: CrimeCase,
    ) -> Optional[CorrelationResult]:
        """Analyze correlation between two cases."""
        factors = []
        shared_entities: List[str] = []
        score = 0.0
        
        # Check entity overlap
        entities1 = set(case1.entity_ids)
        entities2 = set(case2.entity_ids)
        common_entities = entities1 & entities2
        if common_entities:
            shared_entities.extend(common_entities)
            score += 0.4 * (len(common_entities) / max(len(entities1), len(entities2), 1))
            factors.append(f"Shared entities: {', '.join(common_entities)}")
        
        # Check crime type match
        if case1.crime_type == case2.crime_type:
            score += 0.2
            factors.append(f"Same crime type: {case1.crime_type.value}")
        
        # Check temporal proximity
        time_diff = abs((case1.created_at - case2.created_at).total_seconds())
        if time_diff < 86400:  # Within 24 hours
            score += 0.15
            factors.append("Temporal proximity (< 24h)")
        elif time_diff < 604800:  # Within 7 days
            score += 0.05
            factors.append("Recent temporal proximity (< 7d)")
        
        # Check linked cases
        if case1.case_id in case2.linked_cases or case2.case_id in case1.linked_cases:
            score += 0.3
            factors.append("Already linked cases")
        
        # Check threat level similarity
        if case1.threat_level == case2.threat_level:
            score += 0.1
            factors.append("Same threat level")
        
        if score < 0.3:
            return None
        
        action = "escalate" if score > 0.7 else "review" if score > 0.5 else "monitor"
        
        return CorrelationResult(
            source_case_id=case1.case_id,
            target_case_id=case2.case_id,
            correlation_score=min(1.0, score),
            correlation_factors=factors,
            shared_entities=shared_entities,
            recommended_action=action,
        )

    def link_cases(self, source_id: str, target_id: str, correlation_type: str) -> Optional[CorrelationLink]:
        """Link two cases together."""
        source = self.store.get_case(source_id)
        target = self.store.get_case(target_id)
        
        if not source or not target:
            return None
        
        result = self._analyze_correlation(source, target)
        if not result:
            return None
        
        link = CorrelationLink(
            link_id=str(uuid.uuid4()),
            source_case_id=source_id,
            target_case_id=target_id,
            correlation_type=correlation_type,
            confidence=result.correlation_score,
            shared_entities=result.shared_entities,
        )
        
        self.store.store_correlation(link)
        
        # Update linked cases
        if target_id not in source.linked_cases:
            source.linked_cases.append(target_id)
            source.updated_at = datetime.now(timezone.utc)
        if source_id not in target.linked_cases:
            target.linked_cases.append(source_id)
            target.updated_at = datetime.now(timezone.utc)
        
        return link

    def get_network_graph(self, case_id: str, depth: int = 2) -> Dict[str, Any]:
        """Get network graph of related cases."""
        case = self.store.get_case(case_id)
        if not case:
            return {"nodes": [], "edges": []}
        
        nodes = [case.case_id]
        edges = []
        visited: Set[str] = {case_id}
        frontier = [case_id]
        
        for _ in range(depth):
            next_frontier = []
            for cid in frontier:
                correlations = self.store.get_correlations_for_case(cid)
                for corr in correlations:
                    other = corr.target_case_id if corr.source_case_id == cid else corr.source_case_id
                    if other not in visited:
                        nodes.append(other)
                        next_frontier.append(other)
                        visited.add(other)
                    edges.append({
                        "from": corr.source_case_id,
                        "to": corr.target_case_id,
                        "weight": corr.confidence,
                        "type": corr.correlation_type,
                    })
            frontier = next_frontier
        
        return {
            "nodes": nodes,
            "edges": edges,
            "center": case_id,
            "depth": depth,
        }

    def suggest_correlations(self, min_score: float = 0.5) -> List[CorrelationResult]:
        """Suggest potential correlations across all cases."""
        suggestions: List[CorrelationResult] = []
        cases = [c for c in self.store._cases.values() if c.status != CaseStatus.CLOSED]
        
        for i, case1 in enumerate(cases):
            for case2 in cases[i + 1:]:
                result = self._analyze_correlation(case1, case2)
                if result and result.correlation_score >= min_score:
                    # Check if already linked
                    existing = self.store.get_correlations_for_case(case1.case_id)
                    already_linked = any(
                        c.target_case_id == case2.case_id for c in existing
                    )
                    if not already_linked:
                        suggestions.append(result)
        
        return sorted(suggestions, key=lambda x: x.correlation_score, reverse=True)[:50]


# Singleton instance
_engine: Optional[CaseCorrelationEngine] = None


def get_correlation_engine() -> CaseCorrelationEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = CaseCorrelationEngine()
    return _engine


def reset_correlation_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None