"""
Storage layer for Autonomous Investigation Platform.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from .models import (
    InvestigationCase,
    EvidenceArtifact,
    RiskAssessment,
    FraudNarrative,
    EntityCorrelation,
    FraudPattern,
    CasePriority,
    InvestigationStatus,
    DecisionRecommendation,
    AuditRecord,
)


class LRUCache(OrderedDict):
    """Thread-safe LRU cache."""

    def __init__(self, maxsize: int = 10000, *args, **kwds):
        self.maxsize = maxsize
        super().__init__(*args, **kwds)
        self._lock = threading.RLock()

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value

    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]

    def __delitem__(self, key: str) -> None:
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return super().__contains__(key)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            try:
                return self[key]
            except KeyError:
                return default

    def clear(self) -> None:
        with self._lock:
            super().clear()


class InvestigationStore:
    """
    Central storage for investigation data with O(1) lookup.
    """

    def __init__(
        self,
        max_cases: int = 50000,
        max_evidence: int = 500000,
        max_assessments: int = 100000,
    ):
        # Core storage
        self._cases: LRUCache = LRUCache(maxsize=max_cases)
        self._evidence: LRUCache = LRUCache(maxsize=max_evidence)
        self._assessments: LRUCache = LRUCache(maxsize=max_assessments)
        self._recommendations: Dict[str, List] = {}
        self._narratives: Dict[str, FraudNarrative] = {}
        self._audit_records: List = []
        self._correlations: Dict[str, List] = {}
        self._patterns: Dict[str, FraudPattern] = {}

        # Index structures
        self._case_by_status: Dict[str, Set[str]] = {}
        self._case_by_priority: Dict[str, Set[str]] = {}
        self._evidence_by_case: Dict[str, Set[str]] = {}
        self._entity_cases: Dict[str, Set[str]] = {}

        self._lock = threading.RLock()

    # Case Management
    def store_case(self, case: InvestigationCase) -> None:
        """Store an investigation case."""
        with self._lock:
            self._cases[case.case_id] = case

            # Update indexes
            if case.status.value not in self._case_by_status:
                self._case_by_status[case.status.value] = set()
            self._case_by_status[case.status.value].add(case.case_id)

            if case.priority.value not in self._case_by_priority:
                self._case_by_priority[case.priority.value] = set()
            self._case_by_priority[case.priority.value].add(case.case_id)

            # Entity index
            for entity_id in case.entity_ids:
                if entity_id not in self._entity_cases:
                    self._entity_cases[entity_id] = set()
                self._entity_cases[entity_id].add(case.case_id)

    def get_case(self, case_id: str) -> Optional[InvestigationCase]:
        """Get case by ID with O(1) lookup."""
        return self._cases.get(case_id)

    def get_cases_by_status(
        self, status: str, limit: int = 100
    ) -> List[InvestigationCase]:
        """Get cases by status."""
        case_ids = list(self._case_by_status.get(status, set()))[:limit]
        return [self._cases[cid] for cid in case_ids if cid in self._cases]

    def get_cases_by_priority(
        self, priority: str, limit: int = 100
    ) -> List[InvestigationCase]:
        """Get cases by priority."""
        case_ids = list(self._case_by_priority.get(priority, set()))[:limit]
        return [self._cases[cid] for cid in case_ids if cid in self._cases]

    def get_cases_by_entity(
        self, entity_id: str, limit: int = 100
    ) -> List[InvestigationCase]:
        """Get cases involving an entity."""
        case_ids = list(self._entity_cases.get(entity_id, set()))[:limit]
        return [self._cases[cid] for cid in case_ids if cid in self._cases]

    def get_open_cases(self, limit: int = 100) -> List[InvestigationCase]:
        """Get all open cases."""
        open_statuses = [
            InvestigationStatus.CREATED.value,
            InvestigationStatus.IN_PROGRESS.value,
            InvestigationStatus.EVIDENCE_COLLECTED.value,
            InvestigationStatus.ANALYZING.value,
            InvestigationStatus.DECISION_PENDING.value,
        ]
        result = []
        for status in open_statuses:
            result.extend(self.get_cases_by_status(status, limit))
            if len(result) >= limit:
                break
        return result[:limit]

    def get_all_cases(self, limit: int = 100) -> List[InvestigationCase]:
        """Get all cases."""
        return list(self._cases.values())[:limit]

    def update_case_status(self, case_id: str, status: InvestigationStatus) -> bool:
        """Update case status."""
        case = self._cases.get(case_id)
        if not case:
            return False

        old_status = case.status.value
        case.status = status
        case.updated_at = datetime.now(timezone.utc)

        # Update indexes
        if old_status in self._case_by_status:
            self._case_by_status[old_status].discard(case_id)
        if status.value not in self._case_by_status:
            self._case_by_status[status.value] = set()
        self._case_by_status[status.value].add(case_id)

        return True

    # Evidence Management
    def store_evidence(self, evidence: EvidenceArtifact) -> None:
        """Store evidence artifact."""
        with self._lock:
            self._evidence[evidence.evidence_id] = evidence

            # Update evidence index
            if evidence.evidence_id not in self._evidence_by_case:
                self._evidence_by_case[evidence.evidence_id] = set()

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceArtifact]:
        """Get evidence by ID."""
        return self._evidence.get(evidence_id)

    def get_evidence_for_case(self, case_id: str) -> List[EvidenceArtifact]:
        """Get all evidence for a case."""
        case = self._cases.get(case_id)
        if not case:
            return []

        return [
            self._evidence[eid]
            for eid in case.evidence_ids
            if eid in self._evidence
        ]

    def link_evidence_to_case(
        self, case_id: str, evidence_id: str
    ) -> bool:
        """Link evidence to a case."""
        case = self._cases.get(case_id)
        if not case:
            return False

        if evidence_id not in case.evidence_ids:
            case.evidence_ids.append(evidence_id)
            case.updated_at = datetime.now(timezone.utc)

        if case_id not in self._evidence_by_case:
            self._evidence_by_case[case_id] = set()
        self._evidence_by_case[case_id].add(evidence_id)

        return True

    # Assessment Management
    def store_assessment(self, assessment: RiskAssessment) -> None:
        """Store risk assessment."""
        with self._lock:
            self._assessments[assessment.assessment_id] = assessment

    def get_assessment(
        self, assessment_id: str
    ) -> Optional[RiskAssessment]:
        """Get assessment by ID."""
        return self._assessments.get(assessment_id)

    def get_latest_assessment(
        self, case_id: str
    ) -> Optional[RiskAssessment]:
        """Get latest assessment for a case."""
        assessments = [
            a for a in self._assessments.values()
            if a.case_id == case_id
        ]
        if not assessments:
            return None
        return max(assessments, key=lambda a: a.assessment_date)

    # Recommendation Management
    def store_recommendation(
        self, case_id: str, recommendation: DecisionRecommendation
    ) -> None:
        """Store decision recommendation."""
        with self._lock:
            if case_id not in self._recommendations:
                self._recommendations[case_id] = []
            self._recommendations[case_id].append(recommendation)

    def get_recommendations(
        self, case_id: str
    ) -> List[DecisionRecommendation]:
        """Get recommendations for a case."""
        return self._recommendations.get(case_id, [])

    # Narrative Management
    def store_narrative(self, narrative: FraudNarrative) -> None:
        """Store fraud narrative."""
        with self._lock:
            self._narratives[narrative.narrative_id] = narrative

    def get_narrative(
        self, narrative_id: str
    ) -> Optional[FraudNarrative]:
        """Get narrative by ID."""
        return self._narratives.get(narrative_id)

    def get_narrative_for_case(
        self, case_id: str
    ) -> Optional[FraudNarrative]:
        """Get latest narrative for a case."""
        narratives = [
            n for n in self._narratives.values()
            if n.case_id == case_id
        ]
        if not narratives:
            return None
        return max(narratives, key=lambda n: n.generated_at)

    # Correlation Management
    def store_correlation(self, correlation: EntityCorrelation) -> None:
        """Store entity correlation."""
        with self._lock:
            if correlation.case_id not in self._correlations:
                self._correlations[correlation.case_id] = []
            self._correlations[correlation.case_id].append(correlation)

    def get_correlations(self, case_id: str) -> List[EntityCorrelation]:
        """Get correlations for a case."""
        return self._correlations.get(case_id, [])

    # Pattern Management
    def store_pattern(self, pattern: FraudPattern) -> None:
        """Store fraud pattern."""
        with self._lock:
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns(self) -> List[FraudPattern]:
        """Get all fraud patterns."""
        return list(self._patterns.values())

    def get_pattern(self, pattern_id: str) -> Optional[FraudPattern]:
        """Get pattern by ID."""
        return self._patterns.get(pattern_id)

    # Audit Management
    def store_audit_record(self, record: AuditRecord) -> None:
        """Store audit record."""
        with self._lock:
            self._audit_records.append(record)
            if len(self._audit_records) > 10000:
                self._audit_records = self._audit_records[-10000:]

    def get_audit_records(
        self,
        case_id: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Query audit records."""
        result = []
        for record in reversed(self._audit_records):
            if case_id and record.case_id != case_id:
                continue
            if user_id and record.user_id != user_id:
                continue
            result.append(record)
            if len(result) >= limit:
                break
        return result

    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        open_cases = self.get_open_cases(limit=10000)
        high_priority = self.get_cases_by_priority(
            CasePriority.P0_CRITICAL.value, limit=10000
        )
        high_priority.extend(
            self.get_cases_by_priority(CasePriority.P1_HIGH.value, limit=10000)
        )

        return {
            "total_cases": len(self._cases),
            "open_cases": len(open_cases),
            "high_priority_cases": len(high_priority),
            "total_evidence": len(self._evidence),
            "total_assessments": len(self._assessments),
            "total_patterns": len(self._patterns),
            "total_correlations": sum(
                len(c) for c in self._correlations.values()
            ),
            "by_status": {
                status: len(cases)
                for status, cases in self._case_by_status.items()
            },
            "by_priority": {
                priority: len(cases)
                for priority, cases in self._case_by_priority.items()
            },
        }


# Global store instance
_store: Optional[InvestigationStore] = None


def get_investigation_store() -> InvestigationStore:
    """Get the investigation store instance."""
    global _store
    if _store is None:
        _store = InvestigationStore()
    return _store


def reset_store() -> None:
    """Reset the store (for testing)."""
    global _store
    _store = None