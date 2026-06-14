"""
Case Prioritization Engine for AI-driven case prioritization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    InvestigationCase,
    CasePriority,
    InvestigationStatus,
)


class CasePrioritizationEngine:
    """
    Prioritizes investigation cases using AI-driven scoring.

    Handles:
    - Priority scoring
    - SLA monitoring
    - Queue optimization
    - Workload balancing
    """

    def __init__(self):
        self._priority_weights = self._initialize_weights()

    def _initialize_weights(self) -> Dict[str, float]:
        """Initialize priority scoring weights."""
        return {
            "risk_score": 0.35,
            "severity": 0.25,
            "sla_urgency": 0.20,
            "entity_count": 0.10,
            "correlation_strength": 0.10,
        }

    def calculate_priority_score(
        self,
        case: InvestigationCase,
        queue_stats: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Calculate priority score for a case."""
        score = 0.0

        # Risk score contribution
        score += case.risk_score * self._priority_weights["risk_score"]

        # Severity contribution
        severity_score = self._severity_to_score(case.severity)
        score += severity_score * self._priority_weights["severity"]

        # SLA urgency contribution
        sla_score = self._calculate_sla_urgency(case)
        score += sla_score * self._priority_weights["sla_urgency"]

        # Entity count contribution
        entity_score = min(1.0, len(case.entity_ids) / 10)
        score += entity_score * self._priority_weights["entity_count"]

        # Correlation strength contribution
        correlation_score = min(1.0, case.correlations_found / 20)
        score += correlation_score * self._priority_weights["correlation_strength"]

        # Queue adjustment
        if queue_stats:
            queue_size = queue_stats.get("queue_size", 0)
            if queue_size > 100:
                # Reduce priority for backlogged queues
                score *= 0.9

        return max(0.0, min(1.0, score))

    def determine_priority(
        self, case: InvestigationCase, queue_stats: Optional[Dict[str, Any]] = None
    ) -> CasePriority:
        """Determine priority level for a case."""
        score = self.calculate_priority_score(case, queue_stats)

        if score >= 0.9:
            return CasePriority.P0_CRITICAL
        elif score >= 0.7:
            return CasePriority.P1_HIGH
        elif score >= 0.5:
            return CasePriority.P2_MEDIUM
        elif score >= 0.3:
            return CasePriority.P3_LOW
        else:
            return CasePriority.P4_ROUTINE

    def prioritize_queue(
        self,
        cases: List[InvestigationCase],
        queue_stats: Optional[Dict[str, Any]] = None,
    ) -> List[InvestigationCase]:
        """Prioritize a queue of cases."""
        # Calculate scores for all cases
        scored_cases = []
        for case in cases:
            score = self.calculate_priority_score(case, queue_stats)
            scored_cases.append((case, score))

        # Sort by score descending
        scored_cases.sort(key=lambda x: x[1], reverse=True)

        # Return sorted cases
        return [case for case, _ in scored_cases]

    def get_next_case(
        self,
        open_cases: List[InvestigationCase],
        analyst_workload: Optional[Dict[str, int]] = None,
    ) -> Optional[InvestigationCase]:
        """Get the next best case to assign."""
        if not open_cases:
            return None

        # Filter to actionable cases
        actionable_statuses = [
            InvestigationStatus.CREATED,
            InvestigationStatus.IN_PROGRESS,
            InvestigationStatus.DECISION_PENDING,
        ]
        actionable = [
            c for c in open_cases
            if c.status in actionable_statuses
        ]

        if not actionable:
            return None

        # Prioritize
        prioritized = self.prioritize_queue(actionable)

        # Apply workload balancing
        if analyst_workload:
            prioritized = self._balance_by_workload(
                prioritized, analyst_workload
            )

        return prioritized[0] if prioritized else None

    def get_sla_status(
        self, case: InvestigationCase
    ) -> Dict[str, Any]:
        """Get SLA status for a case."""
        if not case.sla_deadline:
            return {
                "has_sla": False,
                "status": "no_sla",
            }

        now = datetime.now(timezone.utc)
        time_remaining = (case.sla_deadline - now).total_seconds() / 60

        if time_remaining < 0:
            status = "breached"
            urgency = "critical"
        elif time_remaining < 30:
            status = "at_risk"
            urgency = "high"
        elif time_remaining < 60:
            status = "warning"
            urgency = "medium"
        else:
            status = "on_track"
            urgency = "low"

        return {
            "has_sla": True,
            "status": status,
            "urgency": urgency,
            "time_remaining_minutes": max(0, time_remaining),
            "deadline": case.sla_deadline.isoformat(),
        }

    def get_queue_metrics(
        self, cases: List[InvestigationCase]
    ) -> Dict[str, Any]:
        """Get queue-level metrics."""
        if not cases:
            return {
                "queue_size": 0,
                "avg_priority_score": 0,
                "sla_breached": 0,
                "sla_at_risk": 0,
                "by_priority": {},
                "by_status": {},
            }

        # Calculate metrics
        priority_scores = [
            self.calculate_priority_score(c) for c in cases
        ]

        by_priority: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        sla_breached = 0
        sla_at_risk = 0

        for case in cases:
            # Count by priority
            priority = case.priority.value
            by_priority[priority] = by_priority.get(priority, 0) + 1

            # Count by status
            status = case.status.value
            by_status[status] = by_status.get(status, 0) + 1

            # Check SLA
            sla = self.get_sla_status(case)
            if sla["status"] == "breached":
                sla_breached += 1
            elif sla["status"] == "at_risk":
                sla_at_risk += 1

        return {
            "queue_size": len(cases),
            "avg_priority_score": sum(priority_scores) / len(priority_scores),
            "sla_breached": sla_breached,
            "sla_at_risk": sla_at_risk,
            "by_priority": by_priority,
            "by_status": by_status,
        }

    def suggest_reassignment(
        self,
        case: InvestigationCase,
        available_analysts: List[str],
        analyst_workload: Dict[str, int],
    ) -> Optional[str]:
        """Suggest best analyst to reassign a case."""
        if not available_analysts:
            return None

        # Find analyst with lowest workload
        best_analyst = None
        min_workload = float("inf")

        for analyst in available_analysts:
            workload = analyst_workload.get(analyst, 0)
            if workload < min_workload:
                min_workload = workload
                best_analyst = analyst

        return best_analyst

    def _severity_to_score(self, severity) -> float:
        """Convert severity to numeric score."""
        severity_map = {
            "critical": 1.0,
            "severe": 0.8,
            "moderate": 0.5,
            "warning": 0.3,
            "info": 0.1,
        }
        return severity_map.get(severity.value if hasattr(severity, 'value') else severity, 0.5)

    def _calculate_sla_urgency(self, case: InvestigationCase) -> float:
        """Calculate SLA urgency score."""
        if not case.sla_deadline:
            return 0.5  # Neutral if no SLA

        now = datetime.now(timezone.utc)
        time_remaining = (case.sla_deadline - now).total_seconds() / 3600  # hours

        if time_remaining < 0:
            return 1.0  # Already breached
        elif time_remaining < 1:
            return 0.9  # Less than 1 hour
        elif time_remaining < 4:
            return 0.7  # Less than 4 hours
        elif time_remaining < 24:
            return 0.5  # Less than 24 hours
        else:
            return 0.3  # Plenty of time

    def _balance_by_workload(
        self,
        cases: List[InvestigationCase],
        workload: Dict[str, int],
    ) -> List[InvestigationCase]:
        """Balance queue by analyst workload."""
        # Simple implementation: cases are already prioritized
        # More sophisticated version would consider skill matching
        return cases


# Global engine instance
_engine: Optional[CasePrioritizationEngine] = None


def get_case_prioritization_engine() -> CasePrioritizationEngine:
    """Get the case prioritization engine instance."""
    global _engine
    if _engine is None:
        _engine = CasePrioritizationEngine()
    return _engine