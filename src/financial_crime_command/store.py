"""
Financial Crime Command Center Store.

Storage layer for cases, alerts, and correlations.
"""

from __future__ import annotations

import threading

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


from .models import (
    Alert,
    AlertStatus,
    CaseStatus,
    CommandCenterConfig,
    CorrelationLink,
    CrimeCase,
    CrimeType,
    ThreatIndicator,
    ThreatLevel,
)


class FinancialCrimeStore:
    """Store for financial crime command center data."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._cases: Dict[str, CrimeCase] = {}
        self._alerts: Dict[str, Alert] = {}
        self._correlations: Dict[str, CorrelationLink] = {}
        self._threats: Dict[str, ThreatIndicator] = {}
        self._config = CommandCenterConfig()
        self._lock = threading.RLock()

    def store_case(self, case: CrimeCase) -> None:
        """Store a crime case."""
        with self._lock:
            self._cases[case.case_id] = case

    def get_case(self, case_id: str) -> Optional[CrimeCase]:
        """Get a case by ID."""
        return self._cases.get(case_id)

    def get_cases_by_status(self, status: str) -> List[CrimeCase]:
        """Get all cases with given status."""
        return [c for c in self._cases.values() if c.status.value == status]

    def get_cases_by_type(self, crime_type: CrimeType) -> List[CrimeCase]:
        """Get all cases of given crime type."""
        return [c for c in self._cases.values() if c.crime_type == crime_type]

    def get_high_priority_cases(self, threshold: float = 0.7) -> List[CrimeCase]:
        """Get high priority cases."""
        return [c for c in self._cases.values() if c.priority_score >= threshold]

    def update_case_status(self, case_id: str, status: CaseStatus) -> bool:
        """Update case status."""
        case = self._cases.get(case_id)
        if case:
            case.status = status
            case.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def store_alert(self, alert: Alert) -> None:
        """Store an alert."""
        with self._lock:
            self._alerts[alert.alert_id] = alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        return self._alerts.get(alert_id)

    def get_alerts_by_status(self, status: AlertStatus) -> List[Alert]:
        """Get alerts by status."""
        return [a for a in self._alerts.values() if a.status == status]

    def get_alerts_by_type(self, crime_type: CrimeType) -> List[Alert]:
        """Get alerts by crime type."""
        return [a for a in self._alerts.values() if a.crime_type == crime_type]

    def get_recent_alerts(self, hours: int = 24) -> List[Alert]:
        """Get recent alerts within specified hours."""
        cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        return [
            a for a in self._alerts.values()
            if a.triggered_at.timestamp() >= cutoff
        ]

    def store_correlation(self, link: CorrelationLink) -> None:
        """Store a correlation link."""
        with self._lock:
            self._correlations[link.link_id] = link

    def get_correlations_for_case(self, case_id: str) -> List[CorrelationLink]:
        """Get all correlations for a case."""
        return [
            c for c in self._correlations.values()
            if c.source_case_id == case_id or c.target_case_id == case_id
        ]

    def store_threat(self, threat: ThreatIndicator) -> None:
        """Store a threat indicator."""
        with self._lock:
            self._threats[threat.indicator_id] = threat

    def get_threat(self, indicator_id: str) -> Optional[ThreatIndicator]:
        """Get a threat by ID."""
        return self._threats.get(indicator_id)

    def get_threats_by_type(self, indicator_type: str) -> List[ThreatIndicator]:
        """Get threats by type."""
        return [t for t in self._threats.values() if t.indicator_type == indicator_type]

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics."""
        cases = list(self._cases.values())
        alerts = list(self._alerts.values())

        return {
            "total_cases": len(cases),
            "open_cases": len([c for c in cases if c.status != CaseStatus.CLOSED]),
            "closed_cases": len([c for c in cases if c.status == CaseStatus.CLOSED]),
            "escalated_cases": len([c for c in cases if c.status == CaseStatus.ESCALATED]),
            "high_priority_cases": len(self.get_high_priority_cases()),
            "cases_by_type": {
                ct.value: len([c for c in cases if c.crime_type == ct])
                for ct in CrimeType
            },
            "cases_by_status": {
                cs.value: len([c for c in cases if c.status == cs])
                for cs in CaseStatus
            },
            "threat_level_distribution": {
                tl.value: len([c for c in cases if c.threat_level == tl])
                for tl in ThreatLevel
            },
            "recent_alerts": len(self.get_recent_alerts()),
            "pending_investigations": len(self.get_cases_by_status(CaseStatus.IN_PROGRESS.value)),
        }

    def clear(self) -> None:
        """Clear all stored data."""
        with self._lock:
            self._cases.clear()
            self._alerts.clear()
            self._correlations.clear()
            self._threats.clear()


# Global store instance
_store: Optional[FinancialCrimeStore] = None
_store_lock = threading.Lock()


def get_financial_crime_store() -> FinancialCrimeStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = FinancialCrimeStore()
    return _store


def reset_financial_crime_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None