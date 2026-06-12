"""
Financial Crime Intelligence Exchange Store.

Storage layer for financial intelligence exchange.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AlertLevel,
    AMLIntelligence,
    AuditEvent,
    CaseStatus,
    CrossBorderInvestigation,
    FraudAlert,
    FraudPattern,
    Institution,
    InstitutionType,
    ShareLevel,
    SharedCase,
)


class FinIntelStore:
    """Store for financial intelligence exchange."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._institutions: Dict[str, Institution] = {}
        self._fraud_alerts: Dict[str, FraudAlert] = {}
        self._fraud_patterns: Dict[str, FraudPattern] = {}
        self._shared_cases: Dict[str, SharedCase] = {}
        self._aml_intel: Dict[str, AMLIntelligence] = {}
        self._investigations: Dict[str, CrossBorderInvestigation] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def add_institution(self, institution: Institution) -> None:
        """Add an institution."""
        with self._lock:
            self._institutions[institution.institution_id] = institution

    def get_institution(self, institution_id: str) -> Optional[Institution]:
        """Get an institution."""
        return self._institutions.get(institution_id)

    def add_fraud_alert(self, alert: FraudAlert) -> None:
        """Add a fraud alert."""
        with self._lock:
            self._fraud_alerts[alert.alert_id] = alert

    def get_fraud_alert(self, alert_id: str) -> Optional[FraudAlert]:
        """Get a fraud alert."""
        return self._fraud_alerts.get(alert_id)

    def get_fraud_alerts_by_institution(
        self,
        institution_id: str,
    ) -> List[FraudAlert]:
        """Get fraud alerts from an institution."""
        return [
            a for a in self._fraud_alerts.values()
            if a.source_institution == institution_id
        ]

    def add_fraud_pattern(self, pattern: FraudPattern) -> None:
        """Add a fraud pattern."""
        with self._lock:
            self._fraud_patterns[pattern.pattern_id] = pattern

    def get_fraud_pattern(self, pattern_id: str) -> Optional[FraudPattern]:
        """Get a fraud pattern."""
        return self._fraud_patterns.get(pattern_id)

    def get_all_patterns(self) -> List[FraudPattern]:
        """Get all fraud patterns."""
        return list(self._fraud_patterns.values())

    def create_shared_case(self, case: SharedCase) -> None:
        """Create a shared case."""
        with self._lock:
            self._shared_cases[case.case_id] = case

    def get_shared_case(self, case_id: str) -> Optional[SharedCase]:
        """Get a shared case."""
        return self._shared_cases.get(case_id)

    def get_cases_by_institution(self, institution_id: str) -> List[SharedCase]:
        """Get cases involving an institution."""
        return [
            c for c in self._shared_cases.values()
            if c.source_institution == institution_id or
            institution_id in c.participants
        ]

    def add_aml_intel(self, intel: AMLIntelligence) -> None:
        """Add AML intelligence."""
        with self._lock:
            self._aml_intel[intel.intel_id] = intel

    def get_aml_intel(self, intel_id: str) -> Optional[AMLIntelligence]:
        """Get AML intelligence."""
        return self._aml_intel.get(intel_id)

    def create_investigation(self, investigation: CrossBorderInvestigation) -> None:
        """Create a cross-border investigation."""
        with self._lock:
            self._investigations[investigation.investigation_id] = investigation

    def get_investigation(
        self,
        investigation_id: str,
    ) -> Optional[CrossBorderInvestigation]:
        """Get an investigation."""
        return self._investigations.get(investigation_id)

    def log_audit(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log."""
        return self._audit_log[-limit:]

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics."""
        return {
            "total_institutions": len(self._institutions),
            "total_fraud_alerts": len(self._fraud_alerts),
            "total_patterns": len(self._fraud_patterns),
            "total_shared_cases": len(self._shared_cases),
            "total_aml_intel": len(self._aml_intel),
            "active_investigations": len([
                i for i in self._investigations.values()
                if i.status == "active"
            ]),
        }

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._institutions.clear()
            self._fraud_alerts.clear()
            self._fraud_patterns.clear()
            self._shared_cases.clear()
            self._aml_intel.clear()
            self._investigations.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[FinIntelStore] = None
_store_lock = threading.Lock()


def get_finintel_store() -> FinIntelStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = FinIntelStore()
    return _store


def reset_finintel_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None