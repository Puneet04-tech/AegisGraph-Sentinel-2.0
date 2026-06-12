"""
Financial Intelligence Exchange Engine.

Main service for financial crime intelligence exchange.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AlertLevel,
    AMLIntelligence,
    CaseStatus,
    CrossBorderInvestigation,
    FraudAlert,
    FraudPattern,
    Institution,
    InstitutionType,
    ShareLevel,
    SharedCase,
)
from .store import FinIntelStore, get_finintel_store


class FinIntelEngine:
    """Main financial intelligence exchange engine."""

    def __init__(self, store: Optional[FinIntelStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_finintel_store()

    def register_institution(
        self,
        name: str,
        institution_type: str,
        country: str,
    ) -> Institution:
        """Register an institution."""
        institution_id = f"inst-{uuid.uuid4().hex[:12]}"
        
        institution = Institution(
            institution_id=institution_id,
            name=name,
            institution_type=InstitutionType(institution_type),
            country=country,
        )
        
        self.store.add_institution(institution)
        
        self.store.log_audit(
            user_id="system",
            action="institution_registered",
            resource_type="institution",
            resource_id=institution_id,
            details={"name": name},
        )
        
        return institution

    def share_fraud_alert(
        self,
        source_institution: str,
        alert_type: str,
        account_identifier: str,
        amount: float,
        description: str,
        share_level: str = "anonymized",
    ) -> FraudAlert:
        """Share a fraud alert."""
        alert_id = f"alert-{uuid.uuid4().hex[:12]}"
        
        alert = FraudAlert(
            alert_id=alert_id,
            source_institution=source_institution,
            alert_type=alert_type,
            account_identifier=account_identifier,
            amount=amount,
            description=description,
            share_level=ShareLevel(share_level),
        )
        
        self.store.add_fraud_alert(alert)
        
        source = self.store.get_institution(source_institution)
        if source:
            source.intelligence_shared += 1
        
        self.store.log_audit(
            user_id=source_institution,
            action="fraud_alert_shared",
            resource_type="fraud_alert",
            resource_id=alert_id,
        )
        
        return alert

    def identify_pattern(
        self,
        pattern_type: str,
        description: str,
        indicators: List[str],
    ) -> FraudPattern:
        """Identify a fraud pattern."""
        pattern_id = f"pattern-{uuid.uuid4().hex[:12]}"
        
        pattern = FraudPattern(
            pattern_id=pattern_id,
            pattern_type=pattern_type,
            description=description,
            indicators=indicators,
        )
        
        self.store.add_fraud_pattern(pattern)
        
        return pattern

    def create_shared_case(
        self,
        source_institution: str,
        title: str,
        description: str,
        case_type: str,
        participants: Optional[List[str]] = None,
    ) -> SharedCase:
        """Create a shared case."""
        case_id = f"case-{uuid.uuid4().hex[:12]}"
        
        case = SharedCase(
            case_id=case_id,
            source_institution=source_institution,
            title=title,
            description=description,
            case_type=case_type,
            participants=participants or [],
        )
        
        self.store.create_shared_case(case)
        
        self.store.log_audit(
            user_id=source_institution,
            action="case_shared",
            resource_type="shared_case",
            resource_id=case_id,
        )
        
        return case

    def share_aml_intelligence(
        self,
        source_institution: str,
        subject_type: str,
        subject_identifier: str,
        risk_indicators: List[str],
        share_level: str = "anonymized",
    ) -> AMLIntelligence:
        """Share AML intelligence."""
        intel_id = f"aml-{uuid.uuid4().hex[:12]}"
        
        intel = AMLIntelligence(
            intel_id=intel_id,
            source_institution=source_institution,
            subject_type=subject_type,
            subject_identifier=subject_identifier,
            risk_indicators=risk_indicators,
            share_level=ShareLevel(share_level),
        )
        
        self.store.add_aml_intel(intel)
        
        return intel

    def initiate_cross_border_investigation(
        self,
        title: str,
        primary_institution: str,
        subjects: List[str],
        involved_institutions: Optional[List[str]] = None,
    ) -> CrossBorderInvestigation:
        """Initiate a cross-border investigation."""
        investigation_id = f"invest-{uuid.uuid4().hex[:12]}"
        
        investigation = CrossBorderInvestigation(
            investigation_id=investigation_id,
            title=title,
            primary_institution=primary_institution,
            involved_institutions=involved_institutions or [],
            subjects=subjects,
            status="active",
        )
        
        self.store.create_investigation(investigation)
        
        self.store.log_audit(
            user_id=primary_institution,
            action="investigation_initiated",
            resource_type="cross_border_investigation",
            resource_id=investigation_id,
        )
        
        return investigation

    def search_fraud_alerts(
        self,
        query: str,
        alert_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search fraud alerts."""
        alerts = list(self.store._fraud_alerts.values())
        
        if query:
            query_lower = query.lower()
            alerts = [
                a for a in alerts
                if query_lower in a.description.lower() or
                query_lower in a.account_identifier.lower()
            ]
        
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        
        return [
            {
                "alert_id": a.alert_id,
                "alert_type": a.alert_type,
                "amount": a.amount,
                "description": a.description,
                "share_level": a.share_level.value,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ]

    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard."""
        metrics = self.store.get_dashboard_metrics()
        
        return {
            **metrics,
            "shared_intelligence": sum(
                i.intelligence_shared for i in self.store._institutions.values()
            ),
            "received_intelligence": sum(
                i.intelligence_received for i in self.store._institutions.values()
            ),
        }

    def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "resource_type": e.resource_type,
            }
            for e in events
        ]


# Singleton instance
_engine: Optional[FinIntelEngine] = None


def get_finintel_engine() -> FinIntelEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = FinIntelEngine()
    return _engine


def reset_finintel_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None