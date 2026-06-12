"""
Financial Crime Command Center Service.

Main service for the Autonomous Financial Crime Command Center.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Alert,
    AlertStatus,
    AuditEntry,
    CaseStatus,
    CrimeCase,
    CrimeType,
    ThreatLevel,
)
from .store import (
    FinancialCrimeStore,
    get_financial_crime_store,
    reset_financial_crime_store,
)
from .correlation_engine import (
    CaseCorrelationEngine,
    get_correlation_engine,
    reset_correlation_engine,
)
from .intelligence_engine import (
    CrimeIntelligenceEngine,
    get_crime_intelligence_engine,
    reset_crime_intelligence_engine,
)
from .prioritization_engine import (
    RiskPrioritizationEngine,
    get_risk_prioritization_engine,
    reset_risk_prioritization_engine,
)
from .threat_fusion import (
    ThreatFusionEngine,
    get_threat_fusion_engine,
    reset_threat_fusion_engine,
)


class FinancialCrimeCommandCenter:
    """Main service for the Financial Crime Command Center."""

    def __init__(self, store: Optional[FinancialCrimeStore] = None) -> None:
        """Initialize the command center."""
        self.store = store or get_financial_crime_store()
        self.intelligence = get_crime_intelligence_engine()
        self.correlation = get_correlation_engine()
        self.prioritization = get_risk_prioritization_engine()
        self.threat_fusion = get_threat_fusion_engine()
        self._audit_log: List[AuditEntry] = []

    async def create_case(
        self,
        title: str,
        description: str,
        crime_type: str,
        entity_ids: Optional[List[str]] = None,
        priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new financial crime case."""
        case_id = f"fcc-{uuid.uuid4().hex[:8]}"
        
        priority_score = 0.5
        if priority:
            priority_map = {
                "p0_critical": 0.95,
                "p1_high": 0.75,
                "p2_medium": 0.5,
                "p3_low": 0.25,
            }
            priority_score = priority_map.get(priority.lower(), 0.5)
        
        case = CrimeCase(
            case_id=case_id,
            title=title,
            description=description,
            crime_type=CrimeType(crime_type),
            priority_score=priority_score,
            entity_ids=entity_ids or [],
        )
        
        self.store.store_case(case)
        
        await self._audit(
            action="create_case",
            resource_type="case",
            resource_id=case_id,
            details={"crime_type": crime_type},
        )
        
        return {
            "case_id": case.case_id,
            "status": case.status.value,
            "priority_score": case.priority_score,
        }

    async def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get case details."""
        case = self.store.get_case(case_id)
        if not case:
            return None
        
        return {
            "case_id": case.case_id,
            "title": case.title,
            "description": case.description,
            "crime_type": case.crime_type.value,
            "status": case.status.value,
            "threat_level": case.threat_level.value,
            "priority_score": case.priority_score,
            "entity_ids": case.entity_ids,
            "linked_cases": case.linked_cases,
            "created_at": case.created_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
        }

    async def get_dashboard(self) -> Dict[str, Any]:
        """Get command center dashboard metrics."""
        metrics = self.store.get_dashboard_metrics()
        
        threats = await self.threat_fusion.fuse_threats()
        
        prioritized = self.prioritization.prioritize_queue()
        top_priorities = [
            {"case_id": p.case_id, "score": p.priority_score}
            for p in prioritized[:10]
        ]
        
        return {
            **metrics,
            "top_priorities": top_priorities,
            "threat_summary": self.threat_fusion.get_threat_summary(),
        }

    async def get_threats(self) -> Dict[str, Any]:
        """Get current threats."""
        threats = await self.threat_fusion.fuse_threats()
        
        return {
            "threat_clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "threat_level": c.threat_level.value,
                    "threat_count": len(c.threats),
                    "confidence": c.confidence,
                }
                for c in threats.threat_clusters
            ],
            "high_priority": [
                {
                    "indicator_id": t.indicator_id,
                    "type": t.indicator_type,
                    "confidence": t.confidence,
                }
                for t in threats.high_priority_threats
            ],
            "recommended_actions": threats.recommended_actions,
        }

    async def get_investigations(
        self,
        status: Optional[str] = None,
        crime_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get investigations."""
        cases = list(self.store._cases.values())
        
        if status:
            cases = [c for c in cases if c.status.value == status]
        if crime_type:
            cases = [c for c in cases if c.crime_type.value == crime_type]
        
        cases.sort(key=lambda c: c.priority_score, reverse=True)
        
        return [
            {
                "case_id": c.case_id,
                "title": c.title,
                "crime_type": c.crime_type.value,
                "status": c.status.value,
                "priority_score": c.priority_score,
                "threat_level": c.threat_level.value,
            }
            for c in cases
        ]

    async def prioritize_cases(self) -> List[Dict[str, Any]]:
        """Prioritize all open cases."""
        results = self.prioritization.prioritize_queue()
        
        await self._audit(
            action="prioritize_cases",
            resource_type="batch",
            resource_id="all",
            details={"count": len(results)},
        )
        
        return [
            {
                "case_id": r.case_id,
                "priority_score": r.priority_score,
                "rank": r.priority_rank,
                "action": r.recommended_action,
            }
            for r in results
        ]

    async def correlate_cases(self, case_id: str) -> Dict[str, Any]:
        """Find correlations for a case."""
        correlations = self.correlation.find_correlations(case_id)
        
        return {
            "case_id": case_id,
            "correlations": [
                {
                    "target_case_id": c.target_case_id,
                    "score": c.correlation_score,
                    "factors": c.correlation_factors,
                    "action": c.recommended_action,
                }
                for c in correlations
            ],
        }

    async def get_analytics(
        self,
        period_start: Optional[str] = None,
        period_end: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get analytics report."""
        cases = list(self.store._cases.values())
        
        if period_start:
            start = datetime.fromisoformat(period_start)
        else:
            start = datetime.now(timezone.utc).replace(day=1)
        
        if period_end:
            end = datetime.fromisoformat(period_end)
        else:
            end = datetime.now(timezone.utc)
        
        period_cases = [
            c for c in cases
            if start <= c.created_at <= end
        ]
        
        return {
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "total_cases": len(period_cases),
            "by_crime_type": {
                ct.value: len([c for c in period_cases if c.crime_type == ct])
                for ct in CrimeType
            },
            "by_status": {
                cs.value: len([c for c in period_cases if c.status == cs])
                for cs in CaseStatus
            },
            "avg_priority": sum(c.priority_score for c in period_cases) / len(period_cases) if period_cases else 0,
        }

    async def get_alerts(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts."""
        if status:
            alerts = self.store.get_alerts_by_status(AlertStatus(status))
        else:
            alerts = self.store.get_recent_alerts()
        
        return [
            {
                "alert_id": a.alert_id,
                "title": a.title,
                "crime_type": a.crime_type.value,
                "status": a.status.value,
                "threat_level": a.threat_level.value,
                "triggered_at": a.triggered_at.isoformat(),
            }
            for a in alerts
        ]

    async def get_audit_log(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log."""
        return [
            {
                "entry_id": e.entry_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
            }
            for e in self._audit_log[-limit:]
        ]

    async def _audit(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Log an audit entry."""
        entry = AuditEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id="system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )
        self._audit_log.append(entry)


# Singleton instance
_service: Optional[FinancialCrimeCommandCenter] = None


def get_financial_crime_command_center() -> FinancialCrimeCommandCenter:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = FinancialCrimeCommandCenter()
    return _service


def reset_financial_crime_command_center() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_financial_crime_store()
    reset_correlation_engine()
    reset_crime_intelligence_engine()
    reset_risk_prioritization_engine()
    reset_threat_fusion_engine()