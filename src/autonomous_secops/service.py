"""
Autonomous SecOps Service.

Main service for autonomous security operations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import AuditEvent, Severity
from .store import (
    AutonomousSecOpsStore,
    get_secops_store,
    reset_secops_store,
)
from .secops_engine import (
    SecurityOperationsEngine,
    get_secops_engine,
    reset_secops_engine,
)
from .correlation_engine import (
    ThreatCorrelationEngine,
    get_correlation_engine,
    reset_correlation_engine,
)
from .investigation_engine import (
    InvestigationEngine,
    get_investigation_engine,
    reset_investigation_engine,
)
from .playbook_engine import (
    PlaybookEngine,
    get_playbook_engine,
    reset_playbook_engine,
)
from .threat_hunting import (
    ThreatHuntingEngine,
    get_threat_hunting_engine,
    reset_threat_hunting_engine,
)


class AutonomousSecOpsService:
    """Main service for autonomous security operations."""

    def __init__(self, store: Optional[AutonomousSecOpsStore] = None) -> None:
        """Initialize the service."""
        self.store = store or get_secops_store()
        self.secops = get_secops_engine()
        self.correlation = get_correlation_engine()
        self.investigation = get_investigation_engine()
        self.playbook = get_playbook_engine()
        self.hunting = get_threat_hunting_engine()

    async def process_alert(
        self,
        title: str,
        description: str,
        severity: str,
        source: str,
        indicators: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Process a new alert."""
        alert = self.secops.process_alert(
            title=title,
            description=description,
            severity=severity,
            source=source,
            indicators=indicators,
        )
        
        triage_result = self.secops.triage_alert(alert.alert_id)
        
        if triage_result.get("escalated"):
            incident = self.secops.create_incident_from_alert(alert.alert_id)
            return {
                "alert_id": alert.alert_id,
                "triage_score": triage_result["triage_score"],
                "escalated": True,
                "incident_id": incident.incident_id if incident else None,
            }
        
        return {
            "alert_id": alert.alert_id,
            "triage_score": triage_result["triage_score"],
            "escalated": False,
        }

    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get incident details."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return None
        
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "alerts": incident.alerts,
            "affected_assets": incident.affected_assets,
            "timeline": incident.timeline,
            "created_at": incident.created_at.isoformat(),
        }

    async def investigate(self, incident_id: str) -> Dict[str, Any]:
        """Start investigation for an incident."""
        result = self.investigation.start_investigation(incident_id)
        
        if result.get("success"):
            evidence = self.investigation.gather_evidence(incident_id)
            impact = self.investigation.analyze_impact(incident_id)
            
            return {
                **result,
                "evidence": evidence.get("evidence", {}),
                "impact": impact,
            }
        
        return result

    async def execute_playbook(
        self,
        playbook_id: str,
        incident_id: str,
    ) -> Dict[str, Any]:
        """Execute a playbook."""
        execution = self.playbook.execute_playbook(playbook_id, incident_id)
        
        return {
            "execution_id": execution.execution_id,
            "playbook_id": playbook_id,
            "incident_id": incident_id,
            "status": "started",
        }

    async def hunt_threats(
        self,
        name: str,
        hypothesis: str,
        created_by: str,
        indicators: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Create and execute a threat hunt."""
        hunt = self.hunting.create_hunt(
            name=name,
            hypothesis=hypothesis,
            created_by=created_by,
            indicators=indicators,
        )
        
        result = self.hunting.execute_hunt(hunt.hunt_id)
        
        return {
            "hunt_id": hunt.hunt_id,
            **result,
        }

    async def correlate_alerts(self) -> Dict[str, Any]:
        """Correlate all alerts."""
        matches = self.correlation.evaluate_alerts()
        
        return {
            "matches_count": len(matches),
            "matches": matches,
        }

    async def get_dashboard(self) -> Dict[str, Any]:
        """Get SOC dashboard."""
        return self.secops.get_dashboard()

    async def get_playbooks(self) -> List[Dict[str, Any]]:
        """Get all playbooks."""
        return self.playbook.get_all_playbooks()

    async def get_hunts(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get threat hunts."""
        return self.hunting.get_hunts_by_status(status)

    async def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "success": e.success,
            }
            for e in events
        ]


# Singleton instance
_service: Optional[AutonomousSecOpsService] = None


def get_secops_service() -> AutonomousSecOpsService:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = AutonomousSecOpsService()
    return _service


def reset_secops_service() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_secops_store()
    reset_secops_engine()
    reset_correlation_engine()
    reset_investigation_engine()
    reset_playbook_engine()
    reset_threat_hunting_engine()